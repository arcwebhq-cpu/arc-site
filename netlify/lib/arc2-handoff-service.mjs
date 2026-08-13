import { createHmac } from 'node:crypto';
import {
  CLAIM_TOKEN_TTL_SECONDS,
  canonicalNetlifySiteUrl,
  canonicalJson,
  createClaimStateEvidence,
  createClaimableSite,
  createInitialRecord,
  createOutboxClaim,
  createStoredZip,
  deployZip,
  downloadVerifiedArtifacts,
  ensureEmailHook,
  findNetlifyForm,
  handoffIdFromKey,
  handoffKey,
  handoffKeyFromId,
  hmacHex,
  netlifyClaimUrl,
  normalizeClaimWebhook,
  normalizeProductionUrl,
  normalizeStartPayload,
  pollDeployReady,
  publicStatus,
  reviseRecord,
  safeEqual,
  sha256Hex,
  siteIndexKey,
  transitionRecord,
  validateExpectedBindings,
  verifyNetlifyHandoff,
} from './arc2-handoff-core.mjs';
import { createEntry, createIndex, readEntry, readIndex, replaceEntry } from './arc2-handoff-store.mjs';

const NETLIFY_API_ORIGIN = 'https://api.netlify.com/api/v1';
const LEAD_ROUTE_RECEIPT_VERSION = 'arc2-lead-route-inbox-receipt-v1';
const LEAD_ROUTE_RECEIPT_SCOPE = 'authoritative-lead-route-inbox-receipt';
const LEAD_ROUTE_RECEIPT_PREFIX = 'arc2-lead-route-inbox-receipt-signature-v1\n';
const CLAIM_BEARER_DERIVATION_PREFIX = 'arc2-claim-bearer-derivation-v1\n';
const CLAIM_BEARER_STORAGE_PREFIX = 'arc2-claim-bearer-at-rest-v1\n';
const INVITATION_READY_OUTBOX_VERSION = 'arc2-claim-invitation-ready-outbox-v1';
const RECEIPT_FRESHNESS_MS = 10 * 60_000;

const waitForNetlify = (attempt) => new Promise((resolve) => setTimeout(resolve, Math.min(250 * (2 ** attempt), 3000)));

function exactReplay(record, normalized) {
  return record.payment_evidence_sha256 === normalized.payment.digest &&
    record.artifact_evidence_sha256 === normalized.artifact.digest &&
    record.bundle_fingerprint === normalized.artifact.value.bundle_fingerprint &&
    record.lead_notification_email_sha256 === normalized.leadEmailHash && record.form_name === normalized.formName;
}

function checkoutSessionIndexKey(paymentEvidence, env) {
  const digest = hmacHex(env.ARC_HANDOFF_STATE_SECRET, `checkout-session-index-v1\n${paymentEvidence.checkout_session_id}`);
  return `checkout-session-index/${digest}`;
}

function checkoutSessionIndexValue(handoffId, normalized) {
  return {
    schema: 'arc2-checkout-session-index-v1',
    handoff_id: handoffId,
    payment_evidence_sha256: normalized.payment.digest,
    artifact_evidence_sha256: normalized.artifact.digest,
    bundle_fingerprint: normalized.artifact.value.bundle_fingerprint,
  };
}

function exactObjectKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function sha256(value, label) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) throw new TypeError(`${label} must be lowercase SHA-256.`);
  return value;
}

function identifier(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function iso(value, label) {
  if (typeof value !== 'string' || new Date(value).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return value;
}

async function ensureImmutableIndex(store, key, value) {
  const existing = await readIndex(store, key);
  if (existing) {
    if (canonicalJson(existing) !== canonicalJson(value)) throw new Error('ARC2_INDEX_CONFLICT');
    return existing;
  }
  try {
    await createIndex(store, key, value);
    return value;
  } catch (error) {
    if (error.message !== 'ARC2_INDEX_CONFLICT') throw error;
    const raced = await readIndex(store, key);
    if (!raced || canonicalJson(raced) !== canonicalJson(value)) throw error;
    return raced;
  }
}

async function netlifyRequest(path, options, env, fetchImpl) {
  const response = await fetchImpl(`${NETLIFY_API_ORIGIN}${path}`, {
    ...options,
    headers: { Accept: 'application/json', Authorization: `Bearer ${env.NETLIFY_ADMIN_PAT}`, ...(options.headers || {}) },
    redirect: 'error',
  });
  if (!response.ok) throw new Error(`ARC2_NETLIFY_HTTP_${response.status}`);
  return response;
}

async function netlifyJson(path, env, fetchImpl) {
  return (await netlifyRequest(path, { method: 'GET' }, env, fetchImpl)).json();
}

function validateSiteIntent(site, record, env, allowDestination = false) {
  if (!site || identifier(site.id, 'Netlify site id') !== site.id || site.name !== record.netlify_site_name || site.session_id !== record.netlify_session_id) {
    throw new Error('ARC2_SITE_INTENT_MISMATCH');
  }
  if (allowDestination) {
    if (site.account_id === record.netlify_source_account_id) throw new Error('ARC2_SITE_NOT_CLAIMED');
  } else if (site.account_id !== env.NETLIFY_TEAM_ACCOUNT_ID || site.account_slug !== env.NETLIFY_TEAM_SLUG) {
    throw new Error('ARC2_SITE_SOURCE_ACCOUNT_MISMATCH');
  }
  return site;
}

async function recoverSiteByIntent(record, env, fetchImpl) {
  const query = new URLSearchParams({ name: record.netlify_site_name, filter: 'owner' });
  const sites = await netlifyJson(`/sites?${query}`, env, fetchImpl);
  const matches = (Array.isArray(sites) ? sites : []).filter((site) => site?.name === record.netlify_site_name);
  if (matches.length > 1) throw new Error('ARC2_DUPLICATE_DETERMINISTIC_SITE');
  if (matches.length === 0) return null;
  const site = await netlifyJson(`/sites/${encodeURIComponent(identifier(matches[0].id, 'Netlify site id'))}`, env, fetchImpl);
  return validateSiteIntent(site, record, env);
}

async function createOrRecoverSite(record, env, fetchImpl, wait) {
  const existing = await recoverSiteByIntent(record, env, fetchImpl);
  if (existing) return existing;
  try {
    return await createClaimableSite(record, env, fetchImpl);
  } catch (cause) {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await wait(attempt);
      const recovered = await recoverSiteByIntent(record, env, fetchImpl);
      if (recovered) return recovered;
    }
    throw new Error('ARC2_SITE_CREATE_AMBIGUOUS', { cause });
  }
}

function deployTitle(record, phase) {
  return `ARC ${phase} ${record.handoff_id.slice(0, 16)} ${record.bundle_fingerprint.slice(0, 12)}`;
}

async function recoverDeploy(record, phase, env, fetchImpl) {
  const candidateId = record[`${phase}_deploy_candidate_id`];
  if (candidateId) return { id: identifier(candidateId, 'Netlify deploy candidate id'), site_id: record.netlify_site_id };
  const deploys = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}/deploys?per_page=100`, env, fetchImpl);
  const title = deployTitle(record, phase);
  const matches = (Array.isArray(deploys) ? deploys : []).filter((deploy) => deploy?.site_id === record.netlify_site_id && deploy?.title === title);
  if (matches.length > 1) throw new Error(`ARC2_DUPLICATE_${phase.toUpperCase()}_DEPLOY`);
  if (matches.length === 0) return null;
  identifier(matches[0].id, 'Netlify deploy id');
  return matches[0];
}

async function ensurePublished(record, deployId, env, fetchImpl) {
  let site = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl);
  if (site?.published_deploy?.id === deployId) return;
  try {
    await netlifyRequest(`/sites/${encodeURIComponent(record.netlify_site_id)}/deploys/${encodeURIComponent(deployId)}/restore`, { method: 'POST' }, env, fetchImpl);
  } catch (cause) {
    site = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl);
    if (site?.published_deploy?.id !== deployId) throw new Error('ARC2_DEPLOY_RESTORE_AMBIGUOUS', { cause });
    return;
  }
  site = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl);
  if (site?.published_deploy?.id !== deployId) throw new Error('ARC2_DEPLOY_RESTORE_UNVERIFIED');
}

async function ensureDeploy(entry, key, artifacts, phase, env, adapters) {
  const fetchImpl = adapters.fetch || fetch;
  const wait = adapters.wait || waitForNetlify;
  const clock = adapters.clock || (() => new Date());
  const attemptedField = `${phase}_deploy_attempted_at`;
  const candidateField = `${phase}_deploy_candidate_id`;
  let candidate = await recoverDeploy(entry.record, phase, env, fetchImpl);
  if (!candidate && entry.record[attemptedField]) {
    for (let attempt = 0; attempt < 5 && !candidate; attempt += 1) {
      await wait(attempt);
      candidate = await recoverDeploy(entry.record, phase, env, fetchImpl);
    }
  }
  if (!candidate) {
    if (entry.record[attemptedField]) throw new Error(`ARC2_${phase.toUpperCase()}_DEPLOY_AMBIGUOUS`);
    entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { [attemptedField]: clock().toISOString() }, clock()));
    const zip = createStoredZip(artifacts);
    try {
      candidate = await deployZip(entry.record.netlify_site_id, zip, deployTitle(entry.record, phase), env, fetchImpl);
      entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { [candidateField]: candidate.id }, clock()));
    } catch (cause) {
      for (let attempt = 0; attempt < 5 && !candidate; attempt += 1) {
        await wait(attempt);
        candidate = await recoverDeploy(entry.record, phase, env, fetchImpl);
      }
      if (!candidate) throw new Error(`ARC2_${phase.toUpperCase()}_DEPLOY_AMBIGUOUS`, { cause });
    }
  }
  if (!entry.record[candidateField]) {
    entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { [candidateField]: candidate.id }, clock()));
  } else if (entry.record[candidateField] !== candidate.id) {
    throw new Error(`ARC2_${phase.toUpperCase()}_DEPLOY_CANDIDATE_CONFLICT`);
  }
  const ready = await pollDeployReady(entry.record.netlify_site_id, candidate.id, env, fetchImpl, { wait });
  await ensurePublished(entry.record, ready.id, env, fetchImpl);
  return { entry, ready };
}

async function recoverEmailHook(siteId, formId, leadEmail, env, fetchImpl) {
  const hooks = await netlifyJson(`/hooks?site_id=${encodeURIComponent(siteId)}`, env, fetchImpl);
  const forForm = (Array.isArray(hooks) ? hooks : []).filter((hook) => hook?.site_id === siteId && hook?.form_id === formId &&
    hook?.type === 'email' && hook?.event === 'submission_created' && hook?.disabled !== true);
  if (forForm.some((hook) => String(hook.data?.email || '').trim().toLowerCase() !== leadEmail)) throw new Error('ARC2_EMAIL_HOOK_CONFLICT');
  if (forForm.length > 1) throw new Error('ARC2_DUPLICATE_EMAIL_HOOK');
  return forForm[0] || null;
}

async function ensureLeadHook(entry, key, leadEmail, env, adapters) {
  const fetchImpl = adapters.fetch || fetch;
  const wait = adapters.wait || waitForNetlify;
  const clock = adapters.clock || (() => new Date());
  const form = await findNetlifyForm(entry.record.netlify_site_id, entry.record.form_name, env, fetchImpl, { wait });
  let hook = await recoverEmailHook(entry.record.netlify_site_id, form.id, leadEmail, env, fetchImpl);
  if (!hook && entry.record.email_hook_attempted_at) {
    for (let attempt = 0; attempt < 5 && !hook; attempt += 1) {
      await wait(attempt);
      hook = await recoverEmailHook(entry.record.netlify_site_id, form.id, leadEmail, env, fetchImpl);
    }
  }
  if (!hook) {
    if (entry.record.email_hook_attempted_at) throw new Error('ARC2_EMAIL_HOOK_CREATE_AMBIGUOUS');
    entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { email_hook_attempted_at: clock().toISOString() }, clock()));
    try {
      hook = await ensureEmailHook(entry.record.netlify_site_id, form.id, leadEmail, env, fetchImpl);
    } catch (cause) {
      for (let attempt = 0; attempt < 5 && !hook; attempt += 1) {
        await wait(attempt);
        hook = await recoverEmailHook(entry.record.netlify_site_id, form.id, leadEmail, env, fetchImpl);
      }
      if (!hook) throw new Error('ARC2_EMAIL_HOOK_CREATE_AMBIGUOUS', { cause });
    }
  }
  identifier(hook.id, 'Netlify hook id');
  if (entry.record.form_id !== form.id || entry.record.hook_id !== hook.id) {
    entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { form_id: form.id, hook_id: hook.id }, clock()));
  }
  return entry;
}

export async function startHandoff(input, env, adapters = {}) {
  const clock = adapters.clock || (() => new Date());
  const fetchImpl = adapters.fetch || fetch;
  const wait = adapters.wait || waitForNetlify;
  let normalized = normalizeStartPayload(input, env, clock(), { enforceFreshness: false });
  normalized.leadEmailHash = sha256Hex(normalized.leadEmail);
  const key = handoffKey(normalized.payment.value, env.ARC_HANDOFF_STATE_SECRET);
  const handoffId = handoffIdFromKey(key);
  let entry = await readEntry(adapters.store, key);
  const existedAtStart = Boolean(entry);
  if (entry && !exactReplay(entry.record, normalized)) throw new Error('ARC2_IDEMPOTENCY_CONFLICT');
  // Old signed evidence may resume only the exact immutable handoff it already
  // created. A brand-new handoff still requires fresh artifact evidence.
  if (!entry) normalized = normalizeStartPayload(input, env, clock());
  // Reserve one immutable handoff per authenticated Checkout Session before
  // any Netlify write. The key is an HMAC, and the value stores only digests.
  await ensureImmutableIndex(adapters.store, checkoutSessionIndexKey(normalized.payment.value, env),
    checkoutSessionIndexValue(handoffId, normalized));
  if (!entry) {
    const initial = createInitialRecord(normalized, env, key, clock(), { uuid: adapters.uuid });
    entry = await createEntry(adapters.store, key, initial.record);
    if (!entry) {
      entry = await readEntry(adapters.store, key);
      if (!entry || !exactReplay(entry.record, normalized)) throw new Error('ARC2_IDEMPOTENCY_CONFLICT');
    }
  }
  if (entry.record.state === 'PAYMENT_VERIFIED') entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'SITE_INTENT', {}, clock()));
  if (entry.record.state === 'SITE_INTENT') {
    const site = await createOrRecoverSite(entry.record, env, fetchImpl, wait);
    await ensureImmutableIndex(adapters.store, siteIndexKey(site.id), {
      schema: 'arc2-site-index-v1', handoff_id: handoffId, netlify_site_id: site.id, netlify_session_id: entry.record.netlify_session_id,
    });
    entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'SITE_CREATED', {
      netlify_site_id: site.id, site_created_at: clock().toISOString(),
    }, clock()));
  }
  if (entry.record.state === 'SITE_CREATED') {
    const deployed = await ensureDeploy(entry, key, normalized.deployArtifacts, 'preclaim', env, adapters);
    entry = await replaceEntry(adapters.store, key, deployed.entry, transitionRecord(deployed.entry.record, 'PRECLAIM_DEPLOY_READY', {
      preclaim_deploy_id: deployed.ready.id,
    }, clock()));
  }
  if (entry.record.state === 'PRECLAIM_DEPLOY_READY') {
    if (!entry.record.form_id || !entry.record.hook_id) entry = await ensureLeadHook(entry, key, normalized.leadEmail, env, adapters);
    await verifyNetlifyHandoff(entry.record, {
      accountId: env.NETLIFY_TEAM_ACCOUNT_ID, artifacts: entry.record.artifacts, deployId: entry.record.preclaim_deploy_id,
      formId: entry.record.form_id, formName: entry.record.form_name, hookId: entry.record.hook_id,
      leadEmailSha256: entry.record.lead_notification_email_sha256,
    }, env, fetchImpl);
  }
  return { handoffId, record: entry.record, idempotentReplay: existedAtStart };
}

function normalizeLeadRouteReceipt(raw, signature, record, env, now) {
  if (typeof raw !== 'string' || raw.length < 2 || raw.length > 20_000) throw new TypeError('Lead-route receipt evidence is invalid.');
  const value = JSON.parse(raw);
  const keys = ['form_id_sha256', 'handoff_id', 'hook_id_sha256', 'inbox_receipt_id_sha256', 'issued_at', 'netlify_site_id_sha256',
    'provider_message_id_sha256', 'received_at', 'recipient_email_sha256', 'scope', 'version'];
  if (!exactObjectKeys(value, keys) || canonicalJson(value) !== raw || value.version !== LEAD_ROUTE_RECEIPT_VERSION ||
      value.scope !== LEAD_ROUTE_RECEIPT_SCOPE || value.handoff_id !== record.handoff_id) throw new TypeError('Lead-route receipt evidence fields are invalid.');
  const suppliedSignature = sha256(signature, 'Lead-route receipt signature');
  if (!safeEqual(suppliedSignature, hmacHex(env.ARC_LEAD_ROUTE_EVIDENCE_SECRET, `${LEAD_ROUTE_RECEIPT_PREFIX}${raw}`))) {
    throw new TypeError('Lead-route receipt signature mismatch.');
  }
  const issuedAt = Date.parse(iso(value.issued_at, 'Lead-route receipt issued_at'));
  const receivedAt = Date.parse(iso(value.received_at, 'Lead-route receipt received_at'));
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || issuedAt > nowMs + 60_000 || issuedAt < nowMs - RECEIPT_FRESHNESS_MS || receivedAt > issuedAt || receivedAt < issuedAt - RECEIPT_FRESHNESS_MS) {
    throw new TypeError('Lead-route receipt evidence is stale or out of order.');
  }
  const bindings = {
    netlify_site_id_sha256: sha256Hex(record.netlify_site_id), form_id_sha256: sha256Hex(record.form_id),
    hook_id_sha256: sha256Hex(record.hook_id), recipient_email_sha256: record.lead_notification_email_sha256,
  };
  for (const [field, expected] of Object.entries(bindings)) if (!safeEqual(sha256(value[field], field), expected)) throw new TypeError('Lead-route receipt binding mismatch.');
  sha256(value.provider_message_id_sha256, 'provider_message_id_sha256');
  sha256(value.inbox_receipt_id_sha256, 'inbox_receipt_id_sha256');
  return { canonical: raw, digest: sha256Hex(raw), value };
}

function deriveClaimBearer(record, env) {
  const material = canonicalJson({
    handoff_id: record.handoff_id, lead_route_receipt_sha256: record.lead_route_receipt_sha256,
    claim_invitation_ready_at: record.claim_invitation_ready_at, claim_token_expires_at: record.claim_token_expires_at,
  });
  return createHmac('sha256', env.ARC_CLAIM_TOKEN_SECRET).update(`${CLAIM_BEARER_DERIVATION_PREFIX}${material}`).digest('base64url');
}

function claimBearerDigest(token, env) {
  return hmacHex(env.ARC_CLAIM_TOKEN_SECRET, `${CLAIM_BEARER_STORAGE_PREFIX}${token}`);
}

function invitationReadyOutbox(record, env) {
  const canonical = canonicalJson({
    version: INVITATION_READY_OUTBOX_VERSION, handoff_id: record.handoff_id, recipient_email_sha256: record.customer_email_sha256,
    claim_token_hmac_sha256: record.claim_token_hmac_sha256, expires_at: record.claim_token_expires_at,
  });
  const digest = hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET, canonical);
  return { key: `invitation-ready-outbox/${digest}`, value: {
    schema: INVITATION_READY_OUTBOX_VERSION, status: 'READY', handoff_id: record.handoff_id,
    recipient_email_sha256: record.customer_email_sha256, claim_token_hmac_sha256: record.claim_token_hmac_sha256,
    expires_at: record.claim_token_expires_at,
  } };
}

export async function markClaimInvitationReady(handoffId, evidence, signature, env, adapters = {}) {
  const key = handoffKeyFromId(handoffId);
  const clock = adapters.clock || (() => new Date());
  let entry = await readEntry(adapters.store, key);
  if (!entry) return null;
  const observedAt = clock();
  let receipt;
  if (entry.record.lead_route_receipt_sha256 !== null) {
    // Replays of an already-bound receipt re-check its signature, canonical
    // fields, and record bindings without pretending it was newly issued.
    let issuedAt;
    try {
      issuedAt = JSON.parse(evidence).issued_at;
    } catch {
      issuedAt = observedAt;
    }
    receipt = normalizeLeadRouteReceipt(evidence, signature, entry.record, env, new Date(issuedAt));
  } else {
    receipt = normalizeLeadRouteReceipt(evidence, signature, entry.record, env, observedAt);
  }
  if (!['PRECLAIM_DEPLOY_READY', 'LEAD_ROUTE_VERIFIED', 'INVITATION_READY'].includes(entry.record.state)) {
    if (entry.record.lead_route_receipt_sha256 !== receipt.digest) throw new Error('ARC2_CLAIM_INVITATION_STATE_CONFLICT');
    return { handoffId, record: entry.record, claimBearer: null, alreadyConsumed: true };
  }
  if (entry.record.state === 'PRECLAIM_DEPLOY_READY' || entry.record.state === 'LEAD_ROUTE_VERIFIED') {
    const readyAt = observedAt;
    const expiresAt = new Date(readyAt.getTime() + CLAIM_TOKEN_TTL_SECONDS * 1000);
    const draft = transitionRecord(entry.record, 'INVITATION_READY', {
      lead_route_receipt_sha256: receipt.digest, claim_invitation_ready_at: readyAt.toISOString(),
      lead_route_provider_message_id_sha256: receipt.value.provider_message_id_sha256,
      claim_token_expires_at: expiresAt.toISOString(),
    }, readyAt);
    const token = deriveClaimBearer(draft, env);
    entry = await replaceEntry(adapters.store, key, entry, { ...draft, claim_token_hmac_sha256: claimBearerDigest(token, env) });
  } else if (entry.record.lead_route_receipt_sha256 !== receipt.digest) throw new Error('ARC2_CLAIM_INVITATION_EVIDENCE_CONFLICT');
  if (Date.parse(entry.record.claim_token_expires_at) <= observedAt.getTime()) throw new Error('ARC2_CLAIM_BEARER_EXPIRED');
  const token = deriveClaimBearer(entry.record, env);
  if (!safeEqual(claimBearerDigest(token, env), entry.record.claim_token_hmac_sha256)) throw new Error('ARC2_CLAIM_BEARER_BINDING_FAILED');
  const outbox = invitationReadyOutbox(entry.record, env);
  await ensureImmutableIndex(adapters.store, outbox.key, outbox.value);
  return { handoffId, record: entry.record, claimBearer: token, alreadyConsumed: false };
}

export async function exchangeClaimBearer(handoffId, suppliedBearer, env, adapters = {}) {
  if (typeof suppliedBearer !== 'string' || suppliedBearer.length !== 43 || !/^[A-Za-z0-9_-]+$/.test(suppliedBearer)) throw new Error('ARC2_CLAIM_BEARER_INVALID');
  const key = handoffKeyFromId(handoffId);
  const clock = adapters.clock || (() => new Date());
  let entry = await readEntry(adapters.store, key);
  if (!entry) return null;
  const suppliedDigest = claimBearerDigest(suppliedBearer, env);
  if (entry.record.state === 'INVITATION_READY') {
    const usedAt = clock();
    const expiresAt = Date.parse(entry.record.claim_token_expires_at);
    if (expiresAt - usedAt.getTime() < 1000 || !safeEqual(suppliedDigest, entry.record.claim_token_hmac_sha256) ||
        !safeEqual(deriveClaimBearer(entry.record, env), suppliedBearer)) throw new Error('ARC2_CLAIM_BEARER_INVALID');
    const projected = transitionRecord(entry.record, 'CLAIM_WRAPPER_CONSUMED', {
      claim_token_hmac_sha256: null, claim_token_consumed_hmac_sha256: suppliedDigest,
      claim_token_used_at: usedAt.toISOString(), claim_wrapper_consumed_at: usedAt.toISOString(),
      claim_jwt_issued_at: Math.floor(usedAt.getTime() / 1000),
    }, usedAt);
    // Validate the exact provider URL before consuming the wrapper state so an
    // expiry-rounding failure cannot permanently brick an otherwise valid row.
    const projectedClaimUrl = netlifyClaimUrl(projected, env);
    try {
      entry = await replaceEntry(adapters.store, key, entry, projected);
      return { handoffId, record: entry.record, claimUrl: projectedClaimUrl };
    } catch (error) {
      if (error.message !== 'ARC2_STATE_CONTENTION') throw error;
      entry = await readEntry(adapters.store, key);
    }
  }
  const replayedAt = clock();
  if (entry.record.state !== 'CLAIM_WRAPPER_CONSUMED' || Date.parse(entry.record.claim_token_expires_at) - replayedAt.getTime() < 1000 ||
      !safeEqual(entry.record.claim_token_consumed_hmac_sha256 || '', suppliedDigest)) throw new Error('ARC2_CLAIM_BEARER_INVALID');
  return { handoffId, record: entry.record, claimUrl: netlifyClaimUrl(entry.record, env) };
}

async function verifyClaimedRecord(record, deployId, destinationAccountId, env, fetchImpl) {
  const site = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl);
  validateSiteIntent(site, record, env, true);
  if (site.account_id !== destinationAccountId || destinationAccountId === record.netlify_source_account_id || site.published_deploy?.id !== deployId) {
    throw new Error('ARC2_POSTCLAIM_ACCOUNT_OR_DEPLOY_MISMATCH');
  }
  const deploy = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}/deploys/${encodeURIComponent(deployId)}`, env, fetchImpl);
  if (deploy?.id !== deployId || deploy?.site_id !== record.netlify_site_id || deploy?.state !== 'ready') throw new Error('ARC2_POSTCLAIM_DEPLOY_MISMATCH');
  const files = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}/files`, env, fetchImpl);
  if (!Array.isArray(files) || files.length !== record.artifacts.length || record.artifacts.some((artifact) => {
    const file = files.find((item) => item?.path === `/${artifact.path}`);
    return !file || Number(file.size) !== artifact.size;
  })) throw new Error('ARC2_POSTCLAIM_FILES_MISMATCH');
  const artifactBytes = await downloadVerifiedArtifacts(record.netlify_site_id, record.artifacts, env, fetchImpl);
  const forms = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}/forms`, env, fetchImpl);
  if ((Array.isArray(forms) ? forms : []).filter((form) => form?.id === record.form_id && form?.site_id === record.netlify_site_id && form?.name === record.form_name).length !== 1) {
    throw new Error('ARC2_POSTCLAIM_FORM_MISMATCH');
  }
  const hooks = await netlifyJson(`/hooks?site_id=${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl);
  if ((Array.isArray(hooks) ? hooks : []).filter((hook) => hook?.id === record.hook_id && hook?.site_id === record.netlify_site_id &&
      hook?.form_id === record.form_id && hook?.type === 'email' && hook?.event === 'submission_created' && hook?.disabled !== true &&
      sha256Hex(String(hook.data?.email || '').trim().toLowerCase()) === record.lead_notification_email_sha256).length !== 1) {
    throw new Error('ARC2_POSTCLAIM_HOOK_MISMATCH');
  }
  const productionUrl = canonicalNetlifySiteUrl(record.netlify_site_name);
  const publicResponse = await fetchImpl(productionUrl, { method: 'GET', redirect: 'error' });
  if (!publicResponse.ok || !(publicResponse.headers.get('x-robots-tag') || '').toLowerCase().includes('noindex')) throw new Error('ARC2_POSTCLAIM_PUBLICATION_MISMATCH');
  return { site, deploy, artifactBytes, productionUrl };
}

async function finishClaim(entry, key, hint, env, adapters) {
  const fetchImpl = adapters.fetch || fetch;
  const clock = adapters.clock || (() => new Date());
  if (entry.record.state === 'CLAIM_WRAPPER_CONSUMED') {
    const verified = await verifyClaimedRecord(entry.record, entry.record.preclaim_deploy_id, hint.destinationAccountId, env, fetchImpl);
    entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'CLAIM_CALLBACK_RECEIVED', {
      destination_account_id: hint.destinationAccountId, claim_callback_received_at: clock().toISOString(), production_url: verified.productionUrl,
    }, clock()));
  }
  if (entry.record.state === 'CLAIM_CALLBACK_RECEIVED') {
    if (entry.record.destination_account_id !== hint.destinationAccountId) throw new Error('ARC2_CLAIM_DESTINATION_CONFLICT');
    const verified = await verifyClaimedRecord(entry.record, entry.record.preclaim_deploy_id, hint.destinationAccountId, env, fetchImpl);
    entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'CLAIMED_VERIFIED', {
      claimed_verified_at: clock().toISOString(), production_url: verified.productionUrl,
    }, clock()));
  }
  if (entry.record.state === 'CLAIMED_VERIFIED') {
    if (entry.record.destination_account_id !== hint.destinationAccountId) throw new Error('ARC2_CLAIM_DESTINATION_CONFLICT');
    const preclaim = await verifyClaimedRecord(entry.record, entry.record.preclaim_deploy_id, hint.destinationAccountId, env, fetchImpl);
    const deployed = await ensureDeploy(entry, key, preclaim.artifactBytes, 'final', env, adapters);
    entry = deployed.entry;
    const final = await verifyClaimedRecord(entry.record, deployed.ready.id, hint.destinationAccountId, env, fetchImpl);
    // Build the outbox binding from the verified final values in memory, then
    // persist final deploy, URL, outbox, and state in one CAS. A crash cannot
    // leave FINAL fields attached to the preceding state.
    const verifiedFinalRecord = {
      ...entry.record,
      final_deploy_id: deployed.ready.id,
      production_url: final.productionUrl,
    };
    const outbox = createOutboxClaim(verifiedFinalRecord, env);
    await ensureImmutableIndex(adapters.store, outbox.key, outbox.value);
    entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'FINAL_DEPLOY_READY', {
      final_deploy_id: deployed.ready.id, production_url: final.productionUrl,
      final_deploy_ready_at: clock().toISOString(), outbox_claim_status: 'CLAIMED', outbox_claim_key_hmac_sha256: outbox.digest,
    }, clock()));
  }
  if (entry.record.state === 'FINAL_DEPLOY_READY' || entry.record.state === 'DELIVERED') {
    if (entry.record.destination_account_id !== hint.destinationAccountId) throw new Error('ARC2_CLAIM_DESTINATION_CONFLICT');
    await verifyClaimedRecord(entry.record, entry.record.final_deploy_id, hint.destinationAccountId, env, fetchImpl);
  }
  return entry;
}

export async function processClaimWebhook(input, env, adapters = {}) {
  const hint = normalizeClaimWebhook(input);
  const index = await readIndex(adapters.store, siteIndexKey(hint.siteId));
  if (!index || index.netlify_site_id !== hint.siteId) throw new Error('ARC2_UNKNOWN_CLAIM_SITE');
  const key = handoffKeyFromId(index.handoff_id);
  const entry = await readEntry(adapters.store, key);
  if (!entry || entry.record.netlify_site_id !== hint.siteId || entry.record.netlify_session_id !== index.netlify_session_id ||
      hint.destinationAccountId === entry.record.netlify_source_account_id) throw new Error('ARC2_CLAIM_BINDING_FAILED');
  if (!['CLAIM_WRAPPER_CONSUMED', 'CLAIM_CALLBACK_RECEIVED', 'CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED'].includes(entry.record.state)) {
    throw new Error('ARC2_CLAIM_STATE_CONFLICT');
  }
  const finished = await finishClaim(entry, key, hint, env, adapters);
  return { handoffId: index.handoff_id, record: finished.record };
}

export async function getHandoffStatus(handoffId, env, adapters = {}, options = {}) {
  const clock = adapters.clock || (() => new Date());
  const entry = await readEntry(adapters.store, handoffKeyFromId(handoffId));
  if (!entry) return null;
  const record = validateExpectedBindings(entry.record);
  const status = { ...publicStatus(record, clock()), claim_available: record.state === 'INVITATION_READY' && Date.parse(record.claim_token_expires_at) > clock().getTime() };
  if (options.includePrivate && record.state === 'FINAL_DEPLOY_READY') Object.assign(status, createClaimStateEvidence(record, env));
  return status;
}

export const leadRouteReceiptContract = Object.freeze({
  version: LEAD_ROUTE_RECEIPT_VERSION, scope: LEAD_ROUTE_RECEIPT_SCOPE, signaturePrefix: LEAD_ROUTE_RECEIPT_PREFIX,
});
