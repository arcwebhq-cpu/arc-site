import { createHmac } from 'node:crypto';
import {
  CLAIM_TOKEN_TTL_SECONDS,
  FINAL_DELIVERY_PROVIDER_EVENT_ID_PREFIX,
  FINAL_DELIVERY_PROVIDER_MESSAGE_ID_PREFIX,
  FINAL_DELIVERY_RECEIPT_SCOPE,
  FINAL_DELIVERY_RECEIPT_SIGNATURE_PREFIX,
  FINAL_DELIVERY_RECEIPT_VERSION,
  OUTBOX_CLAIM_VERSION,
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
  resolveHandoffEnvironment,
  safeEqual,
  sha256Hex,
  siteIndexKey,
  transitionRecord,
  validateExpectedBindings,
  verifyNetlifyHandoff,
} from './arc2-handoff-core.mjs';
import {
  createEntry,
  createIndex,
  readEntry,
  readIndex,
  readIndexEntry,
  replaceEntry,
  replaceIndex,
} from './arc2-handoff-store.mjs';

const NETLIFY_API_ORIGIN = 'https://api.netlify.com/api/v1';
const LEAD_ROUTE_RECEIPT_VERSION = 'arc2-lead-route-inbox-receipt-v1';
const LEAD_ROUTE_RECEIPT_SCOPE = 'authoritative-lead-route-inbox-receipt';
const LEAD_ROUTE_RECEIPT_PREFIX = 'arc2-lead-route-inbox-receipt-signature-v1\n';
const PRODUCER_LEAD_ROUTE_VERSION = 'arc-lead-route-evidence-v1';
const PRODUCER_LEAD_ROUTE_SCOPE = 'arc-controlled-netlify-staging';
const PRODUCER_LEAD_ROUTE_PREFIX = 'arc-lead-route-evidence-signature-v1\n';
const CLAIM_BEARER_DERIVATION_PREFIX = 'arc2-claim-bearer-derivation-v1\n';
const CLAIM_BEARER_STORAGE_PREFIX = 'arc2-claim-bearer-at-rest-v1\n';
const INVITATION_READY_OUTBOX_VERSION = 'arc2-claim-invitation-ready-outbox-v1';
const RECEIPT_FRESHNESS_MS = 10 * 60_000;
const PRODUCER_SOURCE_FRESHNESS_MS = 30 * 60_000;
const PRODUCER_EXTERNAL_ID_PATTERN = /^(?:[a-f0-9]{24}|[a-f0-9]{40}|[a-f0-9]{8}-[a-f0-9]{4}-[1-5a-f][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/;
const PRODUCER_LEAD_ROUTE_FIELDS = Object.freeze([
  'version', 'scope', 'preview_folder', 'production_content_sha256', 'artifact_manifest_sha256',
  'handoff_artifact_evidence_sha256', 'bundle_fingerprint', 'netlify_account_id', 'staging_site_id',
  'staging_site_url', 'staging_deploy_id', 'staging_deploy_url', 'deploy_file_manifest_sha256',
  'served_html_sha256', 'staging_robots_header_sha256', 'staging_form_id', 'notification_hook_id',
  'form_name', 'recipient_hmac_sha256', 'synthetic_submission_id', 'synthetic_probe_sha256',
  'netlify_submission_timestamp', 'inbox_provider', 'inbox_account_hmac_sha256',
  'inbox_message_id_hmac_sha256', 'inbox_received_timestamp', 'inbox_receipt_evidence_sha256',
]);
const FINAL_DELIVERY_RECEIPT_FIELDS = Object.freeze([
  'delivered_at',
  'delivery_status',
  'event_type',
  'handoff_id',
  'issued_at',
  'netlify_deploy_id_sha256',
  'netlify_site_id_sha256',
  'outbox_claim_key_hmac_sha256',
  'production_url_sha256',
  'provider',
  'provider_account_hmac_sha256',
  'provider_event_id',
  'provider_message_id',
  'recipient_email_sha256',
  'scope',
  'version',
]);
const FINAL_DELIVERY_EVENT_INDEX_SCHEMA = 'arc2-final-delivery-provider-event-index-v1';
const FINAL_DELIVERY_MESSAGE_INDEX_SCHEMA = 'arc2-final-delivery-provider-message-index-v1';
const LEGACY_SITE_NAME_PATTERN = /^arc-[a-f0-9]{24}$/;
const PRE_INVITATION_STATES = new Set([
  'PAYMENT_VERIFIED',
  'SITE_INTENT',
  'SITE_CREATED',
  'PRECLAIM_DEPLOY_READY',
  'LEAD_ROUTE_VERIFIED',
]);

const waitForNetlify = (attempt) => new Promise((resolve) => setTimeout(resolve, Math.min(250 * (2 ** attempt), 3000)));

function exactReplay(record, normalized) {
  return record.payment_evidence_sha256 === normalized.payment.digest &&
    record.artifact_evidence_sha256 === normalized.artifact.digest &&
    record.bundle_fingerprint === normalized.artifact.value.bundle_fingerprint &&
    record.lead_notification_email_sha256 === normalized.leadEmailHash &&
    (record.lead_route_recipient_hmac_sha256 === null ||
      record.lead_route_recipient_hmac_sha256 === normalized.leadRouteRecipientHmacSha256) &&
    record.form_name === normalized.formName;
}

function rejectQuarantinedLegacyNamespace(record) {
  if (LEGACY_SITE_NAME_PATTERN.test(record.netlify_site_name) && PRE_INVITATION_STATES.has(record.state)) {
    throw new Error('ARC2_LEGACY_SITE_NAMESPACE_QUARANTINED');
  }
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
  const resolved = resolveHandoffEnvironment(env);
  if (resolved.conflicts.length) throw new TypeError('Handoff environment aliases conflict.');
  env = resolved.environment;
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
  if (entry) rejectQuarantinedLegacyNamespace(entry.record);
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
  if (entry.record.lead_route_recipient_hmac_sha256 === null) {
    entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, {
      lead_route_recipient_hmac_sha256: normalized.leadRouteRecipientHmacSha256,
    }, clock()));
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

function verifyLeadRouteSignature(signature, raw, prefix, env) {
  const suppliedSignature = sha256(signature, 'Lead-route receipt signature');
  if (!safeEqual(suppliedSignature, hmacHex(env.ARC_LEAD_ROUTE_EVIDENCE_SECRET, `${prefix}${raw}`))) {
    throw new TypeError('Lead-route receipt signature mismatch.');
  }
}

function normalizeLegacyLeadRouteReceipt(raw, value, signature, record, env, now, options) {
  const keys = ['form_id_sha256', 'handoff_id', 'hook_id_sha256', 'inbox_receipt_id_sha256', 'issued_at', 'netlify_site_id_sha256',
    'provider_message_id_sha256', 'received_at', 'recipient_email_sha256', 'scope', 'version'];
  if (!exactObjectKeys(value, keys) || canonicalJson(value) !== raw || value.version !== LEAD_ROUTE_RECEIPT_VERSION ||
      value.scope !== LEAD_ROUTE_RECEIPT_SCOPE || value.handoff_id !== record.handoff_id) throw new TypeError('Lead-route receipt evidence fields are invalid.');
  verifyLeadRouteSignature(signature, raw, LEAD_ROUTE_RECEIPT_PREFIX, env);
  const issuedAt = Date.parse(iso(value.issued_at, 'Lead-route receipt issued_at'));
  const receivedAt = Date.parse(iso(value.received_at, 'Lead-route receipt received_at'));
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) ||
      (options.enforceFreshness !== false && (issuedAt > nowMs + 60_000 || issuedAt < nowMs - RECEIPT_FRESHNESS_MS)) ||
      receivedAt > issuedAt || receivedAt < issuedAt - RECEIPT_FRESHNESS_MS) {
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

function plainHttpsRoot(value, label) {
  if (typeof value !== 'string' || value.length < 12 || value.length > 512 || value !== value.trim()) {
    throw new TypeError(`${label} is invalid.`);
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${label} is invalid.`);
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/' || url.toString() !== value) {
    throw new TypeError(`${label} must be a canonical HTTPS root.`);
  }
  return value;
}

function normalizeProducerLeadRouteReceipt(raw, value, signature, record, env, now, options) {
  if (!exactObjectKeys(value, PRODUCER_LEAD_ROUTE_FIELDS) ||
      JSON.stringify(Object.keys(value)) !== JSON.stringify(PRODUCER_LEAD_ROUTE_FIELDS) || JSON.stringify(value) !== raw ||
      value.version !== PRODUCER_LEAD_ROUTE_VERSION || value.scope !== PRODUCER_LEAD_ROUTE_SCOPE) {
    throw new TypeError('Lead-route producer evidence fields are invalid.');
  }
  verifyLeadRouteSignature(signature, raw, PRODUCER_LEAD_ROUTE_PREFIX, env);

  for (const field of ['staging_site_id', 'staging_deploy_id', 'staging_form_id', 'notification_hook_id', 'synthetic_submission_id']) {
    if (typeof value[field] !== 'string' || !PRODUCER_EXTERNAL_ID_PATTERN.test(value[field])) {
      throw new TypeError(`Lead-route producer ${field} is invalid.`);
    }
  }
  identifier(value.netlify_account_id, 'Lead-route producer Netlify account id');
  if (typeof value.inbox_provider !== 'string' || !/^[a-z0-9][a-z0-9_.-]{1,63}$/.test(value.inbox_provider)) {
    throw new TypeError('Lead-route producer inbox provider is invalid.');
  }
  const digestFields = [
    'production_content_sha256', 'artifact_manifest_sha256', 'handoff_artifact_evidence_sha256', 'bundle_fingerprint',
    'deploy_file_manifest_sha256', 'served_html_sha256', 'staging_robots_header_sha256', 'recipient_hmac_sha256',
    'synthetic_probe_sha256', 'inbox_account_hmac_sha256', 'inbox_message_id_hmac_sha256', 'inbox_receipt_evidence_sha256',
  ];
  for (const field of digestFields) sha256(value[field], field);

  const bindings = {
    preview_folder: record.preview_folder,
    production_content_sha256: record.production_content_sha256,
    artifact_manifest_sha256: record.artifact_manifest_sha256,
    handoff_artifact_evidence_sha256: record.artifact_evidence_sha256,
    bundle_fingerprint: record.bundle_fingerprint,
    netlify_account_id: record.netlify_source_account_id,
    staging_site_id: record.netlify_site_id,
    staging_deploy_id: record.preclaim_deploy_id,
    staging_form_id: record.form_id,
    notification_hook_id: record.hook_id,
    form_name: record.form_name,
    recipient_hmac_sha256: record.lead_route_recipient_hmac_sha256,
  };
  for (const [field, expected] of Object.entries(bindings)) {
    if (typeof expected !== 'string' || !safeEqual(value[field], expected)) throw new TypeError('Lead-route producer evidence binding mismatch.');
  }
  const expectedSiteUrl = canonicalNetlifySiteUrl(record.netlify_site_name);
  const expectedDeployUrl = `https://${record.preclaim_deploy_id}--${record.netlify_site_name}.netlify.app/`;
  if (plainHttpsRoot(value.staging_site_url, 'Lead-route producer staging site URL') !== expectedSiteUrl ||
      plainHttpsRoot(value.staging_deploy_url, 'Lead-route producer staging deploy URL') !== expectedDeployUrl) {
    throw new TypeError('Lead-route producer URL binding mismatch.');
  }

  const submissionAt = Date.parse(iso(value.netlify_submission_timestamp, 'Lead-route producer Netlify submission timestamp'));
  const receivedAt = Date.parse(iso(value.inbox_received_timestamp, 'Lead-route producer inbox received timestamp'));
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || submissionAt > receivedAt || receivedAt - submissionAt > PRODUCER_SOURCE_FRESHNESS_MS ||
      (options.enforceFreshness !== false && (receivedAt > nowMs + 60_000 || receivedAt < nowMs - RECEIPT_FRESHNESS_MS ||
        submissionAt < nowMs - PRODUCER_SOURCE_FRESHNESS_MS))) {
    throw new TypeError('Lead-route producer evidence is stale or out of order.');
  }

  const normalized = {
    version: LEAD_ROUTE_RECEIPT_VERSION,
    scope: LEAD_ROUTE_RECEIPT_SCOPE,
    handoff_id: record.handoff_id,
    netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
    form_id_sha256: sha256Hex(record.form_id),
    hook_id_sha256: sha256Hex(record.hook_id),
    recipient_email_sha256: record.lead_notification_email_sha256,
    provider_message_id_sha256: sha256Hex(value.inbox_message_id_hmac_sha256),
    inbox_receipt_id_sha256: value.inbox_receipt_evidence_sha256,
    received_at: value.inbox_received_timestamp,
    issued_at: value.inbox_received_timestamp,
  };
  return { canonical: canonicalJson(normalized), digest: sha256Hex(raw), value: normalized };
}

function normalizeLeadRouteReceipt(raw, signature, record, env, now, options = {}) {
  if (typeof raw !== 'string' || raw.length < 2 || raw.length > 20_000) throw new TypeError('Lead-route receipt evidence is invalid.');
  const value = JSON.parse(raw);
  if (value?.version === PRODUCER_LEAD_ROUTE_VERSION && value?.scope === PRODUCER_LEAD_ROUTE_SCOPE) {
    return normalizeProducerLeadRouteReceipt(raw, value, signature, record, env, now, options);
  }
  return normalizeLegacyLeadRouteReceipt(raw, value, signature, record, env, now, options);
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
  // The committed producer can address only arc-lead-route-* sites. An older
  // namespace record that never reached invitation readiness has no valid
  // receipt path, so reject it before parsing evidence or changing state.
  rejectQuarantinedLegacyNamespace(entry.record);
  const observedAt = clock();
  // Replays re-check the exact source signature, shape, ordering, and durable
  // bindings, but do not pretend an already-bound receipt was newly observed.
  const receipt = normalizeLeadRouteReceipt(evidence, signature, entry.record, env, observedAt, {
    enforceFreshness: entry.record.lead_route_receipt_sha256 === null,
  });
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

function normalizeFinalDeliveryReceipt(raw, signature, record, env, now, options = {}) {
  if (typeof raw !== 'string' || raw.length < 2 || raw.length > 20_000) {
    throw new TypeError('Final delivery receipt evidence is invalid.');
  }
  const value = JSON.parse(raw);
  if (!exactObjectKeys(value, FINAL_DELIVERY_RECEIPT_FIELDS) || canonicalJson(value) !== raw ||
      value.version !== FINAL_DELIVERY_RECEIPT_VERSION || value.scope !== FINAL_DELIVERY_RECEIPT_SCOPE) {
    throw new TypeError('Final delivery receipt fields are invalid.');
  }
  const receiptSecret = env.ARC_FINAL_DELIVERY_RECEIPT_SECRET;
  if (typeof receiptSecret !== 'string' || receiptSecret.length < 32 || receiptSecret.length > 512 ||
      receiptSecret === env.ARC_EMAIL_CLAIM_BINDING_SECRET || receiptSecret === env.ARC_HANDOFF_TRIGGER_SECRET ||
      receiptSecret === env.ARC_CLAIM_STATE_EVIDENCE_SECRET || receiptSecret === env.ARC_FINAL_DELIVERY_ACK_SECRET) {
    throw new TypeError('Final delivery receipt secret is unavailable or not distinct.');
  }
  const suppliedSignature = sha256(signature, 'Final delivery receipt signature');
  if (!safeEqual(suppliedSignature, hmacHex(receiptSecret, `${FINAL_DELIVERY_RECEIPT_SIGNATURE_PREFIX}${raw}`))) {
    throw new TypeError('Final delivery receipt signature mismatch.');
  }
  if (typeof value.provider !== 'string' || !/^[a-z0-9][a-z0-9_.-]{1,63}$/.test(value.provider) ||
      value.delivery_status !== 'delivered' || value.event_type !== 'message.delivered') {
    throw new TypeError('Final delivery provider, status, or event type is invalid.');
  }
  sha256(value.provider_account_hmac_sha256, 'provider_account_hmac_sha256');
  for (const [field, label] of [['provider_event_id', 'event'], ['provider_message_id', 'message']]) {
    if (typeof value[field] !== 'string' || value[field].length < 1 || value[field].length > 512 ||
        value[field] !== value[field].trim() || /[\u0000-\u001f\u007f]/.test(value[field])) {
      throw new TypeError(`Final delivery provider ${label} id is invalid.`);
    }
  }
  const expectedBindings = {
    handoff_id: record.handoff_id,
    outbox_claim_key_hmac_sha256: record.outbox_claim_key_hmac_sha256,
    recipient_email_sha256: record.customer_email_sha256,
    production_url_sha256: sha256Hex(normalizeProductionUrl(record.production_url)),
    netlify_deploy_id_sha256: sha256Hex(record.final_deploy_id),
    netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
  };
  for (const [field, expected] of Object.entries(expectedBindings)) {
    sha256(value[field], field);
    if (!safeEqual(value[field], expected)) throw new TypeError('Final delivery receipt binding mismatch.');
  }
  const receiptTimestamp = (timestamp, label) => {
    if (typeof timestamp !== 'string') throw new TypeError(`${label} is invalid.`);
    const parsed = Date.parse(timestamp);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== timestamp) throw new TypeError(`${label} is invalid.`);
    return parsed;
  };
  const deliveredAt = receiptTimestamp(value.delivered_at, 'Final delivery delivered_at');
  const issuedAt = receiptTimestamp(value.issued_at, 'Final delivery issued_at');
  const finalReadyAt = receiptTimestamp(record.final_deploy_ready_at, 'Final deploy ready timestamp');
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || deliveredAt < finalReadyAt || deliveredAt > issuedAt ||
      issuedAt - deliveredAt > RECEIPT_FRESHNESS_MS ||
      (options.enforceFreshness !== false && (issuedAt > nowMs + 60_000 || issuedAt < nowMs - RECEIPT_FRESHNESS_MS))) {
    throw new TypeError('Final delivery receipt is stale or out of order.');
  }
  return {
    canonical: raw,
    digest: sha256Hex(raw),
    providerEventIdHmacSha256: hmacHex(receiptSecret, `${FINAL_DELIVERY_PROVIDER_EVENT_ID_PREFIX}${canonicalJson({
      provider: value.provider,
      provider_account_hmac_sha256: value.provider_account_hmac_sha256,
      provider_event_id: value.provider_event_id,
    })}`),
    providerMessageIdHmacSha256: hmacHex(receiptSecret, `${FINAL_DELIVERY_PROVIDER_MESSAGE_ID_PREFIX}${canonicalJson({
      provider: value.provider,
      provider_account_hmac_sha256: value.provider_account_hmac_sha256,
      provider_message_id: value.provider_message_id,
    })}`),
    issuedAt,
    value,
  };
}

function finalDeliveryIdentityReservations(record, receipt) {
  const common = {
    handoff_id: record.handoff_id,
    delivery_receipt_sha256: receipt.digest,
    provider: receipt.value.provider,
    provider_account_hmac_sha256: receipt.value.provider_account_hmac_sha256,
  };
  return [{
    key: `final-delivery-provider-event/${receipt.providerEventIdHmacSha256}`,
    value: {
      schema: FINAL_DELIVERY_EVENT_INDEX_SCHEMA,
      kind: 'provider-event',
      ...common,
      identity_hmac_sha256: receipt.providerEventIdHmacSha256,
    },
  }, {
    key: `final-delivery-provider-message/${receipt.providerMessageIdHmacSha256}`,
    value: {
      schema: FINAL_DELIVERY_MESSAGE_INDEX_SCHEMA,
      kind: 'provider-message',
      ...common,
      identity_hmac_sha256: receipt.providerMessageIdHmacSha256,
    },
  }];
}

function finalDeliveryOutboxValues(record, receipt) {
  const common = {
    schema: OUTBOX_CLAIM_VERSION,
    handoff_id: record.handoff_id,
    netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
    netlify_deploy_id_sha256: sha256Hex(record.final_deploy_id),
    outbox_claim_key_hmac_sha256: record.outbox_claim_key_hmac_sha256,
  };
  const receiptBinding = {
    delivery_receipt_sha256: receipt.digest,
    provider: receipt.value.provider,
    provider_account_hmac_sha256: receipt.value.provider_account_hmac_sha256,
    provider_event_id_hmac_sha256: receipt.providerEventIdHmacSha256,
    provider_message_id_hmac_sha256: receipt.providerMessageIdHmacSha256,
    event_type: receipt.value.event_type,
    delivery_status: receipt.value.delivery_status,
    delivered_at: receipt.value.delivered_at,
    receipt_issued_at: receipt.value.issued_at,
  };
  return {
    key: `outbox/${record.outbox_claim_key_hmac_sha256}`,
    claimed: { ...common, status: 'CLAIMED' },
    pending: { ...common, status: 'DELIVERY_ACK_PENDING', ...receiptBinding },
    delivered: {
      ...common,
      status: 'DELIVERED',
      ...receiptBinding,
    },
  };
}

function exactStoredValue(actual, expected) {
  return actual && canonicalJson(actual) === canonicalJson(expected);
}

async function inspectFinalDeliveryReservations(store, reservations) {
  let found = false;
  for (const reservation of reservations) {
    const existing = await readIndex(store, reservation.key);
    if (existing && !exactStoredValue(existing, reservation.value)) throw new Error('ARC2_FINAL_DELIVERY_IDENTITY_CONFLICT');
    if (existing) found = true;
  }
  return found;
}

async function inspectFinalDeliveryOutbox(store, values) {
  const entry = await readIndexEntry(store, values.key);
  if (!entry) throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_MISSING');
  if (exactStoredValue(entry.value, values.delivered)) return { entry, status: 'DELIVERED' };
  if (exactStoredValue(entry.value, values.pending)) return { entry, status: 'DELIVERY_ACK_PENDING' };
  if (exactStoredValue(entry.value, values.claimed)) return { entry, status: 'CLAIMED' };
  throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_CONFLICT');
}

async function makeFinalDeliveryOutboxPending(store, values) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const current = await inspectFinalDeliveryOutbox(store, values);
    if (current.status !== 'CLAIMED') return current;
    try {
      const entry = await replaceIndex(store, values.key, current.entry, values.pending);
      return { entry, status: 'DELIVERY_ACK_PENDING' };
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 2) throw error;
    }
  }
  throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_CONFLICT');
}

async function makeFinalDeliveryOutboxTerminal(store, values) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const current = await inspectFinalDeliveryOutbox(store, values);
    if (current.status === 'DELIVERED') return current.entry;
    if (current.status !== 'DELIVERY_ACK_PENDING') throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_CONFLICT');
    try {
      return await replaceIndex(store, values.key, current.entry, values.delivered);
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 2) throw error;
    }
  }
  throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_CONFLICT');
}

function finalDeliveryMatchesRecord(record, receipt) {
  return record.state === 'DELIVERED' &&
    safeEqual(record.final_delivery_receipt_sha256, receipt.digest) &&
    record.final_delivery_provider === receipt.value.provider &&
    safeEqual(record.final_delivery_provider_account_hmac_sha256, receipt.value.provider_account_hmac_sha256) &&
    safeEqual(record.final_delivery_provider_event_id_hmac_sha256, receipt.providerEventIdHmacSha256) &&
    safeEqual(record.final_delivery_provider_message_id_hmac_sha256, receipt.providerMessageIdHmacSha256) &&
    record.final_delivery_event_type === receipt.value.event_type &&
    record.final_delivery_status === receipt.value.delivery_status &&
    record.delivered_at === receipt.value.delivered_at &&
    record.final_delivery_receipt_issued_at === receipt.value.issued_at;
}

export async function acknowledgeFinalDelivery(handoffId, evidence, signature, env, adapters = {}) {
  const key = handoffKeyFromId(handoffId);
  const clock = adapters.clock || (() => new Date());
  let entry = await readEntry(adapters.store, key);
  if (!entry) return null;
  if (!['FINAL_DEPLOY_READY', 'DELIVERED'].includes(entry.record.state)) throw new Error('ARC2_FINAL_DELIVERY_STATE_CONFLICT');
  const receipt = normalizeFinalDeliveryReceipt(evidence, signature, entry.record, env, clock(), { enforceFreshness: false });
  if (entry.record.state === 'DELIVERED' && !finalDeliveryMatchesRecord(entry.record, receipt)) {
    throw new Error('ARC2_FINAL_DELIVERY_RECEIPT_CONFLICT');
  }
  const reservations = finalDeliveryIdentityReservations(entry.record, receipt);
  const outboxValues = finalDeliveryOutboxValues(entry.record, receipt);
  await inspectFinalDeliveryReservations(adapters.store, reservations);
  const outboxBefore = await inspectFinalDeliveryOutbox(adapters.store, outboxValues);
  const durablyBound = outboxBefore.status !== 'CLAIMED' || entry.record.state === 'DELIVERED';
  if (!durablyBound) {
    normalizeFinalDeliveryReceipt(evidence, signature, entry.record, env, clock(), { enforceFreshness: true });
  }

  // First bind this handoff/outbox to one exact signed receipt. Competing
  // receipts cannot reserve provider identities for the same handoff.
  await makeFinalDeliveryOutboxPending(adapters.store, outboxValues);
  for (const reservation of reservations) await ensureImmutableIndex(adapters.store, reservation.key, reservation.value);

  // Blob keys cannot be committed atomically. DELIVERY_ACK_PENDING is the
  // receipt lock/no-resend latch; DELIVERED is terminal. A retry converges the
  // provider reservations, terminal outbox, and handoff before success.
  await makeFinalDeliveryOutboxTerminal(adapters.store, outboxValues);
  if (entry.record.state === 'DELIVERED') return { handoffId, record: entry.record, idempotentReplay: true };

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const delivered = transitionRecord(entry.record, 'DELIVERED', {
      delivered_at: receipt.value.delivered_at,
      final_delivery_receipt_sha256: receipt.digest,
      final_delivery_provider: receipt.value.provider,
      final_delivery_provider_account_hmac_sha256: receipt.value.provider_account_hmac_sha256,
      final_delivery_provider_event_id_hmac_sha256: receipt.providerEventIdHmacSha256,
      final_delivery_provider_message_id_hmac_sha256: receipt.providerMessageIdHmacSha256,
      final_delivery_event_type: receipt.value.event_type,
      final_delivery_status: receipt.value.delivery_status,
      final_delivery_receipt_issued_at: receipt.value.issued_at,
    }, clock());
    try {
      entry = await replaceEntry(adapters.store, key, entry, delivered);
      return { handoffId, record: entry.record, idempotentReplay: false };
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 2) throw error;
      entry = await readEntry(adapters.store, key);
      if (!entry) throw new Error('ARC2_FINAL_DELIVERY_STATE_CONFLICT');
      if (entry.record.state === 'DELIVERED') {
        if (!finalDeliveryMatchesRecord(entry.record, receipt)) throw new Error('ARC2_FINAL_DELIVERY_RECEIPT_CONFLICT');
        return { handoffId, record: entry.record, idempotentReplay: true };
      }
      if (entry.record.state !== 'FINAL_DEPLOY_READY') throw new Error('ARC2_FINAL_DELIVERY_STATE_CONFLICT');
    }
  }
  throw new Error('ARC2_FINAL_DELIVERY_STATE_CONFLICT');
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
  version: LEAD_ROUTE_RECEIPT_VERSION,
  scope: LEAD_ROUTE_RECEIPT_SCOPE,
  signaturePrefix: LEAD_ROUTE_RECEIPT_PREFIX,
  producerVersion: PRODUCER_LEAD_ROUTE_VERSION,
  producerScope: PRODUCER_LEAD_ROUTE_SCOPE,
  producerSignaturePrefix: PRODUCER_LEAD_ROUTE_PREFIX,
});

export const finalDeliveryReceiptContract = Object.freeze({
  version: FINAL_DELIVERY_RECEIPT_VERSION,
  scope: FINAL_DELIVERY_RECEIPT_SCOPE,
  signaturePrefix: FINAL_DELIVERY_RECEIPT_SIGNATURE_PREFIX,
  fields: FINAL_DELIVERY_RECEIPT_FIELDS,
});
