import {
  createClaimableSite,
  createClaimStateEvidence,
  createInitialRecord,
  createStoredZip,
  deployZip,
  ensureEmailHook,
  findNetlifyForm,
  handoffIdFromKey,
  handoffKey,
  handoffKeyFromId,
  normalizeClaimWebhook,
  normalizeStartPayload,
  pollDeployReady,
  publicStatus,
  reviseRecord,
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
  replaceEntry,
} from './arc2-handoff-store.mjs';

const waitForNetlify = (attempt) => new Promise((resolve) => setTimeout(resolve, Math.min(250 * (2 ** attempt), 3000)));

function exactReplay(record, normalized) {
  return record.payment_evidence_sha256 === normalized.payment.digest &&
    record.artifact_evidence_sha256 === normalized.artifact.digest &&
    record.bundle_fingerprint === normalized.artifact.value.bundle_fingerprint &&
    record.lead_notification_email_sha256 === normalized.leadEmailHash &&
    record.form_name === normalized.formName;
}

async function ensureImmutableIndex(store, key, value) {
  const existing = await readIndex(store, key);
  if (existing) {
    if (JSON.stringify(existing) !== JSON.stringify(value)) throw new Error('ARC2_INDEX_CONFLICT');
    return existing;
  }
  try {
    await createIndex(store, key, value);
    return value;
  } catch (error) {
    if (error.message !== 'ARC2_INDEX_CONFLICT') throw error;
    const raced = await readIndex(store, key);
    if (!raced || JSON.stringify(raced) !== JSON.stringify(value)) throw error;
    return raced;
  }
}

export async function startHandoff(input, env, adapters = {}) {
  const clock = adapters.clock || (() => new Date());
  const fetchImpl = adapters.fetch || fetch;
  const wait = adapters.wait || waitForNetlify;
  const normalized = normalizeStartPayload(input, env, clock());
  normalized.leadEmailHash = sha256Hex(normalized.leadEmail);
  const key = handoffKey(normalized.payment.value, env.ARC_HANDOFF_STATE_SECRET);
  const handoffId = handoffIdFromKey(key);
  let entry = await readEntry(adapters.store, key);
  if (entry) {
    if (!exactReplay(entry.record, normalized)) throw new Error('ARC2_IDEMPOTENCY_CONFLICT');
    return { handoffId, record: entry.record, idempotentReplay: true };
  }

  const initial = createInitialRecord(normalized, env, key, clock(), { uuid: adapters.uuid });
  entry = await createEntry(adapters.store, key, initial.record);
  if (!entry) {
    entry = await readEntry(adapters.store, key);
    if (!entry || !exactReplay(entry.record, normalized)) throw new Error('ARC2_IDEMPOTENCY_CONFLICT');
    return { handoffId, record: entry.record, idempotentReplay: true };
  }
  entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'SITE_INTENT', {}, clock()));

  const site = await createClaimableSite(entry.record, env, fetchImpl);
  const createdAt = clock();
  const index = {
    schema: 'arc2-site-index-v1',
    handoff_id: handoffId,
    netlify_site_id: site.id,
    netlify_session_id: entry.record.netlify_session_id,
  };
  await ensureImmutableIndex(adapters.store, siteIndexKey(site.id), index);
  entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'SITE_CREATED', {
    netlify_site_id: site.id,
    site_created_at: createdAt.toISOString(),
  }, clock()));

  const zip = createStoredZip(normalized.deployArtifacts);
  const deploy = await deployZip(site.id, zip, `ARC handoff ${handoffId.slice(0, 12)}`, env, fetchImpl);
  const ready = await pollDeployReady(site.id, deploy.id, env, fetchImpl, { wait });
  entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'PRECLAIM_DEPLOY_READY', {
    preclaim_deploy_id: ready.id,
  }, clock()));

  const form = await findNetlifyForm(site.id, normalized.formName, env, fetchImpl, { wait });
  const hook = await ensureEmailHook(site.id, form.id, normalized.leadEmail, env, fetchImpl);
  await verifyNetlifyHandoff(entry.record, {
    accountId: env.NETLIFY_TEAM_ACCOUNT_ID,
    artifacts: entry.record.artifacts,
    deployId: ready.id,
    formId: form.id,
    formName: normalized.formName,
    hookId: hook.id,
    leadEmailSha256: entry.record.lead_notification_email_sha256,
  }, env, fetchImpl);
  entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, {
    form_id: form.id,
    hook_id: hook.id,
  }, clock()));
  return { handoffId, record: entry.record, idempotentReplay: false };
}

export async function markClaimInvitationSent(handoffId, providerMessageIdSha256, env, adapters = {}) {
  handoffKeyFromId(handoffId);
  void providerMessageIdSha256;
  void env;
  void adapters;
  throw new Error('ARC2_LEAD_ROUTE_EVIDENCE_ENDPOINT_NOT_IMPLEMENTED');
}

async function verifyRecord(record, deployId, accountId, env, fetchImpl) {
  return verifyNetlifyHandoff(record, {
    accountId,
    artifacts: record.artifacts,
    deployId,
    formId: record.form_id,
    formName: record.form_name,
    hookId: record.hook_id,
    leadEmailSha256: record.lead_notification_email_sha256,
  }, env, fetchImpl);
}

export async function processClaimWebhook(input, env, adapters = {}) {
  const hint = normalizeClaimWebhook(input);
  const index = await readIndex(adapters.store, siteIndexKey(hint.siteId));
  if (!index || index.netlify_site_id !== hint.siteId) throw new Error('ARC2_UNKNOWN_CLAIM_SITE');
  const key = handoffKeyFromId(index.handoff_id);
  const entry = await readEntry(adapters.store, key);
  if (!entry || entry.record.netlify_site_id !== hint.siteId || entry.record.netlify_session_id !== index.netlify_session_id ||
      hint.destinationAccountId === entry.record.netlify_source_account_id) throw new Error('ARC2_CLAIM_BINDING_FAILED');

  if (entry.record.state !== 'CLAIM_INVITED') {
    throw new Error('ARC2_CLAIM_STATE_CONFLICT');
  }
  // Netlify documents the callback as unsigned and does not document that the
  // creator PAT retains post-claim read access. A separate customer-authorized
  // readback credential or a verified partner capability is required here. Do
  // not mutate state from this replayable hint: a spoof must not poison or
  // consume the real callback path. Ownership and final delivery stay blocked.
  throw new Error('ARC2_POSTCLAIM_REVERIFY_NOT_CONFIGURED');
}

export async function getHandoffStatus(handoffId, env, adapters = {}) {
  const clock = adapters.clock || (() => new Date());
  const entry = await readEntry(adapters.store, handoffKeyFromId(handoffId));
  if (!entry) return null;
  const record = validateExpectedBindings(entry.record);
  return {
    ...publicStatus(record, clock()),
    ...(record.state === 'FINAL_DEPLOY_READY' ? createClaimStateEvidence(record, env, clock()) : {}),
  };
}
