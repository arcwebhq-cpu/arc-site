import {
  canonicalJson,
  hmacHex,
  safeEqual,
  sha256Hex,
} from './arc2-handoff-core.mjs';

export const RETENTION_CONTROL_STORE = 'arc-retention-control';
export const RETENTION_MANIFEST_SCHEMA = 'arc-retention-manifest-v1';
export const RETENTION_MANIFEST_SCOPE = 'adult-reviewed-first-party-deletion-manifest';
export const RETENTION_MANIFEST_PREFIX = 'arc-retention-manifest-signature-v1\n';
export const RETENTION_ADULT_APPROVAL_PREFIX = 'arc-retention-adult-approval-v1\n';
export const RETENTION_RUN_SCHEMA = 'arc-retention-run-v1';
export const RETENTION_INTENT_SCHEMA = 'arc-retention-delete-intent-v1';
export const RETENTION_TOMBSTONE_SCHEMA = 'arc-retention-record-tombstone-v1';
export const RETENTION_TOMBSTONE_CLAIM_SCHEMA = 'arc-retention-tombstone-claim-v1';
export const RETENTION_RECEIPT_SCHEMA = 'arc-retention-delete-receipt-v1';
export const RETENTION_COMPLETION_SCHEMA = 'arc-retention-run-completion-v1';
export const RETENTION_POLICY_VERSION = '2026-08-13';
export const UNPAID_PREVIEW_RETENTION_DAYS = 730;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const INTAKE_KEY = /^submissions\/([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/;
const MANIFEST_FIELDS = Object.freeze([
  'adult_approval_hmac_sha256',
  'dry_run_id',
  'dry_run_manifest_sha256',
  'issued_at',
  'mode',
  'policy_version',
  'run_id',
  'scope',
  'targets',
  'version',
]);
const TARGET_FIELDS = Object.freeze(['key', 'last_interaction_at', 'record_sha256', 'retention_class', 'store']);
const INTENT_FIELDS = Object.freeze([
  'adult_approval_hmac_sha256',
  'authorized_at',
  'delete_not_before',
  'dry_run_id',
  'dry_run_manifest_sha256',
  'last_interaction_at',
  'manifest_sha256',
  'mode',
  'policy_version',
  'record_sha256',
  'retention_class',
  'run_id',
  'schema',
  'target_hmac_sha256',
  'target_set_sha256',
  'target_store',
]);
const RECEIPT_FIELDS = Object.freeze([
  'customer_data_stored',
  'deleted_at',
  'deletion_intent_sha256',
  'manifest_sha256',
  'policy_version',
  'record_sha256',
  'run_id',
  'schema',
  'target_hmac_sha256',
  'target_store',
]);

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  return value;
}

function exactKeys(value, fields, label) {
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) throw new TypeError(`${label} fields are invalid.`);
}

function isoTimestamp(value, label) {
  if (typeof value !== 'string') throw new TypeError(`${label} is invalid.`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return parsed;
}

function validSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}

function exactStored(left, right) {
  return left && canonicalJson(left) === canonicalJson(right);
}

async function getEntry(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  return entry ? { value: entry.data, etag: entry.etag } : null;
}

async function ensureImmutable(store, key, value) {
  const existing = await getEntry(store, key);
  if (existing) {
    if (!exactStored(existing.value, value)) throw new Error('ARC_RETENTION_INDEX_CONFLICT');
    return { created: false, value: existing.value };
  }
  const result = await store.setJSON(key, value, { onlyIfNew: true });
  if (result?.modified && result.etag) return { created: true, value };
  const raced = await getEntry(store, key);
  if (!raced || !exactStored(raced.value, value)) throw new Error('ARC_RETENTION_INDEX_CONFLICT');
  return { created: false, value: raced.value };
}

function runKey(runId) {
  if (!UUID.test(runId)) throw new TypeError('Retention run id is invalid.');
  return `runs/${runId}`;
}

function completionKey(runId) {
  if (!UUID.test(runId)) throw new TypeError('Retention run id is invalid.');
  return `completions/${runId}`;
}

function targetHmac(target, env) {
  return hmacHex(env.ARC_RETENTION_RECORD_HMAC_SECRET, `retention-target-v1\n${target.store}\n${target.key}`);
}

function legalHoldKey(target, env) {
  return `legal-holds/${targetHmac(target, env)}`;
}

function intentKey(target, manifestDigest, env) {
  return `delete-intents/${targetHmac(target, env)}/${manifestDigest}`;
}

function receiptKey(target, manifestDigest, env) {
  return `delete-receipts/${targetHmac(target, env)}/${manifestDigest}`;
}

function tombstoneClaimKey(target, manifestDigest, env) {
  return `tombstone-claims/${targetHmac(target, env)}/${manifestDigest}`;
}

export function retentionConfiguration(env = process.env) {
  const enabled = env.ARC_RETENTION_CLEANUP_ENABLED === 'true';
  const executionMode = String(env.ARC_RETENTION_EXECUTION_MODE || 'disabled');
  const modeValid = ['dry-run', 'apply'].includes(executionMode);
  const secrets = [
    env.ARC_RETENTION_CLEANUP_SECRET,
    env.ARC_RETENTION_MANIFEST_SECRET,
    env.ARC_RETENTION_RECORD_HMAC_SECRET,
    env.ARC_RETENTION_ADULT_APPROVAL_SECRET,
  ];
  const secretValues = secrets.filter(validSecret);
  const otherSecretNames = [
    'ARC_HANDOFF_TRIGGER_SECRET', 'ARC_HANDOFF_STATE_SECRET', 'ARC_CHECKOUT_BINDING_SECRET',
    'ARC_CLAIM_TOKEN_SECRET', 'ARC_EMAIL_CLAIM_BINDING_SECRET', 'ARC_FINAL_DELIVERY_ACK_SECRET',
    'ARC_FINAL_DELIVERY_RECEIPT_SECRET', 'ARC_OPERATIONS_AUDIT_SECRET', 'ARC_OPERATIONS_ALERT_HMAC_SECRET',
    'ARC_STRIPE_WEBHOOK_SIGNING_SECRET', 'ARC_STRIPE_REVERSAL_HMAC_SECRET',
    'ARC_STRIPE_REVERSAL_BINDING_SECRET', 'ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET',
    'ARC_STRIPE_REVERSAL_RECHECK_SECRET', 'ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET',
  ];
  const crossSecretCollision = otherSecretNames.some((name) => validSecret(env[name]) && secretValues.includes(env[name]));
  const secretsValid = secretValues.length === secrets.length && new Set(secretValues).size === secretValues.length && !crossSecretCollision;
  const applyAttestationsValid = env.ARC_RETENTION_ADULT_OPERATOR_VERIFIED === 'true' &&
    env.ARC_RETENTION_LEGAL_HOLD_CHECK_VERIFIED === 'true' && env.ARC_RETENTION_DELETION_VERIFIED === 'true';
  return { applyAttestationsValid, enabled: enabled && modeValid && secretsValid, executionMode, modeValid, secretsValid };
}

function normalizeTarget(raw) {
  const target = plainObject(raw, 'Retention target');
  exactKeys(target, TARGET_FIELDS, 'Retention target');
  const match = typeof target.key === 'string' ? target.key.match(INTAKE_KEY) : null;
  if (target.store !== 'arc-intake-submissions' || !match || target.retention_class !== 'unpaid-preview' ||
      !HEX_64.test(target.record_sha256)) throw new TypeError('Retention target is not allowlisted.');
  const lastInteractionMs = isoTimestamp(target.last_interaction_at, 'Retention target last_interaction_at');
  return { ...target, lastInteractionMs, submissionId: match[1] };
}

function normalizeManifest(raw, signature, env, now = new Date(), options = {}) {
  const config = retentionConfiguration(env);
  if (!config.enabled) throw new Error('ARC_RETENTION_CLEANUP_DISABLED');
  if (typeof raw !== 'string' || raw.length < 2 || raw.length > 200_000) throw new TypeError('Retention manifest is invalid.');
  const value = plainObject(JSON.parse(raw), 'Retention manifest');
  exactKeys(value, MANIFEST_FIELDS, 'Retention manifest');
  if (canonicalJson(value) !== raw || value.version !== RETENTION_MANIFEST_SCHEMA || value.scope !== RETENTION_MANIFEST_SCOPE ||
      value.policy_version !== RETENTION_POLICY_VERSION || !UUID.test(value.run_id) || !['dry-run', 'apply'].includes(value.mode) ||
      !Array.isArray(value.targets) || value.targets.length < 1 || value.targets.length > 100) {
    throw new TypeError('Retention manifest is invalid.');
  }
  if (value.mode === 'apply' && (config.executionMode !== 'apply' || !config.applyAttestationsValid)) {
    throw new Error('ARC_RETENTION_APPLY_DISABLED');
  }
  if (value.mode === 'dry-run') {
    if (value.dry_run_id !== null || value.dry_run_manifest_sha256 !== null || value.adult_approval_hmac_sha256 !== null) {
      throw new TypeError('Dry-run retention manifest cannot assert an apply approval.');
    }
  } else if (!UUID.test(value.dry_run_id) || !HEX_64.test(value.dry_run_manifest_sha256) ||
      !HEX_64.test(value.adult_approval_hmac_sha256) || value.dry_run_id === value.run_id) {
    throw new TypeError('Apply retention manifest approval binding is invalid.');
  }
  const targets = value.targets.map(normalizeTarget);
  const targetOrder = targets.map((target) => `${target.store}\n${target.key}`);
  if (new Set(targetOrder).size !== targetOrder.length || targetOrder.some((item, index) => index > 0 && item <= targetOrder[index - 1])) {
    throw new TypeError('Retention targets must be unique and sorted.');
  }
  const issuedAt = isoTimestamp(value.issued_at, 'Retention manifest issued_at');
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || issuedAt > nowMs + 60_000 ||
      (options.enforceFreshness !== false && issuedAt < nowMs - 10 * 60_000)) {
    throw new TypeError('Retention manifest is stale or from the future.');
  }
  const targetSetDigest = sha256Hex(canonicalJson(value.targets));
  if (value.mode === 'apply') {
    const approval = canonicalJson({
      apply_run_id: value.run_id,
      dry_run_id: value.dry_run_id,
      dry_run_manifest_sha256: value.dry_run_manifest_sha256,
      policy_version: value.policy_version,
      target_set_sha256: targetSetDigest,
    });
    if (!safeEqual(value.adult_approval_hmac_sha256, hmacHex(
      env.ARC_RETENTION_ADULT_APPROVAL_SECRET,
      `${RETENTION_ADULT_APPROVAL_PREFIX}${approval}`,
    ))) throw new TypeError('Retention adult approval signature mismatch.');
  }
  if (!HEX_64.test(signature) || !safeEqual(signature, hmacHex(env.ARC_RETENTION_MANIFEST_SECRET, `${RETENTION_MANIFEST_PREFIX}${raw}`))) {
    throw new TypeError('Retention manifest signature mismatch.');
  }
  return { canonical: raw, digest: sha256Hex(raw), targetSetDigest, targets, value };
}

function runReservation(manifest) {
  return {
    schema: RETENTION_RUN_SCHEMA,
    run_id: manifest.value.run_id,
    mode: manifest.value.mode,
    policy_version: manifest.value.policy_version,
    manifest_sha256: manifest.digest,
    target_set_sha256: manifest.targetSetDigest,
    dry_run_id: manifest.value.dry_run_id,
    dry_run_manifest_sha256: manifest.value.dry_run_manifest_sha256,
    adult_approval_hmac_sha256: manifest.value.adult_approval_hmac_sha256,
    issued_at: manifest.value.issued_at,
    target_count: manifest.targets.length,
  };
}

function validateIntakeRecord(target, record, now) {
  if (!record || typeof record !== 'object' || Array.isArray(record) || record.schema !== 'arc-intake-function-submission-v1' ||
      record.submission_id !== target.submissionId || record.arc1_consumer_compatible !== false ||
      sha256Hex(canonicalJson(record)) !== target.record_sha256) throw new Error('ARC_RETENTION_TARGET_CHANGED');
  const hasDelivery = Object.prototype.hasOwnProperty.call(record, 'arc1_delivery');
  const hasDispatch = Object.prototype.hasOwnProperty.call(record, 'arc1_dispatch');
  if (hasDelivery !== hasDispatch || (hasDelivery && (
    record.arc1_delivery?.status !== 'PENDING' || record.arc1_delivery?.attempt_count !== 0 ||
    record.arc1_delivery?.alert_status !== 'NONE' || record.arc1_delivery?.alert_code !== null ||
    record.arc1_dispatch?.status !== 'PENDING' || record.arc1_dispatch?.attempt_count !== 0 ||
    record.arc1_dispatch?.alert_status !== 'NONE' || record.arc1_dispatch?.alert_code !== null
  ))) throw new Error('ARC_RETENTION_TARGET_HAS_DELIVERY_HISTORY');
  const receivedAt = isoTimestamp(record.received_at, 'Intake received_at');
  if (target.lastInteractionMs < receivedAt) throw new Error('ARC_RETENTION_INTERACTION_ORDER_INVALID');
  const deleteNotBefore = target.lastInteractionMs + UNPAID_PREVIEW_RETENTION_DAYS * 86_400_000;
  if (now.getTime() < deleteNotBefore) throw new Error('ARC_RETENTION_TARGET_NOT_EXPIRED');
  return new Date(deleteNotBefore).toISOString();
}

function deleteIntent(target, manifest, deleteNotBefore, env) {
  return {
    schema: RETENTION_INTENT_SCHEMA,
    run_id: manifest.value.run_id,
    mode: 'apply',
    policy_version: manifest.value.policy_version,
    manifest_sha256: manifest.digest,
    target_set_sha256: manifest.targetSetDigest,
    dry_run_id: manifest.value.dry_run_id,
    dry_run_manifest_sha256: manifest.value.dry_run_manifest_sha256,
    adult_approval_hmac_sha256: manifest.value.adult_approval_hmac_sha256,
    target_store: target.store,
    target_hmac_sha256: targetHmac(target, env),
    record_sha256: target.record_sha256,
    retention_class: target.retention_class,
    last_interaction_at: target.last_interaction_at,
    delete_not_before: deleteNotBefore,
    authorized_at: manifest.value.issued_at,
  };
}

export function validateRetentionDeleteIntent(value) {
  plainObject(value, 'Retention delete intent');
  exactKeys(value, INTENT_FIELDS, 'Retention delete intent');
  if (value.schema !== RETENTION_INTENT_SCHEMA || value.mode !== 'apply' || value.policy_version !== RETENTION_POLICY_VERSION ||
      !UUID.test(value.run_id) || !UUID.test(value.dry_run_id) || value.run_id === value.dry_run_id ||
      !HEX_64.test(value.manifest_sha256) || !HEX_64.test(value.target_set_sha256) ||
      !HEX_64.test(value.dry_run_manifest_sha256) || !HEX_64.test(value.adult_approval_hmac_sha256) ||
      value.target_store !== 'arc-intake-submissions' || !HEX_64.test(value.target_hmac_sha256) ||
      !HEX_64.test(value.record_sha256) || value.retention_class !== 'unpaid-preview') {
    throw new TypeError('Retention delete intent is invalid.');
  }
  const lastInteractionAt = isoTimestamp(value.last_interaction_at, 'Retention intent last_interaction_at');
  const deleteNotBefore = isoTimestamp(value.delete_not_before, 'Retention intent delete_not_before');
  const authorizedAt = isoTimestamp(value.authorized_at, 'Retention intent authorized_at');
  if (deleteNotBefore < lastInteractionAt || authorizedAt < lastInteractionAt) throw new TypeError('Retention delete intent ordering is invalid.');
  return value;
}

export function validateRetentionDeleteReceipt(value, intent) {
  validateRetentionDeleteIntent(intent);
  plainObject(value, 'Retention delete receipt');
  exactKeys(value, RECEIPT_FIELDS, 'Retention delete receipt');
  if (value.schema !== RETENTION_RECEIPT_SCHEMA || value.run_id !== intent.run_id ||
      value.policy_version !== intent.policy_version || value.manifest_sha256 !== intent.manifest_sha256 ||
      value.target_store !== intent.target_store || value.target_hmac_sha256 !== intent.target_hmac_sha256 ||
      value.record_sha256 !== intent.record_sha256 || value.deletion_intent_sha256 !== sha256Hex(canonicalJson(intent)) ||
      value.customer_data_stored !== false || isoTimestamp(value.deleted_at, 'Retention receipt deleted_at') <
        isoTimestamp(intent.authorized_at, 'Retention intent authorized_at')) {
    throw new TypeError('Retention delete receipt binding is invalid.');
  }
  return value;
}

function deleteReceipt(intent, deletedAt) {
  return {
    schema: RETENTION_RECEIPT_SCHEMA,
    run_id: intent.run_id,
    policy_version: intent.policy_version,
    manifest_sha256: intent.manifest_sha256,
    target_store: intent.target_store,
    target_hmac_sha256: intent.target_hmac_sha256,
    record_sha256: intent.record_sha256,
    deletion_intent_sha256: sha256Hex(canonicalJson(intent)),
    deleted_at: deletedAt,
    customer_data_stored: false,
  };
}

function recordTombstone(intent, tombstonedAt) {
  return {
    schema: RETENTION_TOMBSTONE_SCHEMA,
    run_id: intent.run_id,
    policy_version: intent.policy_version,
    manifest_sha256: intent.manifest_sha256,
    target_hmac_sha256: intent.target_hmac_sha256,
    record_sha256: intent.record_sha256,
    deletion_intent_sha256: sha256Hex(canonicalJson(intent)),
    tombstoned_at: tombstonedAt,
    customer_data_stored: false,
  };
}

function validateTombstone(value, intent) {
  if (!value || value.schema !== RETENTION_TOMBSTONE_SCHEMA || value.run_id !== intent.run_id ||
      value.policy_version !== intent.policy_version || value.manifest_sha256 !== intent.manifest_sha256 ||
      value.target_hmac_sha256 !== intent.target_hmac_sha256 || value.record_sha256 !== intent.record_sha256 ||
      value.deletion_intent_sha256 !== sha256Hex(canonicalJson(intent)) || value.customer_data_stored !== false ||
      !Number.isFinite(isoTimestamp(value.tombstoned_at, 'Retention tombstone timestamp'))) {
    throw new Error('ARC_RETENTION_TOMBSTONE_CONFLICT');
  }
  return value;
}

function tombstoneClaim(tombstone) {
  return {
    schema: RETENTION_TOMBSTONE_CLAIM_SCHEMA,
    run_id: tombstone.run_id,
    policy_version: tombstone.policy_version,
    manifest_sha256: tombstone.manifest_sha256,
    target_hmac_sha256: tombstone.target_hmac_sha256,
    record_sha256: tombstone.record_sha256,
    tombstone_sha256: sha256Hex(canonicalJson(tombstone)),
    tombstoned_at: tombstone.tombstoned_at,
    customer_data_stored: false,
  };
}

async function deleteTombstone(store, target, expectedTombstone, afterDelete) {
  const immediatelyBeforeDelete = await getEntry(store, target.key);
  if (!immediatelyBeforeDelete || !exactStored(immediatelyBeforeDelete.value, expectedTombstone)) {
    throw new Error('ARC_RETENTION_TARGET_RECREATED');
  }
  let deletionError = null;
  try {
    await store.delete(target.key);
  } catch (error) {
    deletionError = error;
  }
  if (afterDelete) await afterDelete(target);
  const remaining = await getEntry(store, target.key);
  if (remaining) {
    if (!exactStored(remaining.value, expectedTombstone)) throw new Error('ARC_RETENTION_TARGET_RECREATED');
    if (deletionError) throw deletionError;
    throw new Error('ARC_RETENTION_DELETE_UNCONFIRMED');
  }
}

async function processTarget(target, manifest, env, stores, clock, afterDelete) {
  const receiptPath = receiptKey(target, manifest.digest, env);
  const intentPath = intentKey(target, manifest.digest, env);
  const existingReceipt = await getEntry(stores.control, receiptPath);
  const existingIntent = await getEntry(stores.control, intentPath);
  if (existingReceipt) {
    if (!existingIntent) throw new Error('ARC_RETENTION_RECEIPT_WITHOUT_INTENT');
    validateRetentionDeleteReceipt(existingReceipt.value, existingIntent.value);
    if (await getEntry(stores.intake, target.key)) throw new Error('ARC_RETENTION_RECEIPT_TARGET_PRESENT');
    return { status: 'deleted', resumed: true };
  }
  const hold = await getEntry(stores.control, legalHoldKey(target, env));
  if (hold) return { status: 'legal-hold', resumed: false };
  const targetEntry = await getEntry(stores.intake, target.key);
  const tombstoneClaimPath = tombstoneClaimKey(target, manifest.digest, env);
  const existingTombstoneClaim = await getEntry(stores.control, tombstoneClaimPath);
  if (!targetEntry) {
    if (manifest.value.mode === 'apply' && existingIntent && existingTombstoneClaim) {
      validateRetentionDeleteIntent(existingIntent.value);
      const receipt = deleteReceipt(existingIntent.value, clock().toISOString());
      validateRetentionDeleteReceipt(receipt, existingIntent.value);
      await ensureImmutable(stores.control, receiptPath, receipt);
      return { status: 'deleted', resumed: true };
    }
    if (manifest.value.mode === 'apply' && existingIntent) throw new Error('ARC_RETENTION_TARGET_MISSING_WITHOUT_TOMBSTONE');
    return { status: 'missing', resumed: false };
  }
  if (targetEntry.value?.schema === RETENTION_TOMBSTONE_SCHEMA) {
    if (manifest.value.mode !== 'apply' || !existingIntent) throw new Error('ARC_RETENTION_TOMBSTONE_CONFLICT');
    const tombstone = validateTombstone(targetEntry.value, existingIntent.value);
    await ensureImmutable(stores.control, tombstoneClaimPath, tombstoneClaim(tombstone));
    if (await getEntry(stores.control, legalHoldKey(target, env))) return { status: 'legal-hold', resumed: true };
    await deleteTombstone(stores.intake, target, tombstone, afterDelete);
    const receipt = deleteReceipt(existingIntent.value, clock().toISOString());
    validateRetentionDeleteReceipt(receipt, existingIntent.value);
    await ensureImmutable(stores.control, receiptPath, receipt);
    return { status: 'deleted', resumed: true };
  }
  let deleteNotBefore;
  try {
    deleteNotBefore = validateIntakeRecord(target, targetEntry.value, clock());
  } catch (error) {
    if (error.message === 'ARC_RETENTION_TARGET_NOT_EXPIRED') return { status: 'not-expired', resumed: false };
    throw error;
  }
  if (manifest.value.mode === 'dry-run') return { status: 'eligible', resumed: false };
  const intent = deleteIntent(target, manifest, deleteNotBefore, env);
  validateRetentionDeleteIntent(intent);
  await ensureImmutable(stores.control, intentPath, intent);
  // Recheck the legal-hold boundary immediately before the irreversible write.
  // The runbook requires provider writes to be frozen during an apply run
  // because Netlify Blobs cannot transact the hold and deletion keys together.
  if (await getEntry(stores.control, legalHoldKey(target, env))) return { status: 'legal-hold', resumed: false };
  const tombstone = recordTombstone(intent, clock().toISOString());
  const replaced = await stores.intake.setJSON(target.key, tombstone, { onlyIfMatch: targetEntry.etag });
  if (!replaced?.modified || !replaced.etag) throw new Error('ARC_RETENTION_TARGET_CHANGED');
  const storedTombstone = await getEntry(stores.intake, target.key);
  if (!storedTombstone || !exactStored(storedTombstone.value, tombstone)) throw new Error('ARC_RETENTION_TOMBSTONE_CONFLICT');
  await ensureImmutable(stores.control, tombstoneClaimPath, tombstoneClaim(tombstone));
  await deleteTombstone(stores.intake, target, tombstone, afterDelete);
  const receipt = deleteReceipt(intent, clock().toISOString());
  validateRetentionDeleteReceipt(receipt, intent);
  await ensureImmutable(stores.control, receiptPath, receipt);
  return { status: 'deleted', resumed: Boolean(existingIntent) };
}

export async function runRetentionManifest(raw, signature, env, stores, adapters = {}) {
  const clock = adapters.clock || (() => new Date());
  let manifest = normalizeManifest(raw, signature, env, clock(), { enforceFreshness: false });
  const existingRun = await getEntry(stores.control, runKey(manifest.value.run_id));
  if (!existingRun) manifest = normalizeManifest(raw, signature, env, clock(), { enforceFreshness: true });
  if (manifest.value.mode === 'apply') {
    const prior = await getEntry(stores.control, completionKey(manifest.value.dry_run_id));
    const value = prior?.value;
    if (!value || value.schema !== RETENTION_COMPLETION_SCHEMA || value.mode !== 'dry-run' ||
        value.run_id !== manifest.value.dry_run_id || value.manifest_sha256 !== manifest.value.dry_run_manifest_sha256 ||
        value.target_set_sha256 !== manifest.targetSetDigest || value.target_count !== manifest.targets.length ||
        value.eligible !== manifest.targets.length || value.deleted !== 0 || value.legal_hold !== 0 || value.missing !== 0 ||
        value.not_expired !== 0 || value.provider_cleanup_included !== false) {
      throw new Error('ARC_RETENTION_PRIOR_DRY_RUN_REQUIRED');
    }
  }
  const reservation = runReservation(manifest);
  await ensureImmutable(stores.control, runKey(manifest.value.run_id), reservation);
  const existingCompletion = await getEntry(stores.control, completionKey(manifest.value.run_id));
  if (existingCompletion) {
    if (existingCompletion.value.manifest_sha256 !== manifest.digest) throw new Error('ARC_RETENTION_INDEX_CONFLICT');
    return { ...existingCompletion.value, idempotent_replay: true };
  }

  const counts = { deleted: 0, eligible: 0, legal_hold: 0, missing: 0, not_expired: 0, resumed: 0 };
  for (const target of manifest.targets) {
    const result = await processTarget(target, manifest, env, stores, clock, adapters.afterDelete);
    if (result.status === 'legal-hold') counts.legal_hold += 1;
    else if (result.status === 'not-expired') counts.not_expired += 1;
    else counts[result.status] += 1;
    if (result.resumed) counts.resumed += 1;
  }
  const completion = {
    schema: RETENTION_COMPLETION_SCHEMA,
    run_id: manifest.value.run_id,
    mode: manifest.value.mode,
    policy_version: manifest.value.policy_version,
    manifest_sha256: manifest.digest,
    target_set_sha256: manifest.targetSetDigest,
    dry_run_id: manifest.value.dry_run_id,
    dry_run_manifest_sha256: manifest.value.dry_run_manifest_sha256,
    adult_approval_hmac_sha256: manifest.value.adult_approval_hmac_sha256,
    target_count: manifest.targets.length,
    ...counts,
    completed_at: clock().toISOString(),
    provider_cleanup_included: false,
  };
  await ensureImmutable(stores.control, completionKey(manifest.value.run_id), completion);
  return { ...completion, idempotent_replay: false };
}

export const retentionKeys = Object.freeze({
  completionKey, intentKey, legalHoldKey, receiptKey, runKey, targetHmac, tombstoneClaimKey,
});
