import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';

import {
  emailSendAttemptConfiguration,
  planTerminalEmailSendAttemptRetention,
  validateEmailSendAttemptRetentionSource,
  validateEmailSendAttemptRetentionTombstone,
} from './email-send-attempt-core.mjs';
import {
  planExpiredEmailRecipientCapsuleRetention,
  validateEmailRecipientVaultTombstone,
} from './email-recipient-vault-core.mjs';
import {
  assertRetentionGenerationFenceAuthority,
  beginRetentionFreeze,
  completeRetentionFreeze,
  ensureRetentionGenerationFence,
  readRetentionGenerationFence,
  recordRetentionMissingSourceAnomaly,
  renewRetentionGenerationFenceAuthority,
  retentionFreezeOperationHmac,
  retentionGenerationFenceConfiguration,
} from './retention-generation-fence-core.mjs';
import {
  firstPartyLegalHoldKey,
  validateFirstPartyLegalHoldRecord,
} from './first-party-retention-core.mjs';
import { readReviewEmailOutbox } from './review-email-outbox-core.mjs';
import { validateExpectedBindings } from './arc2-handoff-core.mjs';

export const TRANSACTIONAL_EMAIL_RETENTION_SWEEP_SCHEMA =
  'arc-transactional-email-retention-sweep-v1';
export const TRANSACTIONAL_EMAIL_RETENTION_RECEIPT_SCHEMA =
  'arc-transactional-email-retention-sweep-completion-v1';
export const TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_SCHEMA =
  'arc-transactional-email-retention-missing-source-anomaly-v1';
export const TRANSACTIONAL_EMAIL_RETENTION_SWEEP_KEY =
  'retention/control/transactional-email-sweep-v1';
export const TRANSACTIONAL_EMAIL_RETENTION_SWEEP_INTERVAL_MS = 24 * 60 * 60_000;

const LEASE_MS = 2 * 60_000;
const HEX_64 = /^[a-f0-9]{64}$/;
const STATE_FIELDS = Object.freeze([
  'attempt_counts', 'completed_at', 'cursor', 'lease_expires_at', 'lease_hmac_sha256',
  'next_sweep_at', 'phase', 'record_hmac_sha256', 'run_count', 'schema', 'started_at',
  'status', 'sweep_hmac_sha256', 'vault_counts', 'version',
]);
const VAULT_COUNT_FIELDS = Object.freeze(['deleted', 'inspected']);
const ATTEMPT_COUNT_FIELDS = Object.freeze([
  'deleted', 'event_records_deleted', 'inspected', 'provider_message_records_deleted', 'quarantined',
]);
const RECEIPT_FIELDS = Object.freeze([
  'attempt_counts', 'completed_at', 'customer_data_stored', 'record_hmac_sha256',
  'schema', 'started_at', 'sweep_hmac_sha256', 'vault_counts', 'version',
]);
const MISSING_SOURCE_FIELDS = Object.freeze([
  'customer_data_stored', 'detected_at', 'expected_binding_sha256', 'record_hmac_sha256',
  'schema', 'source_key_hmac_sha256', 'source_kind', 'source_store',
  'sweep_hmac_sha256', 'version',
]);
const MISSING_SOURCE_INPUT_FIELDS = Object.freeze([
  'expected_binding_sha256', 'source_key', 'source_kind', 'source_store',
]);
const MISSING_SOURCE_KINDS = Object.freeze({
  attempt: Object.freeze(['email-attempt', 'provider-event-index', 'provider-message-index']),
  vault: Object.freeze(['vault-capsule']),
});
const MISSING_SOURCE_SIGNATURE_DOMAIN =
  'arc-transactional-email-retention-missing-source-anomaly-record-v1';
const MISSING_SOURCE_KEY_DOMAIN =
  'arc-transactional-email-retention-missing-source-key-v1';
const FROZEN_MANIFEST_SCHEMA = 'arc-transactional-email-retention-subject-manifest-v1';
const FROZEN_MANIFEST_SIGNATURE_DOMAIN =
  'arc-transactional-email-retention-subject-manifest-record-v1';
const FROZEN_MANIFEST_PREFIX =
  'first-party-retention/generation-fence/transactional-email-manifests/';
const FROZEN_MANIFEST_FIELDS = Object.freeze([
  'built_at', 'customer_data_stored', 'entries', 'family', 'generation',
  'legal_hold_binding_complete', 'legal_hold_bindings', 'legal_hold_snapshot_sha256',
  'legal_hold_subject_sha256s', 'record_hmac_sha256', 'schema',
  'subject_hmac_sha256', 'sweep_hmac_sha256', 'version',
]);
const LEGAL_HOLD_BINDING_FIELDS = Object.freeze(['family', 'subject_hmac_sha256']);
const LEGAL_HOLD_LOOKUP_FIELDS = Object.freeze(['family', 'subject_sha256']);
const CLAIM_INVITATION_OUTBOX_FIELDS = Object.freeze([
  'claim_invitation_generation', 'claim_token_hmac_sha256', 'expires_at', 'handoff_id',
  'recipient_email_sha256', 'schema', 'status',
]);
const FROZEN_MANIFEST_ENTRY_FIELDS = Object.freeze([
  'action', 'output_record', 'output_record_sha256', 'role', 'source_etag',
  'source_key', 'source_kind', 'source_record_sha256', 'store',
]);

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError('Transactional email retention value is invalid.');
    }
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const result = JSON.stringify(value);
  if (result === undefined) throw new TypeError('Transactional email retention value is invalid.');
  return result;
}

const exactKeys = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
const safeEqual = (left, right) => {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
};
const iso = (value, label) => {
  const parsed = typeof value === 'string' ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new TypeError(`${label} is invalid.`);
  }
  return parsed;
};
const nullableIso = (value, label) => value === null ? null : iso(value, label);
const countsValid = (value, fields) => exactKeys(value, fields) && fields.every((name) =>
  Number.isSafeInteger(value[name]) && value[name] >= 0);
const unsigned = (value) => {
  const { record_hmac_sha256: ignored, ...record } = value;
  return record;
};
const sign = (value, domain, secret) => ({
  ...unsigned(value),
  record_hmac_sha256: createHmac('sha256', secret)
    .update(`${domain}\n${canonicalJson(unsigned(value))}`).digest('hex'),
});
const verify = (value, domain, secret) => {
  const expected = createHmac('sha256', secret)
    .update(`${domain}\n${canonicalJson(unsigned(value))}`).digest('hex');
  if (!HEX_64.test(value.record_hmac_sha256 || '') || !safeEqual(value.record_hmac_sha256, expected)) {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_SIGNATURE_INVALID');
  }
};

export function validateTransactionalEmailRetentionSweepState(value, secret) {
  if (!exactKeys(value, STATE_FIELDS) || value.schema !== TRANSACTIONAL_EMAIL_RETENTION_SWEEP_SCHEMA ||
      value.version !== 1 || !['IDLE', 'RUNNING', 'COMPLETE'].includes(value.status) ||
      !HEX_64.test(value.sweep_hmac_sha256 || '') || !Number.isSafeInteger(value.run_count) ||
      value.run_count < 0 || !countsValid(value.vault_counts, VAULT_COUNT_FIELDS) ||
      !countsValid(value.attempt_counts, ATTEMPT_COUNT_FIELDS) ||
      !(value.cursor === null || typeof value.cursor === 'string' && value.cursor.length <= 1_024) ||
      !['vault', 'attempt', null].includes(value.phase)) {
    throw new TypeError('Transactional email retention sweep state is invalid.');
  }
  const started = iso(value.started_at, 'Transactional email retention started_at');
  const completed = nullableIso(value.completed_at, 'Transactional email retention completed_at');
  const next = nullableIso(value.next_sweep_at, 'Transactional email retention next_sweep_at');
  const lease = nullableIso(value.lease_expires_at, 'Transactional email retention lease_expires_at');
  if (value.status === 'RUNNING' && (!HEX_64.test(value.lease_hmac_sha256 || '') || lease === null) ||
      value.status !== 'RUNNING' && (value.lease_hmac_sha256 !== null || lease !== null) ||
      value.status === 'COMPLETE' && (completed === null || next === null || value.phase !== null || value.cursor !== null) ||
      value.status !== 'COMPLETE' && (completed !== null || next !== null || !['vault', 'attempt'].includes(value.phase)) ||
      completed !== null && (completed < started || next - completed !== TRANSACTIONAL_EMAIL_RETENTION_SWEEP_INTERVAL_MS)) {
    throw new TypeError('Transactional email retention sweep state is inconsistent.');
  }
  verify(value, 'arc-transactional-email-retention-sweep-record-v1', secret);
  return value;
}

export function validateTransactionalEmailRetentionSweepReceipt(value, secret) {
  if (!exactKeys(value, RECEIPT_FIELDS) || value.schema !== TRANSACTIONAL_EMAIL_RETENTION_RECEIPT_SCHEMA ||
      value.version !== 1 || !HEX_64.test(value.sweep_hmac_sha256 || '') ||
      value.customer_data_stored !== false || !countsValid(value.vault_counts, VAULT_COUNT_FIELDS) ||
      !countsValid(value.attempt_counts, ATTEMPT_COUNT_FIELDS) ||
      iso(value.completed_at, 'Transactional email retention receipt completed_at') <
        iso(value.started_at, 'Transactional email retention receipt started_at')) {
    throw new TypeError('Transactional email retention sweep receipt is invalid.');
  }
  verify(value, 'arc-transactional-email-retention-sweep-completion-record-v1', secret);
  return value;
}

export function validateTransactionalEmailRetentionMissingSourceAnomaly(value, secret,
  expectedSweepHmac = null) {
  if (!exactKeys(value, MISSING_SOURCE_FIELDS) ||
      value.schema !== TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_SCHEMA || value.version !== 1 ||
      !HEX_64.test(value.sweep_hmac_sha256 || '') ||
      expectedSweepHmac !== null && value.sweep_hmac_sha256 !== expectedSweepHmac ||
      !Object.hasOwn(MISSING_SOURCE_KINDS, value.source_store) ||
      !MISSING_SOURCE_KINDS[value.source_store].includes(value.source_kind) ||
      !HEX_64.test(value.source_key_hmac_sha256 || '') ||
      !HEX_64.test(value.expected_binding_sha256 || '') || value.customer_data_stored !== false) {
    throw new TypeError('Transactional email retention missing-source anomaly is invalid.');
  }
  iso(value.detected_at, 'Transactional email retention missing-source detected_at');
  verify(value, MISSING_SOURCE_SIGNATURE_DOMAIN, secret);
  return value;
}

const receiptKey = (sweepHmac) => `retention/completions/${sweepHmac}`;
const missingSourcePrefix = (sweepHmac) => `retention/missing-source/${sweepHmac}/`;
const zeroVaultCounts = () => ({ inspected: 0, deleted: 0 });
const zeroAttemptCounts = () => ({
  inspected: 0,
  deleted: 0,
  quarantined: 0,
  event_records_deleted: 0,
  provider_message_records_deleted: 0,
});

async function readState(store, secret) {
  const entry = await store.getWithMetadata(TRANSACTIONAL_EMAIL_RETENTION_SWEEP_KEY,
    { type: 'json', consistency: 'strong' });
  return entry ? { value: validateTransactionalEmailRetentionSweepState(entry.data, secret), etag: entry.etag } : null;
}

async function readReceipt(store, sweepHmac, secret) {
  const entry = await store.getWithMetadata(receiptKey(sweepHmac), { type: 'json', consistency: 'strong' });
  return entry ? validateTransactionalEmailRetentionSweepReceipt(entry.data, secret) : null;
}

function validateMissingSourceInput(input) {
  if (!exactKeys(input, MISSING_SOURCE_INPUT_FIELDS) ||
      !Object.hasOwn(MISSING_SOURCE_KINDS, input.source_store) ||
      !MISSING_SOURCE_KINDS[input.source_store].includes(input.source_kind) ||
      typeof input.source_key !== 'string' || input.source_key.length < 1 || input.source_key.length > 1_024 ||
      !HEX_64.test(input.expected_binding_sha256 || '')) {
    throw new TypeError('Transactional email retention missing-source input is invalid.');
  }
  return input;
}

async function persistMissingSourceAnomaly(store, state, rawInput, secret) {
  const input = validateMissingSourceInput(rawInput);
  const sourceKeyHmac = createHmac('sha256', secret)
    .update(`${MISSING_SOURCE_KEY_DOMAIN}\n${input.source_store}\n${input.source_kind}\n${input.source_key}`)
    .digest('hex');
  const value = sign({
    schema: TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_SCHEMA,
    version: 1,
    sweep_hmac_sha256: state.sweep_hmac_sha256,
    source_store: input.source_store,
    source_kind: input.source_kind,
    source_key_hmac_sha256: sourceKeyHmac,
    expected_binding_sha256: input.expected_binding_sha256,
    detected_at: state.started_at,
    customer_data_stored: false,
  }, MISSING_SOURCE_SIGNATURE_DOMAIN, secret);
  validateTransactionalEmailRetentionMissingSourceAnomaly(
    value, secret, state.sweep_hmac_sha256,
  );
  const identity = createHmac('sha256', secret).update(
    `arc-transactional-email-retention-missing-source-id-v1\n${canonicalJson({
      expected_binding_sha256: input.expected_binding_sha256,
      source_key_hmac_sha256: sourceKeyHmac,
      source_kind: input.source_kind,
      source_store: input.source_store,
      sweep_hmac_sha256: state.sweep_hmac_sha256,
    })}`,
  ).digest('hex');
  const key = `${missingSourcePrefix(state.sweep_hmac_sha256)}${identity}`;
  try { await store.setJSON(key, value, { onlyIfNew: true }); } catch {}
  const stored = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!stored || canonicalJson(stored.data) !== canonicalJson(value)) {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_ANOMALY_UNAVAILABLE');
  }
  validateTransactionalEmailRetentionMissingSourceAnomaly(
    stored.data, secret, state.sweep_hmac_sha256,
  );
  return stored.data;
}

async function hasBlockingMissingSourceAnomaly(store, sweepHmac, secret) {
  const prefix = missingSourcePrefix(sweepHmac);
  const rawListing = store.list({ prefix, paginate: true });
  const resolvedListing = rawListing && typeof rawListing[Symbol.asyncIterator] === 'function'
    ? rawListing : await rawListing;
  const pages = resolvedListing && typeof resolvedListing[Symbol.asyncIterator] === 'function'
    ? resolvedListing : (async function *single() { yield resolvedListing; })();
  let prior = null;
  for await (const page of pages) {
    if (!page || !Array.isArray(page.blobs)) {
      throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_LIST_UNAVAILABLE');
    }
    for (const blob of page.blobs) {
      if (!blob || typeof blob.key !== 'string' || !blob.key.startsWith(prefix) ||
          prior !== null && blob.key <= prior) {
        throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_LIST_INVALID');
      }
      prior = blob.key;
      const entry = await store.getWithMetadata(blob.key, { type: 'json', consistency: 'strong' });
      if (!entry) throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_ANOMALY_UNAVAILABLE');
      validateTransactionalEmailRetentionMissingSourceAnomaly(entry.data, secret, sweepHmac);
      return true;
    }
  }
  return false;
}

async function replaceState(store, entry, value, secret) {
  const signed = sign(value, 'arc-transactional-email-retention-sweep-record-v1', secret);
  validateTransactionalEmailRetentionSweepState(signed, secret);
  const result = await store.setJSON(TRANSACTIONAL_EMAIL_RETENTION_SWEEP_KEY, signed,
    { onlyIfMatch: entry.etag });
  if (!result?.modified || typeof result.etag !== 'string') {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_STATE_CONTENTION');
  }
  return { value: signed, etag: result.etag };
}

function freshState(now, sweepHmac) {
  return {
    schema: TRANSACTIONAL_EMAIL_RETENTION_SWEEP_SCHEMA,
    version: 1,
    status: 'IDLE',
    sweep_hmac_sha256: sweepHmac,
    phase: 'vault',
    cursor: null,
    vault_counts: zeroVaultCounts(),
    attempt_counts: zeroAttemptCounts(),
    started_at: now.toISOString(),
    completed_at: null,
    next_sweep_at: null,
    lease_hmac_sha256: null,
    lease_expires_at: null,
    run_count: 0,
  };
}

async function createState(store, value, secret) {
  const signed = sign(value, 'arc-transactional-email-retention-sweep-record-v1', secret);
  try { await store.setJSON(TRANSACTIONAL_EMAIL_RETENTION_SWEEP_KEY, signed, { onlyIfNew: true }); } catch {}
  const entry = await readState(store, secret);
  if (!entry) throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_STATE_UNAVAILABLE');
  return entry;
}

async function ensureReceipt(store, state, completedAt, secret) {
  const expected = sign({
    schema: TRANSACTIONAL_EMAIL_RETENTION_RECEIPT_SCHEMA,
    version: 1,
    sweep_hmac_sha256: state.sweep_hmac_sha256,
    started_at: state.started_at,
    completed_at: completedAt,
    vault_counts: state.vault_counts,
    attempt_counts: state.attempt_counts,
    customer_data_stored: false,
  }, 'arc-transactional-email-retention-sweep-completion-record-v1', secret);
  try { await store.setJSON(receiptKey(state.sweep_hmac_sha256), expected, { onlyIfNew: true }); } catch {}
  const stored = await readReceipt(store, state.sweep_hmac_sha256, secret);
  if (!stored) throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_RECEIPT_UNAVAILABLE');
  if (canonicalJson(stored) !== canonicalJson(expected)) {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_RECEIPT_CONFLICT');
  }
  return stored;
}

function completedState(state, receipt) {
  return {
    ...state,
    status: 'COMPLETE',
    phase: null,
    cursor: null,
    vault_counts: receipt.vault_counts,
    attempt_counts: receipt.attempt_counts,
    completed_at: receipt.completed_at,
    next_sweep_at: new Date(Date.parse(receipt.completed_at) +
      TRANSACTIONAL_EMAIL_RETENTION_SWEEP_INTERVAL_MS).toISOString(),
    lease_hmac_sha256: null,
    lease_expires_at: null,
  };
}

const recordSha256 = (value) => createHash('sha256').update(canonicalJson(value)).digest('hex');
const rawSha256 = (value) => createHash('sha256').update(String(value)).digest('hex');

function validateFrozenManifestEntry(value) {
  if (!exactKeys(value, FROZEN_MANIFEST_ENTRY_FIELDS) ||
      !['TOMBSTONE', 'CONTROL', 'MISSING'].includes(value.action) ||
      !['CHILD', 'CONTROL', 'PRIMARY'].includes(value.role) ||
      !['attempt', 'vault'].includes(value.store) ||
      typeof value.source_key !== 'string' || value.source_key.length < 1 ||
      value.source_key.length > 1_024 ||
      !['email-attempt', 'provider-event-index', 'provider-message-index',
        'vault-capsule', 'sweep-state'].includes(value.source_kind) ||
      !(value.source_etag === null || typeof value.source_etag === 'string' &&
        value.source_etag.length >= 1 && value.source_etag.length <= 512) ||
      !HEX_64.test(value.source_record_sha256 || '') ||
      !HEX_64.test(value.output_record_sha256 || '')) {
    throw new TypeError('Transactional email frozen manifest entry is invalid.');
  }
  if (value.action === 'MISSING') {
    if (value.source_etag !== null || value.output_record !== null ||
        value.output_record_sha256 !== recordSha256(null)) {
      throw new TypeError('Transactional email missing manifest entry is invalid.');
    }
  } else if (!value.output_record || typeof value.output_record !== 'object' ||
      Array.isArray(value.output_record) ||
      recordSha256(value.output_record) !== value.output_record_sha256 ||
      typeof value.source_etag !== 'string') {
    throw new TypeError('Transactional email frozen manifest output is invalid.');
  }
  return value;
}

function validateFrozenManifest(value, env) {
  const fenceSecret = env.ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET;
  if (!exactKeys(value, FROZEN_MANIFEST_FIELDS) ||
      value.schema !== FROZEN_MANIFEST_SCHEMA || value.version !== 1 ||
      !['attempt', 'control', 'missing', 'vault'].includes(value.family) ||
      !Number.isSafeInteger(value.generation) || value.generation < 0 ||
      !HEX_64.test(value.sweep_hmac_sha256 || '') ||
      !HEX_64.test(value.subject_hmac_sha256 || '') ||
      !HEX_64.test(value.legal_hold_snapshot_sha256 || '') ||
      typeof value.legal_hold_binding_complete !== 'boolean' ||
      !Array.isArray(value.legal_hold_bindings) ||
      !Array.isArray(value.legal_hold_subject_sha256s) ||
      value.customer_data_stored !== false || !Array.isArray(value.entries) ||
      value.entries.length < 1 || value.entries.length > 100_002) {
    throw new TypeError('Transactional email frozen manifest is invalid.');
  }
  iso(value.built_at, 'Transactional email frozen manifest built_at');
  value.entries.forEach(validateFrozenManifestEntry);
  const bindingIdentities = value.legal_hold_bindings.map((binding) => {
    if (!exactKeys(binding, LEGAL_HOLD_BINDING_FIELDS) ||
        !['handoff', 'review'].includes(binding.family) ||
        !HEX_64.test(binding.subject_hmac_sha256 || '')) {
      throw new TypeError('Transactional email legal-hold binding is invalid.');
    }
    return `${binding.family}/${binding.subject_hmac_sha256}`;
  });
  const lookupIdentities = value.legal_hold_subject_sha256s.map((lookup) => {
    if (!exactKeys(lookup, LEGAL_HOLD_LOOKUP_FIELDS) ||
        !['handoff', 'review'].includes(lookup.family) ||
        !HEX_64.test(lookup.subject_sha256 || '')) {
      throw new TypeError('Transactional email legal-hold lookup is invalid.');
    }
    return `${lookup.family}/${lookup.subject_sha256}`;
  });
  if (JSON.stringify(bindingIdentities) !== JSON.stringify([...new Set(bindingIdentities)].sort()) ||
      JSON.stringify(lookupIdentities) !== JSON.stringify([...new Set(lookupIdentities)].sort())) {
    throw new TypeError('Transactional email legal-hold bindings are not canonical.');
  }
  verify(value, FROZEN_MANIFEST_SIGNATURE_DOMAIN, fenceSecret);
  return value;
}

const frozenManifestDescriptor = (manifest) => Object.freeze({
  generation: manifest.generation,
  manifest_entry_count: manifest.entries.length,
  manifest_sha256: recordSha256(manifest),
  subject_hmac_sha256: manifest.subject_hmac_sha256,
});

async function persistFrozenManifest(store, manifest, env) {
  validateFrozenManifest(manifest, env);
  const descriptor = frozenManifestDescriptor(manifest);
  const operation = retentionFreezeOperationHmac(descriptor, env);
  const key = `${FROZEN_MANIFEST_PREFIX}${operation}`;
  try { await store.setJSON(key, manifest, { onlyIfNew: true }); } catch {}
  const stored = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!stored || canonicalJson(stored.data) !== canonicalJson(manifest)) {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MANIFEST_CONFLICT');
  }
  validateFrozenManifest(stored.data, env);
  return Object.freeze({ descriptor, manifest: stored.data, operation_hmac_sha256: operation });
}

async function readFrozenManifest(store, operation, env) {
  if (!HEX_64.test(operation || '')) {
    throw new TypeError('Transactional email frozen operation is invalid.');
  }
  const entry = await store.getWithMetadata(`${FROZEN_MANIFEST_PREFIX}${operation}`,
    { type: 'json', consistency: 'strong' });
  if (!entry) return null;
  const manifest = validateFrozenManifest(entry.data, env);
  const descriptor = frozenManifestDescriptor(manifest);
  if (retentionFreezeOperationHmac(descriptor, env) !== operation) {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MANIFEST_BINDING_INVALID');
  }
  return Object.freeze({ descriptor, manifest, operation_hmac_sha256: operation });
}

async function scanStrongEntries(store, prefix, visitor, adapters = {}) {
  if (!store || typeof store.list !== 'function') return false;
  const listing = store.list({ prefix, paginate: true });
  const pages = listing && typeof listing[Symbol.asyncIterator] === 'function'
    ? listing : (async function *single() { yield await listing; })();
  let prior = null;
  for await (const page of pages) {
    if (adapters.heartbeat) await adapters.heartbeat();
    if (!page || !Array.isArray(page.blobs)) {
      throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_BINDING_LIST_UNAVAILABLE');
    }
    for (const blob of page.blobs) {
      if (!blob || typeof blob.key !== 'string' || !blob.key.startsWith(prefix) ||
          prior !== null && blob.key <= prior) {
        throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_BINDING_LIST_INVALID');
      }
      prior = blob.key;
      if (adapters.heartbeat) await adapters.heartbeat();
      const entry = await store.getWithMetadata(blob.key, { type: 'json', consistency: 'strong' });
      if (!entry) throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_BINDING_SOURCE_MISSING');
      await visitor(blob.key, entry.data);
    }
  }
  return true;
}

function canonicalHoldResolution(bindings, lookups, complete) {
  const normalizedBindings = [...new Map(bindings.map((value) =>
    [`${value.family}/${value.subject_hmac_sha256}`, Object.freeze({ ...value })])).values()]
    .sort((left, right) => `${left.family}/${left.subject_hmac_sha256}`
      .localeCompare(`${right.family}/${right.subject_hmac_sha256}`));
  const normalizedLookups = [...new Map(lookups.map((value) =>
    [`${value.family}/${value.subject_sha256}`, Object.freeze({ ...value })])).values()]
    .sort((left, right) => `${left.family}/${left.subject_sha256}`
      .localeCompare(`${right.family}/${right.subject_sha256}`));
  return Object.freeze({ bindings: Object.freeze(normalizedBindings),
    lookups: Object.freeze(normalizedLookups), complete });
}

async function resolveLegalHoldBindings(plan, stores, env) {
  const mutation = plan?.mutation;
  if (!mutation || !['preview_review', 'claim_invitation', 'final_delivery']
    .includes(mutation.job_kind)) return canonicalHoldResolution([], [], true);
  const family = mutation.job_kind === 'preview_review' ? 'review' : 'handoff';
  const bindings = [];
  const lookups = [{ family, subject_sha256: mutation.job_key_sha256 }];
  if (mutation.legal_hold_binding) bindings.push(mutation.legal_hold_binding);
  if (bindings.length > 0) return canonicalHoldResolution(bindings, lookups, true);

  if (family === 'review') {
    if (!stores.review) return canonicalHoldResolution(bindings, lookups, false);
    let matched = false;
    await scanStrongEntries(stores.review, 'review-email-outbox/', async (key) => {
      const id = key.match(/^review-email-outbox\/([a-f0-9]{64})$/)?.[1];
      if (!id || ![rawSha256(id), rawSha256(`${id}:resend-acceptance-v1`)]
        .includes(mutation.job_key_sha256)) return;
      const outbox = await readReviewEmailOutbox(stores.review, id, env);
      bindings.push({ family: 'review', subject_hmac_sha256: outbox.record.invite_hmac_sha256 });
      matched = true;
    });
    return canonicalHoldResolution(bindings, lookups, matched);
  }

  const jobKeyShas = new Set([mutation.job_key_sha256]);
  if (stores.attempt && mutation.store === 'vault') {
    await scanStrongEntries(stores.attempt, 'attempts/', async (key, value) => {
      const attemptHmac = key.match(/^attempts\/([a-f0-9]{64})$/)?.[1];
      if (!attemptHmac || rawSha256(`attempt-acceptance:${attemptHmac}`) !==
          mutation.job_key_sha256) return;
      const attempt = validateEmailSendAttemptRetentionSource(value, key, env);
      if (attempt.job_kind !== mutation.job_kind) {
        throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_ATTEMPT_BINDING_INVALID');
      }
      jobKeyShas.add(attempt.job_key_sha256);
      lookups.push({ family, subject_sha256: attempt.job_key_sha256 });
    });
  }
  if (!stores.ledger) return canonicalHoldResolution(bindings, lookups, false);
  const candidateHandoffs = new Set();
  const finalBindings = new Map();
  await scanStrongEntries(stores.ledger, 'handoffs/', async (key, value) => {
    const id = key.match(/^handoffs\/([a-f0-9]{64})$/)?.[1];
    if (!id || !jobKeyShas.has(rawSha256(id))) return;
    const handoff = validateExpectedBindings(value);
    if (handoff.handoff_id !== id) throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_HANDOFF_BINDING_INVALID');
    candidateHandoffs.add(id);
  });
  if (mutation.job_kind === 'claim_invitation') {
    await scanStrongEntries(stores.ledger, 'invitation-ready-outbox/', async (key, value) => {
      const jobKey = key.match(/^invitation-ready-outbox\/([a-f0-9]{64})$/)?.[1];
      if (!jobKey || !jobKeyShas.has(rawSha256(jobKey))) return;
      if (!exactKeys(value, CLAIM_INVITATION_OUTBOX_FIELDS) ||
          value.schema !== 'arc2-claim-invitation-ready-outbox-v2' ||
          value.status !== 'READY' || !HEX_64.test(value.handoff_id || '') ||
          !HEX_64.test(value.recipient_email_sha256 || '') ||
          !HEX_64.test(value.claim_token_hmac_sha256 || '') ||
          !Number.isSafeInteger(value.claim_invitation_generation) ||
          value.claim_invitation_generation < 0 ||
          !Number.isFinite(Date.parse(value.expires_at)) ||
          typeof env.ARC_EMAIL_CLAIM_BINDING_SECRET !== 'string') {
        throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_CLAIM_BINDING_INVALID');
      }
      const expected = createHmac('sha256', env.ARC_EMAIL_CLAIM_BINDING_SECRET)
        .update(canonicalJson({
          version: value.schema, handoff_id: value.handoff_id,
          recipient_email_sha256: value.recipient_email_sha256,
          claim_invitation_generation: value.claim_invitation_generation,
          claim_token_hmac_sha256: value.claim_token_hmac_sha256,
          expires_at: value.expires_at,
        })).digest('hex');
      if (!safeEqual(expected, jobKey)) {
        throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_CLAIM_BINDING_INVALID');
      }
      candidateHandoffs.add(value.handoff_id);
    });
  } else {
    await scanStrongEntries(stores.ledger, 'outbox/', async (key, value) => {
      const jobKey = key.match(/^outbox\/([a-f0-9]{64})$/)?.[1];
      if (!jobKey || !jobKeyShas.has(rawSha256(jobKey))) return;
      if (value?.schema !== 'arc2-final-delivery-outbox-v1' ||
          value.outbox_claim_key_hmac_sha256 !== jobKey ||
          !HEX_64.test(value.handoff_id || '')) {
        throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_FINAL_BINDING_INVALID');
      }
      candidateHandoffs.add(value.handoff_id);
      if (finalBindings.has(value.handoff_id) && finalBindings.get(value.handoff_id) !== jobKey) {
        throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_FINAL_BINDING_INVALID');
      }
      finalBindings.set(value.handoff_id, jobKey);
    });
  }
  for (const id of candidateHandoffs) {
    const entry = await stores.ledger.getWithMetadata(`handoffs/${id}`,
      { type: 'json', consistency: 'strong' });
    const handoff = entry ? validateExpectedBindings(entry.data) : null;
    if (!handoff || handoff.handoff_id !== id ||
        finalBindings.has(id) && handoff.outbox_claim_key_hmac_sha256 !== finalBindings.get(id)) {
      throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_HANDOFF_BINDING_INVALID');
    }
    bindings.push({ family: 'handoff', subject_hmac_sha256: id });
  }
  return canonicalHoldResolution(bindings, lookups, bindings.length > 0);
}

async function legalHoldSnapshot(store, resolution, env, now, adapters = {}) {
  const prefix = 'first-party-retention/legal-holds/';
  const listing = store.list({ prefix, paginate: true });
  const pages = listing && typeof listing[Symbol.asyncIterator] === 'function'
    ? listing : (async function *single() { yield await listing; })();
  const records = [];
  const exact = new Set(resolution.bindings.map((binding) =>
    `${binding.family}/${binding.subject_hmac_sha256}`));
  const lookups = new Set(resolution.lookups.map((lookup) =>
    `${lookup.family}/${lookup.subject_sha256}`));
  const fallbackFamilies = resolution.complete ? new Set() :
    new Set(resolution.lookups.map((lookup) => lookup.family));
  let prior = null;
  for await (const page of pages) {
    if (adapters.heartbeat) await adapters.heartbeat();
    if (!page || !Array.isArray(page.blobs)) {
      throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_LEGAL_HOLD_LIST_UNAVAILABLE');
    }
    for (const blob of page.blobs) {
      if (!blob || typeof blob.key !== 'string' || !blob.key.startsWith(prefix) ||
          prior !== null && blob.key <= prior) {
        throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_LEGAL_HOLD_LIST_INVALID');
      }
      prior = blob.key;
      if (adapters.heartbeat) await adapters.heartbeat();
      const entry = await store.getWithMetadata(blob.key, { type: 'json', consistency: 'strong' });
      if (!entry) throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_LEGAL_HOLD_SOURCE_MISSING');
      const validated = validateFirstPartyLegalHoldRecord(entry.data, env, { now });
      const record = validated.record;
      if (blob.key !== firstPartyLegalHoldKey(record.family, record.subject_hmac_sha256)) {
        throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_LEGAL_HOLD_BINDING_INVALID');
      }
      const relevant = exact.has(`${record.family}/${record.subject_hmac_sha256}`) ||
        lookups.has(`${record.family}/${rawSha256(record.subject_hmac_sha256)}`) ||
        fallbackFamilies.has(record.family);
      if (relevant) records.push({ active: validated.active, key: blob.key,
        record_sha256: recordSha256(record) });
    }
  }
  return Object.freeze({ active: records.some((record) => record.active),
    digest: recordSha256(records) });
}

function normalizePlannedMutation(raw, family) {
  if (!raw) return [];
  const mutations = family === 'attempt' ? raw.entries : [raw];
  return mutations.map((value) => validateFrozenManifestEntry({
    action: 'TOMBSTONE', role: value.role, store: value.store,
    source_kind: value.source_kind || 'vault-capsule', source_key: value.source_key,
    source_etag: value.source_etag, source_record_sha256: value.source_record_sha256,
    output_record: value.output_record, output_record_sha256: value.output_record_sha256,
  }));
}

function nextSweepState(state, phase, plan, now, secret) {
  let value = {
    ...state,
    status: 'IDLE',
    lease_hmac_sha256: null,
    lease_expires_at: null,
    cursor: plan.next_cursor,
    run_count: state.run_count + 1,
  };
  if (phase === 'vault') {
    value.vault_counts = {
      inspected: state.vault_counts.inspected + plan.inspected,
      deleted: state.vault_counts.deleted + (plan.mutation ? 1 : 0),
    };
    if (plan.complete) value = { ...value, phase: 'attempt', cursor: null };
  } else {
    const entries = plan.mutation?.entries || [];
    value.attempt_counts = {
      inspected: state.attempt_counts.inspected + plan.inspected,
      deleted: state.attempt_counts.deleted + (plan.mutation ? 1 : 0),
      quarantined: state.attempt_counts.quarantined,
      event_records_deleted: state.attempt_counts.event_records_deleted +
        entries.filter((entry) => entry.source_kind === 'provider-event-index').length,
      provider_message_records_deleted: state.attempt_counts.provider_message_records_deleted +
        entries.filter((entry) => entry.source_kind === 'provider-message-index').length,
    };
    if (plan.complete) {
      const completedAt = now.toISOString();
      value = completedState(value, sign({
        schema: TRANSACTIONAL_EMAIL_RETENTION_RECEIPT_SCHEMA,
        version: 1,
        sweep_hmac_sha256: state.sweep_hmac_sha256,
        started_at: state.started_at,
        completed_at: completedAt,
        vault_counts: value.vault_counts,
        attempt_counts: value.attempt_counts,
        customer_data_stored: false,
      }, 'arc-transactional-email-retention-sweep-completion-record-v1', secret));
    }
  }
  return sign(value, 'arc-transactional-email-retention-sweep-record-v1', secret);
}

function manifestSubject(plan, state, env) {
  if (plan.mutation?.subject_hmac_sha256) return plan.mutation.subject_hmac_sha256;
  if (plan.mutation?.source_key) {
    return createHmac('sha256', env.ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET)
      .update(`arc-transactional-email-retention-vault-subject-v1\n${plan.mutation.source_key}`)
      .digest('hex');
  }
  return createHmac('sha256', env.ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET)
    .update(`arc-transactional-email-retention-control-subject-v1\n${state.sweep_hmac_sha256}\n${state.phase}\n${state.cursor || ''}`)
    .digest('hex');
}

function buildFrozenManifest(env, stateEntry, plan, generation, now, legalHold) {
  const state = stateEntry.value;
  const family = plan.mutation?.family || (state.phase === 'vault' && plan.mutation ? 'vault' : 'control');
  const nextState = nextSweepState(state, state.phase, plan, now,
    emailSendAttemptConfiguration(env).hmacSecret);
  const domainEntries = normalizePlannedMutation(plan.mutation, family);
  const controlEntry = validateFrozenManifestEntry({
    action: 'CONTROL', role: 'CONTROL', store: 'attempt', source_kind: 'sweep-state',
    source_key: TRANSACTIONAL_EMAIL_RETENTION_SWEEP_KEY, source_etag: stateEntry.etag,
    source_record_sha256: recordSha256(state), output_record: nextState,
    output_record_sha256: recordSha256(nextState),
  });
  const entries = [
    ...domainEntries.filter((entry) => entry.role === 'CHILD'),
    controlEntry,
    ...domainEntries.filter((entry) => entry.role === 'PRIMARY'),
  ];
  const unsignedManifest = {
    schema: FROZEN_MANIFEST_SCHEMA,
    version: 1,
    generation,
    sweep_hmac_sha256: state.sweep_hmac_sha256,
    family,
    subject_hmac_sha256: manifestSubject(plan, state, env),
    built_at: now.toISOString(),
    legal_hold_binding_complete: legalHold.resolution.complete,
    legal_hold_bindings: legalHold.resolution.bindings,
    legal_hold_snapshot_sha256: legalHold.digest,
    legal_hold_subject_sha256s: legalHold.resolution.lookups,
    entries,
    customer_data_stored: false,
  };
  return sign(unsignedManifest, FROZEN_MANIFEST_SIGNATURE_DOMAIN,
    env.ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET);
}

function buildMissingFrozenManifest(env, state, input, generation, now, legalHold) {
  const subject = createHmac('sha256', env.ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET)
    .update(`arc-transactional-email-retention-missing-subject-v1\n${input.source_store}\n${input.source_key}`)
    .digest('hex');
  return sign({
    schema: FROZEN_MANIFEST_SCHEMA, version: 1, generation,
    sweep_hmac_sha256: state.sweep_hmac_sha256, family: 'missing',
    subject_hmac_sha256: subject, built_at: now.toISOString(),
    legal_hold_binding_complete: legalHold.resolution.complete,
    legal_hold_bindings: legalHold.resolution.bindings,
    legal_hold_snapshot_sha256: legalHold.digest,
    legal_hold_subject_sha256s: legalHold.resolution.lookups,
    entries: [validateFrozenManifestEntry({
      action: 'MISSING', role: 'PRIMARY', store: input.source_store,
      source_kind: input.source_kind, source_key: input.source_key, source_etag: null,
      source_record_sha256: input.expected_binding_sha256,
      output_record: null, output_record_sha256: recordSha256(null),
    })], customer_data_stored: false,
  }, FROZEN_MANIFEST_SIGNATURE_DOMAIN, env.ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET);
}

function validateFrozenOutput(entry, env) {
  if (entry.action === 'CONTROL') {
    return validateTransactionalEmailRetentionSweepState(entry.output_record,
      emailSendAttemptConfiguration(env).hmacSecret);
  }
  if (entry.store === 'vault') {
    return validateEmailRecipientVaultTombstone(entry.output_record, entry.source_key, env,
      entry.source_record_sha256);
  }
  return validateEmailSendAttemptRetentionTombstone(entry.output_record, entry.source_key, env, {
    recordKind: entry.output_record.record_kind,
    attemptHmac: entry.output_record.attempt_hmac_sha256,
    sourceRecordSha256: entry.source_record_sha256,
  });
}

async function persistFrozenMissingSource(stores, state, manifestEntry, descriptor, authority,
  env, now) {
  const raw = {
    source_store: manifestEntry.store,
    source_kind: manifestEntry.source_kind,
    source_key: manifestEntry.source_key,
    expected_binding_sha256: manifestEntry.source_record_sha256,
  };
  await assertRetentionGenerationFenceAuthority(stores.control, authority, env);
  await persistMissingSourceAnomaly(stores.attempt, state, raw,
    emailSendAttemptConfiguration(env).hmacSecret);
  const sourceKeyHmac = createHmac('sha256', env.ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET)
    .update(`arc-transactional-email-retention-frozen-source-key-v1\n${manifestEntry.store}\n${manifestEntry.source_key}`)
    .digest('hex');
  await recordRetentionMissingSourceAnomaly(stores.control, descriptor, {
    family: 'transactional_email', source_key_hmac_sha256: sourceKeyHmac,
    expected_source_record_sha256: manifestEntry.source_record_sha256,
  }, env, { clock: () => now, authorityEtag: authority.authority_etag });
  throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_BLOCKED');
}

async function readFrozenOutputs(stores, manifest, authorityRef, env, heartbeat) {
  const output = [];
  for (const item of manifest.entries) {
    if (item.action === 'MISSING') {
      throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_BLOCKED');
    }
    await heartbeat();
    await assertRetentionGenerationFenceAuthority(stores.control, authorityRef.current, env);
    const store = stores[item.store];
    const entry = await store.getWithMetadata(item.source_key, { type: 'json', consistency: 'strong' });
    if (!entry || recordSha256(entry.data) !== item.output_record_sha256) {
      throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_OUTPUT_READBACK_INVALID');
    }
    validateFrozenOutput(item, env);
    output.push({ key: item.source_key, record_sha256: item.output_record_sha256, store: item.store });
  }
  return recordSha256(output);
}

async function runFrozenManifest(env, stores, pending, state, now, adapters) {
  const authorityClock = () => {
    const value = new Date(adapters.clock ? adapters.clock() : new Date());
    if (!Number.isFinite(value.getTime())) {
      throw new TypeError('Transactional email retention authority clock is invalid.');
    }
    return value;
  };
  const begun = await beginRetentionFreeze(stores.control, pending.descriptor, env, {
    clock: authorityClock, staleAfterMs: adapters.staleAfterMs,
    emitCriticalAlert: adapters.emitCriticalAlert,
  });
  if (begun.retryable) return Object.freeze({ state: 'IN_PROGRESS', retryable: true });
  if (begun.state === 'COMPLETE') {
    return Object.freeze({ state: 'COMPLETE', idempotent_replay: true,
      next_state: pending.manifest.entries.find((entry) => entry.action === 'CONTROL')?.output_record || null });
  }
  const authorityRef = { current: {
    status: 'FROZEN', generation: begun.generation,
    operation_hmac_sha256: begun.operation_hmac_sha256,
    intent_sha256: begun.intent_sha256, authority_etag: begun.authority_etag,
  } };
  const heartbeat = async () => {
    authorityRef.current = await renewRetentionGenerationFenceAuthority(
      stores.control, authorityRef.current, env, {
        clock: authorityClock, staleAfterMs: adapters.staleAfterMs,
      });
    return authorityRef.current;
  };
  if (adapters.afterSubjectFreeze) await adapters.afterSubjectFreeze({
    manifest: pending.manifest, descriptor: pending.descriptor,
  });
  const holdResolution = canonicalHoldResolution(
    pending.manifest.legal_hold_bindings,
    pending.manifest.legal_hold_subject_sha256s,
    pending.manifest.legal_hold_binding_complete,
  );
  const hold = await legalHoldSnapshot(stores.control, holdResolution, env, now, { heartbeat });
  if (hold.active || hold.digest !== pending.manifest.legal_hold_snapshot_sha256) {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_LEGAL_HOLD_BLOCKED');
  }
  for (const item of pending.manifest.entries) {
    await heartbeat();
    if (item.action === 'MISSING') {
      await persistFrozenMissingSource(stores, state, item, pending.descriptor,
        authorityRef.current, env, now);
    }
    const store = stores[item.store];
    let current = await store.getWithMetadata(item.source_key,
      { type: 'json', consistency: 'strong' });
    if (!current) {
      await persistFrozenMissingSource(stores, state, item, pending.descriptor,
        authorityRef.current, env, now);
    }
    if (recordSha256(current.data) === item.output_record_sha256) {
      validateFrozenOutput(item, env);
      continue;
    }
    if (recordSha256(current.data) !== item.source_record_sha256 || current.etag !== item.source_etag) {
      throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_FROZEN_MANIFEST_DRIFT');
    }
    await assertRetentionGenerationFenceAuthority(stores.control, authorityRef.current, env);
    let writeError = null;
    try {
      await store.setJSON(item.source_key, item.output_record, { onlyIfMatch: item.source_etag });
    } catch (error) { writeError = error; }
    await assertRetentionGenerationFenceAuthority(stores.control, authorityRef.current, env);
    current = await store.getWithMetadata(item.source_key, { type: 'json', consistency: 'strong' });
    if (!current) {
      await persistFrozenMissingSource(stores, state, item, pending.descriptor,
        authorityRef.current, env, now);
    }
    if (recordSha256(current.data) !== item.output_record_sha256) {
      if (writeError) throw writeError;
      throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_FROZEN_WRITE_CONTENTION');
    }
    validateFrozenOutput(item, env);
    if (adapters.afterSubjectMutation) await adapters.afterSubjectMutation(item);
  }
  const outputReadback = await readFrozenOutputs(stores, pending.manifest,
    authorityRef, env, heartbeat);
  const tombstones = pending.manifest.entries.filter((entry) => entry.action === 'TOMBSTONE')
    .map((entry) => entry.output_record_sha256).sort();
  const primary = pending.manifest.entries.find((entry) =>
    entry.action === 'TOMBSTONE' && entry.role === 'PRIMARY');
  const evidence = {
    legal_hold_recheck_sha256: hold.digest,
    output_readback_sha256: outputReadback,
    primary_tombstone_sha256: primary?.output_record_sha256 || recordSha256(null),
    tombstone_set_sha256: recordSha256(tombstones),
  };
  const completed = await completeRetentionFreeze(stores.control, pending.descriptor, evidence, env, {
    clock: authorityClock, authorityEtag: authorityRef.current.authority_etag,
    readback: async ({ authority }) => {
      if (authority) authorityRef.current = authority;
      const digest = await readFrozenOutputs(stores, pending.manifest,
        authorityRef, env, heartbeat);
      if (!authority) return digest;
      return { output_readback_sha256: digest,
        authority_etag: authorityRef.current.authority_etag };
    },
  });
  if (completed.retryable) return Object.freeze({ state: 'IN_PROGRESS', retryable: true });
  return Object.freeze({ state: 'COMPLETE', idempotent_replay: completed.idempotent_replay,
    next_state: pending.manifest.entries.find((entry) => entry.action === 'CONTROL')?.output_record || null });
}

export async function runTransactionalEmailRetentionSweepCycle(env, stores, adapters = {}) {
  const configuration = emailSendAttemptConfiguration(env);
  if (env.ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED !== 'true' || !configuration.enabled) {
    return Object.freeze({ state: 'DISABLED', next_cursor: null });
  }
  if (!stores?.attempt || !stores?.vault || !stores?.control) {
    throw new TypeError('Transactional email retention stores are invalid.');
  }
  if (!retentionGenerationFenceConfiguration(env).ready) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_UNAVAILABLE');
  }
  const secret = configuration.hmacSecret;
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Transactional email retention clock is invalid.');
  const uuid = String((adapters.uuid || randomUUID)());
  const newSweepHmac = () => createHmac('sha256', secret)
    .update(`arc-transactional-email-retention-sweep-id-v1\n${now.toISOString()}\n${uuid}`).digest('hex');
  let stateEntry = await readState(stores.attempt, secret);

  const fence = await ensureRetentionGenerationFence(stores.control, env, { clock: () => now });
  if (fence.record.status === 'FROZEN') {
    const pending = await readFrozenManifest(stores.control, fence.record.operation_hmac_sha256, env);
    if (!pending) {
      return Object.freeze({ state: 'IN_PROGRESS', next_cursor: stateEntry?.value.cursor ?? null,
        sweep_hmac_sha256: stateEntry?.value.sweep_hmac_sha256 ?? null, idempotent_replay: true });
    }
    if (!stateEntry) throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_STATE_UNAVAILABLE');
    const resumed = await runFrozenManifest(env, stores, pending, stateEntry.value, now, adapters);
    if (resumed.retryable) return Object.freeze({ state: 'IN_PROGRESS', next_cursor: stateEntry.value.cursor,
      sweep_hmac_sha256: stateEntry.value.sweep_hmac_sha256, idempotent_replay: true });
    if (resumed.next_state?.status === 'COMPLETE') {
      await ensureReceipt(stores.attempt, resumed.next_state, resumed.next_state.completed_at, secret);
    }
    return Object.freeze({ state: resumed.next_state?.status === 'COMPLETE' ? 'COMPLETE' : 'PARTIAL',
      phase: resumed.next_state?.phase ?? null, next_cursor: resumed.next_state?.cursor ?? null,
      sweep_hmac_sha256: resumed.next_state?.sweep_hmac_sha256 || stateEntry.value.sweep_hmac_sha256,
      idempotent_replay: resumed.idempotent_replay === true });
  }
  if (fence.record.status !== 'OPEN') {
    return Object.freeze({ state: 'IN_PROGRESS', next_cursor: stateEntry?.value.cursor ?? null,
      sweep_hmac_sha256: stateEntry?.value.sweep_hmac_sha256 ?? null, idempotent_replay: true });
  }
  if (!stateEntry) stateEntry = await createState(stores.attempt, freshState(now, newSweepHmac()), secret);
  if (await hasBlockingMissingSourceAnomaly(
    stores.attempt, stateEntry.value.sweep_hmac_sha256, secret,
  )) throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_BLOCKED');

  const durableReceipt = await readReceipt(stores.attempt, stateEntry.value.sweep_hmac_sha256, secret);
  if (durableReceipt && stateEntry.value.status !== 'COMPLETE') {
    stateEntry = await replaceState(stores.attempt, stateEntry,
      completedState(stateEntry.value, durableReceipt), secret);
  }
  if (stateEntry.value.status === 'COMPLETE' && Date.parse(stateEntry.value.next_sweep_at) > now.getTime()) {
    return Object.freeze({ state: 'COMPLETE', next_cursor: null,
      sweep_hmac_sha256: stateEntry.value.sweep_hmac_sha256, idempotent_replay: true });
  }
  if (stateEntry.value.status === 'COMPLETE') {
    stateEntry = await replaceState(stores.attempt, stateEntry,
      freshState(now, newSweepHmac()), secret);
  }
  if (stateEntry.value.status === 'RUNNING' &&
      Date.parse(stateEntry.value.lease_expires_at) > now.getTime()) {
    return Object.freeze({ state: 'IN_PROGRESS', next_cursor: stateEntry.value.cursor,
      sweep_hmac_sha256: stateEntry.value.sweep_hmac_sha256, idempotent_replay: true });
  }

  let missingSource = null;
  const onMissingSource = async (input) => { missingSource = input; };
  let plan;
  try {
    plan = stateEntry.value.phase === 'vault'
      ? await (adapters.planVault || planExpiredEmailRecipientCapsuleRetention)(stores.vault, env, {
        clock: () => now, cursor: stateEntry.value.cursor, onMissingSource,
      })
      : await (adapters.planAttempts || planTerminalEmailSendAttemptRetention)(stores.attempt, env, {
        clock: () => now, cursor: stateEntry.value.cursor,
        limit: adapters.limit === undefined ? 100 : adapters.limit, onMissingSource,
      });
  } catch (error) {
    if (!missingSource) throw error;
  }
  const holdResolution = missingSource
    ? canonicalHoldResolution([], [], true)
    : await resolveLegalHoldBindings(plan, stores, env);
  const holdSnapshot = await legalHoldSnapshot(stores.control, holdResolution, env, now);
  const holds = Object.freeze({ ...holdSnapshot, resolution: holdResolution });
  const manifest = missingSource
    ? buildMissingFrozenManifest(env, stateEntry.value, missingSource,
      fence.record.generation, now, holds)
    : buildFrozenManifest(env, stateEntry, plan, fence.record.generation, now, holds);
  const pending = await persistFrozenManifest(stores.control, manifest, env);
  if (adapters.afterSubjectManifest) await adapters.afterSubjectManifest({
    manifest: pending.manifest, descriptor: pending.descriptor,
  });
  const drift = await readRetentionGenerationFence(stores.control, env);
  if (!drift || drift.record.status !== 'OPEN' ||
      drift.record.generation !== fence.record.generation) {
    return Object.freeze({ state: 'IN_PROGRESS', next_cursor: stateEntry.value.cursor,
      sweep_hmac_sha256: stateEntry.value.sweep_hmac_sha256, idempotent_replay: true });
  }
  const completed = await runFrozenManifest(env, stores, pending, stateEntry.value, now, adapters);
  if (completed.retryable) return Object.freeze({ state: 'IN_PROGRESS', next_cursor: stateEntry.value.cursor,
    sweep_hmac_sha256: stateEntry.value.sweep_hmac_sha256, idempotent_replay: true });
  if (completed.next_state?.status === 'COMPLETE') {
    await ensureReceipt(stores.attempt, completed.next_state, completed.next_state.completed_at, secret);
  }
  return Object.freeze({ state: completed.next_state?.status === 'COMPLETE' ? 'COMPLETE' : 'PARTIAL',
    phase: completed.next_state?.phase ?? null, next_cursor: completed.next_state?.cursor ?? null,
    sweep_hmac_sha256: completed.next_state?.sweep_hmac_sha256 || stateEntry.value.sweep_hmac_sha256,
    idempotent_replay: false });
}
