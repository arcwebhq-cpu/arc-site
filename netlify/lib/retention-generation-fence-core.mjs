import {
  canonicalJson,
  hmacHex,
  safeEqual,
  sha256Hex,
} from './arc2-handoff-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const RETENTION_GENERATION_FENCE_STORE = 'arc-retention-control';
export const RETENTION_GENERATION_FENCE_SECRET_ENV = 'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET';
export const RETENTION_GENERATION_FENCE_STATE_KEY =
  'first-party-retention/generation-fence/state-v1';
export const RETENTION_GENERATION_FENCE_STATE_SCHEMA =
  'arc-first-party-retention-generation-fence-v1';
export const RETENTION_PRODUCER_INTENT_SCHEMA =
  'arc-first-party-retention-producer-intent-v1';
export const RETENTION_FREEZE_INTENT_SCHEMA =
  'arc-first-party-retention-freeze-intent-v1';
export const RETENTION_PRODUCER_COMPLETION_SCHEMA =
  'arc-first-party-retention-producer-completion-v1';
export const RETENTION_FINALIZE_RECEIPT_SCHEMA =
  'arc-first-party-retention-finalize-receipt-v1';
export const RETENTION_MISSING_SOURCE_ANOMALY_SCHEMA =
  'arc-first-party-retention-missing-source-anomaly-v1';
export const RETENTION_GENERATION_FENCE_ALERT_SCHEMA =
  'arc-first-party-retention-generation-fence-alert-v1';

const DEFAULT_STALE_AFTER_MS = 2 * 60_000;
const MIN_STALE_AFTER_MS = 1_000;
const MAX_STALE_AFTER_MS = 24 * 60 * 60_000;
const HEX_64 = /^[a-f0-9]{64}$/;
const ROUTE = /^[a-z0-9][a-z0-9._:/-]{0,159}$/;
const FAMILY = /^[a-z][a-z0-9_-]{0,63}$/;
const FENCE_STATES = Object.freeze(['OPEN', 'WRITING', 'FROZEN']);

const STATE_FIELDS = Object.freeze([
  'entered_at', 'generation', 'intent_sha256', 'operation_hmac_sha256', 'operation_kind',
  'record_hmac_sha256', 'schema', 'stale_at', 'status', 'version',
]);
const PRODUCER_DESCRIPTOR_FIELDS = Object.freeze([
  'idempotency_key_sha256', 'mutation_sha256', 'output_record_sha256', 'route',
  'source_record_sha256', 'subject_hmac_sha256',
]);
const FREEZE_DESCRIPTOR_FIELDS = Object.freeze([
  'generation', 'manifest_entry_count', 'manifest_sha256', 'subject_hmac_sha256',
]);
const PRODUCER_INTENT_FIELDS = Object.freeze([
  'created_at', 'customer_data_stored', 'idempotency_key_sha256', 'kind', 'mutation_sha256',
  'operation_hmac_sha256', 'output_record_sha256', 'record_hmac_sha256', 'route', 'schema',
  'source_record_sha256', 'subject_hmac_sha256', 'version',
]);
const FREEZE_INTENT_FIELDS = Object.freeze([
  'created_at', 'customer_data_stored', 'generation', 'kind', 'manifest_entry_count',
  'manifest_sha256', 'operation_hmac_sha256', 'record_hmac_sha256', 'schema',
  'subject_hmac_sha256', 'version',
]);
const PRODUCER_COMPLETION_FIELDS = Object.freeze([
  'completed_at', 'customer_data_stored', 'generation', 'intent_sha256', 'kind',
  'mutation_sha256', 'operation_hmac_sha256', 'output_record_sha256', 'readback_verified_at',
  'record_hmac_sha256', 'schema', 'source_record_sha256', 'version',
]);
const RETENTION_FINALIZE_FIELDS = Object.freeze([
  'completed_at', 'customer_data_stored', 'generation', 'intent_sha256', 'kind',
  'legal_hold_recheck_sha256', 'manifest_entry_count', 'manifest_sha256',
  'operation_hmac_sha256', 'output_readback_sha256', 'primary_tombstone_sha256',
  'record_hmac_sha256', 'schema', 'subject_hmac_sha256', 'tombstone_set_sha256', 'version',
]);
const RETENTION_FINALIZE_EVIDENCE_FIELDS = Object.freeze([
  'legal_hold_recheck_sha256', 'output_readback_sha256', 'primary_tombstone_sha256',
  'tombstone_set_sha256',
]);
const MISSING_SOURCE_INPUT_FIELDS = Object.freeze([
  'expected_source_record_sha256', 'family', 'source_key_hmac_sha256',
]);
const MISSING_SOURCE_FIELDS = Object.freeze([
  'customer_data_stored', 'detected_at', 'expected_source_record_sha256', 'family',
  'generation', 'manifest_sha256', 'operation_hmac_sha256', 'record_hmac_sha256', 'schema',
  'source_key_hmac_sha256', 'subject_hmac_sha256', 'version',
]);
const ALERT_FIELDS = Object.freeze([
  'customer_data_stored', 'detected_at', 'fence_status', 'generation', 'intent_sha256',
  'operation_hmac_sha256', 'operation_kind', 'reason_code', 'record_hmac_sha256', 'schema',
  'severity', 'stale_at', 'status', 'version',
]);

const SIGNATURE_DOMAINS = Object.freeze({
  state: 'arc-first-party-retention-generation-fence-record-v1',
  producerIntent: 'arc-first-party-retention-producer-intent-record-v1',
  freezeIntent: 'arc-first-party-retention-freeze-intent-record-v1',
  producerCompletion: 'arc-first-party-retention-producer-completion-record-v1',
  finalizeReceipt: 'arc-first-party-retention-finalize-receipt-record-v1',
  missingSource: 'arc-first-party-retention-missing-source-anomaly-record-v1',
  alert: 'arc-first-party-retention-generation-fence-alert-record-v1',
});

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  return value;
}

function exactKeys(value, fields, label) {
  plainObject(value, label);
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    throw new TypeError(`${label} fields are invalid.`);
  }
}

function hex64(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function nonnegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} is invalid.`);
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 1_000_000) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function isoTimestamp(value, label) {
  if (typeof value !== 'string') throw new TypeError(`${label} is invalid.`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new TypeError(`${label} is invalid.`);
  }
  return parsed;
}

function clockDate(adapters = {}) {
  const supplied = adapters.clock ? adapters.clock() : new Date();
  const date = supplied instanceof Date ? new Date(supplied.getTime()) : new Date(supplied);
  if (!Number.isFinite(date.getTime())) throw new TypeError('Retention generation fence clock is invalid.');
  return date;
}

function staleAfterMs(adapters = {}) {
  const value = adapters.staleAfterMs === undefined ? DEFAULT_STALE_AFTER_MS : adapters.staleAfterMs;
  if (!Number.isSafeInteger(value) || value < MIN_STALE_AFTER_MS || value > MAX_STALE_AFTER_MS) {
    throw new TypeError('Retention generation fence stale interval is invalid.');
  }
  return value;
}

function producerHeartbeatIntervalMs(adapters = {}) {
  const leaseMs = staleAfterMs(adapters);
  const value = adapters.heartbeatIntervalMs === undefined
    ? Math.max(250, Math.floor(leaseMs / 3))
    : adapters.heartbeatIntervalMs;
  if (!Number.isSafeInteger(value) || value < 1 || value > Math.floor(leaseMs / 2)) {
    throw new TypeError('Retention producer heartbeat interval is invalid.');
  }
  return value;
}

function startProducerAuthorityHeartbeat(store, env, adapters, getAuthority, setAuthority) {
  const intervalMs = producerHeartbeatIntervalMs(adapters);
  let timer = null;
  let active = null;
  let failure = null;
  let stopped = false;

  const schedule = () => {
    timer = setTimeout(() => {
      active = (async () => {
        try {
          const renewed = await renewRetentionGenerationFenceAuthority(
            store,
            getAuthority(),
            env,
            { clock: adapters.clock, staleAfterMs: staleAfterMs(adapters) },
          );
          setAuthority(renewed);
        } catch (error) {
          failure = error;
          stopped = true;
        }
        if (!stopped) schedule();
      })();
    }, intervalMs);
  };
  schedule();

  return async () => {
    stopped = true;
    if (timer !== null) clearTimeout(timer);
    if (active) await active;
    if (failure) throw failure;
  };
}

function validSecret(value) {
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= 32 &&
    Buffer.byteLength(value, 'utf8') <= 512;
}

export function retentionGenerationFenceConfiguration(env = process.env) {
  const secret = env[RETENTION_GENERATION_FENCE_SECRET_ENV];
  const missing = [];
  const invalid = [];
  if (typeof secret !== 'string' || secret.length === 0) {
    missing.push(RETENTION_GENERATION_FENCE_SECRET_ENV);
  } else if (!validSecret(secret)) {
    invalid.push(RETENTION_GENERATION_FENCE_SECRET_ENV);
  }
  if (validSecret(secret)) {
    if (!sensitiveCredentialsAreIsolated(env, [RETENTION_GENERATION_FENCE_SECRET_ENV])) {
      invalid.push('ARC_FIRST_PARTY_RETENTION_FENCE_SECRET_SEPARATION');
    }
  }
  return Object.freeze({
    ready: missing.length === 0 && invalid.length === 0,
    missing: Object.freeze(missing),
    invalid: Object.freeze(invalid),
  });
}

function requireConfiguration(env) {
  const configuration = retentionGenerationFenceConfiguration(env);
  if (!configuration.ready) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_UNAVAILABLE');
  return { ...configuration, secret: env[RETENTION_GENERATION_FENCE_SECRET_ENV] };
}

function unsignedRecord(value) {
  const { record_hmac_sha256: ignored, ...unsigned } = value;
  return unsigned;
}

function signRecord(value, domain, secret) {
  const unsigned = unsignedRecord(value);
  return {
    ...unsigned,
    record_hmac_sha256: hmacHex(secret, `${domain}\n${canonicalJson(unsigned)}`),
  };
}

function verifySignature(value, domain, secret, label) {
  const signature = hex64(value.record_hmac_sha256, `${label} signature`);
  const expected = hmacHex(secret, `${domain}\n${canonicalJson(unsignedRecord(value))}`);
  if (!safeEqual(signature, expected)) throw new Error(`ARC_${label.toUpperCase().replaceAll(' ', '_')}_SIGNATURE_INVALID`);
  return value;
}

function normalizeProducerDescriptor(raw) {
  exactKeys(raw, PRODUCER_DESCRIPTOR_FIELDS, 'Retention producer descriptor');
  if (typeof raw.route !== 'string' || !ROUTE.test(raw.route)) {
    throw new TypeError('Retention producer route is invalid.');
  }
  for (const field of PRODUCER_DESCRIPTOR_FIELDS.filter((field) => field !== 'route')) {
    hex64(raw[field], `Retention producer ${field}`);
  }
  return Object.freeze({ ...raw });
}

function normalizeFreezeDescriptor(raw) {
  exactKeys(raw, FREEZE_DESCRIPTOR_FIELDS, 'Retention freeze descriptor');
  nonnegativeInteger(raw.generation, 'Retention freeze generation');
  positiveInteger(raw.manifest_entry_count, 'Retention freeze manifest entry count');
  hex64(raw.manifest_sha256, 'Retention freeze manifest digest');
  hex64(raw.subject_hmac_sha256, 'Retention freeze subject HMAC');
  return Object.freeze({ ...raw });
}

function producerOperationId(descriptor, secret) {
  return hmacHex(secret,
    `arc-first-party-retention-producer-operation-id-v1\n${canonicalJson(descriptor)}`);
}

function freezeOperationId(descriptor, secret) {
  return hmacHex(secret,
    `arc-first-party-retention-freeze-operation-id-v1\n${canonicalJson(descriptor)}`);
}

export function retentionProducerOperationHmac(raw, env = process.env) {
  const configuration = requireConfiguration(env);
  return producerOperationId(normalizeProducerDescriptor(raw), configuration.secret);
}

export function retentionFreezeOperationHmac(raw, env = process.env) {
  const configuration = requireConfiguration(env);
  return freezeOperationId(normalizeFreezeDescriptor(raw), configuration.secret);
}

function producerIntentKey(operation) {
  return `first-party-retention/generation-fence/producer-intents/${hex64(operation, 'Producer operation HMAC')}`;
}

function freezeIntentKey(operation) {
  return `first-party-retention/generation-fence/freeze-intents/${hex64(operation, 'Freeze operation HMAC')}`;
}

function producerCompletionKey(operation) {
  return `first-party-retention/generation-fence/producer-completions/${hex64(operation, 'Producer operation HMAC')}`;
}

function finalizeReceiptKey(operation) {
  return `first-party-retention/generation-fence/finalize-receipts/${hex64(operation, 'Freeze operation HMAC')}`;
}

function missingSourcePrefix(operation) {
  return `first-party-retention/generation-fence/missing-source/${hex64(operation, 'Freeze operation HMAC')}/`;
}

function missingSourceKey(operation, sourceKeyHmac) {
  return `${missingSourcePrefix(operation)}${hex64(sourceKeyHmac, 'Retention source-key HMAC')}`;
}

function alertKey(state, reasonCode, secret) {
  const digest = hmacHex(secret, `arc-first-party-retention-generation-fence-alert-id-v1\n${canonicalJson({
    fence_status: state.status,
    generation: state.generation,
    operation_hmac_sha256: state.operation_hmac_sha256,
    reason_code: reasonCode,
    stale_at: state.stale_at,
  })}`);
  return `first-party-retention/generation-fence/critical-alerts/${digest}`;
}

export const retentionGenerationFenceKeys = Object.freeze({
  state: RETENTION_GENERATION_FENCE_STATE_KEY,
  producerIntent: producerIntentKey,
  freezeIntent: freezeIntentKey,
  producerCompletion: producerCompletionKey,
  finalizeReceipt: finalizeReceiptKey,
  missingSourcePrefix,
  missingSource: missingSourceKey,
});

async function getEntry(store, key) {
  if (!store || typeof store.getWithMetadata !== 'function') {
    throw new TypeError('Retention generation fence store is invalid.');
  }
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  return entry ? { value: entry.data, etag: entry.etag } : null;
}

async function createOnly(store, key, value) {
  try {
    const result = await store.setJSON(key, value, { onlyIfNew: true });
    if (result?.modified) return true;
  } catch (error) {
    const raced = await getEntry(store, key);
    if (!raced) throw error;
    return false;
  }
  return false;
}

function validateStateWithSecret(value, secret) {
  exactKeys(value, STATE_FIELDS, 'Retention generation fence state');
  if (value.schema !== RETENTION_GENERATION_FENCE_STATE_SCHEMA || value.version !== 1 ||
      !FENCE_STATES.includes(value.status)) {
    throw new TypeError('Retention generation fence state is invalid.');
  }
  nonnegativeInteger(value.generation, 'Retention generation');
  const entered = isoTimestamp(value.entered_at, 'Retention generation fence entered_at');
  if (value.status === 'OPEN') {
    if (value.operation_kind !== null || value.operation_hmac_sha256 !== null ||
        value.intent_sha256 !== null || value.stale_at !== null) {
      throw new TypeError('Retention OPEN fence state is inconsistent.');
    }
  } else {
    const expectedKind = value.status === 'WRITING' ? 'producer' : 'retention';
    if (value.operation_kind !== expectedKind) {
      throw new TypeError('Retention locked fence kind is inconsistent.');
    }
    hex64(value.operation_hmac_sha256, 'Retention fence operation HMAC');
    hex64(value.intent_sha256, 'Retention fence intent digest');
    if (isoTimestamp(value.stale_at, 'Retention generation fence stale_at') <= entered) {
      throw new TypeError('Retention generation fence stale boundary is invalid.');
    }
  }
  return verifySignature(value, SIGNATURE_DOMAINS.state, secret, 'retention generation fence');
}

export function validateRetentionGenerationFenceState(value, env = process.env) {
  return validateStateWithSecret(value, requireConfiguration(env).secret);
}

async function readStateEntry(store, secret) {
  const entry = await getEntry(store, RETENTION_GENERATION_FENCE_STATE_KEY);
  return entry ? { value: validateStateWithSecret(entry.value, secret), etag: entry.etag } : null;
}

function signedOpenState(generation, enteredAt, secret) {
  return signRecord({
    schema: RETENTION_GENERATION_FENCE_STATE_SCHEMA,
    version: 1,
    status: 'OPEN',
    generation,
    operation_kind: null,
    operation_hmac_sha256: null,
    intent_sha256: null,
    entered_at: enteredAt,
    stale_at: null,
  }, SIGNATURE_DOMAINS.state, secret);
}

async function ensureStateEntry(store, secret, now) {
  let entry = await readStateEntry(store, secret);
  if (entry) return entry;
  const initial = signedOpenState(0, now.toISOString(), secret);
  await createOnly(store, RETENTION_GENERATION_FENCE_STATE_KEY, initial);
  entry = await readStateEntry(store, secret);
  if (!entry) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_STATE_UNAVAILABLE');
  return entry;
}

async function replaceState(store, entry, value, secret) {
  const signed = signRecord(value, SIGNATURE_DOMAINS.state, secret);
  validateStateWithSecret(signed, secret);
  const result = await store.setJSON(RETENTION_GENERATION_FENCE_STATE_KEY, signed,
    { onlyIfMatch: entry.etag });
  if (!result?.modified) return null;
  const stored = await readStateEntry(store, secret);
  if (!stored || canonicalJson(stored.value) !== canonicalJson(signed)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_STATE_READBACK_INVALID');
  }
  return stored;
}

export async function readRetentionGenerationFence(store, env = process.env) {
  const configuration = requireConfiguration(env);
  const entry = await readStateEntry(store, configuration.secret);
  return entry ? Object.freeze({ record: entry.value, etag: entry.etag }) : null;
}

export async function ensureRetentionGenerationFence(store, env = process.env, adapters = {}) {
  const configuration = requireConfiguration(env);
  const entry = await ensureStateEntry(store, configuration.secret, clockDate(adapters));
  return Object.freeze({ record: entry.value, etag: entry.etag });
}

function normalizeAuthority(raw) {
  plainObject(raw, 'Retention generation fence authority');
  if (!['WRITING', 'FROZEN'].includes(raw.status) ||
      !Number.isSafeInteger(raw.generation) || raw.generation < 0 ||
      typeof raw.operation_hmac_sha256 !== 'string' || !HEX_64.test(raw.operation_hmac_sha256) ||
      typeof raw.intent_sha256 !== 'string' || !HEX_64.test(raw.intent_sha256) ||
      typeof raw.authority_etag !== 'string' || raw.authority_etag.length < 1 ||
      raw.authority_etag.length > 512) {
    throw new TypeError('Retention generation fence authority is invalid.');
  }
  return Object.freeze({
    status: raw.status,
    generation: raw.generation,
    operation_hmac_sha256: raw.operation_hmac_sha256,
    intent_sha256: raw.intent_sha256,
    authority_etag: raw.authority_etag,
  });
}

export async function assertRetentionGenerationFenceAuthority(store, rawAuthority,
  env = process.env) {
  const configuration = requireConfiguration(env);
  const authority = normalizeAuthority(rawAuthority);
  const entry = await readStateEntry(store, configuration.secret);
  if (!entry || entry.etag !== authority.authority_etag ||
      entry.value.status !== authority.status ||
      entry.value.generation !== authority.generation ||
      entry.value.operation_hmac_sha256 !== authority.operation_hmac_sha256 ||
      entry.value.intent_sha256 !== authority.intent_sha256) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_AUTHORITY_LOST');
  }
  return Object.freeze({ record: entry.value, etag: entry.etag });
}

export async function renewRetentionGenerationFenceAuthority(store, rawAuthority,
  env = process.env, adapters = {}) {
  const configuration = requireConfiguration(env);
  const authority = normalizeAuthority(rawAuthority);
  const current = await assertRetentionGenerationFenceAuthority(store, authority, env);
  const now = clockDate(adapters);
  const refreshed = lockedState(authority.status, authority.generation,
    authority.operation_hmac_sha256, authority.intent_sha256, now,
    staleAfterMs(adapters), configuration.secret);
  const replaced = await replaceState(store, { value: current.record, etag: current.etag },
    refreshed, configuration.secret);
  if (!replaced) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_AUTHORITY_LOST');
  return Object.freeze({
    status: replaced.value.status,
    generation: replaced.value.generation,
    operation_hmac_sha256: replaced.value.operation_hmac_sha256,
    intent_sha256: replaced.value.intent_sha256,
    authority_etag: replaced.etag,
  });
}

function producerDescriptorFromIntent(value) {
  return normalizeProducerDescriptor(Object.fromEntries(PRODUCER_DESCRIPTOR_FIELDS.map((field) =>
    [field, value[field]])));
}

function freezeDescriptorFromIntent(value) {
  return normalizeFreezeDescriptor(Object.fromEntries(FREEZE_DESCRIPTOR_FIELDS.map((field) =>
    [field, value[field]])));
}

function validateProducerIntentWithSecret(value, secret) {
  exactKeys(value, PRODUCER_INTENT_FIELDS, 'Retention producer intent');
  if (value.schema !== RETENTION_PRODUCER_INTENT_SCHEMA || value.version !== 1 ||
      value.kind !== 'producer' || value.customer_data_stored !== false) {
    throw new TypeError('Retention producer intent is invalid.');
  }
  isoTimestamp(value.created_at, 'Retention producer intent created_at');
  const descriptor = producerDescriptorFromIntent(value);
  if (value.operation_hmac_sha256 !== producerOperationId(descriptor, secret)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_PRODUCER_OPERATION_INVALID');
  }
  return verifySignature(value, SIGNATURE_DOMAINS.producerIntent, secret, 'retention producer intent');
}

export function validateRetentionProducerIntent(value, env = process.env) {
  return validateProducerIntentWithSecret(value, requireConfiguration(env).secret);
}

function validateFreezeIntentWithSecret(value, secret) {
  exactKeys(value, FREEZE_INTENT_FIELDS, 'Retention freeze intent');
  if (value.schema !== RETENTION_FREEZE_INTENT_SCHEMA || value.version !== 1 ||
      value.kind !== 'retention' || value.customer_data_stored !== false) {
    throw new TypeError('Retention freeze intent is invalid.');
  }
  isoTimestamp(value.created_at, 'Retention freeze intent created_at');
  const descriptor = freezeDescriptorFromIntent(value);
  if (value.operation_hmac_sha256 !== freezeOperationId(descriptor, secret)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_FREEZE_OPERATION_INVALID');
  }
  return verifySignature(value, SIGNATURE_DOMAINS.freezeIntent, secret, 'retention freeze intent');
}

export function validateRetentionFreezeIntent(value, env = process.env) {
  return validateFreezeIntentWithSecret(value, requireConfiguration(env).secret);
}

function sameDescriptor(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

async function ensureProducerIntent(store, descriptor, configuration, now) {
  const operation = producerOperationId(descriptor, configuration.secret);
  const key = producerIntentKey(operation);
  let entry = await getEntry(store, key);
  if (!entry) {
    const candidate = signRecord({
      schema: RETENTION_PRODUCER_INTENT_SCHEMA,
      version: 1,
      kind: 'producer',
      operation_hmac_sha256: operation,
      ...descriptor,
      created_at: now.toISOString(),
      customer_data_stored: false,
    }, SIGNATURE_DOMAINS.producerIntent, configuration.secret);
    await createOnly(store, key, candidate);
    entry = await getEntry(store, key);
  }
  if (!entry) throw new Error('ARC_FIRST_PARTY_RETENTION_PRODUCER_INTENT_UNAVAILABLE');
  const value = validateProducerIntentWithSecret(entry.value, configuration.secret);
  if (!sameDescriptor(producerDescriptorFromIntent(value), descriptor)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_PRODUCER_INTENT_CONFLICT');
  }
  return { value, digest: sha256Hex(canonicalJson(value)) };
}

async function ensureFreezeIntent(store, descriptor, configuration, now) {
  const operation = freezeOperationId(descriptor, configuration.secret);
  const key = freezeIntentKey(operation);
  let entry = await getEntry(store, key);
  if (!entry) {
    const candidate = signRecord({
      schema: RETENTION_FREEZE_INTENT_SCHEMA,
      version: 1,
      kind: 'retention',
      operation_hmac_sha256: operation,
      ...descriptor,
      created_at: now.toISOString(),
      customer_data_stored: false,
    }, SIGNATURE_DOMAINS.freezeIntent, configuration.secret);
    await createOnly(store, key, candidate);
    entry = await getEntry(store, key);
  }
  if (!entry) throw new Error('ARC_FIRST_PARTY_RETENTION_FREEZE_INTENT_UNAVAILABLE');
  const value = validateFreezeIntentWithSecret(entry.value, configuration.secret);
  if (!sameDescriptor(freezeDescriptorFromIntent(value), descriptor)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_FREEZE_INTENT_CONFLICT');
  }
  return { value, digest: sha256Hex(canonicalJson(value)) };
}

function contentionResult(state, expectedStatus, operation, intentDigest) {
  void expectedStatus;
  void intentDigest;
  return Object.freeze({
    state: state.status === 'OPEN' ? 'RETRYABLE_DRIFT' : 'RETRYABLE_CONTENTION',
    acquired: false,
    resumed: false,
    retryable: true,
    observed_generation: state.generation,
    operation_hmac_sha256: operation,
  });
}

function lockedState(status, generation, operation, intentDigest, now, duration, secret) {
  return signRecord({
    schema: RETENTION_GENERATION_FENCE_STATE_SCHEMA,
    version: 1,
    status,
    generation,
    operation_kind: status === 'WRITING' ? 'producer' : 'retention',
    operation_hmac_sha256: operation,
    intent_sha256: intentDigest,
    entered_at: now.toISOString(),
    stale_at: new Date(now.getTime() + duration).toISOString(),
  }, SIGNATURE_DOMAINS.state, secret);
}

function validateProducerCompletionWithSecret(value, intent, secret) {
  exactKeys(value, PRODUCER_COMPLETION_FIELDS, 'Retention producer completion receipt');
  if (value.schema !== RETENTION_PRODUCER_COMPLETION_SCHEMA || value.version !== 1 ||
      value.kind !== 'producer' || value.customer_data_stored !== false ||
      value.operation_hmac_sha256 !== intent.operation_hmac_sha256 ||
      value.intent_sha256 !== sha256Hex(canonicalJson(intent)) ||
      value.source_record_sha256 !== intent.source_record_sha256 ||
      value.mutation_sha256 !== intent.mutation_sha256 ||
      value.output_record_sha256 !== intent.output_record_sha256) {
    throw new TypeError('Retention producer completion receipt is invalid.');
  }
  nonnegativeInteger(value.generation, 'Retention producer completion generation');
  const readbackAt = isoTimestamp(value.readback_verified_at,
    'Retention producer completion readback_verified_at');
  if (isoTimestamp(value.completed_at, 'Retention producer completion completed_at') < readbackAt) {
    throw new TypeError('Retention producer completion ordering is invalid.');
  }
  return verifySignature(value, SIGNATURE_DOMAINS.producerCompletion, secret,
    'retention producer completion');
}

export function validateRetentionProducerCompletionReceipt(value, intent, env = process.env) {
  const configuration = requireConfiguration(env);
  return validateProducerCompletionWithSecret(value,
    validateProducerIntentWithSecret(intent, configuration.secret), configuration.secret);
}

function validateFinalizeReceiptWithSecret(value, intent, secret) {
  exactKeys(value, RETENTION_FINALIZE_FIELDS, 'Retention finalize receipt');
  if (value.schema !== RETENTION_FINALIZE_RECEIPT_SCHEMA || value.version !== 1 ||
      value.kind !== 'retention' || value.customer_data_stored !== false ||
      value.operation_hmac_sha256 !== intent.operation_hmac_sha256 || value.generation !== intent.generation ||
      value.intent_sha256 !== sha256Hex(canonicalJson(intent)) ||
      value.subject_hmac_sha256 !== intent.subject_hmac_sha256 ||
      value.manifest_sha256 !== intent.manifest_sha256 ||
      value.manifest_entry_count !== intent.manifest_entry_count) {
    throw new TypeError('Retention finalize receipt is invalid.');
  }
  for (const field of RETENTION_FINALIZE_EVIDENCE_FIELDS) {
    hex64(value[field], `Retention finalize ${field}`);
  }
  isoTimestamp(value.completed_at, 'Retention finalize completed_at');
  return verifySignature(value, SIGNATURE_DOMAINS.finalizeReceipt, secret,
    'retention finalize receipt');
}

export function validateRetentionFinalizeReceipt(value, intent, env = process.env) {
  const configuration = requireConfiguration(env);
  return validateFinalizeReceiptWithSecret(value,
    validateFreezeIntentWithSecret(intent, configuration.secret), configuration.secret);
}

async function readProducerIntent(store, operation, configuration) {
  const entry = await getEntry(store, producerIntentKey(operation));
  return entry ? validateProducerIntentWithSecret(entry.value, configuration.secret) : null;
}

async function readFreezeIntent(store, operation, configuration) {
  const entry = await getEntry(store, freezeIntentKey(operation));
  return entry ? validateFreezeIntentWithSecret(entry.value, configuration.secret) : null;
}

async function readProducerCompletion(store, operation, intent, configuration) {
  const entry = await getEntry(store, producerCompletionKey(operation));
  return entry ? validateProducerCompletionWithSecret(entry.value, intent, configuration.secret) : null;
}

async function readFinalizeReceipt(store, operation, intent, configuration) {
  const entry = await getEntry(store, finalizeReceiptKey(operation));
  return entry ? validateFinalizeReceiptWithSecret(entry.value, intent, configuration.secret) : null;
}

function completeReplay(state, receipt, operation) {
  return Object.freeze({
    state: 'COMPLETE',
    acquired: false,
    resumed: true,
    retryable: false,
    idempotent_replay: true,
    generation: receipt.generation,
    observed_generation: state.generation,
    operation_hmac_sha256: operation,
    receipt,
  });
}

export async function beginRetentionProducerOperation(store, rawDescriptor, env = process.env, adapters = {}) {
  const configuration = requireConfiguration(env);
  const descriptor = normalizeProducerDescriptor(rawDescriptor);
  const expectedGeneration = adapters.expectedGeneration;
  if (expectedGeneration !== undefined) {
    nonnegativeInteger(expectedGeneration, 'Retention producer expected generation');
  }
  const now = clockDate(adapters);
  const duration = staleAfterMs(adapters);
  const intent = await ensureProducerIntent(store, descriptor, configuration, now);
  const operation = intent.value.operation_hmac_sha256;
  let state = await ensureStateEntry(store, configuration.secret, now);
  if (expectedGeneration !== undefined && state.value.generation !== expectedGeneration) {
    return Object.freeze({
      state: 'RETRYABLE_DRIFT', acquired: false, resumed: false, retryable: true,
      observed_generation: state.value.generation,
      operation_hmac_sha256: operation,
    });
  }
  const receipt = await readProducerCompletion(store, operation, intent.value, configuration);
  if (receipt && state.value.generation > receipt.generation) {
    return completeReplay(state.value, receipt, operation);
  }
  if (state.value.status === 'WRITING' && state.value.operation_hmac_sha256 === operation &&
      state.value.intent_sha256 === intent.digest) {
    if (!receipt && now.getTime() < Date.parse(state.value.stale_at)) {
      return contentionResult(state.value, 'WRITING', operation, intent.digest);
    }
    let staleAlert = null;
    if (!receipt) {
      staleAlert = await emitCriticalAlert(store, state.value,
        'FENCE_STALE_EXACT_RETRY_RESUMED', configuration, adapters);
      const refreshed = lockedState('WRITING', state.value.generation, operation, intent.digest,
        now, duration, configuration.secret);
      const replaced = await replaceState(store, state, refreshed, configuration.secret);
      if (!replaced) {
        state = await readStateEntry(store, configuration.secret);
        if (!state) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_STATE_UNAVAILABLE');
        return contentionResult(state.value, 'WRITING', operation, intent.digest);
      }
      state = replaced;
    }
    return Object.freeze({
      state: 'WRITING', acquired: true, resumed: true, retryable: false,
      completion_pending: Boolean(receipt), generation: state.value.generation,
      operation_hmac_sha256: operation, intent: intent.value,
      intent_sha256: intent.digest, authority_etag: state.etag,
      critical_alert: Boolean(staleAlert), alert_created: staleAlert?.created || false,
    });
  }
  if (receipt) throw new Error('ARC_FIRST_PARTY_RETENTION_PRODUCER_COMPLETION_STATE_INVALID');
  if (state.value.status !== 'OPEN') {
    return contentionResult(state.value, 'WRITING', operation, intent.digest);
  }
  const next = lockedState('WRITING', state.value.generation, operation, intent.digest,
    now, duration, configuration.secret);
  const replaced = await replaceState(store, state, next, configuration.secret);
  if (!replaced) {
    state = await readStateEntry(store, configuration.secret);
    if (!state) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_STATE_UNAVAILABLE');
    return contentionResult(state.value, 'WRITING', operation, intent.digest);
  }
  return Object.freeze({
    state: 'WRITING', acquired: true, resumed: false, retryable: false,
    completion_pending: false, generation: replaced.value.generation,
    operation_hmac_sha256: operation, intent: intent.value,
    intent_sha256: intent.digest, authority_etag: replaced.etag,
  });
}

export async function beginRetentionFreeze(store, rawDescriptor, env = process.env, adapters = {}) {
  const configuration = requireConfiguration(env);
  const descriptor = normalizeFreezeDescriptor(rawDescriptor);
  const now = clockDate(adapters);
  const duration = staleAfterMs(adapters);
  const intent = await ensureFreezeIntent(store, descriptor, configuration, now);
  const operation = intent.value.operation_hmac_sha256;
  let state = await ensureStateEntry(store, configuration.secret, now);
  const receipt = await readFinalizeReceipt(store, operation, intent.value, configuration);
  if (receipt && state.value.generation > receipt.generation) {
    return completeReplay(state.value, receipt, operation);
  }
  if (state.value.status === 'FROZEN' && state.value.operation_hmac_sha256 === operation &&
      state.value.intent_sha256 === intent.digest) {
    if (!receipt && now.getTime() < Date.parse(state.value.stale_at)) {
      return contentionResult(state.value, 'FROZEN', operation, intent.digest);
    }
    let staleAlert = null;
    if (!receipt) {
      staleAlert = await emitCriticalAlert(store, state.value,
        'FENCE_STALE_EXACT_RETRY_RESUMED', configuration, adapters);
      const refreshed = lockedState('FROZEN', state.value.generation, operation, intent.digest,
        now, duration, configuration.secret);
      const replaced = await replaceState(store, state, refreshed, configuration.secret);
      if (!replaced) {
        state = await readStateEntry(store, configuration.secret);
        if (!state) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_STATE_UNAVAILABLE');
        return contentionResult(state.value, 'FROZEN', operation, intent.digest);
      }
      state = replaced;
    }
    return Object.freeze({
      state: 'FROZEN', acquired: true, resumed: true, retryable: false,
      completion_pending: Boolean(receipt), generation: state.value.generation,
      operation_hmac_sha256: operation, intent: intent.value,
      intent_sha256: intent.digest, authority_etag: state.etag,
      critical_alert: Boolean(staleAlert), alert_created: staleAlert?.created || false,
    });
  }
  if (receipt) throw new Error('ARC_FIRST_PARTY_RETENTION_FINALIZE_STATE_INVALID');
  if (state.value.status !== 'OPEN' || state.value.generation !== descriptor.generation) {
    return contentionResult(state.value, 'FROZEN', operation, intent.digest);
  }
  const next = lockedState('FROZEN', descriptor.generation, operation, intent.digest,
    now, duration, configuration.secret);
  const replaced = await replaceState(store, state, next, configuration.secret);
  if (!replaced) {
    state = await readStateEntry(store, configuration.secret);
    if (!state) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_STATE_UNAVAILABLE');
    return contentionResult(state.value, 'FROZEN', operation, intent.digest);
  }
  return Object.freeze({
    state: 'FROZEN', acquired: true, resumed: false, retryable: false,
    completion_pending: false, generation: replaced.value.generation,
    operation_hmac_sha256: operation, intent: intent.value,
    intent_sha256: intent.digest, authority_etag: replaced.etag,
  });
}

function normalizeOutputReadback(value, field, label) {
  if (typeof value === 'string') return hex64(value, label);
  exactKeys(value, [field], label);
  return hex64(value[field], label);
}

async function ensureProducerCompletion(store, intent, generation, now, configuration) {
  const key = producerCompletionKey(intent.operation_hmac_sha256);
  let entry = await getEntry(store, key);
  let created = false;
  if (!entry) {
    const candidate = signRecord({
      schema: RETENTION_PRODUCER_COMPLETION_SCHEMA,
      version: 1,
      kind: 'producer',
      operation_hmac_sha256: intent.operation_hmac_sha256,
      intent_sha256: sha256Hex(canonicalJson(intent)),
      generation,
      source_record_sha256: intent.source_record_sha256,
      mutation_sha256: intent.mutation_sha256,
      output_record_sha256: intent.output_record_sha256,
      readback_verified_at: now.toISOString(),
      completed_at: now.toISOString(),
      customer_data_stored: false,
    }, SIGNATURE_DOMAINS.producerCompletion, configuration.secret);
    created = await createOnly(store, key, candidate);
    entry = await getEntry(store, key);
  }
  if (!entry) throw new Error('ARC_FIRST_PARTY_RETENTION_PRODUCER_COMPLETION_UNAVAILABLE');
  const value = validateProducerCompletionWithSecret(entry.value, intent, configuration.secret);
  if (value.generation !== generation) throw new Error('ARC_FIRST_PARTY_RETENTION_PRODUCER_COMPLETION_CONFLICT');
  return { value, created };
}

async function ensureFinalizeReceipt(store, intent, evidence, now, configuration) {
  const key = finalizeReceiptKey(intent.operation_hmac_sha256);
  let entry = await getEntry(store, key);
  let created = false;
  if (!entry) {
    const candidate = signRecord({
      schema: RETENTION_FINALIZE_RECEIPT_SCHEMA,
      version: 1,
      kind: 'retention',
      operation_hmac_sha256: intent.operation_hmac_sha256,
      intent_sha256: sha256Hex(canonicalJson(intent)),
      generation: intent.generation,
      subject_hmac_sha256: intent.subject_hmac_sha256,
      manifest_sha256: intent.manifest_sha256,
      manifest_entry_count: intent.manifest_entry_count,
      ...evidence,
      completed_at: now.toISOString(),
      customer_data_stored: false,
    }, SIGNATURE_DOMAINS.finalizeReceipt, configuration.secret);
    created = await createOnly(store, key, candidate);
    entry = await getEntry(store, key);
  }
  if (!entry) throw new Error('ARC_FIRST_PARTY_RETENTION_FINALIZE_RECEIPT_UNAVAILABLE');
  const value = validateFinalizeReceiptWithSecret(entry.value, intent, configuration.secret);
  for (const field of RETENTION_FINALIZE_EVIDENCE_FIELDS) {
    if (value[field] !== evidence[field]) throw new Error('ARC_FIRST_PARTY_RETENTION_FINALIZE_RECEIPT_CONFLICT');
  }
  return { value, created };
}

async function advanceCompletedOperation(store, stateStatus, operation, intentDigest, generation,
  receipt, configuration, authorityEtag = null) {
  let state = await readStateEntry(store, configuration.secret);
  if (!state) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_STATE_UNAVAILABLE');
  if (state.value.generation > generation) return { state: state.value, advanced: false };
  if (authorityEtag !== null && state.etag !== authorityEtag) {
    return { state: state.value, advanced: false, retryable: true };
  }
  if (state.value.generation !== generation || state.value.status !== stateStatus ||
      state.value.operation_hmac_sha256 !== operation || state.value.intent_sha256 !== intentDigest) {
    return { state: state.value, advanced: false, retryable: true };
  }
  if (generation === Number.MAX_SAFE_INTEGER) throw new Error('ARC_FIRST_PARTY_RETENTION_GENERATION_EXHAUSTED');
  const opened = signedOpenState(generation + 1, receipt.completed_at, configuration.secret);
  const replaced = await replaceState(store, state, opened, configuration.secret);
  if (replaced) return { state: replaced.value, advanced: true };
  state = await readStateEntry(store, configuration.secret);
  if (!state) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_STATE_UNAVAILABLE');
  if (state.value.generation > generation) return { state: state.value, advanced: false };
  return { state: state.value, advanced: false, retryable: true };
}

export async function completeRetentionProducerOperation(store, rawDescriptor, env = process.env, adapters = {}) {
  const configuration = requireConfiguration(env);
  const descriptor = normalizeProducerDescriptor(rawDescriptor);
  if (typeof adapters.readback !== 'function') {
    throw new TypeError('Retention producer strong readback adapter is required.');
  }
  const operation = producerOperationId(descriptor, configuration.secret);
  const intent = await readProducerIntent(store, operation, configuration);
  if (!intent || !sameDescriptor(producerDescriptorFromIntent(intent), descriptor)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_PRODUCER_INTENT_INVALID');
  }
  let state = await readStateEntry(store, configuration.secret);
  if (!state) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_STATE_UNAVAILABLE');
  let receipt = await readProducerCompletion(store, operation, intent, configuration);
  const generation = receipt?.generation ?? state.value.generation;
  const intentDigest = sha256Hex(canonicalJson(intent));
  if (!receipt && (state.value.status !== 'WRITING' || state.value.operation_hmac_sha256 !== operation ||
      state.value.intent_sha256 !== intentDigest)) {
    return contentionResult(state.value, 'WRITING', operation, intentDigest);
  }
  let authority = receipt ? null : Object.freeze({
    status: 'WRITING',
    generation,
    operation_hmac_sha256: operation,
    intent_sha256: intentDigest,
    authority_etag: adapters.authorityEtag,
  });
  if (authority) {
    await assertRetentionGenerationFenceAuthority(store, authority, env);
  }
  const readback = normalizeOutputReadback(await adapters.readback(Object.freeze({
    generation, operation_hmac_sha256: operation, intent,
  })), 'output_record_sha256', 'Retention producer output readback');
  if (readback !== descriptor.output_record_sha256) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_PRODUCER_OUTPUT_READBACK_INVALID');
  }
  if (!receipt) {
    await assertRetentionGenerationFenceAuthority(store, authority, env);
    const ensured = await ensureProducerCompletion(store, intent, generation, clockDate(adapters), configuration);
    receipt = ensured.value;
    if (ensured.created && adapters.afterCompletionReceipt) {
      await adapters.afterCompletionReceipt(receipt);
    }
  }
  const advanced = await advanceCompletedOperation(store, 'WRITING', operation,
    intentDigest, receipt.generation, receipt, configuration, authority?.authority_etag ?? null);
  if (advanced.retryable) {
    return Object.freeze({
      state: 'RETRYABLE_CONTENTION', retryable: true, idempotent_replay: false,
      generation: receipt.generation, operation_hmac_sha256: operation, receipt,
    });
  }
  return Object.freeze({
    state: 'COMPLETE', retryable: false, idempotent_replay: !advanced.advanced,
    generation: receipt.generation, observed_generation: advanced.state.generation,
    operation_hmac_sha256: operation, receipt,
  });
}

export async function runRetentionProducerOperation(store, rawDescriptor, env = process.env, adapters = {}) {
  if (typeof adapters.readSource !== 'function' || typeof adapters.readOutput !== 'function' ||
      typeof adapters.mutate !== 'function') {
    throw new TypeError('Retention producer source, mutation, and output adapters are required.');
  }
  const descriptor = normalizeProducerDescriptor(rawDescriptor);
  const begun = await beginRetentionProducerOperation(store, descriptor, env, adapters);
  if (begun.retryable) return begun;
  if (begun.state === 'COMPLETE') {
    return completeRetentionProducerOperation(store, descriptor, env, {
      ...adapters,
      readback: adapters.readOutput,
    });
  }
  let fenceAuthority = Object.freeze({
    status: 'WRITING',
    generation: begun.generation,
    operation_hmac_sha256: begun.operation_hmac_sha256,
    intent_sha256: begun.intent_sha256,
    authority_etag: begun.authority_etag,
  });
  const authority = Object.freeze({
    generation: begun.generation,
    operation_hmac_sha256: begun.operation_hmac_sha256,
    intent: begun.intent || null,
    resumed: begun.resumed,
  });
  const assertAuthority = () => assertRetentionGenerationFenceAuthority(store, fenceAuthority, env);
  // A fresh operation always performs the authoritative source/tombstone read
  // before it may mutate. An exact retry may first validate that the expected
  // deterministic output already exists, but must reread the source before
  // resuming any incomplete mutation.
  let sourceRead = false;
  if (!begun.resumed) {
    await assertAuthority();
    const source = normalizeOutputReadback(await adapters.readSource(authority),
      'source_record_sha256', 'Retention producer source readback');
    await assertAuthority();
    if (source !== descriptor.source_record_sha256) {
      throw new Error('ARC_FIRST_PARTY_RETENTION_PRODUCER_SOURCE_CHANGED');
    }
    sourceRead = true;
  }
  await assertAuthority();
  const existingOutput = normalizeOutputReadback(await adapters.readOutput(authority),
    'output_record_sha256', 'Retention producer output readback');
  await assertAuthority();
  if (existingOutput !== descriptor.output_record_sha256) {
    if (!sourceRead) {
      await assertAuthority();
      const source = normalizeOutputReadback(await adapters.readSource(authority),
        'source_record_sha256', 'Retention producer source readback');
      await assertAuthority();
      if (source !== descriptor.source_record_sha256) {
        throw new Error('ARC_FIRST_PARTY_RETENTION_PRODUCER_SOURCE_CHANGED');
      }
    }
    await assertAuthority();
    const stopHeartbeat = startProducerAuthorityHeartbeat(
      store,
      env,
      adapters,
      () => fenceAuthority,
      (renewed) => { fenceAuthority = renewed; },
    );
    let mutationFailure = null;
    try {
      await adapters.mutate(authority);
    } catch (error) {
      mutationFailure = error;
    }
    // Completion and output readback may use only the latest exact ETag. Stop
    // the periodic renewal and await an in-flight CAS before inspecting either
    // the mutation result or the fence authority.
    await stopHeartbeat();
    if (mutationFailure) throw mutationFailure;
    await assertAuthority();
  }
  await assertAuthority();
  return completeRetentionProducerOperation(store, descriptor, env, {
    ...adapters,
    authorityEtag: fenceAuthority.authority_etag,
    readback: adapters.readOutput,
  });
}

function normalizeFinalizeEvidence(raw) {
  exactKeys(raw, RETENTION_FINALIZE_EVIDENCE_FIELDS, 'Retention finalize evidence');
  for (const field of RETENTION_FINALIZE_EVIDENCE_FIELDS) {
    hex64(raw[field], `Retention finalize ${field}`);
  }
  return Object.freeze({ ...raw });
}

function validateMissingSourceWithSecret(value, intent, secret) {
  exactKeys(value, MISSING_SOURCE_FIELDS, 'Retention missing-source anomaly');
  if (value.schema !== RETENTION_MISSING_SOURCE_ANOMALY_SCHEMA || value.version !== 1 ||
      value.customer_data_stored !== false || value.operation_hmac_sha256 !== intent.operation_hmac_sha256 ||
      value.generation !== intent.generation || value.subject_hmac_sha256 !== intent.subject_hmac_sha256 ||
      value.manifest_sha256 !== intent.manifest_sha256 || typeof value.family !== 'string' ||
      !FAMILY.test(value.family)) {
    throw new TypeError('Retention missing-source anomaly is invalid.');
  }
  hex64(value.source_key_hmac_sha256, 'Retention missing-source key HMAC');
  hex64(value.expected_source_record_sha256, 'Retention missing-source expected record digest');
  isoTimestamp(value.detected_at, 'Retention missing-source detected_at');
  return verifySignature(value, SIGNATURE_DOMAINS.missingSource, secret,
    'retention missing source anomaly');
}

export function validateRetentionMissingSourceAnomaly(value, intent, env = process.env) {
  const configuration = requireConfiguration(env);
  return validateMissingSourceWithSecret(value,
    validateFreezeIntentWithSecret(intent, configuration.secret), configuration.secret);
}

export async function recordRetentionMissingSourceAnomaly(store, rawFreezeDescriptor, rawAnomaly,
  env = process.env, adapters = {}) {
  const configuration = requireConfiguration(env);
  const descriptor = normalizeFreezeDescriptor(rawFreezeDescriptor);
  exactKeys(rawAnomaly, MISSING_SOURCE_INPUT_FIELDS, 'Retention missing-source input');
  if (typeof rawAnomaly.family !== 'string' || !FAMILY.test(rawAnomaly.family)) {
    throw new TypeError('Retention missing-source family is invalid.');
  }
  hex64(rawAnomaly.source_key_hmac_sha256, 'Retention missing-source key HMAC');
  hex64(rawAnomaly.expected_source_record_sha256,
    'Retention missing-source expected record digest');
  const operation = freezeOperationId(descriptor, configuration.secret);
  const intent = await readFreezeIntent(store, operation, configuration);
  const state = await readStateEntry(store, configuration.secret);
  if (!intent || !state || state.value.status !== 'FROZEN' ||
      state.value.operation_hmac_sha256 !== operation ||
      state.value.intent_sha256 !== sha256Hex(canonicalJson(intent))) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_FREEZE_AUTHORITY_INVALID');
  }
  const authority = Object.freeze({
    status: 'FROZEN',
    generation: descriptor.generation,
    operation_hmac_sha256: operation,
    intent_sha256: sha256Hex(canonicalJson(intent)),
    authority_etag: adapters.authorityEtag,
  });
  await assertRetentionGenerationFenceAuthority(store, authority, env);
  const key = missingSourceKey(operation, rawAnomaly.source_key_hmac_sha256);
  let entry = await getEntry(store, key);
  let created = false;
  if (!entry) {
    await assertRetentionGenerationFenceAuthority(store, authority, env);
    const candidate = signRecord({
      schema: RETENTION_MISSING_SOURCE_ANOMALY_SCHEMA,
      version: 1,
      operation_hmac_sha256: operation,
      generation: descriptor.generation,
      subject_hmac_sha256: descriptor.subject_hmac_sha256,
      manifest_sha256: descriptor.manifest_sha256,
      ...rawAnomaly,
      detected_at: clockDate(adapters).toISOString(),
      customer_data_stored: false,
    }, SIGNATURE_DOMAINS.missingSource, configuration.secret);
    created = await createOnly(store, key, candidate);
    entry = await getEntry(store, key);
  }
  await assertRetentionGenerationFenceAuthority(store, authority, env);
  if (!entry) throw new Error('ARC_FIRST_PARTY_RETENTION_MISSING_SOURCE_ANOMALY_UNAVAILABLE');
  const value = validateMissingSourceWithSecret(entry.value, intent, configuration.secret);
  if (value.family !== rawAnomaly.family ||
      value.source_key_hmac_sha256 !== rawAnomaly.source_key_hmac_sha256 ||
      value.expected_source_record_sha256 !== rawAnomaly.expected_source_record_sha256) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_MISSING_SOURCE_ANOMALY_CONFLICT');
  }
  return Object.freeze({ anomaly: value, idempotent_replay: !created });
}

async function listEntries(store, prefix) {
  if (!store || typeof store.list !== 'function') {
    throw new TypeError('Retention generation fence store listing is unavailable.');
  }
  const listing = store.list({ prefix, paginate: true });
  const pages = listing && typeof listing[Symbol.asyncIterator] === 'function'
    ? listing : (async function *single() { yield await listing; })();
  const entries = [];
  let prior = null;
  for await (const page of pages) {
    if (!page || !Array.isArray(page.blobs)) {
      throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_LIST_UNAVAILABLE');
    }
    for (const blob of page.blobs) {
      if (!blob || typeof blob.key !== 'string' || !blob.key.startsWith(prefix) ||
          prior !== null && blob.key <= prior) {
        throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_LIST_INVALID');
      }
      prior = blob.key;
      entries.push(blob.key);
    }
  }
  return entries;
}

async function hasMissingSource(store, intent, configuration) {
  const keys = await listEntries(store, missingSourcePrefix(intent.operation_hmac_sha256));
  for (const key of keys) {
    const entry = await getEntry(store, key);
    if (!entry) throw new Error('ARC_FIRST_PARTY_RETENTION_MISSING_SOURCE_EVIDENCE_MISSING');
    validateMissingSourceWithSecret(entry.value, intent, configuration.secret);
  }
  return keys.length > 0;
}

export async function completeRetentionFreeze(store, rawDescriptor, rawEvidence,
  env = process.env, adapters = {}) {
  const configuration = requireConfiguration(env);
  const descriptor = normalizeFreezeDescriptor(rawDescriptor);
  const evidence = normalizeFinalizeEvidence(rawEvidence);
  if (typeof adapters.readback !== 'function') {
    throw new TypeError('Retention finalize strong readback adapter is required.');
  }
  const operation = freezeOperationId(descriptor, configuration.secret);
  const intent = await readFreezeIntent(store, operation, configuration);
  if (!intent || !sameDescriptor(freezeDescriptorFromIntent(intent), descriptor)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_FREEZE_INTENT_INVALID');
  }
  const state = await readStateEntry(store, configuration.secret);
  if (!state) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_STATE_UNAVAILABLE');
  let receipt = await readFinalizeReceipt(store, operation, intent, configuration);
  const intentDigest = sha256Hex(canonicalJson(intent));
  if (!receipt && (state.value.status !== 'FROZEN' || state.value.generation !== descriptor.generation ||
      state.value.operation_hmac_sha256 !== operation ||
      state.value.intent_sha256 !== intentDigest)) {
    return contentionResult(state.value, 'FROZEN', operation, intentDigest);
  }
  let authority = receipt ? null : Object.freeze({
    status: 'FROZEN',
    generation: descriptor.generation,
    operation_hmac_sha256: operation,
    intent_sha256: intentDigest,
    authority_etag: adapters.authorityEtag,
  });
  if (authority) await assertRetentionGenerationFenceAuthority(store, authority, env);
  if (await hasMissingSource(store, intent, configuration)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_MISSING_SOURCE_BLOCKED');
  }
  const rawReadback = await adapters.readback(Object.freeze({
    generation: descriptor.generation, operation_hmac_sha256: operation, intent,
    authority,
  }));
  let readback;
  if (rawReadback && typeof rawReadback === 'object' &&
      !Array.isArray(rawReadback) && Object.getPrototypeOf(rawReadback) === Object.prototype &&
      JSON.stringify(Object.keys(rawReadback).sort()) ===
        JSON.stringify(['authority_etag', 'output_readback_sha256'])) {
    readback = hex64(rawReadback.output_readback_sha256,
      'Retention finalize output readback');
    if (authority) {
      authority = Object.freeze({ ...authority,
        authority_etag: typeof rawReadback.authority_etag === 'string'
          ? rawReadback.authority_etag : '' });
      await assertRetentionGenerationFenceAuthority(store, authority, env);
    }
  } else {
    readback = normalizeOutputReadback(rawReadback,
      'output_readback_sha256', 'Retention finalize output readback');
  }
  if (readback !== evidence.output_readback_sha256) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_FINALIZE_READBACK_INVALID');
  }
  if (!receipt) {
    await assertRetentionGenerationFenceAuthority(store, authority, env);
    const ensured = await ensureFinalizeReceipt(store, intent, evidence, clockDate(adapters), configuration);
    receipt = ensured.value;
    if (ensured.created && adapters.afterCompletionReceipt) {
      await adapters.afterCompletionReceipt(receipt);
    }
  }
  const advanced = await advanceCompletedOperation(store, 'FROZEN', operation,
    intentDigest, descriptor.generation, receipt, configuration, authority?.authority_etag ?? null);
  if (advanced.retryable) {
    return Object.freeze({
      state: 'RETRYABLE_CONTENTION', retryable: true, idempotent_replay: false,
      generation: descriptor.generation, operation_hmac_sha256: operation, receipt,
    });
  }
  return Object.freeze({
    state: 'COMPLETE', retryable: false, idempotent_replay: !advanced.advanced,
    generation: descriptor.generation, observed_generation: advanced.state.generation,
    operation_hmac_sha256: operation, receipt,
  });
}

function validateAlertWithSecret(value, secret) {
  exactKeys(value, ALERT_FIELDS, 'Retention generation fence alert');
  if (value.schema !== RETENTION_GENERATION_FENCE_ALERT_SCHEMA || value.version !== 1 ||
      value.severity !== 'CRITICAL' || value.status !== 'OPEN' ||
      value.customer_data_stored !== false || !['WRITING', 'FROZEN'].includes(value.fence_status) ||
      !['producer', 'retention'].includes(value.operation_kind) ||
      typeof value.reason_code !== 'string' || !/^[A-Z][A-Z0-9_]{2,79}$/.test(value.reason_code)) {
    throw new TypeError('Retention generation fence alert is invalid.');
  }
  nonnegativeInteger(value.generation, 'Retention generation fence alert generation');
  hex64(value.operation_hmac_sha256, 'Retention generation fence alert operation HMAC');
  hex64(value.intent_sha256, 'Retention generation fence alert intent digest');
  isoTimestamp(value.stale_at, 'Retention generation fence alert stale_at');
  isoTimestamp(value.detected_at, 'Retention generation fence alert detected_at');
  return verifySignature(value, SIGNATURE_DOMAINS.alert, secret,
    'retention generation fence alert');
}

export function validateRetentionGenerationFenceAlert(value, env = process.env) {
  return validateAlertWithSecret(value, requireConfiguration(env).secret);
}

export async function raiseRetentionGenerationFenceCriticalAlert(
  store,
  rawAuthority,
  reasonCode,
  env = process.env,
  adapters = {},
) {
  const configuration = requireConfiguration(env);
  const authority = normalizeAuthority(rawAuthority);
  if (typeof reasonCode !== 'string' || !/^[A-Z][A-Z0-9_]{2,79}$/.test(reasonCode)) {
    throw new TypeError('Retention generation fence critical reason is invalid.');
  }
  const current = await assertRetentionGenerationFenceAuthority(store, authority, env);
  const emitted = await emitCriticalAlert(
    store,
    current.record,
    reasonCode,
    configuration,
    {},
  );
  // Queue adapters are create-only/deduplicating. Invoke them on every exact
  // retry so a prior queue-delivery failure cannot permanently strand the
  // signed control-store alert.
  if (typeof adapters.emitCriticalAlert === 'function') {
    await adapters.emitCriticalAlert(emitted.alert);
  }
  return Object.freeze({ alert: emitted.alert, idempotent_replay: !emitted.created });
}

async function emitCriticalAlert(store, state, reasonCode, configuration, adapters) {
  const key = alertKey(state, reasonCode, configuration.secret);
  let entry = await getEntry(store, key);
  let created = false;
  if (!entry) {
    const candidate = signRecord({
      schema: RETENTION_GENERATION_FENCE_ALERT_SCHEMA,
      version: 1,
      severity: 'CRITICAL',
      status: 'OPEN',
      fence_status: state.status,
      generation: state.generation,
      operation_kind: state.operation_kind,
      operation_hmac_sha256: state.operation_hmac_sha256,
      intent_sha256: state.intent_sha256,
      reason_code: reasonCode,
      stale_at: state.stale_at,
      detected_at: state.stale_at,
      customer_data_stored: false,
    }, SIGNATURE_DOMAINS.alert, configuration.secret);
    created = await createOnly(store, key, candidate);
    entry = await getEntry(store, key);
  }
  if (!entry) throw new Error('ARC_FIRST_PARTY_RETENTION_FENCE_ALERT_UNAVAILABLE');
  const alert = validateAlertWithSecret(entry.value, configuration.secret);
  // Delivery is independently idempotent. Retry it for an existing immutable
  // alert too, so a transient queue failure cannot permanently orphan the
  // critical condition after the create-only evidence has succeeded.
  if (adapters.emitCriticalAlert) await adapters.emitCriticalAlert(alert);
  return { alert, created };
}

async function staleBlocked(store, state, reasonCode, configuration, adapters) {
  const emitted = await emitCriticalAlert(store, state, reasonCode, configuration, adapters);
  return Object.freeze({
    state: 'STALE_BLOCKED', retryable: false, critical_alert: true,
    alert_created: emitted.created, reason_code: reasonCode, alert: emitted.alert,
    generation: state.generation, operation_hmac_sha256: state.operation_hmac_sha256,
  });
}

export async function recoverStaleRetentionGenerationFence(store, env = process.env, adapters = {}) {
  const configuration = requireConfiguration(env);
  const now = clockDate(adapters);
  const entry = await readStateEntry(store, configuration.secret);
  if (!entry) return Object.freeze({ state: 'UNINITIALIZED', retryable: false, critical_alert: false });
  const state = entry.value;
  if (state.status === 'OPEN') {
    return Object.freeze({ state: 'OPEN', retryable: false, critical_alert: false,
      generation: state.generation });
  }
  if (now.getTime() < Date.parse(state.stale_at)) {
    return Object.freeze({ state: 'IN_PROGRESS', retryable: true, critical_alert: false,
      generation: state.generation, operation_hmac_sha256: state.operation_hmac_sha256 });
  }
  let intent;
  try {
    intent = state.operation_kind === 'producer'
      ? await readProducerIntent(store, state.operation_hmac_sha256, configuration)
      : await readFreezeIntent(store, state.operation_hmac_sha256, configuration);
  } catch {
    return staleBlocked(store, state, 'FENCE_INTENT_INVALID', configuration, adapters);
  }
  if (!intent || sha256Hex(canonicalJson(intent)) !== state.intent_sha256 ||
      state.operation_kind === 'retention' && intent.generation !== state.generation) {
    return staleBlocked(store, state, intent ? 'FENCE_INTENT_MISBOUND' : 'FENCE_INTENT_MISSING',
      configuration, adapters);
  }
  let receipt;
  try {
    receipt = state.operation_kind === 'producer'
      ? await readProducerCompletion(store, state.operation_hmac_sha256, intent, configuration)
      : await readFinalizeReceipt(store, state.operation_hmac_sha256, intent, configuration);
  } catch {
    return staleBlocked(store, state, 'FENCE_COMPLETION_RECEIPT_INVALID', configuration, adapters);
  }
  if (!receipt) {
    return staleBlocked(store, state, 'FENCE_COMPLETION_RECEIPT_MISSING', configuration, adapters);
  }
  if (receipt.generation !== state.generation) {
    return staleBlocked(store, state, 'FENCE_COMPLETION_RECEIPT_MISBOUND', configuration, adapters);
  }
  if (typeof adapters.validateCompletion === 'function' &&
      await adapters.validateCompletion(Object.freeze({ intent, receipt, state })) !== true) {
    return staleBlocked(store, state, 'FENCE_COMPLETION_READBACK_INVALID', configuration, adapters);
  }
  const expectedStatus = state.operation_kind === 'producer' ? 'WRITING' : 'FROZEN';
  const advanced = await advanceCompletedOperation(store, expectedStatus, state.operation_hmac_sha256,
    state.intent_sha256, state.generation, receipt, configuration);
  if (advanced.retryable) {
    return Object.freeze({
      state: 'RETRYABLE_CONTENTION', retryable: true, critical_alert: false,
      generation: state.generation, operation_hmac_sha256: state.operation_hmac_sha256,
    });
  }
  return Object.freeze({
    state: 'RECOVERED', retryable: false, critical_alert: false,
    generation: state.generation, observed_generation: advanced.state.generation,
    operation_hmac_sha256: state.operation_hmac_sha256, receipt,
  });
}

export const retentionGenerationFenceContract = Object.freeze({
  store: RETENTION_GENERATION_FENCE_STORE,
  state_key: RETENTION_GENERATION_FENCE_STATE_KEY,
  secret_env: RETENTION_GENERATION_FENCE_SECRET_ENV,
  states: FENCE_STATES,
  default_stale_after_ms: DEFAULT_STALE_AFTER_MS,
});
