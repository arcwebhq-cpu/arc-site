import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { TRANSACTIONAL_EMAIL_KINDS } from './transactional-email-template-core.mjs';

export const EMAIL_SEND_ATTEMPT_STORE = 'arc-transactional-email-attempts';
export const EMAIL_SEND_ATTEMPT_SCHEMA = 'arc-transactional-email-attempt-v1';
export const EMAIL_SEND_ATTEMPT_TOMBSTONE_SCHEMA = 'arc-transactional-email-retention-tombstone-v1';
export const EMAIL_SEND_ATTEMPT_ENABLED_ENV = 'ARC_TRANSACTIONAL_EMAIL_ENABLED';
export const EMAIL_SEND_ATTEMPT_HMAC_SECRET_ENV = 'ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET';
export const EMAIL_SEND_RETRY_WINDOW_MS = 23 * 60 * 60_000;
export const EMAIL_SEND_ATTEMPT_RETENTION_ENABLED_ENV = 'ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED';
export const EMAIL_SEND_ATTEMPT_RETENTION_DAYS_ENV = 'ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS';

const HEX_64 = /^[a-f0-9]{64}$/;
const PROVIDER_MESSAGE_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const CONTROL = /[\u0000-\u001f\u007f]/;
const PRUNE_CURSOR_SCHEMA = 'arc-transactional-email-attempt-prune-cursor-v1';
const PRUNE_CURSOR_SIGNATURE_PREFIX = 'arc-transactional-email-attempt-prune-cursor-signature-v1\n';
const PRUNE_SHARDS = '0123456789abcdef';
const QUARANTINE_SCHEMA = 'arc-transactional-email-attempt-quarantine-v1';
const STATES = Object.freeze([
  'INTENT', 'PROVIDER_ACCEPTED', 'DELIVERED', 'BOUNCED', 'COMPLAINED', 'FAILED', 'SUPPRESSED',
]);
const EVENT_TO_STATE = Object.freeze({
  'email.delivered': 'DELIVERED',
  'email.bounced': 'BOUNCED',
  'email.complained': 'COMPLAINED',
  'email.failed': 'FAILED',
  'email.suppressed': 'SUPPRESSED',
});
const STATE_PRIORITY = Object.freeze({
  INTENT: 0,
  PROVIDER_ACCEPTED: 10,
  DELIVERED: 20,
  FAILED: 30,
  BOUNCED: 40,
  SUPPRESSED: 40,
  COMPLAINED: 50,
});
const ATTEMPT_FIELDS = Object.freeze([
  'accepted_at', 'attempt_hmac_sha256', 'created_at', 'job_key_sha256', 'job_kind', 'last_event_at',
  'last_event_id_hmac_sha256', 'last_event_type', 'message_sha256', 'provider',
  'provider_idempotency_key_sha256', 'provider_message_id_hmac_sha256', 'recipient_email_sha256',
  'record_hmac_sha256', 'record_revision', 'schema', 'sender_sha256', 'state', 'updated_at', 'version',
]);
const REVERSE_FIELDS = Object.freeze([
  'attempt_hmac_sha256', 'created_at', 'provider', 'provider_message_id_hmac_sha256',
  'record_hmac_sha256', 'schema', 'version',
]);
const EVENT_FIELDS = Object.freeze([
  'attempt_hmac_sha256', 'event_type', 'occurred_at', 'payload_sha256', 'provider',
  'provider_event_id_hmac_sha256', 'record_hmac_sha256', 'schema', 'version',
]);
const QUARANTINE_FIELDS = Object.freeze([
  'attempt_hmac_sha256', 'prior_state', 'quarantined_at', 'reason', 'record_hmac_sha256',
  'source_record_sha256', 'stale_since', 'schema', 'version',
]);
const TOMBSTONE_FIELDS = Object.freeze([
  'attempt_hmac_sha256', 'customer_data_stored', 'record_hmac_sha256', 'record_kind', 'schema',
  'source_key_hmac_sha256', 'source_record_sha256', 'tombstoned_at', 'version',
]);
const TOMBSTONE_KINDS = Object.freeze(['attempt', 'provider-event-index', 'provider-message-index']);
const TOMBSTONE_SIGNATURE_DOMAIN = 'arc-transactional-email-retention-tombstone-record-v1';
const TOMBSTONE_SOURCE_KEY_PREFIX = 'arc-transactional-email-retention-tombstone-source-key-v1\n';

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError('Email attempt value is invalid.');
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const result = JSON.stringify(value);
  if (result === undefined) throw new TypeError('Email attempt value is invalid.');
  return result;
}

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const safeEqual = (left, right) => {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
};
const exactKeys = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());

function iso(value, label) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return parsed;
}

function nullableIso(value, label) {
  return value === null ? null : iso(value, label);
}

function secret(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 32 ||
      Buffer.byteLength(value, 'utf8') > 256 || CONTROL.test(value)) {
    throw new TypeError(`${EMAIL_SEND_ATTEMPT_HMAC_SECRET_ENV} is invalid.`);
  }
  return value;
}

function job(kind, key) {
  if (!TRANSACTIONAL_EMAIL_KINDS.includes(kind) || typeof key !== 'string' || key.length < 8 ||
      Buffer.byteLength(key, 'utf8') > 256 || CONTROL.test(key)) throw new TypeError('Email attempt job binding is invalid.');
  return { kind, key };
}

function idempotencyKey(value) {
  if (typeof value !== 'string' || value.length < 1 || Buffer.byteLength(value, 'utf8') > 256 || CONTROL.test(value)) {
    throw new TypeError('Email provider idempotency key is invalid.');
  }
  return value;
}

function providerMessageId(value) {
  if (typeof value !== 'string' || !PROVIDER_MESSAGE_ID.test(value)) {
    throw new TypeError('Email provider message identity is invalid.');
  }
  return value.toLowerCase();
}

function attemptId(kind, key, resolved) {
  return hmac(resolved.hmacSecret, `arc-transactional-email-attempt-id-v1\n${kind}\n${key}`);
}

const attemptKey = (id) => `attempts/${id}`;
const reverseId = (providerId, resolved) => hmac(resolved.hmacSecret,
  `arc-transactional-email-provider-message-id-v1\nresend\n${providerId}`);
const reverseKey = (id) => `provider-messages/resend/${id}`;
const eventId = (providerEventId, resolved) => hmac(resolved.hmacSecret,
  `arc-transactional-email-provider-event-id-v1\nresend\n${providerEventId}`);
const eventKey = (id) => `provider-events/resend/${id}`;
const quarantineKey = (id) => `quarantine/${id}`;

function encodePruneCursor(cursor, resolved) {
  const raw = Buffer.from(canonicalJson({
    schema: PRUNE_CURSOR_SCHEMA,
    shard: cursor.shard,
    after_key: cursor.afterKey,
  })).toString('base64url');
  return `${raw}.${hmac(resolved.hmacSecret, `${PRUNE_CURSOR_SIGNATURE_PREFIX}${raw}`)}`;
}

function decodePruneCursor(value, resolved) {
  if (value === null || value === undefined) return { shard: 0, afterKey: null };
  if (typeof value !== 'string' || value.length > 1_024) {
    throw new TypeError('Email attempt prune cursor is invalid.');
  }
  const match = /^([A-Za-z0-9_-]+)\.([a-f0-9]{64})$/.exec(value);
  if (!match || !safeEqual(match[2], hmac(resolved.hmacSecret,
    `${PRUNE_CURSOR_SIGNATURE_PREFIX}${match[1]}`))) {
    throw new TypeError('Email attempt prune cursor signature is invalid.');
  }
  let cursor;
  try { cursor = JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8')); } catch {
    throw new TypeError('Email attempt prune cursor is invalid.');
  }
  if (!exactKeys(cursor, ['after_key', 'schema', 'shard']) || cursor.schema !== PRUNE_CURSOR_SCHEMA ||
      !Number.isSafeInteger(cursor.shard) || cursor.shard < 0 || cursor.shard >= PRUNE_SHARDS.length ||
      !(cursor.after_key === null || new RegExp(
        `^attempts/${PRUNE_SHARDS[cursor.shard]}[a-f0-9]{63}$`,
      ).test(cursor.after_key))) {
    throw new TypeError('Email attempt prune cursor is invalid.');
  }
  return { shard: cursor.shard, afterKey: cursor.after_key };
}

async function *listPages(store, prefix) {
  const listing = store.list({ prefix, paginate: true });
  if (listing && typeof listing[Symbol.asyncIterator] === 'function') {
    for await (const page of listing) yield page;
    return;
  }
  yield await listing;
}

function unsigned(value) {
  const { record_hmac_sha256: ignored, ...record } = value;
  return record;
}

function sign(value, domain, resolved) {
  const record = unsigned(value);
  return { ...record, record_hmac_sha256: hmac(resolved.hmacSecret, `${domain}\n${canonicalJson(record)}`) };
}

function verifySignature(value, domain, resolved) {
  const expected = hmac(resolved.hmacSecret, `${domain}\n${canonicalJson(unsigned(value))}`);
  if (!HEX_64.test(value.record_hmac_sha256) || !safeEqual(value.record_hmac_sha256, expected)) {
    throw new Error('ARC_EMAIL_ATTEMPT_SIGNATURE_INVALID');
  }
}

function validateAttempt(record, resolved) {
  if (!exactKeys(record, ATTEMPT_FIELDS) || record.schema !== EMAIL_SEND_ATTEMPT_SCHEMA || record.version !== 1 ||
      !Number.isSafeInteger(record.record_revision) || record.record_revision < 1 ||
      !TRANSACTIONAL_EMAIL_KINDS.includes(record.job_kind) || record.provider !== 'resend' ||
      !STATES.includes(record.state) || ![record.attempt_hmac_sha256, record.job_key_sha256,
        record.provider_idempotency_key_sha256, record.recipient_email_sha256, record.sender_sha256,
        record.message_sha256].every((value) => HEX_64.test(value))) {
    throw new TypeError('Email attempt record is invalid.');
  }
  iso(record.created_at, 'Email attempt created_at');
  iso(record.updated_at, 'Email attempt updated_at');
  nullableIso(record.accepted_at, 'Email attempt accepted_at');
  nullableIso(record.last_event_at, 'Email attempt last_event_at');
  for (const field of ['provider_message_id_hmac_sha256', 'last_event_id_hmac_sha256']) {
    if (record[field] !== null && !HEX_64.test(record[field])) throw new TypeError('Email attempt digest is invalid.');
  }
  if (record.last_event_type !== null && !Object.hasOwn(EVENT_TO_STATE, record.last_event_type)) {
    throw new TypeError('Email attempt event type is invalid.');
  }
  const untouched = record.provider_message_id_hmac_sha256 === null && record.accepted_at === null &&
    record.last_event_id_hmac_sha256 === null && record.last_event_type === null && record.last_event_at === null;
  const accepted = record.provider_message_id_hmac_sha256 !== null && record.accepted_at !== null;
  const noEvent = record.last_event_id_hmac_sha256 === null && record.last_event_type === null && record.last_event_at === null;
  const withEvent = record.last_event_id_hmac_sha256 !== null && record.last_event_type !== null && record.last_event_at !== null;
  if (record.state === 'INTENT' && !untouched) throw new TypeError('Email attempt intent is inconsistent.');
  if (record.state === 'PROVIDER_ACCEPTED' && (!accepted || !noEvent)) throw new TypeError('Email acceptance is inconsistent.');
  if (!['INTENT', 'PROVIDER_ACCEPTED'].includes(record.state) && (!accepted || !withEvent ||
      EVENT_TO_STATE[record.last_event_type] !== record.state)) {
    throw new TypeError('Email terminal event is inconsistent.');
  }
  verifySignature(record, 'arc-transactional-email-attempt-record-v1', resolved);
  return record;
}

function validateReverse(record, resolved) {
  if (!exactKeys(record, REVERSE_FIELDS) || record.schema !== 'arc-transactional-email-provider-message-index-v1' ||
      record.version !== 1 || record.provider !== 'resend' ||
      !HEX_64.test(record.attempt_hmac_sha256) || !HEX_64.test(record.provider_message_id_hmac_sha256)) {
    throw new TypeError('Email provider message index is invalid.');
  }
  iso(record.created_at, 'Email provider message index created_at');
  verifySignature(record, 'arc-transactional-email-provider-message-index-record-v1', resolved);
  return record;
}

function validateEventRecord(record, resolved) {
  if (!exactKeys(record, EVENT_FIELDS) || record.schema !== 'arc-transactional-email-provider-event-v1' ||
      record.version !== 1 || record.provider !== 'resend' ||
      !HEX_64.test(record.attempt_hmac_sha256) || !HEX_64.test(record.provider_event_id_hmac_sha256) ||
      !HEX_64.test(record.payload_sha256) ||
      !['email.sent', 'email.delivery_delayed', ...Object.keys(EVENT_TO_STATE)].includes(record.event_type)) {
    throw new TypeError('Email provider event record is invalid.');
  }
  iso(record.occurred_at, 'Email provider event occurred_at');
  verifySignature(record, 'arc-transactional-email-provider-event-record-v1', resolved);
  return record;
}

function validateQuarantine(record, resolved) {
  if (!exactKeys(record, QUARANTINE_FIELDS) || record.schema !== QUARANTINE_SCHEMA || record.version !== 1 ||
      !HEX_64.test(record.attempt_hmac_sha256) || !HEX_64.test(record.source_record_sha256) ||
      !['INTENT', 'PROVIDER_ACCEPTED'].includes(record.prior_state) ||
      record.reason !== `STALE_${record.prior_state}`) {
    throw new TypeError('Email attempt quarantine record is invalid.');
  }
  const staleSince = iso(record.stale_since, 'Email attempt quarantine stale_since');
  const quarantinedAt = iso(record.quarantined_at, 'Email attempt quarantine quarantined_at');
  if (quarantinedAt < staleSince) throw new TypeError('Email attempt quarantine ordering is invalid.');
  verifySignature(record, 'arc-transactional-email-attempt-quarantine-record-v1', resolved);
  return record;
}

function isAttemptRetentionTombstone(value) {
  return value?.schema === EMAIL_SEND_ATTEMPT_TOMBSTONE_SCHEMA;
}

function tombstoneKeyMatches(record, key) {
  if (record.record_kind === 'attempt') return key === attemptKey(record.attempt_hmac_sha256);
  if (record.record_kind === 'provider-message-index') {
    return /^provider-messages\/resend\/[a-f0-9]{64}$/.test(key);
  }
  return record.record_kind === 'provider-event-index' &&
    /^provider-events\/resend\/[a-f0-9]{64}$/.test(key);
}

function validateRetentionTombstone(record, key, resolved, expected = {}) {
  if (!exactKeys(record, TOMBSTONE_FIELDS) ||
      record.schema !== EMAIL_SEND_ATTEMPT_TOMBSTONE_SCHEMA || record.version !== 1 ||
      !TOMBSTONE_KINDS.includes(record.record_kind) || record.customer_data_stored !== false ||
      ![record.attempt_hmac_sha256, record.source_key_hmac_sha256,
        record.source_record_sha256, record.record_hmac_sha256].every((value) => HEX_64.test(value)) ||
      !tombstoneKeyMatches(record, key) ||
      record.source_key_hmac_sha256 !== hmac(resolved.hmacSecret, `${TOMBSTONE_SOURCE_KEY_PREFIX}${key}`) ||
      expected.recordKind !== undefined && record.record_kind !== expected.recordKind ||
      expected.attemptHmac !== undefined && record.attempt_hmac_sha256 !== expected.attemptHmac ||
      expected.sourceRecordSha256 !== undefined &&
        record.source_record_sha256 !== expected.sourceRecordSha256) {
    throw new TypeError('Email retention tombstone is invalid.');
  }
  iso(record.tombstoned_at, 'Email retention tombstone tombstoned_at');
  verifySignature(record, TOMBSTONE_SIGNATURE_DOMAIN, resolved);
  return record;
}

export function validateEmailSendAttemptRetentionTombstone(record, key, env = process.env, expected = {}) {
  return validateRetentionTombstone(record, key, requireConfiguration(env), expected);
}

// Read-only proof used by the globally-frozen retention coordinator when an
// encrypted acceptance capsule is addressed by attempt identity rather than
// by the original review/handoff job key.
export function validateEmailSendAttemptRetentionSource(record, key, env = process.env) {
  const validated = validateAttempt(record, requireConfiguration(env));
  if (key !== attemptKey(validated.attempt_hmac_sha256)) {
    throw new Error('ARC_EMAIL_ATTEMPT_BINDING_INVALID');
  }
  return validated;
}

function buildRetentionTombstone(key, source, recordKind, attemptHmac, resolved, now) {
  return sign({
    schema: EMAIL_SEND_ATTEMPT_TOMBSTONE_SCHEMA,
    version: 1,
    record_kind: recordKind,
    attempt_hmac_sha256: attemptHmac,
    source_key_hmac_sha256: hmac(resolved.hmacSecret, `${TOMBSTONE_SOURCE_KEY_PREFIX}${key}`),
    source_record_sha256: sha256(canonicalJson(source)),
    tombstoned_at: now.toISOString(),
    customer_data_stored: false,
  }, TOMBSTONE_SIGNATURE_DOMAIN, resolved);
}

export function emailSendAttemptConfiguration(env = process.env) {
  if (env[EMAIL_SEND_ATTEMPT_ENABLED_ENV] !== 'true') return Object.freeze({ enabled: false });
  try { return Object.freeze({ enabled: true, hmacSecret: secret(env[EMAIL_SEND_ATTEMPT_HMAC_SECRET_ENV]) }); }
  catch { return Object.freeze({ enabled: false }); }
}

function requireConfiguration(env) {
  const resolved = emailSendAttemptConfiguration(env);
  if (!resolved.enabled) throw new Error('ARC_TRANSACTIONAL_EMAIL_DISABLED');
  return resolved;
}

async function readAttemptById(store, id, resolved) {
  const key = attemptKey(id);
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (entry && isAttemptRetentionTombstone(entry.data)) {
    validateRetentionTombstone(entry.data, key, resolved, { recordKind: 'attempt', attemptHmac: id });
    return null;
  }
  return entry ? { record: validateAttempt(entry.data, resolved), etag: entry.etag } : null;
}

async function readQuarantineById(store, id, resolved) {
  const entry = await store.getWithMetadata(quarantineKey(id), { type: 'json', consistency: 'strong' });
  return entry ? validateQuarantine(entry.data, resolved) : null;
}

async function ensureQuarantine(store, attempt, resolved, now) {
  const expected = sign({
    schema: QUARANTINE_SCHEMA,
    version: 1,
    attempt_hmac_sha256: attempt.attempt_hmac_sha256,
    prior_state: attempt.state,
    reason: `STALE_${attempt.state}`,
    stale_since: attempt.updated_at,
    quarantined_at: now.toISOString(),
    source_record_sha256: sha256(canonicalJson(attempt)),
  }, 'arc-transactional-email-attempt-quarantine-record-v1', resolved);
  const key = quarantineKey(attempt.attempt_hmac_sha256);
  let entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  let created = false;
  if (!entry) {
    try {
      const result = await store.setJSON(key, expected, { onlyIfNew: true });
      created = result?.modified === true;
    } catch {}
    entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  }
  if (!entry) throw new Error('ARC_EMAIL_ATTEMPT_QUARANTINE_UNAVAILABLE');
  const record = validateQuarantine(entry.data, resolved);
  if (record.attempt_hmac_sha256 !== attempt.attempt_hmac_sha256 ||
      record.prior_state !== attempt.state ||
      record.source_record_sha256 !== expected.source_record_sha256) {
    throw new Error('ARC_EMAIL_ATTEMPT_QUARANTINE_CONFLICT');
  }
  return { record, created };
}

async function replaceAttempt(store, entry, value, resolved) {
  const signed = sign({ ...value, record_revision: entry.record.record_revision + 1 },
    'arc-transactional-email-attempt-record-v1', resolved);
  validateAttempt(signed, resolved);
  const result = await store.setJSON(attemptKey(signed.attempt_hmac_sha256), signed, { onlyIfMatch: entry.etag });
  if (!result?.modified || typeof result.etag !== 'string') throw new Error('ARC_EMAIL_ATTEMPT_STATE_CONTENTION');
  return { record: signed, etag: result.etag };
}

function normalizedIntent(input, resolved, now) {
  if (!exactKeys(input, ['job_key', 'job_kind', 'message_sha256', 'provider_idempotency_key',
    'recipient_email_sha256', 'sender_sha256'])) throw new TypeError('Email attempt input is invalid.');
  const binding = job(input.job_kind, input.job_key);
  const digests = [input.message_sha256, input.recipient_email_sha256, input.sender_sha256];
  if (!digests.every((value) => HEX_64.test(value))) throw new TypeError('Email attempt binding digest is invalid.');
  const idempotency = idempotencyKey(input.provider_idempotency_key);
  const stamp = now.toISOString();
  return sign({
    schema: EMAIL_SEND_ATTEMPT_SCHEMA,
    version: 1,
    record_revision: 1,
    attempt_hmac_sha256: attemptId(binding.kind, binding.key, resolved),
    job_kind: binding.kind,
    job_key_sha256: sha256(binding.key),
    provider: 'resend',
    provider_idempotency_key_sha256: sha256(idempotency),
    recipient_email_sha256: input.recipient_email_sha256,
    sender_sha256: input.sender_sha256,
    message_sha256: input.message_sha256,
    state: 'INTENT',
    provider_message_id_hmac_sha256: null,
    accepted_at: null,
    last_event_id_hmac_sha256: null,
    last_event_type: null,
    last_event_at: null,
    created_at: stamp,
    updated_at: stamp,
  }, 'arc-transactional-email-attempt-record-v1', resolved);
}

function sameIntent(record, expected) {
  return ['job_kind', 'job_key_sha256', 'provider', 'provider_idempotency_key_sha256',
    'recipient_email_sha256', 'sender_sha256', 'message_sha256'].every((field) => record[field] === expected[field]);
}

export async function reserveEmailSendAttempt(store, input, env = process.env, adapters = {}) {
  const resolved = requireConfiguration(env);
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Email attempt clock is invalid.');
  const expected = normalizedIntent(input, resolved, now);
  let entry = await readAttemptById(store, expected.attempt_hmac_sha256, resolved);
  let created = false;
  if (!entry) {
    try {
      const result = await store.setJSON(attemptKey(expected.attempt_hmac_sha256), expected, { onlyIfNew: true });
      created = result?.modified === true;
    } catch {}
    entry = await readAttemptById(store, expected.attempt_hmac_sha256, resolved);
  }
  if (!entry || !sameIntent(entry.record, expected)) throw new Error('ARC_EMAIL_ATTEMPT_CONFLICT');
  const quarantine = await readQuarantineById(store, entry.record.attempt_hmac_sha256, resolved);
  if (quarantine) {
    return Object.freeze({
      attempt_hmac_sha256: entry.record.attempt_hmac_sha256,
      state: 'QUARANTINED',
      created: false,
      idempotent_replay: true,
      decision: 'REVIEW_REQUIRED',
    });
  }
  return Object.freeze({
    attempt_hmac_sha256: entry.record.attempt_hmac_sha256,
    state: entry.record.state,
    created,
    idempotent_replay: !created,
    decision: emailSendAttemptDecision(entry.record, now),
  });
}

export function emailSendAttemptDecision(record, nowValue = new Date()) {
  const now = nowValue instanceof Date ? new Date(nowValue.getTime()) : new Date(nowValue);
  if (!Number.isFinite(now.getTime())) throw new TypeError('Email attempt clock is invalid.');
  if (record.state !== 'INTENT') return 'DO_NOT_SEND';
  return now.getTime() - Date.parse(record.created_at) <= EMAIL_SEND_RETRY_WINDOW_MS
    ? 'SEND_EXACT_IDEMPOTENT_REQUEST' : 'REVIEW_REQUIRED';
}

export async function readEmailSendAttempt(store, input, env = process.env) {
  const resolved = requireConfiguration(env);
  if (!exactKeys(input, ['job_key', 'job_kind'])) throw new TypeError('Email attempt lookup is invalid.');
  const binding = job(input.job_kind, input.job_key);
  const entry = await readAttemptById(store, attemptId(binding.kind, binding.key, resolved), resolved);
  if (!entry) return null;
  if (entry.record.job_kind !== binding.kind || entry.record.job_key_sha256 !== sha256(binding.key)) {
    throw new Error('ARC_EMAIL_ATTEMPT_BINDING_INVALID');
  }
  return structuredClone(entry.record);
}

export async function readEmailSendAttemptQuarantine(store, input, env = process.env) {
  const resolved = requireConfiguration(env);
  if (!exactKeys(input, ['attempt_hmac_sha256']) || !HEX_64.test(input.attempt_hmac_sha256)) {
    throw new TypeError('Email attempt quarantine lookup is invalid.');
  }
  const record = await readQuarantineById(store, input.attempt_hmac_sha256, resolved);
  return record ? structuredClone(record) : null;
}

async function ensureReverseIndex(store, attempt, rawProviderMessageId, resolved, now) {
  const providerIdHmac = reverseId(rawProviderMessageId, resolved);
  const key = reverseKey(providerIdHmac);
  const expected = sign({
    schema: 'arc-transactional-email-provider-message-index-v1',
    version: 1,
    provider: 'resend',
    provider_message_id_hmac_sha256: providerIdHmac,
    attempt_hmac_sha256: attempt.attempt_hmac_sha256,
    created_at: now.toISOString(),
  }, 'arc-transactional-email-provider-message-index-record-v1', resolved);
  let entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (entry && isAttemptRetentionTombstone(entry.data)) {
    validateRetentionTombstone(entry.data, key, resolved, {
      recordKind: 'provider-message-index', attemptHmac: attempt.attempt_hmac_sha256,
    });
    throw new Error('ARC_EMAIL_PROVIDER_MESSAGE_INDEX_TOMBSTONED');
  }
  if (!entry) {
    try { await store.setJSON(key, expected, { onlyIfNew: true }); } catch {}
    entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  }
  if (!entry) throw new Error('ARC_EMAIL_PROVIDER_MESSAGE_INDEX_UNAVAILABLE');
  if (isAttemptRetentionTombstone(entry.data)) {
    validateRetentionTombstone(entry.data, key, resolved, {
      recordKind: 'provider-message-index', attemptHmac: attempt.attempt_hmac_sha256,
    });
    throw new Error('ARC_EMAIL_PROVIDER_MESSAGE_INDEX_TOMBSTONED');
  }
  const record = validateReverse(entry.data, resolved);
  if (record.provider_message_id_hmac_sha256 !== providerIdHmac ||
      record.attempt_hmac_sha256 !== attempt.attempt_hmac_sha256) {
    throw new Error('ARC_EMAIL_PROVIDER_MESSAGE_INDEX_CONFLICT');
  }
  return providerIdHmac;
}

export async function markEmailProviderAccepted(store, input, env = process.env, adapters = {}) {
  const resolved = requireConfiguration(env);
  if (!exactKeys(input, ['attempt_hmac_sha256', 'provider_message_id'])) {
    throw new TypeError('Email provider acceptance input is invalid.');
  }
  if (!HEX_64.test(input.attempt_hmac_sha256)) throw new TypeError('Email attempt identity is invalid.');
  const rawProviderId = providerMessageId(input.provider_message_id);
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Email attempt clock is invalid.');
  let entry = await readAttemptById(store, input.attempt_hmac_sha256, resolved);
  if (!entry) throw new Error('ARC_EMAIL_ATTEMPT_NOT_FOUND');
  if (await readQuarantineById(store, input.attempt_hmac_sha256, resolved)) {
    throw new Error('ARC_EMAIL_ATTEMPT_QUARANTINED');
  }
  const providerIdHmac = await ensureReverseIndex(store, entry.record, rawProviderId, resolved, now);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    if (!entry) throw new Error('ARC_EMAIL_ATTEMPT_NOT_FOUND');
    if (entry.record.state !== 'INTENT') {
      if (!safeEqual(entry.record.provider_message_id_hmac_sha256, providerIdHmac)) {
        throw new Error('ARC_EMAIL_PROVIDER_ACCEPTANCE_CONFLICT');
      }
      return Object.freeze({ state: entry.record.state, idempotent_replay: true, unlock_delivery: false });
    }
    const value = {
      ...entry.record,
      state: 'PROVIDER_ACCEPTED',
      provider_message_id_hmac_sha256: providerIdHmac,
      accepted_at: now.toISOString(),
      updated_at: now.toISOString(),
    };
    try {
      entry = await replaceAttempt(store, entry, value, resolved);
      return Object.freeze({ state: entry.record.state, idempotent_replay: false, unlock_delivery: false });
    } catch (error) {
      if (error?.message !== 'ARC_EMAIL_ATTEMPT_STATE_CONTENTION' || attempt === 3) throw error;
      entry = await readAttemptById(store, input.attempt_hmac_sha256, resolved);
    }
  }
  throw new Error('ARC_EMAIL_ATTEMPT_STATE_CONTENTION');
}

async function readReverseByProviderId(store, rawProviderId, resolved) {
  const id = reverseId(rawProviderId, resolved);
  const key = reverseKey(id);
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!entry) return null;
  if (isAttemptRetentionTombstone(entry.data)) {
    validateRetentionTombstone(entry.data, key, resolved, { recordKind: 'provider-message-index' });
    return null;
  }
  const record = validateReverse(entry.data, resolved);
  if (record.provider_message_id_hmac_sha256 !== id) throw new Error('ARC_EMAIL_PROVIDER_MESSAGE_INDEX_CONFLICT');
  return record;
}

async function ensureEventIndex(store, normalized, attemptHmac, resolved) {
  const id = eventId(normalized.provider_event_id, resolved);
  const key = eventKey(id);
  const expected = sign({
    schema: 'arc-transactional-email-provider-event-v1',
    version: 1,
    provider: 'resend',
    provider_event_id_hmac_sha256: id,
    attempt_hmac_sha256: attemptHmac,
    event_type: normalized.event_type,
    occurred_at: normalized.occurred_at,
    payload_sha256: normalized.payload_sha256,
  }, 'arc-transactional-email-provider-event-record-v1', resolved);
  let entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  let created = false;
  if (entry && isAttemptRetentionTombstone(entry.data)) {
    validateRetentionTombstone(entry.data, key, resolved, {
      recordKind: 'provider-event-index', attemptHmac,
    });
    throw new Error('ARC_EMAIL_PROVIDER_EVENT_INDEX_TOMBSTONED');
  }
  if (!entry) {
    try {
      const result = await store.setJSON(key, expected, { onlyIfNew: true });
      created = result?.modified === true;
    } catch {}
    entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  }
  if (!entry) throw new Error('ARC_EMAIL_PROVIDER_EVENT_INDEX_UNAVAILABLE');
  if (isAttemptRetentionTombstone(entry.data)) {
    validateRetentionTombstone(entry.data, key, resolved, {
      recordKind: 'provider-event-index', attemptHmac,
    });
    throw new Error('ARC_EMAIL_PROVIDER_EVENT_INDEX_TOMBSTONED');
  }
  const record = validateEventRecord(entry.data, resolved);
  if (canonicalJson(unsigned(record)) !== canonicalJson(unsigned(expected))) {
    throw new Error('ARC_EMAIL_PROVIDER_EVENT_CONFLICT');
  }
  return { eventIdHmac: id, idempotentReplay: !created };
}

export async function reconcileEmailProviderEvent(store, normalized, env = process.env) {
  const resolved = requireConfiguration(env);
  if (!exactKeys(normalized, ['event_type', 'occurred_at', 'payload_sha256', 'provider',
    'provider_event_id', 'provider_message_id']) || normalized.provider !== 'resend' ||
      typeof normalized.provider_event_id !== 'string' || normalized.provider_event_id.length < 1 ||
      normalized.provider_event_id.length > 256 || CONTROL.test(normalized.provider_event_id) ||
      !['email.sent', 'email.delivery_delayed', ...Object.keys(EVENT_TO_STATE)].includes(normalized.event_type) ||
      !HEX_64.test(normalized.payload_sha256)) {
    throw new TypeError('Email provider event is invalid.');
  }
  iso(normalized.occurred_at, 'Email provider event occurred_at');
  const rawProviderId = providerMessageId(normalized.provider_message_id);
  const reverse = await readReverseByProviderId(store, rawProviderId, resolved);
  if (!reverse) return Object.freeze({ state: 'UNMAPPED', attempt_hmac_sha256: null, job_kind: null,
    idempotent_replay: false, unlock_delivery: false });
  const indexed = await ensureEventIndex(store, normalized, reverse.attempt_hmac_sha256, resolved);
  const quarantined = await readQuarantineById(store, reverse.attempt_hmac_sha256, resolved);
  if (quarantined) {
    const quarantinedAttempt = await readAttemptById(store, reverse.attempt_hmac_sha256, resolved);
    if (!quarantinedAttempt) throw new Error('ARC_EMAIL_PROVIDER_EVENT_BINDING_INVALID');
    return Object.freeze({ state: 'QUARANTINED', attempt_hmac_sha256: reverse.attempt_hmac_sha256,
      job_kind: quarantinedAttempt.record.job_kind, idempotent_replay: indexed.idempotentReplay,
      unlock_delivery: false });
  }
  if (!Object.hasOwn(EVENT_TO_STATE, normalized.event_type)) {
    const ignoredAttempt = await readAttemptById(store, reverse.attempt_hmac_sha256, resolved);
    if (!ignoredAttempt) throw new Error('ARC_EMAIL_PROVIDER_EVENT_BINDING_INVALID');
    return Object.freeze({ state: 'IGNORED', attempt_hmac_sha256: reverse.attempt_hmac_sha256,
      job_kind: ignoredAttempt.record.job_kind, idempotent_replay: indexed.idempotentReplay, unlock_delivery: false });
  }
  const target = EVENT_TO_STATE[normalized.event_type];
  let entry = await readAttemptById(store, reverse.attempt_hmac_sha256, resolved);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    if (!entry || entry.record.provider_message_id_hmac_sha256 !== reverse.provider_message_id_hmac_sha256) {
      throw new Error('ARC_EMAIL_PROVIDER_EVENT_BINDING_INVALID');
    }
    if (entry.record.state === target && entry.record.last_event_id_hmac_sha256 === indexed.eventIdHmac) {
      return Object.freeze({ state: target, attempt_hmac_sha256: reverse.attempt_hmac_sha256,
        job_kind: entry.record.job_kind, idempotent_replay: true,
        unlock_delivery: target === 'DELIVERED' });
    }
    if (STATE_PRIORITY[target] <= STATE_PRIORITY[entry.record.state]) {
      return Object.freeze({ state: entry.record.state, attempt_hmac_sha256: reverse.attempt_hmac_sha256,
        job_kind: entry.record.job_kind, idempotent_replay: indexed.idempotentReplay,
        unlock_delivery: false });
    }
    const value = {
      ...entry.record,
      state: target,
      last_event_id_hmac_sha256: indexed.eventIdHmac,
      last_event_type: normalized.event_type,
      last_event_at: normalized.occurred_at,
      updated_at: new Date().toISOString(),
    };
    try {
      entry = await replaceAttempt(store, entry, value, resolved);
      return Object.freeze({ state: target, attempt_hmac_sha256: reverse.attempt_hmac_sha256,
        job_kind: entry.record.job_kind, idempotent_replay: indexed.idempotentReplay,
        unlock_delivery: target === 'DELIVERED' });
    } catch (error) {
      if (error?.message !== 'ARC_EMAIL_ATTEMPT_STATE_CONTENTION' || attempt === 3) throw error;
      entry = await readAttemptById(store, reverse.attempt_hmac_sha256, resolved);
    }
  }
  throw new Error('ARC_EMAIL_ATTEMPT_STATE_CONTENTION');
}

export function emailSendAttemptRetentionConfiguration(env = process.env) {
  if (env[EMAIL_SEND_ATTEMPT_RETENTION_ENABLED_ENV] !== 'true') {
    return Object.freeze({ enabled: false, retention_days: null });
  }
  const raw = env[EMAIL_SEND_ATTEMPT_RETENTION_DAYS_ENV];
  if (typeof raw !== 'string' || !/^\d{1,3}$/.test(raw)) {
    return Object.freeze({ enabled: false, retention_days: null });
  }
  const days = Number(raw);
  return Object.freeze({
    enabled: Number.isSafeInteger(days) && days >= 7 && days <= 365,
    retention_days: days,
  });
}

async function reportMissingRetentionSource(adapters, input) {
  if (typeof adapters.onMissingSource !== 'function') {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_ANOMALY_UNAVAILABLE');
  }
  await adapters.onMissingSource(Object.freeze(input));
  throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_BLOCKED');
}

export async function pruneTerminalEmailSendAttempts() {
  throw new Error('ARC_EMAIL_ATTEMPT_RETENTION_PRUNE_RETIRED_USE_FROZEN_SWEEP');
}

// Builds, but never applies, one exact retention subject. The caller can sign
// and freeze this PII-free plan before performing any of its conditional
// writes. All provider-event pages are consumed before the plan is returned.
export async function planTerminalEmailSendAttemptRetention(store, env = process.env, adapters = {}) {
  const resolved = requireConfiguration(env);
  const retention = emailSendAttemptRetentionConfiguration(env);
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Email attempt retention clock is invalid.');
  const limit = adapters.limit === undefined ? 100 : adapters.limit;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
    throw new TypeError('Email attempt retention limit is invalid.');
  }
  const cutoff = retention.enabled
    ? now.getTime() - retention.retention_days * 24 * 60 * 60_000
    : Number.NEGATIVE_INFINITY;
  let cursor = decodePruneCursor(adapters.cursor, resolved);
  let inspected = 0;
  while (cursor.shard < PRUNE_SHARDS.length) {
    const prefix = `attempts/${PRUNE_SHARDS[cursor.shard]}`;
    let priorKey = null;
    for await (const page of listPages(store, prefix)) {
      if (!page || !Array.isArray(page.blobs)) throw new Error('ARC_EMAIL_ATTEMPT_LIST_UNAVAILABLE');
      for (const blob of page.blobs) {
        if (!blob || typeof blob.key !== 'string' ||
            !new RegExp(`^${prefix}[a-f0-9]{63}$`).test(blob.key) ||
            priorKey !== null && blob.key <= priorKey) {
          throw new Error('ARC_EMAIL_ATTEMPT_LIST_INVALID');
        }
        priorKey = blob.key;
        if (cursor.afterKey !== null && blob.key <= cursor.afterKey) continue;
        if (inspected >= limit) {
          return Object.freeze({ inspected, complete: false,
            next_cursor: encodePruneCursor(cursor, resolved), mutation: null });
        }
        inspected += 1;
        const entry = await store.getWithMetadata(blob.key, { type: 'json', consistency: 'strong' });
        cursor = { ...cursor, afterKey: blob.key };
        if (!entry) {
          await reportMissingRetentionSource(adapters, {
            source_store: 'attempt', source_kind: 'email-attempt', source_key: blob.key,
            expected_binding_sha256: sha256(`arc-transactional-email-listed-attempt-v1\n${blob.key}`),
          });
        }
        if (isAttemptRetentionTombstone(entry.data)) {
          validateRetentionTombstone(entry.data, blob.key, resolved,
            { recordKind: 'attempt', attemptHmac: blob.key.slice('attempts/'.length) });
          continue;
        }
        const record = validateAttempt(entry.data, resolved);
        if (blob.key !== attemptKey(record.attempt_hmac_sha256)) {
          throw new Error('ARC_EMAIL_ATTEMPT_BINDING_INVALID');
        }
        if (['INTENT', 'PROVIDER_ACCEPTED'].includes(record.state) || !retention.enabled ||
            Date.parse(record.updated_at) > cutoff) continue;

        const entries = [];
        let priorEventKey = null;
        for await (const eventPage of listPages(store, 'provider-events/resend/')) {
          if (!eventPage || !Array.isArray(eventPage.blobs)) {
            throw new Error('ARC_EMAIL_ATTEMPT_LIST_UNAVAILABLE');
          }
          for (const eventBlob of eventPage.blobs) {
            if (!eventBlob || typeof eventBlob.key !== 'string' ||
                !/^provider-events\/resend\/[a-f0-9]{64}$/.test(eventBlob.key) ||
                priorEventKey !== null && eventBlob.key <= priorEventKey) {
              throw new Error('ARC_EMAIL_ATTEMPT_LIST_INVALID');
            }
            priorEventKey = eventBlob.key;
            const eventEntry = await store.getWithMetadata(eventBlob.key,
              { type: 'json', consistency: 'strong' });
            if (!eventEntry) {
              await reportMissingRetentionSource(adapters, {
                source_store: 'attempt', source_kind: 'provider-event-index',
                source_key: eventBlob.key,
                expected_binding_sha256: sha256(
                  `arc-transactional-email-listed-provider-event-v1\n${record.attempt_hmac_sha256}\n${eventBlob.key}`,
                ),
              });
            }
            if (isAttemptRetentionTombstone(eventEntry.data)) {
              validateRetentionTombstone(eventEntry.data, eventBlob.key, resolved,
                { recordKind: 'provider-event-index' });
              continue;
            }
            const eventRecord = validateEventRecord(eventEntry.data, resolved);
            if (eventRecord.attempt_hmac_sha256 !== record.attempt_hmac_sha256) continue;
            const output = buildRetentionTombstone(eventBlob.key, eventRecord,
              'provider-event-index', record.attempt_hmac_sha256, resolved, now);
            entries.push(Object.freeze({
              store: 'attempt', action: 'TOMBSTONE', role: 'CHILD',
              source_kind: 'provider-event-index', source_key: eventBlob.key,
              source_etag: eventEntry.etag, source_record_sha256: sha256(canonicalJson(eventRecord)),
              output_record: output, output_record_sha256: sha256(canonicalJson(output)),
            }));
          }
        }
        if (record.provider_message_id_hmac_sha256 !== null) {
          const key = reverseKey(record.provider_message_id_hmac_sha256);
          const reverseEntry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
          if (!reverseEntry) {
            await reportMissingRetentionSource(adapters, {
              source_store: 'attempt', source_kind: 'provider-message-index', source_key: key,
              expected_binding_sha256: sha256(canonicalJson({
                attempt_hmac_sha256: record.attempt_hmac_sha256,
                provider_message_id_hmac_sha256: record.provider_message_id_hmac_sha256,
              })),
            });
          }
          if (isAttemptRetentionTombstone(reverseEntry.data)) {
            validateRetentionTombstone(reverseEntry.data, key, resolved,
              { recordKind: 'provider-message-index', attemptHmac: record.attempt_hmac_sha256 });
          } else {
            const reverse = validateReverse(reverseEntry.data, resolved);
            if (reverse.provider_message_id_hmac_sha256 !== record.provider_message_id_hmac_sha256 ||
                reverse.attempt_hmac_sha256 !== record.attempt_hmac_sha256) {
              throw new Error('ARC_EMAIL_PROVIDER_MESSAGE_INDEX_CONFLICT');
            }
            const output = buildRetentionTombstone(key, reverse, 'provider-message-index',
              record.attempt_hmac_sha256, resolved, now);
            entries.push(Object.freeze({
              store: 'attempt', action: 'TOMBSTONE', role: 'CHILD',
              source_kind: 'provider-message-index', source_key: key,
              source_etag: reverseEntry.etag, source_record_sha256: sha256(canonicalJson(reverse)),
              output_record: output, output_record_sha256: sha256(canonicalJson(output)),
            }));
          }
        }
        const primaryOutput = buildRetentionTombstone(blob.key, record, 'attempt',
          record.attempt_hmac_sha256, resolved, now);
        entries.push(Object.freeze({
          store: 'attempt', action: 'TOMBSTONE', role: 'PRIMARY', source_kind: 'email-attempt',
          source_key: blob.key, source_etag: entry.etag,
          source_record_sha256: sha256(canonicalJson(record)), output_record: primaryOutput,
          output_record_sha256: sha256(canonicalJson(primaryOutput)),
        }));
        return Object.freeze({ inspected, complete: false,
          next_cursor: encodePruneCursor(cursor, resolved),
          mutation: Object.freeze({
            family: 'attempt', subject_hmac_sha256: record.attempt_hmac_sha256,
            job_kind: record.job_kind, job_key_sha256: record.job_key_sha256,
            entries: Object.freeze(entries),
          }) });
      }
    }
    cursor = { shard: cursor.shard + 1, afterKey: null };
  }
  return Object.freeze({ inspected, complete: true, next_cursor: null, mutation: null });
}
