import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

import { TRANSACTIONAL_EMAIL_KINDS } from './transactional-email-template-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const EMAIL_RECIPIENT_VAULT_STORE = 'arc-email-recipient-vault';
export const EMAIL_RECIPIENT_VAULT_SCHEMA = 'arc-email-recipient-vault-v1';
export const EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA = 'arc-email-recipient-vault-tombstone-v1';
export const EMAIL_RECIPIENT_VAULT_ENABLED_ENV = 'ARC_EMAIL_RECIPIENT_VAULT_ENABLED';
export const EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY_ENV = 'ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY';
export const EMAIL_RECIPIENT_VAULT_HMAC_SECRET_ENV = 'ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET';

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const MAX_TTL_MS = 30 * 24 * 60 * 60_000;
const PRUNE_CURSOR_SCHEMA = 'arc-email-recipient-vault-prune-cursor-v1';
const PRUNE_CURSOR_SIGNATURE_PREFIX = 'arc-email-recipient-vault-prune-cursor-signature-v1\n';
const PRUNE_SHARDS = '0123456789abcdef';
const RECORD_FIELDS = Object.freeze([
  'ciphertext_base64url', 'created_at', 'expires_at', 'iv_base64url', 'job_key_sha256', 'job_kind',
  'payload_hmac_sha256', 'recipient_email_sha256', 'record_hmac_sha256', 'schema', 'tag_base64url',
  'vault_hmac_sha256', 'version',
]);
const TOMBSTONE_FIELDS = Object.freeze([
  'customer_data_stored', 'record_hmac_sha256', 'schema', 'source_key_hmac_sha256',
  'source_record_sha256', 'tombstoned_at', 'vault_hmac_sha256', 'version',
]);
const TOMBSTONE_SIGNATURE_PREFIX = 'arc-email-recipient-vault-tombstone-record-v1\n';
const TOMBSTONE_SOURCE_KEY_PREFIX = 'arc-email-recipient-vault-tombstone-source-key-v1\n';

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError('Vault payload is invalid.');
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const result = JSON.stringify(value);
  if (result === undefined) throw new TypeError('Vault payload is invalid.');
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

function secret(value, label) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 32 ||
      Buffer.byteLength(value, 'utf8') > 256 || CONTROL.test(value)) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function encryptionKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new TypeError(`${EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY_ENV} is invalid.`);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== 32 || decoded.toString('base64url') !== value) {
    throw new TypeError(`${EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY_ENV} is invalid.`);
  }
  return decoded;
}

function stamp(value, label) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return parsed;
}

function job(kind, key) {
  if (!TRANSACTIONAL_EMAIL_KINDS.includes(kind) || typeof key !== 'string' || key.length < 8 ||
      Buffer.byteLength(key, 'utf8') > 256 || CONTROL.test(key)) {
    throw new TypeError('Email vault job binding is invalid.');
  }
  return { kind, key };
}

function recipient(value) {
  if (typeof value !== 'string' || value !== value.trim().toLowerCase() || value.length > 254 ||
      !EMAIL.test(value) || CONTROL.test(value)) throw new TypeError('Email vault recipient is invalid.');
  return value;
}

function unsigned(record) {
  const { record_hmac_sha256: ignored, ...value } = record;
  return value;
}

function publicAad(record) {
  return canonicalJson({
    schema: record.schema,
    version: record.version,
    vault_hmac_sha256: record.vault_hmac_sha256,
    job_kind: record.job_kind,
    job_key_sha256: record.job_key_sha256,
    recipient_email_sha256: record.recipient_email_sha256,
    payload_hmac_sha256: record.payload_hmac_sha256,
    created_at: record.created_at,
    expires_at: record.expires_at,
  });
}

function vaultId(kind, key, resolved) {
  return hmac(resolved.hmacSecret, `arc-email-recipient-vault-id-v1\n${kind}\n${key}`);
}

function vaultKey(id) {
  return `capsules/${id}`;
}

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
    throw new TypeError('Email vault prune cursor is invalid.');
  }
  const match = /^([A-Za-z0-9_-]+)\.([a-f0-9]{64})$/.exec(value);
  if (!match || !safeEqual(match[2], hmac(resolved.hmacSecret,
    `${PRUNE_CURSOR_SIGNATURE_PREFIX}${match[1]}`))) {
    throw new TypeError('Email vault prune cursor signature is invalid.');
  }
  let cursor;
  try { cursor = JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8')); } catch {
    throw new TypeError('Email vault prune cursor is invalid.');
  }
  if (!exactKeys(cursor, ['after_key', 'schema', 'shard']) || cursor.schema !== PRUNE_CURSOR_SCHEMA ||
      !Number.isSafeInteger(cursor.shard) || cursor.shard < 0 || cursor.shard >= PRUNE_SHARDS.length ||
      !(cursor.after_key === null || new RegExp(
        `^capsules/${PRUNE_SHARDS[cursor.shard]}[a-f0-9]{63}$`,
      ).test(cursor.after_key))) {
    throw new TypeError('Email vault prune cursor is invalid.');
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

function validateRecord(record, resolved) {
  if (!exactKeys(record, RECORD_FIELDS) || record.schema !== EMAIL_RECIPIENT_VAULT_SCHEMA || record.version !== 1 ||
      !TRANSACTIONAL_EMAIL_KINDS.includes(record.job_kind) ||
      ![record.vault_hmac_sha256, record.job_key_sha256, record.recipient_email_sha256,
        record.payload_hmac_sha256, record.record_hmac_sha256].every((value) => HEX_64.test(value)) ||
      !/^[A-Za-z0-9_-]{16}$/.test(record.iv_base64url) ||
      !/^[A-Za-z0-9_-]{22}$/.test(record.tag_base64url) ||
      typeof record.ciphertext_base64url !== 'string' || record.ciphertext_base64url.length < 16 ||
      record.ciphertext_base64url.length > 16_384 || !/^[A-Za-z0-9_-]+$/.test(record.ciphertext_base64url)) {
    throw new TypeError('Email vault record is invalid.');
  }
  const created = stamp(record.created_at, 'Email vault created_at');
  const expires = stamp(record.expires_at, 'Email vault expires_at');
  if (expires <= created || expires - created > MAX_TTL_MS) throw new TypeError('Email vault lifetime is invalid.');
  const expected = hmac(resolved.hmacSecret,
    `arc-email-recipient-vault-record-v1\n${canonicalJson(unsigned(record))}`);
  if (!safeEqual(record.record_hmac_sha256, expected)) throw new Error('ARC_EMAIL_VAULT_RECORD_SIGNATURE_INVALID');
  return record;
}

function isVaultTombstone(value) {
  return value?.schema === EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA;
}

function validateVaultTombstone(record, key, resolved, expectedSourceRecordSha256 = null) {
  if (!exactKeys(record, TOMBSTONE_FIELDS) ||
      record.schema !== EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA || record.version !== 1 ||
      record.customer_data_stored !== false ||
      ![record.vault_hmac_sha256, record.source_key_hmac_sha256,
        record.source_record_sha256, record.record_hmac_sha256].every((value) => HEX_64.test(value)) ||
      key !== vaultKey(record.vault_hmac_sha256) ||
      record.source_key_hmac_sha256 !== hmac(resolved.hmacSecret, `${TOMBSTONE_SOURCE_KEY_PREFIX}${key}`) ||
      expectedSourceRecordSha256 !== null && record.source_record_sha256 !== expectedSourceRecordSha256) {
    throw new TypeError('Email vault tombstone is invalid.');
  }
  stamp(record.tombstoned_at, 'Email vault tombstone tombstoned_at');
  const expected = hmac(resolved.hmacSecret,
    `${TOMBSTONE_SIGNATURE_PREFIX}${canonicalJson(unsigned(record))}`);
  if (!safeEqual(record.record_hmac_sha256, expected)) {
    throw new Error('ARC_EMAIL_VAULT_TOMBSTONE_SIGNATURE_INVALID');
  }
  return record;
}

export function validateEmailRecipientVaultTombstone(record, key, env = process.env,
  expectedSourceRecordSha256 = null) {
  return validateVaultTombstone(record, key, requireConfiguration(env), expectedSourceRecordSha256);
}

function buildVaultTombstone(key, record, resolved, now) {
  const unsignedTombstone = {
    schema: EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA,
    version: 1,
    vault_hmac_sha256: record.vault_hmac_sha256,
    source_key_hmac_sha256: hmac(resolved.hmacSecret, `${TOMBSTONE_SOURCE_KEY_PREFIX}${key}`),
    source_record_sha256: sha256(canonicalJson(record)),
    tombstoned_at: now.toISOString(),
    customer_data_stored: false,
  };
  return {
    ...unsignedTombstone,
    record_hmac_sha256: hmac(resolved.hmacSecret,
      `${TOMBSTONE_SIGNATURE_PREFIX}${canonicalJson(unsignedTombstone)}`),
  };
}

async function tombstoneVaultRecord(store, key, entry, record, resolved, now) {
  if (typeof entry?.etag !== 'string' || entry.etag.length === 0) {
    throw new Error('ARC_EMAIL_VAULT_TOMBSTONE_ETAG_UNAVAILABLE');
  }
  const sourceRecordSha256 = sha256(canonicalJson(record));
  const expected = buildVaultTombstone(key, record, resolved, now);
  let result = null;
  let writeError = null;
  try {
    result = await store.setJSON(key, expected, { onlyIfMatch: entry.etag });
  } catch (error) {
    writeError = error;
  }
  const stored = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (result?.modified) {
    if (!stored || canonicalJson(stored.data) !== canonicalJson(expected)) {
      throw new Error('ARC_EMAIL_VAULT_TOMBSTONE_UNAVAILABLE');
    }
    validateVaultTombstone(stored.data, key, resolved, sourceRecordSha256);
    return { created: true, record: stored.data };
  }
  if (stored && isVaultTombstone(stored.data)) {
    validateVaultTombstone(stored.data, key, resolved, sourceRecordSha256);
    return {
      created: writeError !== null && canonicalJson(stored.data) === canonicalJson(expected),
      record: stored.data,
    };
  }
  if (writeError) throw writeError;
  throw new Error('ARC_EMAIL_VAULT_STATE_CONTENTION');
}

function decryptRecord(record, resolved) {
  const decipher = createDecipheriv('aes-256-gcm', resolved.encryptionKey,
    Buffer.from(record.iv_base64url, 'base64url'));
  decipher.setAAD(Buffer.from(publicAad(record)));
  decipher.setAuthTag(Buffer.from(record.tag_base64url, 'base64url'));
  let plaintext;
  try {
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(record.ciphertext_base64url, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  } catch { throw new Error('ARC_EMAIL_VAULT_DECRYPTION_FAILED'); }
  let value;
  try { value = JSON.parse(plaintext); } catch { throw new Error('ARC_EMAIL_VAULT_DECRYPTION_FAILED'); }
  if (!exactKeys(value, ['private_payload', 'recipient_email']) || canonicalJson(value) !== plaintext) {
    throw new Error('ARC_EMAIL_VAULT_DECRYPTION_FAILED');
  }
  const normalizedRecipient = recipient(value.recipient_email);
  if (sha256(normalizedRecipient) !== record.recipient_email_sha256 ||
      !safeEqual(record.payload_hmac_sha256, hmac(resolved.hmacSecret, `arc-email-recipient-vault-payload-v1\n${plaintext}`))) {
    throw new Error('ARC_EMAIL_VAULT_BINDING_INVALID');
  }
  return value;
}

export function emailRecipientVaultConfiguration(env = process.env) {
  if (env[EMAIL_RECIPIENT_VAULT_ENABLED_ENV] !== 'true') return Object.freeze({ enabled: false });
  try {
    if (!sensitiveCredentialsAreIsolated(env, [
      EMAIL_RECIPIENT_VAULT_HMAC_SECRET_ENV,
      EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY_ENV,
    ])) throw new TypeError('Email vault credentials must be isolated.');
    const hmacSecret = secret(env[EMAIL_RECIPIENT_VAULT_HMAC_SECRET_ENV], EMAIL_RECIPIENT_VAULT_HMAC_SECRET_ENV);
    const key = encryptionKey(env[EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY_ENV]);
    if (safeEqual(hmacSecret, env[EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY_ENV])) {
      throw new TypeError('Email vault secrets must be distinct.');
    }
    return Object.freeze({ enabled: true, hmacSecret, encryptionKey: key });
  } catch { return Object.freeze({ enabled: false }); }
}

function requireConfiguration(env) {
  const resolved = emailRecipientVaultConfiguration(env);
  if (!resolved.enabled) throw new Error('ARC_EMAIL_VAULT_DISABLED');
  return resolved;
}

export async function sealEmailRecipientCapsule(store, input, env = process.env, adapters = {}) {
  const resolved = requireConfiguration(env);
  if (!exactKeys(input, ['expires_at', 'job_key', 'job_kind', 'private_payload', 'recipient_email'])) {
    throw new TypeError('Email vault input is invalid.');
  }
  const binding = job(input.job_kind, input.job_key);
  const normalizedRecipient = recipient(input.recipient_email);
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Email vault clock is invalid.');
  const expires = stamp(input.expires_at, 'Email vault expires_at');
  if (expires <= now.getTime() || expires - now.getTime() > MAX_TTL_MS) throw new TypeError('Email vault lifetime is invalid.');
  const payloadJson = canonicalJson({ recipient_email: normalizedRecipient, private_payload: input.private_payload });
  if (Buffer.byteLength(payloadJson, 'utf8') > 8_192) throw new TypeError('Email vault payload is too large.');
  const id = vaultId(binding.kind, binding.key, resolved);
  const key = vaultKey(id);
  let existing = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (existing) {
    if (isVaultTombstone(existing.data)) {
      validateVaultTombstone(existing.data, key, resolved);
      throw new Error('ARC_EMAIL_VAULT_TOMBSTONED');
    }
    const record = validateRecord(existing.data, resolved);
    const opened = decryptRecord(record, resolved);
    if (record.job_kind !== binding.kind || record.job_key_sha256 !== sha256(binding.key) ||
        record.expires_at !== input.expires_at || canonicalJson(opened) !== payloadJson) {
      throw new Error('ARC_EMAIL_VAULT_CONFLICT');
    }
    return Object.freeze({ vault_hmac_sha256: id, created: false, idempotent_replay: true });
  }
  const iv = Buffer.from((adapters.randomBytes || randomBytes)(12));
  if (iv.length !== 12) throw new TypeError('Email vault IV source is invalid.');
  const base = {
    schema: EMAIL_RECIPIENT_VAULT_SCHEMA,
    version: 1,
    vault_hmac_sha256: id,
    job_kind: binding.kind,
    job_key_sha256: sha256(binding.key),
    recipient_email_sha256: sha256(normalizedRecipient),
    payload_hmac_sha256: hmac(resolved.hmacSecret, `arc-email-recipient-vault-payload-v1\n${payloadJson}`),
    created_at: now.toISOString(),
    expires_at: input.expires_at,
  };
  const cipher = createCipheriv('aes-256-gcm', resolved.encryptionKey, iv);
  cipher.setAAD(Buffer.from(publicAad(base)));
  const ciphertext = Buffer.concat([cipher.update(payloadJson), cipher.final()]);
  const unsignedRecord = {
    ...base,
    iv_base64url: iv.toString('base64url'),
    ciphertext_base64url: ciphertext.toString('base64url'),
    tag_base64url: cipher.getAuthTag().toString('base64url'),
  };
  const record = {
    ...unsignedRecord,
    record_hmac_sha256: hmac(resolved.hmacSecret,
      `arc-email-recipient-vault-record-v1\n${canonicalJson(unsignedRecord)}`),
  };
  validateRecord(record, resolved);
  try { await store.setJSON(key, record, { onlyIfNew: true }); } catch {}
  existing = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!existing) throw new Error('ARC_EMAIL_VAULT_WRITE_UNAVAILABLE');
  if (isVaultTombstone(existing.data)) {
    validateVaultTombstone(existing.data, key, resolved);
    throw new Error('ARC_EMAIL_VAULT_TOMBSTONED');
  }
  const persisted = validateRecord(existing.data, resolved);
  const opened = decryptRecord(persisted, resolved);
  if (persisted.vault_hmac_sha256 !== id || persisted.job_key_sha256 !== sha256(binding.key) ||
      persisted.expires_at !== input.expires_at || canonicalJson(opened) !== payloadJson) {
    throw new Error('ARC_EMAIL_VAULT_CONFLICT');
  }
  return Object.freeze({ vault_hmac_sha256: id, created: true, idempotent_replay: false });
}

export async function openEmailRecipientCapsule(store, input, env = process.env, adapters = {}) {
  const resolved = requireConfiguration(env);
  if (!exactKeys(input, ['job_key', 'job_kind'])) throw new TypeError('Email vault lookup is invalid.');
  const binding = job(input.job_kind, input.job_key);
  const key = vaultKey(vaultId(binding.kind, binding.key, resolved));
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!entry) throw new Error('ARC_EMAIL_VAULT_NOT_FOUND');
  if (isVaultTombstone(entry.data)) {
    validateVaultTombstone(entry.data, key, resolved);
    throw new Error('ARC_EMAIL_VAULT_NOT_FOUND');
  }
  const record = validateRecord(entry.data, resolved);
  if (record.job_kind !== binding.kind || record.job_key_sha256 !== sha256(binding.key)) {
    throw new Error('ARC_EMAIL_VAULT_BINDING_INVALID');
  }
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Email vault clock is invalid.');
  if (Date.parse(record.expires_at) <= now.getTime()) throw new Error('ARC_EMAIL_VAULT_EXPIRED');
  const value = decryptRecord(record, resolved);
  return Object.freeze({
    vault_hmac_sha256: record.vault_hmac_sha256,
    recipient_email: value.recipient_email,
    private_payload: structuredClone(value.private_payload),
    expires_at: record.expires_at,
  });
}

export async function deleteEmailRecipientCapsule(store, input, env = process.env, adapters = {}) {
  const resolved = requireConfiguration(env);
  if (!exactKeys(input, ['job_key', 'job_kind'])) throw new TypeError('Email vault deletion is invalid.');
  const binding = job(input.job_kind, input.job_key);
  const key = vaultKey(vaultId(binding.kind, binding.key, resolved));
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!entry) return Object.freeze({ deleted: false, idempotent_replay: true });
  if (isVaultTombstone(entry.data)) {
    validateVaultTombstone(entry.data, key, resolved);
    return Object.freeze({ deleted: false, idempotent_replay: true });
  }
  const record = validateRecord(entry.data, resolved);
  if (record.job_kind !== binding.kind || record.job_key_sha256 !== sha256(binding.key)) {
    throw new Error('ARC_EMAIL_VAULT_BINDING_INVALID');
  }
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Email vault clock is invalid.');
  const result = await tombstoneVaultRecord(store, key, entry, record, resolved, now);
  return Object.freeze({ deleted: result.created, idempotent_replay: !result.created });
}

async function reportMissingRetentionSource(adapters, key) {
  if (typeof adapters.onMissingSource !== 'function') {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_ANOMALY_UNAVAILABLE');
  }
  await adapters.onMissingSource(Object.freeze({
    source_store: 'vault',
    source_kind: 'vault-capsule',
    source_key: key,
    expected_binding_sha256: sha256(`arc-email-recipient-vault-listed-source-v1\n${key}`),
  }));
  throw new Error('ARC_TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_BLOCKED');
}

/**
 * Builds, but never applies, the next expired-capsule retention mutation.
 *
 * The returned source coordinates are sufficient for a caller to re-read and
 * conditionally replace the exact record while a global retention fence is
 * held.  Neither the encrypted source record nor any recipient binding is
 * copied into the plan.
 */
export async function planExpiredEmailRecipientCapsuleRetention(store, env = process.env,
  adapters = {}) {
  const resolved = requireConfiguration(env);
  if (typeof adapters.clock !== 'function') {
    throw new TypeError('Email vault retention plan clock is required.');
  }
  const now = new Date(adapters.clock());
  if (!Number.isFinite(now.getTime())) {
    throw new TypeError('Email vault retention plan clock is invalid.');
  }
  let cursor = decodePruneCursor(adapters.cursor, resolved);
  let inspected = 0;
  while (cursor.shard < PRUNE_SHARDS.length) {
    const prefix = `capsules/${PRUNE_SHARDS[cursor.shard]}`;
    let priorKey = null;
    for await (const page of listPages(store, prefix)) {
      if (!page || !Array.isArray(page.blobs)) throw new Error('ARC_EMAIL_VAULT_LIST_UNAVAILABLE');
      for (const blob of page.blobs) {
        if (!blob || typeof blob.key !== 'string' ||
            !new RegExp(`^${prefix}[a-f0-9]{63}$`).test(blob.key) ||
            priorKey !== null && blob.key <= priorKey) {
          throw new Error('ARC_EMAIL_VAULT_LIST_INVALID');
        }
        priorKey = blob.key;
        if (cursor.afterKey !== null && blob.key <= cursor.afterKey) continue;
        inspected += 1;
        const entry = await store.getWithMetadata(blob.key,
          { type: 'json', consistency: 'strong' });
        cursor = { ...cursor, afterKey: blob.key };
        if (!entry) await reportMissingRetentionSource(adapters, blob.key);
        if (isVaultTombstone(entry.data)) {
          validateVaultTombstone(entry.data, blob.key, resolved);
          continue;
        }
        const record = validateRecord(entry.data, resolved);
        if (blob.key !== vaultKey(record.vault_hmac_sha256)) {
          throw new Error('ARC_EMAIL_VAULT_BINDING_INVALID');
        }
        if (Date.parse(record.expires_at) > now.getTime()) continue;
        if (typeof entry.etag !== 'string' || entry.etag.length === 0) {
          throw new Error('ARC_EMAIL_VAULT_TOMBSTONE_ETAG_UNAVAILABLE');
        }
        const output = buildVaultTombstone(blob.key, record, resolved, now);
        const sourceRecordSha256 = sha256(canonicalJson(record));
        const outputRecordSha256 = sha256(canonicalJson(output));
        const opened = decryptRecord(record, resolved);
        const directHoldSubject = typeof opened.private_payload?.handoff_id === 'string' &&
          HEX_64.test(opened.private_payload.handoff_id)
          ? { family: 'handoff', subject_hmac_sha256: opened.private_payload.handoff_id }
          : typeof opened.private_payload?.invite_hmac_sha256 === 'string' &&
              HEX_64.test(opened.private_payload.invite_hmac_sha256)
            ? { family: 'review',
              subject_hmac_sha256: opened.private_payload.invite_hmac_sha256 }
            : null;
        return Object.freeze({
          inspected,
          complete: false,
          next_cursor: encodePruneCursor(cursor, resolved),
          mutation: Object.freeze({
            store: 'vault',
            action: 'TOMBSTONE',
            role: 'PRIMARY',
            source_key: blob.key,
            source_etag: entry.etag,
            source_record_sha256: sourceRecordSha256,
            output_record: Object.freeze(output),
            output_record_sha256: outputRecordSha256,
            job_kind: record.job_kind,
            job_key_sha256: record.job_key_sha256,
            legal_hold_binding: directHoldSubject,
          }),
        });
      }
    }
    cursor = { shard: cursor.shard + 1, afterKey: null };
  }
  return Object.freeze({ inspected, complete: true, next_cursor: null, mutation: null });
}

export async function pruneExpiredEmailRecipientCapsules() {
  throw new Error('ARC_EMAIL_VAULT_RETENTION_PRUNE_RETIRED_USE_FROZEN_SWEEP');
}
