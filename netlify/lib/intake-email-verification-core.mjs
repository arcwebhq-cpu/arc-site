import { createHmac, timingSafeEqual } from 'node:crypto';

import { assertPublicIntakeAuthority } from './activation-manifest-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const INTAKE_EMAIL_VERIFICATION_ENABLED_ENV = 'ARC_INTAKE_EMAIL_VERIFICATION_ENABLED';
export const INTAKE_EMAIL_VERIFICATION_STATE_SECRET_ENV = 'ARC_INTAKE_EMAIL_VERIFICATION_STATE_SECRET';
export const INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET_ENV = 'ARC_INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET';
export const INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET_ENV = 'ARC_INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET';
export const INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET_ENV = 'ARC_INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET';
export const INTAKE_EMAIL_VERIFICATION_STATE_SCHEMA = 'arc-intake-email-verification-state-v1';
export const INTAKE_EMAIL_VERIFICATION_TOKEN_INDEX_SCHEMA = 'arc-intake-email-verification-token-index-v1';
export const INTAKE_EMAIL_VERIFICATION_ARC1_RECEIPT_SCHEMA = 'arc-intake-email-verification-arc1-release-v1';
export const INTAKE_EMAIL_VERIFICATION_REQUEST_SCHEMA = 'arc-intake-email-verification-request-v1';
export const INTAKE_EMAIL_VERIFICATION_TTL_MS = 24 * 60 * 60_000;
export const INTAKE_EMAIL_VERIFICATION_ARC1_RECEIPT_TTL_MS = 24 * 60 * 60_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const TOKEN = /^arcv1\.[A-Za-z0-9_-]{43}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const STATE_FIELDS = Object.freeze([
  'arc1_receipt_expires_at', 'arc1_release_receipt_hmac_sha256', 'arc1_released_at', 'created_at',
  'expires_at', 'recipient_identity_hmac_sha256', 'schema', 'source_submission_data_sha256',
  'status', 'submission_id', 'token_hmac_sha256', 'verification_id_hmac_sha256', 'verified_at', 'version',
]);
const INDEX_FIELDS = Object.freeze([
  'schema', 'state_key', 'token_hmac_sha256', 'verification_id_hmac_sha256', 'version',
]);
const RECEIPT_FIELDS = Object.freeze([
  'expires_at', 'hmac_sha256', 'released_at', 'schema', 'source_submission_data_sha256',
  'submission_id', 'verification_id_hmac_sha256', 'version',
]);

function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(Object.is(value, -0) ? 0 : value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('Plain JSON is required.');
}

const hmac = (secret, value, encoding = 'hex') => createHmac('sha256', secret).update(value).digest(encoding);
const exactKeys = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
const safeEqual = (left, right) => {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
};
const secret = (value, label) => {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 32 ||
      Buffer.byteLength(value, 'utf8') > 256 || CONTROL.test(value)) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
};
const stamp = (value, label) => {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return parsed;
};
const nullableStamp = (value, label) => value === null ? null : stamp(value, label);

function origin(value) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new TypeError('Intake email verification origin is invalid.'); }
  if (parsed.protocol !== 'https:' || parsed.hostname !== 'arcweb.onl' || parsed.username || parsed.password ||
      parsed.port || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new TypeError('Intake email verification origin is invalid.');
  }
  return parsed.origin;
}

function normalizedSource(value) {
  const submissionId = String(value?.submission_id || '').toLowerCase();
  const sourceDigest = String(value?.submission_data_sha256 || '').toLowerCase();
  const recipient = String(value?.data?.email || '').trim().toLowerCase();
  if (!UUID.test(submissionId) || !HEX_64.test(sourceDigest) || recipient.length > 254 ||
      !EMAIL.test(recipient) || CONTROL.test(recipient)) throw new TypeError('Intake email verification source is invalid.');
  return { submissionId, sourceDigest, recipient };
}

export function intakeEmailVerificationConfiguration(env = process.env) {
  if (env[INTAKE_EMAIL_VERIFICATION_ENABLED_ENV] !== 'true') return Object.freeze({ enabled: false });
  try {
    const names = [
      INTAKE_EMAIL_VERIFICATION_STATE_SECRET_ENV,
      INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET_ENV,
      INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET_ENV,
      INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET_ENV,
    ];
    const values = Object.fromEntries(names.map((name) => [name, secret(env[name], name)]));
    if (!sensitiveCredentialsAreIsolated(env, names)) {
      throw new TypeError('Verification secrets must be distinct from other ARC secrets.');
    }
    return Object.freeze({ enabled: true, origin: origin(env.URL), ...values });
  } catch {
    return Object.freeze({ enabled: false });
  }
}

function requireConfiguration(env) {
  const resolved = intakeEmailVerificationConfiguration(env);
  if (!resolved.enabled) throw new Error('ARC_INTAKE_EMAIL_VERIFICATION_DISABLED');
  return resolved;
}

function assertAuthority(env, adapters) {
  const now = new Date((adapters.authorityClock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new Error('ARC_PUBLIC_INTAKE_AUTHORITY_REQUIRED');
  assertPublicIntakeAuthority(env, now);
}

function identity(source, resolved) {
  return hmac(resolved[INTAKE_EMAIL_VERIFICATION_STATE_SECRET_ENV],
    `arc-intake-email-verification-id-v1\n${source.submissionId}\n${source.sourceDigest}`);
}

function stateKey(verificationId) {
  return `email-verification/state/${verificationId}`;
}

function tokenFor(record, resolved) {
  return `arcv1.${hmac(resolved[INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET_ENV],
    `arc-intake-email-verification-token-v1\n${record.verification_id_hmac_sha256}\n${record.expires_at}`, 'base64url')}`;
}

function tokenHmac(token, resolved) {
  return hmac(resolved[INTAKE_EMAIL_VERIFICATION_STATE_SECRET_ENV],
    `arc-intake-email-verification-token-index-v1\n${token}`);
}

function tokenIndexKey(digest) {
  return `email-verification/token/${digest}`;
}

export function validateIntakeEmailVerificationState(value) {
  if (!exactKeys(value, STATE_FIELDS) || value.schema !== INTAKE_EMAIL_VERIFICATION_STATE_SCHEMA || value.version !== 1 ||
      !HEX_64.test(value.verification_id_hmac_sha256) || !UUID.test(value.submission_id) ||
      !HEX_64.test(value.source_submission_data_sha256) || !HEX_64.test(value.recipient_identity_hmac_sha256) ||
      !HEX_64.test(value.token_hmac_sha256) || !['PENDING', 'VERIFIED', 'ARC1_RELEASED', 'EXPIRED'].includes(value.status)) {
    throw new TypeError('Intake email verification state is invalid.');
  }
  const created = stamp(value.created_at, 'Verification created_at');
  const expires = stamp(value.expires_at, 'Verification expires_at');
  const verified = nullableStamp(value.verified_at, 'Verification verified_at');
  const released = nullableStamp(value.arc1_released_at, 'Verification arc1_released_at');
  const receiptExpires = nullableStamp(value.arc1_receipt_expires_at, 'Verification receipt expires_at');
  if (expires <= created || expires - created !== INTAKE_EMAIL_VERIFICATION_TTL_MS) {
    throw new TypeError('Intake email verification lifetime is invalid.');
  }
  const noVerification = verified === null && released === null && receiptExpires === null &&
    value.arc1_release_receipt_hmac_sha256 === null;
  if (['PENDING', 'EXPIRED'].includes(value.status) && !noVerification) {
    throw new TypeError('Intake email verification state is inconsistent.');
  }
  if (value.status === 'VERIFIED' && (!(verified >= created && verified < expires) || released !== null ||
      receiptExpires !== null || value.arc1_release_receipt_hmac_sha256 !== null)) {
    throw new TypeError('Verified intake email state is inconsistent.');
  }
  if (value.status === 'ARC1_RELEASED' && (!(verified >= created && verified < expires) || !(released >= verified) ||
      !(receiptExpires > released) || receiptExpires - released !== INTAKE_EMAIL_VERIFICATION_ARC1_RECEIPT_TTL_MS ||
      !HEX_64.test(value.arc1_release_receipt_hmac_sha256 || ''))) {
    throw new TypeError('Released intake email state is inconsistent.');
  }
  return value;
}

function validateTokenIndex(value) {
  if (!exactKeys(value, INDEX_FIELDS) || value.schema !== INTAKE_EMAIL_VERIFICATION_TOKEN_INDEX_SCHEMA ||
      value.version !== 1 || !HEX_64.test(value.verification_id_hmac_sha256) ||
      !HEX_64.test(value.token_hmac_sha256) ||
      value.state_key !== stateKey(value.verification_id_hmac_sha256)) {
    throw new TypeError('Intake email verification token index is invalid.');
  }
  return value;
}

async function readState(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  return entry ? { value: validateIntakeEmailVerificationState(entry.data), etag: entry.etag } : null;
}

async function replaceState(store, key, entry, value) {
  validateIntakeEmailVerificationState(value);
  const result = await store.setJSON(key, value, { onlyIfMatch: entry.etag });
  if (!result?.modified || typeof result.etag !== 'string' || !result.etag) {
    throw new Error('ARC_INTAKE_EMAIL_VERIFICATION_STATE_CONTENTION');
  }
  return { value, etag: result.etag };
}

async function ensureIndex(store, record, resolved) {
  const token = tokenFor(record, resolved);
  const digest = tokenHmac(token, resolved);
  if (!safeEqual(digest, record.token_hmac_sha256)) throw new Error('ARC_INTAKE_EMAIL_VERIFICATION_BINDING_INVALID');
  const key = tokenIndexKey(digest);
  const expected = {
    schema: INTAKE_EMAIL_VERIFICATION_TOKEN_INDEX_SCHEMA,
    version: 1,
    verification_id_hmac_sha256: record.verification_id_hmac_sha256,
    token_hmac_sha256: digest,
    state_key: stateKey(record.verification_id_hmac_sha256),
  };
  let entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!entry) {
    try { await store.setJSON(key, expected, { onlyIfNew: true }); } catch {}
    entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  }
  if (!entry || canonicalJson(validateTokenIndex(entry.data)) !== canonicalJson(expected)) {
    throw new Error('ARC_INTAKE_EMAIL_VERIFICATION_INDEX_CONFLICT');
  }
  return token;
}

export async function reserveIntakeEmailVerification(sourceRecord, env, store, adapters = {}) {
  const now = new Date((adapters.clock || (() => new Date()))());
  assertAuthority(env, adapters);
  if (!Number.isFinite(now.getTime())) throw new TypeError('Intake email verification clock is invalid.');
  const resolved = requireConfiguration(env);
  const source = normalizedSource(sourceRecord);
  const verificationId = identity(source, resolved);
  const key = stateKey(verificationId);
  let entry = await readState(store, key);
  let created = false;
  if (!entry) {
    const base = {
      schema: INTAKE_EMAIL_VERIFICATION_STATE_SCHEMA,
      version: 1,
      verification_id_hmac_sha256: verificationId,
      submission_id: source.submissionId,
      source_submission_data_sha256: source.sourceDigest,
      recipient_identity_hmac_sha256: hmac(resolved[INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET_ENV],
        `arc-intake-email-verification-recipient-v1\n${source.recipient}`),
      created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + INTAKE_EMAIL_VERIFICATION_TTL_MS).toISOString(),
    };
    const provisional = { ...base, token_hmac_sha256: '0'.repeat(64), status: 'PENDING', verified_at: null,
      arc1_released_at: null, arc1_receipt_expires_at: null, arc1_release_receipt_hmac_sha256: null };
    const token = tokenFor(provisional, resolved);
    const expected = { ...provisional, token_hmac_sha256: tokenHmac(token, resolved) };
    validateIntakeEmailVerificationState(expected);
    try { await store.setJSON(key, expected, { onlyIfNew: true }); } catch {}
    entry = await readState(store, key);
    created = entry?.value && canonicalJson(entry.value) === canonicalJson(expected);
  }
  if (!entry || entry.value.verification_id_hmac_sha256 !== verificationId ||
      entry.value.submission_id !== source.submissionId ||
      entry.value.source_submission_data_sha256 !== source.sourceDigest ||
      !safeEqual(entry.value.recipient_identity_hmac_sha256,
        hmac(resolved[INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET_ENV],
          `arc-intake-email-verification-recipient-v1\n${source.recipient}`))) {
    throw new Error('ARC_INTAKE_EMAIL_VERIFICATION_CONFLICT');
  }
  const token = await ensureIndex(store, entry.value, resolved);
  return Object.freeze({
    created,
    state: entry.value.status,
    verification_id_hmac_sha256: verificationId,
    recipient_identity_hmac_sha256: entry.value.recipient_identity_hmac_sha256,
    expires_at: entry.value.expires_at,
    verification_url: `${resolved.origin}/verify/#${token}`,
  });
}

function genericRejection() {
  return new Error('ARC_INTAKE_EMAIL_VERIFICATION_REJECTED');
}

export async function consumeIntakeEmailVerificationToken(rawToken, env, store, adapters = {}) {
  const now = new Date((adapters.clock || (() => new Date()))());
  assertAuthority(env, adapters);
  if (!Number.isFinite(now.getTime())) throw genericRejection();
  const resolved = requireConfiguration(env);
  if (typeof rawToken !== 'string' || !TOKEN.test(rawToken)) throw genericRejection();
  const digest = tokenHmac(rawToken, resolved);
  const indexKey = tokenIndexKey(digest);
  let index;
  try {
    const entry = await store.getWithMetadata(indexKey, { type: 'json', consistency: 'strong' });
    index = entry ? validateTokenIndex(entry.data) : null;
  } catch { throw genericRejection(); }
  if (!index || !safeEqual(index.token_hmac_sha256, digest)) throw genericRejection();
  let entry = await readState(store, index.state_key);
  if (!entry || entry.value.verification_id_hmac_sha256 !== index.verification_id_hmac_sha256 ||
      !safeEqual(entry.value.token_hmac_sha256, digest)) throw genericRejection();
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const record = entry.value;
    if (record.status !== 'PENDING') throw genericRejection();
    if (Date.parse(record.expires_at) <= now.getTime()) {
      try { await replaceState(store, index.state_key, entry, { ...record, status: 'EXPIRED' }); } catch {}
      try { await store.delete(indexKey); } catch {}
      throw genericRejection();
    }
    const verified = { ...record, status: 'VERIFIED', verified_at: now.toISOString() };
    try {
      entry = await replaceState(store, index.state_key, entry, verified);
      try { await store.delete(indexKey); } catch {}
      return Object.freeze({
        verified: true,
        submission_id: record.submission_id,
        source_submission_data_sha256: record.source_submission_data_sha256,
        verification_id_hmac_sha256: record.verification_id_hmac_sha256,
      });
    } catch (error) {
      if (error?.message !== 'ARC_INTAKE_EMAIL_VERIFICATION_STATE_CONTENTION' || attempt === 3) throw genericRejection();
      entry = await readState(store, index.state_key);
      if (!entry) throw genericRejection();
    }
  }
  throw genericRejection();
}

export async function intakeEmailVerificationDispatchReady(sourceRecord, env, store, adapters = {}) {
  const now = new Date((adapters.clock || (() => new Date()))());
  assertAuthority(env, adapters);
  if (!Number.isFinite(now.getTime())) return false;
  const resolved = requireConfiguration(env);
  const source = normalizedSource(sourceRecord);
  const entry = await readState(store, stateKey(identity(source, resolved)));
  return Boolean(entry && entry.value.submission_id === source.submissionId &&
    entry.value.source_submission_data_sha256 === source.sourceDigest &&
    ['VERIFIED', 'ARC1_RELEASED'].includes(entry.value.status));
}

function receiptValue(record) {
  return {
    schema: INTAKE_EMAIL_VERIFICATION_ARC1_RECEIPT_SCHEMA,
    version: 1,
    verification_id_hmac_sha256: record.verification_id_hmac_sha256,
    submission_id: record.submission_id,
    source_submission_data_sha256: record.source_submission_data_sha256,
    released_at: record.arc1_released_at,
    expires_at: record.arc1_receipt_expires_at,
  };
}

function signedReceipt(record, resolved) {
  const value = receiptValue(record);
  return Object.freeze({ ...value, hmac_sha256: hmac(resolved[INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET_ENV],
    `arc-intake-email-verification-arc1-release-v1\n${canonicalJson(value)}`) });
}

export function validateIntakeEmailVerificationArc1Receipt(receipt, sourceRecord, env, now = new Date()) {
  const resolved = requireConfiguration(env);
  const source = normalizedSource(sourceRecord);
  if (!exactKeys(receipt, RECEIPT_FIELDS) || receipt.schema !== INTAKE_EMAIL_VERIFICATION_ARC1_RECEIPT_SCHEMA ||
      receipt.version !== 1 || !HEX_64.test(receipt.verification_id_hmac_sha256 || '') ||
      receipt.submission_id !== source.submissionId || receipt.source_submission_data_sha256 !== source.sourceDigest ||
      !HEX_64.test(receipt.hmac_sha256 || '')) return false;
  const released = stamp(receipt.released_at, 'ARC1 verification receipt released_at');
  const expires = stamp(receipt.expires_at, 'ARC1 verification receipt expires_at');
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || expires <= nowMs || expires - released !== INTAKE_EMAIL_VERIFICATION_ARC1_RECEIPT_TTL_MS ||
      receipt.verification_id_hmac_sha256 !== identity(source, resolved)) return false;
  const { hmac_sha256: ignored, ...value } = receipt;
  return safeEqual(receipt.hmac_sha256, hmac(resolved[INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET_ENV],
    `arc-intake-email-verification-arc1-release-v1\n${canonicalJson(value)}`));
}

export async function consumeVerifiedIntakeForArc1(sourceRecord, env, store, adapters = {}) {
  const now = new Date((adapters.clock || (() => new Date()))());
  assertAuthority(env, adapters);
  if (!Number.isFinite(now.getTime())) throw new TypeError('Intake email verification clock is invalid.');
  const resolved = requireConfiguration(env);
  const source = normalizedSource(sourceRecord);
  const key = stateKey(identity(source, resolved));
  let entry = await readState(store, key);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    if (!entry || entry.value.submission_id !== source.submissionId ||
        entry.value.source_submission_data_sha256 !== source.sourceDigest) {
      throw new Error('ARC_INTAKE_EMAIL_VERIFICATION_REQUIRED');
    }
    if (entry.value.status === 'ARC1_RELEASED') {
      const receipt = signedReceipt(entry.value, resolved);
      if (!safeEqual(receipt.hmac_sha256, entry.value.arc1_release_receipt_hmac_sha256) ||
          !validateIntakeEmailVerificationArc1Receipt(receipt, sourceRecord, env, now)) {
        throw new Error('ARC_INTAKE_EMAIL_VERIFICATION_RELEASE_EXPIRED');
      }
      return Object.freeze({ receipt, idempotent_replay: true });
    }
    if (entry.value.status !== 'VERIFIED') throw new Error('ARC_INTAKE_EMAIL_VERIFICATION_REQUIRED');
    const released = {
      ...entry.value,
      status: 'ARC1_RELEASED',
      arc1_released_at: now.toISOString(),
      arc1_receipt_expires_at: new Date(now.getTime() + INTAKE_EMAIL_VERIFICATION_ARC1_RECEIPT_TTL_MS).toISOString(),
      arc1_release_receipt_hmac_sha256: '0'.repeat(64),
    };
    const receipt = signedReceipt(released, resolved);
    released.arc1_release_receipt_hmac_sha256 = receipt.hmac_sha256;
    try {
      entry = await replaceState(store, key, entry, released);
      return Object.freeze({ receipt: signedReceipt(entry.value, resolved), idempotent_replay: false });
    } catch (error) {
      if (error?.message !== 'ARC_INTAKE_EMAIL_VERIFICATION_STATE_CONTENTION' || attempt === 3) throw error;
      entry = await readState(store, key);
    }
  }
  throw new Error('ARC_INTAKE_EMAIL_VERIFICATION_STATE_CONTENTION');
}
