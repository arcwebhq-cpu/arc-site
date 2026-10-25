import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { assertPublicIntakeAuthority } from './activation-manifest-core.mjs';
import { canonicalJson } from './intake-arc1-bridge-core.mjs';
import { sealEmailRecipientCapsule } from './email-recipient-vault-core.mjs';
import { INTAKE_SUBMISSION_SCHEMA } from './intake-submission-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const INTAKE_CONFIRMATION_OUTBOX_ENABLED_ENV = 'ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED';
export const INTAKE_CONFIRMATION_CONSUMER_ENABLED_ENV = 'ARC_INTAKE_CONFIRMATION_CONSUMER_ENABLED';
export const INTAKE_CONFIRMATION_OUTBOX_SECRET_ENV = 'ARC_INTAKE_CONFIRMATION_OUTBOX_SECRET';
export const INTAKE_CONFIRMATION_CONSUMER_BEARER_ENV = 'ARC_INTAKE_CONFIRMATION_CONSUMER_BEARER';
export const INTAKE_CONFIRMATION_RECEIPT_SECRET_ENV = 'ARC_INTAKE_CONFIRMATION_RECEIPT_SECRET';
export const INTAKE_CONFIRMATION_OUTBOX_STORE = 'arc-intake-confirmation-outbox';
export const INTAKE_CONFIRMATION_OUTBOX_SCHEMA = 'arc-intake-confirmation-outbox-v1';
export const INTAKE_CONFIRMATION_PENDING_INDEX_SCHEMA = 'arc-intake-confirmation-pending-index-v1';
export const INTAKE_CONFIRMATION_CLAIM_REQUEST_SCHEMA = 'arc-intake-confirmation-claim-request-v1';
export const INTAKE_CONFIRMATION_CLAIM_RESPONSE_SCHEMA = 'arc-intake-confirmation-claim-v1';
export const INTAKE_CONFIRMATION_COMPLETION_REQUEST_SCHEMA = 'arc-intake-confirmation-completion-request-v1';
export const INTAKE_CONFIRMATION_COMPLETION_RESPONSE_SCHEMA = 'arc-intake-confirmation-completion-v1';
export const INTAKE_CONFIRMATION_CLAIM_ENDPOINT_PATH = '/internal/intake/confirmation/claim';
export const INTAKE_CONFIRMATION_COMPLETION_ENDPOINT_PATH = '/internal/intake/confirmation/complete';
export const INTAKE_CONFIRMATION_CLAIM_LEASE_MS = 15 * 60_000;
export const INTAKE_CONFIRMATION_PENDING_SCAN_LIMIT = 100;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const OUTBOX_ID_PATTERN = /^arcconfirm_[a-f0-9]{40}$/;
const ATTEMPT_ID_PATTERN = /^arcconfirmattempt_[a-f0-9]{40}$/;
const PROVIDER_PATTERN = /^[a-z0-9][a-z0-9_-]{1,31}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const OUTBOX_FIELDS = Object.freeze([
  'claim_attempt_id', 'claim_expires_at', 'claim_request_sha256', 'claim_token_sha256', 'claimed_at',
  'completion_receipt_hmac_sha256', 'completion_receipt_sha256', 'created_at', 'message', 'outbox_id',
  'provider', 'provider_message_id_sha256', 'recipient_identity_hmac_sha256', 'recipient_vault_hmac_sha256',
  'review_code', 'review_required_at', 'schema', 'sent_at', 'source_submission_data_sha256', 'status', 'submission_id',
  'verification_id_hmac_sha256',
]);
const MESSAGE_FIELDS = Object.freeze(['html', 'subject', 'template_id', 'text']);
const PENDING_FIELDS = Object.freeze(['outbox_id_sha256', 'outbox_key', 'schema']);

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
const safeEqual = (left, right) => {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
};
const secret = (value, label) => {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 32 || Buffer.byteLength(value, 'utf8') > 256) {
    throw new TypeError(`${label} must be 32-256 UTF-8 bytes.`);
  }
  return value;
};
const iso = (value, label) => {
  if (typeof value !== 'string' || new Date(value).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return value;
};
const nullableIso = (value, label) => value === null ? null : iso(value, label);
const nullableSha = (value, label) => {
  if (value !== null && !SHA256_PATTERN.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
};

export function intakeConfirmationProtocolEnabled(env = process.env) {
  return env[INTAKE_CONFIRMATION_OUTBOX_ENABLED_ENV] === 'true' &&
    env[INTAKE_CONFIRMATION_CONSUMER_ENABLED_ENV] === 'true';
}

function exactOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Intake confirmation origin is invalid.'); }
  if (url.protocol !== 'https:' || url.hostname !== 'arcweb.onl' || url.username || url.password || url.port ||
      url.pathname !== '/' || url.search || url.hash) throw new TypeError('Intake confirmation origin is invalid.');
  return url.origin;
}

export function resolveIntakeConfirmationEnvironment(env = process.env) {
  const credentialNames = [
    INTAKE_CONFIRMATION_OUTBOX_SECRET_ENV,
    INTAKE_CONFIRMATION_CONSUMER_BEARER_ENV,
    INTAKE_CONFIRMATION_RECEIPT_SECRET_ENV,
  ];
  const origin = exactOrigin(env.URL);
  const outboxSecret = secret(env[INTAKE_CONFIRMATION_OUTBOX_SECRET_ENV], INTAKE_CONFIRMATION_OUTBOX_SECRET_ENV);
  const consumerBearer = secret(env[INTAKE_CONFIRMATION_CONSUMER_BEARER_ENV], INTAKE_CONFIRMATION_CONSUMER_BEARER_ENV);
  const receiptSecret = secret(env[INTAKE_CONFIRMATION_RECEIPT_SECRET_ENV], INTAKE_CONFIRMATION_RECEIPT_SECRET_ENV);
  if (!sensitiveCredentialsAreIsolated(env, credentialNames)) {
    throw new TypeError('Intake confirmation secrets must be distinct.');
  }
  return { origin, outboxSecret, consumerBearer, receiptSecret };
}

export function intakeConfirmationRuntimeConfigured(env = process.env) {
  if (!intakeConfirmationProtocolEnabled(env)) return false;
  try { resolveIntakeConfirmationEnvironment(env); return true; } catch { return false; }
}

function outboxId(record) {
  // This identifier is a routing identity, not authority. Keeping it
  // deterministic lets the signed ARC1 consumer derive it from the immutable
  // bridge evidence; every read and mutation still requires the private HMAC
  // key, bearer, and exact store key below.
  return `arcconfirm_${sha256(
    `arc-intake-confirmation-outbox-id-v1\n${record.submission_id}\n${record.submission_data_sha256}`,
  ).slice(0, 40)}`;
}

function outboxKey(id, resolved) {
  return `outbox/${hmac(resolved.outboxSecret, `arc-intake-confirmation-outbox-key-v1\n${id}`)}`;
}

function pendingKey(id, resolved) {
  return `pending/${hmac(resolved.outboxSecret, `arc-intake-confirmation-pending-key-v1\n${id}`)}`;
}

function claimToken(record, attemptId, claimedAt, resolved) {
  return hmac(resolved.outboxSecret,
    `arc-intake-confirmation-claim-token-v1\n${record.outbox_id}\n${attemptId}\n${claimedAt}`);
}

function confirmationMessage() {
  return {
    template_id: 'arc-intake-confirmation-v1',
    subject: 'Confirm your email to start your free preview',
    text: 'Confirm your email to start your free website preview. We will email the preview when it is ready. No payment is due unless you approve it.',
    html: '<p>Confirm your email to start your free website preview.</p><p>We will email the preview when it is ready.</p><p><strong>No payment is due unless you approve it.</strong></p>',
  };
}

export function validateIntakeConfirmationOutbox(value) {
  if (!exactKeys(value, OUTBOX_FIELDS) || value.schema !== INTAKE_CONFIRMATION_OUTBOX_SCHEMA ||
      !OUTBOX_ID_PATTERN.test(value.outbox_id) || !UUID_PATTERN.test(value.submission_id) ||
      !SHA256_PATTERN.test(value.source_submission_data_sha256) ||
      !SHA256_PATTERN.test(value.recipient_identity_hmac_sha256) ||
      !SHA256_PATTERN.test(value.recipient_vault_hmac_sha256) ||
      !SHA256_PATTERN.test(value.verification_id_hmac_sha256) ||
      !['PENDING', 'CLAIMED', 'PROVIDER_ACCEPTED', 'REVIEW_REQUIRED'].includes(value.status) ||
      !exactKeys(value.message, MESSAGE_FIELDS) || value.message.template_id !== 'arc-intake-confirmation-v1' ||
      !['subject', 'text', 'html'].every((field) => typeof value.message[field] === 'string' &&
        value.message[field].length > 0 && Buffer.byteLength(value.message[field], 'utf8') <= 8_192)) {
    throw new TypeError('Intake confirmation outbox is invalid.');
  }
  iso(value.created_at, 'Intake confirmation created_at');
  for (const field of ['claimed_at', 'claim_expires_at', 'sent_at', 'review_required_at']) {
    nullableIso(value[field], `Intake confirmation ${field}`);
  }
  for (const field of ['claim_request_sha256', 'claim_token_sha256', 'completion_receipt_sha256',
    'completion_receipt_hmac_sha256', 'provider_message_id_sha256']) {
    nullableSha(value[field], `Intake confirmation ${field}`);
  }
  if (value.claim_attempt_id !== null && !ATTEMPT_ID_PATTERN.test(value.claim_attempt_id)) {
    throw new TypeError('Intake confirmation claim attempt is invalid.');
  }
  if (value.provider !== null && !PROVIDER_PATTERN.test(value.provider)) throw new TypeError('Intake confirmation provider is invalid.');
  if (![null, 'CLAIM_EXPIRED'].includes(value.review_code)) throw new TypeError('Intake confirmation review code is invalid.');
  const claimEmpty = value.claim_attempt_id === null && value.claim_request_sha256 === null &&
    value.claim_token_sha256 === null && value.claimed_at === null && value.claim_expires_at === null;
  const claimComplete = value.claim_attempt_id !== null && value.claim_request_sha256 !== null &&
    value.claim_token_sha256 !== null && value.claimed_at !== null && value.claim_expires_at !== null;
  const completionEmpty = value.completion_receipt_sha256 === null && value.completion_receipt_hmac_sha256 === null &&
    value.provider === null && value.provider_message_id_sha256 === null && value.sent_at === null;
  if (value.status === 'PENDING' && (!claimEmpty || !completionEmpty || value.review_code !== null || value.review_required_at !== null)) {
    throw new TypeError('Pending intake confirmation is inconsistent.');
  }
  if (value.status === 'CLAIMED' && (!claimComplete || !completionEmpty || value.review_code !== null || value.review_required_at !== null)) {
    throw new TypeError('Claimed intake confirmation is inconsistent.');
  }
  if (value.status === 'PROVIDER_ACCEPTED' && (!claimComplete || completionEmpty || !value.completion_receipt_sha256 ||
      !value.completion_receipt_hmac_sha256 || !value.provider || !value.provider_message_id_sha256 || !value.sent_at ||
      value.review_code !== null || value.review_required_at !== null)) {
    throw new TypeError('Accepted intake confirmation is incomplete.');
  }
  if (value.status === 'REVIEW_REQUIRED' && (!claimComplete || !completionEmpty || value.review_code !== 'CLAIM_EXPIRED' ||
      !value.review_required_at)) throw new TypeError('Intake confirmation review state is incomplete.');
  if (claimComplete && (Date.parse(value.claimed_at) < Date.parse(value.created_at) ||
      Date.parse(value.claim_expires_at) <= Date.parse(value.claimed_at))) {
    throw new TypeError('Intake confirmation claim timing is invalid.');
  }
  if (value.sent_at && (Date.parse(value.sent_at) < Date.parse(value.claimed_at) ||
      Date.parse(value.sent_at) > Date.parse(value.claim_expires_at))) {
    throw new TypeError('Intake confirmation provider acceptance is outside its lease.');
  }
  return value;
}

function initialOutbox(record, id, now, verification, recipientVaultHmac) {
  return {
    schema: INTAKE_CONFIRMATION_OUTBOX_SCHEMA,
    outbox_id: id,
    submission_id: record.submission_id,
    source_submission_data_sha256: record.submission_data_sha256,
    recipient_identity_hmac_sha256: verification.recipient_identity_hmac_sha256,
    recipient_vault_hmac_sha256: recipientVaultHmac,
    verification_id_hmac_sha256: verification.verification_id_hmac_sha256,
    message: confirmationMessage(),
    created_at: now.toISOString(),
    status: 'PENDING',
    claim_attempt_id: null,
    claim_request_sha256: null,
    claim_token_sha256: null,
    claimed_at: null,
    claim_expires_at: null,
    completion_receipt_sha256: null,
    completion_receipt_hmac_sha256: null,
    provider: null,
    provider_message_id_sha256: null,
    sent_at: null,
    review_code: null,
    review_required_at: null,
  };
}

async function readOutbox(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  return entry ? { value: validateIntakeConfirmationOutbox(entry.data), etag: entry.etag } : null;
}

async function replaceOutbox(store, key, entry, value) {
  validateIntakeConfirmationOutbox(value);
  const result = await store.setJSON(key, value, { onlyIfMatch: entry.etag });
  if (!result?.modified || typeof result.etag !== 'string' || result.etag.length === 0) {
    throw new Error('ARC_INTAKE_CONFIRMATION_STATE_CONTENTION');
  }
  return { value, etag: result.etag };
}

async function ensurePendingIndex(store, record, resolved) {
  const key = pendingKey(record.outbox_id, resolved);
  const expected = {
    schema: INTAKE_CONFIRMATION_PENDING_INDEX_SCHEMA,
    outbox_id_sha256: sha256(record.outbox_id),
    outbox_key: outboxKey(record.outbox_id, resolved),
  };
  let existing = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!existing) {
    try { await store.setJSON(key, expected, { onlyIfNew: true }); } catch {}
    existing = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  }
  if (!existing || !exactKeys(existing.data, PENDING_FIELDS) || canonicalJson(existing.data) !== canonicalJson(expected)) {
    throw new Error('ARC_INTAKE_CONFIRMATION_PENDING_INDEX_CONFLICT');
  }
}

async function removePendingIndex(store, id, resolved) {
  if (typeof store.delete === 'function') await store.delete(pendingKey(id, resolved));
}

export async function reserveIntakeConfirmationOutbox(sourceRecord, env, store, adapters = {}) {
  assertPublicIntakeAuthority(env);
  if (!intakeConfirmationProtocolEnabled(env)) throw new Error('ARC_INTAKE_CONFIRMATION_DISABLED');
  if (!sourceRecord || sourceRecord.schema !== INTAKE_SUBMISSION_SCHEMA || !UUID_PATTERN.test(sourceRecord.submission_id) ||
      !SHA256_PATTERN.test(sourceRecord.submission_data_sha256) || !EMAIL_PATTERN.test(sourceRecord.data?.email || '')) {
    throw new TypeError('Intake confirmation source record is invalid.');
  }
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Intake confirmation clock is invalid.');
  const resolved = resolveIntakeConfirmationEnvironment(env);
  const id = outboxId(sourceRecord);
  const key = outboxKey(id, resolved);
  const verification = adapters.verification;
  let verificationUrl;
  try { verificationUrl = new URL(verification?.verification_url); } catch {
    throw new TypeError('Intake confirmation verification binding is invalid.');
  }
  if (!adapters.vaultStore || verificationUrl.origin !== resolved.origin || verificationUrl.pathname !== '/verify/' ||
      verificationUrl.search || !/^#arcv1\.[A-Za-z0-9_-]{43}$/.test(verificationUrl.hash) ||
      !SHA256_PATTERN.test(verification?.verification_id_hmac_sha256 || '') ||
      !SHA256_PATTERN.test(verification?.recipient_identity_hmac_sha256 || '') ||
      typeof verification?.expires_at !== 'string' || Date.parse(verification.expires_at) <= now.getTime()) {
    throw new TypeError('Intake confirmation verification binding is invalid.');
  }
  const sealed = await sealEmailRecipientCapsule(adapters.vaultStore, {
    job_kind: 'intake_confirmation',
    job_key: id,
    recipient_email: sourceRecord.data.email.trim().toLowerCase(),
    private_payload: {
      schema: 'arc-intake-confirmation-private-v1',
      verification_url: verificationUrl.toString(),
      verification_id_hmac_sha256: verification.verification_id_hmac_sha256,
      source_submission_data_sha256: sourceRecord.submission_data_sha256,
    },
    expires_at: verification.expires_at,
  }, env, { clock: adapters.clock, randomBytes: adapters.randomBytes });
  const expected = initialOutbox(sourceRecord, id, now, verification, sealed.vault_hmac_sha256);
  validateIntakeConfirmationOutbox(expected);
  let entry = await readOutbox(store, key);
  let created = false;
  if (!entry) {
    try {
      const result = await store.setJSON(key, expected, { onlyIfNew: true });
      created = result?.modified === true;
    } catch {}
    entry = await readOutbox(store, key);
  }
  if (!entry || entry.value.outbox_id !== id || entry.value.submission_id !== sourceRecord.submission_id ||
      entry.value.source_submission_data_sha256 !== sourceRecord.submission_data_sha256 ||
      entry.value.recipient_identity_hmac_sha256 !== verification.recipient_identity_hmac_sha256 ||
      entry.value.recipient_vault_hmac_sha256 !== sealed.vault_hmac_sha256 ||
      entry.value.verification_id_hmac_sha256 !== verification.verification_id_hmac_sha256 ||
      canonicalJson(entry.value.message) !== canonicalJson(expected.message)) {
    throw new Error('ARC_INTAKE_CONFIRMATION_OUTBOX_CONFLICT');
  }
  if (['PENDING', 'CLAIMED'].includes(entry.value.status)) await ensurePendingIndex(store, entry.value, resolved);
  else await removePendingIndex(store, entry.value.outbox_id, resolved);
  return { outboxId: id, created, state: entry.value.status };
}

function parseCanonical(raw, schema, fields) {
  let value;
  try { value = JSON.parse(raw); } catch { throw new TypeError('Intake confirmation request is invalid JSON.'); }
  if (canonicalJson(value) !== raw || !exactKeys(value, fields) || value.schema !== schema) {
    throw new TypeError('Intake confirmation request is invalid.');
  }
  return value;
}

function authorize(request, resolved) {
  const supplied = request.headers.get('authorization') || '';
  return supplied.startsWith('Bearer ') && safeEqual(supplied.slice(7), resolved.consumerBearer);
}

export function authorizeIntakeConfirmationConsumer(request, env = process.env) {
  try { return authorize(request, resolveIntakeConfirmationEnvironment(env)); } catch { return false; }
}

function claimResponse(record, token, replay, resolved) {
  return {
    schema: INTAKE_CONFIRMATION_CLAIM_RESPONSE_SCHEMA,
    status: 'CLAIMED',
    outbox_id: record.outbox_id,
    submission_id: record.submission_id,
    consumer_attempt_id: record.claim_attempt_id,
    claim_token: token,
    claimed_at: record.claimed_at,
    claim_expires_at: record.claim_expires_at,
    provider_idempotency_key: record.outbox_id,
    recipient_identity_hmac_sha256: record.recipient_identity_hmac_sha256,
    recipient_vault_hmac_sha256: record.recipient_vault_hmac_sha256,
    verification_id_hmac_sha256: record.verification_id_hmac_sha256,
    source_submission_data_sha256: record.source_submission_data_sha256,
    message: record.message,
    completion_endpoint: `${resolved.origin}${INTAKE_CONFIRMATION_COMPLETION_ENDPOINT_PATH}`,
    idempotent_replay: replay,
  };
}

export async function claimNextIntakeConfirmationOutbox(env, store, adapters = {}) {
  assertPublicIntakeAuthority(env);
  if (!intakeConfirmationProtocolEnabled(env)) throw new Error('ARC_INTAKE_CONFIRMATION_DISABLED');
  if (typeof store?.list !== 'function') throw new Error('ARC_INTAKE_CONFIRMATION_LIST_UNAVAILABLE');
  const resolved = resolveIntakeConfirmationEnvironment(env);
  const listed = await store.list({ prefix: 'pending/' });
  if (!listed || !Array.isArray(listed.blobs)) throw new Error('ARC_INTAKE_CONFIRMATION_LIST_UNAVAILABLE');
  const keys = listed.blobs.map((blob) => blob?.key).filter((key) => typeof key === 'string' && key.startsWith('pending/'))
    .sort().slice(0, INTAKE_CONFIRMATION_PENDING_SCAN_LIMIT);
  for (const pendingIndexKey of keys) {
    const pendingEntry = await store.getWithMetadata(pendingIndexKey, { type: 'json', consistency: 'strong' });
    if (!pendingEntry) continue;
    const pending = pendingEntry.data;
    if (!exactKeys(pending, PENDING_FIELDS) || pending.schema !== INTAKE_CONFIRMATION_PENDING_INDEX_SCHEMA ||
        !SHA256_PATTERN.test(pending.outbox_id_sha256) || typeof pending.outbox_key !== 'string' ||
        !pending.outbox_key.startsWith('outbox/')) {
      throw new Error('ARC_INTAKE_CONFIRMATION_PENDING_INDEX_CONFLICT');
    }
    const outboxEntry = await readOutbox(store, pending.outbox_key);
    if (!outboxEntry || sha256(outboxEntry.value.outbox_id) !== pending.outbox_id_sha256 ||
        pending.outbox_key !== outboxKey(outboxEntry.value.outbox_id, resolved) ||
        pendingIndexKey !== pendingKey(outboxEntry.value.outbox_id, resolved)) {
      throw new Error('ARC_INTAKE_CONFIRMATION_PENDING_INDEX_CONFLICT');
    }
    const record = outboxEntry.value;
    if (!['PENDING', 'CLAIMED'].includes(record.status)) {
      await removePendingIndex(store, record.outbox_id, resolved);
      continue;
    }
    const suppliedAttempt = typeof adapters.consumerAttemptId === 'function'
      ? adapters.consumerAttemptId(record) : adapters.consumerAttemptId;
    const consumerAttemptId = record.status === 'CLAIMED' ? record.claim_attempt_id : suppliedAttempt;
    if (!ATTEMPT_ID_PATTERN.test(consumerAttemptId || '')) {
      throw new TypeError('Intake confirmation consumer attempt is invalid.');
    }
    const raw = canonicalJson({
      schema: INTAKE_CONFIRMATION_CLAIM_REQUEST_SCHEMA,
      submission_id: record.submission_id,
      outbox_id: record.outbox_id,
      consumer_attempt_id: consumerAttemptId,
    });
    const requestSha = sha256(raw);
    const request = new Request(`${resolved.origin}${INTAKE_CONFIRMATION_CLAIM_ENDPOINT_PATH}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${resolved.consumerBearer}`,
        'content-type': 'application/json',
        'idempotency-key': `arcconfirmclaim_${requestSha.slice(0, 40)}`,
      },
      body: raw,
    });
    try {
      return { found: true, ...(await claimIntakeConfirmationOutbox(raw, request, env, store, adapters)) };
    } catch (error) {
      if (error?.message === 'ARC_INTAKE_CONFIRMATION_REVIEW_REQUIRED' ||
          error?.message === 'ARC_INTAKE_CONFIRMATION_TERMINAL') continue;
      throw error;
    }
  }
  return { found: false };
}

export async function claimIntakeConfirmationOutbox(raw, request, env, store, adapters = {}) {
  assertPublicIntakeAuthority(env);
  if (!intakeConfirmationProtocolEnabled(env)) throw new Error('ARC_INTAKE_CONFIRMATION_DISABLED');
  const resolved = resolveIntakeConfirmationEnvironment(env);
  if (!authorize(request, resolved)) throw new Error('ARC_INTAKE_CONFIRMATION_UNAUTHORIZED');
  if (new URL(request.url).toString() !== `${resolved.origin}${INTAKE_CONFIRMATION_CLAIM_ENDPOINT_PATH}`) {
    throw new TypeError('Intake confirmation claim endpoint mismatch.');
  }
  const input = parseCanonical(raw, INTAKE_CONFIRMATION_CLAIM_REQUEST_SCHEMA,
    ['consumer_attempt_id', 'outbox_id', 'schema', 'submission_id']);
  if (!UUID_PATTERN.test(input.submission_id) || !OUTBOX_ID_PATTERN.test(input.outbox_id) ||
      !ATTEMPT_ID_PATTERN.test(input.consumer_attempt_id)) {
    throw new TypeError('Intake confirmation claim identity is invalid.');
  }
  const requestSha = sha256(raw);
  if (request.headers.get('idempotency-key') !== `arcconfirmclaim_${requestSha.slice(0, 40)}`) {
    throw new TypeError('Intake confirmation claim idempotency key mismatch.');
  }
  const key = outboxKey(input.outbox_id, resolved);
  let entry = await readOutbox(store, key);
  if (!entry || entry.value.submission_id !== input.submission_id) throw new Error('ARC_INTAKE_CONFIRMATION_NOT_FOUND');
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const record = entry.value;
    const now = new Date((adapters.clock || (() => new Date()))());
    if (!Number.isFinite(now.getTime())) throw new TypeError('Intake confirmation clock is invalid.');
    if (record.status === 'PROVIDER_ACCEPTED') {
      await removePendingIndex(store, record.outbox_id, resolved);
      throw new Error('ARC_INTAKE_CONFIRMATION_TERMINAL');
    }
    if (record.status === 'REVIEW_REQUIRED') {
      await removePendingIndex(store, record.outbox_id, resolved);
      throw new Error('ARC_INTAKE_CONFIRMATION_REVIEW_REQUIRED');
    }
    if (record.status === 'CLAIMED') {
      if (Date.parse(record.claim_expires_at) <= now.getTime()) {
        const reviewed = { ...record, status: 'REVIEW_REQUIRED', review_code: 'CLAIM_EXPIRED', review_required_at: now.toISOString() };
        try { entry = await replaceOutbox(store, key, entry, reviewed); await removePendingIndex(store, record.outbox_id, resolved); }
        catch (error) { if (error?.message === 'ARC_INTAKE_CONFIRMATION_STATE_CONTENTION' && attempt < 3) { entry = await readOutbox(store, key); continue; } throw error; }
        throw new Error('ARC_INTAKE_CONFIRMATION_REVIEW_REQUIRED');
      }
      if (record.claim_attempt_id !== input.consumer_attempt_id || !safeEqual(record.claim_request_sha256, requestSha)) {
        throw new Error('ARC_INTAKE_CONFIRMATION_CLAIM_CONFLICT');
      }
      return claimResponse(record, claimToken(record, record.claim_attempt_id, record.claimed_at, resolved), true, resolved);
    }
    const claimedAt = now.toISOString();
    const token = claimToken(record, input.consumer_attempt_id, claimedAt, resolved);
    const claimed = {
      ...record,
      status: 'CLAIMED',
      claim_attempt_id: input.consumer_attempt_id,
      claim_request_sha256: requestSha,
      claim_token_sha256: sha256(token),
      claimed_at: claimedAt,
      claim_expires_at: new Date(now.getTime() + INTAKE_CONFIRMATION_CLAIM_LEASE_MS).toISOString(),
    };
    try { entry = await replaceOutbox(store, key, entry, claimed); return claimResponse(entry.value, token, false, resolved); }
    catch (error) { if (error?.message !== 'ARC_INTAKE_CONFIRMATION_STATE_CONTENTION' || attempt === 3) throw error; entry = await readOutbox(store, key); }
  }
  throw new Error('ARC_INTAKE_CONFIRMATION_STATE_CONTENTION');
}

function completionResponse(record, replay) {
  return {
    schema: INTAKE_CONFIRMATION_COMPLETION_RESPONSE_SCHEMA,
    status: record.status,
    outbox_id: record.outbox_id,
    submission_id: record.submission_id,
    provider: record.provider,
    sent_at: record.sent_at,
    idempotent_replay: replay,
  };
}

export async function completeIntakeConfirmationOutbox(raw, request, env, store, adapters = {}) {
  assertPublicIntakeAuthority(env);
  if (!intakeConfirmationProtocolEnabled(env)) throw new Error('ARC_INTAKE_CONFIRMATION_DISABLED');
  const resolved = resolveIntakeConfirmationEnvironment(env);
  if (!authorize(request, resolved)) throw new Error('ARC_INTAKE_CONFIRMATION_UNAUTHORIZED');
  if (new URL(request.url).toString() !== `${resolved.origin}${INTAKE_CONFIRMATION_COMPLETION_ENDPOINT_PATH}`) {
    throw new TypeError('Intake confirmation completion endpoint mismatch.');
  }
  const input = parseCanonical(raw, INTAKE_CONFIRMATION_COMPLETION_REQUEST_SCHEMA,
    ['claim_token', 'consumer_attempt_id', 'outbox_id', 'provider', 'provider_message_id', 'schema', 'sent_at', 'submission_id']);
  if (!UUID_PATTERN.test(input.submission_id) || !OUTBOX_ID_PATTERN.test(input.outbox_id) ||
      !ATTEMPT_ID_PATTERN.test(input.consumer_attempt_id) || !SHA256_PATTERN.test(input.claim_token) ||
      !PROVIDER_PATTERN.test(input.provider) || typeof input.provider_message_id !== 'string' ||
      input.provider_message_id.length < 1 || input.provider_message_id.length > 256 || CONTROL_PATTERN.test(input.provider_message_id)) {
    throw new TypeError('Intake confirmation completion is invalid.');
  }
  iso(input.sent_at, 'Intake confirmation sent_at');
  const receiptSha = sha256(raw);
  if (request.headers.get('idempotency-key') !== `arcconfirmcomplete_${receiptSha.slice(0, 40)}`) {
    throw new TypeError('Intake confirmation completion idempotency key mismatch.');
  }
  const suppliedHmac = request.headers.get('x-arc-intake-confirmation-receipt-hmac-sha256') || '';
  const expectedHmac = hmac(resolved.receiptSecret, `arc-intake-confirmation-completion-v1\n${raw}`);
  if (!SHA256_PATTERN.test(suppliedHmac) || !safeEqual(suppliedHmac, expectedHmac)) {
    throw new Error('ARC_INTAKE_CONFIRMATION_COMPLETION_UNAUTHORIZED');
  }
  const key = outboxKey(input.outbox_id, resolved);
  let entry = await readOutbox(store, key);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    if (!entry || entry.value.submission_id !== input.submission_id) throw new Error('ARC_INTAKE_CONFIRMATION_NOT_FOUND');
    const record = entry.value;
    if (record.status === 'PROVIDER_ACCEPTED') {
      if (!safeEqual(record.completion_receipt_sha256, receiptSha) ||
          !safeEqual(record.completion_receipt_hmac_sha256, suppliedHmac)) {
        throw new Error('ARC_INTAKE_CONFIRMATION_COMPLETION_CONFLICT');
      }
      await removePendingIndex(store, record.outbox_id, resolved);
      return completionResponse(record, true);
    }
    if (record.status !== 'CLAIMED') throw new Error('ARC_INTAKE_CONFIRMATION_NOT_READY');
    if (record.claim_attempt_id !== input.consumer_attempt_id ||
        !safeEqual(record.claim_token_sha256, sha256(input.claim_token))) {
      throw new Error('ARC_INTAKE_CONFIRMATION_COMPLETION_CONFLICT');
    }
    const now = new Date((adapters.clock || (() => new Date()))());
    const sentMs = Date.parse(input.sent_at);
    if (!Number.isFinite(now.getTime()) || sentMs < Date.parse(record.claimed_at) || sentMs > now.getTime() + 5 * 60_000) {
      throw new TypeError('Intake confirmation sent_at is invalid.');
    }
    if (Date.parse(record.claim_expires_at) <= now.getTime() || sentMs > Date.parse(record.claim_expires_at)) {
      throw new Error('ARC_INTAKE_CONFIRMATION_REVIEW_REQUIRED');
    }
    const accepted = {
      ...record,
      status: 'PROVIDER_ACCEPTED',
      completion_receipt_sha256: receiptSha,
      completion_receipt_hmac_sha256: suppliedHmac,
      provider: input.provider,
      provider_message_id_sha256: sha256(input.provider_message_id),
      sent_at: input.sent_at,
    };
    try {
      entry = await replaceOutbox(store, key, entry, accepted);
      await removePendingIndex(store, record.outbox_id, resolved);
      return completionResponse(entry.value, false);
    } catch (error) {
      if (error?.message !== 'ARC_INTAKE_CONFIRMATION_STATE_CONTENTION' || attempt === 3) throw error;
      entry = await readOutbox(store, key);
    }
  }
  throw new Error('ARC_INTAKE_CONFIRMATION_STATE_CONTENTION');
}
