import { createHash } from 'node:crypto';

import {
  openEmailRecipientCapsule,
  sealEmailRecipientCapsule,
} from './email-recipient-vault-core.mjs';
import { TRANSACTIONAL_EMAIL_KINDS } from './transactional-email-template-core.mjs';

export const TRANSACTIONAL_EMAIL_ATTEMPT_CONTEXT_SCHEMA = 'arc-email-attempt-context-v1';

const HEX_64 = /^[a-f0-9]{64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const FIELDS = Object.freeze([
  'attempt_hmac_sha256', 'context', 'job_key_sha256', 'job_kind', 'schema', 'version',
]);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError('Email attempt context is invalid.');
    }
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const result = JSON.stringify(value);
  if (result === undefined) throw new TypeError('Email attempt context is invalid.');
  return result;
}

function exactKeys(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}

function normalized(input) {
  if (!exactKeys(input, [
    'attempt_hmac_sha256', 'context', 'expires_at', 'job_key', 'job_kind', 'recipient_email',
  ]) || !TRANSACTIONAL_EMAIL_KINDS.includes(input.job_kind) ||
      !HEX_64.test(String(input.attempt_hmac_sha256 || '')) ||
      typeof input.job_key !== 'string' || input.job_key.length < 8 ||
      Buffer.byteLength(input.job_key, 'utf8') > 256 || CONTROL.test(input.job_key) ||
      !input.context || typeof input.context !== 'object' || Array.isArray(input.context) ||
      Object.getPrototypeOf(input.context) !== Object.prototype) {
    throw new TypeError('Email attempt context input is invalid.');
  }
  canonicalJson(input.context);
  return input;
}

function capsuleJobKey(attemptHmac) {
  if (!HEX_64.test(String(attemptHmac || ''))) throw new TypeError('Email attempt context is invalid.');
  return `attempt-context:${attemptHmac}`;
}

function validatePayload(value, kind, attemptHmac) {
  if (!exactKeys(value, FIELDS) || value.schema !== TRANSACTIONAL_EMAIL_ATTEMPT_CONTEXT_SCHEMA ||
      value.version !== 1 || value.job_kind !== kind || value.attempt_hmac_sha256 !== attemptHmac ||
      !HEX_64.test(String(value.job_key_sha256 || '')) || !value.context ||
      typeof value.context !== 'object' || Array.isArray(value.context) ||
      Object.getPrototypeOf(value.context) !== Object.prototype) {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_ATTEMPT_CONTEXT_INVALID');
  }
  canonicalJson(value.context);
  return value;
}

export async function sealTransactionalEmailAttemptContext(vaultStore, input,
  env = process.env, adapters = {}) {
  const value = normalized(input);
  const payload = {
    schema: TRANSACTIONAL_EMAIL_ATTEMPT_CONTEXT_SCHEMA,
    version: 1,
    attempt_hmac_sha256: value.attempt_hmac_sha256,
    job_kind: value.job_kind,
    job_key_sha256: sha256(value.job_key),
    context: structuredClone(value.context),
  };
  await sealEmailRecipientCapsule(vaultStore, {
    job_kind: value.job_kind,
    job_key: capsuleJobKey(value.attempt_hmac_sha256),
    recipient_email: value.recipient_email,
    private_payload: payload,
    expires_at: value.expires_at,
  }, env, adapters);
  const opened = await openEmailRecipientCapsule(vaultStore, {
    job_kind: value.job_kind,
    job_key: capsuleJobKey(value.attempt_hmac_sha256),
  }, env, { clock: adapters.clock });
  const stored = validatePayload(opened.private_payload, value.job_kind, value.attempt_hmac_sha256);
  if (opened.recipient_email !== value.recipient_email || opened.expires_at !== value.expires_at ||
      canonicalJson(stored) !== canonicalJson(payload)) {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_ATTEMPT_CONTEXT_INVALID');
  }
  return Object.freeze({
    recipient_email: opened.recipient_email,
    expires_at: opened.expires_at,
    ...structuredClone(stored),
  });
}

export async function openTransactionalEmailAttemptContext(vaultStore, input,
  env = process.env, adapters = {}) {
  if (!exactKeys(input, ['attempt_hmac_sha256', 'job_kind']) ||
      !TRANSACTIONAL_EMAIL_KINDS.includes(input.job_kind) ||
      !HEX_64.test(String(input.attempt_hmac_sha256 || ''))) {
    throw new TypeError('Email attempt context lookup is invalid.');
  }
  const opened = await openEmailRecipientCapsule(vaultStore, {
    job_kind: input.job_kind,
    job_key: capsuleJobKey(input.attempt_hmac_sha256),
  }, env, { clock: adapters.clock });
  return Object.freeze({
    recipient_email: opened.recipient_email,
    expires_at: opened.expires_at,
    ...structuredClone(validatePayload(opened.private_payload, input.job_kind,
      input.attempt_hmac_sha256)),
  });
}
