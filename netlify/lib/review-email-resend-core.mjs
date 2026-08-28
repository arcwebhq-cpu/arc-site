import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import {
  emailSendAttemptConfiguration,
  markEmailProviderAccepted,
  reserveEmailSendAttempt,
} from './email-send-attempt-core.mjs';
import {
  deleteEmailRecipientCapsule,
  emailRecipientVaultConfiguration,
  openEmailRecipientCapsule,
  sealEmailRecipientCapsule,
} from './email-recipient-vault-core.mjs';
import {
  acknowledgeReviewEmailReceipt,
  claimNextReviewEmail,
  readReviewEmailOutbox,
  reserveReviewEmailSend,
  reviewEmailOutboxConfiguration,
  reviewEmailReceiptContract,
  reviewEmailRecipientSha256,
} from './review-email-outbox-core.mjs';
import { reviewInviteHmac } from './review-flow-core.mjs';
import {
  resendProviderConfiguration,
  sendResendTransactionalEmail,
} from './resend-transactional-provider-core.mjs';
import { renderTransactionalEmail } from './transactional-email-template-core.mjs';
import { sealTransactionalEmailAttemptContext } from './transactional-email-attempt-context-core.mjs';

export const REVIEW_EMAIL_RESEND_CAPSULE_ENABLED_ENV = 'ARC_REVIEW_EMAIL_RESEND_CAPSULE_ENABLED';
export const REVIEW_EMAIL_RESEND_WORKER_ENABLED_ENV = 'ARC_REVIEW_EMAIL_RESEND_WORKER_ENABLED';
export const RESEND_PROVIDER_ACCOUNT_ID_ENV = 'ARC_RESEND_PROVIDER_ACCOUNT_ID';
export const RESEND_PROVIDER_BINDING_HMAC_SECRET_ENV = 'ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET';
export const REVIEW_EMAIL_RESEND_BINDING_SCHEMA = 'arc-preview-review-email-resend-attempt-binding-v1';

const HEX_64 = /^[a-f0-9]{64}$/;
const TOKEN = /^[A-Za-z0-9_-]{43,128}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const PAID_RECIPIENT_CAPSULE_TTL_MS = 30 * 24 * 60 * 60_000;
const BINDING_FIELDS = Object.freeze([
  'attempt_hmac_sha256', 'created_at', 'invite_hmac_sha256', 'outbox_hmac_sha256',
  'preview_manifest_sha256', 'provider_account_hmac_sha256', 'recipient_email_sha256',
  'record_hmac_sha256', 'schema', 'version',
]);
const CAPSULE_FIELDS = Object.freeze([
  'invite_hmac_sha256', 'invite_token', 'outbox_hmac_sha256', 'preview_manifest_sha256',
  'recipient_email_sha256', 'review_url', 'template_version',
]);
const ACCEPTANCE_FIELDS = Object.freeze(['accepted_at', 'provider_message_id']);
const PROVIDER_STATUS = Object.freeze({
  'email.delivered': Object.freeze({ delivery_status: 'delivered', event_type: 'message.delivered' }),
  'email.bounced': Object.freeze({ delivery_status: 'bounced', event_type: 'message.bounced' }),
  'email.complained': Object.freeze({ delivery_status: 'complained', event_type: 'message.complained' }),
  'email.failed': Object.freeze({ delivery_status: 'bounced', event_type: 'message.bounced' }),
  // The provider's suppression event is a negative delivery outcome. The
  // review domain deliberately projects it onto its existing fail-closed
  // bounced category, which revokes the invite and every bound Checkout.
  'email.suppressed': Object.freeze({ delivery_status: 'bounced', event_type: 'message.bounced' }),
});

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError('Review Resend value is invalid.');
    }
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const result = JSON.stringify(value);
  if (result === undefined) throw new TypeError('Review Resend value is invalid.');
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
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new TypeError(`${label} is invalid.`);
  }
  return parsed;
}

function accountId(value) {
  if (typeof value !== 'string' || value.length < 3 || value.length > 128 ||
      value !== value.trim() || CONTROL.test(value)) {
    throw new TypeError(`${RESEND_PROVIDER_ACCOUNT_ID_ENV} is invalid.`);
  }
  return value;
}

function providerBindingSecret(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 32 ||
      Buffer.byteLength(value, 'utf8') > 256 || CONTROL.test(value)) {
    throw new TypeError(`${RESEND_PROVIDER_BINDING_HMAC_SECRET_ENV} is invalid.`);
  }
  return value;
}

function configuredOrigin(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.origin === value && !parsed.username && !parsed.password
      ? parsed.origin : null;
  } catch { return null; }
}

function recipient(value) {
  if (typeof value !== 'string') throw new TypeError('Review Resend recipient is invalid.');
  const normalized = value.trim().toLowerCase();
  if (normalized !== value || normalized.length < 3 || normalized.length > 254 || CONTROL.test(normalized) ||
      !/^[^@]+@[^@]+\.[^@]+$/.test(normalized)) {
    throw new TypeError('Review Resend recipient is invalid.');
  }
  return normalized;
}

function reviewUrl(origin, inviteToken) {
  const url = new URL('/review/', origin);
  url.hash = `invite=${inviteToken}`;
  return url.href;
}

function providerAccountHmac(env) {
  const id = accountId(env[RESEND_PROVIDER_ACCOUNT_ID_ENV]);
  return hmac(providerBindingSecret(env[RESEND_PROVIDER_BINDING_HMAC_SECRET_ENV]),
    `arc-resend-provider-account-binding-v1\n${id}`);
}

function secretsDistinct(env) {
  const requiredNames = [
    'ARC_REVIEW_INVITE_HMAC_SECRET',
    'ARC_REVIEW_SESSION_HMAC_SECRET',
    'ARC_REVIEW_RECORD_HMAC_SECRET',
    'ARC_REVIEW_DECISION_HMAC_SECRET',
    'ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET',
    'ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET',
    'ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET',
    'ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET',
    'ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY',
    RESEND_PROVIDER_BINDING_HMAC_SECRET_ENV,
  ];
  const required = requiredNames.map((name) => env[name]);
  if (required.some((value) => typeof value !== 'string' || value.length === 0)) return false;
  const optional = ['ARC_REVIEW_EMAIL_INTERNAL_API_SECRET', 'ARC_RESEND_WEBHOOK_SECRET']
    .map((name) => env[name]).filter((value) => typeof value === 'string' && value.length > 0);
  const values = [...required, ...optional];
  return new Set(values).size === values.length;
}

export function previewReviewCapsuleConfiguration(env = process.env) {
  const vault = emailRecipientVaultConfiguration(env);
  const outbox = reviewEmailOutboxConfiguration(env);
  return Object.freeze({
    enabled: env[REVIEW_EMAIL_RESEND_CAPSULE_ENABLED_ENV] === 'true' && vault.enabled && outbox.enabled &&
      Boolean(configuredOrigin(outbox.reviewOrigin)) && secretsDistinct(env),
    outbox,
    vault,
  });
}

export function previewReviewResendWorkerConfiguration(env = process.env) {
  const attempts = emailSendAttemptConfiguration(env);
  const capsule = previewReviewCapsuleConfiguration(env);
  const resend = resendProviderConfiguration(env);
  let providerAccount = null;
  let providerBinding = null;
  try { providerAccount = accountId(env[RESEND_PROVIDER_ACCOUNT_ID_ENV]); } catch {}
  try { providerBinding = providerBindingSecret(env[RESEND_PROVIDER_BINDING_HMAC_SECRET_ENV]); } catch {}
  return Object.freeze({
    enabled: env[REVIEW_EMAIL_RESEND_WORKER_ENABLED_ENV] === 'true' && attempts.enabled && capsule.enabled &&
      resend.send_enabled && resend.webhook_enabled && Boolean(providerAccount && providerBinding),
    attempts,
    capsule,
    providerAccount,
    resend,
  });
}

function requireCapsuleConfiguration(env) {
  const configuration = previewReviewCapsuleConfiguration(env);
  if (!configuration.enabled) throw new Error('ARC_REVIEW_EMAIL_RESEND_CAPSULE_DISABLED');
  return configuration;
}

function requireWorkerConfiguration(env) {
  const configuration = previewReviewResendWorkerConfiguration(env);
  if (!configuration.enabled) throw new Error('ARC_REVIEW_EMAIL_RESEND_WORKER_DISABLED');
  return configuration;
}

function normalizePreparedBinding(prepared) {
  if (!prepared || typeof prepared !== 'object' || !prepared.invite || !prepared.outbox ||
      ![prepared.invite.invite_hmac_sha256, prepared.outbox.outbox_hmac_sha256,
        prepared.invite.recipient_email_sha256, prepared.invite.preview_manifest_sha256]
        .every((value) => HEX_64.test(String(value || ''))) ||
      prepared.outbox.invite_hmac_sha256 !== prepared.invite.invite_hmac_sha256 ||
      prepared.outbox.recipient_email_sha256 !== prepared.invite.recipient_email_sha256 ||
      prepared.outbox.preview_manifest_sha256 !== prepared.invite.preview_manifest_sha256 ||
      prepared.outbox.expires_at !== prepared.invite.expires_at ||
      typeof prepared.outbox.template_version !== 'string') {
    throw new TypeError('Prepared review email binding is invalid.');
  }
  const createdAt = iso(prepared.outbox.created_at, 'Prepared review email created_at');
  const outboxExpiresAt = iso(prepared.outbox.expires_at, 'Prepared review email expires_at');
  if (outboxExpiresAt <= createdAt) throw new TypeError('Prepared review email binding is invalid.');
  return {
    invite_hmac_sha256: prepared.invite.invite_hmac_sha256,
    outbox_hmac_sha256: prepared.outbox.outbox_hmac_sha256,
    recipient_email_sha256: prepared.invite.recipient_email_sha256,
    preview_manifest_sha256: prepared.invite.preview_manifest_sha256,
    template_version: prepared.outbox.template_version,
    expires_at: prepared.outbox.expires_at,
    capsule_expires_at: new Date(createdAt + PAID_RECIPIENT_CAPSULE_TTL_MS).toISOString(),
  };
}

export async function sealPreviewReviewEmailCapsule(store, input, env = process.env, adapters = {}) {
  const configuration = requireCapsuleConfiguration(env);
  if (!exactKeys(input, ['invite_token', 'prepared', 'recipient_email'])) {
    throw new TypeError('Preview review capsule input is invalid.');
  }
  const binding = normalizePreparedBinding(input.prepared);
  const normalizedRecipient = recipient(input.recipient_email);
  if (!TOKEN.test(String(input.invite_token || '')) ||
      reviewInviteHmac(input.invite_token, env) !== binding.invite_hmac_sha256 ||
      reviewEmailRecipientSha256(normalizedRecipient) !== binding.recipient_email_sha256) {
    throw new Error('ARC_REVIEW_EMAIL_RESEND_CAPSULE_BINDING_INVALID');
  }
  const url = reviewUrl(configuration.outbox.reviewOrigin, input.invite_token);
  const privatePayload = {
    invite_token: input.invite_token,
    invite_hmac_sha256: binding.invite_hmac_sha256,
    outbox_hmac_sha256: binding.outbox_hmac_sha256,
    preview_manifest_sha256: binding.preview_manifest_sha256,
    recipient_email_sha256: binding.recipient_email_sha256,
    review_url: url,
    template_version: binding.template_version,
  };
  const result = await sealEmailRecipientCapsule(store, {
    job_kind: 'preview_review',
    job_key: binding.outbox_hmac_sha256,
    recipient_email: normalizedRecipient,
    private_payload: privatePayload,
    expires_at: binding.capsule_expires_at,
  }, env, adapters);
  return Object.freeze({ ...result, ...binding });
}

function validateOpenedCapsule(capsule, candidate, env) {
  const value = capsule.private_payload;
  if (!exactKeys(value, CAPSULE_FIELDS) || !TOKEN.test(String(value.invite_token || '')) ||
      ![value.invite_hmac_sha256, value.outbox_hmac_sha256, value.preview_manifest_sha256,
        value.recipient_email_sha256].every((entry) => HEX_64.test(String(entry || ''))) ||
      value.outbox_hmac_sha256 !== candidate.outbox_hmac_sha256 ||
      value.invite_hmac_sha256 !== candidate.invite_hmac_sha256 ||
      value.preview_manifest_sha256 !== candidate.preview_manifest_sha256 ||
      value.recipient_email_sha256 !== candidate.recipient_email_sha256 ||
      value.recipient_email_sha256 !== reviewEmailRecipientSha256(capsule.recipient_email) ||
      value.invite_hmac_sha256 !== reviewInviteHmac(value.invite_token, env) ||
      value.review_url !== reviewUrl(reviewEmailOutboxConfiguration(env).reviewOrigin, value.invite_token) ||
      typeof value.template_version !== 'string' || value.template_version.length < 1 ||
      value.template_version.length > 80) {
    throw new Error('ARC_REVIEW_EMAIL_RESEND_CAPSULE_BINDING_INVALID');
  }
  return Object.freeze({
    ...structuredClone(value),
    recipient_email: capsule.recipient_email,
    expires_at: capsule.expires_at,
  });
}

export async function openPreviewReviewEmailCapsule(store, candidate, env = process.env, adapters = {}) {
  requireCapsuleConfiguration(env);
  if (!candidate || ![candidate.outbox_hmac_sha256, candidate.invite_hmac_sha256,
    candidate.preview_manifest_sha256, candidate.recipient_email_sha256]
    .every((value) => HEX_64.test(String(value || '')))) {
    throw new TypeError('Preview review capsule binding is invalid.');
  }
  const capsule = await openEmailRecipientCapsule(store, {
    job_kind: 'preview_review', job_key: candidate.outbox_hmac_sha256,
  }, env, adapters);
  return validateOpenedCapsule(capsule, candidate, env);
}

export async function deletePreviewReviewEmailCapsules(vaultStore, outboxHmacSha256,
  env = process.env) {
  if (!HEX_64.test(String(outboxHmacSha256 || ''))) {
    throw new TypeError('Preview review capsule deletion binding is invalid.');
  }
  const primary = await deleteEmailRecipientCapsule(vaultStore, {
    job_kind: 'preview_review', job_key: outboxHmacSha256,
  }, env);
  const acceptance = await deleteEmailRecipientCapsule(vaultStore, {
    job_kind: 'preview_review', job_key: acceptanceJobKey(outboxHmacSha256),
  }, env);
  return Object.freeze({ deleted: Number(primary.deleted) + Number(acceptance.deleted) });
}

function acceptanceJobKey(outboxHmacSha256) {
  return `${outboxHmacSha256}:resend-acceptance-v1`;
}

async function persistAcceptanceCapsule(vaultStore, candidate, capsule, accepted, env, adapters) {
  await sealEmailRecipientCapsule(vaultStore, {
    job_kind: 'preview_review',
    job_key: acceptanceJobKey(candidate.outbox_hmac_sha256),
    recipient_email: capsule.recipient_email,
    private_payload: {
      accepted_at: accepted.accepted_at,
      provider_message_id: accepted.provider_message_id,
    },
    expires_at: candidate.expires_at,
  }, env, adapters);
}

async function recoverAcceptanceCapsule(vaultStore, candidate, capsule, env, adapters) {
  const acceptance = await openEmailRecipientCapsule(vaultStore, {
    job_kind: 'preview_review', job_key: acceptanceJobKey(candidate.outbox_hmac_sha256),
  }, env, adapters);
  const value = acceptance.private_payload;
  if (acceptance.recipient_email !== capsule.recipient_email || !exactKeys(value, ACCEPTANCE_FIELDS) ||
      !UUID.test(String(value.provider_message_id || ''))) {
    throw new Error('ARC_REVIEW_EMAIL_RESEND_ACCEPTANCE_CAPSULE_INVALID');
  }
  iso(value.accepted_at, 'Review Resend accepted_at');
  return Object.freeze({
    provider: 'resend',
    provider_message_id: value.provider_message_id.toLowerCase(),
    accepted_at: value.accepted_at,
  });
}

function unsignedBinding(record) {
  const { record_hmac_sha256: ignored, ...unsigned } = record;
  return unsigned;
}

function bindingKey(attemptHmacSha256) {
  if (!HEX_64.test(String(attemptHmacSha256 || ''))) throw new TypeError('Review Resend attempt is invalid.');
  return `review-email-resend-attempt/${attemptHmacSha256}`;
}

function signBinding(value, env) {
  const unsigned = unsignedBinding(value);
  return {
    ...unsigned,
    record_hmac_sha256: hmac(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
      `arc-preview-review-email-resend-attempt-binding-record-v1\n${canonicalJson(unsigned)}`),
  };
}

function validateBinding(record, env) {
  if (!exactKeys(record, BINDING_FIELDS) || record.schema !== REVIEW_EMAIL_RESEND_BINDING_SCHEMA ||
      record.version !== 1 || ![record.attempt_hmac_sha256, record.outbox_hmac_sha256,
        record.invite_hmac_sha256, record.recipient_email_sha256, record.preview_manifest_sha256,
        record.provider_account_hmac_sha256, record.record_hmac_sha256]
        .every((value) => HEX_64.test(String(value || ''))) ||
      record.provider_account_hmac_sha256 !== providerAccountHmac(env)) {
    throw new TypeError('Review Resend attempt binding is invalid.');
  }
  iso(record.created_at, 'Review Resend attempt binding created_at');
  const expected = hmac(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    `arc-preview-review-email-resend-attempt-binding-record-v1\n${canonicalJson(unsignedBinding(record))}`);
  if (!safeEqual(expected, record.record_hmac_sha256)) {
    throw new Error('ARC_REVIEW_EMAIL_RESEND_ATTEMPT_BINDING_SIGNATURE_INVALID');
  }
  return record;
}

async function ensureAttemptBinding(reviewStore, attemptHmacSha256, candidate, env, now) {
  const record = signBinding({
    schema: REVIEW_EMAIL_RESEND_BINDING_SCHEMA,
    version: 1,
    attempt_hmac_sha256: attemptHmacSha256,
    outbox_hmac_sha256: candidate.outbox_hmac_sha256,
    invite_hmac_sha256: candidate.invite_hmac_sha256,
    recipient_email_sha256: candidate.recipient_email_sha256,
    preview_manifest_sha256: candidate.preview_manifest_sha256,
    provider_account_hmac_sha256: providerAccountHmac(env),
    created_at: now.toISOString(),
  }, env);
  const key = bindingKey(attemptHmacSha256);
  try { await reviewStore.setJSON(key, record, { onlyIfNew: true }); } catch {}
  const entry = await reviewStore.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!entry) throw new Error('ARC_REVIEW_EMAIL_RESEND_ATTEMPT_BINDING_UNAVAILABLE');
  const stored = validateBinding(entry.data, env);
  const immutable = ['attempt_hmac_sha256', 'outbox_hmac_sha256', 'invite_hmac_sha256',
    'recipient_email_sha256', 'preview_manifest_sha256', 'provider_account_hmac_sha256'];
  if (!immutable.every((field) => stored[field] === record[field])) {
    throw new Error('ARC_REVIEW_EMAIL_RESEND_ATTEMPT_BINDING_CONFLICT');
  }
  return stored;
}

export async function readPreviewReviewResendAttemptBinding(reviewStore, attemptHmacSha256,
  env = process.env) {
  requireWorkerConfiguration(env);
  const entry = await reviewStore.getWithMetadata(bindingKey(attemptHmacSha256),
    { type: 'json', consistency: 'strong' });
  if (!entry) throw new Error('ARC_REVIEW_EMAIL_RESEND_ATTEMPT_BINDING_NOT_FOUND');
  return validateBinding(entry.data, env);
}

function outboundMessage(capsule) {
  const rendered = renderTransactionalEmail('preview_review', {
    recipient_email: capsule.recipient_email,
    review_url: capsule.review_url,
  });
  return Object.freeze({
    to: rendered.to,
    subject: rendered.subject,
    text: rendered.text,
    html: rendered.html,
    tags: [{ name: 'arc_kind', value: 'preview_review' }],
  });
}

export async function runPreviewReviewResendWorkerCycle(env, stores, adapters = {}) {
  const configuration = previewReviewResendWorkerConfiguration(env);
  if (!configuration.enabled) {
    return Object.freeze({ state: 'DISABLED', processed: 0, channel: 'preview_review' });
  }
  if (!stores?.review || !stores?.attempt || !stores?.vault) {
    throw new TypeError('Preview review Resend worker stores are invalid.');
  }
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Preview review Resend worker clock is invalid.');
  const candidate = await claimNextReviewEmail(stores.review, env, { clock: () => now });
  if (!candidate.found) return Object.freeze({ state: 'IDLE', processed: 0, channel: 'preview_review' });
  if (candidate.renewal_required || candidate.reconciliation_required && candidate.state !== 'SEND_RESERVED') {
    return Object.freeze({ state: 'REVIEW_REQUIRED', processed: 0, channel: 'preview_review' });
  }
  const capsule = await openPreviewReviewEmailCapsule(stores.vault, candidate, env, { clock: () => now });
  const authority = await reserveReviewEmailSend(stores.review, {
    invite_token: capsule.invite_token,
    recipient_email: capsule.recipient_email,
  }, env, { clock: () => now });
  if (authority.outbox_hmac_sha256 !== candidate.outbox_hmac_sha256 ||
      authority.review_url !== capsule.review_url ||
      authority.template_version !== capsule.template_version ||
      authority.recipient_email !== capsule.recipient_email) {
    throw new Error('ARC_REVIEW_EMAIL_RESEND_SEND_AUTHORITY_INVALID');
  }
  const message = outboundMessage(capsule);
  const reservation = await reserveEmailSendAttempt(stores.attempt, {
    job_kind: 'preview_review',
    job_key: candidate.outbox_hmac_sha256,
    provider_idempotency_key: authority.provider_idempotency_key,
    recipient_email_sha256: hmac(env.ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET,
      `arc-preview-review-email-attempt-recipient-v1\n${capsule.recipient_email}`),
    sender_sha256: sha256(configuration.resend.from),
    message_sha256: sha256(canonicalJson(message)),
  }, env, { clock: () => now });
  const attemptBinding = await ensureAttemptBinding(stores.review,
    reservation.attempt_hmac_sha256, candidate, env, now);
  await sealTransactionalEmailAttemptContext(stores.vault, {
    job_kind: 'preview_review',
    job_key: candidate.outbox_hmac_sha256,
    attempt_hmac_sha256: reservation.attempt_hmac_sha256,
    recipient_email: capsule.recipient_email,
    context: {
      invite_hmac_sha256: attemptBinding.invite_hmac_sha256,
      outbox_hmac_sha256: attemptBinding.outbox_hmac_sha256,
      preview_manifest_sha256: attemptBinding.preview_manifest_sha256,
      provider_account_hmac_sha256: attemptBinding.provider_account_hmac_sha256,
      recipient_email_sha256: attemptBinding.recipient_email_sha256,
    },
    expires_at: candidate.expires_at,
  }, env, { clock: () => now, randomBytes: adapters.randomBytes });
  if (reservation.decision === 'REVIEW_REQUIRED') {
    return Object.freeze({ state: 'REVIEW_REQUIRED', processed: 0, channel: 'preview_review' });
  }
  let accepted;
  let recoveredAcceptance = reservation.decision === 'DO_NOT_SEND';
  if (reservation.decision === 'DO_NOT_SEND') {
    accepted = await recoverAcceptanceCapsule(stores.vault, candidate, capsule, env, { clock: () => now });
  } else {
    try {
      accepted = await recoverAcceptanceCapsule(stores.vault, candidate, capsule, env, { clock: () => now });
      recoveredAcceptance = true;
    } catch (error) {
      if (error?.message !== 'ARC_EMAIL_VAULT_NOT_FOUND') throw error;
      accepted = await sendResendTransactionalEmail(message, authority.provider_idempotency_key, env, {
        fetch: adapters.fetch, clock: () => now,
      });
      await persistAcceptanceCapsule(stores.vault, candidate, capsule, accepted, env, {
        clock: () => now, randomBytes: adapters.randomBytes,
      });
    }
    await markEmailProviderAccepted(stores.attempt, {
      attempt_hmac_sha256: reservation.attempt_hmac_sha256,
      provider_message_id: accepted.provider_message_id,
    }, env, { clock: () => now });
  }
  return Object.freeze({
    state: 'PROVIDER_ACCEPTED',
    processed: 1,
    channel: 'preview_review',
    idempotent_replay: recoveredAcceptance,
  });
}

function receiptForVerifiedEvent(binding, verified, env, now) {
  const mapped = PROVIDER_STATUS[verified.event_type];
  if (!mapped) throw new Error('ARC_REVIEW_EMAIL_RESEND_EVENT_UNSUPPORTED');
  const stamp = now.toISOString();
  const value = {
    schema: reviewEmailReceiptContract.schema,
    version: reviewEmailReceiptContract.version,
    outbox_hmac_sha256: binding.outbox_hmac_sha256,
    invite_hmac_sha256: binding.invite_hmac_sha256,
    recipient_email_sha256: binding.recipient_email_sha256,
    preview_manifest_sha256: binding.preview_manifest_sha256,
    provider: 'resend',
    provider_account_hmac_sha256: binding.provider_account_hmac_sha256,
    provider_event_id: verified.provider_event_id,
    provider_message_id: verified.provider_message_id,
    event_type: mapped.event_type,
    delivery_status: mapped.delivery_status,
    // The review receipt records the time ARC authenticated and observed the
    // provider event. Resend's native timestamp remains bound in the signed
    // provider-event ledger and payload digest.
    event_at: stamp,
    issued_at: stamp,
  };
  const evidence = canonicalJson(value);
  return {
    evidence,
    signature: hmac(env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET,
      reviewEmailReceiptContract.signaturePrefix + evidence),
  };
}

export async function acknowledgePreviewReviewResendEvent(reviewStore, input, env = process.env, adapters = {}) {
  requireWorkerConfiguration(env);
  if (!input || !HEX_64.test(String(input.attempt_hmac_sha256 || '')) ||
      !Object.hasOwn(PROVIDER_STATUS, input.event_type) || input.provider !== 'resend' ||
      typeof input.provider_event_id !== 'string' || typeof input.provider_message_id !== 'string') {
    throw new TypeError('Preview review Resend event is invalid.');
  }
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Preview review Resend event clock is invalid.');
  const binding = await readPreviewReviewResendAttemptBinding(reviewStore,
    input.attempt_hmac_sha256, env);
  const outbox = await readReviewEmailOutbox(reviewStore, binding.outbox_hmac_sha256, env);
  if (outbox.record.invite_hmac_sha256 !== binding.invite_hmac_sha256 ||
      outbox.record.recipient_email_sha256 !== binding.recipient_email_sha256 ||
      outbox.record.preview_manifest_sha256 !== binding.preview_manifest_sha256) {
    throw new Error('ARC_REVIEW_EMAIL_RESEND_ATTEMPT_BINDING_INVALID');
  }
  const receipt = receiptForVerifiedEvent(binding, input, env, now);
  const result = await acknowledgeReviewEmailReceipt(reviewStore, receipt.evidence, receipt.signature, env, {
    clock: () => now,
    expireRecipientCheckouts: adapters.expireRecipientCheckouts,
    stripeFactory: adapters.stripeFactory,
    stripeRevocationClient: adapters.stripeRevocationClient || adapters.stripeClient,
  });
  if (adapters.vaultStore) {
    // A delivered preview may later become a paid ARC2 handoff. Keep the
    // encrypted recipient/source capsule until its normal expiry so the paid
    // worker can bind the exact approved recipient to the ownership emails.
    // Negative terminal events revoke checkout authority, so they may remove
    // every review capsule immediately.
    if (input.event_type === 'email.delivered') {
      await deleteEmailRecipientCapsule(adapters.vaultStore, {
        job_kind: 'preview_review',
        job_key: acceptanceJobKey(binding.outbox_hmac_sha256),
      }, env);
    } else {
      await deletePreviewReviewEmailCapsules(adapters.vaultStore, binding.outbox_hmac_sha256, env);
    }
    await deleteEmailRecipientCapsule(adapters.vaultStore, {
      job_kind: 'preview_review',
      job_key: `attempt-context:${input.attempt_hmac_sha256}`,
    }, env);
  }
  return result;
}

export const previewReviewResendEventTypes = Object.freeze(Object.keys(PROVIDER_STATUS));
