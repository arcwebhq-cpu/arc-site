import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import {
  REVIEW_EMAIL_DELIVERY_BINDING_SCHEMA,
  REVIEW_EMAIL_SUPPRESSION_BINDING_SCHEMA,
  bindReviewInviteDeliveryReceipt,
  bindReviewInviteEmailSuppression,
  issueReviewInvite,
  readReviewInviteForEmail,
  renewExpiredReviewSuccessor,
  reviewInviteHmac,
  signReviewEmailDeliveryBinding,
  signReviewEmailSuppressionBinding,
} from './review-flow-core.mjs';
import {
  ensureReviewEmailRecipientControl,
  readReviewEmailRecipientControl,
  suppressReviewEmailRecipientControl,
} from './review-email-recipient-control-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const REVIEW_EMAIL_OUTBOX_SCHEMA = 'arc-preview-review-email-outbox-v1';
export const REVIEW_EMAIL_RECEIPT_SCHEMA = 'arc-preview-review-email-receipt-v1';
export const REVIEW_EMAIL_TEMPLATE_VERSION = 'arc-preview-ready-v1';
export const REVIEW_EMAIL_RECEIPT_FRESHNESS_MS = 10 * 60_000;
export const REVIEW_EMAIL_RENEWAL_SCHEMA = 'arc-preview-review-email-renewal-v1';
export const REVIEW_EMAIL_PENDING_SCHEMA = 'arc-preview-review-email-pending-v1';
export const REVIEW_EMAIL_PENDING_KEY = 'review-email-pending/index-v1';

const OUTBOX_RECORD_SIGNATURE_PREFIX = 'arc-preview-review-email-outbox-record-signature-v1\n';
const OUTBOX_ID_PREFIX = 'arc-preview-review-email-outbox-id-v1\n';
const PROVIDER_IDEMPOTENCY_PREFIX = 'arc-preview-review-email-provider-idempotency-v1\n';
const RECEIPT_SIGNATURE_PREFIX = 'arc-preview-review-email-receipt-signature-v1\n';
const PROVIDER_EVENT_ID_PREFIX = 'arc-preview-review-email-provider-event-id-v1\n';
const PROVIDER_MESSAGE_ID_PREFIX = 'arc-preview-review-email-provider-message-id-v1\n';
const RECIPIENT_SUPPRESSION_ID_PREFIX = 'arc-preview-review-email-recipient-suppression-id-v1\n';
const RECIPIENT_SUPPRESSION_SIGNATURE_PREFIX = 'arc-preview-review-email-recipient-suppression-signature-v1\n';
const RENEWAL_ID_PREFIX = 'arc-preview-review-email-renewal-id-v1\n';
const RENEWAL_SIGNATURE_PREFIX = 'arc-preview-review-email-renewal-record-signature-v1\n';
const PENDING_SIGNATURE_PREFIX = 'arc-preview-review-email-pending-record-signature-v1\n';
const PENDING_SOURCE_REFERENCE_PREFIX = 'arc-preview-review-email-pending-source-reference-v1\n';
const OUTBOX_STATES = new Set(['READY', 'SEND_RESERVED', 'RECEIPT_BOUND', 'DELIVERED', 'BOUNCED', 'COMPLAINED']);
const TERMINAL_STATES = new Set(['DELIVERED', 'BOUNCED', 'COMPLAINED']);
const STATUS_TO_EVENT = Object.freeze({
  bounced: 'message.bounced',
  complained: 'message.complained',
  delivered: 'message.delivered',
});
const STATUS_TO_STATE = Object.freeze({ bounced: 'BOUNCED', complained: 'COMPLAINED', delivered: 'DELIVERED' });
const HEX_64 = /^[a-f0-9]{64}$/;
const TOKEN = /^[A-Za-z0-9_-]{43,128}$/;
const PROVIDER = /^[a-z0-9][a-z0-9_.-]{1,63}$/;
const TEMPLATE_VERSION = /^[a-z0-9][a-z0-9.-]{5,79}$/;
const OUTBOX_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'state', 'outbox_hmac_sha256', 'invite_hmac_sha256',
  'recipient_email_sha256', 'preview_manifest_sha256', 'template_version', 'created_at', 'expires_at',
  'send_reserved_at', 'provider_idempotency_key_sha256', 'delivery_receipt_sha256', 'provider',
  'provider_account_hmac_sha256', 'provider_event_id_hmac_sha256', 'provider_message_id_hmac_sha256',
  'event_type', 'delivery_status', 'event_at', 'receipt_issued_at', 'delivered_receipt_sha256',
  'suppression_receipt_sha256', 'suppression_status', 'suppressed_at', 'terminal_at', 'record_hmac_sha256',
]);
const RECEIPT_FIELDS = Object.freeze([
  'schema', 'version', 'outbox_hmac_sha256', 'invite_hmac_sha256', 'recipient_email_sha256',
  'preview_manifest_sha256', 'provider', 'provider_account_hmac_sha256', 'provider_event_id',
  'provider_message_id', 'event_type', 'delivery_status', 'event_at', 'issued_at',
]);
const RECIPIENT_SUPPRESSION_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'recipient_suppression_hmac_sha256', 'recipient_email_sha256',
  'suppression_receipt_sha256', 'suppression_status', 'suppressed_at', 'source_invite_hmac_sha256',
  'source_outbox_hmac_sha256', 'record_hmac_sha256',
]);
const RENEWAL_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'state', 'renewal_hmac_sha256',
  'replaced_invite_hmac_sha256', 'replaced_outbox_hmac_sha256', 'replacement_invite_hmac_sha256',
  'replacement_outbox_hmac_sha256', 'recipient_email_sha256', 'preview_manifest_sha256',
  'created_at', 'replacement_expires_at', 'ready_at', 'record_hmac_sha256',
]);
const RENEWAL_INVITE_FIELDS = Object.freeze([
  'brief_sha256', 'expires_at', 'invite_token', 'page_bindings', 'preview_content_sha256',
  'preview_manifest_sha256', 'preview_source_commit_sha', 'preview_source_repository', 'preview_url',
  'prior_invite_hmac_sha256', 'recipient_email_sha256', 'scope_version',
]);
const PENDING_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'entries', 'updated_at', 'record_hmac_sha256',
]);
const PENDING_ENTRY_FIELDS = Object.freeze([
  'outbox_hmac_sha256', 'invite_hmac_sha256', 'recipient_email_sha256',
  'source_reference_hmac_sha256', 'enqueued_at',
]);
const RECIPIENT_SUPPRESSION_SCHEMA = 'arc-preview-review-email-recipient-suppression-v1';

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const output = JSON.stringify(value);
  if (output === undefined) throw new TypeError('Canonical JSON does not support undefined.');
  return output;
}

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function hmacHex(secret, value) {
  return createHmac('sha256', secret).update(value).digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw new TypeError(`${label} fields are invalid.`);
  }
}

function hex64(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function isoTimestamp(value, label) {
  if (typeof value !== 'string' || value.length < 20 || value.length > 32 || new Date(value).toISOString() !== value) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function validSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}

function configuredOrigin(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value && !url.username && !url.password ? url.origin : null;
  } catch {
    return null;
  }
}

function normalizeRecipientEmail(value) {
  if (typeof value !== 'string') throw new TypeError('Review recipient email is invalid.');
  const normalized = value.trim().toLowerCase();
  if (normalized.length < 3 || normalized.length > 254 || /[\u0000-\u0020\u007f]/.test(normalized) ||
      !/^[^@]+@[^@]+\.[^@]+$/.test(normalized)) {
    throw new TypeError('Review recipient email is invalid.');
  }
  return normalized;
}

export function reviewEmailRecipientSha256(value) {
  return sha256Hex(normalizeRecipientEmail(value));
}

export function reviewEmailOutboxConfiguration(env = process.env) {
  const flagValid = env.ARC_REVIEW_EMAIL_OUTBOX_ENABLED === 'true' || env.ARC_REVIEW_EMAIL_OUTBOX_ENABLED === 'false';
  const outboxSecret = env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET;
  const receiptSecret = env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET;
  const related = [
    env.ARC_REVIEW_INVITE_HMAC_SECRET,
    env.ARC_REVIEW_SESSION_HMAC_SECRET,
    env.ARC_REVIEW_RECORD_HMAC_SECRET,
    env.ARC_REVIEW_DECISION_HMAC_SECRET,
  ];
  const selectedSecretNames = [
    'ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET',
    'ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET',
  ];
  const secretsValid = validSecret(outboxSecret) && validSecret(receiptSecret) && outboxSecret !== receiptSecret &&
    !related.includes(outboxSecret) && !related.includes(receiptSecret) &&
    sensitiveCredentialsAreIsolated(env, selectedSecretNames);
  const reviewOrigin = configuredOrigin(env.ARC_REVIEW_PUBLIC_ORIGIN);
  return {
    enabled: flagValid && env.ARC_REVIEW_EMAIL_OUTBOX_ENABLED === 'true' && secretsValid && Boolean(reviewOrigin),
    flagValid,
    reviewOrigin,
    secretsValid,
  };
}

function requireOutbox(env) {
  const configuration = reviewEmailOutboxConfiguration(env);
  if (!configuration.enabled) throw new Error('ARC_REVIEW_EMAIL_OUTBOX_DISABLED');
  return configuration;
}

function outboxHmac(inviteHmac, env) {
  return hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET, OUTBOX_ID_PREFIX + inviteHmac);
}

export function reviewEmailOutboxKey(outboxHmacSha256) {
  return `review-email-outbox/${hex64(outboxHmacSha256, 'Review email outbox HMAC')}`;
}

function recipientSuppressionHmac(recipientEmailSha256, env) {
  return hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    RECIPIENT_SUPPRESSION_ID_PREFIX + hex64(recipientEmailSha256, 'Review email recipient digest'));
}

export function reviewEmailRecipientSuppressionKey(recipientSuppressionHmacSha256) {
  return `review-email-recipient-suppression/${hex64(recipientSuppressionHmacSha256,
    'Review email recipient suppression HMAC')}`;
}

function unsignedRecipientSuppression(record) {
  const { record_hmac_sha256: _signature, ...unsigned } = record;
  return unsigned;
}

function signRecipientSuppression(record, env) {
  const unsigned = unsignedRecipientSuppression(record);
  return {
    ...unsigned,
    record_hmac_sha256: hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
      RECIPIENT_SUPPRESSION_SIGNATURE_PREFIX + canonicalJson(unsigned)),
  };
}

function validateRecipientSuppression(record, env) {
  exactKeys(record, RECIPIENT_SUPPRESSION_FIELDS, 'Review email recipient suppression');
  if (record.schema !== RECIPIENT_SUPPRESSION_SCHEMA || record.version !== 1 ||
      !Number.isSafeInteger(record.record_revision) || record.record_revision < 1 ||
      !['bounced', 'complained'].includes(record.suppression_status)) {
    throw new TypeError('Review email recipient suppression is invalid.');
  }
  hex64(record.recipient_suppression_hmac_sha256, 'Review email recipient suppression HMAC');
  hex64(record.recipient_email_sha256, 'Review email recipient digest');
  hex64(record.suppression_receipt_sha256, 'Review email suppression receipt digest');
  isoTimestamp(record.suppressed_at, 'Review email suppression timestamp');
  hex64(record.source_invite_hmac_sha256, 'Review email suppression source invite HMAC');
  hex64(record.source_outbox_hmac_sha256, 'Review email suppression source outbox HMAC');
  const expectedId = recipientSuppressionHmac(record.recipient_email_sha256, env);
  if (!safeEqual(expectedId, record.recipient_suppression_hmac_sha256)) {
    throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_SUPPRESSION_BINDING_INVALID');
  }
  hex64(record.record_hmac_sha256, 'Review email recipient suppression signature');
  const expectedSignature = hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    RECIPIENT_SUPPRESSION_SIGNATURE_PREFIX + canonicalJson(unsignedRecipientSuppression(record)));
  if (!safeEqual(expectedSignature, record.record_hmac_sha256)) {
    throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_SUPPRESSION_SIGNATURE_INVALID');
  }
  return record;
}

async function readRecipientSuppressionEntry(store, recipientEmailSha256, env) {
  const id = recipientSuppressionHmac(recipientEmailSha256, env);
  const entry = await store.getWithMetadata(reviewEmailRecipientSuppressionKey(id),
    { type: 'json', consistency: 'strong' });
  return entry ? { record: validateRecipientSuppression(entry.data, env), etag: entry.etag } : null;
}

export async function readReviewEmailRecipientSuppression(store, recipientEmailSha256, env = process.env) {
  requireOutbox(env);
  return readRecipientSuppressionEntry(store, recipientEmailSha256, env);
}

function normalizeRecipientSuppressionInput(value, env) {
  const recipientEmailSha256 = hex64(value.recipient_email_sha256, 'Review email recipient digest');
  if (!['bounced', 'complained'].includes(value.suppression_status)) {
    throw new TypeError('Review email recipient suppression status is invalid.');
  }
  return {
    schema: RECIPIENT_SUPPRESSION_SCHEMA,
    version: 1,
    recipient_suppression_hmac_sha256: recipientSuppressionHmac(recipientEmailSha256, env),
    recipient_email_sha256: recipientEmailSha256,
    suppression_receipt_sha256: hex64(value.suppression_receipt_sha256,
      'Review email suppression receipt digest'),
    suppression_status: value.suppression_status,
    suppressed_at: isoTimestamp(value.suppressed_at, 'Review email suppression timestamp'),
    source_invite_hmac_sha256: hex64(value.source_invite_hmac_sha256,
      'Review email suppression source invite HMAC'),
    source_outbox_hmac_sha256: hex64(value.source_outbox_hmac_sha256,
      'Review email suppression source outbox HMAC'),
  };
}

function sameRecipientSuppression(record, value) {
  return record.recipient_email_sha256 === value.recipient_email_sha256 &&
    record.suppression_receipt_sha256 === value.suppression_receipt_sha256 &&
    record.suppression_status === value.suppression_status && record.suppressed_at === value.suppressed_at &&
    record.source_invite_hmac_sha256 === value.source_invite_hmac_sha256 &&
    record.source_outbox_hmac_sha256 === value.source_outbox_hmac_sha256;
}

async function bindRecipientSuppression(store, rawValue, env, nowValue = new Date()) {
  const value = normalizeRecipientSuppressionInput(rawValue, env);
  const controlled = await suppressReviewEmailRecipientControl(store, {
    recipient_email_sha256: value.recipient_email_sha256,
    suppression_receipt_sha256: value.suppression_receipt_sha256,
    suppression_status: value.suppression_status,
    suppressed_at: value.suppressed_at,
    source_invite_hmac_sha256: value.source_invite_hmac_sha256,
    source_outbox_hmac_sha256: value.source_outbox_hmac_sha256,
  }, env, nowValue);
  if (controlled.pending) throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_AUTHORITY_CONTENTION');
  const key = reviewEmailRecipientSuppressionKey(value.recipient_suppression_hmac_sha256);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const existing = await readRecipientSuppressionEntry(store, value.recipient_email_sha256, env);
    if (!existing) {
      const createdRecord = signRecipientSuppression({ ...value, record_revision: 1 }, env);
      const created = await store.setJSON(key, createdRecord, { onlyIfNew: true });
      if (created?.modified) return { idempotent_replay: false, record: createdRecord };
      if (attempt === 2) throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
      continue;
    }
    if (sameRecipientSuppression(existing.record, value)) {
      return { idempotent_replay: true, record: existing.record };
    }
    if (receiptPriority(STATUS_TO_STATE[value.suppression_status]) <=
        receiptPriority(STATUS_TO_STATE[existing.record.suppression_status])) {
      // The recipient is already suppressed at the same or stronger level.
      // Preserve that immutable global latch while allowing this independently
      // signed in-flight outbox to terminalize and revoke its own invite.
      return { idempotent_replay: true, record: existing.record };
    }
    const updated = signRecipientSuppression({
      ...value,
      record_revision: existing.record.record_revision + 1,
    }, env);
    const replaced = await store.setJSON(key, updated, { onlyIfMatch: existing.etag });
    if (replaced?.modified) return { idempotent_replay: false, record: updated };
    if (attempt === 2) throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
  }
  throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
}

async function expireRecipientCheckoutsBeforeSuppression(store, suppression, env, adapters) {
  const expire = adapters.expireRecipientCheckouts;
  if (typeof expire !== 'function') {
    // A revocation-enabled deployment must never finish a negative delivery
    // acknowledgement without the provider reconciliation hook. When the
    // feature is disabled there cannot be a valid revocable review Checkout.
    if (env.ARC_STRIPE_REVIEW_REVOCATION_ENABLED === 'true') {
      throw new Error('ARC_REVIEW_EMAIL_CHECKOUT_REVOCATION_UNAVAILABLE');
    }
    return { complete: true, pending: false, revoked: 0 };
  }
  const result = await expire(store, suppression, env, {
    clock: adapters.clock,
    stripeClient: adapters.stripeRevocationClient || adapters.stripeClient,
    stripeFactory: adapters.stripeFactory,
  });
  if (!result || result.complete !== true || result.pending !== false ||
      !Number.isSafeInteger(result.revoked) || result.revoked < 0) {
    throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_AUTHORITY_CONTENTION');
  }
  return result;
}

function unsignedPending(record) {
  const { record_hmac_sha256: _signature, ...unsigned } = record;
  return unsigned;
}

function signPending(record, env) {
  const unsigned = unsignedPending(record);
  return {
    ...unsigned,
    record_hmac_sha256: hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
      PENDING_SIGNATURE_PREFIX + canonicalJson(unsigned)),
  };
}

function validatePendingEntry(entry) {
  exactKeys(entry, PENDING_ENTRY_FIELDS, 'Review email pending entry');
  hex64(entry.outbox_hmac_sha256, 'Review email pending outbox HMAC');
  hex64(entry.invite_hmac_sha256, 'Review email pending invite HMAC');
  hex64(entry.recipient_email_sha256, 'Review email pending recipient digest');
  hex64(entry.source_reference_hmac_sha256, 'Review email pending source reference');
  isoTimestamp(entry.enqueued_at, 'Review email pending timestamp');
  return entry;
}

function validatePending(record, env) {
  exactKeys(record, PENDING_FIELDS, 'Review email pending index');
  if (record.schema !== REVIEW_EMAIL_PENDING_SCHEMA || record.version !== 1 ||
      !Number.isSafeInteger(record.record_revision) || record.record_revision < 1 ||
      !Array.isArray(record.entries) || record.entries.length > 1_000) {
    throw new TypeError('Review email pending index is invalid.');
  }
  const outboxes = new Set();
  const invites = new Set();
  for (const entry of record.entries) {
    validatePendingEntry(entry);
    if (outboxes.has(entry.outbox_hmac_sha256) || invites.has(entry.invite_hmac_sha256)) {
      throw new TypeError('Review email pending index contains duplicates.');
    }
    outboxes.add(entry.outbox_hmac_sha256);
    invites.add(entry.invite_hmac_sha256);
  }
  isoTimestamp(record.updated_at, 'Review email pending update timestamp');
  hex64(record.record_hmac_sha256, 'Review email pending signature');
  const expected = hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    PENDING_SIGNATURE_PREFIX + canonicalJson(unsignedPending(record)));
  if (!safeEqual(expected, record.record_hmac_sha256)) {
    throw new Error('ARC_REVIEW_EMAIL_PENDING_SIGNATURE_INVALID');
  }
  return record;
}

async function readPendingEntry(store, env) {
  const entry = await store.getWithMetadata(REVIEW_EMAIL_PENDING_KEY,
    { type: 'json', consistency: 'strong' });
  return entry ? { record: validatePending(entry.data, env), etag: entry.etag } : null;
}

export async function readReviewEmailPending(store, env = process.env) {
  requireOutbox(env);
  return readPendingEntry(store, env);
}

function defaultSourceReference(inviteHmacSha256, env) {
  return hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    PENDING_SOURCE_REFERENCE_PREFIX + hex64(inviteHmacSha256, 'Review email invite HMAC'));
}

function pendingSourceReference(value, inviteHmacSha256, env) {
  return value === undefined || value === null
    ? defaultSourceReference(inviteHmacSha256, env)
    : hex64(value, 'Review email pending source reference');
}

async function ensurePendingEntry(store, outbox, sourceReference, env, now) {
  const sourceReferenceExplicit = sourceReference !== undefined && sourceReference !== null;
  const desired = {
    outbox_hmac_sha256: outbox.outbox_hmac_sha256,
    invite_hmac_sha256: outbox.invite_hmac_sha256,
    recipient_email_sha256: outbox.recipient_email_sha256,
    source_reference_hmac_sha256: pendingSourceReference(sourceReference, outbox.invite_hmac_sha256, env),
    enqueued_at: now.toISOString(),
  };
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const current = await readPendingEntry(store, env);
    if (!current) {
      const createdRecord = signPending({
        schema: REVIEW_EMAIL_PENDING_SCHEMA,
        version: 1,
        record_revision: 1,
        entries: [desired],
        updated_at: now.toISOString(),
      }, env);
      const created = await store.setJSON(REVIEW_EMAIL_PENDING_KEY, createdRecord, { onlyIfNew: true });
      if (created?.modified) return { idempotent_replay: false, record: createdRecord };
      continue;
    }
    const existing = current.record.entries.find(entry => entry.outbox_hmac_sha256 === outbox.outbox_hmac_sha256);
    if (existing) {
      if (existing.invite_hmac_sha256 !== desired.invite_hmac_sha256 ||
          existing.recipient_email_sha256 !== desired.recipient_email_sha256 ||
          (sourceReferenceExplicit &&
            existing.source_reference_hmac_sha256 !== desired.source_reference_hmac_sha256)) {
        throw new Error('ARC_REVIEW_EMAIL_PENDING_CONFLICT');
      }
      return { idempotent_replay: true, record: current.record };
    }
    if (current.record.entries.some(entry => entry.invite_hmac_sha256 === desired.invite_hmac_sha256) ||
        current.record.entries.length >= 1_000) {
      throw new Error('ARC_REVIEW_EMAIL_PENDING_CONFLICT');
    }
    const updated = signPending({
      ...unsignedPending(current.record),
      record_revision: current.record.record_revision + 1,
      entries: [...current.record.entries, desired],
      updated_at: now.toISOString(),
    }, env);
    const replaced = await store.setJSON(REVIEW_EMAIL_PENDING_KEY, updated, { onlyIfMatch: current.etag });
    if (replaced?.modified) return { idempotent_replay: false, record: updated };
  }
  throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
}

async function removePendingEntry(store, outboxHmacSha256, env, now) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const current = await readPendingEntry(store, env);
    if (!current) return true;
    const entries = current.record.entries.filter(entry => entry.outbox_hmac_sha256 !== outboxHmacSha256);
    if (entries.length === current.record.entries.length) return true;
    const updated = signPending({
      ...unsignedPending(current.record),
      record_revision: current.record.record_revision + 1,
      entries,
      updated_at: now.toISOString(),
    }, env);
    const replaced = await store.setJSON(REVIEW_EMAIL_PENDING_KEY, updated, { onlyIfMatch: current.etag });
    if (replaced?.modified) return true;
  }
  throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
}

function unsignedOutbox(record) {
  const { record_hmac_sha256: _signature, ...unsigned } = record;
  return unsigned;
}

function signOutbox(record, env) {
  const unsigned = unsignedOutbox(record);
  return {
    ...unsigned,
    record_hmac_sha256: hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
      OUTBOX_RECORD_SIGNATURE_PREFIX + canonicalJson(unsigned)),
  };
}

function receiptFieldsAreNull(record) {
  return [
    record.delivery_receipt_sha256,
    record.provider,
    record.provider_account_hmac_sha256,
    record.provider_event_id_hmac_sha256,
    record.provider_message_id_hmac_sha256,
    record.event_type,
    record.delivery_status,
    record.event_at,
    record.receipt_issued_at,
    record.delivered_receipt_sha256,
    record.suppression_receipt_sha256,
    record.suppression_status,
    record.suppressed_at,
  ].every(value => value === null);
}

function validateOutbox(record, env) {
  exactKeys(record, OUTBOX_FIELDS, 'Review email outbox');
  if (record.schema !== REVIEW_EMAIL_OUTBOX_SCHEMA || record.version !== 1 ||
      !Number.isSafeInteger(record.record_revision) || record.record_revision < 1 || !OUTBOX_STATES.has(record.state)) {
    throw new TypeError('Review email outbox is invalid.');
  }
  hex64(record.outbox_hmac_sha256, 'Review email outbox HMAC');
  hex64(record.invite_hmac_sha256, 'Review email invite HMAC');
  hex64(record.recipient_email_sha256, 'Review email recipient digest');
  hex64(record.preview_manifest_sha256, 'Review email preview manifest digest');
  if (!TEMPLATE_VERSION.test(record.template_version)) throw new TypeError('Review email template version is invalid.');
  isoTimestamp(record.created_at, 'Review email outbox creation timestamp');
  isoTimestamp(record.expires_at, 'Review email outbox expiration timestamp');
  if (Date.parse(record.expires_at) <= Date.parse(record.created_at)) throw new TypeError('Review email expiration is invalid.');

  if (record.state === 'READY') {
    if (record.send_reserved_at !== null || record.provider_idempotency_key_sha256 !== null ||
        !receiptFieldsAreNull(record) || record.terminal_at !== null) throw new TypeError('Review email READY state is invalid.');
  } else {
    isoTimestamp(record.send_reserved_at, 'Review email send reservation timestamp');
    hex64(record.provider_idempotency_key_sha256, 'Review email provider idempotency digest');
    if (Date.parse(record.send_reserved_at) < Date.parse(record.created_at)) throw new TypeError('Review email send timing is invalid.');
    if (record.state === 'SEND_RESERVED') {
      if (!receiptFieldsAreNull(record) || record.terminal_at !== null) {
        throw new TypeError('Review email SEND_RESERVED state is invalid.');
      }
    } else {
      hex64(record.delivery_receipt_sha256, 'Review email delivery receipt digest');
      if (!PROVIDER.test(record.provider)) throw new TypeError('Review email provider is invalid.');
      hex64(record.provider_account_hmac_sha256, 'Review email provider account HMAC');
      hex64(record.provider_event_id_hmac_sha256, 'Review email provider event HMAC');
      hex64(record.provider_message_id_hmac_sha256, 'Review email provider message HMAC');
      if (STATUS_TO_EVENT[record.delivery_status] !== record.event_type) {
        throw new TypeError('Review email event binding is invalid.');
      }
      isoTimestamp(record.event_at, 'Review email event timestamp');
      isoTimestamp(record.receipt_issued_at, 'Review email receipt timestamp');
      if (Date.parse(record.event_at) < Date.parse(record.send_reserved_at) ||
          Date.parse(record.event_at) > Date.parse(record.receipt_issued_at)) {
        throw new TypeError('Review email receipt ordering is invalid.');
      }
      if (record.delivery_status === 'delivered') {
        if (record.delivered_receipt_sha256 !== record.delivery_receipt_sha256 ||
            record.suppression_receipt_sha256 !== null || record.suppression_status !== null ||
            record.suppressed_at !== null) {
          throw new TypeError('Review email delivery evidence is invalid.');
        }
      } else {
        if (record.delivered_receipt_sha256 !== null) {
          hex64(record.delivered_receipt_sha256, 'Prior review email delivery receipt digest');
        }
        if (record.suppression_receipt_sha256 !== record.delivery_receipt_sha256 ||
            record.suppression_status !== record.delivery_status || record.suppressed_at !== record.event_at) {
          throw new TypeError('Review email suppression evidence is invalid.');
        }
      }
      if (record.state === 'RECEIPT_BOUND') {
        if (record.terminal_at !== null) throw new TypeError('Review email receipt latch is invalid.');
      } else {
        if (STATUS_TO_STATE[record.delivery_status] !== record.state) throw new TypeError('Review email terminal state is invalid.');
        isoTimestamp(record.terminal_at, 'Review email terminal timestamp');
        if (Date.parse(record.terminal_at) < Date.parse(record.receipt_issued_at)) {
          throw new TypeError('Review email terminal ordering is invalid.');
        }
      }
    }
  }
  hex64(record.record_hmac_sha256, 'Review email outbox signature');
  const expected = hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    OUTBOX_RECORD_SIGNATURE_PREFIX + canonicalJson(unsignedOutbox(record)));
  if (!safeEqual(expected, record.record_hmac_sha256)) throw new Error('ARC_REVIEW_EMAIL_OUTBOX_SIGNATURE_INVALID');
  return record;
}

async function readOutboxEntry(store, outboxHmacSha256, env) {
  const entry = await store.getWithMetadata(reviewEmailOutboxKey(outboxHmacSha256),
    { type: 'json', consistency: 'strong' });
  if (!entry) throw new Error('ARC_REVIEW_EMAIL_OUTBOX_NOT_FOUND');
  return { record: validateOutbox(entry.data, env), etag: entry.etag };
}

export async function readReviewEmailOutbox(store, outboxHmacSha256, env = process.env) {
  requireOutbox(env);
  return readOutboxEntry(store, outboxHmacSha256, env);
}

function renewalHmac(replacedInviteHmacSha256, env) {
  return hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    RENEWAL_ID_PREFIX + hex64(replacedInviteHmacSha256, 'Replaced review invite HMAC'));
}

export function reviewEmailRenewalKey(renewalHmacSha256) {
  return `review-email-renewal/${hex64(renewalHmacSha256, 'Review email renewal HMAC')}`;
}

function unsignedRenewal(record) {
  const { record_hmac_sha256: _signature, ...unsigned } = record;
  return unsigned;
}

function signRenewal(record, env) {
  const unsigned = unsignedRenewal(record);
  return {
    ...unsigned,
    record_hmac_sha256: hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
      RENEWAL_SIGNATURE_PREFIX + canonicalJson(unsigned)),
  };
}

export function validateReviewEmailRenewal(record, env = process.env) {
  exactKeys(record, RENEWAL_FIELDS, 'Review email renewal');
  if (record.schema !== REVIEW_EMAIL_RENEWAL_SCHEMA || record.version !== 1 ||
      !Number.isSafeInteger(record.record_revision) || record.record_revision < 1 ||
      !['PLANNED', 'READY'].includes(record.state)) {
    throw new TypeError('Review email renewal is invalid.');
  }
  for (const [value, label] of [
    [record.renewal_hmac_sha256, 'Review email renewal HMAC'],
    [record.replaced_invite_hmac_sha256, 'Replaced review invite HMAC'],
    [record.replaced_outbox_hmac_sha256, 'Replaced review email outbox HMAC'],
    [record.replacement_invite_hmac_sha256, 'Replacement review invite HMAC'],
    [record.replacement_outbox_hmac_sha256, 'Replacement review email outbox HMAC'],
    [record.recipient_email_sha256, 'Review email recipient digest'],
    [record.preview_manifest_sha256, 'Review email preview manifest digest'],
  ]) hex64(value, label);
  isoTimestamp(record.created_at, 'Review email renewal creation timestamp');
  isoTimestamp(record.replacement_expires_at, 'Review email renewal expiration');
  if (record.state === 'PLANNED') {
    if (record.record_revision !== 1 || record.ready_at !== null) {
      throw new TypeError('Review email renewal plan is invalid.');
    }
  } else {
    isoTimestamp(record.ready_at, 'Review email renewal ready timestamp');
    if (record.record_revision < 2 || Date.parse(record.ready_at) < Date.parse(record.created_at)) {
      throw new TypeError('Review email renewal ready state is invalid.');
    }
  }
  if (record.replaced_invite_hmac_sha256 === record.replacement_invite_hmac_sha256 ||
      record.replaced_outbox_hmac_sha256 !== outboxHmac(record.replaced_invite_hmac_sha256, env) ||
      record.replacement_outbox_hmac_sha256 !== outboxHmac(record.replacement_invite_hmac_sha256, env) ||
      record.renewal_hmac_sha256 !== renewalHmac(record.replaced_invite_hmac_sha256, env)) {
    throw new Error('ARC_REVIEW_EMAIL_RENEWAL_BINDING_INVALID');
  }
  hex64(record.record_hmac_sha256, 'Review email renewal signature');
  const expected = hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    RENEWAL_SIGNATURE_PREFIX + canonicalJson(unsignedRenewal(record)));
  if (!safeEqual(expected, record.record_hmac_sha256)) {
    throw new Error('ARC_REVIEW_EMAIL_RENEWAL_SIGNATURE_INVALID');
  }
  return record;
}

async function readRenewalEntry(store, replacedInviteHmacSha256, env) {
  const id = renewalHmac(replacedInviteHmacSha256, env);
  const entry = await store.getWithMetadata(reviewEmailRenewalKey(id),
    { type: 'json', consistency: 'strong' });
  return entry ? { record: validateReviewEmailRenewal(entry.data, env), etag: entry.etag } : null;
}

export async function readReviewEmailRenewal(store, replacedInviteHmacSha256, env = process.env) {
  requireOutbox(env);
  return readRenewalEntry(store, replacedInviteHmacSha256, env);
}

function validateRenewalInviteInput(rawInvite, replaced, now, env) {
  exactKeys(rawInvite, RENEWAL_INVITE_FIELDS, 'Review email renewal invite');
  const replacementInviteHmac = reviewInviteHmac(rawInvite.invite_token, env);
  const expiresAt = isoTimestamp(rawInvite.expires_at, 'Review email renewal expiration');
  if (replacementInviteHmac === replaced.invite_hmac_sha256 ||
      Date.parse(expiresAt) <= now.getTime() ||
      Date.parse(expiresAt) > now.getTime() + 30 * 24 * 60 * 60_000) {
    throw new Error('ARC_REVIEW_EMAIL_RENEWAL_INVALID');
  }
  const exactImmutable = rawInvite.brief_sha256 === replaced.brief_sha256 &&
    rawInvite.preview_content_sha256 === replaced.preview_content_sha256 &&
    rawInvite.preview_manifest_sha256 === replaced.preview_manifest_sha256 &&
    rawInvite.preview_source_commit_sha === replaced.preview_source_commit_sha &&
    rawInvite.preview_source_repository === replaced.preview_source_repository &&
    rawInvite.preview_url === replaced.preview_url &&
    rawInvite.prior_invite_hmac_sha256 === replaced.prior_invite_hmac_sha256 &&
    rawInvite.recipient_email_sha256 === replaced.recipient_email_sha256 &&
    rawInvite.scope_version === replaced.scope_version &&
    canonicalJson(rawInvite.page_bindings) === canonicalJson(replaced.page_bindings);
  if (!exactImmutable) throw new Error('ARC_REVIEW_EMAIL_RENEWAL_BINDING_INVALID');
  return { expiresAt, replacementInviteHmac };
}

function sameRenewalPlan(record, expected) {
  return record.replaced_invite_hmac_sha256 === expected.replacedInviteHmac &&
    record.replaced_outbox_hmac_sha256 === expected.replacedOutboxHmac &&
    record.replacement_invite_hmac_sha256 === expected.replacementInviteHmac &&
    record.replacement_outbox_hmac_sha256 === expected.replacementOutboxHmac &&
    record.recipient_email_sha256 === expected.recipientEmailSha256 &&
    record.preview_manifest_sha256 === expected.previewManifestSha256 &&
    record.replacement_expires_at === expected.expiresAt;
}

async function readReadyRenewalTarget(store, renewal, env) {
  const [invite, outbox] = await Promise.all([
    readReviewInviteForEmail(store, renewal.replacement_invite_hmac_sha256, env),
    readOutboxEntry(store, renewal.replacement_outbox_hmac_sha256, env),
  ]);
  if (invite.record.state !== 'OPEN' || invite.record.session_nonce_hmac_sha256 !== null ||
      invite.record.email_delivery_receipt_sha256 !== null ||
      invite.record.email_suppression_receipt_sha256 !== null ||
      invite.record.recipient_email_sha256 !== renewal.recipient_email_sha256 ||
      invite.record.preview_manifest_sha256 !== renewal.preview_manifest_sha256 ||
      invite.record.expires_at !== renewal.replacement_expires_at || outbox.record.state !== 'READY' ||
      outbox.record.invite_hmac_sha256 !== invite.record.invite_hmac_sha256 ||
      outbox.record.recipient_email_sha256 !== invite.record.recipient_email_sha256 ||
      outbox.record.preview_manifest_sha256 !== invite.record.preview_manifest_sha256 ||
      outbox.record.expires_at !== invite.record.expires_at) {
    throw new Error('ARC_REVIEW_EMAIL_RENEWAL_TARGET_INVALID');
  }
  return { invite: invite.record, outbox: outbox.record };
}

// Replans only an expired READY outbox. The replacement token remains solely
// in caller memory; a signed HMAC-only plan is durable before a replacement
// invite/outbox can be created. Initial invites use that plan as their link,
// while revision successors also CAS-update their predecessor lineage.
export async function renewExpiredReadyReviewEmail(store, replacedInviteHmacSha256, rawInvite,
  env = process.env, adapters = {}) {
  requireOutbox(env);
  const nowValue = adapters.clock?.() || new Date();
  const now = nowValue instanceof Date ? new Date(nowValue.getTime()) : new Date(nowValue);
  if (!Number.isFinite(now.getTime())) throw new TypeError('Review email renewal clock is invalid.');
  const replacedInviteHmac = hex64(replacedInviteHmacSha256, 'Replaced review invite HMAC');
  const replacedOutboxHmac = outboxHmac(replacedInviteHmac, env);
  const [replacedInvite, replacedOutbox, globalSuppression] = await Promise.all([
    readReviewInviteForEmail(store, replacedInviteHmac, env),
    readOutboxEntry(store, replacedOutboxHmac, env),
    (async () => {
      const invite = await readReviewInviteForEmail(store, replacedInviteHmac, env);
      return readRecipientSuppressionEntry(store, invite.record.recipient_email_sha256, env);
    })(),
  ]);
  const oldInvite = replacedInvite.record;
  const oldOutbox = replacedOutbox.record;
  if (globalSuppression || oldInvite.email_suppression_receipt_sha256 !== null) {
    throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_SUPPRESSED');
  }
  if (oldInvite.state !== 'OPEN' || Date.parse(oldInvite.expires_at) > now.getTime() ||
      oldInvite.session_nonce_hmac_sha256 !== null || oldInvite.exchanged_at !== null || oldInvite.decision !== null ||
      oldInvite.email_delivery_receipt_sha256 !== null || oldInvite.email_delivery_binding_mode !== null ||
      oldInvite.email_delivery_outbox_hmac_sha256 !== null || oldOutbox.state !== 'READY' ||
      Date.parse(oldOutbox.expires_at) > now.getTime() || oldOutbox.invite_hmac_sha256 !== replacedInviteHmac ||
      oldOutbox.recipient_email_sha256 !== oldInvite.recipient_email_sha256 ||
      oldOutbox.preview_manifest_sha256 !== oldInvite.preview_manifest_sha256 ||
      oldOutbox.expires_at !== oldInvite.expires_at) {
    throw new Error('ARC_REVIEW_EMAIL_RENEWAL_NOT_ALLOWED');
  }
  const pendingIndex = await readPendingEntry(store, env);
  const replacedPending = pendingIndex?.record.entries.find(entry =>
    entry.outbox_hmac_sha256 === replacedOutboxHmac) || null;
  const suppliedSourceReference = adapters.sourceReferenceHmacSha256;
  if (replacedPending && suppliedSourceReference !== undefined && suppliedSourceReference !== null &&
      replacedPending.source_reference_hmac_sha256 !== suppliedSourceReference) {
    throw new Error('ARC_REVIEW_EMAIL_PENDING_CONFLICT');
  }
  const sourceReference = replacedPending?.source_reference_hmac_sha256 ||
    pendingSourceReference(suppliedSourceReference, replacedInviteHmac, env);
  const normalized = validateRenewalInviteInput(rawInvite, oldInvite, now, env);
  const expected = {
    replacedInviteHmac,
    replacedOutboxHmac,
    replacementInviteHmac: normalized.replacementInviteHmac,
    replacementOutboxHmac: outboxHmac(normalized.replacementInviteHmac, env),
    recipientEmailSha256: oldInvite.recipient_email_sha256,
    previewManifestSha256: oldInvite.preview_manifest_sha256,
    expiresAt: normalized.expiresAt,
  };
  let renewal = await readRenewalEntry(store, replacedInviteHmac, env);
  let planCreated = false;
  if (!renewal) {
    const planned = signRenewal({
      schema: REVIEW_EMAIL_RENEWAL_SCHEMA,
      version: 1,
      record_revision: 1,
      state: 'PLANNED',
      renewal_hmac_sha256: renewalHmac(replacedInviteHmac, env),
      replaced_invite_hmac_sha256: replacedInviteHmac,
      replaced_outbox_hmac_sha256: replacedOutboxHmac,
      replacement_invite_hmac_sha256: expected.replacementInviteHmac,
      replacement_outbox_hmac_sha256: expected.replacementOutboxHmac,
      recipient_email_sha256: expected.recipientEmailSha256,
      preview_manifest_sha256: expected.previewManifestSha256,
      created_at: now.toISOString(),
      replacement_expires_at: expected.expiresAt,
      ready_at: null,
    }, env);
    const created = await store.setJSON(reviewEmailRenewalKey(planned.renewal_hmac_sha256), planned,
      { onlyIfNew: true });
    if (created?.modified) {
      planCreated = true;
      renewal = { record: planned, etag: created.etag };
    } else {
      renewal = await readRenewalEntry(store, replacedInviteHmac, env);
    }
  }
  if (!renewal || !sameRenewalPlan(renewal.record, expected)) {
    throw new Error('ARC_REVIEW_EMAIL_RENEWAL_CONFLICT');
  }
  if (renewal.record.state === 'READY') {
    const ready = await readReadyRenewalTarget(store, renewal.record, env);
    await ensurePendingEntry(store, ready.outbox, sourceReference, env, now);
    await removePendingEntry(store, replacedOutboxHmac, env, now);
    return { idempotent_replay: true, ...ready, renewal: renewal.record };
  }

  if (oldInvite.prior_invite_hmac_sha256 !== null) {
    await renewExpiredReviewSuccessor(store, replacedInviteHmac, rawInvite, env, { clock: () => new Date(now) });
  }
  const prepared = await prepareReviewInviteEmail(store, rawInvite, env, {
    clock: () => new Date(now),
    sourceReferenceHmacSha256: sourceReference,
  });
  if (prepared.invite.invite_hmac_sha256 !== expected.replacementInviteHmac ||
      prepared.outbox.outbox_hmac_sha256 !== expected.replacementOutboxHmac ||
      prepared.outbox.state !== 'READY') {
    throw new Error('ARC_REVIEW_EMAIL_RENEWAL_TARGET_INVALID');
  }
  const readyRecord = signRenewal({
    ...unsignedRenewal(renewal.record),
    record_revision: renewal.record.record_revision + 1,
    state: 'READY',
    ready_at: now.toISOString(),
  }, env);
  const linked = await store.setJSON(reviewEmailRenewalKey(renewal.record.renewal_hmac_sha256), readyRecord,
    { onlyIfMatch: renewal.etag });
  if (!linked?.modified) {
    const current = await readRenewalEntry(store, replacedInviteHmac, env);
    if (!current || current.record.state !== 'READY' || !sameRenewalPlan(current.record, expected)) {
      throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
    }
    const ready = await readReadyRenewalTarget(store, current.record, env);
    await removePendingEntry(store, replacedOutboxHmac, env, now);
    return { idempotent_replay: true, ...ready, renewal: current.record };
  }
  await removePendingEntry(store, replacedOutboxHmac, env, now);
  return {
    idempotent_replay: !planCreated,
    invite: prepared.invite,
    outbox: prepared.outbox,
    renewal: readyRecord,
  };
}

function immutableOutbox(record) {
  return {
    schema: record.schema,
    version: record.version,
    outbox_hmac_sha256: record.outbox_hmac_sha256,
    invite_hmac_sha256: record.invite_hmac_sha256,
    recipient_email_sha256: record.recipient_email_sha256,
    preview_manifest_sha256: record.preview_manifest_sha256,
    template_version: record.template_version,
    expires_at: record.expires_at,
  };
}

async function createOutbox(store, invite, env, now) {
  const id = outboxHmac(invite.invite_hmac_sha256, env);
  const record = signOutbox({
    schema: REVIEW_EMAIL_OUTBOX_SCHEMA,
    version: 1,
    record_revision: 1,
    state: 'READY',
    outbox_hmac_sha256: id,
    invite_hmac_sha256: invite.invite_hmac_sha256,
    recipient_email_sha256: invite.recipient_email_sha256,
    preview_manifest_sha256: invite.preview_manifest_sha256,
    template_version: REVIEW_EMAIL_TEMPLATE_VERSION,
    created_at: now.toISOString(),
    expires_at: invite.expires_at,
    send_reserved_at: null,
    provider_idempotency_key_sha256: null,
    delivery_receipt_sha256: null,
    provider: null,
    provider_account_hmac_sha256: null,
    provider_event_id_hmac_sha256: null,
    provider_message_id_hmac_sha256: null,
    event_type: null,
    delivery_status: null,
    event_at: null,
    receipt_issued_at: null,
    delivered_receipt_sha256: null,
    suppression_receipt_sha256: null,
    suppression_status: null,
    suppressed_at: null,
    terminal_at: null,
  }, env);
  const created = await store.setJSON(reviewEmailOutboxKey(id), record, { onlyIfNew: true });
  if (created?.modified) return { idempotent_replay: false, record };
  const existing = await readOutboxEntry(store, id, env);
  if (canonicalJson(immutableOutbox(existing.record)) !== canonicalJson(immutableOutbox(record))) {
    throw new Error('ARC_REVIEW_EMAIL_OUTBOX_CONFLICT');
  }
  return { idempotent_replay: true, record: existing.record };
}

export async function prepareReviewInviteEmail(store, rawInvite, env = process.env, adapters = {}) {
  requireOutbox(env);
  if (!rawInvite || typeof rawInvite !== 'object' || Array.isArray(rawInvite) ||
      (rawInvite.email_delivery_receipt_sha256 !== undefined && rawInvite.email_delivery_receipt_sha256 !== null)) {
    throw new TypeError('Review email preparation requires an unconfirmed invite.');
  }
  const now = adapters.clock?.() || new Date();
  const recipientControl = await ensureReviewEmailRecipientControl(store,
    rawInvite.recipient_email_sha256, env, now);
  if (recipientControl.record.state === 'SUPPRESSED' ||
      recipientControl.record.suppression_receipt_sha256 !== null) {
    throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_SUPPRESSED');
  }
  const issued = await issueReviewInvite(store, {
    ...rawInvite,
    email_delivery_receipt_sha256: null,
  }, env, { clock: () => now });
  const id = outboxHmac(issued.record.invite_hmac_sha256, env);
  if (issued.record.email_delivery_receipt_sha256 !== null) {
    const existing = await readOutboxEntry(store, id, env);
    if (existing.record.state !== 'DELIVERED' ||
        existing.record.delivery_receipt_sha256 !== issued.record.email_delivery_receipt_sha256) {
      throw new Error('ARC_REVIEW_EMAIL_OUTBOX_CONFLICT');
    }
    await removePendingEntry(store, existing.record.outbox_hmac_sha256, env, now);
    return { idempotent_replay: true, invite: issued.record, outbox: existing.record };
  }
  const outbox = await createOutbox(store, issued.record, env, now);
  const pending = await ensurePendingEntry(store, outbox.record,
    adapters.sourceReferenceHmacSha256, env, now);
  return {
    idempotent_replay: issued.idempotent_replay && outbox.idempotent_replay && pending.idempotent_replay,
    invite: issued.record,
    outbox: outbox.record,
  };
}

function reviewUrl(origin, inviteToken) {
  const url = new URL('/review/', origin);
  url.hash = `invite=${inviteToken}`;
  return url.href;
}

function providerIdempotencyKey(outboxHmacSha256, env) {
  return `arc_review_email_${hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    PROVIDER_IDEMPOTENCY_PREFIX + outboxHmacSha256)}`;
}

function sendAuthority(record, inviteToken, recipientEmail, configuration, env, idempotentReplay) {
  return {
    idempotent_replay: idempotentReplay,
    outbox_hmac_sha256: record.outbox_hmac_sha256,
    provider_idempotency_key: providerIdempotencyKey(record.outbox_hmac_sha256, env),
    recipient_email: recipientEmail,
    review_url: reviewUrl(configuration.reviewOrigin, inviteToken),
    template_version: record.template_version,
  };
}

function suppressionEvidenceFromInvite(record) {
  if (record.email_suppression_receipt_sha256 === null) return null;
  return {
    recipient_email_sha256: record.recipient_email_sha256,
    suppression_receipt_sha256: record.email_suppression_receipt_sha256,
    suppression_status: record.email_suppression_status,
    suppressed_at: record.email_suppressed_at,
    source_invite_hmac_sha256: record.invite_hmac_sha256,
    source_outbox_hmac_sha256: record.email_suppression_source_outbox_hmac_sha256,
  };
}

function strongerSuppression(left, right) {
  if (!left) return right;
  if (!right) return left;
  return receiptPriority(STATUS_TO_STATE[right.suppression_status]) >
    receiptPriority(STATUS_TO_STATE[left.suppression_status]) ? right : left;
}

async function readLineageSuppression(store, startingRecord, env) {
  let current = startingRecord;
  let strongest = suppressionEvidenceFromInvite(current);
  const seen = new Set([current.invite_hmac_sha256]);
  while (current.prior_invite_hmac_sha256 !== null) {
    if (seen.has(current.prior_invite_hmac_sha256) || seen.size > 4) {
      throw new Error('ARC_REVIEW_EMAIL_REVISION_LINEAGE_INVALID');
    }
    const prior = await readReviewInviteForEmail(store, current.prior_invite_hmac_sha256, env);
    if (prior.record.recipient_email_sha256 !== startingRecord.recipient_email_sha256 ||
        prior.record.successor_invite_hmac_sha256 !== current.invite_hmac_sha256) {
      throw new Error('ARC_REVIEW_EMAIL_REVISION_LINEAGE_INVALID');
    }
    seen.add(prior.record.invite_hmac_sha256);
    strongest = strongerSuppression(strongest, suppressionEvidenceFromInvite(prior.record));
    current = prior.record;
  }
  return strongest;
}

async function readEffectiveRecipientSuppression(store, inviteRecord, env) {
  const [stored, lineage, control] = await Promise.all([
    readRecipientSuppressionEntry(store, inviteRecord.recipient_email_sha256, env),
    readLineageSuppression(store, inviteRecord, env),
    readReviewEmailRecipientControl(store, inviteRecord.recipient_email_sha256, env),
  ]);
  let effective = stored?.record || null;
  effective = strongerSuppression(effective, lineage);
  const controlled = control?.record.suppression_receipt_sha256 === null ? null : {
    recipient_email_sha256: control.record.recipient_email_sha256,
    suppression_receipt_sha256: control.record.suppression_receipt_sha256,
    suppression_status: control.record.suppression_status,
    suppressed_at: control.record.suppressed_at,
    source_invite_hmac_sha256: control.record.source_invite_hmac_sha256,
    source_outbox_hmac_sha256: control.record.source_outbox_hmac_sha256,
  };
  effective = strongerSuppression(effective, controlled);
  if (lineage && (!stored || effective === lineage)) {
    const bound = await bindRecipientSuppression(store, lineage, env);
    effective = bound.record;
  }
  if (controlled && (!stored || effective === controlled)) {
    const bound = await bindRecipientSuppression(store, controlled, env);
    effective = bound.record;
  }
  return effective;
}

async function guardReviewEmailSend(store, inviteRecord, outboxRecord, env, now) {
  const suppression = await readEffectiveRecipientSuppression(store, inviteRecord, env);
  if (!suppression) return;
  const binding = {
    schema: REVIEW_EMAIL_SUPPRESSION_BINDING_SCHEMA,
    invite_hmac_sha256: inviteRecord.invite_hmac_sha256,
    outbox_hmac_sha256: outboxRecord.outbox_hmac_sha256,
    source_outbox_hmac_sha256: suppression.source_outbox_hmac_sha256,
    recipient_email_sha256: inviteRecord.recipient_email_sha256,
    preview_manifest_sha256: inviteRecord.preview_manifest_sha256,
    suppression_receipt_sha256: suppression.suppression_receipt_sha256,
    suppression_status: suppression.suppression_status,
    suppressed_at: suppression.suppressed_at,
  };
  await bindReviewInviteEmailSuppression(store, binding,
    signReviewEmailSuppressionBinding(binding, env), env);
  await removePendingEntry(store, outboxRecord.outbox_hmac_sha256, env, now);
  throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_SUPPRESSED');
}

export async function reserveReviewEmailSend(store, input, env = process.env, adapters = {}) {
  const configuration = requireOutbox(env);
  exactKeys(input, ['invite_token', 'recipient_email'], 'Review email send reservation');
  if (!TOKEN.test(String(input.invite_token || ''))) throw new TypeError('Review invite token is invalid.');
  const recipientEmail = normalizeRecipientEmail(input.recipient_email);
  const recipientSha = sha256Hex(recipientEmail);
  const inviteHmacSha = reviewInviteHmac(input.invite_token, env);
  const id = outboxHmac(inviteHmacSha, env);
  const now = adapters.clock?.() || new Date();

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const entry = await readOutboxEntry(store, id, env);
    if (entry.record.invite_hmac_sha256 !== inviteHmacSha || entry.record.recipient_email_sha256 !== recipientSha) {
      throw new Error('ARC_REVIEW_EMAIL_SEND_BINDING_INVALID');
    }
    if (Date.parse(entry.record.expires_at) <= now.getTime()) throw new Error('ARC_REVIEW_EMAIL_OUTBOX_EXPIRED');
    const invite = await readReviewInviteForEmail(store, inviteHmacSha, env);
    if (invite.record.recipient_email_sha256 !== recipientSha ||
        invite.record.preview_manifest_sha256 !== entry.record.preview_manifest_sha256) {
      throw new Error('ARC_REVIEW_EMAIL_SEND_BINDING_INVALID');
    }
    await ensurePendingEntry(store, entry.record, undefined, env, now);
    if (invite.record.state === 'REVOKED' || invite.record.email_suppression_receipt_sha256 !== null ||
        invite.record.email_delivery_receipt_sha256 !== null) {
      throw new Error('ARC_REVIEW_EMAIL_SEND_FINALIZED');
    }
    await guardReviewEmailSend(store, invite.record, entry.record, env, now);
    if (entry.record.state === 'SEND_RESERVED') {
      const latestInvite = await readReviewInviteForEmail(store, inviteHmacSha, env);
      await guardReviewEmailSend(store, latestInvite.record, entry.record, env, now);
      return sendAuthority(entry.record, input.invite_token, recipientEmail, configuration, env, true);
    }
    if (entry.record.state !== 'READY') throw new Error('ARC_REVIEW_EMAIL_SEND_FINALIZED');
    if (invite.record.state !== 'OPEN') {
      throw new Error('ARC_REVIEW_EMAIL_SEND_BINDING_INVALID');
    }
    const idempotencyKey = providerIdempotencyKey(id, env);
    const reserved = signOutbox({
      ...unsignedOutbox(entry.record),
      record_revision: entry.record.record_revision + 1,
      state: 'SEND_RESERVED',
      send_reserved_at: now.toISOString(),
      provider_idempotency_key_sha256: sha256Hex(idempotencyKey),
    }, env);
    const replaced = await store.setJSON(reviewEmailOutboxKey(id), reserved, { onlyIfMatch: entry.etag });
    if (replaced?.modified) {
      const latestInvite = await readReviewInviteForEmail(store, inviteHmacSha, env);
      await guardReviewEmailSend(store, latestInvite.record, reserved, env, now);
      return sendAuthority(reserved, input.invite_token, recipientEmail, configuration, env, false);
    }
    if (attempt === 2) throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
  }
  throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
}

// Durable discovery is intentionally authority-only: it returns HMAC/source
// references, never a token, email address, or URL. The internal worker must
// resolve those ephemeral values from its authoritative source before reserve,
// or obtain a fresh reservation and call the renewal form of prepare.
export async function claimNextReviewEmail(store, env = process.env, adapters = {}) {
  requireOutbox(env);
  const nowValue = adapters.clock?.() || new Date();
  const now = nowValue instanceof Date ? new Date(nowValue.getTime()) : new Date(nowValue);
  if (!Number.isFinite(now.getTime())) throw new TypeError('Review email pending clock is invalid.');
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const pending = await readPendingEntry(store, env);
    if (!pending || pending.record.entries.length === 0) return { found: false };
    let removedTerminal = false;
    let deferredRecovery = null;
    for (const job of pending.record.entries) {
      const [outbox, invite] = await Promise.all([
        readOutboxEntry(store, job.outbox_hmac_sha256, env),
        readReviewInviteForEmail(store, job.invite_hmac_sha256, env),
      ]);
      if (outbox.record.invite_hmac_sha256 !== job.invite_hmac_sha256 ||
          outbox.record.recipient_email_sha256 !== job.recipient_email_sha256 ||
          invite.record.recipient_email_sha256 !== job.recipient_email_sha256 ||
          invite.record.preview_manifest_sha256 !== outbox.record.preview_manifest_sha256) {
        throw new Error('ARC_REVIEW_EMAIL_PENDING_BINDING_INVALID');
      }
      if (TERMINAL_STATES.has(outbox.record.state) || invite.record.state === 'REVOKED' ||
          invite.record.email_suppression_receipt_sha256 !== null) {
        await removePendingEntry(store, job.outbox_hmac_sha256, env, now);
        removedTerminal = true;
        break;
      }
      if (['READY', 'SEND_RESERVED', 'RECEIPT_BOUND'].includes(outbox.record.state)) {
        const expired = Date.parse(outbox.record.expires_at) <= now.getTime();
        const candidate = {
          found: true,
          state: outbox.record.state,
          invite_hmac_sha256: job.invite_hmac_sha256,
          outbox_hmac_sha256: job.outbox_hmac_sha256,
          recipient_email_sha256: job.recipient_email_sha256,
          preview_manifest_sha256: outbox.record.preview_manifest_sha256,
          source_reference_hmac_sha256: job.source_reference_hmac_sha256,
          expires_at: outbox.record.expires_at,
          renewal_required: outbox.record.state === 'READY' && expired,
          reconciliation_required: outbox.record.state !== 'READY' && expired,
        };
        // READY work always outranks an already-reserved message awaiting a
        // provider retry/webhook, so one delayed receipt cannot starve every
        // later unsent preview. Reserved recovery is still returned once no
        // READY entry remains.
        if (outbox.record.state === 'READY') return candidate;
        deferredRecovery ||= candidate;
      }
    }
    if (!removedTerminal) return deferredRecovery || { found: false };
  }
  throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
}

function normalizeReceipt(raw, signature, env) {
  if (typeof raw !== 'string' || raw.length < 2 || raw.length > 20_000) {
    throw new TypeError('Review email receipt evidence is invalid.');
  }
  let value;
  try { value = JSON.parse(raw); } catch { throw new TypeError('Review email receipt evidence is invalid.'); }
  exactKeys(value, RECEIPT_FIELDS, 'Review email receipt');
  if (canonicalJson(value) !== raw || value.schema !== REVIEW_EMAIL_RECEIPT_SCHEMA || value.version !== 1) {
    throw new TypeError('Review email receipt fields are invalid.');
  }
  const supplied = hex64(signature, 'Review email receipt signature');
  const expected = hmacHex(env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET, RECEIPT_SIGNATURE_PREFIX + raw);
  if (!safeEqual(supplied, expected)) throw new Error('ARC_REVIEW_EMAIL_RECEIPT_SIGNATURE_INVALID');
  hex64(value.outbox_hmac_sha256, 'Review email outbox HMAC');
  hex64(value.invite_hmac_sha256, 'Review email invite HMAC');
  hex64(value.recipient_email_sha256, 'Review email recipient digest');
  hex64(value.preview_manifest_sha256, 'Review email preview manifest digest');
  if (!PROVIDER.test(value.provider)) throw new TypeError('Review email provider is invalid.');
  hex64(value.provider_account_hmac_sha256, 'Review email provider account HMAC');
  for (const field of ['provider_event_id', 'provider_message_id']) {
    if (typeof value[field] !== 'string' || value[field].length < 1 || value[field].length > 512 ||
        value[field] !== value[field].trim() || /[\u0000-\u001f\u007f]/.test(value[field])) {
      throw new TypeError('Review email provider identity is invalid.');
    }
  }
  if (STATUS_TO_EVENT[value.delivery_status] !== value.event_type) {
    throw new TypeError('Review email receipt status is invalid.');
  }
  isoTimestamp(value.event_at, 'Review email event timestamp');
  isoTimestamp(value.issued_at, 'Review email receipt timestamp');
  const identityBase = { provider: value.provider, provider_account_hmac_sha256: value.provider_account_hmac_sha256 };
  return {
    digest: sha256Hex(raw),
    providerEventHmac: hmacHex(env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET,
      PROVIDER_EVENT_ID_PREFIX + canonicalJson({ ...identityBase, provider_event_id: value.provider_event_id })),
    providerMessageHmac: hmacHex(env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET,
      PROVIDER_MESSAGE_ID_PREFIX + canonicalJson({ ...identityBase, provider_message_id: value.provider_message_id })),
    targetState: STATUS_TO_STATE[value.delivery_status],
    value,
  };
}

function receiptMutation(receipt) {
  const mutation = {
    delivery_receipt_sha256: receipt.digest,
    provider: receipt.value.provider,
    provider_account_hmac_sha256: receipt.value.provider_account_hmac_sha256,
    provider_event_id_hmac_sha256: receipt.providerEventHmac,
    provider_message_id_hmac_sha256: receipt.providerMessageHmac,
    event_type: receipt.value.event_type,
    delivery_status: receipt.value.delivery_status,
    event_at: receipt.value.event_at,
    receipt_issued_at: receipt.value.issued_at,
  };
  if (receipt.value.delivery_status === 'delivered') {
    return {
      ...mutation,
      delivered_receipt_sha256: receipt.digest,
      suppression_receipt_sha256: null,
      suppression_status: null,
      suppressed_at: null,
    };
  }
  return {
    ...mutation,
    suppression_receipt_sha256: receipt.digest,
    suppression_status: receipt.value.delivery_status,
    suppressed_at: receipt.value.event_at,
  };
}

function receiptMatches(record, receipt) {
  const mutation = receiptMutation(receipt);
  return Object.entries(mutation).every(([field, value]) => record[field] === value);
}

function assertReceiptBinding(record, receipt) {
  const value = receipt.value;
  if (record.outbox_hmac_sha256 !== value.outbox_hmac_sha256 ||
      record.invite_hmac_sha256 !== value.invite_hmac_sha256 ||
      record.recipient_email_sha256 !== value.recipient_email_sha256 ||
      record.preview_manifest_sha256 !== value.preview_manifest_sha256) {
    throw new Error('ARC_REVIEW_EMAIL_RECEIPT_BINDING_INVALID');
  }
}

function assertFreshReceipt(record, receipt, now) {
  const eventAt = Date.parse(receipt.value.event_at);
  const issuedAt = Date.parse(receipt.value.issued_at);
  const reservedAt = Date.parse(record.send_reserved_at);
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || eventAt < reservedAt || eventAt > issuedAt ||
      issuedAt - eventAt > REVIEW_EMAIL_RECEIPT_FRESHNESS_MS || issuedAt > nowMs + 60_000 ||
      issuedAt < nowMs - REVIEW_EMAIL_RECEIPT_FRESHNESS_MS) {
    throw new Error('ARC_REVIEW_EMAIL_RECEIPT_STALE');
  }
}

function receiptPriority(state) {
  if (state === 'COMPLAINED') return 3;
  if (state === 'BOUNCED') return 2;
  if (state === 'DELIVERED') return 1;
  return 0;
}

function suppressedDeliveryReplay(record, receipt) {
  return ['BOUNCED', 'COMPLAINED'].includes(record.state) && receipt.targetState === 'DELIVERED' &&
    record.delivered_receipt_sha256 === receipt.digest;
}

function assertReceiptTransitionAllowed(record, receipt, now, freshnessAlreadyBound = false) {
  assertReceiptBinding(record, receipt);
  if (record.state === 'READY') throw new Error('ARC_REVIEW_EMAIL_SEND_NOT_RESERVED');
  if (record.state === 'SEND_RESERVED') {
    if (!freshnessAlreadyBound) assertFreshReceipt(record, receipt, now);
    return;
  }
  if (record.state === 'RECEIPT_BOUND') {
    if (!receiptMatches(record, receipt)) throw new Error('ARC_REVIEW_EMAIL_RECEIPT_CONFLICT');
    return;
  }
  if (!TERMINAL_STATES.has(record.state)) throw new Error('ARC_REVIEW_EMAIL_RECEIPT_CONFLICT');
  if (record.state === receipt.targetState && receiptMatches(record, receipt)) return;
  if (suppressedDeliveryReplay(record, receipt)) return;
  const escalation = receipt.targetState !== 'DELIVERED' &&
    receiptPriority(receipt.targetState) > receiptPriority(record.state);
  if (!escalation) throw new Error('ARC_REVIEW_EMAIL_RECEIPT_CONFLICT');
  if (!freshnessAlreadyBound) assertFreshReceipt(record, receipt, now);
}

function identityReservations(record, receipt) {
  const common = {
    schema: 'arc-preview-review-email-provider-identity-v1',
    outbox_hmac_sha256: record.outbox_hmac_sha256,
    provider: receipt.value.provider,
    provider_account_hmac_sha256: receipt.value.provider_account_hmac_sha256,
  };
  return [{
    key: `review-email-provider-event/${receipt.providerEventHmac}`,
    value: {
      ...common,
      kind: 'provider-event',
      identity_hmac_sha256: receipt.providerEventHmac,
      delivery_receipt_sha256: receipt.digest,
    },
  }, {
    key: `review-email-provider-message/${receipt.providerMessageHmac}`,
    value: { ...common, kind: 'provider-message', identity_hmac_sha256: receipt.providerMessageHmac },
  }];
}

async function inspectIdentityReservations(store, reservations) {
  for (const reservation of reservations) {
    const entry = await store.getWithMetadata(reservation.key, { type: 'json', consistency: 'strong' });
    if (entry && canonicalJson(entry.data) !== canonicalJson(reservation.value)) {
      throw new Error('ARC_REVIEW_EMAIL_PROVIDER_IDENTITY_CONFLICT');
    }
  }
}

async function ensureIdentityReservation(store, reservation) {
  const created = await store.setJSON(reservation.key, reservation.value, { onlyIfNew: true });
  if (created?.modified) return;
  const entry = await store.getWithMetadata(reservation.key, { type: 'json', consistency: 'strong' });
  if (!entry || canonicalJson(entry.data) !== canonicalJson(reservation.value)) {
    throw new Error('ARC_REVIEW_EMAIL_PROVIDER_IDENTITY_CONFLICT');
  }
}

async function latchReceipt(store, outboxId, receipt, env, now, freshnessAlreadyBound = false) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const entry = await readOutboxEntry(store, outboxId, env);
    assertReceiptBinding(entry.record, receipt);
    if (entry.record.state === 'READY') throw new Error('ARC_REVIEW_EMAIL_SEND_NOT_RESERVED');
    const escalation = TERMINAL_STATES.has(entry.record.state) && receipt.targetState !== 'DELIVERED' &&
      receiptPriority(receipt.targetState) > receiptPriority(entry.record.state);
    if (entry.record.state === 'SEND_RESERVED' || escalation) {
      if (!freshnessAlreadyBound) assertFreshReceipt(entry.record, receipt, now);
      const mutation = receiptMutation(receipt);
      if (entry.record.delivered_receipt_sha256 !== null && receipt.targetState !== 'DELIVERED') {
        mutation.delivered_receipt_sha256 = entry.record.delivered_receipt_sha256;
      }
      const pending = signOutbox({
        ...unsignedOutbox(entry.record),
        record_revision: entry.record.record_revision + 1,
        state: 'RECEIPT_BOUND',
        ...mutation,
        terminal_at: null,
      }, env);
      const replaced = await store.setJSON(reviewEmailOutboxKey(outboxId), pending, { onlyIfMatch: entry.etag });
      if (replaced?.modified) return { already_terminal: false, entry: { record: pending, etag: replaced.etag } };
      if (attempt === 2) throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
      continue;
    }
    if (!receiptMatches(entry.record, receipt)) throw new Error('ARC_REVIEW_EMAIL_RECEIPT_CONFLICT');
    if (entry.record.state === 'RECEIPT_BOUND') return { already_terminal: false, entry };
    if (TERMINAL_STATES.has(entry.record.state) && entry.record.state === receipt.targetState) {
      return { already_terminal: true, entry };
    }
    throw new Error('ARC_REVIEW_EMAIL_RECEIPT_CONFLICT');
  }
  throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
}

async function terminalizeReceipt(store, outboxId, receipt, env, now) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const entry = await readOutboxEntry(store, outboxId, env);
    assertReceiptBinding(entry.record, receipt);
    if (TERMINAL_STATES.has(entry.record.state)) {
      if (entry.record.state !== receipt.targetState || !receiptMatches(entry.record, receipt)) {
        throw new Error('ARC_REVIEW_EMAIL_RECEIPT_CONFLICT');
      }
      return { idempotent_replay: true, record: entry.record };
    }
    if (entry.record.state !== 'RECEIPT_BOUND' || !receiptMatches(entry.record, receipt)) {
      throw new Error('ARC_REVIEW_EMAIL_RECEIPT_CONFLICT');
    }
    const terminal = signOutbox({
      ...unsignedOutbox(entry.record),
      record_revision: entry.record.record_revision + 1,
      state: receipt.targetState,
      terminal_at: now.toISOString(),
    }, env);
    const replaced = await store.setJSON(reviewEmailOutboxKey(outboxId), terminal, { onlyIfMatch: entry.etag });
    if (replaced?.modified) return { idempotent_replay: false, record: terminal };
    if (attempt === 2) throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
  }
  throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
}

export async function acknowledgeReviewEmailReceipt(store, evidence, signature, env = process.env, adapters = {}) {
  requireOutbox(env);
  const receipt = normalizeReceipt(evidence, signature, env);
  const now = adapters.clock?.() || new Date();
  const initial = await readOutboxEntry(store, receipt.value.outbox_hmac_sha256, env);
  assertReceiptBinding(initial.record, receipt);
  if (suppressedDeliveryReplay(initial.record, receipt)) {
    return {
      delivery_status: initial.record.delivery_status,
      idempotent_replay: true,
      outbox_hmac_sha256: initial.record.outbox_hmac_sha256,
      state: initial.record.state,
    };
  }
  if (receipt.targetState === 'DELIVERED') {
    const globalSuppression = await readRecipientSuppressionEntry(store,
      initial.record.recipient_email_sha256, env);
    if (globalSuppression) {
      const invite = await readReviewInviteForEmail(store, initial.record.invite_hmac_sha256, env);
      const binding = {
        schema: REVIEW_EMAIL_SUPPRESSION_BINDING_SCHEMA,
        invite_hmac_sha256: invite.record.invite_hmac_sha256,
        outbox_hmac_sha256: initial.record.outbox_hmac_sha256,
        source_outbox_hmac_sha256: globalSuppression.record.source_outbox_hmac_sha256,
        recipient_email_sha256: invite.record.recipient_email_sha256,
        preview_manifest_sha256: invite.record.preview_manifest_sha256,
        suppression_receipt_sha256: globalSuppression.record.suppression_receipt_sha256,
        suppression_status: globalSuppression.record.suppression_status,
        suppressed_at: globalSuppression.record.suppressed_at,
      };
      await bindReviewInviteEmailSuppression(store, binding,
        signReviewEmailSuppressionBinding(binding, env), env);
      await removePendingEntry(store, initial.record.outbox_hmac_sha256, env, now);
      throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_SUPPRESSED');
    }
  }
  let suppression = null;
  let recipientSuppression = null;
  let suppressionAlreadyBound = false;
  if (receipt.targetState !== 'DELIVERED') {
    suppression = {
      schema: REVIEW_EMAIL_SUPPRESSION_BINDING_SCHEMA,
      invite_hmac_sha256: initial.record.invite_hmac_sha256,
      outbox_hmac_sha256: initial.record.outbox_hmac_sha256,
      source_outbox_hmac_sha256: initial.record.outbox_hmac_sha256,
      recipient_email_sha256: initial.record.recipient_email_sha256,
      preview_manifest_sha256: initial.record.preview_manifest_sha256,
      suppression_receipt_sha256: receipt.digest,
      suppression_status: receipt.value.delivery_status,
      suppressed_at: receipt.value.event_at,
    };
    recipientSuppression = {
      recipient_email_sha256: initial.record.recipient_email_sha256,
      suppression_receipt_sha256: receipt.digest,
      suppression_status: receipt.value.delivery_status,
      suppressed_at: receipt.value.event_at,
      source_invite_hmac_sha256: initial.record.invite_hmac_sha256,
      source_outbox_hmac_sha256: initial.record.outbox_hmac_sha256,
    };
    const [invite, storedSuppression, recipientControl] = await Promise.all([
      readReviewInviteForEmail(store, initial.record.invite_hmac_sha256, env),
      readRecipientSuppressionEntry(store, initial.record.recipient_email_sha256, env),
      readReviewEmailRecipientControl(store, initial.record.recipient_email_sha256, env),
    ]);
    const inviteBound = invite.record.email_suppression_receipt_sha256 === suppression.suppression_receipt_sha256 &&
      invite.record.email_suppression_source_outbox_hmac_sha256 === suppression.source_outbox_hmac_sha256 &&
      invite.record.email_suppression_status === suppression.suppression_status &&
      invite.record.email_suppressed_at === suppression.suppressed_at;
    const globalBound = Boolean(storedSuppression &&
      sameRecipientSuppression(storedSuppression.record, recipientSuppression));
    const controlBound = Boolean(recipientControl &&
      recipientControl.record.recipient_email_sha256 === recipientSuppression.recipient_email_sha256 &&
      recipientControl.record.suppression_receipt_sha256 === recipientSuppression.suppression_receipt_sha256 &&
      recipientControl.record.suppression_status === recipientSuppression.suppression_status &&
      recipientControl.record.suppressed_at === recipientSuppression.suppressed_at &&
      recipientControl.record.source_invite_hmac_sha256 === recipientSuppression.source_invite_hmac_sha256 &&
      recipientControl.record.source_outbox_hmac_sha256 === recipientSuppression.source_outbox_hmac_sha256);
    // Only the exact authenticated receipt may reuse a durable first-
    // observation latch after freshness. A different provider event, message,
    // timestamp, or source must pass normal freshness checks even when this
    // recipient is already suppressed for another event.
    suppressionAlreadyBound = inviteBound || globalBound || controlBound;
  }
  assertReceiptTransitionAllowed(initial.record, receipt, now, suppressionAlreadyBound);
  const reservations = identityReservations(initial.record, receipt);
  await inspectIdentityReservations(store, reservations);

  let suppressionReplay = true;
  let recipientSuppressionReplay = true;
  if (receipt.targetState !== 'DELIVERED') {
    // Attach the signed suppression to the recipient control before touching
    // provider state. If an authority lease is active, the owner observes the
    // pending evidence and must revoke any Session before it can release.
    const controlled = await suppressReviewEmailRecipientControl(store,
      recipientSuppression, env, now);
    await expireRecipientCheckoutsBeforeSuppression(store, recipientSuppression, env, adapters);
    if (controlled.pending) {
      throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_AUTHORITY_CONTENTION');
    }
    // Only after every known provider Checkout is durably expired may the
    // legacy global latch, invite revocation, and outbox terminal receipt
    // converge. This makes webhook retry the crash-recovery mechanism.
    const recipientBound = await bindRecipientSuppression(store, recipientSuppression, env, now);
    recipientSuppressionReplay = recipientBound.idempotent_replay;
    const bound = await bindReviewInviteEmailSuppression(store, suppression,
      signReviewEmailSuppressionBinding(suppression, env), env);
    suppressionReplay = bound.idempotent_replay;
  }

  // RECEIPT_BOUND is the durable no-resend latch. Once it exists, exact
  // retries may converge after the first-observation freshness window.
  const latched = await latchReceipt(store, initial.record.outbox_hmac_sha256, receipt, env, now,
    suppressionAlreadyBound);
  for (const reservation of reservations) await ensureIdentityReservation(store, reservation);
  const terminal = await terminalizeReceipt(store, initial.record.outbox_hmac_sha256, receipt, env, now);

  let inviteReplay = true;
  if (receipt.targetState === 'DELIVERED') {
    const binding = {
      schema: REVIEW_EMAIL_DELIVERY_BINDING_SCHEMA,
      invite_hmac_sha256: terminal.record.invite_hmac_sha256,
      outbox_hmac_sha256: terminal.record.outbox_hmac_sha256,
      recipient_email_sha256: terminal.record.recipient_email_sha256,
      preview_manifest_sha256: terminal.record.preview_manifest_sha256,
      delivery_receipt_sha256: terminal.record.delivery_receipt_sha256,
      delivery_status: 'delivered',
    };
    const bound = await bindReviewInviteDeliveryReceipt(store, binding,
      signReviewEmailDeliveryBinding(binding, env), env);
    inviteReplay = bound.idempotent_replay;
  }
  await removePendingEntry(store, terminal.record.outbox_hmac_sha256, env, now);
  return {
    delivery_status: receipt.value.delivery_status,
    idempotent_replay: latched.already_terminal && terminal.idempotent_replay && inviteReplay &&
      suppressionReplay && recipientSuppressionReplay,
    outbox_hmac_sha256: terminal.record.outbox_hmac_sha256,
    state: terminal.record.state,
  };
}

export const reviewEmailReceiptContract = Object.freeze({
  fields: RECEIPT_FIELDS,
  schema: REVIEW_EMAIL_RECEIPT_SCHEMA,
  signaturePrefix: RECEIPT_SIGNATURE_PREFIX,
  version: 1,
});
