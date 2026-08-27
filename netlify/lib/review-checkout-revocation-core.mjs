import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const REVIEW_CHECKOUT_BINDING_SCHEMA = 'arc-review-checkout-revocable-binding-v1';
export const REVIEW_CHECKOUT_RECIPIENT_INDEX_SCHEMA = 'arc-review-checkout-recipient-index-v1';
export const REVIEW_CHECKOUT_REVOCATION_ALERT_SCHEMA = 'arc-review-checkout-revocation-alert-v1';

const BINDING_ID_PREFIX = 'arc-review-checkout-revocable-binding-id-v1\n';
const BINDING_SIGNATURE_PREFIX = 'arc-review-checkout-revocable-binding-signature-v1\n';
const INDEX_ID_PREFIX = 'arc-review-checkout-recipient-index-id-v1\n';
const INDEX_SIGNATURE_PREFIX = 'arc-review-checkout-recipient-index-signature-v1\n';
const EXPIRY_IDEMPOTENCY_PREFIX = 'arc-review-checkout-expiry-idempotency-v1\n';
const ALERT_ID_PREFIX = 'arc-review-checkout-revocation-alert-id-v1\n';
const ALERT_SIGNATURE_PREFIX = 'arc-review-checkout-revocation-alert-signature-v1\n';
const HEX_64 = /^[a-f0-9]{64}$/;
const SESSION_ID = /^cs_(?:test|live)_[A-Za-z0-9_]{6,128}$/;
const INTEGRATION_IDENTIFIER = /^arc_review_checkout_[a-z]{8}$/;
const MAX_BINDINGS_PER_RECIPIENT = 16;
const MAX_CAS_ATTEMPTS = 8;
const STATES = new Set(['CREATING', 'OPEN', 'EXPIRY_PENDING', 'EXPIRED', 'CANCELLED', 'REVIEW_REQUIRED']);
const BINDING_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'state', 'binding_hmac_sha256',
  'approval_receipt_sha256', 'approval_receipt_hmac_sha256', 'invite_hmac_sha256',
  'preview_manifest_sha256', 'recipient_email_sha256', 'scope_version', 'session_id',
  'session_livemode', 'integration_identifier', 'session_url_sha256', 'created_at', 'session_bound_at',
  'suppression_receipt_sha256', 'suppression_status', 'suppressed_at',
  'source_invite_hmac_sha256', 'source_outbox_hmac_sha256', 'expiry_idempotency_key_sha256',
  'expiry_requested_at', 'expired_at', 'provider_status', 'provider_payment_status',
  'fulfillment_halted', 'alert_code', 'record_hmac_sha256',
]);
const INDEX_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'recipient_index_hmac_sha256',
  'recipient_email_sha256', 'bindings', 'updated_at', 'record_hmac_sha256',
]);
const INDEX_ENTRY_FIELDS = Object.freeze(['approval_receipt_sha256', 'binding_hmac_sha256']);
const RESERVATION_FIELDS = Object.freeze([
  'approval_receipt_hmac_sha256', 'approval_receipt_sha256', 'invite_hmac_sha256',
  'preview_manifest_sha256', 'recipient_email_sha256', 'scope_version',
]);
const SESSION_FIELDS = Object.freeze(['id', 'integration_identifier', 'livemode', 'url']);
const SUPPRESSION_FIELDS = Object.freeze([
  'recipient_email_sha256', 'source_invite_hmac_sha256', 'source_outbox_hmac_sha256',
  'suppressed_at', 'suppression_receipt_sha256', 'suppression_status',
]);
const ALERT_FIELDS = Object.freeze([
  'schema', 'version', 'alert_hmac_sha256', 'binding_hmac_sha256', 'approval_receipt_sha256',
  'recipient_email_sha256', 'session_id', 'suppression_receipt_sha256', 'suppression_status',
  'provider_status', 'provider_payment_status', 'alert_code', 'created_at', 'record_hmac_sha256',
]);

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const output = JSON.stringify(value);
  if (output === undefined) throw new TypeError('Canonical JSON does not support undefined.');
  return output;
}

function hmac(secret, value) {
  return createHmac('sha256', secret).update(value).digest('hex');
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw new TypeError(`${label} fields are invalid.`);
  }
}

function hex64(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function nullableHex64(value, label) {
  if (value === null) return null;
  return hex64(value, label);
}

function iso(value, label) {
  if (typeof value !== 'string' || value.length < 20 || value.length > 32 ||
      new Date(value).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return value;
}

function nowDate(value) {
  const now = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(now.getTime())) throw new TypeError('Review Checkout revocation clock is invalid.');
  return now;
}

function validSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}

export function reviewCheckoutRevocationConfiguration(env = process.env) {
  const flagValid = env.ARC_STRIPE_REVIEW_REVOCATION_ENABLED === 'true' ||
    env.ARC_STRIPE_REVIEW_REVOCATION_ENABLED === 'false';
  const secret = env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET;
  const related = [
    env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET,
    env.ARC_REVIEW_DECISION_HMAC_SECRET,
    env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
    env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET,
  ];
  const secretValid = validSecret(secret) && !related.includes(secret);
  return Object.freeze({
    enabled: flagValid && env.ARC_STRIPE_REVIEW_REVOCATION_ENABLED === 'true' && secretValid &&
      env.ARC_REVIEW_EMAIL_OUTBOX_ENABLED === 'true',
    flagValid,
    secretValid,
  });
}

function secret(env) {
  const configuration = reviewCheckoutRevocationConfiguration(env);
  if (!configuration.enabled) throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_DISABLED');
  return env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET;
}

function bindingHmac(approvalReceiptSha256, env) {
  return hmac(secret(env), BINDING_ID_PREFIX + hex64(approvalReceiptSha256, 'Approval receipt digest'));
}

function recipientIndexHmac(recipientEmailSha256, env) {
  return hmac(secret(env), INDEX_ID_PREFIX + hex64(recipientEmailSha256, 'Recipient digest'));
}

export function reviewCheckoutBindingKey(bindingHmacSha256) {
  return `review-checkout-binding/${hex64(bindingHmacSha256, 'Review Checkout binding HMAC')}`;
}

export function reviewCheckoutRecipientIndexKey(indexHmacSha256) {
  return `review-checkout-recipient-index/${hex64(indexHmacSha256, 'Review Checkout recipient index HMAC')}`;
}

function unsigned(record) {
  const { record_hmac_sha256: _signature, ...value } = record;
  return value;
}

function signBinding(record, env) {
  const value = unsigned(record);
  return { ...value, record_hmac_sha256: hmac(secret(env), BINDING_SIGNATURE_PREFIX + canonicalJson(value)) };
}

function signIndex(record, env) {
  const value = unsigned(record);
  return { ...value, record_hmac_sha256: hmac(secret(env), INDEX_SIGNATURE_PREFIX + canonicalJson(value)) };
}

function suppressionPriority(value) {
  return value === 'complained' ? 2 : value === 'bounced' ? 1 : 0;
}

function validateSuppression(value, expectedRecipient = null) {
  exactKeys(value, SUPPRESSION_FIELDS, 'Review Checkout suppression');
  for (const field of SUPPRESSION_FIELDS.filter(name => name.endsWith('_sha256'))) hex64(value[field], field);
  if (expectedRecipient !== null && value.recipient_email_sha256 !== expectedRecipient) {
    throw new Error('ARC_REVIEW_CHECKOUT_SUPPRESSION_BINDING_INVALID');
  }
  if (!['bounced', 'complained'].includes(value.suppression_status)) {
    throw new TypeError('Review Checkout suppression status is invalid.');
  }
  iso(value.suppressed_at, 'Review Checkout suppression timestamp');
  return value;
}

function suppressionFromRecord(record) {
  if (record.suppression_receipt_sha256 === null) return null;
  return {
    recipient_email_sha256: record.recipient_email_sha256,
    source_invite_hmac_sha256: record.source_invite_hmac_sha256,
    source_outbox_hmac_sha256: record.source_outbox_hmac_sha256,
    suppressed_at: record.suppressed_at,
    suppression_receipt_sha256: record.suppression_receipt_sha256,
    suppression_status: record.suppression_status,
  };
}

function validateBinding(record, env) {
  exactKeys(record, BINDING_FIELDS, 'Review Checkout revocable binding');
  if (record.schema !== REVIEW_CHECKOUT_BINDING_SCHEMA || record.version !== 1 ||
      !Number.isSafeInteger(record.record_revision) || record.record_revision < 1 || !STATES.has(record.state)) {
    throw new TypeError('Review Checkout revocable binding is invalid.');
  }
  for (const field of BINDING_FIELDS.filter(name => name.endsWith('_sha256') && name !== 'record_hmac_sha256')) {
    nullableHex64(record[field], `Review Checkout ${field}`);
  }
  if (record.binding_hmac_sha256 !== bindingHmac(record.approval_receipt_sha256, env) ||
      record.scope_version !== 'arc-fixed-five-page-offer-v1') {
    throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_BINDING_INVALID');
  }
  iso(record.created_at, 'Review Checkout binding creation time');
  if (record.session_bound_at !== null) iso(record.session_bound_at, 'Review Checkout Session binding time');
  if (record.suppressed_at !== null) iso(record.suppressed_at, 'Review Checkout suppression time');
  if (record.expiry_requested_at !== null) iso(record.expiry_requested_at, 'Review Checkout expiry request time');
  if (record.expired_at !== null) iso(record.expired_at, 'Review Checkout expiry time');
  const hasSession = record.session_id !== null;
  if (hasSession) {
    if (!SESSION_ID.test(record.session_id) || typeof record.session_livemode !== 'boolean' ||
        !INTEGRATION_IDENTIFIER.test(String(record.integration_identifier || '')) ||
        record.session_url_sha256 === null || record.session_bound_at === null) {
      throw new TypeError('Review Checkout Session binding is invalid.');
    }
  } else if ([record.session_livemode, record.integration_identifier, record.session_url_sha256,
    record.session_bound_at].some(value => value !== null)) {
    throw new TypeError('Review Checkout Session binding is invalid.');
  }
  const hasSuppression = record.suppression_receipt_sha256 !== null;
  const suppressionValues = [record.suppression_receipt_sha256, record.suppression_status, record.suppressed_at,
    record.source_invite_hmac_sha256, record.source_outbox_hmac_sha256];
  if (hasSuppression !== suppressionValues.every(value => value !== null)) {
    throw new TypeError('Review Checkout suppression binding is invalid.');
  }
  if (hasSuppression) validateSuppression(suppressionFromRecord(record), record.recipient_email_sha256);
  const expectedShape = {
    CREATING: !hasSession && !hasSuppression && !record.fulfillment_halted,
    OPEN: hasSession && !hasSuppression && record.provider_status === 'open' &&
      record.provider_payment_status === 'unpaid' && !record.fulfillment_halted,
    EXPIRY_PENDING: hasSession && hasSuppression && record.provider_status === 'open' &&
      record.provider_payment_status === 'unpaid' && record.fulfillment_halted &&
      record.expiry_idempotency_key_sha256 !== null && record.expiry_requested_at !== null && record.expired_at === null,
    EXPIRED: hasSession && hasSuppression && record.provider_status === 'expired' &&
      record.provider_payment_status === 'unpaid' && record.fulfillment_halted && record.expired_at !== null,
    CANCELLED: !hasSession && hasSuppression && record.fulfillment_halted,
    REVIEW_REQUIRED: hasSession && hasSuppression && record.fulfillment_halted &&
      record.alert_code === 'REFUND_REVIEW_REQUIRED',
  }[record.state];
  if (!expectedShape || (record.state !== 'REVIEW_REQUIRED' && record.alert_code !== null) ||
      (['CREATING', 'OPEN', 'CANCELLED'].includes(record.state) &&
        [record.expiry_idempotency_key_sha256, record.expiry_requested_at, record.expired_at]
          .some(value => value !== null))) {
    throw new TypeError('Review Checkout revocation state is invalid.');
  }
  hex64(record.record_hmac_sha256, 'Review Checkout record signature');
  const expected = hmac(secret(env), BINDING_SIGNATURE_PREFIX + canonicalJson(unsigned(record)));
  if (!safeEqual(expected, record.record_hmac_sha256)) {
    throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_SIGNATURE_INVALID');
  }
  return record;
}

function validateIndex(record, env) {
  exactKeys(record, INDEX_FIELDS, 'Review Checkout recipient index');
  if (record.schema !== REVIEW_CHECKOUT_RECIPIENT_INDEX_SCHEMA || record.version !== 1 ||
      !Number.isSafeInteger(record.record_revision) || record.record_revision < 1 ||
      !Array.isArray(record.bindings) || record.bindings.length > MAX_BINDINGS_PER_RECIPIENT) {
    throw new TypeError('Review Checkout recipient index is invalid.');
  }
  hex64(record.recipient_email_sha256, 'Review Checkout recipient digest');
  if (record.recipient_index_hmac_sha256 !== recipientIndexHmac(record.recipient_email_sha256, env)) {
    throw new Error('ARC_REVIEW_CHECKOUT_RECIPIENT_INDEX_BINDING_INVALID');
  }
  let prior = '';
  for (const entry of record.bindings) {
    exactKeys(entry, INDEX_ENTRY_FIELDS, 'Review Checkout recipient index entry');
    hex64(entry.approval_receipt_sha256, 'Review Checkout indexed approval');
    hex64(entry.binding_hmac_sha256, 'Review Checkout indexed binding');
    if (entry.binding_hmac_sha256 !== bindingHmac(entry.approval_receipt_sha256, env) ||
        entry.approval_receipt_sha256 <= prior) throw new TypeError('Review Checkout recipient index is invalid.');
    prior = entry.approval_receipt_sha256;
  }
  iso(record.updated_at, 'Review Checkout recipient index update time');
  hex64(record.record_hmac_sha256, 'Review Checkout recipient index signature');
  const expected = hmac(secret(env), INDEX_SIGNATURE_PREFIX + canonicalJson(unsigned(record)));
  if (!safeEqual(expected, record.record_hmac_sha256)) {
    throw new Error('ARC_REVIEW_CHECKOUT_RECIPIENT_INDEX_SIGNATURE_INVALID');
  }
  return record;
}

async function readBindingEntry(store, bindingId, env) {
  const entry = await store.getWithMetadata(reviewCheckoutBindingKey(bindingId),
    { type: 'json', consistency: 'strong' });
  return entry ? { record: validateBinding(entry.data, env), etag: entry.etag } : null;
}

async function readIndexEntry(store, recipientEmailSha256, env) {
  const id = recipientIndexHmac(recipientEmailSha256, env);
  const entry = await store.getWithMetadata(reviewCheckoutRecipientIndexKey(id),
    { type: 'json', consistency: 'strong' });
  return entry ? { record: validateIndex(entry.data, env), etag: entry.etag } : null;
}

async function ensureIndex(store, input, env, now) {
  const id = recipientIndexHmac(input.recipient_email_sha256, env);
  const desired = {
    approval_receipt_sha256: input.approval_receipt_sha256,
    binding_hmac_sha256: bindingHmac(input.approval_receipt_sha256, env),
  };
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
    const entry = await readIndexEntry(store, input.recipient_email_sha256, env);
    if (entry?.record.bindings.some(value => value.approval_receipt_sha256 === desired.approval_receipt_sha256)) {
      const existing = entry.record.bindings.find(value => value.approval_receipt_sha256 === desired.approval_receipt_sha256);
      if (existing.binding_hmac_sha256 !== desired.binding_hmac_sha256) {
        throw new Error('ARC_REVIEW_CHECKOUT_RECIPIENT_INDEX_CONFLICT');
      }
      return entry.record;
    }
    const bindings = [...(entry?.record.bindings || []), desired]
      .sort((left, right) => left.approval_receipt_sha256.localeCompare(right.approval_receipt_sha256));
    if (bindings.length > MAX_BINDINGS_PER_RECIPIENT) throw new Error('ARC_REVIEW_CHECKOUT_RECIPIENT_INDEX_FULL');
    const record = signIndex({
      schema: REVIEW_CHECKOUT_RECIPIENT_INDEX_SCHEMA,
      version: 1,
      record_revision: (entry?.record.record_revision || 0) + 1,
      recipient_index_hmac_sha256: id,
      recipient_email_sha256: input.recipient_email_sha256,
      bindings,
      updated_at: now.toISOString(),
    }, env);
    const result = await store.setJSON(reviewCheckoutRecipientIndexKey(id), record,
      entry ? { onlyIfMatch: entry.etag } : { onlyIfNew: true });
    if (result?.modified) return record;
  }
  throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_CONTENTION');
}

function immutableReservation(record) {
  return Object.fromEntries(RESERVATION_FIELDS.map(field => [field, record[field]]));
}

export async function reserveReviewCheckoutBinding(store, rawInput, env = process.env, nowValue = new Date()) {
  exactKeys(rawInput, RESERVATION_FIELDS, 'Review Checkout binding reservation');
  for (const field of RESERVATION_FIELDS.filter(name => name.endsWith('_sha256'))) hex64(rawInput[field], field);
  if (rawInput.scope_version !== 'arc-fixed-five-page-offer-v1') {
    throw new TypeError('Review Checkout scope is invalid.');
  }
  const now = nowDate(nowValue);
  const input = { ...rawInput };
  const id = bindingHmac(input.approval_receipt_sha256, env);
  const record = signBinding({
    schema: REVIEW_CHECKOUT_BINDING_SCHEMA,
    version: 1,
    record_revision: 1,
    state: 'CREATING',
    binding_hmac_sha256: id,
    ...input,
    session_id: null,
    session_livemode: null,
    integration_identifier: null,
    session_url_sha256: null,
    created_at: now.toISOString(),
    session_bound_at: null,
    suppression_receipt_sha256: null,
    suppression_status: null,
    suppressed_at: null,
    source_invite_hmac_sha256: null,
    source_outbox_hmac_sha256: null,
    expiry_idempotency_key_sha256: null,
    expiry_requested_at: null,
    expired_at: null,
    provider_status: null,
    provider_payment_status: null,
    fulfillment_halted: false,
    alert_code: null,
  }, env);
  const created = await store.setJSON(reviewCheckoutBindingKey(id), record, { onlyIfNew: true });
  let durable = record;
  if (!created?.modified) {
    const existing = await readBindingEntry(store, id, env);
    if (!existing || canonicalJson(immutableReservation(existing.record)) !== canonicalJson(input)) {
      throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_CONFLICT');
    }
    durable = existing.record;
  }
  // Publish the recipient lookup only after its target exists. A crash before
  // this write leaves an unindexed CREATING record with no provider Session;
  // retry can safely converge the index. The reverse ordering could leave a
  // permanent index -> missing-binding reference that suppression could never
  // repair after the recipient control became terminal.
  await ensureIndex(store, input, env, now);
  return durable;
}

function sessionProjection(value) {
  exactKeys(value, SESSION_FIELDS, 'Review Checkout Session projection');
  if (!SESSION_ID.test(String(value.id || '')) || typeof value.livemode !== 'boolean' ||
      !INTEGRATION_IDENTIFIER.test(String(value.integration_identifier || ''))) {
    throw new TypeError('Review Checkout Session projection is invalid.');
  }
  let url;
  try { url = new URL(value.url); } catch { throw new TypeError('Review Checkout Session URL is invalid.'); }
  if (url.protocol !== 'https:' || url.origin !== 'https://checkout.stripe.com' || url.username || url.password) {
    throw new TypeError('Review Checkout Session URL is invalid.');
  }
  return { id: value.id, livemode: value.livemode, integration_identifier: value.integration_identifier,
    session_url_sha256: sha256(url.href) };
}

function sameSession(record, session) {
  return record.session_id === session.id && record.session_livemode === session.livemode &&
    record.integration_identifier === session.integration_identifier &&
    record.session_url_sha256 === session.session_url_sha256;
}

export function reviewCheckoutExpiryIdempotencyKey(record, env = process.env) {
  validateBinding(record, env);
  if (!record.session_id) throw new Error('ARC_REVIEW_CHECKOUT_SESSION_BINDING_REQUIRED');
  return `arc_review_expire_${hmac(secret(env), EXPIRY_IDEMPOTENCY_PREFIX + record.binding_hmac_sha256 + '\n' + record.session_id)}`;
}

export async function bindReviewCheckoutSession(store, approvalReceiptSha256, rawSession,
  env = process.env, nowValue = new Date()) {
  const id = bindingHmac(approvalReceiptSha256, env);
  const session = sessionProjection(rawSession);
  const now = nowDate(nowValue);
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
    const entry = await readBindingEntry(store, id, env);
    if (!entry) throw new Error('ARC_REVIEW_CHECKOUT_BINDING_REQUIRED');
    if (entry.record.session_id !== null) {
      if (!sameSession(entry.record, session)) throw new Error('ARC_REVIEW_CHECKOUT_SESSION_CONFLICT');
      return entry.record;
    }
    if (!['CREATING', 'CANCELLED'].includes(entry.record.state)) {
      throw new Error('ARC_REVIEW_CHECKOUT_SESSION_CONFLICT');
    }
    const suppressed = entry.record.state === 'CANCELLED';
    const base = {
      ...unsigned(entry.record),
      record_revision: entry.record.record_revision + 1,
      state: suppressed ? 'EXPIRY_PENDING' : 'OPEN',
      session_id: session.id,
      session_livemode: session.livemode,
      integration_identifier: session.integration_identifier,
      session_url_sha256: session.session_url_sha256,
      session_bound_at: now.toISOString(),
      provider_status: 'open',
      provider_payment_status: 'unpaid',
    };
    if (suppressed) {
      const expiryKey = `arc_review_expire_${hmac(secret(env), EXPIRY_IDEMPOTENCY_PREFIX +
        entry.record.binding_hmac_sha256 + '\n' + session.id)}`;
      base.expiry_idempotency_key_sha256 = sha256(expiryKey);
      base.expiry_requested_at = now.toISOString();
    }
    const updated = signBinding(base, env);
    const replaced = await store.setJSON(reviewCheckoutBindingKey(id), updated, { onlyIfMatch: entry.etag });
    if (replaced?.modified) return updated;
  }
  throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_CONTENTION');
}

function suppressionMutation(value) {
  return {
    suppression_receipt_sha256: value.suppression_receipt_sha256,
    suppression_status: value.suppression_status,
    suppressed_at: value.suppressed_at,
    source_invite_hmac_sha256: value.source_invite_hmac_sha256,
    source_outbox_hmac_sha256: value.source_outbox_hmac_sha256,
  };
}

export async function requestReviewCheckoutRevocation(store, bindingId, rawSuppression,
  env = process.env, nowValue = new Date(), options = {}) {
  const now = nowDate(nowValue);
  const suppression = validateSuppression(rawSuppression);
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
    const entry = await readBindingEntry(store, bindingId, env);
    if (!entry || entry.record.recipient_email_sha256 !== suppression.recipient_email_sha256) {
      throw new Error('ARC_REVIEW_CHECKOUT_BINDING_REQUIRED');
    }
    const currentSuppression = suppressionFromRecord(entry.record);
    const chosen = currentSuppression && suppressionPriority(currentSuppression.suppression_status) >=
      suppressionPriority(suppression.suppression_status) ? currentSuppression : suppression;
    if (entry.record.state === 'EXPIRED' || entry.record.state === 'REVIEW_REQUIRED') {
      if (currentSuppression === chosen) return entry.record;
    }
    if (entry.record.state === 'CREATING' && options.cancelCreating !== true) {
      return { ...entry.record, revocation_pending: true };
    }
    let state = entry.record.state;
    const mutation = { ...suppressionMutation(chosen), fulfillment_halted: true };
    if (entry.record.state === 'CREATING') state = 'CANCELLED';
    else if (entry.record.state === 'OPEN') {
      state = 'EXPIRY_PENDING';
      const expiryKey = reviewCheckoutExpiryIdempotencyKey(entry.record, env);
      mutation.expiry_idempotency_key_sha256 = sha256(expiryKey);
      mutation.expiry_requested_at = now.toISOString();
    }
    const updated = signBinding({
      ...unsigned(entry.record),
      record_revision: entry.record.record_revision + 1,
      state,
      ...mutation,
    }, env);
    const replaced = await store.setJSON(reviewCheckoutBindingKey(bindingId), updated,
      { onlyIfMatch: entry.etag });
    if (replaced?.modified) return updated;
  }
  throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_CONTENTION');
}

export async function listReviewCheckoutBindingsForRecipient(store, recipientEmailSha256,
  env = process.env) {
  const index = await readIndexEntry(store, recipientEmailSha256, env);
  if (!index) return { complete: true, records: [] };
  const records = [];
  for (const value of index.record.bindings) {
    const entry = await readBindingEntry(store, value.binding_hmac_sha256, env);
    if (!entry) return { complete: false, records };
    if (entry.record.recipient_email_sha256 !== index.record.recipient_email_sha256 ||
        entry.record.approval_receipt_sha256 !== value.approval_receipt_sha256) {
      throw new Error('ARC_REVIEW_CHECKOUT_RECIPIENT_INDEX_CONFLICT');
    }
    records.push(entry.record);
  }
  return { complete: true, records };
}

export async function markReviewCheckoutExpired(store, bindingId, sessionId,
  env = process.env, nowValue = new Date()) {
  const now = nowDate(nowValue);
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
    const entry = await readBindingEntry(store, bindingId, env);
    if (!entry || entry.record.session_id !== sessionId) throw new Error('ARC_REVIEW_CHECKOUT_BINDING_REQUIRED');
    if (entry.record.state === 'EXPIRED') return entry.record;
    if (entry.record.state !== 'EXPIRY_PENDING') throw new Error('ARC_REVIEW_CHECKOUT_EXPIRY_NOT_REQUESTED');
    const updated = signBinding({
      ...unsigned(entry.record),
      record_revision: entry.record.record_revision + 1,
      state: 'EXPIRED',
      expired_at: now.toISOString(),
      provider_status: 'expired',
      provider_payment_status: 'unpaid',
    }, env);
    const replaced = await store.setJSON(reviewCheckoutBindingKey(bindingId), updated,
      { onlyIfMatch: entry.etag });
    if (replaced?.modified) return updated;
  }
  throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_CONTENTION');
}

function alertId(binding, suppression, env) {
  return hmac(secret(env), ALERT_ID_PREFIX + binding.binding_hmac_sha256 + '\n' +
    suppression.suppression_receipt_sha256);
}

async function ensureManualReviewAlert(store, binding, suppression, env, now) {
  const id = alertId(binding, suppression, env);
  const value = {
    schema: REVIEW_CHECKOUT_REVOCATION_ALERT_SCHEMA,
    version: 1,
    alert_hmac_sha256: id,
    binding_hmac_sha256: binding.binding_hmac_sha256,
    approval_receipt_sha256: binding.approval_receipt_sha256,
    recipient_email_sha256: binding.recipient_email_sha256,
    session_id: binding.session_id,
    suppression_receipt_sha256: suppression.suppression_receipt_sha256,
    suppression_status: suppression.suppression_status,
    provider_status: binding.provider_status,
    provider_payment_status: binding.provider_payment_status,
    alert_code: 'REFUND_REVIEW_REQUIRED',
    created_at: now.toISOString(),
  };
  const record = { ...value, record_hmac_sha256: hmac(secret(env), ALERT_SIGNATURE_PREFIX + canonicalJson(value)) };
  const key = `review-checkout-revocation-alert/${id}`;
  const created = await store.setJSON(key, record, { onlyIfNew: true });
  if (created?.modified) return record;
  const existing = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!existing || canonicalJson(existing.data) !== canonicalJson(record)) {
    throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_ALERT_CONFLICT');
  }
  return record;
}

export async function markReviewCheckoutManualReview(store, bindingId, sessionId, providerState,
  rawSuppression, env = process.env, nowValue = new Date()) {
  exactKeys(providerState, ['payment_status', 'status'], 'Review Checkout provider state');
  if (typeof providerState.status !== 'string' || typeof providerState.payment_status !== 'string') {
    throw new TypeError('Review Checkout provider state is invalid.');
  }
  const suppression = validateSuppression(rawSuppression);
  const now = nowDate(nowValue);
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
    const entry = await readBindingEntry(store, bindingId, env);
    if (!entry || entry.record.session_id !== sessionId ||
        entry.record.recipient_email_sha256 !== suppression.recipient_email_sha256) {
      throw new Error('ARC_REVIEW_CHECKOUT_BINDING_REQUIRED');
    }
    const updated = signBinding({
      ...unsigned(entry.record),
      record_revision: entry.record.record_revision + 1,
      state: 'REVIEW_REQUIRED',
      ...suppressionMutation(suppression),
      provider_status: providerState.status,
      provider_payment_status: providerState.payment_status,
      fulfillment_halted: true,
      alert_code: 'REFUND_REVIEW_REQUIRED',
    }, env);
    const replaced = await store.setJSON(reviewCheckoutBindingKey(bindingId), updated,
      { onlyIfMatch: entry.etag });
    if (replaced?.modified) {
      await ensureManualReviewAlert(store, updated, suppression, env, now);
      return updated;
    }
  }
  throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_CONTENTION');
}

export async function assertReviewCheckoutFulfillmentAllowed(store, approvalReceiptSha256,
  env = process.env) {
  const entry = await readBindingEntry(store, bindingHmac(approvalReceiptSha256, env), env);
  if (!entry || entry.record.state !== 'OPEN' || entry.record.fulfillment_halted) {
    throw new Error('ARC_PAYMENT_ARC2_REVIEW_REQUIRED');
  }
  return entry.record;
}
