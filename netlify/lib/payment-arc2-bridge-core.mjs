import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { readReviewInviteForEmail } from './review-flow-core.mjs';
import { readReviewEmailRecipientControl } from './review-email-recipient-control-core.mjs';
import {
  assertReviewCheckoutFulfillmentAllowed,
  reviewCheckoutRevocationConfiguration,
} from './review-checkout-revocation-core.mjs';
import {
  STRIPE_CHECKOUT_RECEIPT_SCHEMA,
  STRIPE_CHECKOUT_SESSION_SCHEMA,
  stripeCheckoutConfiguration,
  stripeCheckoutKeys,
} from './stripe-checkout-core.mjs';

export const PAYMENT_ARC2_OUTBOX_STORE = 'arc-payment-arc2-outbox';
export const PAYMENT_ARC2_OUTBOX_SCHEMA = 'arc-payment-arc2-start-outbox-v2';
export const PAYMENT_ARC2_IMMUTABLE_SCHEMA = 'arc-payment-arc2-start-binding-v2';
export const PAYMENT_ARC2_REVIEW_SESSION_BINDING_SCHEMA = 'arc-payment-review-session-binding-v1';
export const PAYMENT_ARC2_COMPLETION_SCHEMA = 'arc2-start-processing-receipt-v2';
export const PAYMENT_ARC2_PENDING_INDEX_SCHEMA = 'arc-payment-arc2-pending-index-v1';
export const PAYMENT_ARC2_REVIEW_EVIDENCE_VERSION = 'arc2-review-session-payment-evidence-v1';
export const PAYMENT_ARC2_REVIEW_EVIDENCE_SCOPE = 'authoritative-approved-review-paid-checkout-session';
export const PAYMENT_ARC2_REVIEW_EVIDENCE_SIGNATURE_PREFIX = 'arc2-review-session-payment-evidence-signature-v1\n';
export const PAYMENT_ARC2_LEASE_SECONDS = 5 * 60;
export const PAYMENT_ARC2_APPROVAL_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
export const PAYMENT_ARC2_SETTLEMENT_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

const OUTBOX_KEY_PREFIX = 'payment-arc2-start-outbox/';
const REVIEW_SESSION_KEY_PREFIX = 'payment-review-session-binding/';
const PENDING_INDEX_KEY_PREFIX = 'payment-arc2-pending/';
const OUTBOX_KEY_HMAC_PREFIX = 'arc-payment-arc2-start-outbox-key-v2\n';
const REVIEW_SESSION_KEY_HMAC_PREFIX = 'arc-payment-review-session-binding-key-v1\n';
const CLAIM_HMAC_PREFIX = 'arc-payment-arc2-start-claim-v2\n';
const APPROVAL_SIGNATURE_PREFIX = 'arc-preview-customer-approval-signature-v1\n';
const CHECKOUT_IDEMPOTENCY_PREFIX = 'arc-preview-checkout-idempotency-v1\n';
const REVIEW_APPROVAL_SCHEMA = 'arc-preview-customer-approval-v1';
const PROVIDER_METADATA_SCHEMA = 'arc-review-checkout-session-v1';
const OFFER_CONTRACT_ID = 'arc-fixed-five-page-offer-v1';
const TERMS_VERSION = '2026-08-25';
const HEX_64 = /^[a-f0-9]{64}$/;
const CLAIM_TOKEN = /^[A-Za-z0-9_-]{32,256}$/;
const CHECKOUT_SESSION_ID = /^cs_(?:test|live)_[A-Za-z0-9_]{6,128}$/;
const PAYMENT_INTENT_ID = /^pi_[A-Za-z0-9_]{6,128}$/;
const ACCOUNT_ID = /^acct_[A-Za-z0-9]{6,128}$/;
const INTEGRATION_IDENTIFIER = /^arc_review_checkout_[a-z]{8}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_CAS_ATTEMPTS = 8;
const FUTURE_CLOCK_SKEW_MS = 5 * 60 * 1000;
const OUTBOX_STATES = new Set(['PENDING', 'CLAIMED', 'COMPLETED']);

const REVIEW_ARTIFACT_BINDING_FIELDS = Object.freeze([
  'artifact_evidence_sha256', 'artifact_manifest_sha256', 'bundle_fingerprint',
  'checkout_reference_sha256', 'preview_folder', 'preview_source_commit_sha',
  'preview_source_repository', 'production_content_sha256',
]);

const METADATA_FIELDS = Object.freeze([
  'approval_receipt_hmac_sha256',
  'approval_receipt_sha256',
  'invite_hmac_sha256',
  'offer_contract_id',
  'preview_manifest_sha256',
  'recipient_email_sha256',
  'schema',
  'scope_version',
  'terms_version',
]);

const REVIEW_SESSION_IMMUTABLE_FIELDS = Object.freeze([
  'schema', 'invite_hmac_sha256', 'review_record_revision', 'review_record_hmac_sha256',
  'review_record_sha256', 'approval_receipt_sha256', 'approval_receipt_hmac_sha256',
  'preview_manifest_sha256', 'preview_content_sha256', 'brief_sha256', 'recipient_email_sha256',
  'payer_email_sha256',
  'checkout_idempotency_key_sha256', 'checkout_session_id_hmac_sha256',
  'payment_intent_id_hmac_sha256', 'client_reference_id_sha256', 'stripe_account_id_sha256',
  'livemode', 'currency', 'subtotal_amount_minor_units', 'tax_amount_minor_units',
  'amount_total_minor_units', 'customer_address_country', 'customer_address_state', 'scope_version',
  'revision_round', 'approval_decided_at', 'authorization_expires_at', 'checkout_session_created_at',
  'provider_metadata_sha256',
  'provider_session_binding_sha256', 'ledger_session_storage_key', 'ledger_payment_binding_sha256',
  'ledger_receipt_sha256', 'payment_state_event_sha256',
]);

const REVIEW_SESSION_RECORD_FIELDS = Object.freeze(['schema', 'created_at', 'immutable', 'immutable_sha256']);

const OUTBOX_IMMUTABLE_FIELDS = Object.freeze([
  'schema', 'review_session_binding_sha256', 'invite_hmac_sha256', 'payment_binding_sha256',
  'payment_receipt_sha256', 'payment_state_event_sha256', 'approval_receipt_sha256',
  'approval_receipt_hmac_sha256', 'preview_manifest_sha256', 'preview_content_sha256',
  'brief_sha256', 'recipient_email_sha256', 'checkout_session_id_hmac_sha256',
  'payer_email_sha256',
  'payment_intent_id_hmac_sha256', 'stripe_account_id_sha256', 'livemode', 'scope_version',
  'authorization_expires_at',
]);

const OUTBOX_FIELDS = Object.freeze([
  'schema', 'record_revision', 'status', 'created_at', 'updated_at', 'immutable', 'immutable_sha256',
  'claim_attempt_count', 'lease_claim_hmac_sha256', 'lease_claimed_at', 'lease_expires_at',
  'completion_claim_hmac_sha256', 'arc2_start_receipt_sha256', 'completion_receipt_sha256', 'completed_at',
]);

const COMPLETION_FIELDS = Object.freeze([
  'schema', 'accepted', 'immutable_binding_sha256', 'arc2_start_receipt',
  'arc2_start_receipt_hmac_sha256',
]);
const START_RECEIPT_FIELDS = Object.freeze([
  'schema', 'accepted', 'handoff_id', 'started_at', 'payment_evidence_sha256',
  'artifact_evidence_sha256', 'bridge_immutable_binding_sha256',
  'review_session_binding_sha256', 'checkout_session_id_hmac_sha256',
  'payment_intent_id_hmac_sha256', 'recipient_email_sha256', 'payer_email_sha256',
  'handoff_state', 'reversal_control_ready', 'continuation_ready',
]);
const START_RECEIPT_SCHEMA = 'arc2-review-handoff-start-receipt-v2';
const START_RECEIPT_SIGNATURE_PREFIX = 'arc2-review-handoff-start-receipt-signature-v2\n';
const ARC2_CONTINUATION_STATES = new Set([
  'INVITATION_READY', 'CLAIM_WRAPPER_CONSUMED', 'CLAIM_CALLBACK_RECEIVED',
  'CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED',
]);

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  plainObject(value, label);
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw new TypeError(`${label} fields are invalid.`);
  }
}

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

function hex64(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function integer(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) throw new TypeError(`${label} is invalid.`);
  return value;
}

function amount(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 100_000_000) throw new TypeError(`${label} is invalid.`);
  return value;
}

function isoTimestamp(value, label) {
  if (typeof value !== 'string' || value.length < 20 || value.length > 32) throw new TypeError(`${label} is invalid.`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return value;
}

function clockDate(adapters) {
  const value = adapters?.clock?.() || new Date();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new TypeError('Payment ARC2 bridge clock is invalid.');
  return value;
}

function validSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}

function exactBoolean(value) {
  return value === 'true' || value === 'false';
}

function identityHmac(env, kind, value) {
  return hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `stripe-checkout-${kind}-v1\n${value}`);
}

function storeSet(stores, label) {
  const store = plainObject(stores, 'Payment ARC2 stores')[label];
  if (!store?.getWithMetadata || !store?.setJSON) throw new TypeError(`Payment ARC2 ${label} store is unavailable.`);
  return store;
}

export function paymentArc2BridgeConfiguration(env = process.env) {
  const flagValid = exactBoolean(env.ARC_PAYMENT_ARC2_BRIDGE_ENABLED);
  const liveModeValid = exactBoolean(env.ARC_STRIPE_LIVE_MODE_ENABLED);
  const bridgeSecretValid = validSecret(env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET);
  const accountValid = HEX_64.test(String(env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 || ''));
  const integrationIdentifierValid = INTEGRATION_IDENTIFIER.test(
    String(env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER || ''),
  );
  const ledger = stripeCheckoutConfiguration(env);
  const revocation = reviewCheckoutRevocationConfiguration(env);
  const secretSet = [
    env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET,
    env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
    env.ARC_REVIEW_RECORD_HMAC_SECRET,
    env.ARC_REVIEW_DECISION_HMAC_SECRET,
  ];
  const secretsDistinct = secretSet.every(validSecret) && new Set(secretSet).size === secretSet.length;
  return {
    accountValid,
    bridgeSecretValid,
    enabled: flagValid && env.ARC_PAYMENT_ARC2_BRIDGE_ENABLED === 'true' && liveModeValid &&
      bridgeSecretValid && accountValid && integrationIdentifierValid && ledger.webhookOperational &&
      revocation.enabled && secretsDistinct,
    expectedLivemode: env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true',
    flagValid,
    integrationIdentifierValid,
    ledgerOperational: ledger.webhookOperational,
    liveModeValid,
    revocationReady: revocation.enabled,
    secretsDistinct,
  };
}

function requireBridge(env) {
  const configuration = paymentArc2BridgeConfiguration(env);
  if (!configuration.enabled) throw new Error('ARC_PAYMENT_ARC2_BRIDGE_DISABLED');
  return configuration;
}

function approvalReceipt(record) {
  return {
    schema: REVIEW_APPROVAL_SCHEMA,
    invite_hmac_sha256: record.invite_hmac_sha256,
    recipient_email_sha256: record.recipient_email_sha256,
    email_delivery_receipt_sha256: record.email_delivery_receipt_sha256,
    email_delivery_binding_mode: record.email_delivery_binding_mode,
    email_delivery_outbox_hmac_sha256: record.email_delivery_outbox_hmac_sha256,
    preview_url: record.preview_url,
    preview_source_repository: record.preview_source_repository,
    preview_source_commit_sha: record.preview_source_commit_sha,
    preview_manifest_sha256: record.preview_manifest_sha256,
    preview_content_sha256: record.preview_content_sha256,
    brief_sha256: record.brief_sha256,
    scope_version: record.scope_version,
    page_bindings: record.page_bindings,
    revision_round: record.revision_round,
    session_nonce_hmac_sha256: record.session_nonce_hmac_sha256,
    action_payload_sha256: record.decision.action_payload_sha256,
    decided_at: record.decision.decided_at,
  };
}

async function readAuthoritativeReview(reviewStore, inviteHmac, env, now, { enforceFreshness = true } = {}) {
  const entry = await readReviewInviteForEmail(reviewStore, inviteHmac, env);
  const record = entry.record;
  if (!entry.etag || record.state !== 'APPROVED' || record.decision?.action !== 'APPROVE_AND_PAY' ||
      record.successor_invite_hmac_sha256 !== null || record.email_delivery_receipt_sha256 === null ||
      record.session_nonce_hmac_sha256 === null || record.invite_hmac_sha256 !== inviteHmac) {
    throw new Error('ARC_PAYMENT_ARC2_APPROVAL_REQUIRED');
  }
  if (env.ARC_REVIEW_EMAIL_OUTBOX_ENABLED === 'true' &&
      (record.email_delivery_binding_mode !== 'signed-outbox' ||
        !HEX_64.test(String(record.email_delivery_outbox_hmac_sha256 || '')))) {
    throw new Error('ARC_PAYMENT_ARC2_EMAIL_DELIVERY_REQUIRED');
  }
  const decidedMs = Date.parse(record.decision.decided_at);
  const expiresMs = Date.parse(record.expires_at);
  const nowMs = now.getTime();
  if (!Number.isFinite(decidedMs) || !Number.isFinite(expiresMs) || decidedMs > expiresMs ||
      (enforceFreshness && (decidedMs > nowMs + FUTURE_CLOCK_SKEW_MS || expiresMs <= nowMs ||
        nowMs - decidedMs > PAYMENT_ARC2_APPROVAL_MAX_AGE_MS))) {
    throw new Error('ARC_PAYMENT_ARC2_APPROVAL_STALE');
  }
  if (record.prior_invite_hmac_sha256 !== null) {
    const prior = (await readReviewInviteForEmail(reviewStore, record.prior_invite_hmac_sha256, env)).record;
    if (prior.state !== 'REVISION_SUPERSEDED' || prior.successor_invite_hmac_sha256 !== inviteHmac ||
        prior.recipient_email_sha256 !== record.recipient_email_sha256 || prior.brief_sha256 !== record.brief_sha256 ||
        prior.scope_version !== record.scope_version) {
      throw new Error('ARC_PAYMENT_ARC2_APPROVAL_STALE');
    }
  }
  const receipt = approvalReceipt(record);
  const receiptCanonical = canonicalJson(receipt);
  const receiptSha = sha256Hex(receiptCanonical);
  const receiptHmac = hmacHex(env.ARC_REVIEW_DECISION_HMAC_SECRET, APPROVAL_SIGNATURE_PREFIX + receiptCanonical);
  const checkoutIdempotency = hmacHex(env.ARC_REVIEW_DECISION_HMAC_SECRET,
    CHECKOUT_IDEMPOTENCY_PREFIX + record.invite_hmac_sha256);
  if (!safeEqual(receiptSha, record.decision.approval_receipt_sha256) ||
      !safeEqual(receiptHmac, record.decision.approval_receipt_hmac_sha256) ||
      !safeEqual(sha256Hex(checkoutIdempotency), record.decision.checkout_idempotency_key_sha256)) {
    throw new Error('ARC_PAYMENT_ARC2_APPROVAL_BINDING_INVALID');
  }
  let recipientControlSha256 = null;
  let checkoutAuthoritySha256 = null;
  let checkoutAuthority = null;
  if (env.ARC_REVIEW_EMAIL_OUTBOX_ENABLED === 'true') {
    const control = await readReviewEmailRecipientControl(reviewStore, record.recipient_email_sha256, env);
    if (!control || control.record.state !== 'ACTIVE') {
      throw new Error('ARC_PAYMENT_ARC2_REVIEW_REQUIRED');
    }
    checkoutAuthority = await assertReviewCheckoutFulfillmentAllowed(
      reviewStore, record.decision.approval_receipt_sha256, env,
    );
    if (checkoutAuthority.recipient_email_sha256 !== record.recipient_email_sha256 ||
        checkoutAuthority.invite_hmac_sha256 !== record.invite_hmac_sha256 ||
        checkoutAuthority.session_livemode !== (env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true') ||
        checkoutAuthority.integration_identifier !== env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER) {
      throw new Error('ARC_PAYMENT_ARC2_REVIEW_REQUIRED');
    }
    recipientControlSha256 = sha256Hex(canonicalJson(control.record));
    checkoutAuthoritySha256 = sha256Hex(canonicalJson(checkoutAuthority));
  }
  return {
    checkoutAuthority,
    checkoutAuthoritySha256,
    etag: entry.etag,
    recipientControlSha256,
    record,
    recordSha256: sha256Hex(canonicalJson(record)),
  };
}

function metadataForReview(record) {
  return {
    approval_receipt_hmac_sha256: record.decision.approval_receipt_hmac_sha256,
    approval_receipt_sha256: record.decision.approval_receipt_sha256,
    invite_hmac_sha256: record.invite_hmac_sha256,
    offer_contract_id: OFFER_CONTRACT_ID,
    preview_manifest_sha256: record.preview_manifest_sha256,
    recipient_email_sha256: record.recipient_email_sha256,
    schema: PROVIDER_METADATA_SCHEMA,
    scope_version: record.scope_version,
    terms_version: TERMS_VERSION,
  };
}

function acceptedAdultField(fields) {
  if (!Array.isArray(fields)) return false;
  const match = fields.filter(field => field?.key === 'adultpurchaserack');
  return match.length === 1 && match[0].type === 'dropdown' && match[0].dropdown?.value === 'accepted';
}

function emailDigest(value) {
  if (typeof value !== 'string' || value.length > 254 || value !== value.trim() || !EMAIL.test(value)) {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_SESSION_MISMATCH');
  }
  return sha256Hex(value.toLowerCase());
}

function providerProjection(authority, checkoutSessionId, review, env, configuration, now,
  { enforceSettlementFreshness = true } = {}) {
  const account = authority?.account;
  const session = authority?.session;
  if (!account || typeof account !== 'object' || Array.isArray(account) || account.object !== 'account' ||
      !ACCOUNT_ID.test(String(account.id || '')) || !safeEqual(sha256Hex(account.id), env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256)) {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_ACCOUNT_MISMATCH');
  }
  if (!session || typeof session !== 'object' || Array.isArray(session) || session.object !== 'checkout.session' ||
      session.id !== checkoutSessionId || session.mode !== 'payment' || session.status !== 'complete' ||
      session.payment_status !== 'paid' || session.livemode !== configuration.expectedLivemode || session.payment_link !== null ||
      session.ui_mode !== 'hosted_page' ||
      session.integration_identifier !== env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER ||
      session.currency !== 'usd' || session.client_reference_id !== review.decision.approval_receipt_sha256 ||
      session.automatic_tax?.enabled !== true || session.automatic_tax?.status !== 'complete' ||
      session.consent?.terms_of_service !== 'accepted' || !acceptedAdultField(session.custom_fields)) {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_SESSION_MISMATCH');
  }
  const sessionCreatedMs = Number.isSafeInteger(session.created) && session.created > 0
    ? session.created * 1000 : NaN;
  const approvalDecidedMs = Date.parse(review.decision.decided_at);
  const authorizationExpiresMs = Date.parse(review.expires_at);
  const approvalSecondMs = Math.floor(approvalDecidedMs / 1000) * 1000;
  const authorizationExpiresSecondMs = Math.floor(authorizationExpiresMs / 1000) * 1000;
  if (!Number.isFinite(sessionCreatedMs) || sessionCreatedMs < approvalSecondMs ||
      sessionCreatedMs > authorizationExpiresSecondMs || sessionCreatedMs > now.getTime() + FUTURE_CLOCK_SKEW_MS) {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_AUTHORIZATION_WINDOW_INVALID');
  }
  if (enforceSettlementFreshness && now.getTime() - sessionCreatedMs > PAYMENT_ARC2_SETTLEMENT_MAX_AGE_MS) {
    throw new Error('ARC_PAYMENT_ARC2_SETTLEMENT_STALE');
  }
  exactKeys(session.metadata, METADATA_FIELDS, 'Provider Checkout metadata');
  const expectedMetadata = metadataForReview(review);
  if (METADATA_FIELDS.some(field => !safeEqual(session.metadata[field], expectedMetadata[field]))) {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_METADATA_MISMATCH');
  }
  const paymentIntent = session.payment_intent;
  if (!paymentIntent || typeof paymentIntent !== 'object' || Array.isArray(paymentIntent) ||
      paymentIntent.object !== 'payment_intent' || !PAYMENT_INTENT_ID.test(String(paymentIntent.id || '')) ||
      paymentIntent.status !== 'succeeded' || paymentIntent.livemode !== configuration.expectedLivemode ||
      paymentIntent.currency !== 'usd') {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_SESSION_MISMATCH');
  }
  exactKeys(paymentIntent.metadata, METADATA_FIELDS, 'Provider PaymentIntent metadata');
  if (METADATA_FIELDS.some(field => !safeEqual(paymentIntent.metadata[field], expectedMetadata[field]))) {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_METADATA_MISMATCH');
  }
  const subtotal = amount(session.amount_subtotal, 'Provider Checkout subtotal');
  const total = amount(session.amount_total, 'Provider Checkout total');
  const tax = amount(session.total_details?.amount_tax, 'Provider Checkout tax');
  if (subtotal !== 500_000 || session.total_details?.amount_discount !== 0 ||
      session.total_details?.amount_shipping !== 0 || total !== subtotal + tax ||
      paymentIntent.amount !== total || paymentIntent.amount_received !== total) {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_SESSION_MISMATCH');
  }
  // The signed review record remains the fulfillment-recipient authority.
  // Stripe's payer email is a separate audit identity and may legitimately be
  // a different address (gift, assistant, finance team, or corrected billing).
  const payerEmailSha256 = emailDigest(session.customer_details?.email ?? session.customer_email);
  const country = session.customer_details?.address?.country;
  const region = session.customer_details?.address?.state;
  if (!/^[A-Z]{2}$/.test(String(country || '')) || (country === 'US' && !/^[A-Z]{2}$/.test(String(region || '')))) {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_SESSION_MISMATCH');
  }
  const projection = {
    schema: 'arc-payment-provider-session-binding-v1',
    stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    checkout_session_id_hmac_sha256: identityHmac(env, 'session-id', session.id),
    payment_intent_id_hmac_sha256: identityHmac(env, 'payment-intent-id', paymentIntent.id),
    client_reference_id_sha256: sha256Hex(session.client_reference_id),
    payer_email_sha256: payerEmailSha256,
    customer_address_country: country,
    customer_address_state: region ?? '',
    livemode: session.livemode,
    currency: session.currency,
    subtotal_amount_minor_units: subtotal,
    tax_amount_minor_units: tax,
    amount_total_minor_units: total,
    checkout_session_created_at: new Date(sessionCreatedMs).toISOString(),
    ui_mode: session.ui_mode,
    integration_identifier: session.integration_identifier,
    metadata_sha256: sha256Hex(canonicalJson(expectedMetadata)),
  };
  return { projection, digest: sha256Hex(canonicalJson(projection)) };
}

async function strongRead(store, key, missingCode) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!entry?.etag || !entry.data) throw new Error(missingCode);
  return entry;
}

function receiptStorageKey(stateEventIdHmac) {
  return `stripe-checkout-receipt/${hex64(stateEventIdHmac, 'Stripe paid state event HMAC')}`;
}

function validateReviewCheckoutMetadata(value, expected) {
  exactKeys(value, METADATA_FIELDS, 'Ledger review Checkout metadata');
  if (METADATA_FIELDS.some(field => !safeEqual(value[field], expected[field]))) {
    throw new Error('ARC_PAYMENT_ARC2_CHECKOUT_METADATA_MISMATCH');
  }
  return sha256Hex(canonicalJson(value));
}

function validateLedger(summary, receipt, expected, review, env, configuration) {
  plainObject(summary, 'Stripe Checkout ledger summary');
  plainObject(receipt, 'Stripe Checkout ledger receipt');
  if (summary.state === 'REVIEW_REQUIRED' || summary.manual_review_required === true ||
      receipt.resulting_state === 'REVIEW_REQUIRED' || receipt.review_alert_required === true) {
    throw new Error('ARC_PAYMENT_ARC2_REVIEW_REQUIRED');
  }
  if (summary.schema !== STRIPE_CHECKOUT_SESSION_SCHEMA || summary.state !== 'PAID' ||
      summary.fulfillment_allowed !== true || summary.manual_review_required !== false ||
      receipt.schema !== STRIPE_CHECKOUT_RECEIPT_SCHEMA || receipt.accepted !== true ||
      receipt.resulting_state !== 'PAID' || receipt.review_alert_required !== false) {
    throw new Error('ARC_PAYMENT_ARC2_PAYMENT_NOT_AUTHORIZED');
  }
  const sessionHmac = hex64(summary.checkout_session_id_hmac_sha256, 'Ledger Checkout Session HMAC');
  const paymentIntentHmac = hex64(summary.payment_intent_id_hmac_sha256, 'Ledger PaymentIntent HMAC');
  const clientReference = hex64(summary.client_reference_id_sha256, 'Ledger client reference digest');
  const payerEmail = hex64(summary.payer_email_sha256, 'Ledger payer email digest');
  const account = hex64(summary.stripe_account_id_sha256, 'Ledger Stripe account digest');
  const stateEventId = hex64(summary.state_event_id_hmac_sha256, 'Ledger state event HMAC');
  const stateEventSha = hex64(summary.state_event_sha256, 'Ledger state event digest');
  const subtotal = amount(summary.subtotal_amount_minor_units, 'Ledger subtotal');
  const tax = amount(summary.tax_amount_minor_units, 'Ledger tax');
  const total = amount(summary.amount_total_minor_units, 'Ledger total');
  const metadataSha256 = validateReviewCheckoutMetadata(summary.review_checkout_binding, metadataForReview(review));
  if (summary.payment_link_id_hmac_sha256 !== null || summary.livemode !== configuration.expectedLivemode ||
      summary.currency !== 'usd' || total !== subtotal + tax || summary.automatic_tax_enabled !== true ||
      summary.automatic_tax_status !== 'complete' || summary.terms_of_service_consent !== true ||
      summary.adult_purchaser_acknowledgement !== true || !safeEqual(account, env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256) ||
      sessionHmac !== expected.checkout_session_id_hmac_sha256 || paymentIntentHmac !== expected.payment_intent_id_hmac_sha256 ||
      clientReference !== expected.client_reference_id_sha256 || payerEmail !== expected.payer_email_sha256 ||
      summary.customer_address_country !== expected.customer_address_country ||
      summary.customer_address_state !== expected.customer_address_state ||
      subtotal !== expected.subtotal_amount_minor_units || tax !== expected.tax_amount_minor_units ||
      total !== expected.amount_total_minor_units || metadataSha256 !== expected.metadata_sha256 ||
      receipt.event_id_hmac_sha256 !== stateEventId || receipt.event_sha256 !== stateEventSha ||
      receipt.checkout_session_id_hmac_sha256 !== sessionHmac || receipt.stripe_account_id_sha256 !== account) {
    throw new Error('ARC_PAYMENT_ARC2_LEDGER_BINDING_MISMATCH');
  }
  const receiptSha256 = sha256Hex(canonicalJson(receipt));
  const binding = {
    schema: 'arc-payment-paid-ledger-binding-v2',
    checkout_session_id_hmac_sha256: sessionHmac,
    payment_intent_id_hmac_sha256: paymentIntentHmac,
    client_reference_id_sha256: clientReference,
    payer_email_sha256: payerEmail,
    stripe_account_id_sha256: account,
    livemode: summary.livemode,
    currency: summary.currency,
    subtotal_amount_minor_units: subtotal,
    tax_amount_minor_units: tax,
    amount_total_minor_units: total,
    payment_state_event_id_hmac_sha256: stateEventId,
    payment_state_event_sha256: stateEventSha,
    review_checkout_binding_sha256: metadataSha256,
    payment_receipt_sha256: receiptSha256,
  };
  return { binding, digest: sha256Hex(canonicalJson(binding)), receiptSha256 };
}

async function readAuthoritativeLedger(ledgerStore, sessionStorageKey, expected, review, env, configuration) {
  if (!/^stripe-checkout-session\/[a-f0-9]{64}$/.test(sessionStorageKey)) {
    throw new Error('ARC_PAYMENT_ARC2_LEDGER_BINDING_MISMATCH');
  }
  const sessionEntry = await strongRead(ledgerStore, sessionStorageKey, 'ARC_PAYMENT_ARC2_LEDGER_REQUIRED');
  const receiptEntry = await strongRead(ledgerStore, receiptStorageKey(sessionEntry.data?.state_event_id_hmac_sha256),
    'ARC_PAYMENT_ARC2_RECEIPT_REQUIRED');
  const validated = validateLedger(sessionEntry.data, receiptEntry.data, expected, review, env, configuration);
  return {
    ...validated,
    receiptEtag: receiptEntry.etag,
    sessionEtag: sessionEntry.etag,
    sessionStorageKey,
  };
}

function reviewSessionKey(inviteHmac, secret) {
  return `${REVIEW_SESSION_KEY_PREFIX}${hmacHex(secret, REVIEW_SESSION_KEY_HMAC_PREFIX + inviteHmac)}`;
}

function outboxKey(immutableSha256, secret) {
  return `${OUTBOX_KEY_PREFIX}${hmacHex(secret, OUTBOX_KEY_HMAC_PREFIX + immutableSha256)}`;
}

function validateReviewSessionImmutable(value) {
  exactKeys(value, REVIEW_SESSION_IMMUTABLE_FIELDS, 'Payment review Session immutable binding');
  if (value.schema !== 'arc-payment-review-session-immutable-v1') throw new Error('ARC_PAYMENT_ARC2_BINDING_CORRUPT');
  for (const field of REVIEW_SESSION_IMMUTABLE_FIELDS.filter(name => name.endsWith('_sha256'))) {
    hex64(value[field], `Payment review Session ${field}`);
  }
  if (!/^stripe-checkout-session\/[a-f0-9]{64}$/.test(value.ledger_session_storage_key) ||
      typeof value.livemode !== 'boolean' || value.currency !== 'usd' || value.scope_version !== OFFER_CONTRACT_ID ||
      !/^[A-Z]{2}$/.test(value.customer_address_country) ||
      !/^[A-Z0-9-]{0,10}$/.test(value.customer_address_state)) {
    throw new Error('ARC_PAYMENT_ARC2_BINDING_CORRUPT');
  }
  integer(value.review_record_revision, 'Review record revision', 1);
  integer(value.revision_round, 'Review revision round');
  amount(value.subtotal_amount_minor_units, 'Review Session subtotal');
  amount(value.tax_amount_minor_units, 'Review Session tax');
  amount(value.amount_total_minor_units, 'Review Session total');
  if (value.amount_total_minor_units !== value.subtotal_amount_minor_units + value.tax_amount_minor_units) {
    throw new Error('ARC_PAYMENT_ARC2_BINDING_CORRUPT');
  }
  isoTimestamp(value.approval_decided_at, 'Review approval time');
  isoTimestamp(value.authorization_expires_at, 'Review authorization expiration');
  isoTimestamp(value.checkout_session_created_at, 'Provider Checkout Session creation time');
  if (Date.parse(value.checkout_session_created_at) <
        Math.floor(Date.parse(value.approval_decided_at) / 1000) * 1000 ||
      Date.parse(value.checkout_session_created_at) >
        Math.floor(Date.parse(value.authorization_expires_at) / 1000) * 1000) {
    throw new Error('ARC_PAYMENT_ARC2_BINDING_CORRUPT');
  }
  return value;
}

function validateReviewSessionRecord(record, key, env) {
  exactKeys(record, REVIEW_SESSION_RECORD_FIELDS, 'Payment review Session record');
  if (record.schema !== PAYMENT_ARC2_REVIEW_SESSION_BINDING_SCHEMA) throw new Error('ARC_PAYMENT_ARC2_BINDING_CORRUPT');
  isoTimestamp(record.created_at, 'Payment review Session creation time');
  validateReviewSessionImmutable(record.immutable);
  const digest = sha256Hex(canonicalJson(record.immutable));
  if (!safeEqual(digest, hex64(record.immutable_sha256, 'Payment review Session binding digest')) ||
      !safeEqual(key, reviewSessionKey(record.immutable.invite_hmac_sha256, env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET))) {
    throw new Error('ARC_PAYMENT_ARC2_BINDING_CORRUPT');
  }
  return record;
}

async function createReviewSessionBinding(bridgeStore, immutable, env, now) {
  validateReviewSessionImmutable(immutable);
  const digest = sha256Hex(canonicalJson(immutable));
  const key = reviewSessionKey(immutable.invite_hmac_sha256, env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET);
  const record = {
    schema: PAYMENT_ARC2_REVIEW_SESSION_BINDING_SCHEMA,
    created_at: now.toISOString(),
    immutable,
    immutable_sha256: digest,
  };
  let result;
  try {
    result = await bridgeStore.setJSON(key, record, { onlyIfNew: true });
  } catch (error) {
    const recovered = await bridgeStore.getWithMetadata(key, { type: 'json', consistency: 'strong' }).catch(() => null);
    if (recovered?.data && safeEqual(validateReviewSessionRecord(recovered.data, key, env).immutable_sha256, digest)) {
      return { key, record: recovered.data, created: false };
    }
    throw error;
  }
  if (result?.modified) return { key, record, created: true };
  const existing = await strongRead(bridgeStore, key, 'ARC_PAYMENT_ARC2_BINDING_REQUIRED');
  validateReviewSessionRecord(existing.data, key, env);
  if (!safeEqual(existing.data.immutable_sha256, digest)) throw new Error('ARC_PAYMENT_ARC2_REVIEW_SESSION_CONFLICT');
  return { key, record: existing.data, created: false };
}

function buildOutboxImmutable(binding) {
  const value = binding.immutable;
  return {
    schema: PAYMENT_ARC2_IMMUTABLE_SCHEMA,
    review_session_binding_sha256: binding.immutable_sha256,
    invite_hmac_sha256: value.invite_hmac_sha256,
    payment_binding_sha256: value.ledger_payment_binding_sha256,
    payment_receipt_sha256: value.ledger_receipt_sha256,
    payment_state_event_sha256: value.payment_state_event_sha256,
    approval_receipt_sha256: value.approval_receipt_sha256,
    approval_receipt_hmac_sha256: value.approval_receipt_hmac_sha256,
    preview_manifest_sha256: value.preview_manifest_sha256,
    preview_content_sha256: value.preview_content_sha256,
    brief_sha256: value.brief_sha256,
    recipient_email_sha256: value.recipient_email_sha256,
    payer_email_sha256: value.payer_email_sha256,
    checkout_session_id_hmac_sha256: value.checkout_session_id_hmac_sha256,
    payment_intent_id_hmac_sha256: value.payment_intent_id_hmac_sha256,
    stripe_account_id_sha256: value.stripe_account_id_sha256,
    livemode: value.livemode,
    scope_version: value.scope_version,
    authorization_expires_at: value.authorization_expires_at,
  };
}

function validateOutboxImmutable(value) {
  exactKeys(value, OUTBOX_IMMUTABLE_FIELDS, 'Payment ARC2 immutable binding');
  if (value.schema !== PAYMENT_ARC2_IMMUTABLE_SCHEMA || typeof value.livemode !== 'boolean' ||
      value.scope_version !== OFFER_CONTRACT_ID) throw new Error('ARC_PAYMENT_ARC2_OUTBOX_CORRUPT');
  for (const field of OUTBOX_IMMUTABLE_FIELDS.filter(name => name.endsWith('_sha256'))) {
    hex64(value[field], `Payment ARC2 ${field}`);
  }
  isoTimestamp(value.authorization_expires_at, 'Payment ARC2 authorization expiration');
  return value;
}

function validateOutboxKey(key) {
  if (typeof key !== 'string' || !/^payment-arc2-start-outbox\/[a-f0-9]{64}$/.test(key)) {
    throw new TypeError('Payment ARC2 outbox key is invalid.');
  }
  return key;
}

function pendingIndexKey(outboxKeyValue) {
  validateOutboxKey(outboxKeyValue);
  return `${PENDING_INDEX_KEY_PREFIX}${outboxKeyValue.slice(OUTBOX_KEY_PREFIX.length)}`;
}

function validatePendingIndex(record, key) {
  exactKeys(record, ['schema', 'outbox_key', 'immutable_binding_sha256', 'created_at'],
    'Payment ARC2 pending index');
  validateOutboxKey(record.outbox_key);
  if (record.schema !== PAYMENT_ARC2_PENDING_INDEX_SCHEMA || key !== pendingIndexKey(record.outbox_key)) {
    throw new Error('ARC_PAYMENT_ARC2_QUEUE_CORRUPT');
  }
  hex64(record.immutable_binding_sha256, 'Payment ARC2 pending immutable binding');
  isoTimestamp(record.created_at, 'Payment ARC2 pending creation time');
  return record;
}

function validateOutboxRecord(record, key, env) {
  exactKeys(record, OUTBOX_FIELDS, 'Payment ARC2 outbox record');
  if (record.schema !== PAYMENT_ARC2_OUTBOX_SCHEMA || !OUTBOX_STATES.has(record.status)) {
    throw new Error('ARC_PAYMENT_ARC2_OUTBOX_CORRUPT');
  }
  integer(record.record_revision, 'Payment ARC2 outbox revision', 1);
  integer(record.claim_attempt_count, 'Payment ARC2 claim attempts');
  isoTimestamp(record.created_at, 'Payment ARC2 created timestamp');
  isoTimestamp(record.updated_at, 'Payment ARC2 updated timestamp');
  validateOutboxImmutable(record.immutable);
  const digest = sha256Hex(canonicalJson(record.immutable));
  if (!safeEqual(digest, hex64(record.immutable_sha256, 'Payment ARC2 immutable binding digest')) ||
      !safeEqual(key, outboxKey(digest, env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET))) {
    throw new Error('ARC_PAYMENT_ARC2_IMMUTABLE_MISMATCH');
  }
  if (record.status === 'PENDING') {
    if (record.lease_claim_hmac_sha256 !== null || record.lease_claimed_at !== null ||
        record.lease_expires_at !== null || record.completion_claim_hmac_sha256 !== null ||
        record.arc2_start_receipt_sha256 !== null || record.completion_receipt_sha256 !== null || record.completed_at !== null) {
      throw new Error('ARC_PAYMENT_ARC2_OUTBOX_CORRUPT');
    }
  } else if (record.status === 'CLAIMED') {
    hex64(record.lease_claim_hmac_sha256, 'Payment ARC2 lease claim HMAC');
    isoTimestamp(record.lease_claimed_at, 'Payment ARC2 lease claim time');
    isoTimestamp(record.lease_expires_at, 'Payment ARC2 lease expiration');
    if (record.claim_attempt_count < 1 || record.completion_claim_hmac_sha256 !== null ||
        record.arc2_start_receipt_sha256 !== null || record.completion_receipt_sha256 !== null || record.completed_at !== null ||
        Date.parse(record.lease_expires_at) <= Date.parse(record.lease_claimed_at)) {
      throw new Error('ARC_PAYMENT_ARC2_OUTBOX_CORRUPT');
    }
  } else {
    if (record.claim_attempt_count < 1 || record.lease_claim_hmac_sha256 !== null || record.lease_claimed_at !== null ||
        record.lease_expires_at !== null) throw new Error('ARC_PAYMENT_ARC2_OUTBOX_CORRUPT');
    hex64(record.completion_claim_hmac_sha256, 'Payment ARC2 completion claim HMAC');
    hex64(record.arc2_start_receipt_sha256, 'ARC2 start receipt digest');
    hex64(record.completion_receipt_sha256, 'Payment ARC2 completion receipt digest');
    isoTimestamp(record.completed_at, 'Payment ARC2 completion time');
  }
  return record;
}

async function readOutbox(bridgeStore, key, env) {
  const entry = await bridgeStore.getWithMetadata(validateOutboxKey(key), { type: 'json', consistency: 'strong' });
  if (!entry) return null;
  if (!entry.etag) throw new Error('ARC_PAYMENT_ARC2_OUTBOX_CORRUPT');
  return { record: validateOutboxRecord(entry.data, key, env), etag: entry.etag };
}

async function removePendingIndex(bridgeStore, outboxKeyValue) {
  const key = pendingIndexKey(outboxKeyValue);
  const existing = await bridgeStore.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!existing) return;
  validatePendingIndex(existing.data, key);
  if (typeof bridgeStore.delete !== 'function') throw new Error('ARC_PAYMENT_ARC2_QUEUE_UNAVAILABLE');
  await bridgeStore.delete(key);
}

async function ensurePendingIndex(bridgeStore, outboxKeyValue, env) {
  const outbox = await readOutbox(bridgeStore, outboxKeyValue, env);
  if (!outbox) throw new Error('ARC_PAYMENT_ARC2_OUTBOX_REQUIRED');
  if (outbox.record.status === 'COMPLETED') {
    await removePendingIndex(bridgeStore, outboxKeyValue);
    return false;
  }
  const key = pendingIndexKey(outboxKeyValue);
  const record = {
    schema: PAYMENT_ARC2_PENDING_INDEX_SCHEMA,
    outbox_key: outboxKeyValue,
    immutable_binding_sha256: outbox.record.immutable_sha256,
    created_at: outbox.record.created_at,
  };
  let result;
  try {
    result = await bridgeStore.setJSON(key, record, { onlyIfNew: true });
  } catch (error) {
    const recovered = await bridgeStore.getWithMetadata(key, { type: 'json', consistency: 'strong' }).catch(() => null);
    if (!recovered || canonicalJson(validatePendingIndex(recovered.data, key)) !== canonicalJson(record)) throw error;
    return false;
  }
  if (result?.modified) return true;
  const existing = await strongRead(bridgeStore, key, 'ARC_PAYMENT_ARC2_QUEUE_UNAVAILABLE');
  if (canonicalJson(validatePendingIndex(existing.data, key)) !== canonicalJson(record)) {
    throw new Error('ARC_PAYMENT_ARC2_QUEUE_CONFLICT');
  }
  return false;
}

function publicResult(record, key, idempotentReplay) {
  return {
    outbox_key: key,
    state: record.status,
    idempotent_replay: idempotentReplay,
    immutable_binding_sha256: record.immutable_sha256,
    claim_attempt_count: record.claim_attempt_count,
    lease_expires_at: record.lease_expires_at,
    arc2_start_receipt_sha256: record.arc2_start_receipt_sha256,
  };
}

async function createOutbox(bridgeStore, immutable, env, now) {
  validateOutboxImmutable(immutable);
  const immutableSha256 = sha256Hex(canonicalJson(immutable));
  const key = outboxKey(immutableSha256, env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET);
  const timestamp = now.toISOString();
  const record = {
    schema: PAYMENT_ARC2_OUTBOX_SCHEMA,
    record_revision: 1,
    status: 'PENDING',
    created_at: timestamp,
    updated_at: timestamp,
    immutable,
    immutable_sha256: immutableSha256,
    claim_attempt_count: 0,
    lease_claim_hmac_sha256: null,
    lease_claimed_at: null,
    lease_expires_at: null,
    completion_claim_hmac_sha256: null,
    arc2_start_receipt_sha256: null,
    completion_receipt_sha256: null,
    completed_at: null,
  };
  validateOutboxRecord(record, key, env);
  let result;
  try {
    result = await bridgeStore.setJSON(key, record, { onlyIfNew: true });
  } catch (error) {
    const recovered = await readOutbox(bridgeStore, key, env).catch(() => null);
    if (recovered && safeEqual(recovered.record.immutable_sha256, immutableSha256)) {
      return publicResult(recovered.record, key, true);
    }
    throw error;
  }
  if (result?.modified) return publicResult(record, key, false);
  const existing = await readOutbox(bridgeStore, key, env);
  if (!existing || !safeEqual(existing.record.immutable_sha256, immutableSha256)) {
    throw new Error('ARC_PAYMENT_ARC2_OUTBOX_CONFLICT');
  }
  return publicResult(existing.record, key, true);
}

function sameReview(left, right) {
  return left.etag === right.etag && left.record.record_revision === right.record.record_revision &&
    safeEqual(left.record.record_hmac_sha256, right.record.record_hmac_sha256) &&
    safeEqual(left.recordSha256, right.recordSha256) &&
    left.recipientControlSha256 === right.recipientControlSha256 &&
    left.checkoutAuthoritySha256 === right.checkoutAuthoritySha256;
}

function sameLedger(left, right) {
  return left.sessionEtag === right.sessionEtag && left.receiptEtag === right.receiptEtag &&
    safeEqual(left.digest, right.digest) && safeEqual(left.receiptSha256, right.receiptSha256);
}

export async function createPaymentArc2StartOutbox(stores, input, env = process.env, adapters = {}) {
  const configuration = requireBridge(env);
  const reviewStore = storeSet(stores, 'review');
  const ledgerStore = storeSet(stores, 'ledger');
  const bridgeStore = storeSet(stores, 'bridge');
  exactKeys(input, ['invite_hmac_sha256', 'checkout_session_id'], 'Payment ARC2 creation input');
  const inviteHmac = hex64(input.invite_hmac_sha256, 'Payment ARC2 review invite HMAC');
  if (!CHECKOUT_SESSION_ID.test(String(input.checkout_session_id || '')) ||
      !input.checkout_session_id.startsWith(configuration.expectedLivemode ? 'cs_live_' : 'cs_test_')) {
    throw new TypeError('Payment ARC2 Checkout Session id is invalid.');
  }
  if (typeof adapters.retrieveCheckoutSessionAuthority !== 'function') {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_AUTHORITY_REQUIRED');
  }
  const now = clockDate(adapters);
  // A payment method may settle asynchronously after the invite expires. The
  // provider's immutable Session.created timestamp consumes the fresh approval
  // window; a later signed PAID settlement is bounded separately below.
  const review = await readAuthoritativeReview(reviewStore, inviteHmac, env, now, { enforceFreshness: false });
  const sessionStorageKey = stripeCheckoutKeys.sessionStateKey(input.checkout_session_id, env);
  let providerAuthority;
  try {
    providerAuthority = await adapters.retrieveCheckoutSessionAuthority(input.checkout_session_id, {
      expand: ['payment_intent'],
    });
  } catch (cause) {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_AUTHORITY_FAILED', { cause });
  }
  const provider = providerProjection(
    providerAuthority,
    input.checkout_session_id,
    review.record,
    env,
    configuration,
    now,
  );
  if (review.checkoutAuthority && review.checkoutAuthority.session_id !== input.checkout_session_id) {
    throw new Error('ARC_PAYMENT_ARC2_REVIEW_REQUIRED');
  }
  const ledger = await readAuthoritativeLedger(ledgerStore, sessionStorageKey, provider.projection,
    review.record, env, configuration);
  const currentReview = await readAuthoritativeReview(reviewStore, inviteHmac, env, now, { enforceFreshness: false });
  const currentLedger = await readAuthoritativeLedger(ledgerStore, sessionStorageKey, provider.projection,
    review.record, env, configuration);
  if (!sameReview(review, currentReview) || !sameLedger(ledger, currentLedger)) {
    throw new Error('ARC_PAYMENT_ARC2_AUTHORITY_CHANGED');
  }
  const bindingImmutable = {
    schema: 'arc-payment-review-session-immutable-v1',
    invite_hmac_sha256: review.record.invite_hmac_sha256,
    review_record_revision: review.record.record_revision,
    review_record_hmac_sha256: review.record.record_hmac_sha256,
    review_record_sha256: review.recordSha256,
    approval_receipt_sha256: review.record.decision.approval_receipt_sha256,
    approval_receipt_hmac_sha256: review.record.decision.approval_receipt_hmac_sha256,
    preview_manifest_sha256: review.record.preview_manifest_sha256,
    preview_content_sha256: review.record.preview_content_sha256,
    brief_sha256: review.record.brief_sha256,
    recipient_email_sha256: review.record.recipient_email_sha256,
    payer_email_sha256: provider.projection.payer_email_sha256,
    checkout_idempotency_key_sha256: review.record.decision.checkout_idempotency_key_sha256,
    checkout_session_id_hmac_sha256: provider.projection.checkout_session_id_hmac_sha256,
    payment_intent_id_hmac_sha256: provider.projection.payment_intent_id_hmac_sha256,
    client_reference_id_sha256: provider.projection.client_reference_id_sha256,
    stripe_account_id_sha256: provider.projection.stripe_account_id_sha256,
    livemode: provider.projection.livemode,
    currency: provider.projection.currency,
    subtotal_amount_minor_units: provider.projection.subtotal_amount_minor_units,
    tax_amount_minor_units: provider.projection.tax_amount_minor_units,
    amount_total_minor_units: provider.projection.amount_total_minor_units,
    customer_address_country: provider.projection.customer_address_country,
    customer_address_state: provider.projection.customer_address_state,
    scope_version: review.record.scope_version,
    revision_round: review.record.revision_round,
    approval_decided_at: review.record.decision.decided_at,
    authorization_expires_at: review.record.expires_at,
    checkout_session_created_at: provider.projection.checkout_session_created_at,
    provider_metadata_sha256: provider.projection.metadata_sha256,
    provider_session_binding_sha256: provider.digest,
    ledger_session_storage_key: sessionStorageKey,
    ledger_payment_binding_sha256: ledger.digest,
    ledger_receipt_sha256: ledger.receiptSha256,
    payment_state_event_sha256: ledger.binding.payment_state_event_sha256,
  };
  const binding = await createReviewSessionBinding(bridgeStore, bindingImmutable, env, now);
  const outbox = await createOutbox(bridgeStore, buildOutboxImmutable(binding.record), env, now);
  const pendingIndexCreated = await ensurePendingIndex(bridgeStore, outbox.outbox_key, env);
  return {
    ...outbox,
    pending_index_created: pendingIndexCreated,
    review_session_binding_created: binding.created,
    review_session_binding_sha256: binding.record.immutable_sha256,
  };
}

async function readBindingForOutbox(stores, outbox, env, configuration, now) {
  const reviewStore = storeSet(stores, 'review');
  const ledgerStore = storeSet(stores, 'ledger');
  const bridgeStore = storeSet(stores, 'bridge');
  const key = reviewSessionKey(outbox.immutable.invite_hmac_sha256, env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET);
  const entry = await strongRead(bridgeStore, key, 'ARC_PAYMENT_ARC2_BINDING_REQUIRED');
  const binding = validateReviewSessionRecord(entry.data, key, env);
  if (!safeEqual(binding.immutable_sha256, outbox.immutable.review_session_binding_sha256)) {
    throw new Error('ARC_PAYMENT_ARC2_BINDING_MISMATCH');
  }
  // Authorization freshness is consumed exactly once when the paid binding is
  // created. Resumable claim/completion still revalidate the current signed
  // review identity, lineage/revocation state, and authoritative paid ledger,
  // but an elapsed invite window cannot strand already-verified paid work.
  const review = await readAuthoritativeReview(reviewStore, binding.immutable.invite_hmac_sha256, env, now, {
    enforceFreshness: false,
  });
  if (review.checkoutAuthority && (!CHECKOUT_SESSION_ID.test(String(review.checkoutAuthority.session_id || '')) ||
      !safeEqual(identityHmac(env, 'session-id', review.checkoutAuthority.session_id),
        binding.immutable.checkout_session_id_hmac_sha256))) {
    throw new Error('ARC_PAYMENT_ARC2_REVIEW_REQUIRED');
  }
  if (review.record.record_revision !== binding.immutable.review_record_revision ||
      !safeEqual(review.record.record_hmac_sha256, binding.immutable.review_record_hmac_sha256) ||
      !safeEqual(review.recordSha256, binding.immutable.review_record_sha256)) {
    throw new Error('ARC_PAYMENT_ARC2_APPROVAL_STALE');
  }
  const expected = {
    checkout_session_id_hmac_sha256: binding.immutable.checkout_session_id_hmac_sha256,
    payment_intent_id_hmac_sha256: binding.immutable.payment_intent_id_hmac_sha256,
    client_reference_id_sha256: binding.immutable.client_reference_id_sha256,
    payer_email_sha256: binding.immutable.payer_email_sha256,
    customer_address_country: binding.immutable.customer_address_country,
    customer_address_state: binding.immutable.customer_address_state,
    subtotal_amount_minor_units: binding.immutable.subtotal_amount_minor_units,
    tax_amount_minor_units: binding.immutable.tax_amount_minor_units,
    amount_total_minor_units: binding.immutable.amount_total_minor_units,
    metadata_sha256: binding.immutable.provider_metadata_sha256,
  };
  const ledger = await readAuthoritativeLedger(ledgerStore, binding.immutable.ledger_session_storage_key,
    expected, review.record, env, configuration);
  if (!safeEqual(ledger.digest, binding.immutable.ledger_payment_binding_sha256) ||
      !safeEqual(ledger.receiptSha256, binding.immutable.ledger_receipt_sha256)) {
    throw new Error('ARC_PAYMENT_ARC2_LEDGER_BINDING_MISMATCH');
  }
  return { binding, ledger, review };
}

function validateReviewArtifactBinding(value, review) {
  exactKeys(value, REVIEW_ARTIFACT_BINDING_FIELDS, 'Payment ARC2 review artifact binding');
  for (const field of REVIEW_ARTIFACT_BINDING_FIELDS.filter(name => name.endsWith('_sha256'))) {
    hex64(value[field], `Payment ARC2 review artifact ${field}`);
  }
  if (!/^[a-z0-9][a-z0-9-]*-[a-f0-9]{8}$/.test(String(value.preview_folder || '')) ||
      !/^[a-f0-9]{40}$/.test(String(value.preview_source_commit_sha || '')) ||
      value.preview_source_repository !== 'arcwebhq-cpu/arc-previews' ||
      value.preview_source_repository !== review.preview_source_repository ||
      value.preview_source_commit_sha !== review.preview_source_commit_sha ||
      !safeEqual(value.artifact_manifest_sha256, review.preview_manifest_sha256) ||
      !safeEqual(value.production_content_sha256, review.preview_content_sha256) ||
      !safeEqual(value.checkout_reference_sha256, sha256Hex(review.decision.approval_receipt_sha256))) {
    throw new Error('ARC_PAYMENT_ARC2_ARTIFACT_BINDING_MISMATCH');
  }
  return value;
}

/**
 * Produces transient, signed ARC2 review-session evidence only for the holder
 * of a live outbox lease. Raw Stripe ids are never persisted by this bridge;
 * they are re-read from Stripe authority and bound to their durable HMACs.
 */
export async function createPaymentArc2ReviewEvidence(stores, input, env = process.env, adapters = {}) {
  const configuration = requireBridge(env);
  exactKeys(input, ['artifact_binding', 'checkout_session_id', 'claim_token', 'outbox_key'],
    'Payment ARC2 review evidence input');
  validateOutboxKey(input.outbox_key);
  if (!CHECKOUT_SESSION_ID.test(String(input.checkout_session_id || '')) ||
      !input.checkout_session_id.startsWith(configuration.expectedLivemode ? 'cs_live_' : 'cs_test_')) {
    throw new TypeError('Payment ARC2 Checkout Session id is invalid.');
  }
  if (typeof adapters.retrieveCheckoutSessionAuthority !== 'function') {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_AUTHORITY_REQUIRED');
  }
  const now = clockDate(adapters);
  const bridgeStore = storeSet(stores, 'bridge');
  const entry = await readOutbox(bridgeStore, input.outbox_key, env);
  if (!entry || entry.record.status !== 'CLAIMED') throw new Error('ARC_PAYMENT_ARC2_CLAIM_REQUIRED');
  if (Date.parse(entry.record.lease_expires_at) <= now.getTime()) throw new Error('ARC_PAYMENT_ARC2_LEASE_EXPIRED');
  const expectedClaimHmac = claimHmac(input.outbox_key, input.claim_token,
    env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET);
  if (!safeEqual(entry.record.lease_claim_hmac_sha256, expectedClaimHmac)) {
    throw new Error('ARC_PAYMENT_ARC2_CLAIM_MISMATCH');
  }
  const authority = await readBindingForOutbox(stores, entry.record, env, configuration, now);
  const immutable = authority.binding.immutable;
  if (!safeEqual(entry.record.immutable.review_session_binding_sha256,
    authority.binding.immutable_sha256) ||
      !safeEqual(entry.record.immutable_sha256, sha256Hex(canonicalJson(entry.record.immutable)))) {
    throw new Error('ARC_PAYMENT_ARC2_BINDING_MISMATCH');
  }
  const artifact = validateReviewArtifactBinding(input.artifact_binding, authority.review.record);
  let providerAuthority;
  try {
    providerAuthority = await adapters.retrieveCheckoutSessionAuthority(input.checkout_session_id, {
      expand: ['payment_intent'],
    });
  } catch (cause) {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_AUTHORITY_FAILED', { cause });
  }
  const provider = providerProjection(providerAuthority, input.checkout_session_id,
    authority.review.record, env, configuration, now, { enforceSettlementFreshness: false });
  if (!safeEqual(provider.digest, immutable.provider_session_binding_sha256) ||
      !safeEqual(provider.projection.checkout_session_id_hmac_sha256,
        immutable.checkout_session_id_hmac_sha256) ||
      !safeEqual(provider.projection.payment_intent_id_hmac_sha256,
        immutable.payment_intent_id_hmac_sha256) ||
      !safeEqual(provider.projection.payer_email_sha256, immutable.payer_email_sha256)) {
    throw new Error('ARC_PAYMENT_ARC2_PROVIDER_SESSION_MISMATCH');
  }
  const paymentIntentId = providerAuthority.session.payment_intent.id;
  const evidence = {
    version: PAYMENT_ARC2_REVIEW_EVIDENCE_VERSION,
    scope: PAYMENT_ARC2_REVIEW_EVIDENCE_SCOPE,
    bridge_outbox_key_sha256: sha256Hex(input.outbox_key),
    bridge_immutable_binding_sha256: entry.record.immutable_sha256,
    review_session_binding_sha256: authority.binding.immutable_sha256,
    invite_hmac_sha256: immutable.invite_hmac_sha256,
    approval_receipt_sha256: immutable.approval_receipt_sha256,
    approval_receipt_hmac_sha256: immutable.approval_receipt_hmac_sha256,
    preview_manifest_sha256: immutable.preview_manifest_sha256,
    preview_content_sha256: immutable.preview_content_sha256,
    brief_sha256: immutable.brief_sha256,
    claim_recipient_email_sha256: immutable.recipient_email_sha256,
    payer_email_sha256: immutable.payer_email_sha256,
    checkout_session_id: input.checkout_session_id,
    checkout_session_id_hmac_sha256: immutable.checkout_session_id_hmac_sha256,
    payment_intent_id: paymentIntentId,
    payment_intent_id_hmac_sha256: immutable.payment_intent_id_hmac_sha256,
    payment_link_id: null,
    client_reference_id_sha256: immutable.client_reference_id_sha256,
    stripe_account_id_sha256: immutable.stripe_account_id_sha256,
    livemode: immutable.livemode,
    mode: 'payment',
    status: 'complete',
    payment_status: 'paid',
    currency: immutable.currency,
    subtotal_amount_minor_units: immutable.subtotal_amount_minor_units,
    tax_amount_minor_units: immutable.tax_amount_minor_units,
    amount_total_minor_units: immutable.amount_total_minor_units,
    automatic_tax_enabled: true,
    automatic_tax_status: 'complete',
    terms_of_service_consent: 'accepted',
    adult_purchaser_acknowledgement: 'accepted',
    customer_address_country: immutable.customer_address_country,
    customer_address_state: immutable.customer_address_state,
    artifact_manifest_sha256: artifact.artifact_manifest_sha256,
    handoff_artifact_evidence_sha256: artifact.artifact_evidence_sha256,
    bundle_fingerprint: artifact.bundle_fingerprint,
    production_content_sha256: artifact.production_content_sha256,
    preview_folder: artifact.preview_folder,
    preview_source_repository: artifact.preview_source_repository,
    preview_source_commit_sha: artifact.preview_source_commit_sha,
  };
  const canonical = canonicalJson(evidence);
  const stripeMode = configuration.expectedLivemode ? 'live' : 'test';
  return Object.freeze({
    canonical,
    digest: sha256Hex(canonical),
    signature: hmacHex(env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET,
      `${PAYMENT_ARC2_REVIEW_EVIDENCE_SIGNATURE_PREFIX}${stripeMode}\n${canonical}`),
    value: Object.freeze(evidence),
  });
}

function claimHmac(key, token, secret) {
  if (typeof token !== 'string' || !CLAIM_TOKEN.test(token)) throw new TypeError('Payment ARC2 claim token is invalid.');
  return hmacHex(secret, `${CLAIM_HMAC_PREFIX}${key}\n${token}`);
}

function claimResult(record, key, idempotentReplay) {
  return { ...publicResult(record, key, idempotentReplay), payload: structuredClone(record.immutable) };
}

export async function claimPaymentArc2StartOutbox(stores, key, claimToken, env = process.env, adapters = {}) {
  const configuration = requireBridge(env);
  const bridgeStore = storeSet(stores, 'bridge');
  validateOutboxKey(key);
  const tokenHmac = claimHmac(key, claimToken, env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET);
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
    const now = clockDate(adapters);
    const entry = await readOutbox(bridgeStore, key, env);
    if (!entry) throw new Error('ARC_PAYMENT_ARC2_OUTBOX_REQUIRED');
    if (entry.record.status === 'COMPLETED') return claimResult(entry.record, key, true);
    await readBindingForOutbox(stores, entry.record, env, configuration, now);
    if (entry.record.status === 'CLAIMED' && Date.parse(entry.record.lease_expires_at) > now.getTime()) {
      if (!safeEqual(entry.record.lease_claim_hmac_sha256, tokenHmac)) throw new Error('ARC_PAYMENT_ARC2_OUTBOX_LEASED');
      return claimResult(entry.record, key, true);
    }
    const timestamp = now.toISOString();
    const next = {
      ...entry.record,
      record_revision: entry.record.record_revision + 1,
      status: 'CLAIMED',
      updated_at: timestamp,
      claim_attempt_count: entry.record.claim_attempt_count + 1,
      lease_claim_hmac_sha256: tokenHmac,
      lease_claimed_at: timestamp,
      lease_expires_at: new Date(now.getTime() + PAYMENT_ARC2_LEASE_SECONDS * 1000).toISOString(),
    };
    validateOutboxRecord(next, key, env);
    try {
      const result = await bridgeStore.setJSON(key, next, { onlyIfMatch: entry.etag });
      if (result?.modified) return claimResult(next, key, false);
    } catch (error) {
      const recovered = await readOutbox(bridgeStore, key, env).catch(() => null);
      if (recovered?.record.status === 'CLAIMED' && safeEqual(recovered.record.lease_claim_hmac_sha256, tokenHmac)) {
        return claimResult(recovered.record, key, true);
      }
      throw error;
    }
  }
  throw new Error('ARC_PAYMENT_ARC2_OUTBOX_CONTENTION');
}

export async function releasePaymentArc2StartOutbox(stores, key, claimToken, env = process.env, adapters = {}) {
  const configuration = requireBridge(env);
  const bridgeStore = storeSet(stores, 'bridge');
  validateOutboxKey(key);
  const tokenHmac = claimHmac(key, claimToken, env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET);
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
    const now = clockDate(adapters);
    const entry = await readOutbox(bridgeStore, key, env);
    if (!entry) throw new Error('ARC_PAYMENT_ARC2_OUTBOX_REQUIRED');
    if (entry.record.status === 'COMPLETED') return publicResult(entry.record, key, true);
    if (entry.record.status === 'PENDING') {
      await ensurePendingIndex(bridgeStore, key, env);
      return publicResult(entry.record, key, true);
    }
    await readBindingForOutbox(stores, entry.record, env, configuration, now);
    if (Date.parse(entry.record.lease_expires_at) <= now.getTime()) {
      throw new Error('ARC_PAYMENT_ARC2_LEASE_EXPIRED');
    }
    if (!safeEqual(entry.record.lease_claim_hmac_sha256, tokenHmac)) {
      throw new Error('ARC_PAYMENT_ARC2_CLAIM_MISMATCH');
    }
    const next = {
      ...entry.record,
      record_revision: entry.record.record_revision + 1,
      status: 'PENDING',
      updated_at: now.toISOString(),
      lease_claim_hmac_sha256: null,
      lease_claimed_at: null,
      lease_expires_at: null,
    };
    validateOutboxRecord(next, key, env);
    try {
      const result = await bridgeStore.setJSON(key, next, { onlyIfMatch: entry.etag });
      if (result?.modified) {
        await ensurePendingIndex(bridgeStore, key, env);
        return publicResult(next, key, false);
      }
    } catch (error) {
      const recovered = await readOutbox(bridgeStore, key, env).catch(() => null);
      if (recovered?.record.status === 'PENDING') {
        await ensurePendingIndex(bridgeStore, key, env);
        return publicResult(recovered.record, key, true);
      }
      throw error;
    }
  }
  throw new Error('ARC_PAYMENT_ARC2_OUTBOX_CONTENTION');
}

export async function claimNextPaymentArc2StartOutbox(stores, claimToken, env = process.env, adapters = {}) {
  requireBridge(env);
  const bridgeStore = storeSet(stores, 'bridge');
  if (typeof bridgeStore.list !== 'function') throw new Error('ARC_PAYMENT_ARC2_QUEUE_UNAVAILABLE');
  // Validate the worker capability even when the durable queue is empty.
  claimHmac(`${OUTBOX_KEY_PREFIX}${'0'.repeat(64)}`, claimToken, env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET);
  const pages = bridgeStore.list({ prefix: PENDING_INDEX_KEY_PREFIX, paginate: true });
  if (!pages || typeof pages[Symbol.asyncIterator] !== 'function') {
    throw new Error('ARC_PAYMENT_ARC2_QUEUE_UNAVAILABLE');
  }
  for await (const page of pages) {
    if (!page || !Array.isArray(page.blobs)) throw new Error('ARC_PAYMENT_ARC2_QUEUE_UNAVAILABLE');
    for (const blob of page.blobs) {
      const indexKey = blob?.key;
      if (typeof indexKey !== 'string' || !/^payment-arc2-pending\/[a-f0-9]{64}$/.test(indexKey)) {
        throw new Error('ARC_PAYMENT_ARC2_QUEUE_CORRUPT');
      }
      const indexEntry = await strongRead(bridgeStore, indexKey, 'ARC_PAYMENT_ARC2_QUEUE_CORRUPT');
      const pending = validatePendingIndex(indexEntry.data, indexKey);
      const indexedOutbox = await readOutbox(bridgeStore, pending.outbox_key, env);
      if (!indexedOutbox || !safeEqual(
        indexedOutbox.record.immutable_sha256,
        pending.immutable_binding_sha256,
      )) throw new Error('ARC_PAYMENT_ARC2_QUEUE_CORRUPT');
      if (indexedOutbox.record.status === 'COMPLETED') {
        await removePendingIndex(bridgeStore, pending.outbox_key);
        continue;
      }
      try {
        const result = await claimPaymentArc2StartOutbox(stores, pending.outbox_key, claimToken, env, adapters);
        if (result.state === 'CLAIMED') return result;
        if (result.state === 'COMPLETED') await removePendingIndex(bridgeStore, pending.outbox_key);
      } catch (error) {
        if (/ARC_PAYMENT_ARC2_OUTBOX_LEASED/.test(error?.message || '')) continue;
        // Durable review/ledger/revocation authorities already own the manual
        // review/refund state. One halted payment must not head-of-line block
        // independent paid work behind it in the discoverable queue.
        if (/REVIEW_REQUIRED|APPROVAL_REQUIRED|EMAIL_DELIVERY_REQUIRED|LEDGER_HALT|PAYMENT_NOT_AUTHORIZED|AUTHORITY_CHANGED/.test(
          error?.message || '',
        )) continue;
        throw error;
      }
    }
  }
  return null;
}

async function normalizeCompletion(stores, value, outbox, env) {
  exactKeys(value, COMPLETION_FIELDS, 'Payment ARC2 completion receipt');
  if (value.schema !== PAYMENT_ARC2_COMPLETION_SCHEMA || value.accepted !== true) {
    throw new TypeError('Payment ARC2 completion receipt is invalid.');
  }
  if (!safeEqual(hex64(value.immutable_binding_sha256, 'Completion immutable binding digest'),
    outbox.immutable_sha256)) {
    throw new Error('ARC_PAYMENT_ARC2_COMPLETION_MISMATCH');
  }
  const receiptCanonical = typeof value.arc2_start_receipt === 'string'
    ? value.arc2_start_receipt : '';
  if (receiptCanonical.length < 2 || receiptCanonical.length > 20_000) {
    throw new TypeError('ARC2 start receipt is invalid.');
  }
  const receipt = plainObject(JSON.parse(receiptCanonical), 'ARC2 start receipt');
  exactKeys(receipt, START_RECEIPT_FIELDS, 'ARC2 start receipt');
  if (canonicalJson(receipt) !== receiptCanonical || receipt.schema !== START_RECEIPT_SCHEMA ||
      receipt.accepted !== true || receipt.reversal_control_ready !== true ||
      receipt.continuation_ready !== true || !ARC2_CONTINUATION_STATES.has(receipt.handoff_state) ||
      !safeEqual(hex64(value.arc2_start_receipt_hmac_sha256, 'ARC2 start receipt signature'),
        hmacHex(env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET,
          `${START_RECEIPT_SIGNATURE_PREFIX}${receiptCanonical}`))) {
    throw new Error('ARC_PAYMENT_ARC2_START_RECEIPT_INVALID');
  }
  if (!/^[a-f0-9]{64}$/.test(String(receipt.handoff_id || '')) ||
      !safeEqual(receipt.bridge_immutable_binding_sha256, outbox.immutable_sha256) ||
      !safeEqual(receipt.review_session_binding_sha256,
        outbox.immutable.review_session_binding_sha256) ||
      !safeEqual(receipt.checkout_session_id_hmac_sha256,
        outbox.immutable.checkout_session_id_hmac_sha256) ||
      !safeEqual(receipt.payment_intent_id_hmac_sha256,
        outbox.immutable.payment_intent_id_hmac_sha256) ||
      !safeEqual(receipt.recipient_email_sha256, outbox.immutable.recipient_email_sha256) ||
      !safeEqual(receipt.payer_email_sha256, outbox.immutable.payer_email_sha256)) {
    throw new Error('ARC_PAYMENT_ARC2_START_RECEIPT_MISMATCH');
  }
  for (const field of START_RECEIPT_FIELDS.filter(name => name.endsWith('_sha256'))) {
    hex64(receipt[field], `ARC2 start receipt ${field}`);
  }
  isoTimestamp(receipt.started_at, 'ARC2 start receipt timestamp');
  const ledgerStore = storeSet(stores, 'ledger');
  const handoff = await strongRead(ledgerStore, `handoffs/${receipt.handoff_id}`,
    'ARC_PAYMENT_ARC2_HANDOFF_REQUIRED');
  if (handoff.data.schema !== 'arc2-netlify-handoff-v2' ||
      handoff.data.handoff_id !== receipt.handoff_id ||
      handoff.data.created_at !== receipt.started_at ||
      !ARC2_CONTINUATION_STATES.has(handoff.data.state) ||
      handoff.data.payment_evidence_sha256 !== receipt.payment_evidence_sha256 ||
      handoff.data.artifact_evidence_sha256 !== receipt.artifact_evidence_sha256 ||
      handoff.data.customer_email_sha256 !== receipt.recipient_email_sha256) {
    throw new Error('ARC_PAYMENT_ARC2_HANDOFF_MISMATCH');
  }
  const checkoutBinding = await strongRead(ledgerStore,
    `stripe-checkout-handoff/${receipt.handoff_id}`,
    'ARC_PAYMENT_ARC2_HANDOFF_REQUIRED');
  if (checkoutBinding.data.schema !== 'arc-stripe-review-checkout-handoff-binding-v1' ||
      checkoutBinding.data.handoff_id !== receipt.handoff_id ||
      checkoutBinding.data.payment_evidence_sha256 !== receipt.payment_evidence_sha256 ||
      checkoutBinding.data.bridge_immutable_binding_sha256 !== receipt.bridge_immutable_binding_sha256 ||
      checkoutBinding.data.review_session_binding_sha256 !== receipt.review_session_binding_sha256 ||
      checkoutBinding.data.checkout_session_id_hmac_sha256 !== receipt.checkout_session_id_hmac_sha256 ||
      checkoutBinding.data.payment_intent_id_hmac_sha256 !== receipt.payment_intent_id_hmac_sha256 ||
      checkoutBinding.data.recipient_email_sha256 !== receipt.recipient_email_sha256 ||
      checkoutBinding.data.payer_email_sha256 !== receipt.payer_email_sha256 ||
      checkoutBinding.data.payment_link_id_hmac_sha256 !== null) {
    throw new Error('ARC_PAYMENT_ARC2_HANDOFF_MISMATCH');
  }
  return {
    arc2StartReceiptSha256: sha256Hex(receiptCanonical),
    digest: sha256Hex(canonicalJson(value)),
    value: structuredClone(value),
  };
}

export async function completePaymentArc2StartOutbox(stores, key, claimToken, completion, env = process.env, adapters = {}) {
  const configuration = requireBridge(env);
  const bridgeStore = storeSet(stores, 'bridge');
  validateOutboxKey(key);
  const tokenHmac = claimHmac(key, claimToken, env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET);
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
    const now = clockDate(adapters);
    const entry = await readOutbox(bridgeStore, key, env);
    if (!entry) throw new Error('ARC_PAYMENT_ARC2_OUTBOX_REQUIRED');
    if (entry.record.status === 'COMPLETED') {
      const normalized = await normalizeCompletion(stores, completion, entry.record, env);
      if (!safeEqual(entry.record.completion_claim_hmac_sha256, tokenHmac) ||
          !safeEqual(entry.record.completion_receipt_sha256, normalized.digest) ||
          !safeEqual(entry.record.arc2_start_receipt_sha256, normalized.arc2StartReceiptSha256)) {
        throw new Error('ARC_PAYMENT_ARC2_COMPLETION_CONFLICT');
      }
      await removePendingIndex(bridgeStore, key);
      return publicResult(entry.record, key, true);
    }
    await readBindingForOutbox(stores, entry.record, env, configuration, now);
    if (entry.record.status !== 'CLAIMED') throw new Error('ARC_PAYMENT_ARC2_CLAIM_REQUIRED');
    if (Date.parse(entry.record.lease_expires_at) <= now.getTime()) throw new Error('ARC_PAYMENT_ARC2_LEASE_EXPIRED');
    if (!safeEqual(entry.record.lease_claim_hmac_sha256, tokenHmac)) throw new Error('ARC_PAYMENT_ARC2_CLAIM_MISMATCH');
    const normalized = await normalizeCompletion(stores, completion, entry.record, env);
    const timestamp = now.toISOString();
    const next = {
      ...entry.record,
      record_revision: entry.record.record_revision + 1,
      status: 'COMPLETED',
      updated_at: timestamp,
      lease_claim_hmac_sha256: null,
      lease_claimed_at: null,
      lease_expires_at: null,
      completion_claim_hmac_sha256: tokenHmac,
      arc2_start_receipt_sha256: normalized.arc2StartReceiptSha256,
      completion_receipt_sha256: normalized.digest,
      completed_at: timestamp,
    };
    validateOutboxRecord(next, key, env);
    try {
      const result = await bridgeStore.setJSON(key, next, { onlyIfMatch: entry.etag });
      if (result?.modified) {
        await removePendingIndex(bridgeStore, key);
        return publicResult(next, key, false);
      }
    } catch (error) {
      const recovered = await readOutbox(bridgeStore, key, env).catch(() => null);
      if (recovered?.record.status === 'COMPLETED' &&
          safeEqual(recovered.record.completion_claim_hmac_sha256, tokenHmac) &&
          safeEqual(recovered.record.completion_receipt_sha256, normalized.digest)) {
        await removePendingIndex(bridgeStore, key);
        return publicResult(recovered.record, key, true);
      }
      throw error;
    }
  }
  throw new Error('ARC_PAYMENT_ARC2_OUTBOX_CONTENTION');
}
