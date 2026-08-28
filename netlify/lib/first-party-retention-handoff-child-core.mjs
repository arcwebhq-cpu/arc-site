import {
  canonicalJson,
  hmacHex,
  normalizeProductionUrl,
  safeEqual,
  sha256Hex,
  validateExpectedBindings,
} from './arc2-handoff-core.mjs';

export const HANDOFF_CHILD_RETENTION_ACTION = Object.freeze({
  CASCADE: 'CASCADE',
  PRESERVE: 'PRESERVE',
});

export const HANDOFF_CHILD_RETENTION_PREFIXES = Object.freeze([
  'site-index/',
  'checkout-session-index/',
  'checkout-reference-index/',
  'duplicate-payment-review/',
  'invitation-ready-current/',
  'invitation-ready-outbox/',
  'outbox/',
  'final-delivery-provider-event/',
  'final-delivery-provider-message/',
  'stripe-reversal-binding/handoff/',
  'stripe-reversal-recheck/handoff/',
  'stripe-payment-intent/',
  'stripe-reversal-event/',
  'stripe-reversal-pending-payment/',
  'stripe-reversal-pending/',
  'stripe-reversal/handoff/',
  'alerts/stripe-reversal/',
  'alerts/stripe-reversal-unbound/',
  'stripe-checkout-handoff/',
  'stripe-checkout-session/',
  'stripe-checkout-receipt/',
  'stripe-checkout-event/',
  'alerts/stripe-checkout-review/',
]);

const HEX_40 = /^[a-f0-9]{40}$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const CHECKOUT_SESSION_ID = /^cs_(?:test|live)_[A-Za-z0-9_]{6,128}$/;
const HANDOFF_SCHEMA = 'arc2-netlify-handoff-v2';
const FINAL_OUTBOX_SCHEMA = 'arc2-final-delivery-outbox-v1';
const CHECKOUT_EVENT_TYPES = new Set([
  'checkout.session.completed',
  'checkout.session.async_payment_succeeded',
  'checkout.session.async_payment_failed',
  'checkout.session.expired',
]);
const CHECKOUT_STATES = new Set(['PENDING', 'PAID', 'FAILED', 'EXPIRED', 'REVIEW_REQUIRED']);
const REVERSAL_EVENT_TYPES = new Set([
  'charge.dispute.closed', 'charge.dispute.created', 'charge.dispute.funds_reinstated',
  'charge.dispute.funds_withdrawn', 'charge.dispute.updated', 'charge.refunded',
  'refund.created', 'refund.failed', 'refund.updated',
]);

const SITE_INDEX_FIELDS = Object.freeze(['handoff_id', 'netlify_session_id', 'netlify_site_id', 'schema']);
const CHECKOUT_SESSION_INDEX_FIELDS = Object.freeze([
  'artifact_evidence_sha256', 'bundle_fingerprint', 'handoff_id', 'payment_evidence_sha256', 'schema',
]);
const CHECKOUT_REFERENCE_FIELDS = Object.freeze([
  'artifact_evidence_sha256', 'client_reference_id_sha256', 'handoff_id', 'payment_evidence_sha256',
  'preview_source_commit_sha', 'schema', 'winning_checkout_session_id', 'winning_payment_link_id_hmac_sha256',
]);
const REVIEW_CHECKOUT_REFERENCE_FIELDS = Object.freeze([
  'artifact_evidence_sha256', 'bridge_immutable_binding_sha256', 'checkout_session_id_hmac_sha256',
  'client_reference_id_sha256', 'handoff_id', 'payment_evidence_sha256', 'payment_intent_id_hmac_sha256',
  'payment_link_id_hmac_sha256', 'preview_source_commit_sha', 'review_session_binding_sha256', 'schema',
]);
const DUPLICATE_REVIEW_FIELDS = Object.freeze([
  'automatic_refund_requested', 'checkout_reference_sha256', 'duplicate_checkout_session_id_hmac_sha256',
  'duplicate_payment_evidence_sha256', 'duplicate_payment_link_id_hmac_sha256', 'review_hmac_sha256', 'schema',
  'status', 'winning_artifact_evidence_sha256', 'winning_checkout_session_id_hmac_sha256', 'winning_handoff_id',
  'winning_payment_evidence_sha256', 'winning_payment_link_id_hmac_sha256',
]);
const INVITATION_OUTBOX_V1_FIELDS = Object.freeze([
  'claim_token_hmac_sha256', 'expires_at', 'handoff_id', 'recipient_email_sha256', 'schema', 'status',
]);
const INVITATION_OUTBOX_V2_FIELDS = Object.freeze([
  'claim_invitation_generation', ...INVITATION_OUTBOX_V1_FIELDS,
]);
const INVITATION_CURRENT_FIELDS = Object.freeze([
  'binding_hmac_sha256', 'claim_invitation_generation', 'claim_token_hmac_sha256', 'expires_at',
  'handoff_id', 'outbox_key_sha256', 'schema',
]);
const FINAL_OUTBOX_CLAIMED_FIELDS = Object.freeze([
  'handoff_id', 'netlify_deploy_id_sha256', 'netlify_site_id_sha256',
  'outbox_claim_key_hmac_sha256', 'schema', 'status',
]);
const FINAL_OUTBOX_RECEIPT_FIELDS = Object.freeze([
  ...FINAL_OUTBOX_CLAIMED_FIELDS,
  'delivered_at', 'delivery_receipt_sha256', 'delivery_status', 'event_type', 'provider',
  'provider_account_hmac_sha256', 'provider_event_id_hmac_sha256', 'provider_message_id_hmac_sha256',
  'receipt_issued_at',
]);
const FINAL_PROVIDER_FIELDS = Object.freeze([
  'delivery_receipt_sha256', 'handoff_id', 'identity_hmac_sha256', 'kind', 'provider',
  'provider_account_hmac_sha256', 'schema',
]);
const REVERSAL_BINDING_FIELDS = Object.freeze([
  'binding_evidence_sha256', 'checkout_session_id_hmac_sha256', 'handoff_id', 'livemode',
  'payment_evidence_sha256', 'payment_intent_id_hmac_sha256', 'schema', 'stripe_account_id_sha256',
]);
const REVERSAL_RECHECK_FIELDS = Object.freeze([
  'binding_evidence_sha256', 'checkout_session_id_hmac_sha256', 'dispute_status', 'evidence_sha256',
  'handoff_id', 'issued_at', 'livemode', 'payment_intent_id_hmac_sha256', 'payment_intent_status',
  'refunded_amount_minor_units', 'schema', 'stripe_account_id_sha256',
]);
const REVERSAL_EVENT_FIELDS = Object.freeze([
  'amount_minor_units', 'checkout_session_id_hmac_sha256', 'currency', 'event_created_at',
  'event_id_hmac_sha256', 'event_sha256', 'event_status', 'event_type', 'handoff_id', 'kind', 'livemode',
  'object_id_hmac_sha256', 'payment_intent_id_hmac_sha256', 'schema', 'stripe_account_id_sha256',
]);
const PENDING_PAYMENT_FIELDS = Object.freeze([
  'delivery_halted', 'livemode', 'payment_intent_id_hmac_sha256', 'schema', 'stripe_account_id_sha256',
]);
const REVERSAL_STATE_FIELDS = Object.freeze([
  'automatic_refund_requested', 'checkout_session_id_hmac_sha256', 'currency', 'delivery_halted',
  'dispute_observed', 'dispute_state', 'first_event_created_at', 'handoff_id', 'latest_amount_minor_units',
  'latest_event_created_at', 'latest_event_id_hmac_sha256', 'latest_event_sha256', 'latest_event_status',
  'latest_event_type', 'latest_object_id_hmac_sha256', 'livemode', 'manual_review_required',
  'payment_intent_id_hmac_sha256', 'refund_observed', 'refund_state', 'schema', 'severity',
  'stripe_account_id_sha256',
]);
const ALERT_FIELDS = Object.freeze([
  'category', 'contains_customer_data', 'delivery_status', 'detected_at', 'handoff_id', 'schema',
  'severity', 'status', 'subject_hmac_sha256',
]);

const STRIPE_CHECKOUT_EVENT_FIELDS = Object.freeze([
  'adult_purchaser_acknowledgement', 'amount_total_minor_units', 'automatic_tax_enabled',
  'automatic_tax_status', 'checkout_session_id_hmac_sha256', 'client_reference_id_sha256', 'currency',
  'customer_address_country', 'customer_address_state', 'event_created_at', 'event_id_hmac_sha256',
  'event_sha256', 'event_type', 'livemode', 'observed_state', 'payer_email_sha256',
  'payment_intent_id_hmac_sha256', 'payment_link_id_hmac_sha256', 'schema', 'stripe_account_id_sha256',
  'subtotal_amount_minor_units', 'tax_amount_minor_units', 'terms_of_service_consent',
]);
const STRIPE_CHECKOUT_RECEIPT_FIELDS = Object.freeze([
  'accepted', 'checkout_session_id_hmac_sha256', 'event_id_hmac_sha256', 'event_sha256',
  'resulting_state', 'review_alert_required', 'schema', 'stripe_account_id_sha256',
]);
const STRIPE_CHECKOUT_SESSION_FIELDS = Object.freeze([
  'adult_purchaser_acknowledgement', 'amount_total_minor_units', 'automatic_tax_enabled',
  'automatic_tax_status', 'checkout_session_id_hmac_sha256', 'client_reference_id_sha256', 'currency',
  'customer_address_country', 'customer_address_state', 'event_count', 'first_event_created_at',
  'fulfillment_allowed', 'latest_event_created_at', 'latest_event_id_hmac_sha256', 'latest_event_sha256',
  'latest_event_type', 'livemode', 'manual_review_required', 'payer_email_sha256',
  'payment_intent_id_hmac_sha256', 'payment_link_id_hmac_sha256', 'processed_event_hmacs_sha256', 'schema',
  'state', 'state_event_id_hmac_sha256', 'state_event_sha256', 'stripe_account_id_sha256',
  'subtotal_amount_minor_units', 'tax_amount_minor_units', 'terms_of_service_consent',
]);
const STRIPE_CHECKOUT_HANDOFF_FIELDS = Object.freeze([
  'checkout_session_id_hmac_sha256', 'handoff_id', 'livemode', 'payment_evidence_sha256',
  'payment_intent_id_hmac_sha256', 'payment_link_id_hmac_sha256', 'schema', 'stripe_account_id_sha256',
]);
const STRIPE_REVIEW_CHECKOUT_HANDOFF_FIELDS = Object.freeze([
  ...STRIPE_CHECKOUT_HANDOFF_FIELDS,
  'approval_receipt_sha256', 'bridge_immutable_binding_sha256', 'payer_email_sha256',
  'recipient_email_sha256', 'review_checkout_binding_sha256', 'review_session_binding_sha256',
]);
const REVIEW_CHECKOUT_METADATA_FIELDS = Object.freeze([
  'approval_receipt_hmac_sha256', 'approval_receipt_sha256', 'invite_hmac_sha256', 'offer_contract_id',
  'preview_manifest_sha256', 'recipient_email_sha256', 'schema', 'scope_version', 'terms_version',
]);

function exactKeys(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}

function hex64(value) {
  return HEX_64.test(String(value || ''));
}

function iso(value) {
  const parsed = typeof value === 'string' ? Date.parse(value) : Number.NaN;
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}

function validSecret(value) {
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= 32 &&
    Buffer.byteLength(value, 'utf8') <= 512;
}

function unwrap(value) {
  if (!value || typeof value !== 'object') return value || null;
  if (Object.hasOwn(value, 'data') && (Object.hasOwn(value, 'etag') || Object.keys(value).length <= 3)) return value.data;
  if (Object.hasOwn(value, 'value') && Object.hasOwn(value, 'etag')) return value.value;
  if (Object.hasOwn(value, 'record') && Object.hasOwn(value, 'etag')) return value.record;
  return value;
}

async function readValue(read, key) {
  if (typeof read !== 'function') return null;
  return unwrap(await read(key));
}

function primaryRecord(value) {
  const candidate = unwrap(value);
  const record = validateExpectedBindings(candidate);
  if (record.schema !== HANDOFF_SCHEMA || record.state !== 'DELIVERED' || !hex64(record.handoff_id)) {
    throw new TypeError('Terminal handoff primary is invalid.');
  }
  return record;
}

function result(action, family, handoffId, reason, validated) {
  return Object.freeze({ action, family, handoffId: handoffId || null, reason, validated });
}

function cascade(family, handoffId) {
  return result(HANDOFF_CHILD_RETENTION_ACTION.CASCADE, family, handoffId, 'EXACT_TERMINAL_BINDING', true);
}

function preserve(family, handoffId, reason, validated = false) {
  return result(HANDOFF_CHILD_RETENTION_ACTION.PRESERVE, family, handoffId, reason, validated);
}

function envStripeBindingValid(value, env) {
  return hex64(value.stripe_account_id_sha256) &&
    hex64(env?.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256) &&
    safeEqual(value.stripe_account_id_sha256, env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256) &&
    ['true', 'false'].includes(env?.ARC_STRIPE_LIVE_MODE_ENABLED) &&
    value.livemode === (env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true');
}

function sameReversalBinding(left, right) {
  if (!left || !right) return false;
  return ['handoff_id', 'checkout_session_id_hmac_sha256', 'payment_intent_id_hmac_sha256',
    'stripe_account_id_sha256', 'livemode', 'payment_evidence_sha256', 'binding_evidence_sha256']
    .every((field) => left[field] === right[field]);
}

export function handoffChildFamilyForKey(key) {
  if (typeof key !== 'string') return null;
  const prefix = HANDOFF_CHILD_RETENTION_PREFIXES.find((candidate) => key.startsWith(candidate));
  if (!prefix) return null;
  return prefix.slice(0, -1).replaceAll('/', ':');
}

export function checkoutSessionIndexKeyForProof(checkoutSessionId, env) {
  if (!CHECKOUT_SESSION_ID.test(String(checkoutSessionId || '')) || !validSecret(env?.ARC_HANDOFF_STATE_SECRET)) return null;
  return `checkout-session-index/${hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `checkout-session-index-v1\n${checkoutSessionId}`)}`;
}

export function checkoutReferenceIndexKeyForDigest(clientReferenceSha256, env) {
  if (!hex64(clientReferenceSha256) || !validSecret(env?.ARC_HANDOFF_STATE_SECRET)) return null;
  return `checkout-reference-index/${hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `checkout-reference-index-v1\n${clientReferenceSha256}`)}`;
}

function validCheckoutSessionIndex(value, primary) {
  return exactKeys(value, CHECKOUT_SESSION_INDEX_FIELDS) && value.schema === 'arc2-checkout-session-index-v1' &&
    value.handoff_id === primary.handoff_id && value.payment_evidence_sha256 === primary.payment_evidence_sha256 &&
    value.artifact_evidence_sha256 === primary.artifact_evidence_sha256 && value.bundle_fingerprint === primary.bundle_fingerprint &&
    [value.handoff_id, value.payment_evidence_sha256, value.artifact_evidence_sha256, value.bundle_fingerprint].every(hex64);
}

export async function planSiteIndexChild({ key, value, primary }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('site-index', value?.handoff_id, 'PRIMARY_INVALID'); }
  const valid = exactKeys(value, SITE_INDEX_FIELDS) && value.schema === 'arc2-site-index-v1' &&
    value.handoff_id === record.handoff_id && value.netlify_site_id === record.netlify_site_id &&
    value.netlify_session_id === record.netlify_session_id && key === `site-index/${sha256Hex(record.netlify_site_id)}`;
  return valid ? cascade('site-index', record.handoff_id) :
    preserve('site-index', value?.handoff_id, 'SITE_INDEX_BINDING_INVALID');
}

export async function planCheckoutSessionIndexChild({ key, value, primary, env, proof = {} }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('checkout-session-index', value?.handoff_id, 'PRIMARY_INVALID'); }
  if (!validCheckoutSessionIndex(value, record)) {
    return preserve('checkout-session-index', value?.handoff_id, 'CHECKOUT_SESSION_INDEX_BINDING_INVALID');
  }
  const reference = proof.checkoutReference || null;
  const checkoutSessionId = proof.checkoutSessionId ||
    (reference?.schema === 'arc2-checkout-reference-index-v1' ? reference.winning_checkout_session_id : null);
  const expectedKey = checkoutSessionIndexKeyForProof(checkoutSessionId, env);
  if (!expectedKey || key !== expectedKey) {
    return preserve('checkout-session-index', record.handoff_id, 'CHECKOUT_SESSION_RAW_KEY_PROOF_UNAVAILABLE', true);
  }
  return cascade('checkout-session-index', record.handoff_id);
}

export async function planCheckoutReferenceIndexChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('checkout-reference-index', value?.handoff_id, 'PRIMARY_INVALID'); }
  if (!validSecret(env?.ARC_HANDOFF_STATE_SECRET) || !hex64(value?.client_reference_id_sha256) ||
      key !== checkoutReferenceIndexKeyForDigest(value.client_reference_id_sha256, env) || value.handoff_id !== record.handoff_id ||
      value.payment_evidence_sha256 !== record.payment_evidence_sha256 ||
      value.artifact_evidence_sha256 !== record.artifact_evidence_sha256 || !HEX_40.test(String(value.preview_source_commit_sha || ''))) {
    return preserve('checkout-reference-index', value?.handoff_id, 'CHECKOUT_REFERENCE_INDEX_BINDING_INVALID');
  }
  if (value.schema === 'arc2-checkout-reference-index-v1') {
    if (!exactKeys(value, CHECKOUT_REFERENCE_FIELDS) || !CHECKOUT_SESSION_ID.test(value.winning_checkout_session_id) ||
        !hex64(value.winning_payment_link_id_hmac_sha256)) {
      return preserve('checkout-reference-index', record.handoff_id, 'CHECKOUT_REFERENCE_INDEX_SCHEMA_INVALID');
    }
    const sessionKey = checkoutSessionIndexKeyForProof(value.winning_checkout_session_id, env);
    const sessionIndex = await readValue(read, sessionKey);
    if (!validCheckoutSessionIndex(sessionIndex, record)) {
      return preserve('checkout-reference-index', record.handoff_id, 'CHECKOUT_REFERENCE_SESSION_CROSS_BINDING_INVALID');
    }
    return cascade('checkout-reference-index', record.handoff_id);
  }
  if (value.schema !== 'arc2-review-checkout-reference-index-v1' ||
      !exactKeys(value, REVIEW_CHECKOUT_REFERENCE_FIELDS) || value.payment_link_id_hmac_sha256 !== null ||
      ![value.checkout_session_id_hmac_sha256, value.payment_intent_id_hmac_sha256,
        value.bridge_immutable_binding_sha256, value.review_session_binding_sha256].every(hex64)) {
    return preserve('checkout-reference-index', record.handoff_id, 'REVIEW_CHECKOUT_REFERENCE_INDEX_SCHEMA_INVALID');
  }
  const binding = await readValue(read, `stripe-checkout-handoff/${record.handoff_id}`);
  if (!validStripeCheckoutHandoffBinding(binding, record, env) ||
      binding.schema !== 'arc-stripe-review-checkout-handoff-binding-v1' ||
      binding.checkout_session_id_hmac_sha256 !== value.checkout_session_id_hmac_sha256 ||
      binding.payment_intent_id_hmac_sha256 !== value.payment_intent_id_hmac_sha256 ||
      binding.bridge_immutable_binding_sha256 !== value.bridge_immutable_binding_sha256 ||
      binding.review_session_binding_sha256 !== value.review_session_binding_sha256) {
    return preserve('checkout-reference-index', record.handoff_id, 'REVIEW_CHECKOUT_REFERENCE_CROSS_BINDING_INVALID');
  }
  return cascade('checkout-reference-index', record.handoff_id);
}

function validDuplicateReviewShape(value, key, env) {
  const domain = {
    'arc2-duplicate-payment-review-v1': 'arc2-duplicate-payment-review-signature-v1',
    'arc2-review-duplicate-payment-review-v1': 'arc2-review-duplicate-payment-review-signature-v1',
  }[value?.schema];
  if (!domain || !exactKeys(value, DUPLICATE_REVIEW_FIELDS) ||
      value.status !== 'CRITICAL_DUPLICATE_PAID_SESSION_REVIEW_REQUIRED' ||
      value.automatic_refund_requested !== false || !validSecret(env?.ARC_HANDOFF_STATE_SECRET) ||
      ![value.checkout_reference_sha256, value.winning_checkout_session_id_hmac_sha256,
        value.duplicate_checkout_session_id_hmac_sha256, value.winning_handoff_id,
        value.winning_payment_evidence_sha256, value.winning_artifact_evidence_sha256,
        value.duplicate_payment_evidence_sha256, value.review_hmac_sha256].every(hex64) ||
      value.winning_checkout_session_id_hmac_sha256 === value.duplicate_checkout_session_id_hmac_sha256 ||
      value.winning_payment_evidence_sha256 === value.duplicate_payment_evidence_sha256) return false;
  const linkFields = [value.winning_payment_link_id_hmac_sha256, value.duplicate_payment_link_id_hmac_sha256];
  if (value.schema === 'arc2-review-duplicate-payment-review-v1'
    ? linkFields.some((field) => field !== null)
    : linkFields.some((field) => !hex64(field))) return false;
  const digest = hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `duplicate-payment-review-key-v1\n${value.checkout_reference_sha256}\n${value.duplicate_checkout_session_id_hmac_sha256}`);
  if (key !== `duplicate-payment-review/${digest}`) return false;
  const { review_hmac_sha256: signature, ...unsigned } = value;
  return safeEqual(signature, hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `${domain}\n${canonicalJson(unsigned)}`));
}

export async function planDuplicatePaymentReviewChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch {
    return preserve('duplicate-payment-review', value?.winning_handoff_id, 'PRIMARY_INVALID');
  }
  if (!validDuplicateReviewShape(value, key, env) || value.winning_handoff_id !== record.handoff_id ||
      value.winning_payment_evidence_sha256 !== record.payment_evidence_sha256 ||
      value.winning_artifact_evidence_sha256 !== record.artifact_evidence_sha256) {
    return preserve('duplicate-payment-review', value?.winning_handoff_id, 'DUPLICATE_PAYMENT_REVIEW_BINDING_INVALID');
  }
  const referenceKey = checkoutReferenceIndexKeyForDigest(value.checkout_reference_sha256, env);
  const winner = await readValue(read, referenceKey);
  let crossBound = false;
  if (value.schema === 'arc2-duplicate-payment-review-v1' && exactKeys(winner, CHECKOUT_REFERENCE_FIELDS) &&
      winner.schema === 'arc2-checkout-reference-index-v1' && winner.client_reference_id_sha256 === value.checkout_reference_sha256 &&
      winner.handoff_id === record.handoff_id && winner.winning_payment_link_id_hmac_sha256 === value.winning_payment_link_id_hmac_sha256 &&
      winner.payment_evidence_sha256 === value.winning_payment_evidence_sha256 &&
      winner.artifact_evidence_sha256 === value.winning_artifact_evidence_sha256 &&
      CHECKOUT_SESSION_ID.test(winner.winning_checkout_session_id)) {
    const expectedWinnerSession = hmacHex(env.ARC_HANDOFF_STATE_SECRET,
      `duplicate-payment-session-id-v1\n${winner.winning_checkout_session_id}`);
    const session = await readValue(read, checkoutSessionIndexKeyForProof(winner.winning_checkout_session_id, env));
    crossBound = safeEqual(expectedWinnerSession, value.winning_checkout_session_id_hmac_sha256) &&
      validCheckoutSessionIndex(session, record);
  } else if (value.schema === 'arc2-review-duplicate-payment-review-v1' &&
      exactKeys(winner, REVIEW_CHECKOUT_REFERENCE_FIELDS) && winner.schema === 'arc2-review-checkout-reference-index-v1' &&
      winner.client_reference_id_sha256 === value.checkout_reference_sha256 && winner.handoff_id === record.handoff_id &&
      winner.checkout_session_id_hmac_sha256 === value.winning_checkout_session_id_hmac_sha256 &&
      winner.payment_evidence_sha256 === value.winning_payment_evidence_sha256 &&
      winner.artifact_evidence_sha256 === value.winning_artifact_evidence_sha256) {
    crossBound = true;
  }
  return crossBound
    ? preserve('duplicate-payment-review', record.handoff_id, 'UNRESOLVED_DUPLICATE_PAYMENT_REVIEW', true)
    : preserve('duplicate-payment-review', record.handoff_id, 'DUPLICATE_PAYMENT_REVIEW_CROSS_BINDING_INVALID');
}

function currentInvitationToken(record) {
  return record.state === 'INVITATION_READY' ? record.claim_token_hmac_sha256 : record.claim_token_consumed_hmac_sha256;
}

function invitationOutboxProof(key, value, record, env) {
  const legacy = value?.schema === 'arc2-claim-invitation-ready-outbox-v1';
  const current = value?.schema === 'arc2-claim-invitation-ready-outbox-v2';
  if ((!legacy && !current) || !exactKeys(value, legacy ? INVITATION_OUTBOX_V1_FIELDS : INVITATION_OUTBOX_V2_FIELDS) ||
      value.status !== 'READY' || value.handoff_id !== record.handoff_id ||
      value.recipient_email_sha256 !== record.customer_email_sha256 || !hex64(value.claim_token_hmac_sha256) ||
      iso(value.expires_at) === null || !validSecret(env?.ARC_EMAIL_CLAIM_BINDING_SECRET)) return null;
  const generation = legacy ? 0 : value.claim_invitation_generation;
  if (!Number.isSafeInteger(generation) || generation < 0 || generation > 1_000_000 ||
      generation > record.claim_invitation_generation ||
      Date.parse(value.expires_at) > Date.parse(record.claim_token_expires_at)) return null;
  if (generation === record.claim_invitation_generation &&
      (value.claim_token_hmac_sha256 !== currentInvitationToken(record) || value.expires_at !== record.claim_token_expires_at)) return null;
  const binding = legacy ? {
    version: 'arc2-claim-invitation-ready-outbox-v1',
    handoff_id: value.handoff_id,
    recipient_email_sha256: value.recipient_email_sha256,
    claim_token_hmac_sha256: value.claim_token_hmac_sha256,
    expires_at: value.expires_at,
  } : {
    version: 'arc2-claim-invitation-ready-outbox-v2',
    handoff_id: value.handoff_id,
    recipient_email_sha256: value.recipient_email_sha256,
    claim_invitation_generation: generation,
    claim_token_hmac_sha256: value.claim_token_hmac_sha256,
    expires_at: value.expires_at,
  };
  const digest = hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET, canonicalJson(binding));
  return key === `invitation-ready-outbox/${digest}` ? { generation, legacy } : null;
}

function expectedCurrentInvitationOutbox(record, env) {
  const token = currentInvitationToken(record);
  const binding = {
    version: 'arc2-claim-invitation-ready-outbox-v2', handoff_id: record.handoff_id,
    recipient_email_sha256: record.customer_email_sha256,
    claim_invitation_generation: record.claim_invitation_generation,
    claim_token_hmac_sha256: token, expires_at: record.claim_token_expires_at,
  };
  const key = `invitation-ready-outbox/${hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET, canonicalJson(binding))}`;
  return { key, token };
}

function validInvitationPointerShape(value, key, record, env, expectedOutboxKey) {
  if (!exactKeys(value, INVITATION_CURRENT_FIELDS) || value.schema !== 'arc2-claim-invitation-current-v1' ||
      key !== `invitation-ready-current/${record.handoff_id}` || value.handoff_id !== record.handoff_id ||
      value.claim_invitation_generation !== record.claim_invitation_generation ||
      value.claim_token_hmac_sha256 !== currentInvitationToken(record) ||
      value.expires_at !== record.claim_token_expires_at || value.outbox_key_sha256 !== sha256Hex(expectedOutboxKey)) return false;
  const { binding_hmac_sha256: signature, ...binding } = value;
  return hex64(signature) && safeEqual(signature, hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET,
    `arc2-claim-invitation-current-v1\n${canonicalJson(binding)}`));
}

export async function planInvitationOutboxChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('invitation-ready-outbox', value?.handoff_id, 'PRIMARY_INVALID'); }
  const proof = invitationOutboxProof(key, value, record, env);
  if (!proof) return preserve('invitation-ready-outbox', value?.handoff_id, 'INVITATION_OUTBOX_BINDING_INVALID');
  if (proof.generation === record.claim_invitation_generation) return cascade('invitation-ready-outbox', record.handoff_id);
  const current = expectedCurrentInvitationOutbox(record, env);
  const pointerKey = `invitation-ready-current/${record.handoff_id}`;
  const pointer = await readValue(read, pointerKey);
  const currentOutbox = await readValue(read, current.key);
  if (!validInvitationPointerShape(pointer, pointerKey, record, env, current.key) ||
      !invitationOutboxProof(current.key, currentOutbox, record, env)) {
    return preserve('invitation-ready-outbox', record.handoff_id, 'HISTORICAL_INVITATION_CURRENT_AUTHORITY_INVALID');
  }
  return cascade('invitation-ready-outbox', record.handoff_id);
}

export async function planInvitationCurrentChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('invitation-ready-current', value?.handoff_id, 'PRIMARY_INVALID'); }
  const token = currentInvitationToken(record);
  if (!exactKeys(value, INVITATION_CURRENT_FIELDS) || value.schema !== 'arc2-claim-invitation-current-v1' ||
      key !== `invitation-ready-current/${record.handoff_id}` || value.handoff_id !== record.handoff_id ||
      value.claim_invitation_generation !== record.claim_invitation_generation || value.claim_token_hmac_sha256 !== token ||
      value.expires_at !== record.claim_token_expires_at || !hex64(value.outbox_key_sha256) ||
      !validSecret(env?.ARC_EMAIL_CLAIM_BINDING_SECRET)) {
    return preserve('invitation-ready-current', value?.handoff_id, 'INVITATION_CURRENT_BINDING_INVALID');
  }
  const binding = Object.fromEntries(Object.entries(value).filter(([field]) => field !== 'binding_hmac_sha256'));
  if (!safeEqual(value.binding_hmac_sha256, hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET,
    `arc2-claim-invitation-current-v1\n${canonicalJson(binding)}`))) {
    return preserve('invitation-ready-current', record.handoff_id, 'INVITATION_CURRENT_SIGNATURE_INVALID');
  }
  const outboxKey = expectedCurrentInvitationOutbox(record, env).key;
  if (value.outbox_key_sha256 !== sha256Hex(outboxKey) ||
      !invitationOutboxProof(outboxKey, await readValue(read, outboxKey), record, env)) {
    return preserve('invitation-ready-current', record.handoff_id, 'INVITATION_CURRENT_OUTBOX_CROSS_BINDING_INVALID');
  }
  return cascade('invitation-ready-current', record.handoff_id);
}

function validFinalOutbox(value, key, record, env) {
  if (!validSecret(env?.ARC_EMAIL_CLAIM_BINDING_SECRET)) return false;
  let productionUrl;
  try { productionUrl = normalizeProductionUrl(record.production_url); } catch { return false; }
  const digest = hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET, canonicalJson({
    version: FINAL_OUTBOX_SCHEMA,
    netlify_session_id: record.netlify_session_id,
    payment_evidence_sha256: record.payment_evidence_sha256,
    handoff_artifact_evidence_sha256: record.artifact_evidence_sha256,
    recipient_email_sha256: record.customer_email_sha256,
    production_url: productionUrl,
  }));
  if (digest !== record.outbox_claim_key_hmac_sha256 || key !== `outbox/${digest}` || value?.schema !== FINAL_OUTBOX_SCHEMA ||
      value.status !== 'DELIVERED' || !exactKeys(value, FINAL_OUTBOX_RECEIPT_FIELDS) ||
      value.handoff_id !== record.handoff_id || value.outbox_claim_key_hmac_sha256 !== record.outbox_claim_key_hmac_sha256 ||
      value.netlify_site_id_sha256 !== sha256Hex(record.netlify_site_id) ||
      value.netlify_deploy_id_sha256 !== sha256Hex(record.final_deploy_id) ||
      value.delivery_receipt_sha256 !== record.final_delivery_receipt_sha256 ||
      value.provider !== record.final_delivery_provider ||
      value.provider_account_hmac_sha256 !== record.final_delivery_provider_account_hmac_sha256 ||
      value.provider_event_id_hmac_sha256 !== record.final_delivery_provider_event_id_hmac_sha256 ||
      value.provider_message_id_hmac_sha256 !== record.final_delivery_provider_message_id_hmac_sha256 ||
      value.event_type !== record.final_delivery_event_type || value.delivery_status !== record.final_delivery_status ||
      value.delivered_at !== record.delivered_at || value.receipt_issued_at !== record.final_delivery_receipt_issued_at) return false;
  const deliveredAt = iso(value.delivered_at);
  const issuedAt = iso(value.receipt_issued_at);
  return deliveredAt !== null && issuedAt !== null && deliveredAt >= Date.parse(record.final_deploy_ready_at) &&
    issuedAt >= deliveredAt && issuedAt - deliveredAt <= 10 * 60_000;
}

export async function planFinalOutboxChild({ key, value, primary, env }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('outbox', value?.handoff_id, 'PRIMARY_INVALID'); }
  return validFinalOutbox(value, key, record, env) ? cascade('outbox', record.handoff_id) :
    preserve('outbox', value?.handoff_id, 'FINAL_OUTBOX_BINDING_INVALID');
}

export async function planFinalProviderIndexChild({ key, value, primary }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('final-delivery-provider-index', value?.handoff_id, 'PRIMARY_INVALID'); }
  const event = key.startsWith('final-delivery-provider-event/');
  const prefix = event ? 'final-delivery-provider-event/' : 'final-delivery-provider-message/';
  const expectedIdentity = event ? record.final_delivery_provider_event_id_hmac_sha256 :
    record.final_delivery_provider_message_id_hmac_sha256;
  const valid = exactKeys(value, FINAL_PROVIDER_FIELDS) &&
    value.schema === (event ? 'arc2-final-delivery-provider-event-index-v1' : 'arc2-final-delivery-provider-message-index-v1') &&
    value.kind === (event ? 'provider-event' : 'provider-message') && key === `${prefix}${expectedIdentity}` &&
    value.identity_hmac_sha256 === expectedIdentity && value.handoff_id === record.handoff_id &&
    value.delivery_receipt_sha256 === record.final_delivery_receipt_sha256 &&
    value.provider === record.final_delivery_provider &&
    value.provider_account_hmac_sha256 === record.final_delivery_provider_account_hmac_sha256;
  return valid ? cascade('final-delivery-provider-index', record.handoff_id) :
    preserve('final-delivery-provider-index', value?.handoff_id, 'FINAL_PROVIDER_INDEX_BINDING_INVALID');
}

function validReversalBinding(value, schema, record, env) {
  return exactKeys(value, REVERSAL_BINDING_FIELDS) && value.schema === schema && value.handoff_id === record.handoff_id &&
    value.payment_evidence_sha256 === record.payment_evidence_sha256 &&
    [value.checkout_session_id_hmac_sha256, value.payment_intent_id_hmac_sha256,
      value.binding_evidence_sha256].every(hex64) && envStripeBindingValid(value, env);
}

async function reversalChainIsClear(record, binding, read) {
  return !await readValue(read, `stripe-reversal/handoff/${record.handoff_id}`) &&
    !await readValue(read, `stripe-reversal-pending-payment/${binding.payment_intent_id_hmac_sha256}`);
}

export async function planReversalBindingChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-reversal-binding', value?.handoff_id, 'PRIMARY_INVALID'); }
  if (key !== `stripe-reversal-binding/handoff/${record.handoff_id}` ||
      !validReversalBinding(value, 'arc-stripe-reversal-binding-v1', record, env)) {
    return preserve('stripe-reversal-binding', value?.handoff_id, 'REVERSAL_BINDING_INVALID');
  }
  const payment = await readValue(read, `stripe-payment-intent/${value.payment_intent_id_hmac_sha256}`);
  if (!validReversalBinding(payment, 'arc-stripe-payment-intent-index-v1', record, env) ||
      !sameReversalBinding(value, payment)) {
    return preserve('stripe-reversal-binding', record.handoff_id, 'REVERSAL_PAYMENT_CROSS_BINDING_INVALID');
  }
  return await reversalChainIsClear(record, value, read)
    ? cascade('stripe-reversal-binding', record.handoff_id)
    : preserve('stripe-reversal-binding', record.handoff_id, 'REVERSAL_OR_PENDING_STATE_PRESENT', true);
}

export async function planReversalPaymentIntentChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-payment-intent', value?.handoff_id, 'PRIMARY_INVALID'); }
  if (!validReversalBinding(value, 'arc-stripe-payment-intent-index-v1', record, env) ||
      key !== `stripe-payment-intent/${value.payment_intent_id_hmac_sha256}`) {
    return preserve('stripe-payment-intent', value?.handoff_id, 'REVERSAL_PAYMENT_INDEX_INVALID');
  }
  const binding = await readValue(read, `stripe-reversal-binding/handoff/${record.handoff_id}`);
  if (!validReversalBinding(binding, 'arc-stripe-reversal-binding-v1', record, env) ||
      !sameReversalBinding(value, binding)) {
    return preserve('stripe-payment-intent', record.handoff_id, 'REVERSAL_HANDOFF_CROSS_BINDING_INVALID');
  }
  return await reversalChainIsClear(record, binding, read)
    ? cascade('stripe-payment-intent', record.handoff_id)
    : preserve('stripe-payment-intent', record.handoff_id, 'REVERSAL_OR_PENDING_STATE_PRESENT', true);
}

export async function planReversalRecheckChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-reversal-recheck', value?.handoff_id, 'PRIMARY_INVALID'); }
  const binding = await readValue(read, `stripe-reversal-binding/handoff/${record.handoff_id}`);
  const valid = key === `stripe-reversal-recheck/handoff/${record.handoff_id}` &&
    exactKeys(value, REVERSAL_RECHECK_FIELDS) && value.schema === 'arc-stripe-reversal-recheck-v1' &&
    value.handoff_id === record.handoff_id && validReversalBinding(binding, 'arc-stripe-reversal-binding-v1', record, env) &&
    value.checkout_session_id_hmac_sha256 === binding.checkout_session_id_hmac_sha256 &&
    value.payment_intent_id_hmac_sha256 === binding.payment_intent_id_hmac_sha256 &&
    value.stripe_account_id_sha256 === binding.stripe_account_id_sha256 && value.livemode === binding.livemode &&
    value.binding_evidence_sha256 === binding.binding_evidence_sha256 && value.payment_intent_status === 'succeeded' &&
    value.refunded_amount_minor_units === 0 && value.dispute_status === 'none' &&
    hex64(value.evidence_sha256) && iso(value.issued_at) !== null;
  if (!valid) return preserve('stripe-reversal-recheck', value?.handoff_id, 'REVERSAL_RECHECK_BINDING_INVALID');
  return await reversalChainIsClear(record, binding, read)
    ? cascade('stripe-reversal-recheck', record.handoff_id)
    : preserve('stripe-reversal-recheck', record.handoff_id, 'REVERSAL_OR_PENDING_STATE_PRESENT', true);
}

function validReversalEvent(value, eventHmac, paymentIntentHmac, env) {
  if (!exactKeys(value, REVERSAL_EVENT_FIELDS) || value.schema !== 'arc-stripe-reversal-event-v1' ||
      value.handoff_id !== null || value.checkout_session_id_hmac_sha256 !== null ||
      value.event_id_hmac_sha256 !== eventHmac || value.payment_intent_id_hmac_sha256 !== paymentIntentHmac ||
      ![value.object_id_hmac_sha256, value.event_sha256].every(hex64) || !envStripeBindingValid(value, env) ||
      !REVERSAL_EVENT_TYPES.has(value.event_type) || typeof value.event_status !== 'string' ||
      value.event_status.length < 1 || value.event_status.length > 64 || iso(value.event_created_at) === null ||
      !Number.isSafeInteger(value.amount_minor_units) || value.amount_minor_units < 1 || value.currency !== 'usd') return false;
  if (value.event_type.startsWith('refund.')) return value.kind === 'refund' &&
    ['pending', 'requires_action', 'succeeded', 'failed', 'canceled'].includes(value.event_status) &&
    (value.event_type !== 'refund.failed' || value.event_status === 'failed');
  if (value.event_type === 'charge.refunded') return value.kind === 'charge-refund' &&
    ['fully_refunded', 'partially_refunded'].includes(value.event_status);
  return value.event_type.startsWith('charge.dispute.') && value.kind === 'dispute' &&
    ['warning_needs_response', 'warning_under_review', 'warning_closed', 'needs_response', 'under_review',
      'won', 'lost', 'prevented'].includes(value.event_status) &&
    (value.event_type !== 'charge.dispute.closed' ||
      ['lost', 'warning_closed', 'won', 'prevented'].includes(value.event_status));
}

async function reversalPaymentChain(paymentIntentHmac, record, env, read) {
  const payment = await readValue(read, `stripe-payment-intent/${paymentIntentHmac}`);
  const binding = await readValue(read, `stripe-reversal-binding/handoff/${record.handoff_id}`);
  return validReversalBinding(payment, 'arc-stripe-payment-intent-index-v1', record, env) &&
    validReversalBinding(binding, 'arc-stripe-reversal-binding-v1', record, env) &&
    sameReversalBinding(payment, binding) && payment.payment_intent_id_hmac_sha256 === paymentIntentHmac;
}

export async function planReversalEventChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-reversal-event', null, 'PRIMARY_INVALID'); }
  const eventHmac = key.match(/^stripe-reversal-event\/([a-f0-9]{64})$/)?.[1];
  const valid = eventHmac && validReversalEvent(value, eventHmac, value?.payment_intent_id_hmac_sha256, env) &&
    await reversalPaymentChain(value.payment_intent_id_hmac_sha256, record, env, read);
  return valid
    ? preserve('stripe-reversal-event', record.handoff_id, 'REVERSAL_EVENT_REQUIRES_ACCOUNTABLE_RELEASE', true)
    : preserve('stripe-reversal-event', record.handoff_id, 'REVERSAL_EVENT_BINDING_INVALID');
}

export async function planReversalPendingPaymentChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-reversal-pending-payment', null, 'PRIMARY_INVALID'); }
  const paymentHmac = key.match(/^stripe-reversal-pending-payment\/([a-f0-9]{64})$/)?.[1];
  const valid = paymentHmac && exactKeys(value, PENDING_PAYMENT_FIELDS) &&
    value.schema === 'arc-stripe-pending-payment-halt-v1' && value.payment_intent_id_hmac_sha256 === paymentHmac &&
    value.delivery_halted === true && envStripeBindingValid(value, env) &&
    await reversalPaymentChain(paymentHmac, record, env, read);
  return valid
    ? preserve('stripe-reversal-pending-payment', record.handoff_id, 'UNRESOLVED_STRIPE_REVERSAL_PENDING', true)
    : preserve('stripe-reversal-pending-payment', record.handoff_id, 'PENDING_PAYMENT_BINDING_INVALID');
}

export async function planReversalPendingEventChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-reversal-pending-event', null, 'PRIMARY_INVALID'); }
  const match = key.match(/^stripe-reversal-pending\/([a-f0-9]{64})\/([a-f0-9]{64})$/);
  const paymentHmac = match?.[1];
  const eventHmac = match?.[2];
  const reservation = eventHmac ? await readValue(read, `stripe-reversal-event/${eventHmac}`) : null;
  const valid = match && validReversalEvent(value, eventHmac, paymentHmac, env) &&
    canonicalJson(value) === canonicalJson(reservation) &&
    await reversalPaymentChain(paymentHmac, record, env, read);
  return valid
    ? preserve('stripe-reversal-pending-event', record.handoff_id, 'UNRESOLVED_STRIPE_REVERSAL_PENDING', true)
    : preserve('stripe-reversal-pending-event', record.handoff_id, 'PENDING_EVENT_BINDING_INVALID');
}

export async function planReversalStateChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-reversal-state', value?.handoff_id, 'PRIMARY_INVALID'); }
  const binding = await readValue(read, `stripe-reversal-binding/handoff/${record.handoff_id}`);
  const valid = key === `stripe-reversal/handoff/${record.handoff_id}` && exactKeys(value, REVERSAL_STATE_FIELDS) &&
    value.schema === 'arc-stripe-reversal-state-v1' && value.handoff_id === record.handoff_id &&
    value.delivery_halted === true && value.automatic_refund_requested === false && value.manual_review_required === true &&
    ['REVIEW_REQUIRED', 'FUNDS_AT_RISK', 'FUNDS_REVERSED'].includes(value.severity) &&
    ['NONE', 'ATTEMPT_RECORDED', 'FUNDS_REVERSED'].includes(value.refund_state) &&
    ['NONE', 'OPEN', 'RESOLVED'].includes(value.dispute_state) &&
    typeof value.refund_observed === 'boolean' && typeof value.dispute_observed === 'boolean' &&
    REVERSAL_EVENT_TYPES.has(value.latest_event_type) && typeof value.latest_event_status === 'string' &&
    [value.latest_event_id_hmac_sha256, value.latest_event_sha256, value.latest_object_id_hmac_sha256].every(hex64) &&
    Number.isSafeInteger(value.latest_amount_minor_units) && value.latest_amount_minor_units > 0 && value.currency === 'usd' &&
    iso(value.first_event_created_at) !== null && iso(value.latest_event_created_at) !== null &&
    Date.parse(value.first_event_created_at) <= Date.parse(value.latest_event_created_at) &&
    validReversalBinding(binding, 'arc-stripe-reversal-binding-v1', record, env) &&
    value.checkout_session_id_hmac_sha256 === binding.checkout_session_id_hmac_sha256 &&
    value.payment_intent_id_hmac_sha256 === binding.payment_intent_id_hmac_sha256 &&
    value.stripe_account_id_sha256 === binding.stripe_account_id_sha256 && value.livemode === binding.livemode;
  return valid
    ? preserve('stripe-reversal-state', record.handoff_id, 'ACTIVE_REVERSAL_STATE', true)
    : preserve('stripe-reversal-state', value?.handoff_id, 'REVERSAL_STATE_BINDING_INVALID');
}

export async function planReversalAlertChild({ key, value, primary }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-reversal-alert', value?.handoff_id, 'PRIMARY_INVALID'); }
  const bound = key.startsWith('alerts/stripe-reversal/');
  const eventHmac = key.match(/^alerts\/stripe-reversal(?:-unbound)?\/([a-f0-9]{64})$/)?.[1];
  const valid = eventHmac && exactKeys(value, ALERT_FIELDS) && value.schema === 'arc-operational-alert-v1' &&
    value.status === 'OPEN' && value.delivery_status === 'PENDING' && value.contains_customer_data === false &&
    value.subject_hmac_sha256 === eventHmac && iso(value.detected_at) !== null &&
    (bound
      ? value.category === 'stripe-reversal' && ['critical', 'high'].includes(value.severity) && value.handoff_id === record.handoff_id
      : value.category === 'stripe-reversal-unbound' && value.severity === 'critical' && value.handoff_id === null);
  return valid
    ? preserve('stripe-reversal-alert', bound ? record.handoff_id : null, 'OPEN_REVERSAL_ALERT', true)
    : preserve('stripe-reversal-alert', value?.handoff_id, 'REVERSAL_ALERT_BINDING_INVALID');
}

function validReviewCheckoutMetadata(value) {
  return exactKeys(value, REVIEW_CHECKOUT_METADATA_FIELDS) &&
    value.schema === 'arc-review-checkout-session-v1' &&
    value.offer_contract_id === 'arc-fixed-five-page-offer-v1' &&
    value.scope_version === 'arc-fixed-five-page-offer-v1' && value.terms_version === '2026-08-25' &&
    REVIEW_CHECKOUT_METADATA_FIELDS.filter((field) => field.endsWith('_sha256')).every((field) => hex64(value[field]));
}

function validStripeCheckoutHandoffBinding(value, record, env) {
  if (!value || value.handoff_id !== record.handoff_id || value.payment_evidence_sha256 !== record.payment_evidence_sha256 ||
      ![value.checkout_session_id_hmac_sha256, value.payment_intent_id_hmac_sha256].every(hex64) ||
      !envStripeBindingValid(value, env)) return false;
  if (value.schema === 'arc-stripe-checkout-handoff-binding-v1') {
    return exactKeys(value, STRIPE_CHECKOUT_HANDOFF_FIELDS) && hex64(value.payment_link_id_hmac_sha256);
  }
  return value.schema === 'arc-stripe-review-checkout-handoff-binding-v1' &&
    exactKeys(value, STRIPE_REVIEW_CHECKOUT_HANDOFF_FIELDS) && value.payment_link_id_hmac_sha256 === null &&
    [value.bridge_immutable_binding_sha256, value.review_session_binding_sha256, value.approval_receipt_sha256,
      value.recipient_email_sha256, value.payer_email_sha256, value.review_checkout_binding_sha256].every(hex64) &&
    value.recipient_email_sha256 === record.customer_email_sha256;
}

function validStripeCheckoutSession(value, key, binding, record) {
  const review = binding.schema === 'arc-stripe-review-checkout-handoff-binding-v1';
  const fields = review ? [...STRIPE_CHECKOUT_SESSION_FIELDS, 'review_checkout_binding'] : STRIPE_CHECKOUT_SESSION_FIELDS;
  if (!exactKeys(value, fields) || value.schema !== 'arc-stripe-checkout-session-state-v1' ||
      key !== `stripe-checkout-session/${binding.checkout_session_id_hmac_sha256}` ||
      value.checkout_session_id_hmac_sha256 !== binding.checkout_session_id_hmac_sha256 ||
      value.payment_intent_id_hmac_sha256 !== binding.payment_intent_id_hmac_sha256 ||
      value.payment_link_id_hmac_sha256 !== binding.payment_link_id_hmac_sha256 ||
      value.stripe_account_id_sha256 !== binding.stripe_account_id_sha256 || value.livemode !== binding.livemode ||
      value.state !== 'PAID' || value.fulfillment_allowed !== true || value.manual_review_required !== false ||
      !(review ? hex64(value.client_reference_id_sha256) :
        value.client_reference_id_sha256 === null || hex64(value.client_reference_id_sha256)) ||
      !hex64(value.payer_email_sha256) ||
      typeof value.customer_address_country !== 'string' || !/^[A-Z]{2}$/.test(value.customer_address_country) ||
      typeof value.customer_address_state !== 'string' || !/^[A-Z0-9-]{0,10}$/.test(value.customer_address_state) ||
      value.currency !== 'usd' || value.subtotal_amount_minor_units !== 500_000 ||
      !Number.isSafeInteger(value.tax_amount_minor_units) || value.tax_amount_minor_units < 0 || value.tax_amount_minor_units > 500_000 ||
      value.amount_total_minor_units !== value.subtotal_amount_minor_units + value.tax_amount_minor_units ||
      value.automatic_tax_enabled !== true || value.automatic_tax_status !== 'complete' ||
      value.terms_of_service_consent !== true || value.adult_purchaser_acknowledgement !== true ||
      iso(value.first_event_created_at) === null || iso(value.latest_event_created_at) === null ||
      Date.parse(value.first_event_created_at) > Date.parse(value.latest_event_created_at) ||
      !CHECKOUT_EVENT_TYPES.has(value.latest_event_type) ||
      ![value.latest_event_id_hmac_sha256, value.latest_event_sha256,
        value.state_event_id_hmac_sha256, value.state_event_sha256].every(hex64) ||
      !Array.isArray(value.processed_event_hmacs_sha256) || value.processed_event_hmacs_sha256.length < 1 ||
      value.processed_event_hmacs_sha256.length > 64 || value.processed_event_hmacs_sha256.some((entry) => !hex64(entry)) ||
      new Set(value.processed_event_hmacs_sha256).size !== value.processed_event_hmacs_sha256.length ||
      value.event_count !== value.processed_event_hmacs_sha256.length ||
      !value.processed_event_hmacs_sha256.includes(value.latest_event_id_hmac_sha256) ||
      !value.processed_event_hmacs_sha256.includes(value.state_event_id_hmac_sha256)) return false;
  if (!review) return !Object.hasOwn(value, 'review_checkout_binding');
  const metadata = value.review_checkout_binding;
  return validReviewCheckoutMetadata(metadata) && value.payment_link_id_hmac_sha256 === null &&
    binding.payer_email_sha256 === value.payer_email_sha256 &&
    binding.approval_receipt_sha256 === metadata.approval_receipt_sha256 &&
    binding.recipient_email_sha256 === metadata.recipient_email_sha256 &&
    binding.recipient_email_sha256 === record.customer_email_sha256 &&
    binding.review_checkout_binding_sha256 === sha256Hex(canonicalJson(metadata)) &&
    value.client_reference_id_sha256 === sha256Hex(metadata.approval_receipt_sha256);
}

function validStripeCheckoutReceipt(value, key, session) {
  return exactKeys(value, STRIPE_CHECKOUT_RECEIPT_FIELDS) &&
    value.schema === 'arc-stripe-checkout-processing-receipt-v1' &&
    key === `stripe-checkout-receipt/${value.event_id_hmac_sha256}` &&
    [value.event_id_hmac_sha256, value.event_sha256].every(hex64) && value.accepted === true &&
    CHECKOUT_STATES.has(value.resulting_state) &&
    value.review_alert_required === (value.resulting_state === 'REVIEW_REQUIRED') &&
    value.checkout_session_id_hmac_sha256 === session.checkout_session_id_hmac_sha256 &&
    value.stripe_account_id_sha256 === session.stripe_account_id_sha256 &&
    session.processed_event_hmacs_sha256.includes(value.event_id_hmac_sha256);
}

async function stripeCheckoutPaidChain(record, env, read) {
  const binding = await readValue(read, `stripe-checkout-handoff/${record.handoff_id}`);
  if (!validStripeCheckoutHandoffBinding(binding, record, env)) return null;
  const sessionKey = `stripe-checkout-session/${binding.checkout_session_id_hmac_sha256}`;
  const session = await readValue(read, sessionKey);
  if (!validStripeCheckoutSession(session, sessionKey, binding, record)) return null;
  const receiptKey = `stripe-checkout-receipt/${session.state_event_id_hmac_sha256}`;
  const receipt = await readValue(read, receiptKey);
  if (!validStripeCheckoutReceipt(receipt, receiptKey, session) || receipt.resulting_state !== 'PAID' ||
      receipt.review_alert_required !== false || receipt.event_sha256 !== session.state_event_sha256) return null;
  return { binding, receipt, session };
}

function validStripeCheckoutEvent(value, key, chain) {
  const review = chain.binding.schema === 'arc-stripe-review-checkout-handoff-binding-v1';
  const fields = review ? [...STRIPE_CHECKOUT_EVENT_FIELDS, 'review_checkout_binding'] : STRIPE_CHECKOUT_EVENT_FIELDS;
  if (!exactKeys(value, fields) || value.schema !== 'arc-stripe-checkout-event-v1' ||
      key !== `stripe-checkout-event/${value.event_id_hmac_sha256}` ||
      ![value.event_id_hmac_sha256, value.event_sha256].every(hex64) || iso(value.event_created_at) === null ||
      !CHECKOUT_EVENT_TYPES.has(value.event_type) || !CHECKOUT_STATES.has(value.observed_state) ||
      value.checkout_session_id_hmac_sha256 !== chain.session.checkout_session_id_hmac_sha256 ||
      value.payment_link_id_hmac_sha256 !== chain.session.payment_link_id_hmac_sha256 ||
      (value.payment_intent_id_hmac_sha256 !== null &&
        value.payment_intent_id_hmac_sha256 !== chain.session.payment_intent_id_hmac_sha256) ||
      value.stripe_account_id_sha256 !== chain.session.stripe_account_id_sha256 ||
      value.livemode !== chain.session.livemode || value.currency !== chain.session.currency ||
      value.subtotal_amount_minor_units !== chain.session.subtotal_amount_minor_units ||
      value.tax_amount_minor_units !== chain.session.tax_amount_minor_units ||
      value.amount_total_minor_units !== chain.session.amount_total_minor_units ||
      value.automatic_tax_enabled !== true || typeof value.automatic_tax_status !== 'string' ||
      typeof value.terms_of_service_consent !== 'boolean' || typeof value.adult_purchaser_acknowledgement !== 'boolean' ||
      !chain.session.processed_event_hmacs_sha256.includes(value.event_id_hmac_sha256)) return false;
  for (const field of ['client_reference_id_sha256', 'payer_email_sha256', 'customer_address_country', 'customer_address_state']) {
    if (value[field] !== null && value[field] !== chain.session[field]) return false;
  }
  return review
    ? validReviewCheckoutMetadata(value.review_checkout_binding) &&
      canonicalJson(value.review_checkout_binding) === canonicalJson(chain.session.review_checkout_binding)
    : !Object.hasOwn(value, 'review_checkout_binding');
}

export async function planStripeCheckoutHandoffChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-checkout-handoff', value?.handoff_id, 'PRIMARY_INVALID'); }
  if (key !== `stripe-checkout-handoff/${record.handoff_id}` || !validStripeCheckoutHandoffBinding(value, record, env)) {
    return preserve('stripe-checkout-handoff', value?.handoff_id, 'STRIPE_CHECKOUT_HANDOFF_BINDING_INVALID');
  }
  const chain = await stripeCheckoutPaidChain(record, env, read);
  return chain && canonicalJson(chain.binding) === canonicalJson(value)
    ? cascade('stripe-checkout-handoff', record.handoff_id)
    : preserve('stripe-checkout-handoff', record.handoff_id, 'STRIPE_CHECKOUT_PAID_CHAIN_INVALID');
}

export async function planStripeCheckoutSessionChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-checkout-session', null, 'PRIMARY_INVALID'); }
  const chain = await stripeCheckoutPaidChain(record, env, read);
  return chain && key === `stripe-checkout-session/${chain.binding.checkout_session_id_hmac_sha256}` &&
    canonicalJson(value) === canonicalJson(chain.session)
    ? cascade('stripe-checkout-session', record.handoff_id)
    : preserve('stripe-checkout-session', record.handoff_id, 'STRIPE_CHECKOUT_SESSION_BINDING_INVALID');
}

export async function planStripeCheckoutReceiptChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-checkout-receipt', null, 'PRIMARY_INVALID'); }
  const chain = await stripeCheckoutPaidChain(record, env, read);
  if (!chain || !validStripeCheckoutReceipt(value, key, chain.session)) {
    return preserve('stripe-checkout-receipt', record.handoff_id, 'STRIPE_CHECKOUT_RECEIPT_BINDING_INVALID');
  }
  const event = await readValue(read, `stripe-checkout-event/${value.event_id_hmac_sha256}`);
  if (!validStripeCheckoutEvent(event, `stripe-checkout-event/${value.event_id_hmac_sha256}`, chain) ||
      event.event_sha256 !== value.event_sha256) {
    return preserve('stripe-checkout-receipt', record.handoff_id, 'STRIPE_CHECKOUT_RECEIPT_EVENT_CROSS_BINDING_INVALID');
  }
  return cascade('stripe-checkout-receipt', record.handoff_id);
}

export async function planStripeCheckoutEventChild({ key, value, primary, env, read }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-checkout-event', null, 'PRIMARY_INVALID'); }
  const chain = await stripeCheckoutPaidChain(record, env, read);
  if (!chain || !validStripeCheckoutEvent(value, key, chain)) {
    return preserve('stripe-checkout-event', record.handoff_id, 'STRIPE_CHECKOUT_EVENT_BINDING_INVALID');
  }
  const receiptKey = `stripe-checkout-receipt/${value.event_id_hmac_sha256}`;
  const receipt = await readValue(read, receiptKey);
  if (!validStripeCheckoutReceipt(receipt, receiptKey, chain.session) || receipt.event_sha256 !== value.event_sha256) {
    return preserve('stripe-checkout-event', record.handoff_id, 'STRIPE_CHECKOUT_EVENT_RECEIPT_CROSS_BINDING_INVALID');
  }
  return cascade('stripe-checkout-event', record.handoff_id);
}

export async function planStripeCheckoutAlertChild({ key, value, primary }) {
  let record;
  try { record = primaryRecord(primary); } catch { return preserve('stripe-checkout-alert', value?.handoff_id, 'PRIMARY_INVALID'); }
  const eventHmac = key.match(/^alerts\/stripe-checkout-review\/([a-f0-9]{64})$/)?.[1];
  const valid = eventHmac && exactKeys(value, ALERT_FIELDS) && value.schema === 'arc-operational-alert-v1' &&
    value.status === 'OPEN' && value.category === 'stripe-checkout-review' && value.severity === 'critical' &&
    value.handoff_id === null && value.subject_hmac_sha256 === eventHmac && iso(value.detected_at) !== null &&
    value.delivery_status === 'PENDING' && value.contains_customer_data === false;
  return valid
    ? preserve('stripe-checkout-alert', record.handoff_id, 'OPEN_STRIPE_CHECKOUT_REVIEW_ALERT', true)
    : preserve('stripe-checkout-alert', record.handoff_id, 'STRIPE_CHECKOUT_ALERT_BINDING_INVALID');
}

export async function planHandoffChildRetention(input = {}) {
  const key = input.key;
  if (typeof key !== 'string' || key.length < 3 || key.length > 1024) {
    return preserve('unknown', null, 'CHILD_KEY_INVALID');
  }
  try {
    if (key.startsWith('site-index/')) return await planSiteIndexChild(input);
    if (key.startsWith('checkout-session-index/')) return await planCheckoutSessionIndexChild(input);
    if (key.startsWith('checkout-reference-index/')) return await planCheckoutReferenceIndexChild(input);
    if (key.startsWith('duplicate-payment-review/')) return await planDuplicatePaymentReviewChild(input);
    if (key.startsWith('invitation-ready-current/')) return await planInvitationCurrentChild(input);
    if (key.startsWith('invitation-ready-outbox/')) return await planInvitationOutboxChild(input);
    if (key.startsWith('outbox/')) return await planFinalOutboxChild(input);
    if (key.startsWith('final-delivery-provider-event/') ||
        key.startsWith('final-delivery-provider-message/')) return await planFinalProviderIndexChild(input);
    if (key.startsWith('stripe-reversal-binding/handoff/')) return await planReversalBindingChild(input);
    if (key.startsWith('stripe-reversal-recheck/handoff/')) return await planReversalRecheckChild(input);
    if (key.startsWith('stripe-payment-intent/')) return await planReversalPaymentIntentChild(input);
    if (key.startsWith('stripe-reversal-event/')) return await planReversalEventChild(input);
    if (key.startsWith('stripe-reversal-pending-payment/')) return await planReversalPendingPaymentChild(input);
    if (key.startsWith('stripe-reversal-pending/')) return await planReversalPendingEventChild(input);
    if (key.startsWith('stripe-reversal/handoff/')) return await planReversalStateChild(input);
    if (key.startsWith('alerts/stripe-reversal/') ||
        key.startsWith('alerts/stripe-reversal-unbound/')) return await planReversalAlertChild(input);
    if (key.startsWith('stripe-checkout-handoff/')) return await planStripeCheckoutHandoffChild(input);
    if (key.startsWith('stripe-checkout-session/')) return await planStripeCheckoutSessionChild(input);
    if (key.startsWith('stripe-checkout-receipt/')) return await planStripeCheckoutReceiptChild(input);
    if (key.startsWith('stripe-checkout-event/')) return await planStripeCheckoutEventChild(input);
    if (key.startsWith('alerts/stripe-checkout-review/')) return await planStripeCheckoutAlertChild(input);
  } catch {
    return preserve(handoffChildFamilyForKey(key) || 'unknown', null, 'VALIDATION_EXCEPTION');
  }
  return preserve('unknown', null, 'CHILD_FAMILY_UNSUPPORTED');
}

// Plans the full set before any caller performs CAS tombstones. The overlay
// reader keeps cross-record proof independent of mutation order and supplies a
// legacy Checkout Session raw-id proof when the matching reference row exists.
export async function planHandoffChildSet({ entries, primary, env, read }) {
  if (!Array.isArray(entries) || entries.length > 10_000) throw new TypeError('Handoff child set is invalid.');
  const values = new Map();
  for (const entry of entries) {
    if (!entry || typeof entry.key !== 'string' || values.has(entry.key)) {
      throw new TypeError('Handoff child set contains an invalid or duplicate key.');
    }
    values.set(entry.key, entry.value);
  }
  const overlayRead = async (key) => values.has(key) ? values.get(key) : readValue(read, key);
  let normalizedPrimary = null;
  try { normalizedPrimary = primaryRecord(primary); } catch { /* Per-record plans preserve. */ }
  const references = normalizedPrimary ? entries.filter(({ value }) =>
    value?.schema === 'arc2-checkout-reference-index-v1' && value.handoff_id === normalizedPrimary.handoff_id &&
    value.payment_evidence_sha256 === normalizedPrimary.payment_evidence_sha256 &&
    value.artifact_evidence_sha256 === normalizedPrimary.artifact_evidence_sha256) : [];
  const output = [];
  for (const entry of entries) {
    const proof = entry.key.startsWith('checkout-session-index/') && references.length === 1
      ? { checkoutReference: references[0].value }
      : {};
    output.push(Object.freeze({ key: entry.key, plan: await planHandoffChildRetention({
      ...entry, primary, env, read: overlayRead, proof,
    }) }));
  }
  return Object.freeze(output);
}

export async function validateHandoffChildForCascade(input) {
  return (await planHandoffChildRetention(input)).action === HANDOFF_CHILD_RETENTION_ACTION.CASCADE;
}
