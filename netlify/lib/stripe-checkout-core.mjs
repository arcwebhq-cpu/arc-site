import {
  canonicalJson,
  hmacHex,
  safeEqual,
  sha256Hex,
} from './arc2-handoff-core.mjs';
import {
  createIndex,
  readIndex,
  readIndexEntry,
  replaceIndex,
} from './arc2-handoff-store.mjs';
import {
  STRIPE_WEBHOOK_API_VERSION,
  verifyStripeWebhookSignature,
} from './stripe-reversal-core.mjs';
import {
  stripeAccountVerificationConfigured,
  verifyStripeAccountBinding,
  verifyStripeEventOwnership,
} from './stripe-account-verification.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const STRIPE_CHECKOUT_EVENT_SCHEMA = 'arc-stripe-checkout-event-v1';
export const STRIPE_CHECKOUT_SESSION_SCHEMA = 'arc-stripe-checkout-session-state-v1';
export const STRIPE_CHECKOUT_RECEIPT_SCHEMA = 'arc-stripe-checkout-processing-receipt-v1';
export const STRIPE_CHECKOUT_HANDOFF_BINDING_SCHEMA = 'arc-stripe-checkout-handoff-binding-v1';
export const STRIPE_REVIEW_CHECKOUT_HANDOFF_BINDING_SCHEMA = 'arc-stripe-review-checkout-handoff-binding-v1';
export const STRIPE_CHECKOUT_REVIEW_SCHEMA = 'arc-operational-alert-v1';

const EVENT_TYPES = new Set([
  'checkout.session.completed',
  'checkout.session.async_payment_succeeded',
  'checkout.session.async_payment_failed',
  'checkout.session.expired',
]);
const SESSION_STATES = new Set(['PENDING', 'PAID', 'FAILED', 'EXPIRED', 'REVIEW_REQUIRED']);
const HEX_64 = /^[a-f0-9]{64}$/;
const EVENT_ID = /^evt_[A-Za-z0-9_]{6,128}$/;
const CHECKOUT_SESSION_ID = /^cs_(?:test|live)_[A-Za-z0-9_]{6,128}$/;
const PAYMENT_INTENT_ID = /^pi_[A-Za-z0-9_]{6,128}$/;
const PAYMENT_LINK_ID = /^plink_[A-Za-z0-9_]{6,128}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_CAS_ATTEMPTS = 8;
const REVIEW_CHECKOUT_METADATA_SCHEMA = 'arc-review-checkout-session-v1';
const REVIEW_CHECKOUT_OFFER_ID = 'arc-fixed-five-page-offer-v1';
const REVIEW_CHECKOUT_TERMS_VERSION = '2026-08-25';
const REVIEW_CHECKOUT_METADATA_KEYS = Object.freeze([
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

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${label} must be an object.`);
  return value;
}

function validSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}

function exactBoolean(value) {
  return value === 'true' || value === 'false';
}

function identifier(value, pattern, label) {
  const output = typeof value === 'string' ? value : value?.id;
  if (typeof output !== 'string' || !pattern.test(output)) throw new TypeError(`${label} is invalid.`);
  return output;
}

function optionalIdentifier(value, pattern, label) {
  if (value === null || value === undefined) return null;
  return identifier(value, pattern, label);
}

function amount(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 100_000_000) throw new TypeError(`${label} is invalid.`);
  return value;
}

function optionalEmailHash(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value !== 'string' || value.length > 254 || value !== value.trim() || !EMAIL.test(value)) {
    throw new TypeError('Stripe Checkout payer email is invalid.');
  }
  return sha256Hex(value.toLowerCase());
}

function normalizeReviewCheckoutBinding(value) {
  const metadata = plainObject(value, 'Stripe review Checkout metadata');
  if (JSON.stringify(Object.keys(metadata).sort()) !== JSON.stringify([...REVIEW_CHECKOUT_METADATA_KEYS].sort()) ||
      metadata.schema !== REVIEW_CHECKOUT_METADATA_SCHEMA ||
      metadata.offer_contract_id !== REVIEW_CHECKOUT_OFFER_ID ||
      metadata.scope_version !== REVIEW_CHECKOUT_OFFER_ID ||
      metadata.terms_version !== REVIEW_CHECKOUT_TERMS_VERSION ||
      REVIEW_CHECKOUT_METADATA_KEYS.filter((key) => key.endsWith('_sha256'))
        .some((key) => !HEX_64.test(String(metadata[key] || '')))) {
    throw new TypeError('Stripe review Checkout metadata is invalid.');
  }
  return Object.freeze(Object.fromEntries(REVIEW_CHECKOUT_METADATA_KEYS.map((key) => [key, metadata[key]])));
}

function customFieldAccepted(session) {
  if (!Array.isArray(session.custom_fields)) return false;
  const matching = session.custom_fields.filter((field) => field && field.key === 'adultpurchaserack');
  if (matching.length !== 1) return false;
  const field = matching[0];
  if (!['dropdown', 'text', 'numeric'].includes(field.type)) return false;
  const value = field[field.type]?.value;
  return value === 'accepted';
}

function sessionState(eventType, session) {
  if (eventType === 'checkout.session.completed') {
    if (session.status !== 'complete') throw new TypeError('Completed Checkout Session status is invalid.');
    if (session.payment_status === 'paid') return 'PAID';
    if (session.payment_status === 'unpaid') return 'PENDING';
  } else if (eventType === 'checkout.session.async_payment_succeeded') {
    if (session.status === 'complete' && session.payment_status === 'paid') return 'PAID';
  } else if (eventType === 'checkout.session.async_payment_failed') {
    if (session.status === 'complete' && session.payment_status === 'unpaid') return 'FAILED';
  } else if (eventType === 'checkout.session.expired') {
    if (session.status === 'expired' && session.payment_status === 'unpaid') return 'EXPIRED';
  }
  throw new TypeError('Stripe Checkout event and Session state disagree.');
}

function identityHmac(env, kind, value) {
  return hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `stripe-checkout-${kind}-v1\n${value}`);
}

function expectedLivemode(env) {
  return env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true';
}

export function stripeCheckoutConfiguration(env = process.env) {
  const liveModeValid = exactBoolean(env.ARC_STRIPE_LIVE_MODE_ENABLED);
  const enabledFlagValid = exactBoolean(env.ARC_STRIPE_CHECKOUT_LEDGER_ENABLED);
  const requiredFlagValid = exactBoolean(env.ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED);
  const enabledFlag = env.ARC_STRIPE_CHECKOUT_LEDGER_ENABLED === 'true';
  const required = env.ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED === 'true';
  const sandboxBypass = !required && env.ARC_RUNTIME_ENVIRONMENT === 'sandbox' &&
    env.ARC_STRIPE_LIVE_MODE_ENABLED === 'false' && env.ARC_ALLOW_TEST_MODE_EVENTS === 'true' &&
    env.ARC_HANDOFF_ENABLED === 'false';
  const secretNames = ['ARC_STRIPE_WEBHOOK_SIGNING_SECRET', 'ARC_STRIPE_REVERSAL_HMAC_SECRET'];
  const secretsValid = secretNames.every((name) => validSecret(env[name])) &&
    sensitiveCredentialsAreIsolated(env, secretNames);
  const accountVerificationValid = stripeAccountVerificationConfigured(env);
  const expectedAccountValid = HEX_64.test(String(env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 || ''));
  const apiVersionValid = env.ARC_STRIPE_WEBHOOK_API_VERSION === STRIPE_WEBHOOK_API_VERSION;
  const webhookOperational = enabledFlag && enabledFlagValid && requiredFlagValid && liveModeValid && secretsValid && accountVerificationValid &&
    expectedAccountValid && apiVersionValid;
  return {
    accountVerificationValid,
    apiVersionValid,
    enabled: required && webhookOperational,
    enabledFlag,
    expectedLivemode: expectedLivemode(env),
    flagsValid: enabledFlagValid && requiredFlagValid,
    liveModeValid,
    required,
    sandboxBypass,
    secretsValid,
    webhookOperational,
  };
}

function requireWebhookOperational(env) {
  const configuration = stripeCheckoutConfiguration(env);
  if (!configuration.webhookOperational) throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_DISABLED');
  return configuration;
}

export function normalizeStripeCheckoutEvent(raw, stripeSignature, env, now = new Date()) {
  const configuration = requireWebhookOperational(env);
  verifyStripeWebhookSignature(raw, stripeSignature, env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET, now);
  if (typeof raw !== 'string' || raw.length < 2 || Buffer.byteLength(raw, 'utf8') > 1_048_576) {
    throw new TypeError('Stripe Checkout webhook body is invalid.');
  }
  const event = plainObject(JSON.parse(raw), 'Stripe event');
  if (event.object !== 'event' || !EVENT_TYPES.has(event.type) || event.api_version !== STRIPE_WEBHOOK_API_VERSION ||
      event.livemode !== configuration.expectedLivemode || !Number.isSafeInteger(event.created) || event.created < 1 ||
      !event.data || typeof event.data !== 'object' || Array.isArray(event.data)) {
    throw new TypeError('Stripe Checkout event is not allowlisted or is incorrectly bound.');
  }
  if (event.account !== undefined &&
      (typeof event.account !== 'string' || !/^acct_[A-Za-z0-9]{6,128}$/.test(event.account) ||
        !safeEqual(sha256Hex(event.account), env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256))) {
    throw new TypeError('Stripe Checkout event account is invalid.');
  }
  identifier(event.id, EVENT_ID, 'Stripe event id');
  const session = plainObject(event.data.object, 'Stripe Checkout Session');
  if (session.object !== 'checkout.session' || session.mode !== 'payment' || session.livemode !== event.livemode) {
    throw new TypeError('Stripe Checkout Session mode is invalid.');
  }
  const sessionId = identifier(session.id, CHECKOUT_SESSION_ID, 'Stripe Checkout Session id');
  if (!sessionId.startsWith(configuration.expectedLivemode ? 'cs_live_' : 'cs_test_')) {
    throw new TypeError('Stripe Checkout Session mode prefix is invalid.');
  }
  let state = sessionState(event.type, session);
  if (session.currency !== 'usd') throw new TypeError('Stripe Checkout currency is invalid.');
  const subtotal = amount(session.amount_subtotal, 'Stripe Checkout subtotal');
  const total = amount(session.amount_total, 'Stripe Checkout total');
  const totalDetails = plainObject(session.total_details, 'Stripe Checkout total details');
  const tax = amount(totalDetails.amount_tax, 'Stripe Checkout tax');
  const discount = amount(totalDetails.amount_discount ?? 0, 'Stripe Checkout discount');
  const shipping = amount(totalDetails.amount_shipping ?? 0, 'Stripe Checkout shipping');
  if (subtotal !== 500_000 || discount !== 0 || shipping !== 0 || total !== subtotal + tax || tax > 500_000) {
    throw new TypeError('Stripe Checkout amount contract is invalid.');
  }
  const automaticTax = plainObject(session.automatic_tax, 'Stripe Checkout automatic tax');
  const automaticTaxStatus = automaticTax.status === null ? 'not_calculated' : automaticTax.status;
  if (automaticTax.enabled !== true || typeof automaticTaxStatus !== 'string' || automaticTaxStatus.length > 64 ||
      (state === 'PAID' && automaticTaxStatus !== 'complete')) {
    throw new TypeError('Stripe Checkout automatic tax state is invalid.');
  }
  const paymentIntentId = optionalIdentifier(session.payment_intent, PAYMENT_INTENT_ID, 'Stripe PaymentIntent id');
  const paymentLinkId = session.payment_link === null
    ? null
    : identifier(session.payment_link, PAYMENT_LINK_ID, 'Stripe Payment Link id');
  const reviewCheckoutBinding = paymentLinkId === null ? normalizeReviewCheckoutBinding(session.metadata) : null;
  if (state === 'PAID' && !paymentIntentId) throw new TypeError('Paid Checkout Session lacks a PaymentIntent.');

  const reference = session.client_reference_id;
  if (reference !== null && reference !== undefined &&
      (typeof reference !== 'string' || reference.length < 1 || reference.length > 512 || /[\u0000-\u001f\u007f]/.test(reference))) {
    throw new TypeError('Stripe Checkout client reference is invalid.');
  }
  if (reviewCheckoutBinding !== null && reference !== reviewCheckoutBinding.approval_receipt_sha256) {
    throw new TypeError('Stripe review Checkout reference is invalid.');
  }
  const customer = session.customer_details === null || session.customer_details === undefined
    ? null : plainObject(session.customer_details, 'Stripe Checkout customer details');
  const address = customer?.address === null || customer?.address === undefined
    ? null : plainObject(customer.address, 'Stripe Checkout customer address');
  const country = address?.country ?? null;
  const region = address?.state ?? (country ? '' : null);
  if ((country !== null && !/^[A-Z]{2}$/.test(country)) ||
      (region !== null && !/^[A-Z0-9-]{0,10}$/.test(region))) {
    throw new TypeError('Stripe Checkout customer destination is invalid.');
  }
  let payerEmailSha256 = null;
  let payerEmailUsable = true;
  try {
    payerEmailSha256 = optionalEmailHash(customer?.email ?? session.customer_email ?? null);
    payerEmailUsable = payerEmailSha256 !== null;
  } catch (error) {
    // A malformed payer email on a captured review-session payment must become
    // durable manual review, not an endless webhook retry after funds moved.
    // Legacy Payment Link events retain their exact historical rejection.
    if (reviewCheckoutBinding === null || state !== 'PAID') throw error;
    payerEmailUsable = false;
  }
  const termsAccepted = session.consent?.terms_of_service === 'accepted';
  const adultAccepted = customFieldAccepted(session);
  const paidPurchaserDataValid = payerEmailUsable && Boolean(country) &&
    (country !== 'US' || /^[A-Z]{2}$/.test(region)) && termsAccepted && adultAccepted;
  if (state === 'PAID' && !paidPurchaserDataValid) {
    if (reviewCheckoutBinding === null) {
      throw new TypeError('Paid Checkout Session lacks required purchaser consent or destination data.');
    }
    state = 'REVIEW_REQUIRED';
  }
  const createdAt = new Date(event.created * 1000);
  if (!Number.isFinite(createdAt.getTime())) throw new TypeError('Stripe Checkout event timestamp is invalid.');
  return {
    adultAccepted,
    automaticTaxEnabled: automaticTax.enabled,
    automaticTaxStatus,
    canonical: raw,
    clientReferenceSha256: typeof reference === 'string' ? sha256Hex(reference) : null,
    currency: session.currency,
    digest: sha256Hex(raw),
    eventCreatedAt: createdAt.toISOString(),
    eventId: event.id,
    eventType: event.type,
    livemode: event.livemode,
    paymentIntentId,
    paymentLinkId,
    payerEmailSha256,
    reviewCheckoutBinding,
    sessionId,
    state,
    subtotal,
    tax,
    termsAccepted,
    total,
    country,
    region,
  };
}

function eventReservationKey(eventId, env) {
  return `stripe-checkout-event/${identityHmac(env, 'event-id', eventId)}`;
}

function sessionStateKey(sessionId, env) {
  return `stripe-checkout-session/${identityHmac(env, 'session-id', sessionId)}`;
}

function sessionStateKeyFromHmac(sessionIdHmac) {
  if (!HEX_64.test(String(sessionIdHmac || ''))) throw new TypeError('Stripe Checkout Session HMAC is invalid.');
  return `stripe-checkout-session/${sessionIdHmac}`;
}

function handoffBindingKey(handoffId) {
  if (!HEX_64.test(String(handoffId || ''))) throw new TypeError('ARC handoff id is invalid.');
  return `stripe-checkout-handoff/${handoffId}`;
}

function receiptKey(eventId, env) {
  return `stripe-checkout-receipt/${identityHmac(env, 'event-id', eventId)}`;
}

function receiptKeyFromEventHmac(eventIdHmac) {
  if (!HEX_64.test(String(eventIdHmac || ''))) throw new TypeError('Stripe Checkout event HMAC is invalid.');
  return `stripe-checkout-receipt/${eventIdHmac}`;
}

function factsFromEvent(event, env) {
  return {
    adultAccepted: event.adultAccepted,
    automaticTaxEnabled: event.automaticTaxEnabled,
    automaticTaxStatus: event.automaticTaxStatus,
    clientReferenceSha256: event.clientReferenceSha256,
    country: event.country,
    currency: event.currency,
    digest: event.digest,
    eventCreatedAt: event.eventCreatedAt,
    eventIdHmac: identityHmac(env, 'event-id', event.eventId),
    eventType: event.eventType,
    livemode: event.livemode,
    paymentIntentIdHmac: event.paymentIntentId ? identityHmac(env, 'payment-intent-id', event.paymentIntentId) : null,
    paymentLinkIdHmac: event.paymentLinkId ? identityHmac(env, 'payment-link-id', event.paymentLinkId) : null,
    payerEmailSha256: event.payerEmailSha256,
    region: event.region,
    reviewCheckoutBinding: event.reviewCheckoutBinding,
    sessionIdHmac: identityHmac(env, 'session-id', event.sessionId),
    state: event.state,
    subtotal: event.subtotal,
    tax: event.tax,
    termsAccepted: event.termsAccepted,
    total: event.total,
  };
}

function reservationValue(facts, env) {
  return {
    schema: STRIPE_CHECKOUT_EVENT_SCHEMA,
    event_id_hmac_sha256: facts.eventIdHmac,
    event_sha256: facts.digest,
    event_created_at: facts.eventCreatedAt,
    event_type: facts.eventType,
    observed_state: facts.state,
    checkout_session_id_hmac_sha256: facts.sessionIdHmac,
    payment_intent_id_hmac_sha256: facts.paymentIntentIdHmac,
    payment_link_id_hmac_sha256: facts.paymentLinkIdHmac,
    client_reference_id_sha256: facts.clientReferenceSha256,
    payer_email_sha256: facts.payerEmailSha256,
    customer_address_country: facts.country,
    customer_address_state: facts.region,
    livemode: facts.livemode,
    stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    currency: facts.currency,
    subtotal_amount_minor_units: facts.subtotal,
    tax_amount_minor_units: facts.tax,
    amount_total_minor_units: facts.total,
    automatic_tax_enabled: facts.automaticTaxEnabled,
    automatic_tax_status: facts.automaticTaxStatus,
    terms_of_service_consent: facts.termsAccepted,
    adult_purchaser_acknowledgement: facts.adultAccepted,
    ...(facts.reviewCheckoutBinding === null ? {} : { review_checkout_binding: facts.reviewCheckoutBinding }),
  };
}

async function ensureImmutable(store, key, value, conflictCode) {
  const existing = await readIndex(store, key);
  if (existing) {
    if (canonicalJson(existing) !== canonicalJson(value)) throw new Error(conflictCode);
    return { created: false, value: existing };
  }
  try {
    await createIndex(store, key, value);
    return { created: true, value };
  } catch (error) {
    if (error?.message !== 'ARC2_INDEX_CONFLICT') throw error;
    const raced = await readIndex(store, key);
    if (!raced || canonicalJson(raced) !== canonicalJson(value)) throw new Error(conflictCode);
    return { created: false, value: raced };
  }
}

function invariantConflict(current, facts, env) {
  return current.schema !== STRIPE_CHECKOUT_SESSION_SCHEMA ||
    current.checkout_session_id_hmac_sha256 !== facts.sessionIdHmac ||
    current.payment_link_id_hmac_sha256 !== facts.paymentLinkIdHmac ||
    canonicalJson(current.review_checkout_binding ?? null) !== canonicalJson(facts.reviewCheckoutBinding) ||
    current.stripe_account_id_sha256 !== env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 ||
    current.livemode !== facts.livemode || current.currency !== facts.currency ||
    current.subtotal_amount_minor_units !== facts.subtotal || current.tax_amount_minor_units !== facts.tax ||
    current.amount_total_minor_units !== facts.total || current.automatic_tax_enabled !== facts.automaticTaxEnabled ||
    (current.payment_intent_id_hmac_sha256 !== null && facts.paymentIntentIdHmac !== null &&
      current.payment_intent_id_hmac_sha256 !== facts.paymentIntentIdHmac) ||
    (current.client_reference_id_sha256 !== null && facts.clientReferenceSha256 !== null &&
      current.client_reference_id_sha256 !== facts.clientReferenceSha256) ||
    (current.payer_email_sha256 !== null && facts.payerEmailSha256 !== null && current.payer_email_sha256 !== facts.payerEmailSha256) ||
    (current.customer_address_country !== null && facts.country !== null && current.customer_address_country !== facts.country) ||
    (current.customer_address_state !== null && facts.region !== null && current.customer_address_state !== facts.region);
}

function nextState(currentState, observedState, conflict, eventIsOlder) {
  if (currentState === 'REVIEW_REQUIRED' || conflict) return 'REVIEW_REQUIRED';
  if (currentState === observedState) return currentState;
  // A completed-but-pending snapshot is always weaker than a terminal
  // Checkout result, even when Stripe emits both events in the same second.
  if (observedState === 'PENDING') return currentState;
  // Stripe does not guarantee delivery order. An older authenticated snapshot
  // cannot roll back a newer Session state or manufacture a conflict by arriving
  // late. Equal/newer contradictory terminal states still fail closed.
  if (eventIsOlder) return currentState;
  if (currentState === 'PENDING') return observedState;
  return 'REVIEW_REQUIRED';
}

function nextSessionSummary(current, facts, env) {
  const initial = current || {
    schema: STRIPE_CHECKOUT_SESSION_SCHEMA,
    checkout_session_id_hmac_sha256: facts.sessionIdHmac,
    payment_intent_id_hmac_sha256: facts.paymentIntentIdHmac,
    payment_link_id_hmac_sha256: facts.paymentLinkIdHmac,
    client_reference_id_sha256: facts.clientReferenceSha256,
    payer_email_sha256: facts.payerEmailSha256,
    customer_address_country: facts.country,
    customer_address_state: facts.region,
    stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    livemode: facts.livemode,
    currency: facts.currency,
    subtotal_amount_minor_units: facts.subtotal,
    tax_amount_minor_units: facts.tax,
    amount_total_minor_units: facts.total,
    automatic_tax_enabled: facts.automaticTaxEnabled,
    automatic_tax_status: facts.automaticTaxStatus,
    terms_of_service_consent: facts.termsAccepted,
    adult_purchaser_acknowledgement: facts.adultAccepted,
    ...(facts.reviewCheckoutBinding === null ? {} : { review_checkout_binding: facts.reviewCheckoutBinding }),
    state: facts.state,
    fulfillment_allowed: facts.state === 'PAID',
    manual_review_required: facts.state === 'REVIEW_REQUIRED',
    first_event_created_at: facts.eventCreatedAt,
    latest_event_created_at: facts.eventCreatedAt,
    latest_event_type: facts.eventType,
    latest_event_id_hmac_sha256: facts.eventIdHmac,
    latest_event_sha256: facts.digest,
    state_event_id_hmac_sha256: facts.eventIdHmac,
    state_event_sha256: facts.digest,
    processed_event_hmacs_sha256: [facts.eventIdHmac],
    event_count: 1,
  };
  if (!current) return initial;
  if (!SESSION_STATES.has(current.state) || current.fulfillment_allowed !== (current.state === 'PAID') ||
      current.manual_review_required !== (current.state === 'REVIEW_REQUIRED') ||
      !Number.isSafeInteger(current.event_count) || current.event_count < 1 || !HEX_64.test(current.latest_event_sha256) ||
      !HEX_64.test(current.latest_event_id_hmac_sha256) || !HEX_64.test(current.state_event_sha256) ||
      !HEX_64.test(current.state_event_id_hmac_sha256)) {
    throw new Error('ARC_STRIPE_CHECKOUT_STATE_CONFLICT');
  }
  const processedEventHmacs = current.processed_event_hmacs_sha256 === undefined
    ? [current.latest_event_id_hmac_sha256]
    : current.processed_event_hmacs_sha256;
  if (!Array.isArray(processedEventHmacs) || processedEventHmacs.length < 1 || processedEventHmacs.length > 64 ||
      processedEventHmacs.some((value) => !HEX_64.test(value)) || new Set(processedEventHmacs).size !== processedEventHmacs.length ||
      (current.processed_event_hmacs_sha256 !== undefined && current.event_count !== processedEventHmacs.length)) {
    throw new Error('ARC_STRIPE_CHECKOUT_STATE_CONFLICT');
  }
  const conflict = invariantConflict(current, facts, env);
  const alreadyProcessed = processedEventHmacs.includes(facts.eventIdHmac);
  const candidateOrder = `${facts.eventCreatedAt}\n${facts.digest}`;
  const currentOrder = `${current.latest_event_created_at}\n${current.latest_event_sha256}`;
  const newest = candidateOrder > currentOrder;
  const eventIsOlder = facts.eventCreatedAt < current.latest_event_created_at;
  const state = nextState(current.state, facts.state, conflict, eventIsOlder);
  if (alreadyProcessed && state === current.state) return current;
  if (!alreadyProcessed && processedEventHmacs.length >= 64) throw new Error('ARC_STRIPE_CHECKOUT_STATE_CONFLICT');
  const stateChanged = state !== current.state;
  return {
    ...current,
    payment_intent_id_hmac_sha256: current.payment_intent_id_hmac_sha256 ?? facts.paymentIntentIdHmac,
    client_reference_id_sha256: current.client_reference_id_sha256 ?? facts.clientReferenceSha256,
    payer_email_sha256: current.payer_email_sha256 ?? facts.payerEmailSha256,
    customer_address_country: current.customer_address_country ?? facts.country,
    customer_address_state: current.customer_address_state ?? facts.region,
    automatic_tax_status: newest ? facts.automaticTaxStatus : current.automatic_tax_status,
    terms_of_service_consent: current.terms_of_service_consent || facts.termsAccepted,
    adult_purchaser_acknowledgement: current.adult_purchaser_acknowledgement || facts.adultAccepted,
    state,
    fulfillment_allowed: state === 'PAID',
    manual_review_required: state === 'REVIEW_REQUIRED',
    first_event_created_at: facts.eventCreatedAt < current.first_event_created_at ? facts.eventCreatedAt : current.first_event_created_at,
    ...(newest ? {
      latest_event_created_at: facts.eventCreatedAt,
      latest_event_type: facts.eventType,
      latest_event_id_hmac_sha256: facts.eventIdHmac,
      latest_event_sha256: facts.digest,
    } : {}),
    ...(stateChanged ? {
      state_event_id_hmac_sha256: facts.eventIdHmac,
      state_event_sha256: facts.digest,
    } : {}),
    processed_event_hmacs_sha256: alreadyProcessed ? processedEventHmacs : [...processedEventHmacs, facts.eventIdHmac],
    event_count: alreadyProcessed ? current.event_count : current.event_count + 1,
  };
}

async function applySessionEvent(store, key, facts, env) {
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
    const entry = await readIndexEntry(store, key);
    const next = nextSessionSummary(entry?.value || null, facts, env);
    if (!entry) {
      try {
        await createIndex(store, key, next);
        return next;
      } catch (error) {
        if (error?.message !== 'ARC2_INDEX_CONFLICT') throw error;
        continue;
      }
    }
    try {
      await replaceIndex(store, key, entry, next);
      return next;
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION') throw error;
    }
  }
  throw new Error('ARC_STRIPE_CHECKOUT_STATE_CONTENTION');
}

function deterministicReceipt(facts, env, resultingState) {
  if (!SESSION_STATES.has(resultingState)) throw new TypeError('Stripe Checkout receipt state is invalid.');
  return {
    schema: STRIPE_CHECKOUT_RECEIPT_SCHEMA,
    event_id_hmac_sha256: facts.eventIdHmac,
    event_sha256: facts.digest,
    checkout_session_id_hmac_sha256: facts.sessionIdHmac,
    stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    accepted: true,
    resulting_state: resultingState,
    review_alert_required: resultingState === 'REVIEW_REQUIRED',
  };
}

async function ensureReviewAlert(alertStore, facts) {
  if (!alertStore) return;
  const alertKey = `alerts/stripe-checkout-review/${facts.eventIdHmac}`;
  await ensureImmutable(alertStore, alertKey, {
    schema: STRIPE_CHECKOUT_REVIEW_SCHEMA,
    status: 'OPEN',
    category: 'stripe-checkout-review',
    severity: 'critical',
    handoff_id: null,
    subject_hmac_sha256: facts.eventIdHmac,
    detected_at: facts.eventCreatedAt,
    delivery_status: 'PENDING',
    contains_customer_data: false,
  }, 'ARC_STRIPE_CHECKOUT_ALERT_CONFLICT');
}

export async function processStripeCheckoutEvent(raw, stripeSignature, env, adapters = {}) {
  if (!adapters.store) throw new TypeError('Stripe Checkout store is unavailable.');
  const clock = adapters.clock || (() => new Date());
  const event = normalizeStripeCheckoutEvent(raw, stripeSignature, env, clock());
  await verifyStripeEventOwnership({
    eventId: event.eventId,
    eventType: event.eventType,
    livemode: event.livemode,
    objectId: event.sessionId,
    objectType: 'checkout.session',
  }, env, { fetch: adapters.accountFetch });
  const facts = factsFromEvent(event, env);
  const reservation = reservationValue(facts, env);
  const eventKey = eventReservationKey(event.eventId, env);
  const receiptStorageKey = receiptKey(event.eventId, env);
  const eventResult = await ensureImmutable(adapters.store, eventKey, reservation, 'ARC_STRIPE_CHECKOUT_EVENT_CONFLICT');
  const existingReceipt = await readIndex(adapters.store, receiptStorageKey);
  if (existingReceipt) {
    const expectedReceipt = deterministicReceipt(facts, env, existingReceipt.resulting_state);
    if (canonicalJson(existingReceipt) !== canonicalJson(expectedReceipt)) throw new Error('ARC_STRIPE_CHECKOUT_RECEIPT_CONFLICT');
    const existingSummary = await readIndex(adapters.store, sessionStateKey(event.sessionId, env));
    if (!existingSummary) throw new Error('ARC_STRIPE_CHECKOUT_RECEIPT_CONFLICT');
    if (existingReceipt.review_alert_required) await ensureReviewAlert(adapters.alertStore, facts);
    return { event, idempotentReplay: true, receipt: existingReceipt, summary: existingSummary };
  }
  const summary = await applySessionEvent(adapters.store, sessionStateKey(event.sessionId, env), facts, env);
  if (summary.state === 'REVIEW_REQUIRED') await ensureReviewAlert(adapters.alertStore, facts);
  // A processing receipt is written last. Handoff authorization requires the
  // receipt that corresponds to the event which established the paid state,
  // so a crash in state or alert persistence cannot expose a half-processed
  // payment as fulfillable.
  const receipt = deterministicReceipt(facts, env, summary.state);
  await ensureImmutable(adapters.store, receiptStorageKey, receipt, 'ARC_STRIPE_CHECKOUT_RECEIPT_CONFLICT');
  return { event, idempotentReplay: !eventResult.created, receipt, summary };
}

async function assertPaidSummaryAndReceipt(store, summary) {
  if (!summary) throw new Error('ARC_STRIPE_CHECKOUT_EVENT_REQUIRED');
  if (summary.schema !== STRIPE_CHECKOUT_SESSION_SCHEMA || summary.state === 'REVIEW_REQUIRED' || summary.manual_review_required !== false ||
      !HEX_64.test(String(summary.state_event_id_hmac_sha256 || '')) || !HEX_64.test(String(summary.state_event_sha256 || ''))) {
    throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_HALT');
  }
  if (summary.state !== 'PAID' || summary.fulfillment_allowed !== true) throw new Error('ARC_STRIPE_CHECKOUT_PAYMENT_NOT_PAID');
  const stateReceipt = await readIndex(store, receiptKeyFromEventHmac(summary.state_event_id_hmac_sha256));
  if (!stateReceipt) throw new Error('ARC_STRIPE_CHECKOUT_RECEIPT_REQUIRED');
  if (stateReceipt.schema !== STRIPE_CHECKOUT_RECEIPT_SCHEMA || stateReceipt.accepted !== true ||
      stateReceipt.resulting_state !== 'PAID' || stateReceipt.review_alert_required !== false ||
      stateReceipt.event_id_hmac_sha256 !== summary.state_event_id_hmac_sha256 ||
      stateReceipt.event_sha256 !== summary.state_event_sha256 ||
      stateReceipt.checkout_session_id_hmac_sha256 !== summary.checkout_session_id_hmac_sha256 ||
      stateReceipt.stripe_account_id_sha256 !== summary.stripe_account_id_sha256) {
    throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_HALT');
  }
  return summary;
}

export async function assertStripeCheckoutPaid(store, paymentEvidence, env, adapters = {}) {
  const configuration = stripeCheckoutConfiguration(env);
  if (!configuration.flagsValid) throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_DISABLED');
  if (!configuration.required) {
    if (!configuration.sandboxBypass) throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_DISABLED');
    return { required: false, ready: true };
  }
  if (!configuration.webhookOperational) throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_DISABLED');
  const sessionId = identifier(paymentEvidence?.checkout_session_id, CHECKOUT_SESSION_ID, 'Payment evidence Checkout Session id');
  await verifyStripeAccountBinding(env, { fetch: adapters.accountFetch });
  const summary = await assertPaidSummaryAndReceipt(store, await readIndex(store, sessionStateKey(sessionId, env)));
  const expectedReference = paymentEvidence.client_reference_id_observation === 'ABSENT' ? null : paymentEvidence.client_reference_id_sha256;
  const paymentIntentId = identifier(paymentEvidence.payment_intent_id, PAYMENT_INTENT_ID, 'Payment evidence PaymentIntent id');
  const paymentLinkId = identifier(paymentEvidence.payment_link_id, PAYMENT_LINK_ID, 'Payment evidence Payment Link id');
  const bindingsValid = summary.checkout_session_id_hmac_sha256 === identityHmac(env, 'session-id', sessionId) &&
    summary.payment_intent_id_hmac_sha256 === identityHmac(env, 'payment-intent-id', paymentIntentId) &&
    summary.payment_link_id_hmac_sha256 === identityHmac(env, 'payment-link-id', paymentLinkId) &&
    summary.client_reference_id_sha256 === expectedReference &&
    paymentEvidence.client_reference_id_observation !== 'MISMATCH_REVIEW_REQUIRED' &&
    summary.payer_email_sha256 === paymentEvidence.payer_email_sha256 &&
    summary.customer_address_country === paymentEvidence.customer_address_country &&
    summary.customer_address_state === paymentEvidence.customer_address_state &&
    summary.stripe_account_id_sha256 === paymentEvidence.stripe_account_id_sha256 &&
    summary.livemode === paymentEvidence.livemode && summary.currency === paymentEvidence.currency &&
    summary.subtotal_amount_minor_units === paymentEvidence.subtotal_amount_minor_units &&
    summary.tax_amount_minor_units === paymentEvidence.tax_amount_minor_units &&
    summary.amount_total_minor_units === paymentEvidence.amount_total_minor_units &&
    summary.automatic_tax_enabled === paymentEvidence.automatic_tax_enabled &&
    summary.automatic_tax_status === paymentEvidence.automatic_tax_status &&
    summary.terms_of_service_consent === true && paymentEvidence.terms_of_service_consent === 'accepted' &&
    summary.adult_purchaser_acknowledgement === true && paymentEvidence.adult_purchaser_acknowledgement === 'accepted';
  if (!bindingsValid) throw new Error('ARC_STRIPE_CHECKOUT_BINDING_MISMATCH');
  return { required: true, ready: true, summary };
}

export async function assertStripeReviewCheckoutPaid(store, paymentEvidence, env, adapters = {}) {
  const configuration = stripeCheckoutConfiguration(env);
  if (!configuration.flagsValid) throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_DISABLED');
  // Unlike frozen Payment Link v4, the review-session schema has no other
  // payment evidence producer. Even in the explicit sandbox, bind it to the
  // authenticated ledger rather than returning the legacy bypass result.
  if (!configuration.required && !configuration.sandboxBypass) {
    throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_DISABLED');
  }
  if (!configuration.webhookOperational) throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_DISABLED');
  const sessionId = identifier(paymentEvidence?.checkout_session_id, CHECKOUT_SESSION_ID,
    'Review payment evidence Checkout Session id');
  const paymentIntentId = identifier(paymentEvidence?.payment_intent_id, PAYMENT_INTENT_ID,
    'Review payment evidence PaymentIntent id');
  if (paymentEvidence.payment_link_id !== null) throw new Error('ARC_STRIPE_CHECKOUT_BINDING_MISMATCH');
  await verifyStripeAccountBinding(env, { fetch: adapters.accountFetch });
  const summary = await assertPaidSummaryAndReceipt(store, await readIndex(store, sessionStateKey(sessionId, env)));
  const expectedMetadata = {
    approval_receipt_hmac_sha256: paymentEvidence.approval_receipt_hmac_sha256,
    approval_receipt_sha256: paymentEvidence.approval_receipt_sha256,
    invite_hmac_sha256: paymentEvidence.invite_hmac_sha256,
    offer_contract_id: REVIEW_CHECKOUT_OFFER_ID,
    preview_manifest_sha256: paymentEvidence.preview_manifest_sha256,
    recipient_email_sha256: paymentEvidence.claim_recipient_email_sha256,
    schema: REVIEW_CHECKOUT_METADATA_SCHEMA,
    scope_version: REVIEW_CHECKOUT_OFFER_ID,
    terms_version: REVIEW_CHECKOUT_TERMS_VERSION,
  };
  const bindingsValid = summary.checkout_session_id_hmac_sha256 ===
      identityHmac(env, 'session-id', sessionId) &&
    summary.payment_intent_id_hmac_sha256 === identityHmac(env, 'payment-intent-id', paymentIntentId) &&
    summary.payment_link_id_hmac_sha256 === null &&
    canonicalJson(summary.review_checkout_binding) === canonicalJson(expectedMetadata) &&
    summary.client_reference_id_sha256 === paymentEvidence.client_reference_id_sha256 &&
    summary.payer_email_sha256 === paymentEvidence.payer_email_sha256 &&
    summary.customer_address_country === paymentEvidence.customer_address_country &&
    summary.customer_address_state === paymentEvidence.customer_address_state &&
    summary.stripe_account_id_sha256 === paymentEvidence.stripe_account_id_sha256 &&
    summary.livemode === paymentEvidence.livemode && summary.currency === paymentEvidence.currency &&
    summary.subtotal_amount_minor_units === paymentEvidence.subtotal_amount_minor_units &&
    summary.tax_amount_minor_units === paymentEvidence.tax_amount_minor_units &&
    summary.amount_total_minor_units === paymentEvidence.amount_total_minor_units &&
    summary.automatic_tax_enabled === paymentEvidence.automatic_tax_enabled &&
    summary.automatic_tax_status === paymentEvidence.automatic_tax_status &&
    summary.terms_of_service_consent === true && paymentEvidence.terms_of_service_consent === 'accepted' &&
    summary.adult_purchaser_acknowledgement === true &&
      paymentEvidence.adult_purchaser_acknowledgement === 'accepted';
  if (!bindingsValid) throw new Error('ARC_STRIPE_CHECKOUT_BINDING_MISMATCH');
  return { required: true, ready: true, summary };
}

export async function bindStripeReviewCheckoutToHandoff(
  store,
  handoffId,
  paymentEvidence,
  paymentEvidenceSha256,
  env,
  adapters = {},
) {
  if (!HEX_64.test(String(handoffId || '')) || !HEX_64.test(String(paymentEvidenceSha256 || ''))) {
    throw new TypeError('Stripe review Checkout handoff binding identity is invalid.');
  }
  const checkout = await assertStripeReviewCheckoutPaid(store, paymentEvidence, env, adapters);
  if (!checkout.required) return { required: false, ready: true };
  const value = {
    schema: STRIPE_REVIEW_CHECKOUT_HANDOFF_BINDING_SCHEMA,
    handoff_id: handoffId,
    checkout_session_id_hmac_sha256: checkout.summary.checkout_session_id_hmac_sha256,
    payment_intent_id_hmac_sha256: checkout.summary.payment_intent_id_hmac_sha256,
    payment_link_id_hmac_sha256: null,
    payment_evidence_sha256: paymentEvidenceSha256,
    bridge_immutable_binding_sha256: paymentEvidence.bridge_immutable_binding_sha256,
    review_session_binding_sha256: paymentEvidence.review_session_binding_sha256,
    approval_receipt_sha256: paymentEvidence.approval_receipt_sha256,
    recipient_email_sha256: paymentEvidence.claim_recipient_email_sha256,
    payer_email_sha256: paymentEvidence.payer_email_sha256,
    review_checkout_binding_sha256: sha256Hex(canonicalJson(checkout.summary.review_checkout_binding)),
    stripe_account_id_sha256: checkout.summary.stripe_account_id_sha256,
    livemode: checkout.summary.livemode,
  };
  await ensureImmutable(store, handoffBindingKey(handoffId), value,
    'ARC_STRIPE_CHECKOUT_HANDOFF_BINDING_CONFLICT');
  return { binding: value, required: true, ready: true, summary: checkout.summary };
}

export async function bindStripeCheckoutToHandoff(store, handoffId, paymentEvidence, paymentEvidenceSha256, env, adapters = {}) {
  if (!HEX_64.test(String(handoffId || '')) || !HEX_64.test(String(paymentEvidenceSha256 || ''))) {
    throw new TypeError('Stripe Checkout handoff binding identity is invalid.');
  }
  const checkout = await assertStripeCheckoutPaid(store, paymentEvidence, env, adapters);
  if (!checkout.required) return { required: false, ready: true };
  const value = {
    schema: STRIPE_CHECKOUT_HANDOFF_BINDING_SCHEMA,
    handoff_id: handoffId,
    checkout_session_id_hmac_sha256: checkout.summary.checkout_session_id_hmac_sha256,
    payment_intent_id_hmac_sha256: checkout.summary.payment_intent_id_hmac_sha256,
    payment_link_id_hmac_sha256: checkout.summary.payment_link_id_hmac_sha256,
    payment_evidence_sha256: paymentEvidenceSha256,
    stripe_account_id_sha256: checkout.summary.stripe_account_id_sha256,
    livemode: checkout.summary.livemode,
  };
  await ensureImmutable(store, handoffBindingKey(handoffId), value, 'ARC_STRIPE_CHECKOUT_HANDOFF_BINDING_CONFLICT');
  return { binding: value, required: true, ready: true, summary: checkout.summary };
}

export async function assertHandoffStripeCheckoutPaid(store, handoffId, paymentEvidenceSha256, env, adapters = {}) {
  const configuration = stripeCheckoutConfiguration(env);
  if (!configuration.flagsValid) throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_DISABLED');
  if (!configuration.required && !configuration.sandboxBypass) {
    throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_DISABLED');
  }
  if (!HEX_64.test(String(handoffId || '')) || !HEX_64.test(String(paymentEvidenceSha256 || ''))) {
    throw new TypeError('Stripe Checkout handoff binding identity is invalid.');
  }
  const binding = await readIndex(store, handoffBindingKey(handoffId));
  // Preserve the explicit legacy sandbox bypass. Review-session handoffs have
  // no legacy evidence producer, so their durable binding must still be read
  // and revalidated even when the surrounding test runtime uses that bypass.
  if (!configuration.required && configuration.sandboxBypass &&
      binding?.schema !== STRIPE_REVIEW_CHECKOUT_HANDOFF_BINDING_SCHEMA) {
    return { required: false, ready: true };
  }
  if (!configuration.webhookOperational) throw new Error('ARC_STRIPE_CHECKOUT_LEDGER_DISABLED');
  await verifyStripeAccountBinding(env, { fetch: adapters.accountFetch });
  if (!binding) throw new Error('ARC_STRIPE_CHECKOUT_HANDOFF_BINDING_REQUIRED');
  const legacyBinding = binding.schema === STRIPE_CHECKOUT_HANDOFF_BINDING_SCHEMA;
  const reviewBinding = binding.schema === STRIPE_REVIEW_CHECKOUT_HANDOFF_BINDING_SCHEMA;
  if ((!legacyBinding && !reviewBinding) || binding.handoff_id !== handoffId ||
      binding.payment_evidence_sha256 !== paymentEvidenceSha256 || !HEX_64.test(String(binding.checkout_session_id_hmac_sha256 || '')) ||
      !HEX_64.test(String(binding.payment_intent_id_hmac_sha256 || '')) ||
      (legacyBinding ? !HEX_64.test(String(binding.payment_link_id_hmac_sha256 || '')) :
        binding.payment_link_id_hmac_sha256 !== null) ||
      binding.stripe_account_id_sha256 !== env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 ||
      binding.livemode !== configuration.expectedLivemode) {
    throw new Error('ARC_STRIPE_CHECKOUT_HANDOFF_BINDING_CONFLICT');
  }
  if (reviewBinding && (!HEX_64.test(String(binding.bridge_immutable_binding_sha256 || '')) ||
      !HEX_64.test(String(binding.review_session_binding_sha256 || '')) ||
      !HEX_64.test(String(binding.approval_receipt_sha256 || '')) ||
      !HEX_64.test(String(binding.recipient_email_sha256 || '')) ||
      !HEX_64.test(String(binding.payer_email_sha256 || '')) ||
      !HEX_64.test(String(binding.review_checkout_binding_sha256 || '')))) {
    throw new Error('ARC_STRIPE_CHECKOUT_HANDOFF_BINDING_CONFLICT');
  }
  const summary = await assertPaidSummaryAndReceipt(store,
    await readIndex(store, sessionStateKeyFromHmac(binding.checkout_session_id_hmac_sha256)));
  if (summary.checkout_session_id_hmac_sha256 !== binding.checkout_session_id_hmac_sha256 ||
      summary.payment_intent_id_hmac_sha256 !== binding.payment_intent_id_hmac_sha256 ||
      summary.payment_link_id_hmac_sha256 !== binding.payment_link_id_hmac_sha256 ||
      summary.stripe_account_id_sha256 !== binding.stripe_account_id_sha256 || summary.livemode !== binding.livemode) {
    throw new Error('ARC_STRIPE_CHECKOUT_HANDOFF_BINDING_CONFLICT');
  }
  if (reviewBinding && (summary.payer_email_sha256 !== binding.payer_email_sha256 ||
      summary.review_checkout_binding?.approval_receipt_sha256 !== binding.approval_receipt_sha256 ||
      summary.review_checkout_binding?.recipient_email_sha256 !== binding.recipient_email_sha256 ||
      sha256Hex(canonicalJson(summary.review_checkout_binding)) !== binding.review_checkout_binding_sha256)) {
    throw new Error('ARC_STRIPE_CHECKOUT_HANDOFF_BINDING_CONFLICT');
  }
  return { binding, required: true, ready: true, summary };
}

export const stripeCheckoutKeys = Object.freeze({
  eventReservationKey,
  handoffBindingKey,
  receiptKey,
  sessionStateKey,
});
