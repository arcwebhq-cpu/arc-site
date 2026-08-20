import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  canonicalJson,
  hmacHex,
  REQUIRED_STRIPE_WEBHOOK_API_VERSION,
  safeEqual,
  sha256Hex,
  validateExpectedBindings,
} from './arc2-handoff-core.mjs';
import {
  createIndex,
  readEntry,
  readIndex,
  readIndexEntry,
  replaceIndex,
} from './arc2-handoff-store.mjs';

export const STRIPE_REVERSAL_SCHEMA = 'arc-stripe-reversal-state-v1';
export const STRIPE_REVERSAL_EVENT_SCHEMA = 'arc-stripe-reversal-event-v1';
export const STRIPE_REVERSAL_BINDING_SCHEMA = 'arc-stripe-reversal-binding-v1';
export const STRIPE_REVERSAL_BINDING_SCOPE = 'authoritative-checkout-session-payment-intent-binding';
export const STRIPE_REVERSAL_BINDING_PREFIX = 'arc-stripe-reversal-binding-signature-v1\n';
export const STRIPE_REVERSAL_RECHECK_SCHEMA = 'arc-stripe-reversal-recheck-v1';
export const STRIPE_REVERSAL_RECHECK_SCOPE = 'authoritative-stripe-no-reversal-recheck';
export const STRIPE_REVERSAL_RECHECK_PREFIX = 'arc-stripe-reversal-recheck-signature-v1\n';
export const STRIPE_PAYMENT_INTENT_INDEX_SCHEMA = 'arc-stripe-payment-intent-index-v1';
export const STRIPE_PENDING_REVERSAL_SCHEMA = 'arc-stripe-pending-reversal-v1';
export const STRIPE_PENDING_PAYMENT_SCHEMA = 'arc-stripe-pending-payment-halt-v1';
export const STRIPE_REVERSAL_ALERT_SCHEMA = 'arc-operational-alert-v1';
export const STRIPE_WEBHOOK_API_VERSION = REQUIRED_STRIPE_WEBHOOK_API_VERSION;
export const STRIPE_SIGNATURE_TOLERANCE_SECONDS = 300;
export const STRIPE_REVERSAL_RECHECK_MAX_AGE_MS = 5 * 60_000;
export const STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS = 60_000;

export const STRIPE_REVERSAL_EVENT_TYPES = Object.freeze([
  'charge.dispute.closed',
  'charge.dispute.created',
  'charge.dispute.funds_reinstated',
  'charge.dispute.funds_withdrawn',
  'charge.dispute.updated',
  'charge.refunded',
  'refund.created',
  'refund.failed',
  'refund.updated',
]);

const EVENT_TYPES = new Set(STRIPE_REVERSAL_EVENT_TYPES);
const REFUND_STATUSES = new Set(['pending', 'requires_action', 'succeeded', 'failed', 'canceled']);
const DISPUTE_STATUSES = new Set([
  'warning_needs_response',
  'warning_under_review',
  'warning_closed',
  'needs_response',
  'under_review',
  'won',
  'lost',
  'prevented',
]);
const HEX_64 = /^[a-f0-9]{64}$/;
const HANDOFF_ID = /^[a-f0-9]{64}$/;
const CHECKOUT_SESSION_ID = /^cs_(?:test|live)_[A-Za-z0-9_]+$/;
const PAYMENT_INTENT_ID = /^pi_[A-Za-z0-9]+$/;
const EVENT_ID = /^evt_[A-Za-z0-9]+$/;
const REFUND_ID = /^re_[A-Za-z0-9]+$/;
const DISPUTE_ID = /^dp_[A-Za-z0-9]+$/;
const CHARGE_ID = /^ch_[A-Za-z0-9]+$/;
const BINDING_FIELDS = Object.freeze([
  'checkout_session_id',
  'handoff_id',
  'issued_at',
  'livemode',
  'payment_intent_id',
  'scope',
  'stripe_account_id_sha256',
  'version',
]);
const RECHECK_FIELDS = Object.freeze([
  'checkout_session_id',
  'dispute_status',
  'handoff_id',
  'issued_at',
  'livemode',
  'payment_intent_id',
  'payment_intent_status',
  'refunded_amount_minor_units',
  'scope',
  'stripe_account_id_sha256',
  'version',
]);

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  return value;
}

function exactKeys(value, fields, label) {
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    throw new TypeError(`${label} fields are invalid.`);
  }
}

function isoTimestamp(value, label) {
  if (typeof value !== 'string') throw new TypeError(`${label} is invalid.`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return parsed;
}

function validSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}

function checkoutSessionIndexKey(checkoutSessionId, env) {
  return `checkout-session-index/${hmacHex(env.ARC_HANDOFF_STATE_SECRET, `checkout-session-index-v1\n${checkoutSessionId}`)}`;
}

function reversalHandoffKey(handoffId) {
  if (!HANDOFF_ID.test(handoffId)) throw new TypeError('Handoff id is invalid.');
  return `stripe-reversal/handoff/${handoffId}`;
}

function handoffBindingKey(handoffId) {
  if (!HANDOFF_ID.test(handoffId)) throw new TypeError('Handoff id is invalid.');
  return `stripe-reversal-binding/handoff/${handoffId}`;
}

function recheckKey(handoffId) {
  if (!HANDOFF_ID.test(handoffId)) throw new TypeError('Handoff id is invalid.');
  return `stripe-reversal-recheck/handoff/${handoffId}`;
}

function paymentIntentIndexKey(paymentIntentId, env) {
  if (!PAYMENT_INTENT_ID.test(paymentIntentId)) throw new TypeError('PaymentIntent id is invalid.');
  return `stripe-payment-intent/${hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `payment-intent-v1\n${paymentIntentId}`)}`;
}

function eventReservationKey(eventId, env) {
  if (!EVENT_ID.test(eventId)) throw new TypeError('Stripe event id is invalid.');
  return `stripe-reversal-event/${hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `stripe-event-v1\n${eventId}`)}`;
}

function pendingPaymentKeyFromHmac(paymentIntentHmac) {
  if (!HEX_64.test(paymentIntentHmac)) throw new TypeError('PaymentIntent HMAC is invalid.');
  return `stripe-reversal-pending-payment/${paymentIntentHmac}`;
}

function pendingEventKey(paymentIntentHmac, eventHmac) {
  if (!HEX_64.test(paymentIntentHmac) || !HEX_64.test(eventHmac)) throw new TypeError('Pending reversal identity is invalid.');
  return `stripe-reversal-pending/${paymentIntentHmac}/${eventHmac}`;
}

function objectIdentityHmac(kind, id, env) {
  return hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `stripe-${kind}-v1\n${id}`);
}

function exactStored(actual, expected) {
  return actual && canonicalJson(actual) === canonicalJson(expected);
}

async function ensureImmutable(store, key, value) {
  const existing = await readIndex(store, key);
  if (existing) {
    if (!exactStored(existing, value)) throw new Error('ARC_STRIPE_REVERSAL_INDEX_CONFLICT');
    return { created: false, value: existing };
  }
  try {
    await createIndex(store, key, value);
    return { created: true, value };
  } catch (error) {
    if (error?.message !== 'ARC2_INDEX_CONFLICT') throw error;
    const raced = await readIndex(store, key);
    if (!exactStored(raced, value)) throw new Error('ARC_STRIPE_REVERSAL_INDEX_CONFLICT');
    return { created: false, value: raced };
  }
}

export function stripeReversalConfiguration(env = process.env) {
  const mode = String(env.ARC_STRIPE_LIVE_MODE_ENABLED ?? 'false');
  const liveModeValid = mode === 'true' || mode === 'false';
  const names = [
    'ARC_STRIPE_WEBHOOK_SIGNING_SECRET', 'ARC_STRIPE_REVERSAL_HMAC_SECRET', 'ARC_STRIPE_REVERSAL_BINDING_SECRET',
    'ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET', 'ARC_STRIPE_REVERSAL_RECHECK_SECRET',
    'ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET', 'ARC_HANDOFF_STATE_SECRET',
  ];
  const supplied = names.map((name) => env[name]).filter(validSecret);
  const otherSecretNames = [
    'ARC_HANDOFF_TRIGGER_SECRET', 'ARC_CHECKOUT_BINDING_SECRET', 'ARC_CLAIM_TOKEN_SECRET',
    'ARC_EMAIL_CLAIM_BINDING_SECRET', 'ARC_CLAIM_STATE_EVIDENCE_SECRET', 'ARC_FINAL_DELIVERY_ACK_SECRET',
    'ARC_FINAL_DELIVERY_RECEIPT_SECRET', 'ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET', 'ARC_LEAD_ROUTE_EVIDENCE_SECRET',
    'ARC_OPERATIONS_AUDIT_SECRET', 'ARC_OPERATIONS_ALERT_HMAC_SECRET', 'ARC_RETENTION_CLEANUP_SECRET',
    'ARC_RETENTION_MANIFEST_SECRET', 'ARC_RETENTION_RECORD_HMAC_SECRET',
  ];
  const distinct = new Set(supplied).size === supplied.length &&
    !otherSecretNames.some((name) => validSecret(env[name]) && supplied.includes(env[name]));
  const expectedAccount = String(env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 || '');
  const required = env.ARC_STRIPE_REVERSAL_CONTROL_REQUIRED === 'true';
  const webhookEnabled = env.ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED === 'true';
  const bindingEnabled = env.ARC_STRIPE_REVERSAL_BINDING_ENABLED === 'true';
  const recheckEnabled = env.ARC_STRIPE_REVERSAL_RECHECK_ENABLED === 'true';
  const apiVersionValid = env.ARC_STRIPE_WEBHOOK_API_VERSION === STRIPE_WEBHOOK_API_VERSION;
  const commonValid = liveModeValid && HEX_64.test(expectedAccount) && distinct &&
    validSecret(env.ARC_STRIPE_REVERSAL_HMAC_SECRET) && validSecret(env.ARC_HANDOFF_STATE_SECRET);
  const webhookOperational = webhookEnabled && commonValid && apiVersionValid && validSecret(env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET);
  const bindingOperational = bindingEnabled && commonValid && validSecret(env.ARC_STRIPE_REVERSAL_BINDING_SECRET) &&
    validSecret(env.ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET);
  const recheckOperational = recheckEnabled && commonValid && validSecret(env.ARC_STRIPE_REVERSAL_RECHECK_SECRET) &&
    validSecret(env.ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET);
  const enabled = required && webhookOperational && bindingOperational && recheckOperational;
  return {
    apiVersionValid,
    bindingEnabled,
    bindingOperational,
    enabled,
    expectedLivemode: mode === 'true',
    liveModeValid,
    required,
    recheckEnabled,
    recheckOperational,
    secretsValid: distinct && supplied.length === names.length,
    webhookEnabled,
    webhookOperational,
  };
}

function normalizeRecheckEvidence(raw, signature, env, now = new Date()) {
  requireConfigured(env, 'recheck');
  if (typeof raw !== 'string' || raw.length < 2 || raw.length > 20_000) throw new TypeError('Stripe reversal recheck evidence is invalid.');
  const value = plainObject(JSON.parse(raw), 'Stripe reversal recheck evidence');
  exactKeys(value, RECHECK_FIELDS, 'Stripe reversal recheck evidence');
  const configuration = stripeReversalConfiguration(env);
  if (canonicalJson(value) !== raw || value.version !== STRIPE_REVERSAL_RECHECK_SCHEMA || value.scope !== STRIPE_REVERSAL_RECHECK_SCOPE ||
      !CHECKOUT_SESSION_ID.test(value.checkout_session_id) || !PAYMENT_INTENT_ID.test(value.payment_intent_id) ||
      !HANDOFF_ID.test(value.handoff_id) || !HEX_64.test(value.stripe_account_id_sha256) ||
      !safeEqual(value.stripe_account_id_sha256, env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256) ||
      value.livemode !== configuration.expectedLivemode || !value.checkout_session_id.startsWith(value.livemode ? 'cs_live_' : 'cs_test_') ||
      value.payment_intent_status !== 'succeeded' || value.refunded_amount_minor_units !== 0 || value.dispute_status !== 'none') {
    throw new TypeError('Stripe reversal recheck evidence is invalid.');
  }
  const issuedAt = isoTimestamp(value.issued_at, 'Stripe reversal recheck issued_at');
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || issuedAt > nowMs + 30_000 || issuedAt < nowMs - 5 * 60_000) {
    throw new TypeError('Stripe reversal recheck evidence is stale or from the future.');
  }
  if (!HEX_64.test(signature) || !safeEqual(signature, hmacHex(
    env.ARC_STRIPE_REVERSAL_RECHECK_SECRET,
    `${STRIPE_REVERSAL_RECHECK_PREFIX}${raw}`,
  ))) throw new TypeError('Stripe reversal recheck signature mismatch.');
  return { canonical: raw, digest: sha256Hex(raw), issuedAt, value };
}

function recheckStoredValue(normalized, binding, env) {
  return {
    schema: STRIPE_REVERSAL_RECHECK_SCHEMA,
    handoff_id: normalized.value.handoff_id,
    checkout_session_id_hmac_sha256: hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `checkout-session-v1\n${normalized.value.checkout_session_id}`),
    payment_intent_id_hmac_sha256: hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `payment-intent-v1\n${normalized.value.payment_intent_id}`),
    stripe_account_id_sha256: normalized.value.stripe_account_id_sha256,
    livemode: normalized.value.livemode,
    payment_intent_status: 'succeeded',
    refunded_amount_minor_units: 0,
    dispute_status: 'none',
    issued_at: normalized.value.issued_at,
    evidence_sha256: normalized.digest,
    binding_evidence_sha256: binding.binding_evidence_sha256,
  };
}

export async function registerStripeReversalRecheck(raw, signature, env, adapters = {}) {
  const clock = adapters.clock || (() => new Date());
  const normalized = normalizeRecheckEvidence(raw, signature, env, clock());
  const binding = await readIndex(adapters.store, handoffBindingKey(normalized.value.handoff_id));
  if (!binding || binding.schema !== STRIPE_REVERSAL_BINDING_SCHEMA || binding.handoff_id !== normalized.value.handoff_id ||
      binding.checkout_session_id_hmac_sha256 !== hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `checkout-session-v1\n${normalized.value.checkout_session_id}`) ||
      binding.payment_intent_id_hmac_sha256 !== hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `payment-intent-v1\n${normalized.value.payment_intent_id}`) ||
      binding.stripe_account_id_sha256 !== normalized.value.stripe_account_id_sha256 || binding.livemode !== normalized.value.livemode) {
    throw new Error('ARC_STRIPE_REVERSAL_RECHECK_BINDING_MISMATCH');
  }
  if (await readIndex(adapters.store, pendingPaymentKeyFromHmac(binding.payment_intent_id_hmac_sha256))) {
    throw new Error('ARC_STRIPE_REVERSAL_HALT');
  }
  if (await readIndex(adapters.store, reversalHandoffKey(normalized.value.handoff_id))) throw new Error('ARC_STRIPE_REVERSAL_HALT');
  const key = recheckKey(normalized.value.handoff_id);
  const next = recheckStoredValue(normalized, binding, env);
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const existing = await readIndexEntry(adapters.store, key);
    if (existing) {
      if (existing.value.schema !== STRIPE_REVERSAL_RECHECK_SCHEMA || existing.value.handoff_id !== normalized.value.handoff_id ||
          existing.value.checkout_session_id_hmac_sha256 !== next.checkout_session_id_hmac_sha256 ||
          existing.value.payment_intent_id_hmac_sha256 !== next.payment_intent_id_hmac_sha256 ||
          existing.value.binding_evidence_sha256 !== next.binding_evidence_sha256) throw new Error('ARC_STRIPE_REVERSAL_RECHECK_CONFLICT');
      const existingIssuedAt = isoTimestamp(existing.value.issued_at, 'Stored Stripe reversal recheck issued_at');
      if (normalized.issuedAt < existingIssuedAt) throw new Error('ARC_STRIPE_REVERSAL_RECHECK_ROLLBACK');
      if (normalized.issuedAt === existingIssuedAt) {
        if (!exactStored(existing.value, next)) throw new Error('ARC_STRIPE_REVERSAL_RECHECK_CONFLICT');
        return { handoffId: normalized.value.handoff_id, idempotentReplay: true, recheck: existing.value };
      }
      try {
        const replaced = await replaceIndex(adapters.store, key, existing, next);
        return { handoffId: normalized.value.handoff_id, idempotentReplay: false, recheck: replaced.value };
      } catch (error) {
        if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 4) throw error;
        continue;
      }
    }
    try {
      await createIndex(adapters.store, key, next);
      return { handoffId: normalized.value.handoff_id, idempotentReplay: false, recheck: next };
    } catch (error) {
      if (error?.message !== 'ARC2_INDEX_CONFLICT' || attempt === 4) throw error;
    }
  }
  throw new Error('ARC_STRIPE_REVERSAL_RECHECK_CONTENTION');
}

function requireConfigured(env, purpose = 'full') {
  const configuration = stripeReversalConfiguration(env);
  const operational = purpose === 'webhook' ? configuration.webhookOperational :
    purpose === 'binding' ? configuration.bindingOperational :
      purpose === 'recheck' ? configuration.recheckOperational : configuration.enabled;
  if (!operational) throw new Error('ARC_STRIPE_REVERSAL_CONTROL_DISABLED');
  return configuration;
}

function normalizeBindingEvidence(raw, signature, env, now = new Date(), options = {}) {
  requireConfigured(env, 'binding');
  if (typeof raw !== 'string' || raw.length < 2 || raw.length > 20_000) throw new TypeError('Stripe reversal binding evidence is invalid.');
  const value = plainObject(JSON.parse(raw), 'Stripe reversal binding evidence');
  exactKeys(value, BINDING_FIELDS, 'Stripe reversal binding evidence');
  if (canonicalJson(value) !== raw || value.version !== STRIPE_REVERSAL_BINDING_SCHEMA ||
      value.scope !== STRIPE_REVERSAL_BINDING_SCOPE || !CHECKOUT_SESSION_ID.test(value.checkout_session_id) ||
      !PAYMENT_INTENT_ID.test(value.payment_intent_id) || !HANDOFF_ID.test(value.handoff_id) ||
      !HEX_64.test(value.stripe_account_id_sha256) ||
      !safeEqual(value.stripe_account_id_sha256, env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256)) {
    throw new TypeError('Stripe reversal binding evidence is invalid.');
  }
  const configuration = stripeReversalConfiguration(env);
  if (value.livemode !== configuration.expectedLivemode ||
      !value.checkout_session_id.startsWith(value.livemode ? 'cs_live_' : 'cs_test_')) {
    throw new TypeError('Stripe reversal binding mode is invalid.');
  }
  const issuedAt = isoTimestamp(value.issued_at, 'Stripe reversal binding issued_at');
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || issuedAt > nowMs + 60_000 ||
      (options.enforceFreshness !== false && issuedAt < nowMs - 10 * 60_000)) {
    throw new TypeError('Stripe reversal binding evidence is stale or from the future.');
  }
  if (!HEX_64.test(signature) || !safeEqual(signature, hmacHex(
    env.ARC_STRIPE_REVERSAL_BINDING_SECRET,
    `${STRIPE_REVERSAL_BINDING_PREFIX}${raw}`,
  ))) throw new TypeError('Stripe reversal binding signature mismatch.');
  return { canonical: raw, digest: sha256Hex(raw), value };
}

function bindingValues(normalized, checkoutIndex, env) {
  const checkoutSessionHmac = hmacHex(
    env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
    `checkout-session-v1\n${normalized.value.checkout_session_id}`,
  );
  const paymentIntentHmac = hmacHex(
    env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
    `payment-intent-v1\n${normalized.value.payment_intent_id}`,
  );
  const common = {
    schema: STRIPE_REVERSAL_BINDING_SCHEMA,
    handoff_id: normalized.value.handoff_id,
    checkout_session_id_hmac_sha256: checkoutSessionHmac,
    payment_intent_id_hmac_sha256: paymentIntentHmac,
    stripe_account_id_sha256: normalized.value.stripe_account_id_sha256,
    livemode: normalized.value.livemode,
    payment_evidence_sha256: checkoutIndex.payment_evidence_sha256,
    binding_evidence_sha256: normalized.digest,
  };
  return {
    handoff: common,
    paymentIntent: {
      ...common,
      schema: STRIPE_PAYMENT_INTENT_INDEX_SCHEMA,
    },
  };
}

async function reconcilePendingReversals(store, binding) {
  const markerKey = pendingPaymentKeyFromHmac(binding.payment_intent_id_hmac_sha256);
  const marker = await readIndex(store, markerKey);
  if (!marker) return false;
  if (!exactStored(marker, {
    schema: STRIPE_PENDING_PAYMENT_SCHEMA,
    payment_intent_id_hmac_sha256: binding.payment_intent_id_hmac_sha256,
    stripe_account_id_sha256: binding.stripe_account_id_sha256,
    livemode: binding.livemode,
    delivery_halted: true,
  })) throw new Error('ARC_STRIPE_PENDING_REVERSAL_CONFLICT');
  if (!store?.list) throw new Error('ARC_STRIPE_PENDING_REVERSAL_RECONCILIATION_REQUIRED');
  const prefix = `stripe-reversal-pending/${binding.payment_intent_id_hmac_sha256}/`;
  let count = 0;
  const pages = store.list({ prefix, paginate: true });
  if (!pages || typeof pages[Symbol.asyncIterator] !== 'function') throw new Error('ARC_STRIPE_PENDING_REVERSAL_RECONCILIATION_REQUIRED');
  for await (const page of pages) {
    if (!page || !Array.isArray(page.blobs)) throw new Error('ARC_STRIPE_PENDING_REVERSAL_RECONCILIATION_REQUIRED');
    for (const blob of page.blobs) {
      count += 1;
      if (count > 1_000) throw new Error('ARC_STRIPE_PENDING_REVERSAL_LIMIT');
      const eventHmac = String(blob?.key || '').match(new RegExp(`^${prefix}([a-f0-9]{64})$`))?.[1];
      const pending = eventHmac ? await readIndex(store, blob.key) : null;
      if (!pending || pending.event_id_hmac_sha256 !== eventHmac ||
          pending.payment_intent_id_hmac_sha256 !== binding.payment_intent_id_hmac_sha256 ||
          pending.stripe_account_id_sha256 !== binding.stripe_account_id_sha256 || pending.livemode !== binding.livemode ||
          !exactStored(await readIndex(store, `stripe-reversal-event/${eventHmac}`), pending)) {
        throw new Error('ARC_STRIPE_PENDING_REVERSAL_CONFLICT');
      }
      await applySummaryFacts(store, factsFromReservation(pending), binding);
    }
  }
  if (count < 1) throw new Error('ARC_STRIPE_PENDING_REVERSAL_RECONCILIATION_REQUIRED');
  return true;
}

export async function registerStripeReversalBinding(raw, signature, env, adapters = {}) {
  const clock = adapters.clock || (() => new Date());
  let normalized = normalizeBindingEvidence(raw, signature, env, clock(), { enforceFreshness: false });
  const handoffKey = handoffBindingKey(normalized.value.handoff_id);
  const paymentKey = paymentIntentIndexKey(normalized.value.payment_intent_id, env);
  const checkoutIndex = await readIndex(adapters.store, checkoutSessionIndexKey(normalized.value.checkout_session_id, env));
  if (!checkoutIndex || checkoutIndex.schema !== 'arc2-checkout-session-index-v1' ||
      checkoutIndex.handoff_id !== normalized.value.handoff_id || !HEX_64.test(checkoutIndex.payment_evidence_sha256)) {
    throw new Error('ARC_STRIPE_REVERSAL_CHECKOUT_BINDING_MISSING');
  }
  const handoff = await readEntry(adapters.store, `handoffs/${normalized.value.handoff_id}`);
  if (!handoff || validateExpectedBindings(handoff.record).payment_evidence_sha256 !== checkoutIndex.payment_evidence_sha256) {
    throw new Error('ARC_STRIPE_REVERSAL_HANDOFF_BINDING_MISMATCH');
  }
  const values = bindingValues(normalized, checkoutIndex, env);
  const existingHandoff = await readIndex(adapters.store, handoffKey);
  const existingPayment = await readIndex(adapters.store, paymentKey);
  // A brand-new binding must be fresh. If either exact immutable half already
  // exists, an old byte-identical attestation may resume the interrupted
  // two-key reservation. Re-signing would change binding_evidence_sha256 and is
  // deliberately rejected instead of silently rebinding a PaymentIntent.
  if (!existingHandoff && !existingPayment) {
    normalized = normalizeBindingEvidence(raw, signature, env, clock(), { enforceFreshness: true });
  } else {
    if (existingHandoff && !exactStored(existingHandoff, values.handoff)) throw new Error('ARC_STRIPE_REVERSAL_INDEX_CONFLICT');
    if (existingPayment && !exactStored(existingPayment, values.paymentIntent)) throw new Error('ARC_STRIPE_REVERSAL_INDEX_CONFLICT');
  }
  const paymentResult = await ensureImmutable(adapters.store, paymentKey, values.paymentIntent);
  const handoffResult = await ensureImmutable(adapters.store, handoffKey, values.handoff);
  await reconcilePendingReversals(adapters.store, values.handoff);
  return {
    binding: values.handoff,
    created: paymentResult.created || handoffResult.created,
    handoffId: normalized.value.handoff_id,
  };
}

function parseStripeSignature(header) {
  if (typeof header !== 'string' || header.length < 10 || header.length > 4096) throw new TypeError('Stripe signature header is invalid.');
  let timestamp = null;
  const signatures = [];
  for (const component of header.split(',')) {
    const separator = component.indexOf('=');
    if (separator < 1) throw new TypeError('Stripe signature header is invalid.');
    const name = component.slice(0, separator).trim();
    const value = component.slice(separator + 1).trim();
    if (name === 't') {
      if (timestamp !== null || !/^\d{10}$/.test(value)) throw new TypeError('Stripe signature timestamp is invalid.');
      timestamp = Number(value);
    } else if (name === 'v1') {
      if (!HEX_64.test(value)) throw new TypeError('Stripe signature is invalid.');
      signatures.push(value);
    }
  }
  if (!Number.isSafeInteger(timestamp) || signatures.length < 1 || signatures.length > 8) {
    throw new TypeError('Stripe signature header is invalid.');
  }
  return { signatures, timestamp };
}

export function verifyStripeWebhookSignature(raw, header, secret, now = new Date()) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > 1_048_576 || !validSecret(secret)) {
    throw new TypeError('Stripe webhook body or secret is invalid.');
  }
  const parsed = parseStripeSignature(header);
  const nowSeconds = Math.floor(new Date(now).getTime() / 1000);
  if (!Number.isSafeInteger(nowSeconds) || Math.abs(nowSeconds - parsed.timestamp) > STRIPE_SIGNATURE_TOLERANCE_SECONDS) {
    throw new TypeError('Stripe webhook signature timestamp is outside tolerance.');
  }
  const expected = createHmac('sha256', secret).update(`${parsed.timestamp}.${raw}`).digest();
  const matches = parsed.signatures.some((candidate) => {
    const supplied = Buffer.from(candidate, 'hex');
    return supplied.length === expected.length && timingSafeEqual(supplied, expected);
  });
  if (!matches) throw new TypeError('Stripe webhook signature mismatch.');
  return parsed.timestamp;
}

function stripeIdentifier(value, pattern, label) {
  if (typeof value !== 'string' || !pattern.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function paymentIntentId(value) {
  if (typeof value === 'string') return stripeIdentifier(value, PAYMENT_INTENT_ID, 'PaymentIntent id');
  if (value && typeof value === 'object' && !Array.isArray(value)) return stripeIdentifier(value.id, PAYMENT_INTENT_ID, 'PaymentIntent id');
  throw new TypeError('PaymentIntent id is invalid.');
}

function positiveAmount(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 100_000_000) throw new TypeError(`${label} is invalid.`);
  return value;
}

function normalizeReversalObject(eventType, value, env) {
  const object = plainObject(value, 'Stripe reversal object');
  const common = {
    currency: object.currency,
    paymentIntentId: paymentIntentId(object.payment_intent),
  };
  if (common.currency !== 'usd') throw new TypeError('Stripe reversal currency is invalid.');
  if (eventType.startsWith('refund.')) {
    if (object.object !== 'refund') throw new TypeError('Stripe refund object type is invalid.');
    stripeIdentifier(object.id, REFUND_ID, 'Stripe refund id');
    if (!REFUND_STATUSES.has(object.status) || (eventType === 'refund.failed' && object.status !== 'failed')) {
      throw new TypeError('Stripe refund status is invalid.');
    }
    return {
      ...common,
      amount: positiveAmount(object.amount, 'Stripe refund amount'),
      kind: 'refund',
      objectId: object.id,
      status: object.status,
    };
  }
  if (eventType === 'charge.refunded') {
    if (object.object !== 'charge' || object.refunded !== true) throw new TypeError('Stripe refunded charge is invalid.');
    stripeIdentifier(object.id, CHARGE_ID, 'Stripe charge id');
    return {
      ...common,
      amount: positiveAmount(object.amount_refunded, 'Stripe refunded amount'),
      kind: 'charge-refund',
      objectId: object.id,
      status: object.amount_refunded === object.amount ? 'fully_refunded' : 'partially_refunded',
    };
  }
  if (!eventType.startsWith('charge.dispute.') || object.object !== 'dispute') {
    throw new TypeError('Stripe dispute object type is invalid.');
  }
  stripeIdentifier(object.id, DISPUTE_ID, 'Stripe dispute id');
  if (!DISPUTE_STATUSES.has(object.status) ||
      (eventType === 'charge.dispute.closed' && !new Set(['lost', 'warning_closed', 'won', 'prevented']).has(object.status))) {
    throw new TypeError('Stripe dispute status is invalid.');
  }
  return {
    ...common,
    amount: positiveAmount(object.amount, 'Stripe dispute amount'),
    kind: 'dispute',
    objectId: object.id,
    status: object.status,
  };
}

export function normalizeStripeReversalEvent(raw, stripeSignature, env, now = new Date()) {
  const configuration = requireConfigured(env, 'webhook');
  verifyStripeWebhookSignature(raw, stripeSignature, env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET, now);
  const event = plainObject(JSON.parse(raw), 'Stripe event');
  if (!EVENT_TYPES.has(event.type) || event.object !== 'event' || event.api_version !== STRIPE_WEBHOOK_API_VERSION ||
      event.livemode !== configuration.expectedLivemode || !Number.isSafeInteger(event.created) || event.created < 1 ||
      !event.data || typeof event.data !== 'object' || Array.isArray(event.data)) {
    throw new TypeError('Stripe event is not allowlisted or is incorrectly bound.');
  }
  stripeIdentifier(event.id, EVENT_ID, 'Stripe event id');
  const reversal = normalizeReversalObject(event.type, event.data.object, env);
  const eventCreatedAt = new Date(event.created * 1000);
  if (!Number.isFinite(eventCreatedAt.getTime())) throw new TypeError('Stripe event timestamp is invalid.');
  return {
    amount: reversal.amount,
    canonical: raw,
    currency: reversal.currency,
    digest: sha256Hex(raw),
    eventCreatedAt: eventCreatedAt.toISOString(),
    eventId: event.id,
    eventType: event.type,
    kind: reversal.kind,
    livemode: event.livemode,
    objectId: reversal.objectId,
    paymentIntentId: reversal.paymentIntentId,
    status: reversal.status,
  };
}

function severityFor(event) {
  if (event.kind === 'charge-refund' || (event.kind === 'refund' && event.status === 'succeeded') ||
      (event.kind === 'dispute' && event.status === 'lost')) return 'FUNDS_REVERSED';
  if (event.kind === 'dispute' || (event.kind === 'refund' && ['pending', 'requires_action'].includes(event.status))) {
    return 'FUNDS_AT_RISK';
  }
  return 'REVIEW_REQUIRED';
}

const SEVERITY_RANK = Object.freeze({ REVIEW_REQUIRED: 1, FUNDS_AT_RISK: 2, FUNDS_REVERSED: 3 });
const REFUND_RANK = Object.freeze({ NONE: 0, ATTEMPT_RECORDED: 1, FUNDS_REVERSED: 2 });
const DISPUTE_RANK = Object.freeze({ NONE: 0, OPEN: 1, RESOLVED: 2 });

function maxState(left, right, ranks) {
  return ranks[right] > ranks[left] ? right : left;
}

function factsFromEvent(event, env) {
  const severity = severityFor(event);
  return {
    amount: event.amount,
    currency: event.currency,
    digest: event.digest,
    disputeState: event.kind !== 'dispute' ? 'NONE' :
      ['won', 'lost', 'warning_closed', 'prevented'].includes(event.status) ? 'RESOLVED' : 'OPEN',
    eventCreatedAt: event.eventCreatedAt,
    eventIdentityHmac: hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `stripe-event-v1\n${event.eventId}`),
    eventType: event.eventType,
    kind: event.kind,
    objectHmac: objectIdentityHmac(event.kind, event.objectId, env),
    paymentIntentHmac: hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `payment-intent-v1\n${event.paymentIntentId}`),
    refundState: event.kind === 'dispute' ? 'NONE' : severity === 'FUNDS_REVERSED' ? 'FUNDS_REVERSED' : 'ATTEMPT_RECORDED',
    severity,
    status: event.status,
  };
}

function factsFromReservation(value) {
  if (!value || value.schema !== STRIPE_REVERSAL_EVENT_SCHEMA || !HEX_64.test(value.event_id_hmac_sha256) ||
      !HEX_64.test(value.object_id_hmac_sha256) || !HEX_64.test(value.payment_intent_id_hmac_sha256) ||
      !HEX_64.test(value.event_sha256) || !EVENT_TYPES.has(value.event_type) || !['refund', 'charge-refund', 'dispute'].includes(value.kind) ||
      typeof value.event_status !== 'string' || isoTimestamp(value.event_created_at, 'Pending reversal event_created_at') < 0 ||
      !Number.isSafeInteger(value.amount_minor_units) || value.amount_minor_units < 1 || value.currency !== 'usd') {
    throw new Error('ARC_STRIPE_PENDING_REVERSAL_CONFLICT');
  }
  const eventLike = { kind: value.kind, status: value.event_status };
  const severity = severityFor(eventLike);
  return {
    amount: value.amount_minor_units, currency: value.currency, digest: value.event_sha256,
    disputeState: value.kind !== 'dispute' ? 'NONE' :
      ['won', 'lost', 'warning_closed', 'prevented'].includes(value.event_status) ? 'RESOLVED' : 'OPEN',
    eventCreatedAt: value.event_created_at, eventIdentityHmac: value.event_id_hmac_sha256,
    eventType: value.event_type, kind: value.kind, objectHmac: value.object_id_hmac_sha256,
    paymentIntentHmac: value.payment_intent_id_hmac_sha256,
    refundState: value.kind === 'dispute' ? 'NONE' : severity === 'FUNDS_REVERSED' ? 'FUNDS_REVERSED' : 'ATTEMPT_RECORDED',
    severity, status: value.event_status,
  };
}

function nextSummary(current, facts, binding) {
  const { eventIdentityHmac, objectHmac, paymentIntentHmac, severity, refundState, disputeState } = facts;
  const base = current || {
    schema: STRIPE_REVERSAL_SCHEMA,
    handoff_id: binding.handoff_id,
    checkout_session_id_hmac_sha256: binding.checkout_session_id_hmac_sha256,
    payment_intent_id_hmac_sha256: paymentIntentHmac,
    stripe_account_id_sha256: binding.stripe_account_id_sha256,
    livemode: binding.livemode,
    delivery_halted: true,
    automatic_refund_requested: false,
    manual_review_required: true,
    severity: 'REVIEW_REQUIRED',
    refund_state: 'NONE',
    dispute_state: 'NONE',
    refund_observed: false, dispute_observed: false,
    first_event_created_at: facts.eventCreatedAt,
    latest_event_created_at: facts.eventCreatedAt,
    latest_event_type: facts.eventType,
    latest_event_status: facts.status,
    latest_event_id_hmac_sha256: eventIdentityHmac,
    latest_event_sha256: facts.digest,
    latest_object_id_hmac_sha256: objectHmac,
    latest_amount_minor_units: facts.amount,
    currency: facts.currency,
  };
  if (base.schema !== STRIPE_REVERSAL_SCHEMA || base.handoff_id !== binding.handoff_id ||
      base.checkout_session_id_hmac_sha256 !== binding.checkout_session_id_hmac_sha256 ||
      base.payment_intent_id_hmac_sha256 !== paymentIntentHmac || base.stripe_account_id_sha256 !== binding.stripe_account_id_sha256 ||
      base.livemode !== binding.livemode || base.delivery_halted !== true || base.automatic_refund_requested !== false) {
    throw new Error('ARC_STRIPE_REVERSAL_STATE_CONFLICT');
  }
  const candidateOrder = `${facts.eventCreatedAt}\n${facts.digest}`;
  const currentOrder = `${base.latest_event_created_at}\n${base.latest_event_sha256}`;
  const newest = candidateOrder > currentOrder;
  return {
    ...base,
    manual_review_required: true,
    severity: maxState(base.severity, severity, SEVERITY_RANK),
    refund_state: maxState(base.refund_state, refundState, REFUND_RANK),
    dispute_state: maxState(base.dispute_state, disputeState, DISPUTE_RANK),
    refund_observed: base.refund_observed || facts.kind !== 'dispute',
    dispute_observed: base.dispute_observed || facts.kind === 'dispute',
    first_event_created_at: facts.eventCreatedAt < base.first_event_created_at ? facts.eventCreatedAt : base.first_event_created_at,
    ...(newest ? {
      latest_event_created_at: facts.eventCreatedAt,
      latest_event_type: facts.eventType,
      latest_event_status: facts.status,
      latest_event_id_hmac_sha256: eventIdentityHmac,
      latest_event_sha256: facts.digest,
      latest_object_id_hmac_sha256: objectHmac,
      latest_amount_minor_units: facts.amount,
      currency: facts.currency,
    } : {}),
  };
}

async function applySummaryFacts(store, facts, binding) {
  const key = reversalHandoffKey(binding.handoff_id);
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const entry = await readIndexEntry(store, key);
    const next = nextSummary(entry?.value || null, facts, binding);
    if (entry && exactStored(entry.value, next)) return entry.value;
    try {
      if (!entry) {
        await createIndex(store, key, next);
        return next;
      }
      return (await replaceIndex(store, key, entry, next)).value;
    } catch (error) {
      if (!['ARC2_INDEX_CONFLICT', 'ARC2_STATE_CONTENTION'].includes(error?.message) || attempt === 4) throw error;
    }
  }
  throw new Error('ARC_STRIPE_REVERSAL_STATE_CONTENTION');
}

async function applySummary(store, event, binding, env) {
  return applySummaryFacts(store, factsFromEvent(event, env), binding);
}

function reversalEventReservation(event, env) {
  const eventHmac = hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `stripe-event-v1\n${event.eventId}`);
  return {
    key: eventReservationKey(event.eventId, env),
    value: {
      schema: STRIPE_REVERSAL_EVENT_SCHEMA,
      handoff_id: null,
      checkout_session_id_hmac_sha256: null,
      payment_intent_id_hmac_sha256: hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `payment-intent-v1\n${event.paymentIntentId}`),
      event_id_hmac_sha256: eventHmac,
      object_id_hmac_sha256: objectIdentityHmac(event.kind, event.objectId, env),
      event_sha256: event.digest,
      event_type: event.eventType,
      event_status: event.status,
      kind: event.kind,
      event_created_at: event.eventCreatedAt,
      amount_minor_units: event.amount,
      currency: event.currency,
      livemode: event.livemode,
      stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    },
  };
}

function reversalAlert(event, binding, env) {
  const eventHmac = hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `stripe-event-v1\n${event.eventId}`);
  return {
    key: `alerts/stripe-reversal/${eventHmac}`,
    value: {
      schema: STRIPE_REVERSAL_ALERT_SCHEMA,
      status: 'OPEN',
      category: 'stripe-reversal',
      // Event-local severity keeps this create-only alert immutable even after
      // later events raise the aggregate handoff severity.
      severity: severityFor(event) === 'FUNDS_REVERSED' ? 'critical' : 'high',
      handoff_id: binding.handoff_id,
      subject_hmac_sha256: eventHmac,
      detected_at: event.eventCreatedAt,
      delivery_status: 'PENDING',
      contains_customer_data: false,
    },
  };
}

function unboundReversalAlert(event, env) {
  const eventHmac = hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `stripe-event-v1\n${event.eventId}`);
  return {
    key: `alerts/stripe-reversal-unbound/${eventHmac}`,
    value: {
      schema: STRIPE_REVERSAL_ALERT_SCHEMA,
      status: 'OPEN',
      category: 'stripe-reversal-unbound',
      severity: 'critical',
      handoff_id: null,
      subject_hmac_sha256: eventHmac,
      detected_at: event.eventCreatedAt,
      delivery_status: 'PENDING',
      contains_customer_data: false,
    },
  };
}

export async function processStripeReversalEvent(raw, stripeSignature, env, adapters = {}) {
  const clock = adapters.clock || (() => new Date());
  const event = normalizeStripeReversalEvent(raw, stripeSignature, env, clock());
  const paymentKey = paymentIntentIndexKey(event.paymentIntentId, env);
  const reservation = reversalEventReservation(event, env);
  // A verified reversal must become a durable PaymentIntent-level halt before
  // either half of the two-key binding is trusted. This covers delivery during
  // a binding crash: recovery can reconcile it, but fulfillment can never pass
  // through the partial window.
  const paymentIntentHmac = reservation.value.payment_intent_id_hmac_sha256;
  await ensureImmutable(adapters.store, pendingPaymentKeyFromHmac(paymentIntentHmac), {
    schema: STRIPE_PENDING_PAYMENT_SCHEMA,
    payment_intent_id_hmac_sha256: paymentIntentHmac,
    stripe_account_id_sha256: reservation.value.stripe_account_id_sha256,
    livemode: reservation.value.livemode,
    delivery_halted: true,
  });
  const reserved = await ensureImmutable(adapters.store, reservation.key, reservation.value);
  await ensureImmutable(adapters.store, pendingEventKey(paymentIntentHmac, reservation.value.event_id_hmac_sha256), reservation.value);
  const binding = await readIndex(adapters.store, paymentKey);
  if (!binding || binding.schema !== STRIPE_PAYMENT_INTENT_INDEX_SCHEMA ||
      binding.payment_intent_id_hmac_sha256 !== hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `payment-intent-v1\n${event.paymentIntentId}`) ||
      binding.stripe_account_id_sha256 !== env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 || binding.livemode !== event.livemode) {
    if (adapters.alertStore) {
      const alert = unboundReversalAlert(event, env);
      await ensureImmutable(adapters.alertStore, alert.key, alert.value);
    }
    throw new Error('ARC_STRIPE_REVERSAL_PAYMENT_INTENT_UNBOUND');
  }
  const handoffBinding = await readIndex(adapters.store, handoffBindingKey(binding.handoff_id));
  if (!exactStored(handoffBinding, {
    schema: STRIPE_REVERSAL_BINDING_SCHEMA,
    handoff_id: binding.handoff_id,
    checkout_session_id_hmac_sha256: binding.checkout_session_id_hmac_sha256,
    payment_intent_id_hmac_sha256: binding.payment_intent_id_hmac_sha256,
    stripe_account_id_sha256: binding.stripe_account_id_sha256,
    livemode: binding.livemode,
    payment_evidence_sha256: binding.payment_evidence_sha256,
    binding_evidence_sha256: binding.binding_evidence_sha256,
  })) {
    if (adapters.alertStore) {
      const alert = unboundReversalAlert(event, env);
      await ensureImmutable(adapters.alertStore, alert.key, alert.value);
    }
    throw new Error('ARC_STRIPE_REVERSAL_BINDING_CONFLICT');
  }
  const handoff = await readEntry(adapters.store, `handoffs/${binding.handoff_id}`);
  if (!handoff || handoff.record.payment_evidence_sha256 !== binding.payment_evidence_sha256) {
    throw new Error('ARC_STRIPE_REVERSAL_HANDOFF_BINDING_MISMATCH');
  }
  await reconcilePendingReversals(adapters.store, binding);
  const summary = await applySummary(adapters.store, event, binding, env);
  if (adapters.alertStore) {
    const alert = reversalAlert(event, binding, env);
    await ensureImmutable(adapters.alertStore, alert.key, alert.value);
  }
  return {
    handoffId: binding.handoff_id,
    idempotentReplay: !reserved.created,
    summary,
  };
}

export async function assertHandoffFulfillmentAllowed(store, handoffId, env, options = {}) {
  if (!HANDOFF_ID.test(handoffId)) throw new TypeError('Handoff id is invalid.');
  const configuration = stripeReversalConfiguration(env);
  if (!configuration.required) return;
  if (!configuration.enabled) throw new Error('ARC_STRIPE_REVERSAL_CONTROL_DISABLED');
  const binding = await readIndex(store, handoffBindingKey(handoffId));
  if (!binding || binding.schema !== STRIPE_REVERSAL_BINDING_SCHEMA || binding.handoff_id !== handoffId ||
      binding.stripe_account_id_sha256 !== env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 ||
      binding.livemode !== configuration.expectedLivemode) {
    throw new Error('ARC_STRIPE_REVERSAL_BINDING_REQUIRED');
  }
  if (options.checkoutSessionId) {
    if (!CHECKOUT_SESSION_ID.test(options.checkoutSessionId) || binding.checkout_session_id_hmac_sha256 !== hmacHex(
      env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
      `checkout-session-v1\n${options.checkoutSessionId}`,
    )) throw new Error('ARC_STRIPE_REVERSAL_CHECKOUT_BINDING_MISMATCH');
  }
  const state = await readIndex(store, reversalHandoffKey(handoffId));
  if (await readIndex(store, pendingPaymentKeyFromHmac(binding.payment_intent_id_hmac_sha256))) {
    throw new Error('ARC_STRIPE_REVERSAL_HALT');
  }
  if (state) {
    if (state.schema !== STRIPE_REVERSAL_SCHEMA || state.handoff_id !== handoffId || state.delivery_halted !== true ||
        state.automatic_refund_requested !== false || state.payment_intent_id_hmac_sha256 !== binding.payment_intent_id_hmac_sha256 ||
        state.checkout_session_id_hmac_sha256 !== binding.checkout_session_id_hmac_sha256) {
      throw new Error('ARC_STRIPE_REVERSAL_STATE_CONFLICT');
    }
    throw new Error('ARC_STRIPE_REVERSAL_HALT');
  }
  const recheck = await readIndex(store, recheckKey(handoffId));
  const now = new Date(options.now || new Date());
  const recheckIssuedAt = recheck?.issued_at ? Date.parse(recheck.issued_at) : NaN;
  const maxRecheckAgeMs = options.maxRecheckAgeMs ?? STRIPE_REVERSAL_RECHECK_MAX_AGE_MS;
  const recheckNotBeforeMs = options.recheckNotBefore === undefined ? null : Date.parse(options.recheckNotBefore);
  if (!Number.isSafeInteger(maxRecheckAgeMs) || maxRecheckAgeMs < 0 ||
      maxRecheckAgeMs > STRIPE_REVERSAL_RECHECK_MAX_AGE_MS ||
      (recheckNotBeforeMs !== null && !Number.isFinite(recheckNotBeforeMs))) {
    throw new TypeError('Stripe reversal recheck guard options are invalid.');
  }
  if (!recheck || recheck.schema !== STRIPE_REVERSAL_RECHECK_SCHEMA || recheck.handoff_id !== handoffId ||
      recheck.checkout_session_id_hmac_sha256 !== binding.checkout_session_id_hmac_sha256 ||
      recheck.payment_intent_id_hmac_sha256 !== binding.payment_intent_id_hmac_sha256 ||
      recheck.stripe_account_id_sha256 !== binding.stripe_account_id_sha256 || recheck.livemode !== binding.livemode ||
      recheck.payment_intent_status !== 'succeeded' || recheck.refunded_amount_minor_units !== 0 || recheck.dispute_status !== 'none' ||
      !Number.isFinite(now.getTime()) || !Number.isFinite(recheckIssuedAt) || recheckIssuedAt > now.getTime() + 30_000 ||
      recheckIssuedAt < now.getTime() - maxRecheckAgeMs ||
      (recheckNotBeforeMs !== null && recheckIssuedAt < recheckNotBeforeMs)) {
    throw new Error('ARC_STRIPE_REVERSAL_RECHECK_REQUIRED');
  }
}

export const stripeReversalKeys = Object.freeze({
  checkoutSessionIndexKey,
  eventReservationKey,
  handoffBindingKey,
  paymentIntentIndexKey,
  pendingEventKey,
  pendingPaymentKeyFromHmac,
  recheckKey,
  reversalHandoffKey,
});
