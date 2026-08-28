import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  canonicalJson,
  createInitialRecord,
  hmacHex,
  sha256Hex,
} from '../netlify/lib/arc2-handoff-core.mjs';
import { createEntry, createIndex, readIndex } from '../netlify/lib/arc2-handoff-store.mjs';
import {
  STRIPE_REVERSAL_BINDING_PREFIX,
  STRIPE_REVERSAL_BINDING_SCHEMA,
  STRIPE_REVERSAL_BINDING_SCOPE,
  STRIPE_REVERSAL_RECHECK_PREFIX,
  STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS,
  STRIPE_REVERSAL_RECHECK_SCHEMA,
  STRIPE_REVERSAL_RECHECK_SCOPE,
  STRIPE_WEBHOOK_API_VERSION,
  assertHandoffFulfillmentAllowed,
  normalizeStripeReversalEvent,
  processStripeReversalEvent as processStripeReversalEventCore,
  registerStripeReversalBinding,
  registerStripeReversalRecheck,
  stripeReversalConfiguration,
  stripeReversalKeys,
  verifyStripeWebhookSignature,
} from '../netlify/lib/stripe-reversal-core.mjs';
import bindingHandler, { config as bindingConfig } from '../netlify/functions/stripe-reversal-binding.mjs';
import recheckHandler, { config as recheckConfig } from '../netlify/functions/stripe-reversal-recheck.mjs';
import webhookHandler, { config as webhookConfig } from '../netlify/functions/stripe-reversal-webhook.mjs';

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; this.failKeyOnce = null; }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    if (this.failKeyOnce === key) {
      this.failKeyOnce = null;
      throw new Error('simulated_partial_binding_crash');
    }
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `e-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
  list({ prefix = '', paginate = false } = {}) {
    assert.equal(paginate, true);
    const blobs = [...this.values.keys()].filter((key) => key.startsWith(prefix)).sort().map((key) => ({ key }));
    return (async function* () { yield { blobs }; }());
  }
}

function cloneFakeStore(source) {
  const copy = new FakeStore();
  copy.sequence = source.sequence;
  copy.values = new Map([...source.values].map(([key, value]) => [key, structuredClone(value)]));
  return copy;
}

const now = new Date('2026-08-13T12:00:00.000Z');
const handoffId = 'a'.repeat(64);
const checkoutSessionId = 'cs_test_arc_reversal_contract';
const paymentIntentId = 'pi_arcReversalContract123';
const stripeAccountId = 'acct_ArcReversalContract123';
const accountHash = sha256Hex(stripeAccountId);
const env = {
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'true',
  ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_BINDING_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_RECHECK_ENABLED: 'true',
  ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
  ARC_STRIPE_WEBHOOK_API_VERSION: STRIPE_WEBHOOK_API_VERSION,
  ARC_STRIPE_WEBHOOK_SIGNING_SECRET: 'wh' + 'sec_webhook-secret-unique-0123456789abcdef',
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: 'rk_' + 'test_arcReversalRestrictedAccountRead0123456789',
  ARC_STRIPE_REVERSAL_HMAC_SECRET: 'reversal-hmac-secret-unique-0123456789abcdef',
  ARC_STRIPE_REVERSAL_BINDING_SECRET: 'binding-evidence-secret-unique-0123456789abcdef',
  ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET: 'binding-endpoint-secret-unique-0123456789abcdef',
  ARC_STRIPE_REVERSAL_RECHECK_SECRET: 'recheck-evidence-secret-unique-0123456789abcdef',
  ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET: 'recheck-endpoint-secret-unique-0123456789abcdef',
  ARC_HANDOFF_STATE_SECRET: 'handoff-state-secret-unique-0123456789abcdef',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'reversal-retention-fence-secret-unique-0123456789abcdef',
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256: accountHash,
  NETLIFY_TEAM_ACCOUNT_ID: 'team-account-123',
};
const stripeEventFixtures = new Map();
const accountFetch = async (url, options = {}) => {
  const target = String(url);
  assert.equal(options.headers.Authorization, `Bearer ${env.ARC_STRIPE_ACCOUNT_VERIFICATION_KEY}`);
  if (target === 'https://api.stripe.com/v1/account') return new Response(JSON.stringify({ id: stripeAccountId, object: 'account' }), {
    status: 200, headers: { 'content-type': 'application/json' },
  });
  const match = target.match(/^https:\/\/api\.stripe\.com\/v1\/events\/(evt_[A-Za-z0-9_]+)$/);
  const event = match ? stripeEventFixtures.get(match[1]) : null;
  return new Response(JSON.stringify(event || { error: { type: 'invalid_request_error' } }), {
    status: event ? 200 : 404, headers: { 'content-type': 'application/json' },
  });
};
const processStripeReversalEvent = (raw, stripeSignature, environment, adapters = {}) => {
  const event = JSON.parse(raw);
  stripeEventFixtures.set(event.id, event);
  return processStripeReversalEventCore(raw, stripeSignature, environment, { ...adapters, accountFetch });
};
assert.equal(stripeReversalConfiguration(env).enabled, true);
assert.equal(stripeReversalConfiguration({}).enabled, false);
const pausedRecheckEnv = { ...env, ARC_STRIPE_REVERSAL_RECHECK_ENABLED: 'false' };
assert.equal(stripeReversalConfiguration(pausedRecheckEnv).enabled, false);
assert.equal(stripeReversalConfiguration(pausedRecheckEnv).webhookOperational, true,
  'Webhook ingestion must stay operational when a producer-side recheck is paused.');
assert.equal(stripeReversalConfiguration({ ...env, ARC_HANDOFF_TRIGGER_SECRET: env.ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET }).enabled, false,
  'Stripe endpoint credentials must not reuse existing handoff authorization secrets.');

const normalizedFixture = {
  payment: {
    digest: '1'.repeat(64),
    value: {
      checkout_session_id: checkoutSessionId,
      claim_recipient_email_sha256: '2'.repeat(64),
      bundle_fingerprint: '3'.repeat(64),
    },
  },
  artifact: {
    digest: '4'.repeat(64),
    artifacts: [
      { path: '_headers', sha256: '5'.repeat(64), size: 10 },
      { path: 'about/index.html', sha256: '6'.repeat(64), size: 20 },
      { path: 'contact/index.html', sha256: '7'.repeat(64), size: 20 },
      { path: 'process/index.html', sha256: '8'.repeat(64), size: 20 },
      { path: 'services/index.html', sha256: '9'.repeat(64), size: 20 },
      { path: 'index.html', sha256: 'a'.repeat(64), size: 20 },
    ],
    value: {
      artifact_manifest_sha256: '7'.repeat(64),
      bundle_fingerprint: '3'.repeat(64),
      lead_route_mode: 'netlify_form',
      preview_folder: 'sample-roofing-a1b2c3d4',
      production_content_sha256: '8'.repeat(64),
    },
  },
  leadEmail: 'lead@example.test',
  leadEmailHash: sha256Hex('lead@example.test'),
  leadRouteRecipientHmacSha256: '9'.repeat(64),
  formName: 'sample-lead',
};
const record = createInitialRecord(normalizedFixture, env, `handoffs/${handoffId}`, now, {
  uuid: () => '11111111-1111-4111-8111-111111111111',
}).record;
const store = new FakeStore();
const alertStore = new FakeStore();
await createEntry(store, `handoffs/${handoffId}`, record);
await createIndex(store, stripeReversalKeys.checkoutSessionIndexKey(checkoutSessionId, env), {
  schema: 'arc2-checkout-session-index-v1',
  handoff_id: handoffId,
  payment_evidence_sha256: record.payment_evidence_sha256,
  artifact_evidence_sha256: record.artifact_evidence_sha256,
  bundle_fingerprint: record.bundle_fingerprint,
});

await assert.rejects(assertHandoffFulfillmentAllowed(store, handoffId, env, { checkoutSessionId }), /BINDING_REQUIRED/,
  'Required control must stop before any provider write when the PaymentIntent binding is absent.');

const bindingValue = {
  version: STRIPE_REVERSAL_BINDING_SCHEMA,
  scope: STRIPE_REVERSAL_BINDING_SCOPE,
  issued_at: now.toISOString(),
  checkout_session_id: checkoutSessionId,
  payment_intent_id: paymentIntentId,
  handoff_id: handoffId,
  stripe_account_id_sha256: accountHash,
  livemode: false,
};
const bindingEvidence = canonicalJson(bindingValue);
const bindingSignature = hmacHex(env.ARC_STRIPE_REVERSAL_BINDING_SECRET, `${STRIPE_REVERSAL_BINDING_PREFIX}${bindingEvidence}`);
const binding = await registerStripeReversalBinding(bindingEvidence, bindingSignature, env, { store, clock: () => new Date(now) });
assert.equal(binding.created, true);
assert.equal((await registerStripeReversalBinding(bindingEvidence, bindingSignature, env, {
  store, clock: () => new Date(now.getTime() + 24 * 60 * 60_000),
})).created, false, 'An exact durable binding must be resumable after its initial freshness window.');
const partialStore = new FakeStore();
await createEntry(partialStore, `handoffs/${handoffId}`, record);
await createIndex(partialStore, stripeReversalKeys.checkoutSessionIndexKey(checkoutSessionId, env), {
  schema: 'arc2-checkout-session-index-v1', handoff_id: handoffId,
  payment_evidence_sha256: record.payment_evidence_sha256,
  artifact_evidence_sha256: record.artifact_evidence_sha256,
  bundle_fingerprint: record.bundle_fingerprint,
});
partialStore.failKeyOnce = stripeReversalKeys.handoffBindingKey(handoffId);
await assert.rejects(registerStripeReversalBinding(bindingEvidence, bindingSignature, env, {
  store: partialStore, clock: () => new Date(now),
}), /simulated_partial_binding_crash/);
assert.ok(await readIndex(partialStore, stripeReversalKeys.paymentIntentIndexKey(paymentIntentId, env)),
  'The simulated crash occurs after the immutable PaymentIntent half is reserved.');
assert.equal(await readIndex(partialStore, stripeReversalKeys.handoffBindingKey(handoffId)), null);
await assert.rejects(assertHandoffFulfillmentAllowed(store, handoffId, env, { checkoutSessionId, now }), /RECHECK_REQUIRED/);
const recheckValue = {
  version: STRIPE_REVERSAL_RECHECK_SCHEMA,
  scope: STRIPE_REVERSAL_RECHECK_SCOPE,
  handoff_id: handoffId,
  checkout_session_id: checkoutSessionId,
  payment_intent_id: paymentIntentId,
  stripe_account_id_sha256: accountHash,
  livemode: false,
  payment_intent_status: 'succeeded',
  refunded_amount_minor_units: 0,
  dispute_status: 'none',
  issued_at: now.toISOString(),
};
const recheckEvidence = canonicalJson(recheckValue);
const recheckSignature = hmacHex(env.ARC_STRIPE_REVERSAL_RECHECK_SECRET, `${STRIPE_REVERSAL_RECHECK_PREFIX}${recheckEvidence}`);
assert.equal((await registerStripeReversalRecheck(recheckEvidence, recheckSignature, env, {
  store, clock: () => new Date(now),
})).idempotentReplay, false);
assert.equal((await registerStripeReversalRecheck(recheckEvidence, recheckSignature, env, {
  store, clock: () => new Date(now),
})).idempotentReplay, true);
await assert.rejects(registerStripeReversalRecheck(recheckEvidence, recheckSignature, env, {
  store, clock: () => new Date(now.getTime() + 5 * 60_000 + 1),
}), /stale/, 'A stale exact recheck cannot be replayed as current authority.');
const nextRecheckValue = { ...recheckValue, issued_at: new Date(now.getTime() + 60_000).toISOString() };
const nextRecheckEvidence = canonicalJson(nextRecheckValue);
const nextRecheckSignature = hmacHex(env.ARC_STRIPE_REVERSAL_RECHECK_SECRET, `${STRIPE_REVERSAL_RECHECK_PREFIX}${nextRecheckEvidence}`);
assert.equal((await registerStripeReversalRecheck(nextRecheckEvidence, nextRecheckSignature, env, {
  store, clock: () => new Date(now.getTime() + 60_000),
})).idempotentReplay, false);
await assert.rejects(registerStripeReversalRecheck(recheckEvidence, recheckSignature, env, {
  store, clock: () => new Date(now.getTime() + 60_000),
}), /ROLLBACK/, 'An older still-fresh attestation cannot replace a newer recheck.');
await assert.doesNotReject(assertHandoffFulfillmentAllowed(store, handoffId, env, {
  checkoutSessionId, now: new Date(now.getTime() + 60_000),
}));
await assert.doesNotReject(assertHandoffFulfillmentAllowed(store, handoffId, env, {
  checkoutSessionId,
  maxRecheckAgeMs: STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS,
  now: new Date(now.getTime() + 60_000),
  recheckNotBefore: nextRecheckValue.issued_at,
}));
await assert.rejects(assertHandoffFulfillmentAllowed(store, handoffId, env, {
  checkoutSessionId,
  maxRecheckAgeMs: STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS,
  now: new Date(now.getTime() + 60_000),
  recheckNotBefore: new Date(now.getTime() + 60_001).toISOString(),
}), /RECHECK_REQUIRED/, 'Final-email authority must use a Stripe observation made after final-deploy readiness.');
await assert.doesNotReject(assertHandoffFulfillmentAllowed(store, handoffId, env, {
  checkoutSessionId, now: new Date(now.getTime() + 2 * 60_000 + 1),
}), 'The ordinary provider-stage guard retains its five-minute freshness window.');
await assert.rejects(assertHandoffFulfillmentAllowed(store, handoffId, env, {
  checkoutSessionId,
  maxRecheckAgeMs: STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS,
  now: new Date(now.getTime() + 2 * 60_000 + 1),
}), /RECHECK_REQUIRED/, 'Final-email send authority must reject a no-reversal check more than one minute old.');
await assert.rejects(assertHandoffFulfillmentAllowed(store, handoffId, env, {
  checkoutSessionId, maxRecheckAgeMs: 5 * 60_000 + 1, now,
}), /guard options are invalid/, 'A caller cannot widen the global five-minute freshness ceiling.');
await assert.rejects(assertHandoffFulfillmentAllowed(store, handoffId, env, {
  checkoutSessionId, now: new Date(now.getTime() + 6 * 60_000 + 1),
}), /RECHECK_REQUIRED/, 'An authoritative recheck must expire after five minutes.');
await assert.rejects(assertHandoffFulfillmentAllowed(store, handoffId, env, { checkoutSessionId: 'cs_test_other', now }), /CHECKOUT_BINDING_MISMATCH/);

function eventSignature(raw, timestamp = Math.floor(now.getTime() / 1000), secret = env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET) {
  const signature = createHmac('sha256', secret).update(`${timestamp}.${raw}`).digest('hex');
  return `t=${timestamp},v1=${signature}`;
}

function stripeEvent(overrides = {}, objectOverrides = {}) {
  return {
    id: 'evt_refundArcContract1',
    object: 'event',
    api_version: STRIPE_WEBHOOK_API_VERSION,
    created: Math.floor(now.getTime() / 1000) - 30,
    livemode: false,
    type: 'refund.created',
    data: { object: {
      id: 're_arcRefundContract1',
      object: 'refund',
      amount: 500000,
      currency: 'usd',
      payment_intent: paymentIntentId,
      status: 'succeeded',
      ...objectOverrides,
    } },
    ...overrides,
  };
}

const eventRaw = JSON.stringify(stripeEvent());
assert.equal(verifyStripeWebhookSignature(eventRaw, eventSignature(eventRaw), env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET, now), Math.floor(now.getTime() / 1000));
const wrongEventAccountRaw = JSON.stringify(stripeEvent({ account: 'acct_WrongReversalAccount123' }));
assert.throws(() => normalizeStripeReversalEvent(
  wrongEventAccountRaw, eventSignature(wrongEventAccountRaw), env, now,
), /event account is invalid/i);
assert.throws(() => verifyStripeWebhookSignature(eventRaw, eventSignature(eventRaw, Math.floor(now.getTime() / 1000) - 301),
  env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET, now), /outside tolerance/);
assert.throws(() => verifyStripeWebhookSignature(eventRaw, eventSignature(eventRaw, Math.floor(now.getTime() / 1000), 'wrong-secret-but-long-enough-0123456789'),
  env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET, now), /mismatch/);
assert.equal(normalizeStripeReversalEvent(eventRaw, eventSignature(eventRaw), env, now).eventType, 'refund.created');

const paymentIntentHmac = hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `payment-intent-v1\n${paymentIntentId}`);
const haltFirstRaw = JSON.stringify(stripeEvent({ id: 'evt_haltFirstCrashArc1' }));
const haltFirstStore = cloneFakeStore(store);
haltFirstStore.failKeyOnce = stripeReversalKeys.eventReservationKey('evt_haltFirstCrashArc1', env);
await assert.rejects(processStripeReversalEvent(haltFirstRaw, eventSignature(haltFirstRaw), env, {
  store: haltFirstStore, clock: () => new Date(now),
}), /simulated_partial_binding_crash/);
assert.ok(await readIndex(haltFirstStore, stripeReversalKeys.pendingPaymentKeyFromHmac(paymentIntentHmac)),
  'A verified reversal must persist its PaymentIntent halt before its global event reservation.');
await assert.rejects(assertHandoffFulfillmentAllowed(haltFirstStore, handoffId, env, { checkoutSessionId, now }), /REVERSAL_HALT/,
  'A crash immediately after the first reversal write must still halt fulfillment.');

const eventThenCrashId = 'evt_pendingEventCrashArc1';
const eventThenCrashRaw = JSON.stringify(stripeEvent({ id: eventThenCrashId }));
const eventThenCrashHmac = hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `stripe-event-v1\n${eventThenCrashId}`);
const eventThenCrashStore = cloneFakeStore(store);
eventThenCrashStore.failKeyOnce = stripeReversalKeys.pendingEventKey(paymentIntentHmac, eventThenCrashHmac);
await assert.rejects(processStripeReversalEvent(eventThenCrashRaw, eventSignature(eventThenCrashRaw), env, {
  store: eventThenCrashStore, clock: () => new Date(now),
}), /simulated_partial_binding_crash/);
assert.ok(await readIndex(eventThenCrashStore, stripeReversalKeys.pendingPaymentKeyFromHmac(paymentIntentHmac)));
assert.ok(await readIndex(eventThenCrashStore, stripeReversalKeys.eventReservationKey(eventThenCrashId, env)),
  'The global event reservation must remain recoverable after a pending-event crash.');
await assert.rejects(assertHandoffFulfillmentAllowed(eventThenCrashStore, handoffId, env, { checkoutSessionId, now }), /REVERSAL_HALT/,
  'A crash after the global event reservation must still halt fulfillment.');

const partialEventRaw = JSON.stringify(stripeEvent({ id: 'evt_partialBindingArc1' }));
const partialAlertStore = new FakeStore();
await assert.rejects(processStripeReversalEvent(partialEventRaw, eventSignature(partialEventRaw), env, {
  store: partialStore, alertStore: partialAlertStore, clock: () => new Date(now),
}), /BINDING_CONFLICT/,
'A verified reversal during a two-key binding crash may report conflict only after durably reserving its PaymentIntent halt.');
assert.ok(await readIndex(partialStore, stripeReversalKeys.pendingPaymentKeyFromHmac(hmacHex(
  env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
  `payment-intent-v1\n${paymentIntentId}`,
))));
assert.equal([...partialAlertStore.values.keys()].filter((key) => key.startsWith('alerts/stripe-reversal-unbound/')).length, 1);
assert.equal((await registerStripeReversalBinding(bindingEvidence, bindingSignature, env, {
  store: partialStore, clock: () => new Date(now.getTime() + 24 * 60 * 60_000),
})).created, true, 'A byte-identical stale replay must complete the partial binding and reconcile its reserved reversal.');
await assert.rejects(assertHandoffFulfillmentAllowed(partialStore, handoffId, env, { checkoutSessionId, now }), /REVERSAL_HALT/,
'Binding recovery must reconcile a reversal received in the partial-binding window into a permanent handoff halt.');

const highEventRaw = JSON.stringify(stripeEvent({
  id: 'evt_refundFailedArcContract1', type: 'refund.failed', created: Math.floor(now.getTime() / 1000) - 45,
}, {
  id: 're_arcRefundFailedContract1', status: 'failed',
}));
const highFirst = await processStripeReversalEvent(highEventRaw, eventSignature(highEventRaw), env, {
  store, alertStore, clock: () => new Date(now),
});
assert.equal(highFirst.summary.severity, 'REVIEW_REQUIRED');

const processed = await processStripeReversalEvent(eventRaw, eventSignature(eventRaw), env, {
  store, alertStore, clock: () => new Date(now),
});
assert.equal(processed.idempotentReplay, false);
assert.equal(processed.summary.delivery_halted, true);
assert.equal(processed.summary.automatic_refund_requested, false);
assert.equal(processed.summary.severity, 'FUNDS_REVERSED');
assert.equal(processed.summary.refund_state, 'FUNDS_REVERSED');
const highReplayAfterEscalation = await processStripeReversalEvent(highEventRaw, eventSignature(highEventRaw), env, {
  store, alertStore, clock: () => new Date(now),
});
assert.equal(highReplayAfterEscalation.idempotentReplay, true,
  'Replaying an earlier high event after a critical escalation must not mutate or conflict with its alert.');
assert.ok([...alertStore.values.values()].some(({ data }) => data.category === 'stripe-reversal' &&
  data.detected_at === new Date((Math.floor(now.getTime() / 1000) - 45) * 1000).toISOString() && data.severity === 'high'));
await assert.rejects(assertHandoffFulfillmentAllowed(store, handoffId, env, { checkoutSessionId, now }), /REVERSAL_HALT/);
await assert.rejects(registerStripeReversalRecheck(nextRecheckEvidence, nextRecheckSignature, env, {
  store, clock: () => new Date(now.getTime() + 60_000),
}), /REVERSAL_HALT/, 'A no-reversal attestation can never overwrite a durable reversal halt.');
const replay = await processStripeReversalEvent(eventRaw, eventSignature(eventRaw), env, {
  store, alertStore, clock: () => new Date(now),
});
assert.equal(replay.idempotentReplay, true);
assert.deepEqual(replay.summary, processed.summary);

const disputeRaw = JSON.stringify(stripeEvent({
  id: 'evt_disputeArcContract1', type: 'charge.dispute.closed', created: Math.floor(now.getTime() / 1000) - 15,
}, {
  id: 'dp_arcDisputeContract1', object: 'dispute', amount: 500000, status: 'won',
}));
const dispute = await processStripeReversalEvent(disputeRaw, eventSignature(disputeRaw), env, {
  store, alertStore, clock: () => new Date(now),
});
assert.equal(dispute.summary.dispute_state, 'RESOLVED');
assert.equal(dispute.summary.severity, 'FUNDS_REVERSED', 'Later favorable events must never lower or clear the fail-closed halt.');
assert.equal(dispute.summary.delivery_halted, true);

const storedSerialization = JSON.stringify([...store.values.entries()]);
assert.equal(storedSerialization.includes(paymentIntentId), false, 'Raw PaymentIntent ids must not enter durable storage.');
assert.equal(storedSerialization.includes('evt_refundArcContract1'), false, 'Raw Stripe event ids must not enter durable storage.');
assert.equal(storedSerialization.includes('re_arcRefundContract1'), false, 'Raw reversal object ids must not enter durable storage.');
assert.equal([...store.values.keys()].filter((key) => key.startsWith('stripe-reversal-event/')).length, 3);
assert.equal([...alertStore.values.keys()].filter((key) => key.startsWith('alerts/stripe-reversal/')).length, 3);

const changedReplayRaw = JSON.stringify(stripeEvent({}, { amount: 499999 }));
await assert.rejects(processStripeReversalEvent(changedReplayRaw, eventSignature(changedReplayRaw), env, {
  store, alertStore, clock: () => new Date(now),
}), /INDEX_CONFLICT/, 'The same global Stripe event id cannot be rebound to different bytes.');
const unknownRaw = JSON.stringify(stripeEvent({ type: 'payment_intent.succeeded' }));
assert.throws(() => normalizeStripeReversalEvent(unknownRaw, eventSignature(unknownRaw), env, now), /not allowlisted/);
const unboundRaw = JSON.stringify(stripeEvent({ id: 'evt_unboundArcContract1' }, { payment_intent: 'pi_unboundArcContract' }));
await assert.rejects(processStripeReversalEvent(unboundRaw, eventSignature(unboundRaw), env, {
  store, alertStore, clock: () => new Date(now),
}), /PAYMENT_INTENT_UNBOUND/);
assert.equal([...alertStore.values.keys()].filter((key) => key.startsWith('alerts/stripe-reversal-unbound/')).length, 1,
  'A verified reversal for an unbound PaymentIntent must create a durable critical alert before retrying.');
const pendingHandoffId = 'b'.repeat(64);
const pendingCheckoutSessionId = 'cs_test_pendingReversalContract';
const pendingFixture = {
  ...normalizedFixture,
  payment: { ...normalizedFixture.payment, value: { ...normalizedFixture.payment.value, checkout_session_id: pendingCheckoutSessionId } },
};
const pendingRecord = createInitialRecord(pendingFixture, env, `handoffs/${pendingHandoffId}`, now, {
  uuid: () => '22222222-2222-4222-8222-222222222222',
}).record;
await createEntry(store, `handoffs/${pendingHandoffId}`, pendingRecord);
await createIndex(store, stripeReversalKeys.checkoutSessionIndexKey(pendingCheckoutSessionId, env), {
  schema: 'arc2-checkout-session-index-v1', handoff_id: pendingHandoffId,
  payment_evidence_sha256: pendingRecord.payment_evidence_sha256,
  artifact_evidence_sha256: pendingRecord.artifact_evidence_sha256,
  bundle_fingerprint: pendingRecord.bundle_fingerprint,
});
const pendingBindingEvidence = canonicalJson({
  ...bindingValue,
  checkout_session_id: pendingCheckoutSessionId,
  payment_intent_id: 'pi_unboundArcContract',
  handoff_id: pendingHandoffId,
});
await registerStripeReversalBinding(pendingBindingEvidence, hmacHex(
  env.ARC_STRIPE_REVERSAL_BINDING_SECRET,
  `${STRIPE_REVERSAL_BINDING_PREFIX}${pendingBindingEvidence}`,
), env, { store, clock: () => new Date(now) });
const pendingSummary = await readIndex(store, stripeReversalKeys.reversalHandoffKey(pendingHandoffId));
assert.equal(pendingSummary.delivery_halted, true,
  'Binding a PaymentIntent with a pre-existing verified reversal must materialize a permanent handoff halt.');
await assert.rejects(assertHandoffFulfillmentAllowed(store, pendingHandoffId, env, {
  checkoutSessionId: pendingCheckoutSessionId, now,
}), /REVERSAL_HALT/);
const pendingRecheckEvidence = canonicalJson({
  ...recheckValue,
  handoff_id: pendingHandoffId,
  checkout_session_id: pendingCheckoutSessionId,
  payment_intent_id: 'pi_unboundArcContract',
});
await assert.rejects(registerStripeReversalRecheck(pendingRecheckEvidence, hmacHex(
  env.ARC_STRIPE_REVERSAL_RECHECK_SECRET,
  `${STRIPE_REVERSAL_RECHECK_PREFIX}${pendingRecheckEvidence}`,
), env, { store, clock: () => new Date(now) }), /REVERSAL_HALT/,
'A clean recheck cannot erase a reversal observed before binding.');
assert.equal(JSON.stringify([...store.values.entries()]).includes('pi_unboundArcContract'), false,
  'Pending reversal reservations must not store raw PaymentIntent ids.');

const endpointSnapshot = Object.fromEntries(Object.keys(pausedRecheckEnv).map((key) => [key, process.env[key]]));
Object.assign(process.env, pausedRecheckEnv);
try {
  const endpointFence = new FakeStore();
  const pausedWebhook = await webhookHandler(new Request('https://arcweb.onl/internal/stripe/reversal-webhook', {
    method: 'POST', headers: { 'content-type': 'application/json', 'stripe-signature': eventSignature(eventRaw) }, body: eventRaw,
  }), {
    arc2Store: store, alertStore, clock: () => new Date(now),
    retentionFenceStore: endpointFence, stripeAccountFetch: accountFetch,
  });
  assert.equal(pausedWebhook.status, 200, 'Pausing recheck production must not disable signed reversal ingestion.');
  const oversizedWebhook = new Request('https://arcweb.onl/internal/stripe/reversal-webhook', {
    method: 'POST', headers: { 'content-type': 'application/json', 'stripe-signature': 'invalid' },
    body: new ReadableStream({ start(controller) {
      controller.enqueue(new Uint8Array(700_000));
      controller.enqueue(new Uint8Array(400_000));
      controller.close();
    } }),
    duplex: 'half',
  });
  assert.equal((await webhookHandler(oversizedWebhook, {
    arc2Store: store, alertStore, retentionFenceStore: endpointFence,
  })).status, 413,
    'Chunked webhooks must be canceled before buffering beyond one MiB.');
} finally {
  for (const [key, value] of Object.entries(endpointSnapshot)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
}

assert.equal(bindingConfig.path, '/internal/stripe/reversal-binding');
assert.equal(recheckConfig.path, '/internal/stripe/reversal-recheck');
assert.equal(webhookConfig.path, '/internal/stripe/reversal-webhook');
const bodyLimitSnapshot = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
Object.assign(process.env, env);
try {
  for (const [handler, endpoint, bearer, contextKey] of [
    [bindingHandler, 'binding', env.ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET, 'arc2Store'],
    [recheckHandler, 'recheck', env.ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET, 'arc2Store'],
  ]) {
    let canceled = false;
    let storeReads = 0;
    const request = new Request(`https://arcweb.onl/internal/stripe/reversal-${endpoint}`, {
      method: 'POST', duplex: 'half',
      headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' },
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(20_000));
          controller.enqueue(new Uint8Array(20_000));
        },
        cancel() { canceled = true; },
      }),
    });
    const context = { retentionFenceStore: new FakeStore() };
    Object.defineProperty(context, contextKey, { get() { storeReads += 1; throw new Error('store must remain untouched'); } });
    assert.equal((await handler(request, context)).status, 413,
      `${endpoint} must reject a headerless oversized body before parsing or storage.`);
    assert.equal(canceled, true, `${endpoint} must cancel the oversized request stream.`);
    assert.equal(storeReads, 0, `${endpoint} must not resolve durable storage for an oversized body.`);
  }
} finally {
  for (const [key, value] of Object.entries(bodyLimitSnapshot)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
}
const saved = { ...process.env };
try {
  for (const name of Object.keys(process.env)) if (name.startsWith('ARC_STRIPE_REVERSAL_') || name === 'ARC_STRIPE_WEBHOOK_SIGNING_SECRET') delete process.env[name];
  assert.equal((await bindingHandler(new Request('https://arcweb.onl/internal/stripe/reversal-binding', { method: 'POST' }))).status, 503);
  assert.equal((await webhookHandler(new Request('https://arcweb.onl/internal/stripe/reversal-webhook', { method: 'POST' }))).status, 503);
} finally {
  for (const name of Object.keys(process.env)) if (!(name in saved)) delete process.env[name];
  Object.assign(process.env, saved);
}

console.log('ARC Stripe reversal control contract passed.');
