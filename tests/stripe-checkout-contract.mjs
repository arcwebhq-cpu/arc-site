import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import { sha256Hex } from '../netlify/lib/arc2-handoff-core.mjs';
import { readIndex } from '../netlify/lib/arc2-handoff-store.mjs';
import {
  STRIPE_CHECKOUT_EVENT_SCHEMA,
  STRIPE_CHECKOUT_HANDOFF_BINDING_SCHEMA,
  STRIPE_CHECKOUT_RECEIPT_SCHEMA,
  STRIPE_CHECKOUT_REVIEW_SCHEMA,
  STRIPE_CHECKOUT_SESSION_SCHEMA,
  assertStripeCheckoutPaid as assertStripeCheckoutPaidCore,
  assertHandoffStripeCheckoutPaid,
  bindStripeCheckoutToHandoff,
  normalizeStripeCheckoutEvent,
  processStripeCheckoutEvent as processStripeCheckoutEventCore,
  stripeCheckoutConfiguration,
  stripeCheckoutKeys,
} from '../netlify/lib/stripe-checkout-core.mjs';
import { STRIPE_WEBHOOK_API_VERSION } from '../netlify/lib/stripe-reversal-core.mjs';
import webhookHandler, { config as webhookConfig } from '../netlify/functions/stripe-reversal-webhook.mjs';

class FakeStore {
  constructor() {
    this.values = new Map();
    this.sequence = 0;
    this.failPrefixOnce = null;
    this.failAfterCommitPrefixOnce = null;
  }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    if (this.failPrefixOnce && key.startsWith(this.failPrefixOnce)) {
      this.failPrefixOnce = null;
      throw new Error('simulated_checkout_state_crash');
    }
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `checkout-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    if (this.failAfterCommitPrefixOnce && key.startsWith(this.failAfterCommitPrefixOnce)) {
      this.failAfterCommitPrefixOnce = null;
      throw new Error('simulated_checkout_post_commit_crash');
    }
    return { modified: true, etag };
  }
}

const now = new Date('2026-08-24T19:00:00.000Z');
const timestamp = Math.floor(now.getTime() / 1000);
const sessionId = 'cs_test_arcCheckoutLedgerContract';
const paymentIntentId = 'pi_arcCheckoutLedgerContract';
const paymentLinkId = 'plink_arcCheckoutLedgerContract';
const payerEmail = 'adult-payer@example.test';
const reviewInviteHmac = 'a'.repeat(64);
const reviewApprovalReceiptSha256 = 'c'.repeat(64);
const stripeAccountId = 'acct_ArcCheckoutContract123';
const env = {
  ARC_STRIPE_CHECKOUT_LEDGER_ENABLED: 'true',
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'true',
  ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
  ARC_STRIPE_WEBHOOK_API_VERSION: STRIPE_WEBHOOK_API_VERSION,
  ARC_STRIPE_WEBHOOK_SIGNING_SECRET: 'wh' + 'sec_checkout-contract-unique-0123456789abcdef',
  ARC_STRIPE_REVERSAL_HMAC_SECRET: 'checkout-ledger-hmac-unique-0123456789abcdef',
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: 'rk_' + 'test_arcCheckoutRestrictedAccountRead0123456789',
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256: sha256Hex(stripeAccountId),
  ARC_RUNTIME_ENVIRONMENT: 'sandbox',
  ARC_ALLOW_TEST_MODE_EVENTS: 'true',
  ARC_HANDOFF_ENABLED: 'false',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'checkout-retention-fence-secret-unique-0123456789abcdef',
};

const stripeEventFixtures = new Map();
const accountFetch = async (url, options = {}) => {
  const target = String(url);
  assert.equal(options.method, 'GET');
  assert.equal(options.headers.Authorization, `Bearer ${env.ARC_STRIPE_ACCOUNT_VERIFICATION_KEY}`);
  assert.equal(options.headers['Stripe-Version'], STRIPE_WEBHOOK_API_VERSION);
  if (target === 'https://api.stripe.com/v1/account') return new Response(JSON.stringify({ id: stripeAccountId, object: 'account' }), {
    status: 200, headers: { 'content-type': 'application/json' },
  });
  const match = target.match(/^https:\/\/api\.stripe\.com\/v1\/events\/(evt_[A-Za-z0-9_]+)$/);
  const event = match ? stripeEventFixtures.get(match[1]) : null;
  return new Response(JSON.stringify(event || { error: { type: 'invalid_request_error' } }), {
    status: event ? 200 : 404, headers: { 'content-type': 'application/json' },
  });
};
const processStripeCheckoutEvent = (raw, stripeSignature, environment, adapters = {}) => {
  const event = JSON.parse(raw);
  stripeEventFixtures.set(event.id, event);
  return processStripeCheckoutEventCore(raw, stripeSignature, environment, { ...adapters, accountFetch });
};
const assertStripeCheckoutPaid = (store, evidence, environment) =>
  assertStripeCheckoutPaidCore(store, evidence, environment, { accountFetch });

function checkoutSession(overrides = {}) {
  return {
    object: 'checkout.session',
    id: sessionId,
    livemode: false,
    mode: 'payment',
    status: 'complete',
    payment_status: 'paid',
    currency: 'usd',
    amount_subtotal: 500_000,
    amount_total: 550_000,
    total_details: { amount_discount: 0, amount_shipping: 0, amount_tax: 50_000 },
    automatic_tax: { enabled: true, status: 'complete' },
    payment_intent: paymentIntentId,
    payment_link: paymentLinkId,
    client_reference_id: null,
    customer_details: {
      email: payerEmail,
      address: { country: 'US', state: 'WA' },
    },
    consent: { terms_of_service: 'accepted' },
    custom_fields: [{ key: 'adultpurchaserack', type: 'dropdown', dropdown: { value: 'accepted' } }],
    ...overrides,
  };
}

function reviewCheckoutMetadata(overrides = {}) {
  return {
    approval_receipt_hmac_sha256: 'b'.repeat(64),
    approval_receipt_sha256: reviewApprovalReceiptSha256,
    invite_hmac_sha256: reviewInviteHmac,
    offer_contract_id: 'arc-fixed-five-page-offer-v1',
    preview_manifest_sha256: 'd'.repeat(64),
    recipient_email_sha256: sha256Hex(payerEmail),
    schema: 'arc-review-checkout-session-v1',
    scope_version: 'arc-fixed-five-page-offer-v1',
    terms_version: '2026-08-25',
    ...overrides,
  };
}

function eventRaw({
  id = 'evt_arcCheckoutCompletedContract',
  type = 'checkout.session.completed',
  created = timestamp,
  session = checkoutSession(),
  livemode = false,
  apiVersion = STRIPE_WEBHOOK_API_VERSION,
  account,
} = {}) {
  return JSON.stringify({
    id,
    object: 'event',
    api_version: apiVersion,
    created,
    livemode,
    type,
    data: { object: session },
    ...(account === undefined ? {} : { account }),
  });
}

function signature(raw, at = timestamp) {
  return `t=${at},v1=${createHmac('sha256', env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET).update(`${at}.${raw}`).digest('hex')}`;
}

const paymentEvidence = {
  checkout_session_id: sessionId,
  payment_intent_id: paymentIntentId,
  payment_link_id: paymentLinkId,
  client_reference_id_observation: 'ABSENT',
  client_reference_id_sha256: sha256Hex('expected-private-reference'),
  payer_email_sha256: sha256Hex(payerEmail),
  customer_address_country: 'US',
  customer_address_state: 'WA',
  stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
  livemode: false,
  currency: 'usd',
  subtotal_amount_minor_units: 500_000,
  tax_amount_minor_units: 50_000,
  amount_total_minor_units: 550_000,
  automatic_tax_enabled: true,
  automatic_tax_status: 'complete',
  terms_of_service_consent: 'accepted',
  adult_purchaser_acknowledgement: 'accepted',
};

assert.equal(stripeCheckoutConfiguration(env).enabled, true);
assert.equal(STRIPE_WEBHOOK_API_VERSION, '2026-08-26.dahlia');
assert.equal(stripeCheckoutConfiguration({}).enabled, false);
for (const unsupportedApiVersion of ['2026-07-29.dahlia', '2026-07-29.preview']) {
  const unsupported = stripeCheckoutConfiguration({
    ...env,
    ARC_STRIPE_WEBHOOK_API_VERSION: unsupportedApiVersion,
  });
  assert.equal(unsupported.apiVersionValid, false);
  assert.equal(unsupported.webhookOperational, false,
    'Only the exact stable Stripe API version may make webhook ingestion operational.');
}
assert.equal(stripeCheckoutConfiguration({ ...env, ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'false' }).webhookOperational, true,
  'Sandbox webhook ingestion may run while handoff gating remains explicitly disabled.');
assert.equal(stripeCheckoutConfiguration({ ...env, ARC_STRIPE_CHECKOUT_LEDGER_ENABLED: 'false' }).enabled, false);
await assert.rejects(assertStripeCheckoutPaid(new FakeStore(), paymentEvidence, {
  ...env, ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'yes',
}), /LEDGER_DISABLED/, 'Malformed flags cannot become a sandbox bypass.');
assert.equal(stripeCheckoutConfiguration({
  ...env,
  ARC_STRIPE_REVERSAL_HMAC_SECRET: env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET,
}).enabled, false, 'Stripe signatures and stored identity HMACs must not share a secret.');
for (const credentialName of [
  'ARC_STRIPE_WEBHOOK_SIGNING_SECRET',
  'ARC_STRIPE_REVERSAL_HMAC_SECRET',
]) {
  const aliased = stripeCheckoutConfiguration({
    ...env,
    ARC_ROTATED_CREDENTIAL_V2: env[credentialName],
  });
  assert.equal(aliased.secretsValid, false,
    `An arbitrary alias must not reuse ${credentialName}.`);
  assert.equal(aliased.webhookOperational, false);
}
assert.equal(stripeCheckoutConfiguration({
  ...env,
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: 'sk_' + 'test_fullAccessKeysAreNotAccepted0123456789',
}).enabled, false, 'Account verification must use a mode-bound restricted key.');

const paidRaw = eventRaw();
const normalizedPaid = normalizeStripeCheckoutEvent(paidRaw, signature(paidRaw), env, now);
assert.equal(normalizedPaid.state, 'PAID');
assert.equal(normalizedPaid.sessionId, sessionId);
for (const unsupportedApiVersion of ['2026-07-29.dahlia', '2026-07-29.preview']) {
  const unsupportedRaw = eventRaw({ apiVersion: unsupportedApiVersion });
  assert.throws(() => normalizeStripeCheckoutEvent(
    unsupportedRaw, signature(unsupportedRaw), env, now,
  ), /allowlisted|bound/i, 'Signed events on a retired or preview API version must fail closed.');
}
assert.throws(() => normalizeStripeCheckoutEvent(paidRaw, 't=1787600000,v1=' + '0'.repeat(64), env, now), /signature/i);
const wrongAccountStore = new FakeStore();
await assert.rejects(processStripeCheckoutEventCore(paidRaw, signature(paidRaw), env, {
  store: wrongAccountStore,
  clock: () => new Date(now),
  accountFetch: async () => new Response(JSON.stringify({ id: 'acct_WrongCheckout123', object: 'account' }), {
    status: 200, headers: { 'content-type': 'application/json' },
  }),
}), /ACCOUNT_BINDING_MISMATCH/, 'A valid endpoint signature cannot substitute for authoritative account ownership.');
assert.equal(wrongAccountStore.values.size, 0, 'Wrong-account evidence must not create durable Checkout state.');
const unownedEventStore = new FakeStore();
await assert.rejects(processStripeCheckoutEventCore(paidRaw, signature(paidRaw), env, {
  store: unownedEventStore,
  clock: () => new Date(now),
  accountFetch: async (url) => String(url).endsWith('/v1/account')
    ? new Response(JSON.stringify({ id: stripeAccountId, object: 'account' }), {
      status: 200, headers: { 'content-type': 'application/json' },
    })
    : new Response(JSON.stringify({ error: { type: 'invalid_request_error' } }), {
      status: 404, headers: { 'content-type': 'application/json' },
    }),
}), /ACCOUNT_VERIFICATION_FAILED/,
'A signing secret from another endpoint/account cannot authorize an event absent from the verified ARC account.');
assert.equal(unownedEventStore.values.size, 0, 'Unowned signed events must fail before durable reservation.');
const wrongAccountRaw = eventRaw({ account: 'acct_wrongCheckoutLedger' });
assert.throws(() => normalizeStripeCheckoutEvent(wrongAccountRaw, signature(wrongAccountRaw), env, now), /account/i);
for (const invalidSession of [
  checkoutSession({ consent: null }),
  checkoutSession({ custom_fields: [] }),
  checkoutSession({ amount_total: 500_000 }),
  checkoutSession({ automatic_tax: { enabled: true, status: 'requires_location_inputs' } }),
  checkoutSession({ livemode: true, id: 'cs_live_arcCheckoutLedgerContract' }),
]) {
  const raw = eventRaw({ session: invalidSession });
  assert.throws(() => normalizeStripeCheckoutEvent(raw, signature(raw), env, now), /invalid|lacks|required|disagree/i);
}

const dynamicSessionId = 'cs_test_arcReviewCheckoutLedger';
const dynamicRaw = eventRaw({
  id: 'evt_arcReviewCheckoutCompleted',
  session: checkoutSession({
    id: dynamicSessionId,
    payment_link: null,
    client_reference_id: reviewApprovalReceiptSha256,
    metadata: reviewCheckoutMetadata(),
  }),
});
const normalizedDynamic = normalizeStripeCheckoutEvent(dynamicRaw, signature(dynamicRaw), env, now);
assert.equal(normalizedDynamic.paymentLinkId, null);
assert.deepEqual(normalizedDynamic.reviewCheckoutBinding, reviewCheckoutMetadata());
for (const invalidDynamicSession of [
  checkoutSession({ payment_link: null, client_reference_id: reviewApprovalReceiptSha256 }),
  checkoutSession({
    payment_link: null, client_reference_id: reviewApprovalReceiptSha256,
    metadata: reviewCheckoutMetadata({ schema: 'untrusted-checkout-metadata' }),
  }),
  checkoutSession({
    payment_link: null, client_reference_id: 'f'.repeat(64), metadata: reviewCheckoutMetadata(),
  }),
]) {
  const raw = eventRaw({ id: 'evt_arcReviewCheckoutInvalid', session: invalidDynamicSession });
  assert.throws(() => normalizeStripeCheckoutEvent(raw, signature(raw), env, now), /metadata|reference|recipient|object/i,
    'Dynamic Checkout Sessions must carry the exact approval metadata binding.');
}

const alternateRecipientRaw = eventRaw({
  id: 'evt_arcReviewCheckoutAlternatePayer',
  session: checkoutSession({
    id: 'cs_test_arcReviewCheckoutAlternatePayer',
    payment_link: null,
    client_reference_id: reviewApprovalReceiptSha256,
    metadata: reviewCheckoutMetadata({ recipient_email_sha256: 'e'.repeat(64) }),
  }),
});
const alternateRecipient = normalizeStripeCheckoutEvent(
  alternateRecipientRaw, signature(alternateRecipientRaw), env, now,
);
assert.equal(alternateRecipient.state, 'PAID');
assert.equal(alternateRecipient.payerEmailSha256, sha256Hex(payerEmail));
assert.equal(alternateRecipient.reviewCheckoutBinding.recipient_email_sha256, 'e'.repeat(64));
assert.notEqual(alternateRecipient.payerEmailSha256,
  alternateRecipient.reviewCheckoutBinding.recipient_email_sha256,
  'Review fulfillment recipient and Stripe payer are distinct authenticated roles.');

const malformedPayerRaw = eventRaw({
  id: 'evt_arcReviewCheckoutMalformedPayer',
  session: checkoutSession({
    id: 'cs_test_arcReviewCheckoutMalformedPayer',
    payment_link: null,
    client_reference_id: reviewApprovalReceiptSha256,
    metadata: reviewCheckoutMetadata(),
    customer_details: { email: 'not-an-email', address: { country: 'US', state: 'WA' } },
  }),
});
const malformedPayerStore = new FakeStore();
const malformedPayerAlerts = new FakeStore();
const malformedPayer = await processStripeCheckoutEvent(
  malformedPayerRaw,
  signature(malformedPayerRaw),
  env,
  { store: malformedPayerStore, alertStore: malformedPayerAlerts, clock: () => new Date(now) },
);
assert.equal(malformedPayer.summary.state, 'REVIEW_REQUIRED');
assert.equal(malformedPayer.summary.fulfillment_allowed, false);
assert.equal(malformedPayer.summary.manual_review_required, true);
assert.equal(malformedPayer.summary.payer_email_sha256, null);
assert.equal(malformedPayerAlerts.values.size, 1,
  'Captured review payments with unusable payer data require durable manual refund/review.');

const dynamicStore = new FakeStore();
const processedDynamic = await processStripeCheckoutEvent(dynamicRaw, signature(dynamicRaw), env, {
  store: dynamicStore, clock: () => new Date(now),
});
assert.equal(processedDynamic.summary.state, 'PAID');
assert.equal(processedDynamic.summary.payment_link_id_hmac_sha256, null);
assert.deepEqual(processedDynamic.summary.review_checkout_binding, reviewCheckoutMetadata());
assert.deepEqual((await readIndex(dynamicStore,
  stripeCheckoutKeys.eventReservationKey(normalizedDynamic.eventId, env))).review_checkout_binding,
reviewCheckoutMetadata(), 'The signed event reservation must preserve the exact approval binding.');

const store = new FakeStore();
const alertStore = new FakeStore();
const processed = await processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, {
  store, alertStore, clock: () => new Date(now),
});
assert.equal(processed.idempotentReplay, false);
assert.equal(processed.summary.schema, STRIPE_CHECKOUT_SESSION_SCHEMA);
assert.equal(processed.summary.state, 'PAID');
assert.equal(processed.summary.fulfillment_allowed, true);
assert.equal(Object.hasOwn(processed.summary, 'review_checkout_binding'), false,
  'The legacy Payment Link ledger shape and binding path must remain unchanged.');
assert.equal(processed.receipt.schema, STRIPE_CHECKOUT_RECEIPT_SCHEMA);
assert.equal((await assertStripeCheckoutPaid(store, paymentEvidence, env)).ready, true);
await assert.rejects(assertStripeCheckoutPaid(store, { ...paymentEvidence, amount_total_minor_units: 550_001 }, env),
  /BINDING_MISMATCH/, 'Signed payment evidence must match the independently authenticated Checkout ledger.');
const replay = await processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, {
  store, alertStore, clock: () => new Date(now),
});
assert.equal(replay.idempotentReplay, true);
assert.equal(replay.summary.event_count, 1, 'An exact webhook replay must not advance session state twice.');
const persisted = JSON.stringify([...store.values.entries()]);
for (const secretValue of [sessionId, paymentIntentId, paymentLinkId, payerEmail]) {
  assert.equal(persisted.includes(secretValue), false, 'Durable Checkout state must not contain raw Stripe ids or payer email.');
}
assert.equal((await readIndex(store, stripeCheckoutKeys.eventReservationKey(normalizedPaid.eventId, env))).schema,
  STRIPE_CHECKOUT_EVENT_SCHEMA);

const conflictingIdRaw = eventRaw({ session: checkoutSession({ amount_total: 551_000, total_details: {
  amount_discount: 0, amount_shipping: 0, amount_tax: 51_000,
} }) });
await assert.rejects(processStripeCheckoutEvent(conflictingIdRaw, signature(conflictingIdRaw), env, {
  store, alertStore, clock: () => new Date(now),
}), /EVENT_CONFLICT/, 'One Stripe event id cannot be rebound to different bytes.');

const pendingStore = new FakeStore();
const pendingRaw = eventRaw({
  id: 'evt_arcCheckoutPendingContract',
  session: checkoutSession({ payment_status: 'unpaid', payment_intent: null, customer_details: null }),
});
const pending = await processStripeCheckoutEvent(pendingRaw, signature(pendingRaw), env, {
  store: pendingStore, clock: () => new Date(now),
});
assert.equal(pending.summary.state, 'PENDING');
await assert.rejects(assertStripeCheckoutPaid(pendingStore, paymentEvidence, env), /PAYMENT_NOT_PAID/);
const succeededRaw = eventRaw({
  id: 'evt_arcCheckoutSucceededContract',
  type: 'checkout.session.async_payment_succeeded',
  created: timestamp + 60,
});
const succeeded = await processStripeCheckoutEvent(succeededRaw, signature(succeededRaw), env, {
  store: pendingStore, clock: () => new Date(now),
});
assert.equal(succeeded.summary.state, 'PAID');
assert.equal(succeeded.summary.event_count, 2);
await assert.doesNotReject(assertStripeCheckoutPaid(pendingStore, paymentEvidence, env));

const outOfOrderStore = new FakeStore();
await processStripeCheckoutEvent(succeededRaw, signature(succeededRaw), env, {
  store: outOfOrderStore, clock: () => new Date(now),
});
const latePending = await processStripeCheckoutEvent(pendingRaw, signature(pendingRaw), env, {
  store: outOfOrderStore, clock: () => new Date(now),
});
assert.equal(latePending.summary.state, 'PAID',
  'An older authenticated pending snapshot delivered late must not roll back a newer paid state.');
await assert.doesNotReject(assertStripeCheckoutPaid(outOfOrderStore, paymentEvidence, env));

const sameSecondStore = new FakeStore();
await processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, {
  store: sameSecondStore, clock: () => new Date(now),
});
const sameSecondPendingRaw = eventRaw({
  id: 'evt_arcCheckoutSameSecondPending',
  session: checkoutSession({ payment_status: 'unpaid', payment_intent: null, customer_details: null }),
});
assert.equal((await processStripeCheckoutEvent(sameSecondPendingRaw, signature(sameSecondPendingRaw), env, {
  store: sameSecondStore, clock: () => new Date(now),
})).summary.state, 'PAID', 'A same-second pending snapshot must remain weaker than an authenticated paid result.');
await assert.doesNotReject(assertStripeCheckoutPaid(sameSecondStore, paymentEvidence, env));

const crashStore = new FakeStore();
crashStore.failPrefixOnce = 'stripe-checkout-session/';
const crashRaw = eventRaw({ id: 'evt_arcCheckoutCrashContract' });
await assert.rejects(processStripeCheckoutEvent(crashRaw, signature(crashRaw), env, {
  store: crashStore, clock: () => new Date(now),
}), /simulated_checkout_state_crash/);
assert.equal([...crashStore.values.keys()].filter((key) => key.startsWith('stripe-checkout-event/')).length, 1,
  'The authenticated event reservation must survive a crash before session state.');
assert.equal([...crashStore.values.keys()].filter((key) => key.startsWith('stripe-checkout-receipt/')).length, 0);
const recovered = await processStripeCheckoutEvent(crashRaw, signature(crashRaw), env, {
  store: crashStore, clock: () => new Date(now),
});
assert.equal(recovered.idempotentReplay, true);
assert.equal(recovered.summary.state, 'PAID');
assert.equal([...crashStore.values.keys()].filter((key) => key.startsWith('stripe-checkout-receipt/')).length, 1,
  'Retry must converge the reserved event and create its deterministic processing receipt.');

const receiptCrashStore = new FakeStore();
receiptCrashStore.failPrefixOnce = 'stripe-checkout-receipt/';
await assert.rejects(processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, {
  store: receiptCrashStore, clock: () => new Date(now),
}), /simulated_checkout_state_crash/);
await assert.rejects(assertStripeCheckoutPaid(receiptCrashStore, paymentEvidence, env), /RECEIPT_REQUIRED/,
  'A paid state cannot authorize handoff until its deterministic processing receipt exists.');
const receiptRecovered = await processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, {
  store: receiptCrashStore, clock: () => new Date(now),
});
assert.equal(receiptRecovered.summary.event_count, 1,
  'Recovery after state persistence must not count or apply the same Stripe event twice.');
await assert.doesNotReject(assertStripeCheckoutPaid(receiptCrashStore, paymentEvidence, env));

const postCommitCrashStore = new FakeStore();
postCommitCrashStore.failAfterCommitPrefixOnce = 'stripe-checkout-session/';
await assert.rejects(processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, {
  store: postCommitCrashStore, clock: () => new Date(now),
}), /post_commit_crash/);
const postCommitRecovered = await processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, {
  store: postCommitCrashStore, clock: () => new Date(now),
});
assert.equal(postCommitRecovered.summary.event_count, 1,
  'An ambiguous successful CAS must converge without applying or counting the same event twice.');
await assert.doesNotReject(assertStripeCheckoutPaid(postCommitCrashStore, paymentEvidence, env));

const concurrentStore = new FakeStore();
const concurrentResults = await Promise.all([
  processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, { store: concurrentStore, clock: () => new Date(now) }),
  processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, { store: concurrentStore, clock: () => new Date(now) }),
]);
assert.equal(concurrentResults[0].summary.event_count, 1);
assert.equal(concurrentResults[1].summary.event_count, 1,
  'Concurrent exact delivery must converge to one applied event.');

const reviewStore = new FakeStore();
const reviewAlerts = new FakeStore();
await processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, {
  store: reviewStore, alertStore: reviewAlerts, clock: () => new Date(now),
});
const failedRaw = eventRaw({
  id: 'evt_arcCheckoutFailedAfterPaid',
  type: 'checkout.session.async_payment_failed',
  created: timestamp + 120,
  session: checkoutSession({ payment_status: 'unpaid' }),
});
const review = await processStripeCheckoutEvent(failedRaw, signature(failedRaw), env, {
  store: reviewStore, alertStore: reviewAlerts, clock: () => new Date(now),
});
assert.equal(review.summary.state, 'REVIEW_REQUIRED');
assert.equal(review.summary.fulfillment_allowed, false);
assert.equal(review.summary.manual_review_required, true);
assert.equal([...reviewAlerts.values.values()][0].data.schema, STRIPE_CHECKOUT_REVIEW_SCHEMA);
await assert.rejects(assertStripeCheckoutPaid(reviewStore, paymentEvidence, env), /LEDGER_HALT/,
  'A later contradictory payment failure must permanently stop fulfillment.');
const laterSucceededRaw = eventRaw({
  id: 'evt_arcCheckoutSucceededAfterReview',
  type: 'checkout.session.async_payment_succeeded',
  created: timestamp + 180,
});
assert.equal((await processStripeCheckoutEvent(laterSucceededRaw, signature(laterSucceededRaw), env, {
  store: reviewStore, alertStore: reviewAlerts, clock: () => new Date(now),
})).summary.state, 'REVIEW_REQUIRED', 'Automatic success cannot erase a durable review halt.');

const reviewAlertKey = [...reviewAlerts.values.keys()].find((key) => key.startsWith('alerts/stripe-checkout-review/'));
assert.ok(reviewAlertKey);
reviewAlerts.values.delete(reviewAlertKey);
await processStripeCheckoutEvent(failedRaw, signature(failedRaw), env, {
  store: reviewStore, alertStore: reviewAlerts, clock: () => new Date(now),
});
assert.equal(reviewAlerts.values.has(reviewAlertKey), true,
  'A receipt replay must reconcile a missing required review alert.');

const alertCrashStore = new FakeStore();
const alertCrashAlerts = new FakeStore();
await processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, {
  store: alertCrashStore, alertStore: alertCrashAlerts, clock: () => new Date(now),
});
alertCrashAlerts.failAfterCommitPrefixOnce = 'alerts/stripe-checkout-review/';
await assert.rejects(processStripeCheckoutEvent(failedRaw, signature(failedRaw), env, {
  store: alertCrashStore, alertStore: alertCrashAlerts, clock: () => new Date(now),
}), /post_commit_crash/);
assert.equal([...alertCrashStore.values.keys()].some((key) => key.includes('stripe-checkout-receipt/') &&
  alertCrashStore.values.get(key)?.data?.resulting_state === 'REVIEW_REQUIRED'), false,
  'Review receipt must not commit before the required alert converges.');
await processStripeCheckoutEvent(failedRaw, signature(failedRaw), env, {
  store: alertCrashStore, alertStore: alertCrashAlerts, clock: () => new Date(now),
});
assert.equal([...alertCrashAlerts.values.values()].some((entry) => entry.data.category === 'stripe-checkout-review'), true);

const boundStore = new FakeStore();
await processStripeCheckoutEvent(paidRaw, signature(paidRaw), env, {
  store: boundStore, clock: () => new Date(now),
});
const boundHandoffId = 'a'.repeat(64);
const boundPaymentEvidenceSha256 = 'b'.repeat(64);
const bound = await bindStripeCheckoutToHandoff(
  boundStore, boundHandoffId, paymentEvidence, boundPaymentEvidenceSha256, env, { accountFetch },
);
assert.equal(bound.binding.schema, STRIPE_CHECKOUT_HANDOFF_BINDING_SCHEMA);
await assert.doesNotReject(assertHandoffStripeCheckoutPaid(
  boundStore, boundHandoffId, boundPaymentEvidenceSha256, env, { accountFetch },
));
await processStripeCheckoutEvent(failedRaw, signature(failedRaw), env, {
  store: boundStore, alertStore: new FakeStore(), clock: () => new Date(now),
});
await assert.rejects(assertHandoffStripeCheckoutPaid(
  boundStore, boundHandoffId, boundPaymentEvidenceSha256, env, { accountFetch },
), /LEDGER_HALT/, 'A later signed checkout conflict must halt every stage bound to the handoff.');

const expiredStore = new FakeStore();
const expiredRaw = eventRaw({
  id: 'evt_arcCheckoutExpiredContract',
  type: 'checkout.session.expired',
  session: checkoutSession({
    status: 'expired', payment_status: 'unpaid', payment_intent: null, customer_details: null,
    automatic_tax: { enabled: true, status: null }, consent: null, custom_fields: [],
  }),
});
assert.equal((await processStripeCheckoutEvent(expiredRaw, signature(expiredRaw), env, {
  store: expiredStore, clock: () => new Date(now),
})).summary.state, 'EXPIRED');
await assert.rejects(assertStripeCheckoutPaid(expiredStore, paymentEvidence, env), /PAYMENT_NOT_PAID/);
assert.deepEqual(await assertStripeCheckoutPaid(new FakeStore(), paymentEvidence, {
  ...env, ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'false',
}), { required: false, ready: true });
await assert.rejects(assertStripeCheckoutPaidCore(new FakeStore(), paymentEvidence, {
  ...env, ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'false', ARC_RUNTIME_ENVIRONMENT: 'production',
}, { accountFetch }), /LEDGER_DISABLED/, 'A required=false setting is not a bypass outside the exact sandbox tuple.');

assert.equal(webhookConfig.path, '/internal/stripe/reversal-webhook');
const savedEnvironment = { ...process.env };
try {
  Object.assign(process.env, env);
  const endpointStore = new FakeStore();
  const endpointAlerts = new FakeStore();
  const endpointFence = new FakeStore();
  const endpointRaw = eventRaw({ id: 'evt_arcCheckoutEndpointContract' });
  stripeEventFixtures.set(JSON.parse(endpointRaw).id, JSON.parse(endpointRaw));
  const response = await webhookHandler(new Request('https://arcweb.onl/internal/stripe/reversal-webhook', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'stripe-signature': signature(endpointRaw) },
    body: endpointRaw,
  }), {
    arc2Store: endpointStore, alertStore: endpointAlerts, clock: () => new Date(now),
    retentionFenceStore: endpointFence, stripeAccountFetch: accountFetch,
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    accepted: true,
    checkout_state: 'PAID',
    idempotent_replay: false,
    fulfillment_halted: false,
  });
} finally {
  for (const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env, savedEnvironment);
}

console.log('ARC Stripe Checkout ledger contract passed.');
