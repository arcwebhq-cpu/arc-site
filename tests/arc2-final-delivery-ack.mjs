import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import {
  ACTIVATION_EVIDENCE_BY_STAGE,
  ACTIVATION_MANIFEST_SCHEMA,
  ACTIVATION_MANIFEST_VERSION,
  signActivationManifest,
} from '../netlify/lib/activation-manifest-core.mjs';
import {
  HANDOFF_SCHEMA,
  LEGACY_HANDOFF_SCHEMA,
  canonicalJson,
  configuredEnvironment,
  createOutboxClaim,
  hmacHex,
  sha256Hex,
  validateExpectedBindings,
} from '../netlify/lib/arc2-handoff-core.mjs';
import {
  createEntry,
  createIndex,
  readEntry,
  readIndex,
  readIndexEntry,
} from '../netlify/lib/arc2-handoff-store.mjs';
import {
  acknowledgeFinalDelivery,
  finalDeliveryReceiptContract,
} from '../netlify/lib/arc2-handoff-service.mjs';
import deliveryAckHandler, { config as deliveryAckConfig } from '../netlify/functions/arc2-final-delivery-ack.mjs';

class FakeStore {
  constructor() {
    this.values = new Map();
    this.sequence = 0;
    this.failures = [];
  }

  failNextKey(key) { this.failures.push((candidate) => candidate === key); }
  failNextPrefix(prefix) { this.failures.push((candidate) => candidate.startsWith(prefix)); }
  failNextStatus(key, status) {
    this.failures.push((candidate, data) => candidate === key && data?.status === status);
  }

  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }

  async setJSON(key, data, options = {}) {
    const failureIndex = this.failures.findIndex((predicate) => predicate(key, data, options));
    if (failureIndex !== -1) {
      this.failures.splice(failureIndex, 1);
      throw new Error('SIMULATED_PROCESS_CRASH');
    }
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `etag-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
}

const now = new Date('2026-08-13T06:00:00.000Z');
const at = (offsetMs) => new Date(now.getTime() + offsetMs).toISOString();
const handoffId = 'a'.repeat(64);
const secretNames = [
  'ARC_CHECKOUT_BINDING_SECRET',
  'ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET',
  'ARC_LEAD_ROUTE_EVIDENCE_SECRET',
  'ARC_HANDOFF_STATE_SECRET',
  'ARC_HANDOFF_TRIGGER_SECRET',
  'ARC_CLAIM_TOKEN_SECRET',
  'ARC_CLAIM_STATE_EVIDENCE_SECRET',
  'ARC_EMAIL_CLAIM_BINDING_SECRET',
  'ARC_FINAL_DELIVERY_RECEIPT_SECRET',
  'ARC_FINAL_DELIVERY_ACK_SECRET',
  'ARC_STRIPE_WEBHOOK_SIGNING_SECRET',
  'ARC_STRIPE_REVERSAL_HMAC_SECRET',
  'ARC_STRIPE_REVERSAL_BINDING_SECRET',
  'ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET',
  'ARC_STRIPE_REVERSAL_RECHECK_SECRET',
  'ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET',
  'NETLIFY_ADMIN_PAT',
  'NETLIFY_OAUTH_CLIENT_SECRET',
  'ARC_ACTIVATION_MANIFEST_HMAC_SECRET',
];
const secrets = Object.fromEntries(secretNames.map((name, index) => [
  name,
  `${name.toLowerCase()}-${String(index).padStart(2, '0')}-unique-test-secret-0123456789`,
]));
const activationNow = new Date();
const activationDeploymentSha = '9'.repeat(40);
const activationStage = 'CLAIM_SANDBOX';
const activationManifest = signActivationManifest({
  schema: ACTIVATION_MANIFEST_SCHEMA,
  version: ACTIVATION_MANIFEST_VERSION,
  stage: activationStage,
  authority_mode: 'ROLLOUT',
  issued_at: new Date(activationNow.getTime() - 60_000).toISOString(),
  expires_at: new Date(activationNow.getTime() + 60 * 60_000).toISOString(),
  deployment_sha: activationDeploymentSha,
  evidence: ACTIVATION_EVIDENCE_BY_STAGE[activationStage].map((kind) => ({
    kind,
    receipt_ref: `audit:${createHash('sha256').update(`receipt:${kind}`).digest('hex').slice(0, 24)}`,
    sha256: createHash('sha256').update(`evidence:${kind}`).digest('hex'),
  })),
}, secrets.ARC_ACTIVATION_MANIFEST_HMAC_SECRET);
const env = {
  ...secrets,
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: 'rk_' + 'test_arcDeliveryRestrictedAccountRead0123456789',
  ARC_HANDOFF_ENABLED: 'false',
  ARC_CHECKOUT_BINDING_KEY_ID: '01',
  ARC_RETIRED_CHECKOUT_BINDING_KEYS_JSON: '{}',
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_EXPECTED_PAYMENT_LINK_ID: 'plink_1ArcHandoffTest',
  ARC_EXPECTED_PRICE_ID: 'price_1ArcHandoffTest',
  ARC_EXPECTED_PRODUCT_TAX_CODE: 'txcd_10000000',
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256: sha256Hex('acct_arc_test'),
  ARC_ADULT_OPERATOR_VERIFIED: 'true',
  ARC_BUSINESS_LICENSE_VERIFIED: 'true',
  ARC_TAX_REGISTRATION_VERIFIED: 'true',
  ARC_TRANSACTIONAL_EMAIL_VERIFIED: 'true',
  ARC_RETENTION_CONTROL_VERIFIED: 'true',
  ARC_POSTCLAIM_READBACK_VERIFIED: 'true',
  ARC_DEVICE_QA_VERIFIED: 'true',
  ARC_LEAD_ROUTE_VERIFIED: 'true',
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'true',
  ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_BINDING_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_RECHECK_ENABLED: 'true',
  ARC_STRIPE_CHECKOUT_LEDGER_ENABLED: 'true',
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'false',
  ARC_STRIPE_WEBHOOK_API_VERSION: '2026-07-29.dahlia',
  ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
  ARC_ALLOW_TEST_MODE_EVENTS: 'true',
  ARC_RUNTIME_ENVIRONMENT: 'sandbox',
  ARC_PUBLIC_ORIGIN: 'https://arcweb.onl/',
  SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  SITE_NAME: 'arc2-sandbox',
  URL: 'https://arcweb.onl/',
  NETLIFY_TEAM_SLUG: 'arc-team',
  NETLIFY_TEAM_ACCOUNT_ID: 'account-source-123',
  NETLIFY_OAUTH_CLIENT_ID: 'oauth-client-123',
  COMMIT_REF: activationDeploymentSha,
  ARC_ACTIVATION_MANIFEST: activationManifest,
};
assert.equal(configuredEnvironment(env).enabled, true);
assert.equal(configuredEnvironment({ ...env, ARC_FINAL_DELIVERY_RECEIPT_SECRET: env.ARC_EMAIL_CLAIM_BINDING_SECRET }).enabled, false,
  'Final delivery receipts must use a distinct HMAC secret.');
assert.equal(configuredEnvironment({ ...env, ARC_FINAL_DELIVERY_ACK_SECRET: env.ARC_HANDOFF_TRIGGER_SECRET }).enabled, false,
  'The final-delivery endpoint must use a dedicated bearer secret.');
assert.equal(configuredEnvironment({ ...env, ARC_FINAL_DELIVERY_ACK_SECRET: '' }).enabled, false,
  'The final-delivery endpoint bearer secret is required.');

function makeRecord({
  id = handoffId,
  schema = HANDOFF_SCHEMA,
  siteName = `arc-lead-route-${'d'.repeat(24)}`,
  sessionId = '11111111-1111-4111-8111-111111111111',
  paymentDigest = '1'.repeat(64),
  siteId = 'b'.repeat(24),
  deployId = 'c'.repeat(24),
} = {}) {
  const productionUrl = `https://${siteName}.netlify.app/`;
  const candidate = {
    schema,
    handoff_id: id,
    state: 'FINAL_DEPLOY_READY',
    revision: 14,
    created_at: at(-60 * 60_000),
    updated_at: at(-5 * 60_000),
    payment_evidence_sha256: paymentDigest,
    artifact_evidence_sha256: '2'.repeat(64),
    artifact_manifest_sha256: '3'.repeat(64),
    bundle_fingerprint: '4'.repeat(64),
    production_content_sha256: '5'.repeat(64),
    customer_email_sha256: '6'.repeat(64),
    lead_notification_email_sha256: '7'.repeat(64),
    lead_route_recipient_hmac_sha256: '8'.repeat(64),
    lead_route_mode: 'netlify_form',
    preview_folder: 'sample-roofing-a1b2c3d4',
    artifacts: [
      { path: '_headers', sha256: '9'.repeat(64), size: 10 },
      { path: 'about/index.html', sha256: 'a'.repeat(64), size: 20 },
      { path: 'contact/index.html', sha256: 'b'.repeat(64), size: 20 },
      { path: 'process/index.html', sha256: 'c'.repeat(64), size: 20 },
      { path: 'services/index.html', sha256: 'd'.repeat(64), size: 20 },
      { path: 'index.html', sha256: 'a'.repeat(64), size: 20 },
    ],
    form_name: 'sample-lead',
    netlify_session_id: sessionId,
    netlify_site_name: siteName,
    netlify_source_account_id: 'account-source-123',
    netlify_site_id: siteId,
    site_created_at: at(-55 * 60_000),
    preclaim_deploy_attempted_at: at(-50 * 60_000),
    preclaim_deploy_candidate_id: 'e'.repeat(24),
    preclaim_deploy_id: 'e'.repeat(24),
    final_deploy_attempted_at: at(-7 * 60_000),
    final_deploy_candidate_id: deployId,
    final_deploy_id: deployId,
    email_hook_attempted_at: at(-48 * 60_000),
    form_id: 'f'.repeat(24),
    hook_id: '1'.repeat(24),
    destination_account_id: 'account-customer-123',
    lead_route_receipt_sha256: 'b'.repeat(64),
    claim_token_hmac_sha256: null,
    claim_token_consumed_hmac_sha256: 'c'.repeat(64),
    claim_token_expires_at: at(-10 * 60_000),
    claim_token_used_at: at(-35 * 60_000),
    claim_wrapper_consumed_at: at(-35 * 60_000),
    claim_jwt_issued_at: Math.floor(Date.parse(at(-35 * 60_000)) / 1000),
    claim_invitation_ready_at: at(-40 * 60_000),
    lead_route_provider_message_id_sha256: 'd'.repeat(64),
    claim_callback_received_at: at(-20 * 60_000),
    claimed_verified_at: at(-10 * 60_000),
    final_deploy_ready_at: at(-5 * 60_000),
    production_url: productionUrl,
    outbox_claim_status: 'CLAIMED',
    outbox_claim_key_hmac_sha256: null,
    final_delivery_receipt_sha256: null,
    final_delivery_provider: null,
    final_delivery_provider_account_hmac_sha256: null,
    final_delivery_provider_event_id_hmac_sha256: null,
    final_delivery_provider_message_id_hmac_sha256: null,
    final_delivery_event_type: null,
    final_delivery_status: null,
    final_delivery_receipt_issued_at: null,
    delivered_at: null,
  };
  const outbox = createOutboxClaim({ ...candidate, state: 'CLAIMED_VERIFIED' }, env);
  return { record: { ...candidate, outbox_claim_key_hmac_sha256: outbox.digest }, outbox };
}

async function seed(store, record, outbox) {
  await createEntry(store, `handoffs/${record.handoff_id}`, record);
  await createIndex(store, outbox.key, outbox.value);
}

const providerAccountHmac = hmacHex(
  env.ARC_FINAL_DELIVERY_RECEIPT_SECRET,
  'arc2-final-delivery-provider-account-v1\npostmark-server-test',
);
function receiptFor(record, overrides = {}) {
  return {
    version: finalDeliveryReceiptContract.version,
    scope: finalDeliveryReceiptContract.scope,
    handoff_id: record.handoff_id,
    outbox_claim_key_hmac_sha256: record.outbox_claim_key_hmac_sha256,
    recipient_email_sha256: record.customer_email_sha256,
    production_url_sha256: sha256Hex(record.production_url),
    netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
    netlify_deploy_id_sha256: sha256Hex(record.final_deploy_id),
    provider: 'postmark',
    provider_account_hmac_sha256: providerAccountHmac,
    provider_event_id: 'provider-delivery-identity-123',
    provider_message_id: 'provider-delivery-identity-123',
    event_type: 'message.delivered',
    delivery_status: 'delivered',
    delivered_at: at(-30_000),
    issued_at: now.toISOString(),
    ...overrides,
  };
}
const sign = (raw, environment = env) => hmacHex(
  environment.ARC_FINAL_DELIVERY_RECEIPT_SECRET,
  `${finalDeliveryReceiptContract.signaturePrefix}${raw}`,
);

const fixture = makeRecord();
const record = fixture.record;
const receiptValue = receiptFor(record);
const receipt = canonicalJson(receiptValue);
const signature = sign(receipt);
assert.doesNotThrow(() => validateExpectedBindings(record));

const store = new FakeStore();
await seed(store, record, fixture.outbox);
const first = await acknowledgeFinalDelivery(handoffId, receipt, signature, env, { store, clock: () => new Date(now) });
assert.equal(first.record.state, 'DELIVERED');
assert.equal(first.record.revision, record.revision + 1, 'Receipt fields and DELIVERED must be one handoff CAS transition.');
assert.equal(first.record.final_delivery_receipt_sha256, sha256Hex(receipt));
assert.equal(first.record.final_delivery_provider, receiptValue.provider);
assert.equal(first.record.final_delivery_provider_account_hmac_sha256, receiptValue.provider_account_hmac_sha256);
assert.match(first.record.final_delivery_provider_event_id_hmac_sha256, /^[a-f0-9]{64}$/);
assert.match(first.record.final_delivery_provider_message_id_hmac_sha256, /^[a-f0-9]{64}$/);
assert.notEqual(first.record.final_delivery_provider_event_id_hmac_sha256, first.record.final_delivery_provider_message_id_hmac_sha256,
  'Event and message identities must use separate HMAC domains even when their raw IDs are equal.');
assert.equal(first.record.final_delivery_event_type, 'message.delivered');
assert.equal(first.record.final_delivery_status, 'delivered');
assert.equal(first.record.final_delivery_receipt_issued_at, receiptValue.issued_at);
assert.equal(first.record.delivered_at, receiptValue.delivered_at);
assert.equal(first.idempotentReplay, false);
assert.doesNotThrow(() => validateExpectedBindings(first.record));

const eventKeys = [...store.values.keys()].filter((key) => key.startsWith('final-delivery-provider-event/'));
const messageKeys = [...store.values.keys()].filter((key) => key.startsWith('final-delivery-provider-message/'));
assert.equal(eventKeys.length, 1);
assert.equal(messageKeys.length, 1);
assert.notEqual(eventKeys[0].split('/')[1], messageKeys[0].split('/')[1]);
const terminalOutbox = await readIndex(store, fixture.outbox.key);
assert.equal(terminalOutbox.status, 'DELIVERED', 'Terminal outbox state is the durable no-resend latch.');
assert.equal(terminalOutbox.delivery_receipt_sha256, sha256Hex(receipt));
assert.equal(JSON.stringify([...store.values.values()]).includes(receiptValue.provider_event_id), false,
  'Raw provider event/message IDs must not enter durable state.');
assert.equal(JSON.stringify([...store.values.keys()]).includes(receiptValue.provider_event_id), false,
  'Raw provider event/message IDs must not enter durable keys.');

const replay = await acknowledgeFinalDelivery(handoffId, receipt, signature, env, {
  store,
  clock: () => new Date(now.getTime() + 24 * 60 * 60_000),
});
assert.equal(replay.idempotentReplay, true, 'An exact durable replay must remain stable after first-observation freshness.');
assert.deepEqual(replay.record, first.record);

const conflictingValue = receiptFor(record, { provider_message_id: 'different-provider-message' });
const conflictingReceipt = canonicalJson(conflictingValue);
await assert.rejects(acknowledgeFinalDelivery(handoffId, conflictingReceipt, sign(conflictingReceipt), env, {
  store,
  clock: () => new Date(now),
}), /RECEIPT_CONFLICT/, 'A validly signed but different replay must fail.');
await assert.rejects(acknowledgeFinalDelivery(handoffId, receipt, '0'.repeat(64), env, {
  store,
  clock: () => new Date(now),
}), /signature mismatch/i);

for (const [field, wrong] of [
  ['handoff_id', 'f'.repeat(64)],
  ['outbox_claim_key_hmac_sha256', 'f'.repeat(64)],
  ['recipient_email_sha256', 'f'.repeat(64)],
  ['production_url_sha256', 'f'.repeat(64)],
  ['netlify_site_id_sha256', 'f'.repeat(64)],
  ['netlify_deploy_id_sha256', 'f'.repeat(64)],
]) {
  const testStore = new FakeStore();
  await seed(testStore, record, fixture.outbox);
  const value = receiptFor(record, { [field]: wrong });
  const raw = canonicalJson(value);
  await assert.rejects(acknowledgeFinalDelivery(handoffId, raw, sign(raw), env, {
    store: testStore,
    clock: () => new Date(now),
  }), /binding mismatch/i, `${field} must bind exactly to stored final state.`);
}

for (const overrides of [
  { delivery_status: 'accepted' },
  { event_type: 'message.accepted' },
  { provider_account_hmac_sha256: 'not-a-digest' },
  { provider_event_id: ' event-with-padding' },
  { provider_message_id: 'message\nwith-control' },
]) {
  const testStore = new FakeStore();
  await seed(testStore, record, fixture.outbox);
  const raw = canonicalJson(receiptFor(record, overrides));
  await assert.rejects(acknowledgeFinalDelivery(handoffId, raw, sign(raw), env, {
    store: testStore,
    clock: () => new Date(now),
  }), /invalid|lowercase SHA-256/i);
}

for (const value of [
  receiptFor(record, { delivered_at: at(-6 * 60_000) }),
  receiptFor(record, { delivered_at: at(30_000) }),
  receiptFor(record, { issued_at: at(-11 * 60_000), delivered_at: at(-11 * 60_000) }),
]) {
  const testStore = new FakeStore();
  await seed(testStore, record, fixture.outbox);
  const raw = canonicalJson(value);
  await assert.rejects(acknowledgeFinalDelivery(handoffId, raw, sign(raw), env, {
    store: testStore,
    clock: () => new Date(now),
  }), /stale or out of order/i);
}
const staleStore = new FakeStore();
await seed(staleStore, record, fixture.outbox);
await assert.rejects(acknowledgeFinalDelivery(handoffId, receipt, signature, env, {
  store: staleStore,
  clock: () => new Date(now.getTime() + 11 * 60_000),
}), /stale or out of order/i, 'A stale receipt cannot make its first durable transition.');

const nonCanonical = JSON.stringify(receiptValue);
assert.notEqual(nonCanonical, receipt);
const nonCanonicalStore = new FakeStore();
await seed(nonCanonicalStore, record, fixture.outbox);
await assert.rejects(acknowledgeFinalDelivery(handoffId, nonCanonical, sign(nonCanonical), env, {
  store: nonCanonicalStore,
  clock: () => new Date(now),
}), /fields are invalid/i);

const earlyStore = new FakeStore();
const earlyRecord = {
  ...record,
  state: 'CLAIMED_VERIFIED',
  final_deploy_attempted_at: null,
  final_deploy_candidate_id: null,
  final_deploy_id: null,
  final_deploy_ready_at: null,
  outbox_claim_status: null,
  outbox_claim_key_hmac_sha256: null,
};
await createEntry(earlyStore, `handoffs/${handoffId}`, earlyRecord);
await assert.rejects(acknowledgeFinalDelivery(handoffId, receipt, signature, env, {
  store: earlyStore,
  clock: () => new Date(now),
}), /STATE_CONFLICT/, 'Delivery acknowledgement must not skip FINAL_DEPLOY_READY.');
const missingOutboxStore = new FakeStore();
await createEntry(missingOutboxStore, `handoffs/${handoffId}`, record);
await assert.rejects(acknowledgeFinalDelivery(handoffId, receipt, signature, env, {
  store: missingOutboxStore,
  clock: () => new Date(now),
}), /OUTBOX_MISSING/, 'A stored handoff is not evidence that its durable outbox exists.');
const conflictingOutboxStore = new FakeStore();
await seed(conflictingOutboxStore, record, fixture.outbox);
conflictingOutboxStore.values.get(fixture.outbox.key).data.status = 'SENT';
await assert.rejects(acknowledgeFinalDelivery(handoffId, receipt, signature, env, {
  store: conflictingOutboxStore,
  clock: () => new Date(now),
}), /OUTBOX_CONFLICT/, 'An unknown or mutated outbox state must fail closed.');
assert.throws(() => validateExpectedBindings({
  ...record,
  final_delivery_receipt_sha256: 'f'.repeat(64),
}), /must be null/i);
assert.throws(() => validateExpectedBindings({
  ...first.record,
  final_delivery_provider_message_id_hmac_sha256: null,
}), /invalid|lowercase SHA-256/i);

// A partially written identity reservation proves the receipt passed its first
// freshness check. Retry can finish after the normal freshness window.
const partialIdentityStore = new FakeStore();
await seed(partialIdentityStore, record, fixture.outbox);
partialIdentityStore.failNextPrefix('final-delivery-provider-message/');
await assert.rejects(acknowledgeFinalDelivery(handoffId, receipt, signature, env, {
  store: partialIdentityStore,
  clock: () => new Date(now),
}), /SIMULATED_PROCESS_CRASH/);
assert.equal([...partialIdentityStore.values.keys()].filter((key) => key.startsWith('final-delivery-provider-event/')).length, 1);
assert.equal((await readIndex(partialIdentityStore, fixture.outbox.key)).status, 'DELIVERY_ACK_PENDING');
const partialRecovered = await acknowledgeFinalDelivery(handoffId, receipt, signature, env, {
  store: partialIdentityStore,
  clock: () => new Date(now.getTime() + 24 * 60 * 60_000),
});
assert.equal(partialRecovered.record.state, 'DELIVERED');
assert.equal((await readIndex(partialIdentityStore, fixture.outbox.key)).status, 'DELIVERED');

const bothIdentitiesStore = new FakeStore();
await seed(bothIdentitiesStore, record, fixture.outbox);
bothIdentitiesStore.failNextStatus(fixture.outbox.key, 'DELIVERED');
await assert.rejects(acknowledgeFinalDelivery(handoffId, receipt, signature, env, {
  store: bothIdentitiesStore,
  clock: () => new Date(now),
}), /SIMULATED_PROCESS_CRASH/);
assert.equal([...bothIdentitiesStore.values.keys()].filter((key) => key.startsWith('final-delivery-provider-')).length, 2);
assert.equal((await readIndex(bothIdentitiesStore, fixture.outbox.key)).status, 'DELIVERY_ACK_PENDING');
const bothRecovered = await acknowledgeFinalDelivery(handoffId, receipt, signature, env, {
  store: bothIdentitiesStore,
  clock: () => new Date(now.getTime() + 24 * 60 * 60_000),
});
assert.equal(bothRecovered.record.state, 'DELIVERED');

// A crash after terminalizing the outbox cannot cause a resend. Retry only
// converges the handoff record and leaves the terminal outbox ETag untouched.
const terminalCrashStore = new FakeStore();
await seed(terminalCrashStore, record, fixture.outbox);
terminalCrashStore.failNextKey(`handoffs/${handoffId}`);
await assert.rejects(acknowledgeFinalDelivery(handoffId, receipt, signature, env, {
  store: terminalCrashStore,
  clock: () => new Date(now),
}), /SIMULATED_PROCESS_CRASH/);
assert.equal((await readEntry(terminalCrashStore, `handoffs/${handoffId}`)).record.state, 'FINAL_DEPLOY_READY');
const terminalBeforeRetry = await readIndexEntry(terminalCrashStore, fixture.outbox.key);
assert.equal(terminalBeforeRetry.value.status, 'DELIVERED');
const recovered = await acknowledgeFinalDelivery(handoffId, receipt, signature, env, {
  store: terminalCrashStore,
  clock: () => new Date(now.getTime() + 24 * 60 * 60_000),
});
assert.equal(recovered.record.state, 'DELIVERED');
assert.equal((await readIndexEntry(terminalCrashStore, fixture.outbox.key)).etag, terminalBeforeRetry.etag,
  'Recovery must not rewrite or reopen a terminal delivery outbox.');

// Provider event/message identities are globally create-only, not scoped to a
// handoff. Replaying the same identities into another signed receipt fails.
const second = makeRecord({
  id: 'f'.repeat(64),
  sessionId: '22222222-2222-4222-8222-222222222222',
  paymentDigest: 'f'.repeat(64),
  siteName: `arc-lead-route-${'e'.repeat(24)}`,
  siteId: '2'.repeat(24),
  deployId: '3'.repeat(24),
});
await seed(store, second.record, second.outbox);
const crossHandoffValue = receiptFor(second.record);
const crossHandoffReceipt = canonicalJson(crossHandoffValue);
await assert.rejects(acknowledgeFinalDelivery(second.record.handoff_id, crossHandoffReceipt, sign(crossHandoffReceipt), env, {
  store,
  clock: () => new Date(now),
}), /IDENTITY_CONFLICT/, 'A provider identity cannot be replayed across handoffs.');
assert.equal((await readEntry(store, `handoffs/${second.record.handoff_id}`)).record.state, 'FINAL_DEPLOY_READY');
assert.equal((await readIndex(store, second.outbox.key)).status, 'CLAIMED');

const competingStore = new FakeStore();
await seed(competingStore, record, fixture.outbox);
const competingValue = receiptFor(record, {
  provider_event_id: 'competing-event-id',
  provider_message_id: 'competing-message-id',
});
const competingReceipt = canonicalJson(competingValue);
const competingResults = await Promise.allSettled([
  acknowledgeFinalDelivery(handoffId, receipt, signature, env, { store: competingStore, clock: () => new Date(now) }),
  acknowledgeFinalDelivery(handoffId, competingReceipt, sign(competingReceipt), env, { store: competingStore, clock: () => new Date(now) }),
]);
assert.equal(competingResults.filter((result) => result.status === 'fulfilled').length, 1,
  'Exactly one signed receipt may acquire a handoff receipt intent.');
assert.equal(competingResults.filter((result) => result.status === 'rejected').length, 1);
assert.match(competingResults.find((result) => result.status === 'rejected').reason.message, /OUTBOX_CONFLICT/);
assert.equal([...competingStore.values.keys()].filter((key) => key.startsWith('final-delivery-provider-')).length, 2,
  'The losing receipt must not leave provider-identity reservations behind.');

const raceStore = new FakeStore();
await seed(raceStore, record, fixture.outbox);
const raced = await Promise.all([
  acknowledgeFinalDelivery(handoffId, receipt, signature, env, { store: raceStore, clock: () => new Date(now) }),
  acknowledgeFinalDelivery(handoffId, receipt, signature, env, { store: raceStore, clock: () => new Date(now) }),
]);
assert.deepEqual(raced.map((result) => result.idempotentReplay).sort(), [false, true],
  'Concurrent exact acknowledgements must converge through CAS.');
assert.equal((await readEntry(raceStore, `handoffs/${handoffId}`)).record.revision, record.revision + 1);
assert.equal((await readIndex(raceStore, fixture.outbox.key)).status, 'DELIVERED');

// Early v2 rows predate the explicit signed route-mode field. Only an exact
// existing form name + recipient binding can be migrated to form mode; a row
// that could also mean no-form is quarantined instead of being guessed.
const preModeV2 = structuredClone(record);
delete preModeV2.lead_route_mode;
const preModeStore = new FakeStore();
await seed(preModeStore, preModeV2, fixture.outbox);
const migratedPreMode = await readEntry(preModeStore, `handoffs/${preModeV2.handoff_id}`);
assert.equal(migratedPreMode.record.lead_route_mode, 'netlify_form');
assert.doesNotThrow(() => validateExpectedBindings(migratedPreMode.record));
const ambiguousPreMode = structuredClone(preModeV2);
delete ambiguousPreMode.lead_route_recipient_hmac_sha256;
const ambiguousPreModeStore = new FakeStore();
await seed(ambiguousPreModeStore, ambiguousPreMode, fixture.outbox);
await assert.rejects(readEntry(ambiguousPreModeStore, `handoffs/${ambiguousPreMode.handoff_id}`),
  /lead route mode is missing and cannot be inferred safely/i,
  'A v2 row without enough route bindings must remain quarantined.');

// Existing v1 records that already reached the downstream delivery states
// retain their original deterministic site name and are normalized on read.
// Missing lead-recipient HMAC remains null; it is no longer needed after the
// invitation boundary and must not cause an unsafe namespace rewrite.
const legacy = makeRecord({
  schema: LEGACY_HANDOFF_SCHEMA,
  id: '9'.repeat(64),
  siteName: `arc-${'8'.repeat(24)}`,
  sessionId: '33333333-3333-4333-8333-333333333333',
  paymentDigest: '9'.repeat(64),
  siteId: '4'.repeat(24),
  deployId: '5'.repeat(24),
});
delete legacy.record.lead_route_recipient_hmac_sha256;
for (const field of [
  'final_delivery_receipt_sha256',
  'final_delivery_provider',
  'final_delivery_provider_account_hmac_sha256',
  'final_delivery_provider_event_id_hmac_sha256',
  'final_delivery_provider_message_id_hmac_sha256',
  'final_delivery_event_type',
  'final_delivery_status',
  'final_delivery_receipt_issued_at',
]) delete legacy.record[field];
const legacyStore = new FakeStore();
await seed(legacyStore, legacy.record, legacy.outbox);
const migrated = await readEntry(legacyStore, `handoffs/${legacy.record.handoff_id}`);
assert.equal(migrated.record.schema, HANDOFF_SCHEMA);
assert.equal(migrated.record.netlify_site_name, legacy.record.netlify_site_name);
assert.equal(migrated.record.lead_route_recipient_hmac_sha256, null);
assert.equal(migrated.record.final_delivery_receipt_sha256, null);
assert.doesNotThrow(() => validateExpectedBindings(migrated.record));
const legacyReceipt = canonicalJson(receiptFor(migrated.record, {
  provider_event_id: 'legacy-event-id',
  provider_message_id: 'legacy-message-id',
}));
const legacyDelivered = await acknowledgeFinalDelivery(migrated.record.handoff_id, legacyReceipt, sign(legacyReceipt), env, {
  store: legacyStore,
  clock: () => new Date(now),
});
assert.equal(legacyDelivered.record.state, 'DELIVERED');
assert.equal(legacyDelivered.record.schema, HANDOFF_SCHEMA);
assert.equal(legacyDelivered.record.netlify_site_name, `arc-${'8'.repeat(24)}`);
const unverifiableLegacyStore = new FakeStore();
await createEntry(unverifiableLegacyStore, `handoffs/${legacy.record.handoff_id}`, {
  ...legacy.record,
  state: 'DELIVERED',
  delivered_at: at(-30_000),
});
await assert.rejects(readEntry(unverifiableLegacyStore, `handoffs/${legacy.record.handoff_id}`),
  /lacks authoritative delivery evidence/i,
  'A legacy DELIVERED assertion without an authoritative receipt is quarantined, not silently migrated.');

assert.equal(deliveryAckConfig.path, '/internal/arc2/final-delivery-ack');
assert.equal(deliveryAckConfig.method, 'POST');
assert.equal(typeof deliveryAckConfig.rateLimit.windowLimit, 'number');
const handlerSource = await readFile(new URL('../netlify/functions/arc2-final-delivery-ack.mjs', import.meta.url), 'utf8');
assert.doesNotMatch(handlerSource, /gmail|sendgrid|postmark|resend|nodemailer|sendEmail|send_message/i,
  'Acknowledgement endpoint must not send email.');
assert.match(handlerSource, /ARC_FINAL_DELIVERY_ACK_SECRET/);
assert.doesNotMatch(handlerSource, /authenticateBearer\(request, process\.env\.ARC_HANDOFF_TRIGGER_SECRET\)/,
  'The generic handoff trigger secret must not authenticate provider delivery receipts.');

const endpointStore = new FakeStore();
const endpointNow = new Date();
const endpointFixture = makeRecord();
const endpointRecord = {
  ...endpointFixture.record,
  updated_at: new Date(endpointNow.getTime() - 60_000).toISOString(),
  final_deploy_ready_at: new Date(endpointNow.getTime() - 60_000).toISOString(),
};
await seed(endpointStore, endpointRecord, endpointFixture.outbox);
const endpointReceiptValue = receiptFor(endpointRecord, {
  provider_event_id: 'endpoint-event-id',
  provider_message_id: 'endpoint-message-id',
  delivered_at: new Date(endpointNow.getTime() - 30_000).toISOString(),
  issued_at: endpointNow.toISOString(),
});
const endpointReceipt = canonicalJson(endpointReceiptValue);
const body = JSON.stringify({
  handoff_id: handoffId,
  delivery_receipt_evidence: endpointReceipt,
  delivery_receipt_evidence_hmac_sha256: sign(endpointReceipt),
});
const relevantKeys = [...Object.keys(env)];
const prior = Object.fromEntries(relevantKeys.map((key) => [key, process.env[key]]));
Object.assign(process.env, env);
const originalFetch = globalThis.fetch;
let externalCalls = 0;
globalThis.fetch = async () => {
  externalCalls += 1;
  throw new Error('External network calls are forbidden in delivery acknowledgement.');
};
try {
  const oversized = new Request('https://arcweb.onl/internal/arc2/final-delivery-ack', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.ARC_FINAL_DELIVERY_ACK_SECRET}`, 'content-type': 'application/json' },
    body: new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(30_001)); controller.close(); } }),
    duplex: 'half',
  });
  const oversizedResponse = await deliveryAckHandler(oversized, {
    get arc2Store() { throw new Error('Oversized delivery receipt must not touch storage.'); },
  });
  assert.equal(oversizedResponse.status, 413);
  assert.deepEqual(await oversizedResponse.json(), { error: 'delivery_receipt_too_large' });
  assert.equal(externalCalls, 0, 'Oversized delivery receipt must not perform provider access.');

  const request = (bearer = env.ARC_FINAL_DELIVERY_ACK_SECRET) => new Request('https://arcweb.onl/internal/arc2/final-delivery-ack', {
    method: 'POST',
    headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' },
    body,
  });
  const genericSecretResponse = await deliveryAckHandler(request(env.ARC_HANDOFF_TRIGGER_SECRET), { arc2Store: endpointStore });
  assert.equal(genericSecretResponse.status, 401, 'The generic trigger secret cannot invoke final delivery acknowledgement.');
  const firstResponse = await deliveryAckHandler(request(), { arc2Store: endpointStore });
  const firstBody = await firstResponse.json();
  const replayResponse = await deliveryAckHandler(request(), { arc2Store: endpointStore });
  const replayBody = await replayResponse.json();
  assert.equal(firstResponse.status, 200);
  assert.equal(replayResponse.status, 200);
  assert.deepEqual(replayBody, firstBody, 'Endpoint exact replay must have a stable response.');
  assert.deepEqual(firstBody, { handoff_id: handoffId, delivery_status: 'DELIVERED', delivered_at: endpointReceiptValue.delivered_at });
  assert.equal(externalCalls, 0);

  const unauthorized = await deliveryAckHandler(new Request('https://arcweb.onl/internal/arc2/final-delivery-ack', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body,
  }), { arc2Store: endpointStore });
  assert.equal(unauthorized.status, 401);
  const wrongMethod = await deliveryAckHandler(new Request('https://arcweb.onl/internal/arc2/final-delivery-ack', {
    method: 'GET', headers: { authorization: `Bearer ${env.ARC_FINAL_DELIVERY_ACK_SECRET}` },
  }), { arc2Store: endpointStore });
  assert.equal(wrongMethod.status, 405);
  const wrongType = await deliveryAckHandler(new Request('https://arcweb.onl/internal/arc2/final-delivery-ack', {
    method: 'POST', headers: { authorization: `Bearer ${env.ARC_FINAL_DELIVERY_ACK_SECRET}`, 'content-type': 'text/plain' }, body,
  }), { arc2Store: endpointStore });
  assert.equal(wrongType.status, 415);

  const endpointConflictReceipt = canonicalJson(receiptFor(endpointRecord, {
    ...endpointReceiptValue,
    provider_message_id: 'different-endpoint-message',
  }));
  const conflictBody = JSON.stringify({
    handoff_id: handoffId,
    delivery_receipt_evidence: endpointConflictReceipt,
    delivery_receipt_evidence_hmac_sha256: sign(endpointConflictReceipt),
  });
  const conflictResponse = await deliveryAckHandler(new Request('https://arcweb.onl/internal/arc2/final-delivery-ack', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.ARC_FINAL_DELIVERY_ACK_SECRET}`, 'content-type': 'application/json' },
    body: conflictBody,
  }), { arc2Store: endpointStore });
  assert.equal(conflictResponse.status, 409);
  assert.deepEqual(await conflictResponse.json(), { error: 'delivery_acknowledgement_conflict' });
} finally {
  globalThis.fetch = originalFetch;
  for (const [key, value] of Object.entries(prior)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

const disabledPrior = process.env.ARC_FINAL_DELIVERY_ACK_SECRET;
delete process.env.ARC_FINAL_DELIVERY_ACK_SECRET;
try {
  const disabled = await deliveryAckHandler(new Request('https://arcweb.onl/internal/arc2/final-delivery-ack', { method: 'POST' }), {
    get arc2Store() { throw new Error('Disabled endpoint must not touch storage.'); },
  });
  assert.equal(disabled.status, 503);
  assert.deepEqual(await disabled.json(), { error: 'handoff_disabled' });
} finally {
  if (disabledPrior !== undefined) process.env.ARC_FINAL_DELIVERY_ACK_SECRET = disabledPrior;
}

console.log('ARC2 final delivery acknowledgement contract passed.');
