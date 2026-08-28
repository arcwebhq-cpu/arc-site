import assert from 'node:assert/strict';

import {
  acknowledgeOperationsAlertDelivery,
  authenticateOperationsAlertWorker,
  claimNextOperationsAlert,
  operationsAlertDeliveryConfiguration,
  operationsAlertWorkerLeaseToken,
  readOperationsAlertDelivery,
} from '../netlify/lib/operations-alert-delivery-core.mjs';
import { readRetentionGenerationFence } from '../netlify/lib/retention-generation-fence-core.mjs';
import ackHandler, { config as ackConfig } from '../netlify/functions/operations-alert-ack.mjs';
import reserveHandler, { config as reserveConfig } from '../netlify/functions/operations-alert-reserve.mjs';

class FakeStore {
  constructor() {
    this.values = new Map();
    this.sequence = 0;
    this.failRouteOutputWrites = 0;
  }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    if (this.failRouteOutputWrites > 0 && key.includes('/route-outputs/')) {
      this.failRouteOutputWrites -= 1;
      throw new Error('injected crash before route output marker');
    }
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    if (options.onlyIfMatch && !current) return { modified: false };
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

const now = new Date('2026-08-27T21:00:00.000Z');
const env = {
  ARC_OPERATIONS_ALERT_DELIVERY_ENABLED: 'true',
  ARC_OPERATIONS_ALERT_DELIVERY_HMAC_SECRET: 'alert-delivery-hmac-secret-unique-0123456789abcdef',
  ARC_OPERATIONS_ALERT_DELIVERY_BEARER: 'alert-delivery-bearer-unique-0123456789abcdef',
  ARC_OPERATIONS_ALERT_RECIPIENT_EMAIL: 'arcwebhq@gmail.com',
  ARC_OPERATIONS_ALERT_EMAIL_PROVIDER: 'provider-test',
  ARC_OPERATIONS_ALERT_SENDER: 'alerts@arcweb.onl',
  ARC_OPERATIONS_ALERT_HMAC_SECRET: 'operations-alert-source-secret-unique-0123456789abcdef',
  ARC_OPERATIONS_AUDIT_ENABLED: 'true',
  ARC_OPERATIONS_AUDIT_SECRET: 'operations-audit-secret-unique-0123456789abcdef',
  ARC_EMAIL_CLAIM_BINDING_SECRET: 'email-claim-binding-secret-unique-0123456789abcdef',
  ARC_HANDOFF_STATE_SECRET: 'handoff-state-secret-unique-0123456789abcdef',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'operations-alert-retention-fence-secret-unique-0123456789abcdef',
};
const alert = {
  schema: 'arc-operational-alert-v1',
  status: 'OPEN',
  category: 'handoff-stuck',
  severity: 'high',
  handoff_id: null,
  subject_hmac_sha256: '1'.repeat(64),
  condition_hmac_sha256: '2'.repeat(64),
  detail_code: 'state-provisioning',
  detected_at: now.toISOString(),
  delivery_status: 'PENDING',
  contains_customer_data: false,
};
const lease = 'lease_token_abcdefghijklmnopqrstuvwxyz_123456';

assert.equal(operationsAlertDeliveryConfiguration(env).enabled, true);
assert.equal(operationsAlertDeliveryConfiguration({}).enabled, false);
assert.equal(operationsAlertDeliveryConfiguration({
  ...env,
  ARC_OPERATIONS_ALERT_DELIVERY_BEARER: env.ARC_OPERATIONS_ALERT_DELIVERY_HMAC_SECRET,
}).enabled, false, 'Alert delivery secrets must be pairwise distinct.');
const firstWorkerLease = operationsAlertWorkerLeaseToken('a'.repeat(64), env);
assert.match(firstWorkerLease, /^[a-f0-9]{64}$/);
assert.equal(operationsAlertWorkerLeaseToken('a'.repeat(64), env), firstWorkerLease,
  'The authenticated reserve worker lease must be stable for an exact delivery retry.');
assert.notEqual(operationsAlertWorkerLeaseToken('b'.repeat(64), env), firstWorkerLease,
  'Worker lease capabilities must be isolated per delivery.');

const alertStore = new FakeStore();
const deliveryStore = new FakeStore();
await alertStore.setJSON('alerts/handoff-stuck/source', alert, { onlyIfNew: true });

const claimed = await claimNextOperationsAlert(alertStore, deliveryStore, env,
  { clock: () => now, leaseToken: lease });
assert.equal(claimed.status, 'OPERATIONS_ALERT_SEND_AUTHORIZED');
assert.equal(claimed.send_alert_email, true);
assert.equal(claimed.recipient_email_private, 'arcwebhq@gmail.com');
assert.equal(claimed.lease_token_private, lease);
assert.match(claimed.email_subject, /^\[ARC HIGH\]/);
assert.doesNotMatch(JSON.stringify([...deliveryStore.values.values()]), /arcwebhq@gmail\.com|alerts@arcweb\.onl/,
  'Durable alert delivery state must not store raw sender or recipient addresses.');

const held = await claimNextOperationsAlert(alertStore, deliveryStore, env,
  { clock: () => new Date(now.getTime() + 60_000), leaseToken: 'another_lease_token_abcdefghijklmnopqrstuvwxyz' });
assert.equal(held.status, 'NO_PENDING_OPERATIONS_ALERTS');

// Concurrent reserve attempts deriving the same delivery-bound capability converge on
// one CAS and return the same live claim; they never advance to another alert.
{
  const concurrentAlerts = new FakeStore();
  const concurrentDeliveries = new FakeStore();
  await concurrentAlerts.setJSON('alerts/handoff-stuck/source', alert, { onlyIfNew: true });
  const [left, right] = await Promise.all([
    claimNextOperationsAlert(concurrentAlerts, concurrentDeliveries, env,
      { clock: () => now }),
    claimNextOperationsAlert(concurrentAlerts, concurrentDeliveries, env,
      { clock: () => now }),
  ]);
  assert.equal(left.status, 'OPERATIONS_ALERT_SEND_AUTHORIZED');
  assert.equal(right.status, 'OPERATIONS_ALERT_SEND_AUTHORIZED');
  assert.equal(left.delivery_hmac_sha256, right.delivery_hmac_sha256);
  const derivedWorkerLease = operationsAlertWorkerLeaseToken(left.delivery_hmac_sha256, env);
  assert.equal(left.lease_token_private, derivedWorkerLease);
  assert.equal(right.lease_token_private, derivedWorkerLease);
  assert.equal([...concurrentDeliveries.values.keys()].filter((key) =>
    key.startsWith('deliveries/')).length, 1);
  const concurrentRecord = await readOperationsAlertDelivery(concurrentDeliveries,
    left.delivery_hmac_sha256, env);
  assert.equal(concurrentRecord.record.attempt_count, 1);
}
await assert.rejects(acknowledgeOperationsAlertDelivery(deliveryStore, {
  delivery_hmac_sha256: claimed.delivery_hmac_sha256,
  lease_token: 'wrong_lease_token_abcdefghijklmnopqrstuvwxyz',
  provider: 'provider-test',
  provider_message_id: 'message-1',
  provider_event_id: 'event-1',
  provider_event_type: 'email.delivered',
  delivered_at: new Date(now.getTime() + 2 * 60_000).toISOString(),
}, env, { clock: () => new Date(now.getTime() + 2 * 60_000) }), /LEASE_INVALID/);

const receiptInput = {
  delivery_hmac_sha256: claimed.delivery_hmac_sha256,
  lease_token: lease,
  provider: 'provider-test',
  provider_message_id: 'message-1',
  provider_event_id: 'event-1',
  provider_event_type: 'email.delivered',
  delivered_at: new Date(now.getTime() + 2 * 60_000).toISOString(),
};
const delivered = await acknowledgeOperationsAlertDelivery(deliveryStore, receiptInput, env,
  { clock: () => new Date(now.getTime() + 2 * 60_000) });
assert.equal(delivered.status, 'OPERATIONS_ALERT_DELIVERED');
assert.match(delivered.receipt_sha256, /^[a-f0-9]{64}$/);
const replay = await acknowledgeOperationsAlertDelivery(deliveryStore, receiptInput, env,
  { clock: () => new Date(now.getTime() + 3 * 60_000) });
assert.equal(replay.status, 'OPERATIONS_ALERT_DELIVERY_ALREADY_RECORDED');
const stored = await readOperationsAlertDelivery(deliveryStore, claimed.delivery_hmac_sha256, env);
assert.equal(stored.record.state, 'DELIVERED');
assert.equal(stored.record.provider_message_id_hmac_sha256.length, 64);
assert.doesNotMatch(JSON.stringify(stored.record), /message-1|event-1/,
  'Provider identifiers must be HMACed before persistence.');

// A capability returned for one delivery cannot acknowledge a later alert.
{
  const isolatedAlerts = new FakeStore();
  const isolatedDeliveries = new FakeStore();
  await isolatedAlerts.setJSON('alerts/a-first', alert, { onlyIfNew: true });
  await isolatedAlerts.setJSON('alerts/b-second', {
    ...alert,
    subject_hmac_sha256: '3'.repeat(64),
    condition_hmac_sha256: '4'.repeat(64),
    detail_code: 'state-claim-delayed',
  }, { onlyIfNew: true });
  const first = await claimNextOperationsAlert(isolatedAlerts, isolatedDeliveries, env,
    { clock: () => now });
  await acknowledgeOperationsAlertDelivery(isolatedDeliveries, {
    delivery_hmac_sha256: first.delivery_hmac_sha256,
    lease_token: first.lease_token_private,
    provider: 'provider-test',
    provider_message_id: 'isolated-message-1',
    provider_event_id: 'isolated-event-1',
    provider_event_type: 'email.delivered',
    delivered_at: new Date(now.getTime() + 60_000).toISOString(),
  }, env, { clock: () => new Date(now.getTime() + 60_000) });
  const second = await claimNextOperationsAlert(isolatedAlerts, isolatedDeliveries, env,
    { clock: () => new Date(now.getTime() + 2 * 60_000) });
  assert.notEqual(second.delivery_hmac_sha256, first.delivery_hmac_sha256);
  assert.notEqual(second.lease_token_private, first.lease_token_private);
  await assert.rejects(acknowledgeOperationsAlertDelivery(isolatedDeliveries, {
    delivery_hmac_sha256: second.delivery_hmac_sha256,
    lease_token: first.lease_token_private,
    provider: 'provider-test',
    provider_message_id: 'isolated-message-2',
    provider_event_id: 'isolated-event-2',
    provider_event_type: 'email.delivered',
    delivered_at: new Date(now.getTime() + 3 * 60_000).toISOString(),
  }, env, { clock: () => new Date(now.getTime() + 3 * 60_000) }), /LEASE_INVALID/);
}

const recoveryAlerts = new FakeStore();
const recoveryDeliveries = new FakeStore();
await recoveryAlerts.setJSON('alerts/handoff-stuck/source', alert, { onlyIfNew: true });
await claimNextOperationsAlert(recoveryAlerts, recoveryDeliveries, env,
  { clock: () => now, leaseToken: lease });
const recovered = await claimNextOperationsAlert(recoveryAlerts, recoveryDeliveries, env, {
  clock: () => new Date(now.getTime() + 11 * 60_000),
  leaseToken: 'replacement_lease_token_abcdefghijklmnopqrstuvwxyz',
});
assert.equal(recovered.status, 'OPERATIONS_ALERT_SEND_AUTHORIZED');
const recoveredRecord = await readOperationsAlertDelivery(recoveryDeliveries,
  recovered.delivery_hmac_sha256, env);
assert.equal(recoveredRecord.record.attempt_count, 2);

const authorizedRequest = new Request('https://arcweb.onl/api/internal/operations-alert/reserve', {
  method: 'POST', headers: { authorization: `Bearer ${env.ARC_OPERATIONS_ALERT_DELIVERY_BEARER}` },
});
assert.equal(authenticateOperationsAlertWorker(authorizedRequest, env), true);
assert.equal(authenticateOperationsAlertWorker(new Request(authorizedRequest.url), env), false);

const previous = { ...process.env };
Object.assign(process.env, env);
try {
  const functionAlerts = new FakeStore();
  const functionDeliveries = new FakeStore();
  await functionAlerts.setJSON('alerts/handoff-stuck/source', alert, { onlyIfNew: true });
  const reserveResponse = await reserveHandler(authorizedRequest, {
    alertStore: functionAlerts,
    deliveryStore: functionDeliveries,
    retentionFenceStore: new FakeStore(),
    clock: () => now,
  });
  assert.equal(reserveResponse.status, 200);
  const reserved = await reserveResponse.json();
  assert.equal(reserved.send_alert_email, true);
  assert.equal(reserved.lease_token_private,
    operationsAlertWorkerLeaseToken(reserved.delivery_hmac_sha256, env));
  const ackRequest = new Request('https://arcweb.onl/api/internal/operations-alert/ack', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.ARC_OPERATIONS_ALERT_DELIVERY_BEARER}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      ...receiptInput,
      delivery_hmac_sha256: reserved.delivery_hmac_sha256,
      lease_token: reserved.lease_token_private,
    }),
  });
  const ackResponse = await ackHandler(ackRequest, {
    deliveryStore: functionDeliveries,
    retentionFenceStore: new FakeStore(),
    clock: () => new Date(now.getTime() + 2 * 60_000),
  });
  assert.equal(ackResponse.status, 200);
  assert.equal((await ackResponse.json()).delivered, true);

  // If the alert claim commits but the outer fence crashes before its output
  // marker, the stale exact retry must return that same claim. A second pending
  // alert remains untouched.
  const crashAlerts = new FakeStore();
  const crashDeliveries = new FakeStore();
  const crashFence = new FakeStore();
  const crashFenceAlerts = new FakeStore();
  crashFence.failRouteOutputWrites = 1;
  await crashAlerts.setJSON('alerts/a-first', alert, { onlyIfNew: true });
  await crashAlerts.setJSON('alerts/b-second', {
    ...alert,
    subject_hmac_sha256: '3'.repeat(64),
    condition_hmac_sha256: '4'.repeat(64),
    detail_code: 'state-claim-delayed',
  }, { onlyIfNew: true });
  const firstCrash = await reserveHandler(authorizedRequest, {
    alertStore: crashAlerts,
    deliveryStore: crashDeliveries,
    retentionFenceStore: crashFence,
    retentionFenceAlertStore: crashFenceAlerts,
    clock: () => now,
  });
  assert.equal(firstCrash.status, 503);
  assert.deepEqual(await firstCrash.json(), {
    error: 'retention_generation_fence_unavailable',
  });
  assert.equal([...crashDeliveries.values.keys()].filter((key) =>
    key.startsWith('deliveries/')).length, 1);
  const firstDelivery = [...crashDeliveries.values.entries()].find(([key]) =>
    key.startsWith('deliveries/'))[1].data;
  assert.equal(firstDelivery.state, 'CLAIMED');

  const exactRetry = await reserveHandler(authorizedRequest, {
    alertStore: crashAlerts,
    deliveryStore: crashDeliveries,
    retentionFenceStore: crashFence,
    retentionFenceAlertStore: crashFenceAlerts,
    clock: () => new Date(now.getTime() + 2 * 60_000),
  });
  assert.equal(exactRetry.status, 200);
  const retriedClaim = await exactRetry.json();
  assert.equal(retriedClaim.delivery_hmac_sha256, firstDelivery.delivery_hmac_sha256);
  assert.equal(retriedClaim.lease_token_private,
    operationsAlertWorkerLeaseToken(firstDelivery.delivery_hmac_sha256, env));
  assert.equal([...crashDeliveries.values.keys()].filter((key) =>
    key.startsWith('deliveries/')).length, 1,
  'Exact recovery must not lease a second alert.');
  const recoveredFence = await readRetentionGenerationFence(crashFence, process.env);
  assert.equal(recoveredFence.record.status, 'OPEN');
  assert.equal(recoveredFence.record.generation, 1);
} finally {
  for (const key of Object.keys(env)) {
    if (Object.hasOwn(previous, key)) process.env[key] = previous[key];
    else delete process.env[key];
  }
}

assert.equal(reserveConfig.path, '/api/internal/operations-alert/reserve');
assert.equal(ackConfig.path, '/api/internal/operations-alert/ack');

console.log('operations-alert-delivery-contract: ok');
