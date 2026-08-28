import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { createFirstPartyRetentionWorkerHandler } from
  '../netlify/functions/first-party-retention-worker.mjs';
import { beginRetentionFreeze, beginRetentionProducerOperation } from
  '../netlify/lib/retention-generation-fence-core.mjs';
import { enqueueRetentionGenerationFenceCriticalAlert } from
  '../netlify/lib/retention-generation-fence-alert-queue-core.mjs';

class FakeStore {
  constructor() {
    this.entries = new Map();
    this.sequence = 0;
    this.failNextAlertWrite = false;
  }

  async getWithMetadata(key) {
    const entry = this.entries.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }

  async setJSON(key, data, options = {}) {
    if (this.failNextAlertWrite && key.startsWith('alerts/retention-generation-fence/')) {
      this.failNextAlertWrite = false;
      throw new Error('simulated operations alert queue outage');
    }
    const current = this.entries.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `worker-alert-etag-${++this.sequence}`;
    this.entries.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }

  async delete() {
    throw new Error('Unconditional deletes are forbidden.');
  }

  list({ prefix, paginate }) {
    assert.equal(paginate, true);
    const blobs = [...this.entries.keys()].filter((key) => key.startsWith(prefix))
      .sort().map((key) => ({ key }));
    return (async function *pages() { yield { blobs }; })();
  }
}

const digest = (value) => createHash('sha256').update(value).digest('hex');
const origin = Date.parse('2036-01-02T03:04:05.000Z');
const at = (milliseconds = 0) => new Date(origin + milliseconds);
const secretNames = [
  'ARC_FIRST_PARTY_RETENTION_HMAC_SECRET',
  'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET',
  'ARC_INTAKE_ABUSE_HMAC_SECRET',
  'ARC_REVIEW_RECORD_HMAC_SECRET',
  'ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET',
  'ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET',
  'ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET',
  'ARC_HANDOFF_STATE_SECRET',
  'ARC_EMAIL_CLAIM_BINDING_SECRET',
  'ARC_STRIPE_REVERSAL_HMAC_SECRET',
  'ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET',
  'ARC_OPERATIONS_AUDIT_SECRET',
  'ARC_OPERATIONS_ALERT_HMAC_SECRET',
];
const workerEnv = {
  ...Object.fromEntries(secretNames.map((name, index) => [
    name, `worker-alert-${String(index).padStart(2, '0')}-unique-secret-abcdefghijklmnopqrstuvwxyz`,
  ])),
  ARC_FIRST_PARTY_RETENTION_ENABLED: 'true',
  ARC_FIRST_PARTY_RETENTION_UNPAID_DAYS: '730',
  ARC_FIRST_PARTY_RETENTION_PAID_DAYS: '2555',
  ARC_OPERATIONS_AUDIT_ENABLED: 'true',
};

const changedNames = [...Object.keys(workerEnv), 'ARC_OPERATIONS_AUDIT_ENABLED'];
const priorEnvironment = new Map(changedNames.map((name) => [name, process.env[name]]));
const installEnvironment = (env) => {
  for (const name of changedNames) delete process.env[name];
  Object.assign(process.env, env);
};
const restoreEnvironment = () => {
  for (const name of changedNames) {
    const prior = priorEnvironment.get(name);
    if (prior === undefined) delete process.env[name];
    else process.env[name] = prior;
  }
};

const descriptor = (label) => ({
  route: 'worker-alert-contract',
  subject_hmac_sha256: digest(`${label}:subject`),
  idempotency_key_sha256: digest(`${label}:idempotency`),
  source_record_sha256: digest(`${label}:source`),
  mutation_sha256: digest(`${label}:mutation`),
  output_record_sha256: digest(`${label}:output`),
});
const freezeDescriptor = (label) => ({
  generation: 0,
  subject_hmac_sha256: digest(`${label}:subject`),
  manifest_sha256: digest(`${label}:manifest`),
  manifest_entry_count: 1,
});
const stores = () => ({
  controlStore: new FakeStore(),
  abuseStore: new FakeStore(),
  reviewStore: new FakeStore(),
  revisionStore: new FakeStore(),
  handoffStore: new FakeStore(),
  paymentStore: new FakeStore(),
  alertStore: new FakeStore(),
});

try {
  const handler = createFirstPartyRetentionWorkerHandler();

  installEnvironment({});
  const disabled = await handler(new Request('https://arcweb.onl/.netlify/functions/retention'));
  assert.equal(disabled.status, 204, 'The scheduled worker must remain an exact no-op while OFF.');

  installEnvironment({ ...workerEnv, ARC_OPERATIONS_AUDIT_ENABLED: 'false' });
  const unavailableStores = stores();
  const unavailable = await handler(new Request('https://arcweb.onl/.netlify/functions/retention'),
    unavailableStores);
  assert.equal(unavailable.status, 503,
    'Retention must fail closed before touching stores when its signed alert queue is unavailable.');
  assert.equal(unavailableStores.controlStore.entries.size, 0);

  installEnvironment(workerEnv);
  const staleStores = stores();
  const operation = descriptor('genuinely-stale-writing');
  await beginRetentionProducerOperation(staleStores.controlStore, operation, process.env, {
    clock: () => at(), staleAfterMs: 1_000,
  });
  staleStores.alertStore.failNextAlertWrite = true;
  const first = await handler(new Request('https://arcweb.onl/.netlify/functions/retention'), {
    ...staleStores,
    clock: () => at(1_000),
  });
  assert.equal(first.status, 503,
    'A queue outage must fail the worker closed even after immutable fence alert evidence exists.');
  assert.equal([...staleStores.alertStore.entries.keys()].filter((key) =>
    key.startsWith('alerts/retention-generation-fence/')).length, 0);

  const retry = await handler(new Request('https://arcweb.onl/.netlify/functions/retention'), {
    ...staleStores,
    clock: () => at(2_000),
  });
  assert.equal(retry.status, 200,
    'Existing signed fence evidence must retry operations queue delivery after a transient outage.');
  const retryBody = await retry.json();
  assert.equal(retryBody.state, 'BLOCKED');
  assert.equal(retryBody.critical_alert, true);
  assert.equal(retryBody.reason_code, 'FENCE_COMPLETION_RECEIPT_MISSING');
  const queueEntries = [...staleStores.alertStore.entries.entries()].filter(([key]) =>
    key.startsWith('alerts/retention-generation-fence/'));
  assert.equal(queueEntries.length, 1);
  const [queueKey, queueEntry] = queueEntries[0];
  assert.match(queueKey, /^alerts\/retention-generation-fence\/[a-f0-9]{64}$/);
  assert.equal(queueEntry.data.category, 'retention-generation-fence');
  assert.equal(queueEntry.data.severity, 'critical');
  assert.equal(queueEntry.data.detail_code, 'fence-completion-receipt-missing');
  assert.equal(queueEntry.data.delivery_status, 'PENDING');
  assert.equal(queueEntry.data.contains_customer_data, false);
  assert.equal(JSON.stringify(queueEntry.data).includes('genuinely-stale-writing'), false);

  const replay = await handler(new Request('https://arcweb.onl/.netlify/functions/retention'), {
    ...staleStores,
    clock: () => at(3_000),
  });
  assert.equal(replay.status, 200);
  assert.equal([...staleStores.alertStore.entries.keys()].filter((key) =>
    key.startsWith('alerts/retention-generation-fence/')).length, 1,
  'Repeated stale recovery must deduplicate in the signed operations alert queue.');

  const frozenStores = stores();
  const frozenOperation = freezeDescriptor('genuinely-stale-frozen');
  await beginRetentionFreeze(frozenStores.controlStore, frozenOperation, process.env, {
    clock: () => at(4_000), staleAfterMs: 1_000,
  });
  const emitFrozenAlert = (clock) => (alert) =>
    enqueueRetentionGenerationFenceCriticalAlert(alert, process.env, {
      store: frozenStores.alertStore,
      clock,
    });
  frozenStores.alertStore.failNextAlertWrite = true;
  await assert.rejects(beginRetentionFreeze(
    frozenStores.controlStore,
    frozenOperation,
    process.env,
    {
      clock: () => at(5_000),
      staleAfterMs: 1_000,
      emitCriticalAlert: emitFrozenAlert(() => at(5_000)),
    },
  ), /simulated operations alert queue outage/,
  'A stale FROZEN retry must fail closed when its operations alert cannot be queued.');
  const frozenRetry = await beginRetentionFreeze(
    frozenStores.controlStore,
    frozenOperation,
    process.env,
    {
      clock: () => at(5_001),
      staleAfterMs: 1_000,
      emitCriticalAlert: emitFrozenAlert(() => at(5_001)),
    },
  );
  assert.equal(frozenRetry.state, 'FROZEN');
  assert.equal(frozenRetry.acquired, true);
  assert.equal(frozenRetry.critical_alert, true);
  const frozenQueueEntries = [...frozenStores.alertStore.entries.entries()].filter(([key]) =>
    key.startsWith('alerts/retention-generation-fence/'));
  assert.equal(frozenQueueEntries.length, 1,
    'Existing signed FROZEN evidence must retry and deduplicate queue delivery.');
  assert.equal(frozenQueueEntries[0][1].data.detail_code,
    'fence-stale-exact-retry-resumed');
  assert.equal(frozenQueueEntries[0][1].data.contains_customer_data, false);
  const liveFrozenContention = await beginRetentionFreeze(
    frozenStores.controlStore,
    frozenOperation,
    process.env,
    {
      clock: () => at(5_002),
      staleAfterMs: 1_000,
      emitCriticalAlert: () => {
        throw new Error('Live FROZEN contention must not emit an alert.');
      },
    },
  );
  assert.equal(liveFrozenContention.retryable, true);
  assert.equal(frozenStores.alertStore.entries.size, 1);

  const contentionStores = stores();
  await beginRetentionProducerOperation(contentionStores.controlStore,
    descriptor('normal-contention'), process.env, { clock: () => at(10_000) });
  const contention = await handler(new Request('https://arcweb.onl/.netlify/functions/retention'), {
    ...contentionStores,
    clock: () => at(10_001),
  });
  assert.equal(contention.status, 200);
  const contentionBody = await contention.json();
  assert.equal(contentionBody.state, 'IN_PROGRESS');
  assert.equal(contentionBody.critical_alert, false);
  assert.equal(contentionStores.alertStore.entries.size, 0,
    'Ordinary live lock contention must retry without creating an alert.');
} finally {
  restoreEnvironment();
}

console.log('ARC first-party retention worker alert contract passed.');
