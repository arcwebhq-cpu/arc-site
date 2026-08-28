import assert from 'node:assert/strict';

import {
  FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV,
  createFirstPartyRetentionLegalHoldWriterHandler,
  firstPartyRetentionLegalHoldWriterConfiguration,
  firstPartyRetentionLegalHoldWriterContract,
} from '../netlify/functions/first-party-retention-legal-hold.mjs';
import {
  buildFirstPartyLegalHoldRecord,
  firstPartyLegalHoldKey,
} from '../netlify/lib/first-party-retention-core.mjs';
import {
  RETENTION_GENERATION_FENCE_STATE_KEY,
  RETENTION_GENERATION_FENCE_STORE,
  readRetentionGenerationFence,
} from '../netlify/lib/retention-generation-fence-core.mjs';

class FakeStore {
  constructor(label) {
    this.label = label;
    this.sequence = 0;
    this.values = new Map();
    this.modifiedByKey = new Map();
    this.fenceReadPause = null;
    this.failNextAlertWrite = false;
  }

  pauseNextFenceStateRead() {
    let enteredResolve;
    let releaseResolve;
    const entered = new Promise((resolve) => { enteredResolve = resolve; });
    const released = new Promise((resolve) => { releaseResolve = resolve; });
    this.fenceReadPause = { armed: true, enteredResolve, released };
    return { entered, release: releaseResolve };
  }

  async getWithMetadata(key, options = {}) {
    assert.equal(options.type, 'json');
    assert.equal(options.consistency, 'strong');
    if (key === RETENTION_GENERATION_FENCE_STATE_KEY && this.fenceReadPause?.armed) {
      const pause = this.fenceReadPause;
      pause.armed = false;
      pause.enteredResolve();
      await pause.released;
    }
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }

  async setJSON(key, data, options = {}) {
    if (this.failNextAlertWrite && key.startsWith('alerts/retention-generation-fence/')) {
      this.failNextAlertWrite = false;
      throw new Error('simulated legal-hold alert queue outage');
    }
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && (!current || current.etag !== options.onlyIfMatch)) {
      return { modified: false };
    }
    const etag = `${this.label}-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    this.modifiedByKey.set(key, (this.modifiedByKey.get(key) || 0) + 1);
    return { modified: true, etag };
  }
}

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
  FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV,
];
const testEnv = {
  ...Object.fromEntries(secretNames.map((name, index) => [name,
    `legal-hold-writer-${String(index).padStart(2, '0')}-unique-secret-0123456789abcdef`])),
  ARC_FIRST_PARTY_RETENTION_ENABLED: 'true',
  ARC_FIRST_PARTY_RETENTION_UNPAID_DAYS: '730',
  ARC_FIRST_PARTY_RETENTION_PAID_DAYS: '2555',
  ARC_OPERATIONS_AUDIT_ENABLED: 'true',
};
const priorEnv = Object.fromEntries(Object.keys(testEnv).map((name) => [name, process.env[name]]));
Object.assign(process.env, testEnv);

const input = Object.freeze({
  family: 'review',
  subject_hmac_sha256: 'a'.repeat(64),
  reason_code: 'LEGAL',
  issued_at: '2036-08-28T12:00:00.000Z',
  expires_at: null,
});
const bearer = testEnv[FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV];
const at = (offsetMs = 0) => new Date(Date.parse(input.issued_at) + offsetMs);

function request({ token = bearer, body = input, method = 'POST', contentType = 'application/json' } = {}) {
  const headers = { 'content-type': contentType };
  if (token !== null) headers.authorization = `Bearer ${token}`;
  return new Request('https://arcweb.onl/api/internal/retention/legal-hold', {
    method,
    headers,
    ...(method === 'GET' ? {} : { body: JSON.stringify(body) }),
  });
}

try {
  assert.equal(firstPartyRetentionLegalHoldWriterContract.path,
    '/api/internal/retention/legal-hold');
  assert.equal(firstPartyRetentionLegalHoldWriterContract.fence_store,
    RETENTION_GENERATION_FENCE_STORE);
  assert.equal(firstPartyRetentionLegalHoldWriterConfiguration(process.env).enabled, true);
  assert.equal(firstPartyRetentionLegalHoldWriterConfiguration({
    ...process.env,
    [FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV]:
      process.env.ARC_FIRST_PARTY_RETENTION_HMAC_SECRET,
  }).enabled, false, 'The operator bearer cannot reuse retention signing material.');

  // Authentication and shape checks happen before a Blob handle is opened.
  {
    const handler = createFirstPartyRetentionLegalHoldWriterHandler();
    for (const unauthorized of [request({ token: null }), request({ token: 'x'.repeat(32) })]) {
      const context = {};
      Object.defineProperty(context, 'retentionStore', {
        get() { throw new Error('Unauthorized legal-hold calls must not open the store.'); },
      });
      const result = await handler(unauthorized, context);
      assert.equal(result.status, 401);
      assert.deepEqual(await result.json(), { error: 'unauthorized' });
    }
    const extraField = await handler(request({ body: { ...input, note: 'must-not-persist' } }), {
      get retentionStore() { throw new Error('Invalid legal-hold bodies must not open the store.'); },
    });
    assert.equal(extraField.status, 400);
    assert.deepEqual(await extraField.json(), { error: 'invalid_legal_hold' });
  }

  // A normal authenticated hold writes one signed record through the global
  // producer gate and returns to OPEN(N+1).
  {
    const store = new FakeStore('success');
    const result = await createFirstPartyRetentionLegalHoldWriterHandler()(request(), {
      retentionStore: store,
      clock: () => at(),
      staleAfterMs: 1_000,
    });
    assert.equal(result.status, 200);
    const response = await result.json();
    assert.equal(response.accepted, true);
    assert.match(response.operation_hmac_sha256, /^[a-f0-9]{64}$/);
    const holdKey = firstPartyLegalHoldKey(input.family, input.subject_hmac_sha256);
    assert.deepEqual(store.values.get(holdKey)?.data,
      buildFirstPartyLegalHoldRecord(input, process.env));
    const fence = await readRetentionGenerationFence(store, process.env);
    assert.equal(fence.record.status, 'OPEN');
    assert.equal(fence.record.generation, 1);
  }

  // A second same-key hold may commit after this request has created its
  // immutable intent but before it reads/acquires OPEN. Operation identity must
  // not bind a pre-lock hold snapshot: both requests complete in generation
  // order and the delayed request CAS-replaces the current hold under WRITING.
  {
    const store = new FakeStore('pre-lock-race');
    const handler = createFirstPartyRetentionLegalHoldWriterHandler();
    const competing = Object.freeze({
      ...input,
      reason_code: 'SECURITY',
      issued_at: '2036-08-28T12:00:01.000Z',
    });
    const paused = store.pauseNextFenceStateRead();
    const delayedPromise = handler(request({ body: input }), {
      retentionStore: store,
      clock: () => at(),
      staleAfterMs: 1_000,
    });
    await paused.entered;
    let competingResult;
    try {
      competingResult = await handler(request({ body: competing }), {
        retentionStore: store,
        clock: () => at(),
        staleAfterMs: 1_000,
      });
    } finally {
      paused.release();
    }
    assert.equal(competingResult.status, 200);
    const delayedResult = await delayedPromise;
    assert.equal(delayedResult.status, 200,
      'Generation drift before acquisition must not strand a stale-source WRITING operation.');
    const competingBody = await competingResult.json();
    const delayedBody = await delayedResult.json();
    assert.notEqual(competingBody.operation_hmac_sha256, delayedBody.operation_hmac_sha256);
    const holdKey = firstPartyLegalHoldKey(input.family, input.subject_hmac_sha256);
    assert.deepEqual(store.values.get(holdKey)?.data,
      buildFirstPartyLegalHoldRecord(input, process.env));
    const fence = await readRetentionGenerationFence(store, process.env);
    assert.equal(fence.record.status, 'OPEN');
    assert.equal(fence.record.generation, 2);
    assert.equal([...store.values.keys()].some((key) => key.includes('/critical-alerts/')), false);
  }

  // If the hold CAS succeeds and the process crashes before readback/receipt,
  // WRITING stays closed. The exact stale retry recovers the original signed
  // intent, validates the existing output, and never writes the hold twice.
  {
    const store = new FakeStore('crash');
    const holdKey = firstPartyLegalHoldKey(input.family, input.subject_hmac_sha256);
    let now = at();
    let crash = true;
    const handler = createFirstPartyRetentionLegalHoldWriterHandler();
    const first = await handler(request(), {
      retentionStore: store,
      clock: () => now,
      staleAfterMs: 1_000,
      afterLegalHoldMutation: () => {
        if (crash) {
          crash = false;
          throw new Error('INJECTED_CRASH_AFTER_LEGAL_HOLD_CAS');
        }
      },
    });
    assert.equal(first.status, 503);
    assert.equal(store.modifiedByKey.get(holdKey), 1);
    let fence = await readRetentionGenerationFence(store, process.env);
    assert.equal(fence.record.status, 'WRITING');
    assert.equal(fence.record.generation, 0);

    const earlyContext = {
      retentionStore: store,
      clock: () => at(500),
      staleAfterMs: 1_000,
    };
    Object.defineProperty(earlyContext, 'retentionFenceAlertStore', {
      get() { throw new Error('Normal legal-hold contention must not open the alert queue.'); },
    });
    const early = await handler(request(), earlyContext);
    assert.equal(early.status, 503);
    assert.deepEqual(await early.json(), {
      error: 'retention_generation_fence_contention',
      retryable: true,
    });
    assert.equal(store.modifiedByKey.get(holdKey), 1);

    now = at(1_001);
    const alertStore = new FakeStore('crash-alert');
    alertStore.failNextAlertWrite = true;
    const failedAlertDelivery = await handler(request(), {
      retentionStore: store,
      retentionFenceAlertStore: alertStore,
      clock: () => now,
      staleAfterMs: 1_000,
    });
    assert.equal(failedAlertDelivery.status, 503,
      'A stale legal-hold retry must fail closed when its operations alert cannot enqueue.');
    assert.equal([...alertStore.values.keys()].filter((key) =>
      key.startsWith('alerts/retention-generation-fence/')).length, 0);
    assert.equal((await readRetentionGenerationFence(store, process.env)).record.status,
      'WRITING');

    now = at(1_002);
    const recovered = await handler(request(), {
      retentionStore: store,
      retentionFenceAlertStore: alertStore,
      clock: () => now,
      staleAfterMs: 1_000,
    });
    assert.equal(recovered.status, 200);
    assert.equal((await recovered.json()).accepted, true);
    assert.equal(store.modifiedByKey.get(holdKey), 1,
      'Exact recovery must validate the already-written hold instead of rewriting it.');
    fence = await readRetentionGenerationFence(store, process.env);
    assert.equal(fence.record.status, 'OPEN');
    assert.equal(fence.record.generation, 1);
    assert.ok([...store.values.keys()].some((key) => key.includes('/critical-alerts/')),
      'A genuinely stale partial legal-hold operation must leave a critical alert.');
    const queued = [...alertStore.values.entries()].filter(([key]) =>
      key.startsWith('alerts/retention-generation-fence/'));
    assert.equal(queued.length, 1,
      'Existing signed stale evidence must retry and deduplicate operations queue delivery.');
    assert.equal(queued[0][1].data.category, 'retention-generation-fence');
    assert.equal(queued[0][1].data.contains_customer_data, false);
  }

  // The committed endpoint must not be wrapped in the generic route fence;
  // writeRetentionLegalHoldFenced is itself the outermost producer protocol.
  const source = await (await import('node:fs/promises')).readFile(
    new URL('../netlify/functions/first-party-retention-legal-hold.mjs', import.meta.url), 'utf8');
  assert.match(source, /writeRetentionLegalHoldFenced/);
  assert.doesNotMatch(source, /createRetentionFencedRouteHandler/);
  assert.match(source, /ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER/);
  assert.match(source, /path:\s*'\/api\/internal\/retention\/legal-hold'/);
  assert.ok(source.includes(RETENTION_GENERATION_FENCE_STATE_KEY) === false,
    'The endpoint must not manipulate fence state directly.');
} finally {
  for (const [name, prior] of Object.entries(priorEnv)) {
    if (prior === undefined) delete process.env[name];
    else process.env[name] = prior;
  }
}

console.log('First-party retention legal-hold writer contract passed.');
