import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  RETENTION_ROUTE_OUTPUT_PREFIX,
  RETENTION_ROUTE_OUTPUT_SCHEMA,
  createRetentionFencedRouteHandler,
  validateRetentionRouteOutputMarker,
} from '../netlify/lib/retention-fenced-route-core.mjs';
import {
  RETENTION_GENERATION_FENCE_SECRET_ENV,
  RETENTION_GENERATION_FENCE_STATE_KEY,
  assertRetentionGenerationFenceAuthority,
  readRetentionGenerationFence,
} from '../netlify/lib/retention-generation-fence-core.mjs';

class FakeStore {
  constructor(label) {
    this.label = label;
    this.sequence = 0;
    this.values = new Map();
    this.failProducerCompletionWrites = 0;
    this.failNextAlertWrite = false;
  }

  async getWithMetadata(key, options = {}) {
    assert.equal(options.type, 'json');
    assert.equal(options.consistency, 'strong');
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }

  async setJSON(key, data, options = {}) {
    if (this.failNextAlertWrite && key.startsWith('alerts/retention-generation-fence/')) {
      this.failNextAlertWrite = false;
      throw new Error('injected route alert queue outage');
    }
    if (this.failProducerCompletionWrites > 0 &&
        key.includes('/producer-completions/')) {
      this.failProducerCompletionWrites -= 1;
      throw new Error('injected crash before producer completion receipt');
    }
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && (!current || current.etag !== options.onlyIfMatch)) {
      return { modified: false };
    }
    const etag = `${this.label}-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
}

const clock = () => new Date('2036-08-28T12:00:00.000Z');
const secret = 'arc-route-fence-contract-secret-unique-0123456789abcdef';
const alertEnvironment = {
  ARC_OPERATIONS_AUDIT_ENABLED: 'true',
  ARC_OPERATIONS_AUDIT_SECRET:
    'arc-route-operations-audit-secret-unique-0123456789abcdef',
  ARC_OPERATIONS_ALERT_HMAC_SECRET:
    'arc-route-operations-alert-hmac-secret-unique-0123456789abcdef',
  ARC_EMAIL_CLAIM_BINDING_SECRET:
    'arc-route-email-claim-binding-secret-unique-0123456789abcdef',
  ARC_HANDOFF_STATE_SECRET:
    'arc-route-handoff-state-secret-unique-0123456789abcdef',
};
const changedEnvironmentNames = [
  RETENTION_GENERATION_FENCE_SECRET_ENV,
  ...Object.keys(alertEnvironment),
];
const previousEnvironment = new Map(changedEnvironmentNames.map((name) =>
  [name, process.env[name]]));

function request(marker = 'one') {
  return new Request('https://arcweb.onl/api/contract/mutate', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'idempotency-key': `route-contract-${marker}`,
    },
    body: JSON.stringify({ marker }),
  });
}

function requestWithoutIdempotency(marker = 'one') {
  return new Request('https://arcweb.onl/api/contract/mutate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ marker }),
  });
}

function route(handler, active = () => true) {
  return createRetentionFencedRouteHandler({
    route: 'contract/mutation',
    paths: ['/api/contract/mutate'],
    methods: ['POST'],
    active,
    handler,
  });
}

try {
  // Inactive configurations and non-matching route surfaces are genuine
  // no-ops: they neither require the secret nor touch the global store.
  delete process.env[RETENTION_GENERATION_FENCE_SECRET_ENV];
  {
    let calls = 0;
    const handler = route(async () => {
      calls += 1;
      return new Response(null, { status: 204 });
    }, () => false);
    const response = await handler(request('inactive'), {});
    assert.equal(response.status, 204);
    assert.equal(calls, 1);
  }
  {
    let calls = 0;
    const handler = route(async () => {
      calls += 1;
      return new Response('read-only', { status: 200 });
    });
    const response = await handler(new Request('https://arcweb.onl/api/contract/mutate', {
      method: 'GET',
    }), {});
    assert.equal(response.status, 200);
    assert.equal(calls, 1);
  }

  // An active mutation fails closed before the route handler when the
  // dedicated secret is absent.
  {
    let calls = 0;
    const handler = route(async () => {
      calls += 1;
      return new Response('must-not-run');
    });
    const response = await handler(request('missing-secret'), {
      retentionFenceStore: new FakeStore('missing-secret'),
      retentionFenceClock: clock,
    });
    assert.equal(response.status, 503);
    assert.equal(calls, 0);
    assert.deepEqual(await response.json(), { error: 'retention_generation_fence_unavailable' });
  }

  process.env[RETENTION_GENERATION_FENCE_SECRET_ENV] = secret;
  Object.assign(process.env, alertEnvironment);

  // Oversized active requests terminate before either the mutation handler or
  // the fence store. They must never fall through to an unfenced handler.
  {
    let calls = 0;
    const handler = route(async () => {
      calls += 1;
      return new Response('must-not-run');
    });
    const oversized = new Request('https://arcweb.onl/api/contract/mutate', {
      method: 'POST',
      headers: { 'content-length': '5242881' },
      body: '{}',
    });
    const context = {};
    Object.defineProperty(context, 'retentionFenceStore', {
      get() { throw new Error('Oversized request must not touch the fence store.'); },
    });
    const response = await handler(oversized, context);
    assert.equal(response.status, 413);
    assert.deepEqual(await response.json(), { error: 'request_too_large' });
    assert.equal(calls, 0);
  }

  // A successful active mutation writes a signed, strongly read-back output
  // marker before its receipt advances OPEN(0) to OPEN(1).
  {
    const store = new FakeStore('success');
    let calls = 0;
    const handler = route(async () => {
      calls += 1;
      return new Response(JSON.stringify({ changed: true }), {
        status: 201,
        headers: { 'content-type': 'application/json' },
      });
    });
    const response = await handler(request('success'), {
      retentionFenceStore: store,
      retentionFenceClock: clock,
    });
    assert.equal(response.status, 201);
    assert.deepEqual(await response.json(), { changed: true });
    assert.equal(calls, 1);
    const state = await readRetentionGenerationFence(store, process.env);
    assert.equal(state.record.status, 'OPEN');
    assert.equal(state.record.generation, 1);
    const markers = [...store.values.entries()].filter(([key]) =>
      key.startsWith(RETENTION_ROUTE_OUTPUT_PREFIX));
    assert.equal(markers.length, 1);
    const marker = markers[0][1].data;
    assert.equal(marker.schema, RETENTION_ROUTE_OUTPUT_SCHEMA);
    assert.equal(marker.response_status, 201);
    assert.doesNotThrow(() => validateRetentionRouteOutputMarker(marker, {
      route: 'contract/mutation',
      generation: 0,
    }, process.env));
  }

  // A 5xx may represent a partial route failure, so it is returned verbatim
  // while the generation remains WRITING and no output marker is accepted.
  {
    const store = new FakeStore('failure');
    const handler = route(async () => new Response(JSON.stringify({ error: 'injected' }), {
      status: 502,
      headers: { 'content-type': 'application/json' },
    }));
    const response = await handler(request('failure'), {
      retentionFenceStore: store,
      retentionFenceClock: clock,
    });
    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), { error: 'injected' });
    const state = await readRetentionGenerationFence(store, process.env);
    assert.equal(state.record.status, 'WRITING');
    assert.equal(state.record.generation, 0);
    assert.equal([...store.values.keys()].some((key) => key.startsWith(RETENTION_ROUTE_OUTPUT_PREFIX)), false);
  }

  // Normal contention is retryable HTTP 503 and cannot enter the losing route
  // handler. The winner completes and advances exactly once.
  {
    const store = new FakeStore('contention');
    let calls = 0;
    let enteredResolve;
    let releaseResolve;
    const entered = new Promise((resolve) => { enteredResolve = resolve; });
    const release = new Promise((resolve) => { releaseResolve = resolve; });
    const handler = route(async () => {
      calls += 1;
      enteredResolve();
      await release;
      return new Response(JSON.stringify({ winner: true }), {
        headers: { 'content-type': 'application/json' },
      });
    });
    const context = {
      retentionFenceStore: store,
      retentionFenceClock: clock,
    };
    Object.defineProperty(context, 'retentionFenceAlertStore', {
      get() { throw new Error('Normal route contention must not open the alert queue.'); },
    });
    const winning = handler(request('winner'), context);
    await entered;
    const losing = await handler(request('loser'), context);
    assert.equal(losing.status, 503);
    assert.deepEqual(await losing.json(), {
      error: 'retention_generation_fence_contention', retryable: true,
    });
    assert.equal(calls, 1);
    releaseResolve();
    assert.equal((await winning).status, 200);
    assert.equal((await readRetentionGenerationFence(store, process.env)).record.generation, 1);
  }

  // Provider signatures and delivery timestamps are volatile authentication
  // envelopes, not operation identity. A redelivery of the same provider event
  // in the same generation must contend with the original operation instead of
  // creating a second intent that can later become an orphan writer.
  {
    const store = new FakeStore('resigned-redelivery');
    let calls = 0;
    let enteredResolve;
    let releaseResolve;
    const entered = new Promise((resolve) => { enteredResolve = resolve; });
    const release = new Promise((resolve) => { releaseResolve = resolve; });
    const handler = route(async () => {
      calls += 1;
      enteredResolve();
      await release;
      return new Response(null, { status: 204 });
    });
    const providerRequest = (suffix) => new Request(
      'https://arcweb.onl/api/contract/mutate', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'stripe-signature': `t=${suffix},v1=${suffix.repeat(32)}`,
          'svix-id': 'msg_same_delivery',
          'svix-signature': `v1,${suffix.repeat(32)}`,
          'svix-timestamp': suffix === 'a' ? '2100000000' : '2100000030',
          'x-arc-review-email-signature': suffix.repeat(64),
          'x-arc-review-email-timestamp': suffix === 'a' ? '2100000000' : '2100000030',
          'x-request-id': `request-${suffix}`,
        },
        body: JSON.stringify({ event_id: 'evt_same', state: 'delivered' }),
      });
    const context = { retentionFenceStore: store, retentionFenceClock: clock };
    const first = handler(providerRequest('a'), context);
    await entered;
    const resigned = await handler(providerRequest('b'), context);
    assert.equal(resigned.status, 503);
    assert.deepEqual(await resigned.json(), {
      error: 'retention_generation_fence_contention', retryable: true,
    });
    assert.equal(calls, 1);
    assert.equal([...store.values.keys()].filter((key) =>
      key.includes('/producer-intents/')).length, 1);
    releaseResolve();
    assert.equal((await first).status, 204);
  }

  // A crash after the immutable digest-only output marker but before the
  // producer receipt must never turn into a generic success that omits the
  // original checkout URL/cookie/bearer. The stale exact retry validates and
  // closes the old generation with a safe retryable response; the following
  // OPEN-generation retry invokes the idempotent route and returns the real
  // response.
  {
    const store = new FakeStore('marker-crash');
    const alertStore = new FakeStore('marker-crash-alert');
    store.failProducerCompletionWrites = 1;
    let current = new Date('2036-08-28T12:00:00.000Z');
    let calls = 0;
    const handler = route(async () => {
      calls += 1;
      return new Response(JSON.stringify({
        checkout_url: 'https://checkout.stripe.com/c/pay/cs_live_sensitive',
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    const context = {
      retentionFenceStore: store,
      retentionFenceAlertStore: alertStore,
      retentionFenceClock: () => new Date(current),
    };
    const first = await handler(request('marker-crash'), context);
    assert.equal(first.status, 503);
    assert.deepEqual(await first.json(), { error: 'retention_generation_fence_unavailable' });
    assert.equal(calls, 1);
    assert.equal((await readRetentionGenerationFence(store, process.env)).record.status, 'WRITING');
    const markerKey = [...store.values.keys()].find((key) =>
      key.startsWith(RETENTION_ROUTE_OUTPUT_PREFIX));
    assert.ok(markerKey);
    assert.doesNotMatch(JSON.stringify(store.values.get(markerKey).data), /cs_live_sensitive/);

    current = new Date('2036-08-28T12:02:00.000Z');
    const recovered = await handler(request('marker-crash'), context);
    assert.equal(recovered.status, 503);
    assert.deepEqual(await recovered.json(), {
      error: 'retention_route_response_unavailable', retryable: true,
    });
    assert.equal(calls, 1);
    let state = await readRetentionGenerationFence(store, process.env);
    assert.equal(state.record.status, 'OPEN');
    assert.equal(state.record.generation, 1);
    assert.equal([...alertStore.values.keys()].filter((key) =>
      key.startsWith('alerts/retention-generation-fence/')).length, 1);

    const reproduced = await handler(request('marker-crash'), context);
    assert.equal(reproduced.status, 200);
    assert.deepEqual(await reproduced.json(), {
      checkout_url: 'https://checkout.stripe.com/c/pay/cs_live_sensitive',
    });
    assert.equal(calls, 2);
    state = await readRetentionGenerationFence(store, process.env);
    assert.equal(state.record.generation, 2);
  }

  // A genuinely stale route operation must synchronously enter the signed
  // operations queue before it can resume. Queue failure leaves WRITING
  // closed; the existing immutable alert retries and deduplicates next time.
  {
    const store = new FakeStore('stale-alert');
    const alertStore = new FakeStore('stale-alert-queue');
    let current = new Date('2036-08-28T12:00:00.000Z');
    let calls = 0;
    const handler = route(async () => {
      calls += 1;
      if (calls === 1) return new Response('partial failure', { status: 502 });
      return new Response(JSON.stringify({ resumed: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    const context = {
      retentionFenceStore: store,
      retentionFenceAlertStore: alertStore,
      retentionFenceClock: () => new Date(current),
      retentionFenceStaleAfterMs: 1_000,
    };
    const first = await handler(request('stale-alert'), context);
    assert.equal(first.status, 502);
    assert.equal((await readRetentionGenerationFence(store, process.env)).record.status,
      'WRITING');

    current = new Date('2036-08-28T12:00:01.000Z');
    alertStore.failNextAlertWrite = true;
    const queueFailure = await handler(request('stale-alert'), context);
    assert.equal(queueFailure.status, 503);
    assert.deepEqual(await queueFailure.json(), {
      error: 'retention_generation_fence_unavailable',
    });
    assert.equal(calls, 1, 'A stale operation cannot resume before critical alert enqueue.');
    assert.equal([...alertStore.values.keys()].filter((key) =>
      key.startsWith('alerts/retention-generation-fence/')).length, 0);
    assert.equal((await readRetentionGenerationFence(store, process.env)).record.status,
      'WRITING');

    current = new Date('2036-08-28T12:00:01.001Z');
    const recovered = await handler(request('stale-alert'), context);
    assert.equal(recovered.status, 200);
    assert.deepEqual(await recovered.json(), { resumed: true });
    assert.equal(calls, 2);
    const queued = [...alertStore.values.entries()].filter(([key]) =>
      key.startsWith('alerts/retention-generation-fence/'));
    assert.equal(queued.length, 1);
    assert.equal(queued[0][1].data.category, 'retention-generation-fence');
    assert.equal(queued[0][1].data.detail_code,
      'fence-stale-exact-retry-resumed');
    assert.equal(queued[0][1].data.contains_customer_data, false);
    assert.equal((await readRetentionGenerationFence(store, process.env)).record.status,
      'OPEN');
  }

  // A slow live handler receives periodic CAS heartbeats. stale_at advances,
  // the prior ETag loses authority while WRITING, and completion uses only the
  // final renewed authority.
  {
    const store = new FakeStore('route-heartbeat');
    let clockTick = 0;
    let initialAuthority;
    let heartbeatObserved = false;
    const handler = route(async () => {
      const initial = await readRetentionGenerationFence(store, process.env);
      initialAuthority = {
        status: initial.record.status,
        generation: initial.record.generation,
        operation_hmac_sha256: initial.record.operation_hmac_sha256,
        intent_sha256: initial.record.intent_sha256,
        authority_etag: initial.etag,
      };
      const initialStaleAt = initial.record.stale_at;
      await new Promise((resolve) => setTimeout(resolve, 45));
      const renewed = await readRetentionGenerationFence(store, process.env);
      assert.ok(Date.parse(renewed.record.stale_at) > Date.parse(initialStaleAt));
      await assert.rejects(assertRetentionGenerationFenceAuthority(
        store, initialAuthority, process.env), /FENCE_AUTHORITY_LOST/);
      heartbeatObserved = true;
      return new Response(null, { status: 204 });
    });
    const context = {
      retentionFenceStore: store,
      retentionFenceClock: () => new Date(
        Date.parse('2036-08-28T12:10:00.000Z') + clockTick++ * 400,
      ),
      retentionFenceStaleAfterMs: 1_000,
      retentionFenceHeartbeatIntervalMs: 10,
    };
    Object.defineProperty(context, 'retentionFenceAlertStore', {
      get() { throw new Error('A healthy heartbeat must not open the alert queue.'); },
    });
    const response = await handler(request('route-heartbeat'), context);
    assert.equal(response.status, 204);
    assert.equal(heartbeatObserved, true);
    const state = await readRetentionGenerationFence(store, process.env);
    assert.equal(state.record.status, 'OPEN');
    assert.equal(state.record.generation, 1);
  }

  // Review checkout has an empty body; its private session cookie must still
  // produce a distinct operation identity. Two customers in the same
  // generation may contend globally, but must never resume each other's work.
  {
    const store = new FakeStore('checkout-cookie');
    let calls = 0;
    let enteredResolve;
    let releaseResolve;
    const entered = new Promise((resolve) => { enteredResolve = resolve; });
    const release = new Promise((resolve) => { releaseResolve = resolve; });
    const handler = route(async () => {
      calls += 1;
      enteredResolve();
      await release;
      return new Response(JSON.stringify({ checkout_url: 'https://checkout.stripe.com/c/pay/redacted' }), {
        headers: { 'content-type': 'application/json' },
      });
    });
    const checkoutRequest = (cookie) => new Request('https://arcweb.onl/api/contract/mutate', {
      method: 'POST', headers: { cookie }, body: '',
    });
    const context = { retentionFenceStore: store, retentionFenceClock: clock };
    const first = handler(checkoutRequest('arc_review_session=customer_one'), context);
    await entered;
    const second = await handler(checkoutRequest('arc_review_session=customer_two'), context);
    assert.equal(second.status, 503);
    assert.deepEqual(await second.json(), {
      error: 'retention_generation_fence_contention', retryable: true,
    });
    assert.equal(calls, 1, 'A distinct checkout cookie must not resume the active customer operation.');
    assert.equal([...store.values.keys()].filter((key) =>
      key.includes('/producer-intents/')).length, 2);
    releaseResolve();
    assert.equal((await first).status, 200);
  }

  // Cursor-bearing mutation routes share a pathname, so the query must be
  // bound into operation identity. Distinct cursors may contend globally but
  // must never resume each other's work.
  {
    const store = new FakeStore('query-identity');
    let calls = 0;
    let enteredResolve;
    let releaseResolve;
    const entered = new Promise((resolve) => { enteredResolve = resolve; });
    const release = new Promise((resolve) => { releaseResolve = resolve; });
    const handler = route(async () => {
      calls += 1;
      enteredResolve();
      await release;
      return new Response(null, { status: 204 });
    });
    const cursorRequest = (cursor) => new Request(
      `https://arcweb.onl/api/contract/mutate?cursor=${cursor}`,
      {
        method: 'POST',
        headers: { 'idempotency-key': 'same-request-envelope' },
        body: '{}',
      },
    );
    const context = { retentionFenceStore: store, retentionFenceClock: clock };
    const first = handler(cursorRequest('first'), context);
    await entered;
    const second = await handler(cursorRequest('second'), context);
    assert.equal(second.status, 503);
    assert.deepEqual(await second.json(), {
      error: 'retention_generation_fence_contention', retryable: true,
    });
    assert.equal(calls, 1, 'A distinct query must not resume the active operation.');
    assert.equal([...store.values.keys()].filter((key) =>
      key.includes('/producer-intents/')).length, 2);
    releaseResolve();
    assert.equal((await first).status, 204);
  }

  // A checkout-shaped exact HTTP replay after completion belongs to the next
  // OPEN generation. The idempotent route runs again and preserves its real
  // checkout response instead of degrading it to a generic replay body.
  {
    const store = new FakeStore('retry');
    let calls = 0;
    const handler = route(async () => {
      calls += 1;
      return new Response(JSON.stringify({
        checkout_url: 'https://checkout.stripe.com/c/pay/cs_live_redacted',
        checkout_session_id: 'cs_live_redacted',
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    const context = { retentionFenceStore: store, retentionFenceClock: clock };
    const first = await handler(request('exact-retry'), context);
    assert.equal(first.status, 200);
    assert.deepEqual(await first.json(), {
      checkout_url: 'https://checkout.stripe.com/c/pay/cs_live_redacted',
      checkout_session_id: 'cs_live_redacted',
    });
    const markerKey = [...store.values.keys()].find((key) =>
      key.startsWith(RETENTION_ROUTE_OUTPUT_PREFIX));
    const tampered = structuredClone(store.values.get(markerKey).data);
    tampered.response_status = 201;
    assert.throws(() => validateRetentionRouteOutputMarker(tampered, {
      route: 'contract/mutation', generation: 0,
    }, process.env), /SIGNATURE_INVALID/);
    const replay = await handler(request('exact-retry'), context);
    assert.equal(replay.status, 200);
    assert.deepEqual(await replay.json(), {
      checkout_url: 'https://checkout.stripe.com/c/pay/cs_live_redacted',
      checkout_session_id: 'cs_live_redacted',
    });
    assert.equal(calls, 2);
    const state = await readRetentionGenerationFence(store, process.env);
    assert.equal(state.record.status, 'OPEN');
    assert.equal(state.record.generation, 2);
    assert.ok(store.values.has(RETENTION_GENERATION_FENCE_STATE_KEY));
    assert.equal([...store.values.keys()].filter((key) =>
      key.startsWith(RETENTION_ROUTE_OUTPUT_PREFIX)).length, 2);
  }

  // Pollers and scheduled routes commonly have no explicit idempotency key.
  // Their otherwise-identical next invocation binds to the new OPEN
  // generation and must run again instead of becoming a one-shot worker.
  {
    const store = new FakeStore('repeatable');
    let calls = 0;
    const handler = route(async () => {
      calls += 1;
      return new Response(null, { status: 204 });
    });
    const context = { retentionFenceStore: store, retentionFenceClock: clock };
    assert.equal((await handler(requestWithoutIdempotency('poll'), context)).status, 204);
    assert.equal((await handler(requestWithoutIdempotency('poll'), context)).status, 204);
    assert.equal(calls, 2);
    assert.equal((await readRetentionGenerationFence(store, process.env)).record.generation, 2);
  }

  // Every outer mutation route named by the launch retention audit must import
  // and instantiate the shared helper. This prevents route-local opt-outs.
  const requiredRoutes = [
    'review-exchange.mjs',
    'review-email-prepare.mjs',
    'review-email-reserve.mjs',
    'review-email-ack.mjs',
    'review-decision.mjs',
    'review-revision-claim.mjs',
    'review-revision-complete.mjs',
    'review-checkout.mjs',
    'stripe-reversal-webhook.mjs',
    'stripe-reversal-binding.mjs',
    'stripe-reversal-recheck.mjs',
    'payment-arc2-worker.mjs',
    'arc2-handoff-start.mjs',
    'arc2-claim.mjs',
    'arc2-claim-webhook.mjs',
    'arc2-claim-invitation-ready.mjs',
    'arc2-claim-invitation-renew.mjs',
    'arc2-claim-link-renew.mjs',
    'arc2-final-delivery-ack.mjs',
    'resend-webhook.mjs',
    'transactional-email-worker.mjs',
    'operations-audit.mjs',
    'operations-alert-reserve.mjs',
    'operations-alert-ack.mjs',
    'intake-submit.mjs',
    'intake-email-verification-consume.mjs',
    'intake-confirmation-claim.mjs',
    'intake-confirmation-complete.mjs',
    'intake-arc1-background.mjs',
    'intake-arc1-recovery.mjs',
    'intake-arc1-bridge.mjs',
    'intake-arc1-adapter.mjs',
    'intake-arc1-adapter-claim.mjs',
    'intake-arc1-adapter-complete.mjs',
    'intake-arc1-adapter-background.mjs',
    'intake-arc1-adapter-recovery.mjs',
    'intake-arc1-adapter-recovery-runner.mjs',
    'intake-arc1-adapter-legacy-migration.mjs',
    'analytics-event.mjs',
    'support-request.mjs',
    'review-activation-readback-refresh.mjs',
  ];
  for (const filename of requiredRoutes) {
    const source = await readFile(new URL(`../netlify/functions/${filename}`, import.meta.url), 'utf8');
    assert.match(source, /from ['"]\.\.\/lib\/retention-fenced-route-core\.mjs['"];/,
      `${filename} must import the shared retention-fenced route helper.`);
    assert.match(source, /export default createRetentionFencedRouteHandler\s*\(\s*\{/,
      `${filename} must wrap its outermost mutation handler with the shared retention fence.`);
  }
} finally {
  for (const [name, previous] of previousEnvironment) {
    if (previous === undefined) delete process.env[name];
    else process.env[name] = previous;
  }
}

console.log('ARC retention-fenced outer route contract passed.');
