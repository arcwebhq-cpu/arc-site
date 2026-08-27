import assert from 'node:assert/strict';
import { fetchAndVerifyWithRetries } from '../scripts/lib/verify-production-route-retry.mjs';

function fakeClock() {
  let now = 0;
  return {
    clock: () => now,
    wait: async milliseconds => { now += milliseconds; },
  };
}

{
  const time = fakeClock();
  const responses = [
    { status: 404 },
    { status: 503, body: { error: 'cold_start' } },
    { status: 503, body: { error: 'public_intake_authority_required' } },
  ];
  let attempts = 0;
  const response = await fetchAndVerifyWithRetries({
    label: '/internal/intake/arc1/adapter/claim',
    deadlineMs: 100,
    requestTimeoutMs: 25,
    retryDelayMs: 10,
    ...time,
    fetchResponse: async timeoutMs => {
      assert.ok(timeoutMs > 0 && timeoutMs <= 25);
      attempts += 1;
      return responses.shift();
    },
    verifyResponse: async candidate => {
      assert.equal(candidate.status, 503);
      assert.deepEqual(candidate.body, { error: 'public_intake_authority_required' });
    },
  });
  assert.equal(attempts, 3);
  assert.deepEqual(response.body, { error: 'public_intake_authority_required' });
}

{
  const time = fakeClock();
  let attempts = 0;
  await assert.rejects(fetchAndVerifyWithRetries({
    label: '/api/intake/readiness',
    deadlineMs: 100,
    retryDelayMs: 10,
    ...time,
    fetchResponse: async () => {
      attempts += 1;
      return { status: 200, body: { intake_enabled: true } };
    },
    verifyResponse: async response => {
      assert.deepEqual(response.body, { intake_enabled: false });
    },
  }), /Expected values to be strictly deep-equal/);
  assert.equal(attempts, 1, 'A successful HTTP response with unsafe content must fail immediately.');
}

{
  const time = fakeClock();
  let attempts = 0;
  await assert.rejects(fetchAndVerifyWithRetries({
    label: '/cold-route',
    deadlineMs: 30,
    requestTimeoutMs: 25,
    retryDelayMs: 10,
    ...time,
    fetchResponse: async () => {
      attempts += 1;
      throw new Error('network unavailable');
    },
    verifyResponse: async () => {},
  }), /did not reach its exact production contract within 30ms: network unavailable/);
  assert.equal(attempts, 3, 'Retries must stop at the configured deadline.');
}

{
  const time = fakeClock();
  const redirectError = new TypeError('fetch failed', { cause: new Error('unexpected redirect') });
  let attempts = 0;
  await assert.rejects(fetchAndVerifyWithRetries({
    label: '/must-not-redirect',
    deadlineMs: 100,
    retryDelayMs: 10,
    ...time,
    fetchResponse: async () => {
      attempts += 1;
      throw redirectError;
    },
    verifyResponse: async () => {},
  }), /fetch failed/);
  assert.equal(attempts, 1, 'Redirect regressions must not be treated as propagation.');
}

{
  const time = fakeClock();
  const requestId = '11111111-1111-4111-8111-111111111111';
  const responses = [
    { status: 404, body: { error: 'not_found' } },
    { status: 201, body: { schema: 'arc-support-request-accepted-v1', accepted: true, request_id: requestId } },
  ];
  const response = await fetchAndVerifyWithRetries({
    label: '/api/support/request', deadlineMs: 100, retryDelayMs: 10, ...time,
    fetchResponse: async () => responses.shift(),
    verifyResponse: async candidate => {
      assert.equal(candidate.status, 201);
      assert.deepEqual(candidate.body,
        { schema: 'arc-support-request-accepted-v1', accepted: true, request_id: requestId });
    },
  });
  assert.equal(response.body.request_id, requestId,
    'Production verification must bind support acceptance to the submitted retry identity.');
}

console.log('Production route retry contract passed.');
