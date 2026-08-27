import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';

// Only fail-closed/unavailable responses may be retried. A 2xx contract mismatch
// is treated as an immediate production regression.
const TRANSIENT_ROUTE_STATUSES = new Set([404, 408, 425, 429, 500, 502, 503, 504]);

function isUnexpectedRedirect(error) {
  return /unexpected redirect/i.test(error?.cause?.message || '');
}

export async function fetchAndVerifyWithRetries({
  label,
  fetchResponse,
  verifyResponse,
  deadlineMs = 60_000,
  requestTimeoutMs = 15_000,
  retryDelayMs = 2_000,
  clock = Date.now,
  wait = delay,
}) {
  assert.equal(typeof label, 'string');
  assert.equal(typeof fetchResponse, 'function');
  assert.equal(typeof verifyResponse, 'function');
  assert.ok(Number.isSafeInteger(deadlineMs) && deadlineMs > 0);
  assert.ok(Number.isSafeInteger(requestTimeoutMs) && requestTimeoutMs > 0);
  assert.ok(Number.isSafeInteger(retryDelayMs) && retryDelayMs > 0);

  const deadline = clock() + deadlineMs;
  let lastTransientError;

  while (clock() < deadline) {
    const remainingMs = deadline - clock();
    let response;
    try {
      response = await fetchResponse(Math.max(1, Math.min(requestTimeoutMs, remainingMs)));
    } catch (error) {
      if (isUnexpectedRedirect(error)) throw error;
      lastTransientError = error;
      const pauseMs = Math.min(retryDelayMs, deadline - clock());
      if (pauseMs > 0) await wait(pauseMs);
      continue;
    }

    try {
      await verifyResponse(response);
      return response;
    } catch (error) {
      if (!TRANSIENT_ROUTE_STATUSES.has(response?.status)) throw error;
      lastTransientError = error;
    }

    const pauseMs = Math.min(retryDelayMs, deadline - clock());
    if (pauseMs > 0) await wait(pauseMs);
  }

  assert.ok(lastTransientError, `${label} exhausted its propagation window without a response.`);
  lastTransientError.message = `${label} did not reach its exact production contract within ${deadlineMs}ms: ${lastTransientError.message}`;
  throw lastTransientError;
}
