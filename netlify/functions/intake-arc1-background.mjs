import { getStore } from '@netlify/blobs';
import {
  authorizeBackgroundDispatch,
  INTAKE_ARC1_DISPATCH_ENABLED_ENV,
} from '../lib/intake-arc1-dispatch-core.mjs';
import { deliverIntakeToArc1 } from '../lib/intake-arc1-bridge-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';

const response = (status, value) => new Response(status === 204 ? null : JSON.stringify(value), { status, headers: {
  'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff',
} });

async function boundedJson(request) {
  const reader = request.body?.getReader?.();
  if (!reader) throw new TypeError('JSON body is required.');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new TypeError('Invalid JSON body chunk.');
      total += value.byteLength;
      if (total > 2048) {
        try { await reader.cancel(); } catch {}
        throw new TypeError('JSON body is too large.');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally { try { reader.releaseLock(); } catch {} }
  return JSON.parse(Buffer.concat(chunks, total).toString('utf8'));
}

export function createIntakeArc1BackgroundHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return response(405, { error: 'method_not_allowed' });
    if (!authorizeBackgroundDispatch(request, process.env)) return response(401, { error: 'unauthorized' });
    // A queued background invocation can outlive the foreground dispatch that
    // created it. Re-check the kill switch at execution time so revocation is
    // effective before parsing the body or touching durable state/network.
    if (process.env[INTAKE_ARC1_DISPATCH_ENABLED_ENV] !== 'true') {
      return response(503, { error: 'dispatch_disabled' });
    }
    const contentType = request.headers.get('content-type') || '';
    const contentLength = request.headers.get('content-length');
    if (!contentType.toLowerCase().startsWith('application/json') ||
        (contentLength && (!/^\d{1,6}$/.test(contentLength) || Number(contentLength) > 2048))) {
      return response(400, { error: 'invalid_request' });
    }
    let input;
    try { input = await boundedJson(request); } catch { return response(400, { error: 'invalid_request' }); }
    if (!input || Object.getPrototypeOf(input) !== Object.prototype ||
        JSON.stringify(Object.keys(input).sort()) !== JSON.stringify(['schema', 'submission_id']) ||
        input.schema !== 'arc-intake-arc1-delivery-request-v1' || typeof input.submission_id !== 'string') {
      return response(400, { error: 'invalid_request' });
    }
    await deliverIntakeToArc1(input.submission_id, process.env, {
      store: context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' }),
      fetch: context.fetch, clock: context.clock, uuid: context.uuid,
    });
    return response(204, {});
  };
}

export default createIntakeArc1BackgroundHandler();
export const config = { background: true };
