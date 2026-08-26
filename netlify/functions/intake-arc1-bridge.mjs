import { getStore } from '@netlify/blobs';
import { publicIntakeAuthorityReady } from '../lib/activation-manifest-core.mjs';
import {
  INTAKE_ARC1_BRIDGE_ENABLED_ENV,
  INTAKE_ARC1_REQUEST_SCHEMA,
  authorizeBridgeRun,
  deliverIntakeToArc1,
} from '../lib/intake-arc1-bridge-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';

const response = (status, value) => new Response(JSON.stringify(value), { status, headers: {
  'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8',
  'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
} });

function exactRequest(value) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(['schema', 'submission_id']);
}

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

export function createIntakeArc1BridgeHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return response(405, { error: 'method_not_allowed' });
    if (!publicIntakeAuthorityReady(process.env)) {
      return response(503, { error: 'public_intake_authority_required' });
    }
    if (!authorizeBridgeRun(request, process.env)) return response(401, { error: 'unauthorized' });
    if (process.env[INTAKE_ARC1_BRIDGE_ENABLED_ENV] !== 'true') return response(503, { error: 'bridge_disabled' });
    const contentType = request.headers.get('content-type') || '';
    const contentLength = request.headers.get('content-length');
    if (!contentType.toLowerCase().startsWith('application/json') ||
        (contentLength && (!/^\d{1,6}$/.test(contentLength) || Number(contentLength) > 2048))) {
      return response(400, { error: 'invalid_request' });
    }
    let input;
    try { input = await boundedJson(request); } catch { return response(400, { error: 'invalid_request' }); }
    if (!exactRequest(input) || input.schema !== INTAKE_ARC1_REQUEST_SCHEMA || typeof input.submission_id !== 'string') {
      return response(400, { error: 'invalid_request' });
    }
    try {
      const result = await deliverIntakeToArc1(input.submission_id, process.env, {
        store: context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' }),
        fetch: context.fetch, clock: context.clock, uuid: context.uuid,
      });
      const status = result.state === 'NOT_FOUND' ? 404 : result.state === 'DEAD_LETTER' ? 409 : 200;
      return response(status, { schema: 'arc-intake-arc1-delivery-result-v1', ...result });
    } catch (error) {
      if (error?.message === 'ARC1_BRIDGE_DISABLED') return response(503, { error: 'bridge_disabled' });
      if (error instanceof TypeError) return response(400, { error: 'invalid_request' });
      if (error?.message === 'ARC1_BRIDGE_STATE_CONTENTION') return response(409, { error: 'state_contention' });
      return response(503, { error: 'bridge_unavailable' });
    }
  };
}

export default createIntakeArc1BridgeHandler();

export const config = {
  path: '/internal/intake/arc1/deliver', method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
