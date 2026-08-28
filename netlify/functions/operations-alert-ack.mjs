import { getStore } from '@netlify/blobs';

import {
  acknowledgeOperationsAlertDelivery,
  authenticateOperationsAlertWorker,
  OPERATIONS_ALERT_DELIVERY_STORE,
  operationsAlertDeliveryConfiguration,
} from '../lib/operations-alert-delivery-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const MAX_BODY_BYTES = 4_096;

const response = (status, value) => new Response(JSON.stringify(value), { status, headers: {
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8',
  'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
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
      if (!(value instanceof Uint8Array)) throw new TypeError('JSON body chunk is invalid.');
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        try { await reader.cancel(); } catch {}
        throw new TypeError('JSON body is too large.');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally { try { reader.releaseLock(); } catch {} }
  return JSON.parse(Buffer.concat(chunks, total).toString('utf8'));
}

export function createOperationsAlertAckHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return response(405, { error: 'method_not_allowed' });
    if (!authenticateOperationsAlertWorker(request, process.env)) {
      return response(401, { error: 'unauthorized' });
    }
    const type = request.headers.get('content-type') || '';
    if (!type.toLowerCase().startsWith('application/json')) return response(415, { error: 'json_required' });
    try {
      const value = await boundedJson(request);
      const store = context.deliveryStore ||
        getStore({ name: OPERATIONS_ALERT_DELIVERY_STORE, consistency: 'strong' });
      return response(200, await acknowledgeOperationsAlertDelivery(store, value, process.env,
        { clock: context.clock }));
    } catch (error) {
      if (error instanceof TypeError || error?.name === 'SyntaxError') {
        return response(400, { error: 'invalid_alert_delivery_receipt' });
      }
      if (/NOT_FOUND/.test(error?.message || '')) return response(404, { error: 'alert_delivery_not_found' });
      if (/LEASE_INVALID|CONFLICT|CONTENTION/.test(error?.message || '')) {
        return response(409, { error: 'alert_delivery_conflict' });
      }
      if (/DISABLED/.test(error?.message || '')) return response(503, { error: 'alert_delivery_disabled' });
      return response(503, { error: 'alert_delivery_unavailable' });
    }
  };
}

const handler = createOperationsAlertAckHandler();

export default createRetentionFencedRouteHandler({
  route: 'operations-alert-ack',
  paths: ['/api/internal/operations-alert/ack'],
  active: ({ env }) => operationsAlertDeliveryConfiguration(env).enabled,
  handler,
});

export const config = {
  path: '/api/internal/operations-alert/ack',
  method: 'POST',
  rateLimit: { windowLimit: 60, windowSize: 60, aggregateBy: ['domain'] },
};
