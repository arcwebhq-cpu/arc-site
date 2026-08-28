import { getStore } from '@netlify/blobs';

import { OPERATIONS_ALERT_STORE } from '../lib/operations-audit-core.mjs';
import {
  authenticateOperationsAlertWorker,
  claimNextOperationsAlert,
  OPERATIONS_ALERT_DELIVERY_STORE,
  operationsAlertDeliveryConfiguration,
} from '../lib/operations-alert-delivery-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const response = (status, value) => new Response(JSON.stringify(value), { status, headers: {
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8',
  'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
} });

export function createOperationsAlertReserveHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return response(405, { error: 'method_not_allowed' });
    if (!authenticateOperationsAlertWorker(request, process.env)) {
      return response(401, { error: 'unauthorized' });
    }
    try {
      const alertStore = context.alertStore || getStore({ name: OPERATIONS_ALERT_STORE, consistency: 'strong' });
      const deliveryStore = context.deliveryStore ||
        getStore({ name: OPERATIONS_ALERT_DELIVERY_STORE, consistency: 'strong' });
      const result = await claimNextOperationsAlert(alertStore, deliveryStore, process.env, {
        clock: context.clock,
      });
      return response(200, result);
    } catch (error) {
      if (error instanceof TypeError) return response(400, { error: 'invalid_alert_delivery_request' });
      if (/DISABLED/.test(error?.message || '')) return response(503, { error: 'alert_delivery_disabled' });
      return response(503, { error: 'alert_delivery_unavailable' });
    }
  };
}

const handler = createOperationsAlertReserveHandler();

export default createRetentionFencedRouteHandler({
  route: 'operations-alert-reserve',
  paths: ['/api/internal/operations-alert/reserve'],
  active: ({ env }) => operationsAlertDeliveryConfiguration(env).enabled,
  handler,
});

export const config = {
  path: '/api/internal/operations-alert/reserve',
  method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['domain'] },
};
