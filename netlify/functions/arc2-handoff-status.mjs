import { getStore } from '@netlify/blobs';
import { HANDOFF_STORE, authenticateBearer, configuredEnvironment, jsonResponse } from '../lib/arc2-handoff-core.mjs';
import { getHandoffStatus } from '../lib/arc2-handoff-service.mjs';

export default async (request, context = {}) => {
  if (!configuredEnvironment(process.env).enabled) return jsonResponse(503, { error: 'handoff_disabled' });
  if (request.method !== 'GET') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_HANDOFF_TRIGGER_SECRET)) return jsonResponse(401, { error: 'unauthorized' });
  const url = new URL(request.url);
  try {
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const status = await getHandoffStatus(url.searchParams.get('handoff_id') || '', process.env, {
      store,
      clock: context.clock,
      fetch: context.fetch,
      stripeAccountFetch: context.stripeAccountFetch,
    },
      { includePrivate: url.searchParams.get('include_private') === 'true' });
    return status ? jsonResponse(200, status) : jsonResponse(404, { error: 'handoff_not_found' });
  } catch (error) {
    if (/ARC_STRIPE_(?:REVERSAL_HALT|CHECKOUT_(?:LEDGER_HALT|HANDOFF_BINDING_CONFLICT|PAYMENT_NOT_PAID))/.test(error?.message || '')) {
      return jsonResponse(409, { error: 'fulfillment_halted' });
    }
    if (/ARC_STRIPE_(?:CHECKOUT|ACCOUNT)_/.test(error?.message || '')) {
      return jsonResponse(503, { error: 'payment_control_unavailable' });
    }
    if (/ARC_STRIPE_REVERSAL_(?:CONTROL_DISABLED|BINDING_REQUIRED|RECHECK_REQUIRED)/.test(error?.message || '')) {
      return jsonResponse(503, { error: 'stripe_reversal_control_unavailable' });
    }
    return jsonResponse(400, { error: 'invalid_handoff_id' });
  }
};

export const config = { path: '/internal/arc2/handoff-status', method: 'GET', rateLimit: { windowLimit: 60, windowSize: 60, aggregateBy: ['ip', 'domain'] } };
