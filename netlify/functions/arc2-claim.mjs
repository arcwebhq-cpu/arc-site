import { getStore } from '@netlify/blobs';
import { HANDOFF_STORE, configuredEnvironment, jsonResponse } from '../lib/arc2-handoff-core.mjs';
import { exchangeClaimBearer } from '../lib/arc2-handoff-service.mjs';

export default async (request, context = {}) => {
  if (!configuredEnvironment(process.env).enabled) return jsonResponse(503, { error: 'handoff_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  const authorization = request.headers.get('authorization') || '';
  const handoffId = request.headers.get('x-arc-handoff-id') || '';
  if (!authorization.startsWith('Bearer ') || authorization.length > 256) return jsonResponse(401, { error: 'unauthorized' });
  try {
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const result = await exchangeClaimBearer(handoffId, authorization.slice(7), process.env, {
      store, stripeAccountFetch: context.stripeAccountFetch,
    });
    return result ? jsonResponse(200, { claim_url: result.claimUrl }) : jsonResponse(404, { error: 'handoff_not_found' });
  } catch (error) {
    if (/ARC_STRIPE_CHECKOUT_(?:LEDGER_HALT|HANDOFF_BINDING_CONFLICT|PAYMENT_NOT_PAID)/.test(error?.message || '')) {
      return jsonResponse(409, { error: 'fulfillment_halted' });
    }
    if (/ARC_STRIPE_(?:CHECKOUT|ACCOUNT)_/.test(error?.message || '')) {
      return jsonResponse(503, { error: 'payment_control_unavailable' });
    }
    return jsonResponse(401, { error: 'claim_bearer_invalid_or_expired' });
  }
};

export const config = { path: '/api/arc2/claim', method: 'POST', rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] } };
