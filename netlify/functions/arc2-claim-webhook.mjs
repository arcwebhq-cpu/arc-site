import { getStore } from '@netlify/blobs';
import { HANDOFF_STORE, configuredEnvironment, emptyResponse, jsonResponse, parseJsonBodyText } from '../lib/arc2-handoff-core.mjs';
import { processClaimWebhook } from '../lib/arc2-handoff-service.mjs';
import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const handler = async (request, context = {}) => {
  if (!configuredEnvironment(process.env).enabled) return jsonResponse(503, { error: 'handoff_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') return jsonResponse(415, { error: 'json_required' });
  try {
    const input = parseJsonBodyText(await readBoundedRequestText(request, 4096), 4096);
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const reviewStore = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    await processClaimWebhook(input, process.env, {
      store, reviewStore, stripeAccountFetch: context.stripeAccountFetch,
    });
    return emptyResponse(204);
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) return jsonResponse(413, { error: 'claim_hint_too_large' });
    if (error instanceof TypeError || error?.name === 'SyntaxError') return jsonResponse(400, { error: 'invalid_claim_hint' });
    if (/ARC_STRIPE_(?:REVERSAL_HALT|CHECKOUT_(?:LEDGER_HALT|HANDOFF_BINDING_CONFLICT|PAYMENT_NOT_PAID))/.test(error?.message || '')) {
      return jsonResponse(409, { error: 'fulfillment_halted' });
    }
    if (/ARC_STRIPE_(?:CHECKOUT|ACCOUNT)_/.test(error?.message || '')) {
      return jsonResponse(503, { error: 'payment_control_unavailable' });
    }
    if (/UNKNOWN|BINDING|STATE_CONFLICT|MISMATCH|NOT_CLAIMED/.test(error?.message || '')) return jsonResponse(409, { error: 'claim_not_verified' });
    return jsonResponse(503, { error: 'claim_reverification_unavailable' });
  }
};

export default createRetentionFencedRouteHandler({
  route: 'arc2-claim-webhook',
  paths: ['/api/arc2/claim-webhook'],
  active: ({ env }) => configuredEnvironment(env).enabled,
  handler,
});

export const config = { path: '/api/arc2/claim-webhook', method: 'POST', rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] } };
