import { getStore } from '@netlify/blobs';
import {
  HANDOFF_STORE,
  authenticateBearer,
  configuredEnvironment,
  jsonResponse,
  parseJsonBodyText,
} from '../lib/arc2-handoff-core.mjs';
import { renewClaimInvitation } from '../lib/arc2-handoff-service.mjs';
import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';

export default async (request, context = {}) => {
  if (!configuredEnvironment(process.env).enabled) return jsonResponse(503, { error: 'handoff_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_HANDOFF_TRIGGER_SECRET)) return jsonResponse(401, { error: 'unauthorized' });
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return jsonResponse(415, { error: 'json_required' });
  }
  try {
    const body = parseJsonBodyText(await readBoundedRequestText(request, 2_000), 2_000);
    if (Object.keys(body).length !== 1 || typeof body.handoff_id !== 'string') {
      return jsonResponse(400, { error: 'invalid_renewal' });
    }
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const reviewStore = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    const result = await renewClaimInvitation(body.handoff_id, process.env, {
      store,
      reviewStore,
      clock: context.clock,
      fetch: context.fetch,
      stripeAccountFetch: context.stripeAccountFetch,
    });
    if (!result) return jsonResponse(404, { error: 'handoff_not_found' });
    const origin = new URL(process.env.ARC_PUBLIC_ORIGIN).origin;
    return jsonResponse(201, {
      handoff_id: result.handoffId,
      invitation_status: 'READY',
      claim_invitation_generation: result.record.claim_invitation_generation,
      claim_invitation_url: `${origin}/claim/#arc2.${result.handoffId}.${result.claimBearer}`,
      expires_at: result.record.claim_token_expires_at,
    });
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) return jsonResponse(413, { error: 'renewal_too_large' });
    if (error instanceof TypeError || error?.name === 'SyntaxError') return jsonResponse(400, { error: 'invalid_renewal' });
    if (/ARC_STRIPE_(?:REVERSAL_HALT|CHECKOUT_(?:LEDGER_HALT|HANDOFF_BINDING_CONFLICT|PAYMENT_NOT_PAID))/.test(error?.message || '')) {
      return jsonResponse(409, { error: 'fulfillment_halted' });
    }
    if (/ARC_STRIPE_(?:CHECKOUT|ACCOUNT)_/.test(error?.message || '')) {
      return jsonResponse(503, { error: 'payment_control_unavailable' });
    }
    if (/NOT_EXPIRED|STATE_CONFLICT|STATE_CONTENTION|CURRENT_CONFLICT/.test(error?.message || '')) {
      return jsonResponse(409, { error: 'claim_invitation_renewal_conflict' });
    }
    return jsonResponse(503, { error: 'claim_invitation_renewal_unavailable' });
  }
};

export const config = {
  path: '/internal/arc2/claim-invitation-renew',
  method: 'POST',
  rateLimit: { windowLimit: 12, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
