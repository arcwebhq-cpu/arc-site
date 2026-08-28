import { getStore } from '@netlify/blobs';
import {
  HANDOFF_STORE,
  authenticateBearer,
  jsonResponse,
  parseJsonBodyText,
} from '../lib/arc2-handoff-core.mjs';
import {
  registerStripeReversalRecheck,
  stripeReversalConfiguration,
} from '../lib/stripe-reversal-core.mjs';
import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const handler = async (request, context = {}) => {
  if (!stripeReversalConfiguration(process.env).recheckOperational) return jsonResponse(503, { error: 'stripe_reversal_control_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET)) return jsonResponse(401, { error: 'unauthorized' });
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return jsonResponse(415, { error: 'json_required' });
  }
  try {
    const body = parseJsonBodyText(await readBoundedRequestText(request, 30_000), 30_000);
    if (Object.keys(body).length !== 2 || typeof body.recheck_evidence !== 'string' || typeof body.recheck_evidence_hmac_sha256 !== 'string') {
      return jsonResponse(400, { error: 'invalid_recheck_evidence' });
    }
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const result = await registerStripeReversalRecheck(
      body.recheck_evidence, body.recheck_evidence_hmac_sha256, process.env,
      { store, clock: context.clock },
    );
    return jsonResponse(200, { handoff_id: result.handoffId, recheck_accepted: true, idempotent_replay: result.idempotentReplay });
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) return jsonResponse(413, { error: 'recheck_evidence_too_large' });
    if (error instanceof TypeError || error?.name === 'SyntaxError') return jsonResponse(400, { error: 'invalid_recheck_evidence' });
    if (/HALT/.test(error?.message || '')) return jsonResponse(409, { error: 'fulfillment_halted' });
    if (/MISMATCH|CONFLICT|ROLLBACK|CONTENTION/.test(error?.message || '')) return jsonResponse(409, { error: 'recheck_conflict' });
    return jsonResponse(503, { error: 'recheck_unavailable' });
  }
};

export default createRetentionFencedRouteHandler({
  route: 'stripe-reversal-recheck',
  paths: ['/internal/stripe/reversal-recheck'],
  maxRequestBytes: 30_000,
  active: ({ env }) => stripeReversalConfiguration(env).recheckOperational,
  handler,
});

export const config = {
  path: '/internal/stripe/reversal-recheck', method: 'POST',
  rateLimit: { windowLimit: 60, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
