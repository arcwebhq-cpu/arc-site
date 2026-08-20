import { getStore } from '@netlify/blobs';
import { HANDOFF_STORE, authenticateBearer, configuredEnvironment, jsonResponse, parseJsonBodyText, publicStatus } from '../lib/arc2-handoff-core.mjs';
import { startHandoff } from '../lib/arc2-handoff-service.mjs';
import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';

export default async (request, context = {}) => {
  if (!configuredEnvironment(process.env).enabled) return jsonResponse(503, { error: 'handoff_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_HANDOFF_TRIGGER_SECRET)) return jsonResponse(401, { error: 'unauthorized' });
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') return jsonResponse(415, { error: 'json_required' });
  try {
    const body = parseJsonBodyText(await readBoundedRequestText(request, 5_000_000), 5_000_000);
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const result = await startHandoff(body, process.env, { store, clock: context.clock });
    const origin = new URL(process.env.ARC_PUBLIC_ORIGIN).origin;
    return jsonResponse(202, {
      handoff_id: result.handoffId,
      reversal_control_ready: result.reversalControlReady,
      ...(result.claimBearer ? {
        claim_invitation_url: `${origin}/claim/#arc2.${result.handoffId}.${result.claimBearer}`,
        claim_invitation_expires_at: result.record.claim_token_expires_at,
      } : {}),
      ...publicStatus(result.record),
    });
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) return jsonResponse(413, { error: 'handoff_request_too_large' });
    if (error instanceof TypeError || error?.name === 'SyntaxError') return jsonResponse(400, { error: 'invalid_handoff_request' });
    if (/ARC_STRIPE_REVERSAL_HALT/.test(error?.message || '')) return jsonResponse(409, { error: 'fulfillment_halted' });
    if (/ARC_STRIPE_REVERSAL_(?:CONTROL_DISABLED|STATE_CONFLICT)/.test(error?.message || '')) {
      return jsonResponse(503, { error: 'stripe_reversal_control_unavailable' });
    }
    if (/IDEMPOTENCY_CONFLICT|INDEX_CONFLICT|STATE_CONTENTION/.test(error?.message || '')) return jsonResponse(409, { error: 'handoff_conflict' });
    return jsonResponse(503, { error: 'handoff_unavailable' });
  }
};

export const config = { path: '/api/arc2/handoff/start', method: 'POST', rateLimit: { windowLimit: 12, windowSize: 60, aggregateBy: ['ip', 'domain'] } };
