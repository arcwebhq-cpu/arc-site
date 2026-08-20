import { getStore } from '@netlify/blobs';
import {
  HANDOFF_STORE,
  authenticateBearer,
  jsonResponse,
  parseJsonBodyText,
} from '../lib/arc2-handoff-core.mjs';
import {
  registerStripeReversalBinding,
  stripeReversalConfiguration,
} from '../lib/stripe-reversal-core.mjs';
import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';

export default async (request, context = {}) => {
  if (!stripeReversalConfiguration(process.env).bindingOperational) return jsonResponse(503, { error: 'stripe_reversal_control_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET)) {
    return jsonResponse(401, { error: 'unauthorized' });
  }
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return jsonResponse(415, { error: 'json_required' });
  }
  try {
    const body = parseJsonBodyText(await readBoundedRequestText(request, 30_000), 30_000);
    if (Object.keys(body).length !== 2 || typeof body.binding_evidence !== 'string' ||
        typeof body.binding_evidence_hmac_sha256 !== 'string') {
      return jsonResponse(400, { error: 'invalid_binding_evidence' });
    }
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const result = await registerStripeReversalBinding(
      body.binding_evidence,
      body.binding_evidence_hmac_sha256,
      process.env,
      { store, clock: context.clock },
    );
    return jsonResponse(200, {
      bound: true,
      handoff_id: result.handoffId,
      idempotent_replay: !result.created,
    });
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) return jsonResponse(413, { error: 'binding_evidence_too_large' });
    if (error instanceof TypeError || error?.name === 'SyntaxError') return jsonResponse(400, { error: 'invalid_binding_evidence' });
    if (/MISSING|MISMATCH/.test(error?.message || '')) return jsonResponse(409, { error: 'binding_not_ready' });
    if (/CONFLICT|CONTENTION/.test(error?.message || '')) return jsonResponse(409, { error: 'binding_conflict' });
    return jsonResponse(503, { error: 'binding_unavailable' });
  }
};

export const config = {
  path: '/internal/stripe/reversal-binding',
  method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
