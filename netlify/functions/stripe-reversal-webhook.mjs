import { getStore } from '@netlify/blobs';
import { HANDOFF_STORE, jsonResponse } from '../lib/arc2-handoff-core.mjs';
import {
  processStripeReversalEvent,
  stripeReversalConfiguration,
} from '../lib/stripe-reversal-core.mjs';

const ALERT_STORE = 'arc-operations-alerts';

export default async (request, context = {}) => {
  if (!stripeReversalConfiguration(process.env).webhookOperational) return jsonResponse(503, { error: 'stripe_reversal_control_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return jsonResponse(415, { error: 'json_required' });
  }
  const contentLength = request.headers.get('content-length');
  if (contentLength !== null && (!/^\d{1,7}$/.test(contentLength) || Number(contentLength) > 1_048_576)) {
    return jsonResponse(413, { error: 'webhook_too_large' });
  }
  try {
    const reader = request.body?.getReader();
    if (!reader) return jsonResponse(400, { error: 'invalid_webhook' });
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 1_048_576) {
        await reader.cancel();
        return jsonResponse(413, { error: 'webhook_too_large' });
      }
      chunks.push(Buffer.from(value));
    }
    const body = Buffer.concat(chunks, size).toString('utf8');
    if (!body) return jsonResponse(400, { error: 'invalid_webhook' });
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const alertStore = context.alertStore || getStore({ name: ALERT_STORE, consistency: 'strong' });
    const result = await processStripeReversalEvent(
      body,
      request.headers.get('stripe-signature'),
      process.env,
      { store, alertStore, clock: context.clock },
    );
    return jsonResponse(200, {
      accepted: true,
      handoff_id: result.handoffId,
      idempotent_replay: result.idempotentReplay,
      fulfillment_halted: true,
    });
  } catch (error) {
    if (error instanceof TypeError || error?.name === 'SyntaxError') return jsonResponse(400, { error: 'invalid_webhook' });
    if (/UNBOUND|MISSING/.test(error?.message || '')) return jsonResponse(409, { error: 'binding_not_ready' });
    if (/CONFLICT/.test(error?.message || '')) return jsonResponse(409, { error: 'webhook_conflict' });
    return jsonResponse(503, { error: 'webhook_unavailable' });
  }
};

export const config = {
  path: '/internal/stripe/reversal-webhook',
  method: 'POST',
  rateLimit: { windowLimit: 120, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
