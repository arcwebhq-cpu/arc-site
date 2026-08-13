import { getStore } from '@netlify/blobs';
import {
  HANDOFF_STORE,
  authenticateBearer,
  configuredEnvironment,
  jsonResponse,
  parseJsonBodyText,
} from '../lib/arc2-handoff-core.mjs';
import { acknowledgeFinalDelivery } from '../lib/arc2-handoff-service.mjs';

export default async (request, context = {}) => {
  if (!configuredEnvironment(process.env).enabled) return jsonResponse(503, { error: 'handoff_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_FINAL_DELIVERY_ACK_SECRET)) return jsonResponse(401, { error: 'unauthorized' });
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return jsonResponse(415, { error: 'json_required' });
  }
  try {
    const body = parseJsonBodyText(await request.text(), 30_000);
    if (typeof body.handoff_id !== 'string' || typeof body.delivery_receipt_evidence !== 'string' ||
        typeof body.delivery_receipt_evidence_hmac_sha256 !== 'string' || Object.keys(body).length !== 3) {
      return jsonResponse(400, { error: 'invalid_delivery_receipt' });
    }
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const result = await acknowledgeFinalDelivery(
      body.handoff_id,
      body.delivery_receipt_evidence,
      body.delivery_receipt_evidence_hmac_sha256,
      process.env,
      { store },
    );
    if (!result) return jsonResponse(404, { error: 'handoff_not_found' });
    return jsonResponse(200, {
      handoff_id: result.handoffId,
      delivery_status: 'DELIVERED',
      delivered_at: result.record.delivered_at,
    });
  } catch (error) {
    if (error instanceof TypeError || error?.name === 'SyntaxError') {
      return jsonResponse(400, { error: 'invalid_delivery_receipt' });
    }
    if (/CONFLICT|STATE_CONTENTION/.test(error?.message || '')) {
      return jsonResponse(409, { error: 'delivery_acknowledgement_conflict' });
    }
    return jsonResponse(503, { error: 'delivery_acknowledgement_unavailable' });
  }
};

export const config = {
  path: '/internal/arc2/final-delivery-ack',
  method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
