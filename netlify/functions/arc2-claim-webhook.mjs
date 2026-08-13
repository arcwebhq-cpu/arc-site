import { getStore } from '@netlify/blobs';
import { HANDOFF_STORE, configuredEnvironment, emptyResponse, jsonResponse, parseJsonBodyText } from '../lib/arc2-handoff-core.mjs';
import { processClaimWebhook } from '../lib/arc2-handoff-service.mjs';

export default async (request, context = {}) => {
  if (!configuredEnvironment(process.env).enabled) return jsonResponse(503, { error: 'handoff_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') return jsonResponse(415, { error: 'json_required' });
  try {
    const input = parseJsonBodyText(await request.text(), 4096);
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    await processClaimWebhook(input, process.env, { store });
    return emptyResponse(204);
  } catch (error) {
    if (error instanceof TypeError || error?.name === 'SyntaxError') return jsonResponse(400, { error: 'invalid_claim_hint' });
    if (/UNKNOWN|BINDING|STATE_CONFLICT|MISMATCH|NOT_CLAIMED/.test(error?.message || '')) return jsonResponse(409, { error: 'claim_not_verified' });
    return jsonResponse(503, { error: 'claim_reverification_unavailable' });
  }
};

export const config = { path: '/api/arc2/claim-webhook', method: 'POST', rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] } };
