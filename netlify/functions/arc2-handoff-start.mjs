import { getStore } from '@netlify/blobs';
import { HANDOFF_STORE, authenticateBearer, configuredEnvironment, jsonResponse, parseJsonBodyText, publicStatus } from '../lib/arc2-handoff-core.mjs';
import { startHandoff } from '../lib/arc2-handoff-service.mjs';

export default async (request, context = {}) => {
  if (!configuredEnvironment(process.env).enabled) return jsonResponse(503, { error: 'handoff_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_HANDOFF_TRIGGER_SECRET)) return jsonResponse(401, { error: 'unauthorized' });
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') return jsonResponse(415, { error: 'json_required' });
  try {
    const body = parseJsonBodyText(await request.text(), 2_100_000);
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const result = await startHandoff(body, process.env, { store });
    return jsonResponse(202, { handoff_id: result.handoffId, ...publicStatus(result.record) });
  } catch (error) {
    if (error instanceof TypeError || error?.name === 'SyntaxError') return jsonResponse(400, { error: 'invalid_handoff_request' });
    if (/IDEMPOTENCY_CONFLICT|INDEX_CONFLICT|STATE_CONTENTION/.test(error?.message || '')) return jsonResponse(409, { error: 'handoff_conflict' });
    return jsonResponse(503, { error: 'handoff_unavailable' });
  }
};

export const config = { path: '/api/arc2/handoff/start', method: 'POST', rateLimit: { windowLimit: 12, windowSize: 60, aggregateBy: ['ip', 'domain'] } };
