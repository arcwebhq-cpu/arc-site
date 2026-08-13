import { getStore } from '@netlify/blobs';
import { HANDOFF_STORE, authenticateBearer, configuredEnvironment, jsonResponse } from '../lib/arc2-handoff-core.mjs';
import { getHandoffStatus } from '../lib/arc2-handoff-service.mjs';

export default async (request, context = {}) => {
  if (!configuredEnvironment(process.env).enabled) return jsonResponse(503, { error: 'handoff_disabled' });
  if (request.method !== 'GET') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_HANDOFF_TRIGGER_SECRET)) return jsonResponse(401, { error: 'unauthorized' });
  const url = new URL(request.url);
  try {
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const status = await getHandoffStatus(url.searchParams.get('handoff_id') || '', process.env, { store },
      { includePrivate: url.searchParams.get('include_private') === 'true' });
    return status ? jsonResponse(200, status) : jsonResponse(404, { error: 'handoff_not_found' });
  } catch {
    return jsonResponse(400, { error: 'invalid_handoff_id' });
  }
};

export const config = { path: '/internal/arc2/handoff-status', method: 'GET', rateLimit: { windowLimit: 60, windowSize: 60, aggregateBy: ['ip', 'domain'] } };
