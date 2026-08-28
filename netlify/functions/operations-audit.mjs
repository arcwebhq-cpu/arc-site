import { getStore } from '@netlify/blobs';
import {
  HANDOFF_STORE,
  authenticateBearer,
  jsonResponse,
} from '../lib/arc2-handoff-core.mjs';
import { RETENTION_CONTROL_STORE } from '../lib/retention-control-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';
import {
  OPERATIONS_ALERT_STORE,
  operationsAuditConfiguration,
  runOperationsAudit,
} from '../lib/operations-audit-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const handler = async (request, context = {}) => {
  if (!operationsAuditConfiguration(process.env).enabled) return jsonResponse(503, { error: 'operations_audit_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_OPERATIONS_AUDIT_SECRET)) return jsonResponse(401, { error: 'unauthorized' });
  try {
    const result = await runOperationsAudit(process.env, {
      alerts: context.alertStore || getStore({ name: OPERATIONS_ALERT_STORE, consistency: 'strong' }),
      handoff: context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' }),
      intake: context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' }),
      retention: context.retentionStore || getStore({ name: RETENTION_CONTROL_STORE, consistency: 'strong' }),
    }, { clock: context.clock, wallClock: context.wallClock, request });
    return jsonResponse(200, result);
  } catch (error) {
    if (error instanceof TypeError) return jsonResponse(400, { error: 'operations_audit_invalid' });
    if (/DISABLED/.test(error?.message || '')) return jsonResponse(503, { error: 'operations_audit_disabled' });
    if (/CONFLICT|LIMIT/.test(error?.message || '')) return jsonResponse(409, { error: 'operations_audit_conflict' });
    return jsonResponse(503, { error: 'operations_audit_unavailable' });
  }
};

export default createRetentionFencedRouteHandler({
  route: 'operations-audit',
  paths: ['/internal/operations/audit'],
  active: ({ env }) => operationsAuditConfiguration(env).enabled,
  handler,
});

export const config = {
  path: '/internal/operations/audit',
  method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
