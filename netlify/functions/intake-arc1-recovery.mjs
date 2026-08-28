import { getStore } from '@netlify/blobs';
import { publicIntakeAuthorityReady } from '../lib/activation-manifest-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';
import {
  INTAKE_ARC1_DISPATCH_ENABLED_ENV,
  authorizeBackgroundDispatch,
  recoverPendingArc1Dispatches,
} from '../lib/intake-arc1-dispatch-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const response = (status, value) => new Response(JSON.stringify(value), { status, headers: {
  'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff',
} });

export function createIntakeArc1RecoveryHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return response(405, { error: 'method_not_allowed' });
    if (!publicIntakeAuthorityReady(process.env)) {
      return response(503, { error: 'public_intake_authority_required' });
    }
    if (!authorizeBackgroundDispatch(request, process.env)) return response(401, { error: 'unauthorized' });
    if (process.env[INTAKE_ARC1_DISPATCH_ENABLED_ENV] !== 'true') {
      return response(503, { error: 'dispatch_disabled' });
    }
    try {
      const result = await recoverPendingArc1Dispatches(request, process.env, {
        store: context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' }),
        fetch: context.fetch, clock: context.clock,
      });
      return response(200, { schema: 'arc-intake-arc1-recovery-result-v1', ...result });
    } catch { return response(503, { error: 'recovery_unavailable' }); }
  };
}

const handler = createIntakeArc1RecoveryHandler();

export default createRetentionFencedRouteHandler({
  route: 'intake-arc1-recovery',
  paths: ['/internal/intake/arc1/recover'],
  active: ({ env }) => publicIntakeAuthorityReady(env) &&
    env[INTAKE_ARC1_DISPATCH_ENABLED_ENV] === 'true',
  handler,
});
export const config = {
  path: '/internal/intake/arc1/recover', method: 'POST',
  rateLimit: { windowLimit: 1, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
