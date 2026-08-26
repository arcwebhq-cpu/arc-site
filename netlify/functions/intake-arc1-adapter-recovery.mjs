import { getStore } from '@netlify/blobs';

import { publicIntakeAuthorityReady } from '../lib/activation-manifest-core.mjs';
import {
  INTAKE_ARC1_ADAPTER_ENABLED_ENV,
  INTAKE_ARC1_ADAPTER_STORE,
  INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV,
  authorizeArc1AdapterDispatch,
  recoverPendingArc1AdapterDispatches,
} from '../lib/intake-arc1-adapter-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';

const response = (status, value) => new Response(JSON.stringify(value), { status, headers: {
  'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff',
} });

export function createIntakeArc1AdapterRecoveryHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return response(405, { error: 'method_not_allowed' });
    if (!publicIntakeAuthorityReady(process.env)) {
      return response(503, { error: 'public_intake_authority_required' });
    }
    if (!authorizeArc1AdapterDispatch(request, process.env)) return response(401, { error: 'unauthorized' });
    if (process.env[INTAKE_ARC1_ADAPTER_ENABLED_ENV] !== 'true' ||
        process.env[INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV] !== 'true' ||
        process.env.ARC_INTAKE_ASSET_RETRIEVAL_ENABLED !== 'true' ||
        process.env.ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED !== 'true' ||
        process.env.ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED !== 'true') {
      return response(503, { error: 'adapter_disabled' });
    }
    try {
      const result = await recoverPendingArc1AdapterDispatches(request, process.env, {
        source: context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' }),
        adapter: context.adapterStore || getStore({ name: INTAKE_ARC1_ADAPTER_STORE, consistency: 'strong' }),
      }, { fetch: context.fetch, clock: context.clock });
      return response(200, { schema: 'arc-intake-arc1-adapter-recovery-result-v1', ...result });
    } catch { return response(503, { error: 'adapter_recovery_unavailable' }); }
  };
}

export default createIntakeArc1AdapterRecoveryHandler();
export const config = {
  path: '/internal/intake/arc1/adapter/recover', method: 'POST',
  rateLimit: { windowLimit: 1, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
