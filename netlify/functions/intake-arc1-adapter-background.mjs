import { getStore } from '@netlify/blobs';

import { publicIntakeAuthorityReady } from '../lib/activation-manifest-core.mjs';
import { readBoundedRequestText } from '../lib/bounded-request-body.mjs';
import {
  INTAKE_ARC1_ADAPTER_BACKGROUND_SCHEMA,
  INTAKE_ARC1_ADAPTER_ENABLED_ENV,
  INTAKE_ARC1_ADAPTER_STORE,
  INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV,
  arc1AdapterProtocolEnabled,
  authorizeArc1AdapterDispatch,
  dispatchArc1AdapterRecord,
} from '../lib/intake-arc1-adapter-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const response = (status, value) => new Response(status === 204 ? null : JSON.stringify(value), { status, headers: {
  'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff',
} });

const exactRequest = (value) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify(['delivery_id', 'schema']);

export function createIntakeArc1AdapterBackgroundHandler() {
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
    const contentType = request.headers.get('content-type') || '';
    if (!contentType.toLowerCase().startsWith('application/json')) return response(400, { error: 'invalid_request' });
    let input;
    try { input = JSON.parse(await readBoundedRequestText(request, 2048)); } catch { return response(400, { error: 'invalid_request' }); }
    if (!exactRequest(input) || input.schema !== INTAKE_ARC1_ADAPTER_BACKGROUND_SCHEMA || typeof input.delivery_id !== 'string') {
      return response(400, { error: 'invalid_request' });
    }
    try {
      await dispatchArc1AdapterRecord(input.delivery_id, process.env, {
        source: context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' }),
        adapter: context.adapterStore || getStore({ name: INTAKE_ARC1_ADAPTER_STORE, consistency: 'strong' }),
      }, { fetch: context.fetch, clock: context.clock });
      return response(204, {});
    } catch { return response(503, { error: 'adapter_dispatch_unavailable' }); }
  };
}

const handler = createIntakeArc1AdapterBackgroundHandler();

export default createRetentionFencedRouteHandler({
  route: 'intake-arc1-adapter-background',
  active: ({ env }) => publicIntakeAuthorityReady(env) && arc1AdapterProtocolEnabled(env),
  handler,
});
export const config = { background: true };
