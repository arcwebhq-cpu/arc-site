import { getStore } from '@netlify/blobs';

import { publicIntakeAuthorityReady } from '../lib/activation-manifest-core.mjs';
import {
  INTAKE_ARC1_ADAPTER_STORE,
  arc1AdapterLegacyMigrationEnabled,
  authorizeArc1AdapterDispatch,
  migrateLegacyArc1AdapterRecords,
} from '../lib/intake-arc1-adapter-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const headers = Object.freeze({
  'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8',
  'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
});
const json = (status, value) => new Response(JSON.stringify(value), { status, headers });

export function createIntakeArc1AdapterLegacyMigrationHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' });
    if (!publicIntakeAuthorityReady(process.env)) {
      return json(503, { error: 'public_intake_authority_required' });
    }
    if (!authorizeArc1AdapterDispatch(request, process.env)) return json(401, { error: 'unauthorized' });
    if (!arc1AdapterLegacyMigrationEnabled(process.env)) {
      return json(503, { error: 'migration_disabled' });
    }
    try {
      const result = await migrateLegacyArc1AdapterRecords(request, process.env,
        context.adapterStore || getStore({ name: INTAKE_ARC1_ADAPTER_STORE, consistency: 'strong' }),
        Object.hasOwn(context, 'cursor') ? { cursor: context.cursor } : {});
      return json(200, { schema: 'arc-intake-arc1-adapter-legacy-migration-result-v1', ...result });
    } catch (error) {
      if (error instanceof TypeError) return json(400, { error: 'invalid_request' });
      return json(503, { error: 'migration_unavailable' });
    }
  };
}

const handler = createIntakeArc1AdapterLegacyMigrationHandler();

export default createRetentionFencedRouteHandler({
  route: 'intake-arc1-adapter-legacy-migration',
  paths: ['/internal/intake/arc1/adapter/migrate-legacy'],
  active: ({ env }) => publicIntakeAuthorityReady(env) &&
    arc1AdapterLegacyMigrationEnabled(env),
  handler,
});
// Netlify extracts route configuration at build time, so keep these values literal.
export const config = {
  path: '/internal/intake/arc1/adapter/migrate-legacy', method: 'POST',
  rateLimit: { windowLimit: 1, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
