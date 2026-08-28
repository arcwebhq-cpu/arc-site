import { getStore } from '@netlify/blobs';

import { publicIntakeAuthorityReady } from '../lib/activation-manifest-core.mjs';
import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';
import {
  INTAKE_ARC1_ADAPTER_ENABLED_ENV,
  INTAKE_ARC1_ADAPTER_MAX_CONTROL_BYTES,
  INTAKE_ARC1_ADAPTER_STORE,
  INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV,
  arc1AdapterProtocolEnabled,
  authorizeArc1AdapterConsumer,
  completeArc1AdapterConsumer,
} from '../lib/intake-arc1-adapter-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const headers = Object.freeze({
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'Content-Type': 'application/json; charset=utf-8',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
});
const json = (status, value) => new Response(JSON.stringify(value), { status, headers });

export function createIntakeArc1AdapterCompletionHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' });
    if (!publicIntakeAuthorityReady(process.env)) {
      return json(503, { error: 'public_intake_authority_required' });
    }
    if (process.env[INTAKE_ARC1_ADAPTER_ENABLED_ENV] !== 'true' ||
        process.env[INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV] !== 'true' ||
        process.env.ARC_INTAKE_ASSET_RETRIEVAL_ENABLED !== 'true' ||
        process.env.ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED !== 'true' ||
        process.env.ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED !== 'true') {
      return json(503, { error: 'consumer_completion_disabled' });
    }
    if (!authorizeArc1AdapterConsumer(request, process.env)) return json(401, { error: 'unauthorized' });
    if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return json(400, { error: 'invalid_request' });
    }
    let raw;
    try { raw = await readBoundedRequestText(request, INTAKE_ARC1_ADAPTER_MAX_CONTROL_BYTES); } catch (error) {
      return json(error instanceof RequestBodyTooLargeError ? 413 : 400, { error: 'invalid_request' });
    }
    try {
      const result = await completeArc1AdapterConsumer(raw, request, process.env,
        context.adapterStore || getStore({ name: INTAKE_ARC1_ADAPTER_STORE, consistency: 'strong' }),
        { clock: context.clock });
      return json(200, result);
    } catch (error) {
      if (error?.message === 'ARC1_ADAPTER_CONSUMER_COMPLETION_DISABLED') {
        return json(503, { error: 'consumer_completion_disabled' });
      }
      if (error?.message === 'ARC1_ADAPTER_CONSUMER_UNAUTHORIZED') return json(401, { error: 'unauthorized' });
      if (error?.message === 'ARC1_ADAPTER_CONSUMER_COMPLETION_UNAUTHORIZED') return json(401, { error: 'unauthorized' });
      if (error?.message === 'ARC1_ADAPTER_CONSUMER_NOT_FOUND') return json(404, { error: 'consumer_record_not_found' });
      if (error?.message === 'ARC1_ADAPTER_LEGACY_MIGRATION_REQUIRED') {
        return json(409, { error: 'consumer_completion_conflict' });
      }
      if (/ARC1_ADAPTER_CONSUMER_(?:COMPLETION_CONFLICT|COMPLETION_STALE|NOT_READY|TERMINAL)/.test(error?.message || '') ||
          /ARC1_ADAPTER_(?:REVIEW_INDEX)_CONFLICT/.test(error?.message || '')) {
        return json(409, { error: 'consumer_completion_conflict' });
      }
      if (error instanceof TypeError) return json(400, { error: 'invalid_request' });
      return json(503, { error: 'consumer_completion_unavailable' });
    }
  };
}

const handler = createIntakeArc1AdapterCompletionHandler();

export default createRetentionFencedRouteHandler({
  route: 'intake-arc1-adapter-complete',
  paths: ['/internal/intake/arc1/adapter/complete'],
  active: ({ env }) => publicIntakeAuthorityReady(env) && arc1AdapterProtocolEnabled(env),
  handler,
});
// Netlify extracts route configuration at build time, so keep these values literal.
export const config = {
  path: '/internal/intake/arc1/adapter/complete', method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
