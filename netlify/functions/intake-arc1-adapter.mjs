import { getStore } from '@netlify/blobs';

import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';
import {
  INTAKE_ARC1_ADAPTER_ENABLED_ENV,
  INTAKE_ARC1_ADAPTER_MAX_PACKET_BYTES,
  INTAKE_ARC1_ADAPTER_STORE,
  INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV,
  acceptArc1AdapterEnvelope,
  authorizeArc1AdapterIngress,
  markArc1AdapterQueueUnavailable,
  queueArc1AdapterDispatch,
} from '../lib/intake-arc1-adapter-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';

const securityHeaders = Object.freeze({
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'Content-Type': 'application/json; charset=utf-8',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
});

const json = (status, value) => new Response(JSON.stringify(value), { status, headers: securityHeaders });

export function createIntakeArc1AdapterHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' });
    if (process.env[INTAKE_ARC1_ADAPTER_ENABLED_ENV] !== 'true' ||
        process.env[INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV] !== 'true' ||
        process.env.ARC_INTAKE_ASSET_RETRIEVAL_ENABLED !== 'true') {
      return json(503, { error: 'adapter_disabled' });
    }
    if (!authorizeArc1AdapterIngress(request, process.env)) return json(401, { error: 'unauthorized' });
    const contentType = request.headers.get('content-type') || '';
    if (!contentType.toLowerCase().startsWith('application/json')) return json(400, { error: 'invalid_request' });
    let envelopeRaw;
    try {
      envelopeRaw = await readBoundedRequestText(request, INTAKE_ARC1_ADAPTER_MAX_PACKET_BYTES);
    } catch (error) {
      return json(error instanceof RequestBodyTooLargeError ? 413 : 400, { error: 'invalid_request' });
    }
    try {
      const source = context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' });
      const adapter = context.adapterStore || getStore({ name: INTAKE_ARC1_ADAPTER_STORE, consistency: 'strong' });
      const accepted = await acceptArc1AdapterEnvelope(envelopeRaw, request, process.env, { source, adapter }, {
        clock: context.clock,
      });
      // The exact acknowledgement is already durable at this point. Queueing
      // only starts a separately gated background delivery; Zapier is never in
      // the producer's synchronous acknowledgement path.
      if (!['HOOK_ACCEPTED', 'DEAD_LETTER'].includes(accepted.record.dispatch.status)) {
        const queued = await queueArc1AdapterDispatch(accepted.deliveryId, request, process.env, {
          fetch: context.fetch,
        });
        if (queued.state === 'QUEUE_UNAVAILABLE') {
          try { await markArc1AdapterQueueUnavailable(accepted.deliveryId, process.env, adapter, { clock: context.clock }); } catch {}
        }
      }
      return new Response(accepted.acknowledgementJson, { status: 200, headers: securityHeaders });
    } catch (error) {
      if (error?.message === 'ARC1_ADAPTER_DISABLED') return json(503, { error: 'adapter_disabled' });
      if (error?.message === 'ARC1_ADAPTER_UNAUTHORIZED') return json(401, { error: 'unauthorized' });
      if (/ARC1_ADAPTER_(?:ENVELOPE|ASSET|INGRESS|PENDING_INDEX)_CONFLICT/.test(error?.message || '')) {
        return json(409, { error: 'adapter_conflict' });
      }
      if (error instanceof TypeError) return json(400, { error: 'invalid_request' });
      return json(503, { error: 'adapter_unavailable' });
    }
  };
}

export default createIntakeArc1AdapterHandler();

export const config = {
  path: '/internal/intake/arc1/adapter', method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
