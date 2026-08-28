import { getStore } from '@netlify/blobs';

import { publicIntakeAuthorityReady } from '../lib/activation-manifest-core.mjs';
import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';
import {
  INTAKE_CONFIRMATION_CONSUMER_ENABLED_ENV,
  INTAKE_CONFIRMATION_OUTBOX_ENABLED_ENV,
  INTAKE_CONFIRMATION_OUTBOX_STORE,
  authorizeIntakeConfirmationConsumer,
  completeIntakeConfirmationOutbox,
} from '../lib/intake-confirmation-outbox-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const MAX_BODY_BYTES = 4096;
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

export function createIntakeConfirmationCompletionHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' });
    if (!publicIntakeAuthorityReady(process.env)) return json(503, { error: 'public_intake_authority_required' });
    if (process.env[INTAKE_CONFIRMATION_OUTBOX_ENABLED_ENV] !== 'true' ||
        process.env[INTAKE_CONFIRMATION_CONSUMER_ENABLED_ENV] !== 'true') {
      return json(503, { error: 'confirmation_disabled' });
    }
    if (!authorizeIntakeConfirmationConsumer(request, process.env)) return json(401, { error: 'unauthorized' });
    if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return json(400, { error: 'invalid_request' });
    }
    let raw;
    try { raw = await readBoundedRequestText(request, MAX_BODY_BYTES); }
    catch (error) { return json(error instanceof RequestBodyTooLargeError ? 413 : 400, { error: 'invalid_request' }); }
    try {
      const store = context.confirmationStore || getStore({ name: INTAKE_CONFIRMATION_OUTBOX_STORE, consistency: 'strong' });
      return json(200, await completeIntakeConfirmationOutbox(raw, request, process.env, store, { clock: context.clock }));
    } catch (error) {
      if (/ARC_INTAKE_CONFIRMATION_(?:UNAUTHORIZED|COMPLETION_UNAUTHORIZED)/.test(error?.message || '')) {
        return json(401, { error: 'unauthorized' });
      }
      if (error?.message === 'ARC_INTAKE_CONFIRMATION_NOT_FOUND') return json(404, { error: 'confirmation_not_found' });
      if (/ARC_INTAKE_CONFIRMATION_(?:COMPLETION_CONFLICT|NOT_READY|REVIEW_REQUIRED)/.test(error?.message || '')) {
        return json(409, { error: 'confirmation_conflict' });
      }
      if (error instanceof TypeError) return json(400, { error: 'invalid_request' });
      return json(503, { error: 'confirmation_unavailable' });
    }
  };
}

const handler = createIntakeConfirmationCompletionHandler();

export default createRetentionFencedRouteHandler({
  route: 'intake-confirmation-complete',
  paths: ['/internal/intake/confirmation/complete'],
  active: ({ env }) => publicIntakeAuthorityReady(env) &&
    env[INTAKE_CONFIRMATION_OUTBOX_ENABLED_ENV] === 'true' &&
    env[INTAKE_CONFIRMATION_CONSUMER_ENABLED_ENV] === 'true',
  handler,
});

export const config = {
  path: '/internal/intake/confirmation/complete', method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
