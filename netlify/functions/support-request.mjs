import { getStore } from '@netlify/blobs';

import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';
import {
  isExactSupportRetry,
  normalizeSupportRequest,
  SUPPORT_MAX_REQUEST_BYTES,
  SUPPORT_REQUEST_STORE,
  SUPPORT_RESPONSE_SCHEMA,
} from '../lib/support-request-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const ALLOWED_ORIGINS = new Set(['https://arcweb.onl', 'https://arcsites.netlify.app']);

function response(status, value) {
  return new Response(JSON.stringify(value), { status, headers: {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
  } });
}

function requestAllowed(request) {
  let origin;
  try { origin = new URL(request.url).origin; } catch { return false; }
  if (!ALLOWED_ORIGINS.has(origin) || request.headers.get('origin') !== origin) return false;
  const fetchSite = request.headers.get('sec-fetch-site');
  return fetchSite === null || fetchSite === 'same-origin';
}

export function createSupportRequestHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return response(405, { error: 'method_not_allowed' });
    if (!requestAllowed(request)) return response(403, { error: 'forbidden' });
    if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return response(415, { error: 'json_required' });
    }
    const declared = request.headers.get('content-length');
    if (declared !== null && (!/^\d{1,8}$/.test(declared) || Number(declared) > SUPPORT_MAX_REQUEST_BYTES)) {
      return response(Number(declared) > SUPPORT_MAX_REQUEST_BYTES ? 413 : 400, {
        error: Number(declared) > SUPPORT_MAX_REQUEST_BYTES
          ? 'support_request_too_large' : 'invalid_support_request',
      });
    }

    try {
      const body = JSON.parse(await readBoundedRequestText(request, SUPPORT_MAX_REQUEST_BYTES));
      const normalized = normalizeSupportRequest(body, context.clock?.() || new Date());
      const store = context.supportStore || getStore({ name: SUPPORT_REQUEST_STORE, consistency: 'strong' });
      let created = false;
      let existing = null;
      try {
        const result = await store.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
        created = result?.modified === true;
      } catch (error) {
        existing = (await store.getWithMetadata(normalized.key, { type: 'json', consistency: 'strong' }))?.data || null;
        if (!existing) throw error;
      }
      if (!created) {
        existing ||= (await store.getWithMetadata(normalized.key, { type: 'json', consistency: 'strong' }))?.data || null;
        if (!isExactSupportRetry(existing, normalized.record)) {
          return response(409, { error: 'support_request_conflict' });
        }
      }
      return response(created ? 201 : 200, {
        schema: SUPPORT_RESPONSE_SCHEMA,
        accepted: true,
        request_id: normalized.record.request_id,
      });
    } catch (error) {
      if (error instanceof RequestBodyTooLargeError) return response(413, { error: 'support_request_too_large' });
      if (error instanceof TypeError || error?.name === 'SyntaxError') {
        return response(400, { error: 'invalid_support_request' });
      }
      return response(503, { error: 'support_unavailable' });
    }
  };
}

function requestMayMutate(request) {
  if (!requestAllowed(request) ||
      (request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return false;
  }
  const declared = request.headers.get('content-length');
  return declared === null || /^\d{1,8}$/.test(declared) && Number(declared) <= SUPPORT_MAX_REQUEST_BYTES;
}

const handler = createSupportRequestHandler();

export default createRetentionFencedRouteHandler({
  route: 'support-request',
  paths: ['/api/support/request'],
  active: ({ request }) => requestMayMutate(request),
  handler,
});

export const config = {
  path: '/api/support/request', method: 'POST',
  rateLimit: { windowLimit: 3, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
