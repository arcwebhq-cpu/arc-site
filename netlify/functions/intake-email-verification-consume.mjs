import { getStore } from '@netlify/blobs';

import {
  INTAKE_EMAIL_VERIFICATION_REQUEST_SCHEMA,
  consumeIntakeEmailVerificationToken,
  intakeEmailVerificationConfiguration,
} from '../lib/intake-email-verification-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';
import { dispatchIntakeToArc1Background } from '../lib/intake-arc1-dispatch-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const response = (status, value) => new Response(JSON.stringify(value), { status, headers: {
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'Content-Type': 'application/json; charset=utf-8',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
} });

async function boundedText(request) {
  const reader = request.body?.getReader?.();
  if (!reader) throw new TypeError('Verification body is required.');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new TypeError('Verification body is invalid.');
      total += value.byteLength;
      if (total > 512) {
        try { await reader.cancel(); } catch {}
        throw new TypeError('Verification body is too large.');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally { try { reader.releaseLock(); } catch {} }
  return Buffer.concat(chunks, total).toString('utf8');
}

function exactInput(raw) {
  let value;
  try { value = JSON.parse(raw); } catch { throw new TypeError('Verification request is invalid.'); }
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['schema', 'token']) ||
      value.schema !== INTAKE_EMAIL_VERIFICATION_REQUEST_SCHEMA || typeof value.token !== 'string') {
    throw new TypeError('Verification request is invalid.');
  }
  return value;
}

export function createIntakeEmailVerificationConsumeHandler(dispatch = dispatchIntakeToArc1Background) {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return response(405, { error: 'method_not_allowed' });
    if (!intakeEmailVerificationConfiguration(process.env).enabled) {
      return response(503, { error: 'verification_unavailable' });
    }
    let url;
    try { url = new URL(request.url); } catch { return response(403, { error: 'verification_rejected' }); }
    if (url.origin !== 'https://arcweb.onl' || url.pathname !== '/api/intake/verify' || url.search || url.hash ||
        request.headers.get('origin') !== 'https://arcweb.onl' || request.headers.get('sec-fetch-site') !== 'same-origin' ||
        !String(request.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) {
      return response(403, { error: 'verification_rejected' });
    }
    const declared = request.headers.get('content-length');
    if (declared && (!/^\d{1,3}$/.test(declared) || Number(declared) > 512)) {
      return response(400, { error: 'verification_rejected' });
    }
    try {
      const input = exactInput(await boundedText(request));
      const intakeStore = context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' });
      const verified = await consumeIntakeEmailVerificationToken(input.token, process.env, intakeStore, {
        clock: context.clock,
      });
      // Release an immediate same-deploy background dispatch only after the
      // one-time mailbox bearer is durably consumed. A failure here does not
      // undo verification; the separately required recovery runner will retry
      // the still-pending submission without customer action.
      try {
        await dispatch(verified.submission_id, request, process.env, {
          store: intakeStore, fetch: context.fetch, clock: context.clock,
        });
      } catch {}
      return response(200, { verified: true });
    } catch {
      // Invalid, expired, and replayed links deliberately share one response.
      return response(410, { error: 'verification_rejected' });
    }
  };
}

const handler = createIntakeEmailVerificationConsumeHandler();

export default createRetentionFencedRouteHandler({
  route: 'intake-email-verification-consume',
  paths: ['/api/intake/verify'],
  active: ({ env }) => intakeEmailVerificationConfiguration(env).enabled,
  handler,
});
export const config = {
  path: '/api/intake/verify', method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
