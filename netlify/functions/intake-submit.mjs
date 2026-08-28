import { getStore } from '@netlify/blobs';
import { INTAKE_BUILD_MARKER } from '../lib/intake-build-marker.mjs';
import {
  INTAKE_READINESS_ENV,
  intakeActivationReady,
  intakeArc1RuntimeReady,
  intakeEnabledFromAttestation,
  intakeEnabledFromBuildMarker,
} from '../lib/intake-readiness-core.mjs';
import {
  INTAKE_MAX_REQUEST_BYTES,
  INTAKE_RESPONSE_SCHEMA,
  INTAKE_STORE,
  INTAKE_IDEMPOTENCY_SECRET_ENV,
  intakeIdempotencyConfigured,
  normalizeIntakeForm,
} from '../lib/intake-submission-core.mjs';
import { dispatchIntakeToArc1Background } from '../lib/intake-arc1-dispatch-core.mjs';
import { EMAIL_RECIPIENT_VAULT_STORE } from '../lib/email-recipient-vault-core.mjs';
import { reserveIntakeEmailVerification } from '../lib/intake-email-verification-core.mjs';
import {
  INTAKE_ABUSE_STORE,
  IntakeAbuseProtectionError,
  intakeAbuseProtectionConfiguration,
  protectIntakeForm,
} from '../lib/intake-abuse-protection-core.mjs';
import {
  INTAKE_CONFIRMATION_OUTBOX_ENABLED_ENV,
  INTAKE_CONFIRMATION_OUTBOX_STORE,
  reserveIntakeConfirmationOutbox,
} from '../lib/intake-confirmation-outbox-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const ALLOWED_ORIGINS = new Set(['https://arcweb.onl', 'https://arcsites.netlify.app']);

class IntakeRequestError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

async function boundedFormData(request, contentType) {
  const reader = request.body?.getReader?.();
  if (!reader) throw new TypeError('Multipart body is required.');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new TypeError('Multipart body chunk is invalid.');
      total += value.byteLength;
      if (total > INTAKE_MAX_REQUEST_BYTES) {
        try { await reader.cancel(); } catch {}
        throw new IntakeRequestError(413, 'intake_too_large');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  return new Response(Buffer.concat(chunks, total), { headers: { 'Content-Type': contentType } }).formData();
}

function response(status, value) {
  return new Response(JSON.stringify(value), { status, headers: {
    'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8',
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY', 'X-Robots-Tag': 'noindex, nofollow, noarchive',
  } });
}

function isSameOriginBrowserNavigation(request) {
  const accept = request.headers.get('accept') || '';
  return /(?:^|,)\s*text\/html(?:\s*;[^,]*)?(?:,|$)/i.test(accept) &&
    request.headers.get('sec-fetch-mode') === 'navigate' &&
    request.headers.get('sec-fetch-dest') === 'document' &&
    request.headers.get('sec-fetch-site') === 'same-origin';
}

function acceptedResponse(request, status, value) {
  if (!isSameOriginBrowserNavigation(request)) return response(status, value);
  return new Response(null, { status: 303, headers: {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'Location': '/thank-you/',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
  } });
}

export function createIntakeSubmitHandler(
  buildMarker = INTAKE_BUILD_MARKER,
  runtimeReady = intakeArc1RuntimeReady,
  dependencies = {},
) {
  const protect = dependencies.protectIntakeForm || protectIntakeForm;
  const normalize = dependencies.normalizeIntakeForm || normalizeIntakeForm;
  const activationReady = dependencies.intakeActivationReady || intakeActivationReady;
  const getAbuseStore = dependencies.getIntakeAbuseStore || (() =>
    getStore({ name: INTAKE_ABUSE_STORE, consistency: 'strong' }));
  return async (request, context = {}) => {
  if (request.method !== 'POST') return response(405, { error: 'method_not_allowed' });
  let requestOrigin;
  try {
    requestOrigin = new URL(request.url).origin;
  } catch {
    return response(403, { error: 'forbidden' });
  }
  if (!ALLOWED_ORIGINS.has(requestOrigin) || request.headers.get('origin') !== requestOrigin) {
    return response(403, { error: 'forbidden' });
  }
  // The server rechecks the exact attestation at the irreversible storage
  // boundary. UI readiness is never authority, and revocation is immediate.
  if (!intakeEnabledFromBuildMarker(buildMarker) || process.env.ARC_BUILD_INTAKE_ENABLED !== 'true' ||
      !intakeEnabledFromAttestation(process.env[INTAKE_READINESS_ENV]) || !activationReady(process.env) ||
      !runtimeReady(request, process.env) ||
      !intakeIdempotencyConfigured(process.env) || !intakeAbuseProtectionConfiguration(process.env).enabled) {
    return response(503, { error: 'intake_disabled' });
  }
  const contentType = request.headers.get('content-type') || '';
  if (!contentType.toLowerCase().startsWith('multipart/form-data;')) {
    return response(415, { error: 'multipart_required' });
  }
  const contentLength = request.headers.get('content-length');
  if (contentLength !== null) {
    if (!/^\d{1,9}$/.test(contentLength)) return response(400, { error: 'invalid_content_length' });
    if (Number(contentLength) > INTAKE_MAX_REQUEST_BYTES) return response(413, { error: 'intake_too_large' });
  }
  try {
    const formData = await boundedFormData(request, contentType);
    const abuseStore = context.abuseStore || getAbuseStore();
    await protect(formData, request, process.env, abuseStore, {
      clock: context.clock,
      fetch: context.fetch,
      ip: context.ip,
      randomBytes: context.randomBytes,
    });
    const normalized = await normalize(
      formData,
      context.clock?.() || new Date(),
      context.uuid,
      { idempotencySecret: process.env[INTAKE_IDEMPOTENCY_SECRET_ENV] },
    );
    const store = context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' });
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
      const exactRetry = existing?.schema === normalized.record.schema &&
        existing.submission_id === normalized.record.submission_id &&
        existing.submission_data_sha256 === normalized.record.submission_data_sha256;
      if (!exactRetry) throw new Error('ARC_INTAKE_STORAGE_CONFLICT');
    }
    const sourceRecord = created ? normalized.record : existing;
    const verification = await reserveIntakeEmailVerification(sourceRecord, process.env, store, {
      clock: context.clock,
    });
    // The confirmation reservation is create-only and precedes the accepted
    // response. If its write is ambiguous or unavailable, this request fails
    // and an exact browser retry repairs the same deterministic outbox rather
    // than silently accepting an intake that can never receive confirmation.
    if (process.env[INTAKE_CONFIRMATION_OUTBOX_ENABLED_ENV] === 'true') {
      const confirmationStore = context.confirmationStore ||
        getStore({ name: INTAKE_CONFIRMATION_OUTBOX_STORE, consistency: 'strong' });
      const vaultStore = context.vaultStore ||
        getStore({ name: EMAIL_RECIPIENT_VAULT_STORE, consistency: 'strong' });
      await reserveIntakeConfirmationOutbox(sourceRecord, process.env, confirmationStore, {
        clock: context.clock, randomBytes: context.randomBytes, vaultStore, verification,
      });
    }
    // A same-deploy background invocation is best-effort and separately gated.
    // The accepted intake remains durable even if dispatch is paused or fails;
    // dispatch state records the failure for an authenticated recovery run.
    try {
      await dispatchIntakeToArc1Background(normalized.record.submission_id, request, process.env, {
        store, fetch: context.fetch, clock: context.clock,
      });
    } catch {}
    return acceptedResponse(request, created ? 201 : 200, {
      schema: INTAKE_RESPONSE_SCHEMA, accepted: true, submission_id: normalized.record.submission_id,
    });
  } catch (error) {
    if (error instanceof IntakeRequestError) return response(error.status, { error: error.code });
    if (error instanceof IntakeAbuseProtectionError) {
      if (error.status === 403 || error.status === 400) return response(error.status, { error: 'verification_required' });
      if (error.status === 429) return response(429, { error: 'request_not_accepted' });
      return response(503, { error: 'intake_unavailable' });
    }
    if (error instanceof TypeError || error?.name === 'SyntaxError') return response(400, { error: 'invalid_intake' });
    if (/CONFLICT/.test(error?.message || '')) return response(409, { error: 'intake_conflict' });
    return response(503, { error: 'intake_unavailable' });
  }
  };
}

const handler = createIntakeSubmitHandler();

export default createRetentionFencedRouteHandler({
  route: 'intake-submit',
  paths: ['/api/intake/submit'],
  active: ({ env, request }) => intakeEnabledFromBuildMarker(INTAKE_BUILD_MARKER) &&
    env.ARC_BUILD_INTAKE_ENABLED === 'true' &&
    intakeEnabledFromAttestation(env[INTAKE_READINESS_ENV]) &&
    intakeActivationReady(env) && intakeArc1RuntimeReady(request, env) &&
    intakeIdempotencyConfigured(env) && intakeAbuseProtectionConfiguration(env).enabled,
  handler,
});

export const config = {
  path: '/api/intake/submit', method: 'POST',
  rateLimit: { windowLimit: 5, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
