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

export function createIntakeSubmitHandler(buildMarker = INTAKE_BUILD_MARKER, runtimeReady = intakeArc1RuntimeReady) {
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
      !intakeEnabledFromAttestation(process.env[INTAKE_READINESS_ENV]) || !intakeActivationReady(process.env) ||
      !runtimeReady(request, process.env) ||
      !intakeIdempotencyConfigured(process.env)) {
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
    const normalized = await normalizeIntakeForm(
      await boundedFormData(request, contentType),
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
    // A same-deploy background invocation is best-effort and separately gated.
    // The accepted intake remains durable even if dispatch is paused or fails;
    // dispatch state records the failure for an authenticated recovery run.
    try {
      await dispatchIntakeToArc1Background(normalized.record.submission_id, request, process.env, {
        store, fetch: context.fetch, clock: context.clock,
      });
    } catch {}
    return response(created ? 201 : 200, {
      schema: INTAKE_RESPONSE_SCHEMA, accepted: true, submission_id: normalized.record.submission_id,
    });
  } catch (error) {
    if (error instanceof IntakeRequestError) return response(error.status, { error: error.code });
    if (error instanceof TypeError || error?.name === 'SyntaxError') return response(400, { error: 'invalid_intake' });
    if (/CONFLICT/.test(error?.message || '')) return response(409, { error: 'intake_conflict' });
    return response(503, { error: 'intake_unavailable' });
  }
  };
}

export default createIntakeSubmitHandler();

export const config = {
  path: '/api/intake/submit', method: 'POST',
  rateLimit: { windowLimit: 5, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
