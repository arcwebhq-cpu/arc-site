import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { readBoundedRequestText, RequestBodyTooLargeError } from './bounded-request-body.mjs';
import { reviewEmailOutboxConfiguration } from './review-email-outbox-core.mjs';
import { reviewPortalConfiguration } from './review-flow-core.mjs';

export const REVIEW_EMAIL_INTERNAL_SIGNATURE_PREFIX =
  'arc-preview-review-email-internal-request-signature-v1\n';
export const REVIEW_EMAIL_INTERNAL_FRESHNESS_MS = 60_000;

const HEX_64 = /^[a-f0-9]{64}$/;
const INTERNAL_SECRET_ENV = 'ARC_REVIEW_EMAIL_INTERNAL_API_SECRET';

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function validSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}

function exactBoolean(value) {
  return value === 'true' || value === 'false';
}

function requestSignatureInput(method, path, timestamp, body) {
  return `${REVIEW_EMAIL_INTERNAL_SIGNATURE_PREFIX}${timestamp}\n${method}\n${path}\n` +
    createHash('sha256').update(body).digest('hex');
}

export function reviewEmailInternalApiConfiguration(env = process.env) {
  const flagValid = exactBoolean(env.ARC_REVIEW_EMAIL_INTERNAL_API_ENABLED);
  const secret = env[INTERNAL_SECRET_ENV];
  const secretValid = validSecret(secret);
  const secretReused = secretValid && Object.entries(env).some(([name, value]) =>
    name !== INTERNAL_SECRET_ENV && /(?:SECRET|TOKEN|PASSWORD|KEY)$/.test(name) &&
      typeof value === 'string' && value.length > 0 && value === secret);
  const outbox = reviewEmailOutboxConfiguration(env);
  const portalEnabled = reviewPortalConfiguration(env).enabled;
  return Object.freeze({
    enabled: flagValid && env.ARC_REVIEW_EMAIL_INTERNAL_API_ENABLED === 'true' && secretValid &&
      !secretReused && outbox.enabled && portalEnabled,
    flagValid,
    outboxEnabled: outbox.enabled,
    portalEnabled,
    reviewOrigin: outbox.reviewOrigin,
    secretReused,
    secretValid,
  });
}

export function signReviewEmailInternalRequest({ body, method, path, timestamp }, secret) {
  if (!validSecret(secret) || typeof body !== 'string' || method !== 'POST' ||
      typeof path !== 'string' || !path.startsWith('/api/internal/review-email/') ||
      typeof timestamp !== 'string' || new Date(timestamp).toISOString() !== timestamp) {
    throw new TypeError('Review email internal signature input is invalid.');
  }
  return createHmac('sha256', secret)
    .update(requestSignatureInput(method, path, timestamp, body)).digest('hex');
}

export async function readAuthenticatedReviewEmailJson(
  request,
  expectedPath,
  maximumBytes,
  env = process.env,
  adapters = {},
) {
  const configuration = reviewEmailInternalApiConfiguration(env);
  if (!configuration.enabled) throw new Error('ARC_REVIEW_EMAIL_INTERNAL_API_DISABLED');
  if (request.headers.has('origin')) throw new Error('ARC_REVIEW_EMAIL_INTERNAL_UNAUTHORIZED');
  let target;
  try { target = new URL(request.url); } catch {
    throw new Error('ARC_REVIEW_EMAIL_INTERNAL_UNAUTHORIZED');
  }
  if (request.method !== 'POST' || target.protocol !== 'https:' ||
      target.origin !== configuration.reviewOrigin || target.pathname !== expectedPath ||
      target.search || target.hash) {
    throw new Error('ARC_REVIEW_EMAIL_INTERNAL_UNAUTHORIZED');
  }
  const timestamp = request.headers.get('x-arc-review-email-timestamp');
  const signature = request.headers.get('x-arc-review-email-signature');
  if (typeof timestamp !== 'string' || timestamp.length < 20 || timestamp.length > 32 ||
      new Date(timestamp).toISOString() !== timestamp || typeof signature !== 'string' ||
      !HEX_64.test(signature)) {
    throw new Error('ARC_REVIEW_EMAIL_INTERNAL_UNAUTHORIZED');
  }
  const now = adapters.clock?.() || new Date();
  if (!Number.isFinite(now.getTime()) ||
      Math.abs(now.getTime() - Date.parse(timestamp)) > REVIEW_EMAIL_INTERNAL_FRESHNESS_MS) {
    throw new Error('ARC_REVIEW_EMAIL_INTERNAL_UNAUTHORIZED');
  }
  const contentType = (request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new Error('ARC_REVIEW_EMAIL_INTERNAL_JSON_REQUIRED');
  const raw = await readBoundedRequestText(request, maximumBytes);
  const expected = signReviewEmailInternalRequest({
    body: raw,
    method: request.method,
    path: target.pathname,
    timestamp,
  }, env[INTERNAL_SECRET_ENV]);
  if (!safeEqual(signature, expected)) throw new Error('ARC_REVIEW_EMAIL_INTERNAL_UNAUTHORIZED');
  const value = JSON.parse(raw);
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError('Review email internal JSON object is required.');
  }
  return value;
}

export function reviewEmailInternalHttpError(error) {
  const message = error?.message || '';
  if (error instanceof RequestBodyTooLargeError) return [413, 'request_too_large'];
  if (/INTERNAL_UNAUTHORIZED/.test(message)) return [401, 'unauthorized'];
  if (/INTERNAL_JSON_REQUIRED/.test(message)) return [415, 'json_required'];
  if (/NOT_FOUND/.test(message)) return [404, 'email_work_not_found'];
  if (/RECIPIENT_AUTHORITY_CONTENTION/.test(message)) return [503, 'review_email_retry'];
  if (/SUPPRESSED|FINALIZED|EXPIRED|CONFLICT|CONTENTION|BINDING_INVALID|RECEIPT_TRANSITION/.test(message)) {
    return [409, 'email_work_conflict'];
  }
  if (error instanceof TypeError || error?.name === 'SyntaxError') return [400, 'invalid_request'];
  return [503, 'review_email_unavailable'];
}
