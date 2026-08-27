import { readBoundedRequestText, RequestBodyTooLargeError } from './bounded-request-body.mjs';

export const REVIEW_COOKIE_NAME = '__Host-arc_review_session';
const ALLOWED_ORIGINS = new Set(['https://arcweb.onl', 'https://arcsites.netlify.app']);

export function reviewJsonResponse(status, value, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
    ...headers,
  } });
}

export function requestOriginAllowed(request, requireOriginHeader = true) {
  let origin;
  try { origin = new URL(request.url).origin; } catch { return false; }
  if (!ALLOWED_ORIGINS.has(origin)) return false;
  return !requireOriginHeader || request.headers.get('origin') === origin;
}

export function reviewSessionCookie(request) {
  const cookies = (request.headers.get('cookie') || '').split(';').map(value => value.trim()).filter(Boolean);
  const matches = cookies.filter(value => value.startsWith(`${REVIEW_COOKIE_NAME}=`));
  if (matches.length !== 1) return null;
  const value = matches[0].slice(REVIEW_COOKIE_NAME.length + 1);
  return value.length >= 100 && value.length <= 1024 ? value : null;
}

export function sessionSetCookie(sessionToken, maxAge) {
  if (typeof sessionToken !== 'string' || !Number.isSafeInteger(maxAge) || maxAge < 1 || maxAge > 86400) {
    throw new TypeError('Review session cookie is invalid.');
  }
  return `${REVIEW_COOKIE_NAME}=${sessionToken}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Strict`;
}

export async function readReviewJson(request, maximumBytes) {
  const contentType = (request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new TypeError('JSON is required.');
  const text = await readBoundedRequestText(request, maximumBytes);
  const value = JSON.parse(text);
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError('JSON object is required.');
  }
  return value;
}

export function reviewHttpError(error) {
  const message = error?.message || '';
  if (error instanceof RequestBodyTooLargeError) return [413, 'request_too_large'];
  if (/SESSION_|INVITE_(?:INVALID|NOT_FOUND|EXPIRED|INACTIVE|ALREADY_EXCHANGED)/.test(message)) return [401, 'review_credential_invalid'];
  if (/REVISION_LIMIT/.test(message)) return [409, 'revision_limit_reached'];
  if (/STALE_DECISION|DECISION_CONFLICT|STATE_CONTENTION/.test(message)) return [409, 'review_conflict'];
  if (/APPROVAL_REQUIRED/.test(message)) return [409, 'approval_required'];
  if (/CHECKOUT_UNAVAILABLE/.test(message)) return [503, 'checkout_unavailable'];
  if (error instanceof TypeError || error?.name === 'SyntaxError') return [400, 'invalid_request'];
  return [503, 'review_unavailable'];
}
