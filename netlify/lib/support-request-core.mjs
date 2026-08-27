import { createHash } from 'node:crypto';

export const SUPPORT_REQUEST_STORE = 'arc-support-requests';
export const SUPPORT_REQUEST_SCHEMA = 'arc-support-request-outbox-v1';
export const SUPPORT_RESPONSE_SCHEMA = 'arc-support-request-accepted-v1';
export const SUPPORT_MAX_REQUEST_BYTES = 12_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const CATEGORIES = new Set(['project', 'launch_bug', 'billing_refund', 'privacy', 'other']);
const FIELDS = Object.freeze([
  'business', 'category', 'company_website', 'details', 'email', 'form_started_at',
  'name', 'project_url', 'request_id',
]);

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

const sha256 = value => createHash('sha256').update(value).digest('hex');

function exactObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...FIELDS].sort());
}

function text(value, field, minimum, maximum, optional = false) {
  if (typeof value !== 'string') throw new TypeError(`${field} must be text.`);
  const clean = value.trim().replace(/\r\n?/g, '\n');
  if (optional && clean === '') return null;
  if (clean.length < minimum || clean.length > maximum || CONTROL.test(clean)) {
    throw new TypeError(`${field} is invalid.`);
  }
  return clean;
}

function webUrl(value) {
  const clean = text(value, 'project_url', 1, 2048, true);
  if (clean === null) return null;
  let parsed;
  try { parsed = new URL(clean); } catch { throw new TypeError('project_url is invalid.'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new TypeError('project_url is invalid.');
  }
  return parsed.href;
}

export function supportRequestKey(requestId) {
  if (!UUID.test(String(requestId || ''))) throw new TypeError('request_id is invalid.');
  return `support-outbox/${requestId.toLowerCase()}`;
}

export function normalizeSupportRequest(value, now = new Date()) {
  if (!exactObject(value)) throw new TypeError('Support request fields are invalid.');
  const receivedAt = new Date(now);
  if (!Number.isFinite(receivedAt.getTime())) throw new TypeError('Server time is invalid.');
  if (!UUID.test(value.request_id)) throw new TypeError('request_id is invalid.');
  if (!Number.isSafeInteger(value.form_started_at)) throw new TypeError('form_started_at is invalid.');
  const elapsed = receivedAt.getTime() - value.form_started_at;
  if (elapsed < 1_500 || elapsed > 86_400_000) throw new TypeError('form timing is invalid.');
  if (value.company_website !== '') throw new TypeError('Support request rejected.');
  if (!CATEGORIES.has(value.category)) throw new TypeError('category is invalid.');

  const normalized = {
    request_id: value.request_id.toLowerCase(),
    name: text(value.name, 'name', 2, 100),
    email: text(value.email, 'email', 3, 254).toLowerCase(),
    business: text(value.business, 'business', 1, 120, true),
    category: value.category,
    project_url: webUrl(value.project_url),
    details: text(value.details, 'details', 20, 4000),
  };
  if (!EMAIL.test(normalized.email)) throw new TypeError('email is invalid.');

  const createdAt = receivedAt.toISOString();
  const payloadSha256 = sha256(canonicalJson(normalized));
  return {
    key: supportRequestKey(normalized.request_id),
    record: {
      schema: SUPPORT_REQUEST_SCHEMA,
      version: 1,
      record_revision: 1,
      state: 'PENDING',
      request_id: normalized.request_id,
      payload_sha256: payloadSha256,
      created_at: createdAt,
      updated_at: createdAt,
      name: normalized.name,
      email: normalized.email,
      email_sha256: sha256(normalized.email),
      business: normalized.business,
      category: normalized.category,
      project_url: normalized.project_url,
      details: normalized.details,
      attempt_count: 0,
      next_attempt_at: createdAt,
      lease_hmac_sha256: null,
      lease_expires_at: null,
      delivered_at: null,
      provider_receipt_sha256: null,
      last_error_code: null,
    },
  };
}

export function isExactSupportRetry(existing, expected) {
  return existing?.schema === SUPPORT_REQUEST_SCHEMA && existing.version === 1 &&
    existing.request_id === expected.request_id && existing.payload_sha256 === expected.payload_sha256;
}
