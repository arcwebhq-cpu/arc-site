import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const RESEND_SEND_ENABLED_ENV = 'ARC_RESEND_SEND_ENABLED';
export const RESEND_WEBHOOK_ENABLED_ENV = 'ARC_RESEND_WEBHOOK_ENABLED';
export const RESEND_API_KEY_ENV = 'ARC_RESEND_API_KEY';
export const RESEND_WEBHOOK_SECRET_ENV = 'ARC_RESEND_WEBHOOK_SECRET';
export const RESEND_FROM_ENV = 'ARC_RESEND_FROM';
export const RESEND_SEND_ENDPOINT = 'https://api.resend.com/emails';
export const RESEND_REQUEST_TIMEOUT_MS = 10_000;
export const RESEND_WEBHOOK_TOLERANCE_SECONDS = 5 * 60;
export const RESEND_RECONCILED_EVENT_TYPES = Object.freeze([
  'email.sent',
  'email.delivery_delayed',
  'email.delivered',
  'email.bounced',
  'email.complained',
  'email.failed',
  'email.suppressed',
]);

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const CONTROL = /[\u0000-\u001f\u007f]/;
const SVIX_ID = /^[A-Za-z0-9_-]{1,256}$/;
const MAX_WEBHOOK_BYTES = 65_536;
const MAX_RESPONSE_BYTES = 16_384;

const exactKeys = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function safeEqualBuffers(left, right) {
  return left.length === right.length && timingSafeEqual(left, right);
}

function apiKey(value) {
  if (typeof value !== 'string' || !/^re_[A-Za-z0-9_-]{16,252}$/.test(value)) {
    throw new TypeError(`${RESEND_API_KEY_ENV} is invalid.`);
  }
  return value;
}

function fromAddress(value) {
  if (typeof value !== 'string' || value.length < 3 || value.length > 254 || value !== value.trim() || CONTROL.test(value)) {
    throw new TypeError(`${RESEND_FROM_ENV} is invalid.`);
  }
  const bracketed = value.match(/^([^<>]{1,100}) <([^<>]+)>$/);
  const address = (bracketed ? bracketed[2] : value).toLowerCase();
  if (!EMAIL.test(address)) throw new TypeError(`${RESEND_FROM_ENV} is invalid.`);
  return value;
}

function strictBase64(value, label) {
  if (typeof value !== 'string' || value.length < 20 || value.length > 256 ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 === 1) {
    throw new TypeError(`${label} is invalid.`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length < 16 || decoded.length > 128 || decoded.toString('base64').replace(/=+$/, '') !== value.replace(/=+$/, '')) {
    throw new TypeError(`${label} is invalid.`);
  }
  return decoded;
}

function webhookSecret(value) {
  if (typeof value !== 'string' || !value.startsWith('whsec_')) {
    throw new TypeError(`${RESEND_WEBHOOK_SECRET_ENV} is invalid.`);
  }
  return strictBase64(value.slice(6), RESEND_WEBHOOK_SECRET_ENV);
}

export function resendProviderConfiguration(env = process.env) {
  let sender = null;
  let sendKey = null;
  let signingKey = null;
  try { sender = fromAddress(env[RESEND_FROM_ENV]); } catch {}
  try { sendKey = apiKey(env[RESEND_API_KEY_ENV]); } catch {}
  try { signingKey = webhookSecret(env[RESEND_WEBHOOK_SECRET_ENV]); } catch {}
  return Object.freeze({
    send_enabled: env[RESEND_SEND_ENABLED_ENV] === 'true' && Boolean(sender && sendKey),
    webhook_enabled: env[RESEND_WEBHOOK_ENABLED_ENV] === 'true' && Boolean(signingKey),
    from: sender,
    apiKey: sendKey,
    webhookSigningKey: signingKey,
  });
}

function text(value, label, maximum) {
  if (typeof value !== 'string' || value.length < 1 || Buffer.byteLength(value, 'utf8') > maximum || CONTROL.test(value)) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function recipient(value) {
  const normalized = text(value, 'Resend recipient', 254).toLowerCase();
  if (normalized !== value.trim().toLowerCase() || !EMAIL.test(normalized)) throw new TypeError('Resend recipient is invalid.');
  return normalized;
}

function tag(value) {
  if (!exactKeys(value, ['name', 'value']) || !/^[A-Za-z0-9_-]{1,256}$/.test(value.name) ||
      !/^[A-Za-z0-9_-]{1,256}$/.test(value.value)) throw new TypeError('Resend tag is invalid.');
  return { name: value.name, value: value.value };
}

function outboundMessage(input, sender) {
  if (!exactKeys(input, ['html', 'subject', 'tags', 'text', 'to']) || !Array.isArray(input.tags) || input.tags.length > 10) {
    throw new TypeError('Resend message is invalid.');
  }
  return {
    from: sender,
    to: [recipient(input.to)],
    subject: text(input.subject, 'Resend subject', 998),
    text: text(input.text, 'Resend text', 50_000),
    html: text(input.html, 'Resend HTML', 100_000),
    tags: input.tags.map(tag),
  };
}

function idempotencyKey(value) {
  if (typeof value !== 'string' || value.length < 1 || Buffer.byteLength(value, 'utf8') > 256 || CONTROL.test(value)) {
    throw new TypeError('Resend idempotency key is invalid.');
  }
  return value;
}

async function boundedJson(response) {
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_RESPONSE_BYTES) throw new Error('ARC_RESEND_RESPONSE_INVALID');
  let raw;
  try { raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw new Error('ARC_RESEND_RESPONSE_INVALID'); }
  let value;
  try { value = JSON.parse(raw); } catch { throw new Error('ARC_RESEND_RESPONSE_INVALID'); }
  return value;
}

export async function sendResendTransactionalEmail(input, providerIdempotencyKey, env = process.env, adapters = {}) {
  const configuration = resendProviderConfiguration(env);
  if (!configuration.send_enabled) throw new Error('ARC_RESEND_SEND_DISABLED');
  const key = idempotencyKey(providerIdempotencyKey);
  const body = JSON.stringify(outboundMessage(input, configuration.from));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RESEND_REQUEST_TIMEOUT_MS);
  let response;
  try {
    response = await (adapters.fetch || fetch)(RESEND_SEND_ENDPOINT, {
      method: 'POST',
      redirect: 'error',
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${configuration.apiKey}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': key,
      },
      body,
    });
  } catch { throw new Error('ARC_RESEND_SEND_AMBIGUOUS'); }
  finally { clearTimeout(timer); }
  const value = await boundedJson(response);
  if (response.status !== 200 || !exactKeys(value, ['id']) || !UUID.test(value.id)) {
    if (response.status === 409) throw new Error('ARC_RESEND_IDEMPOTENCY_CONFLICT');
    throw new Error('ARC_RESEND_SEND_REJECTED');
  }
  const acceptedAt = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(acceptedAt.getTime())) throw new TypeError('Resend acceptance clock is invalid.');
  return Object.freeze({
    provider: 'resend',
    provider_message_id: value.id.toLowerCase(),
    accepted_at: acceptedAt.toISOString(),
  });
}

function singleHeader(headers, name, options = {}) {
  const value = headers.get(name);
  if (typeof value !== 'string' || value.length < 1 || (!options.allowComma && value.includes(','))) {
    throw new Error('ARC_RESEND_WEBHOOK_SIGNATURE_INVALID');
  }
  return value;
}

function parseSignatures(value) {
  if (typeof value !== 'string' || value.length > 4_096) throw new Error('ARC_RESEND_WEBHOOK_SIGNATURE_INVALID');
  const signatures = [];
  for (const item of value.trim().split(/\s+/)) {
    const parts = item.split(',');
    if (parts.length !== 2 || parts[0] !== 'v1') continue;
    try { signatures.push(strictBase64(parts[1], 'Svix signature')); } catch {}
  }
  if (signatures.length < 1) throw new Error('ARC_RESEND_WEBHOOK_SIGNATURE_INVALID');
  return signatures;
}

export function verifyAndNormalizeResendWebhook(rawBody, headers, env = process.env, adapters = {}) {
  const configuration = resendProviderConfiguration(env);
  if (!configuration.webhook_enabled) throw new Error('ARC_RESEND_WEBHOOK_DISABLED');
  if (!(typeof rawBody === 'string' || rawBody instanceof Uint8Array)) {
    throw new TypeError('Resend webhook body is invalid.');
  }
  const rawBytes = typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') :
    Buffer.from(rawBody.buffer, rawBody.byteOffset, rawBody.byteLength);
  if (rawBytes.byteLength > MAX_WEBHOOK_BYTES) throw new TypeError('Resend webhook body is invalid.');
  let rawText;
  try { rawText = new TextDecoder('utf-8', { fatal: true }).decode(rawBytes); }
  catch { throw new TypeError('Resend webhook body is invalid.'); }
  const svixId = singleHeader(headers, 'svix-id');
  if (!SVIX_ID.test(svixId)) throw new Error('ARC_RESEND_WEBHOOK_SIGNATURE_INVALID');
  const timestampRaw = singleHeader(headers, 'svix-timestamp');
  if (!/^\d{10}$/.test(timestampRaw)) throw new Error('ARC_RESEND_WEBHOOK_SIGNATURE_INVALID');
  const timestamp = Number(timestampRaw);
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime()) || Math.abs(Math.floor(now.getTime() / 1000) - timestamp) >
      RESEND_WEBHOOK_TOLERANCE_SECONDS) throw new Error('ARC_RESEND_WEBHOOK_TIMESTAMP_INVALID');
  const supplied = parseSignatures(singleHeader(headers, 'svix-signature', { allowComma: true }));
  const expected = createHmac('sha256', configuration.webhookSigningKey)
    .update(`${svixId}.${timestampRaw}.`).update(rawBytes).digest();
  if (!supplied.some((candidate) => safeEqualBuffers(candidate, expected))) {
    throw new Error('ARC_RESEND_WEBHOOK_SIGNATURE_INVALID');
  }
  let event;
  try { event = JSON.parse(rawText); } catch { throw new TypeError('Resend webhook body is invalid.'); }
  if (!event || typeof event !== 'object' || Array.isArray(event) ||
      typeof event.type !== 'string' || !/^email\.[a-z_]+$/.test(event.type) ||
      typeof event.created_at !== 'string' || !event.data || typeof event.data !== 'object' ||
      Array.isArray(event.data) || !UUID.test(event.data.email_id || '')) {
    throw new TypeError('Resend webhook event is invalid.');
  }
  const occurred = Date.parse(event.created_at);
  if (!Number.isFinite(occurred) || new Date(occurred).toISOString() !== event.created_at) {
    throw new TypeError('Resend webhook event timestamp is invalid.');
  }
  return Object.freeze({
    provider: 'resend',
    provider_event_id: svixId,
    provider_message_id: event.data.email_id.toLowerCase(),
    event_type: event.type,
    occurred_at: event.created_at,
    payload_sha256: sha256(rawBytes),
    supported_event: RESEND_RECONCILED_EVENT_TYPES.includes(event.type),
  });
}
