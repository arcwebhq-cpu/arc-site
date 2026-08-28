import { createHmac, randomBytes as nodeRandomBytes, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

export const INTAKE_ABUSE_PROTECTION_ENABLED_ENV = 'ARC_INTAKE_ABUSE_PROTECTION_ENABLED';
export const INTAKE_ABUSE_HMAC_SECRET_ENV = 'ARC_INTAKE_ABUSE_HMAC_SECRET';
export const TURNSTILE_SECRET_KEY_ENV = 'ARC_TURNSTILE_SECRET_KEY';
export const TURNSTILE_EXPECTED_HOSTNAME_ENV = 'ARC_TURNSTILE_EXPECTED_HOSTNAME';
export const TURNSTILE_EXPECTED_ACTION_ENV = 'ARC_TURNSTILE_EXPECTED_ACTION';
export const TURNSTILE_MAX_AGE_SECONDS_ENV = 'ARC_TURNSTILE_MAX_AGE_SECONDS';
export const INTAKE_ABUSE_STORE = 'arc-intake-abuse-control';
export const INTAKE_TURNSTILE_ACTION = 'arc_intake_submit';
export const INTAKE_TURNSTILE_RESPONSE_FIELD = 'cf-turnstile-response';
export const TURNSTILE_SITEVERIFY_ENDPOINT = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export const INTAKE_ABUSE_LIMIT_ENV = Object.freeze({
  recipient: Object.freeze({ limit: 'ARC_INTAKE_ABUSE_RECIPIENT_LIMIT', window: 'ARC_INTAKE_ABUSE_RECIPIENT_WINDOW_SECONDS' }),
  domain: Object.freeze({ limit: 'ARC_INTAKE_ABUSE_DOMAIN_LIMIT', window: 'ARC_INTAKE_ABUSE_DOMAIN_WINDOW_SECONDS' }),
  global: Object.freeze({ limit: 'ARC_INTAKE_ABUSE_GLOBAL_LIMIT', window: 'ARC_INTAKE_ABUSE_GLOBAL_WINDOW_SECONDS' }),
});

const TURNSTILE_VERIFY_TIMEOUT_MS = 4_000;
const MAX_TURNSTILE_RESPONSE_BYTES = 16_384;
const REQUEST_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const SUPPRESSION_REASONS = new Set(['DELIVERY_COMPLAINT', 'LEGAL', 'MANUAL_ABUSE', 'SECURITY']);
const EXACT_SUPPRESSION_KEYS = Object.freeze([
  'expires_at', 'identity_hmac_sha256', 'issued_at', 'reason_code', 'record_hmac_sha256', 'schema', 'scope',
].sort());
const EXACT_CIRCUIT_KEYS = Object.freeze([
  'expires_at', 'opened_at', 'reason_code', 'record_hmac_sha256', 'schema', 'state',
].sort());
const EXACT_QUOTA_KEYS = Object.freeze([
  'bucket_expires_at', 'bucket_started_at', 'identity_hmac_sha256', 'record_hmac_sha256',
  'request_hmac_sha256', 'reservation_hmac_sha256', 'schema', 'scope', 'slot',
].sort());

export class IntakeAbuseProtectionError extends Error {
  constructor(code, status = 503) {
    super(code);
    this.name = 'IntakeAbuseProtectionError';
    this.code = code;
    this.status = status;
  }
}

const utf8Bytes = (value) => typeof value === 'string' ? Buffer.byteLength(value, 'utf8') : -1;
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
};
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys);
const safeEqualHex = (left, right) => HEX_64.test(left || '') && HEX_64.test(right || '') &&
  timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
const exactInteger = (raw, minimum, maximum) => {
  if (typeof raw !== 'string' || !/^(?:0|[1-9][0-9]{0,8})$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum ? value : null;
};

function secretIsDistinct(env, name, value) {
  if (utf8Bytes(value) < 20 || utf8Bytes(value) > 256) return false;
  return !Object.entries(env).some(([otherName, otherValue]) => otherName !== name &&
    /(?:SECRET|TOKEN|BEARER|API_KEY|_PAT)$/.test(otherName) && typeof otherValue === 'string' &&
    otherValue.length > 0 && otherValue === value);
}

export function intakeAbuseProtectionConfiguration(env = process.env) {
  const flag = env[INTAKE_ABUSE_PROTECTION_ENABLED_ENV];
  const requested = flag === 'true';
  const missing = [];
  const invalid = [];
  if (flag !== undefined && flag !== 'true' && flag !== 'false') invalid.push(INTAKE_ABUSE_PROTECTION_ENABLED_ENV);
  const required = [
    INTAKE_ABUSE_HMAC_SECRET_ENV,
    TURNSTILE_SECRET_KEY_ENV,
    TURNSTILE_EXPECTED_HOSTNAME_ENV,
    TURNSTILE_EXPECTED_ACTION_ENV,
    TURNSTILE_MAX_AGE_SECONDS_ENV,
    ...Object.values(INTAKE_ABUSE_LIMIT_ENV).flatMap(({ limit, window }) => [limit, window]),
  ];
  if (requested) for (const name of required) {
    if (typeof env[name] !== 'string' || env[name].length === 0) missing.push(name);
  }

  const hmacSecret = env[INTAKE_ABUSE_HMAC_SECRET_ENV];
  const turnstileSecret = env[TURNSTILE_SECRET_KEY_ENV];
  if (requested && !missing.includes(INTAKE_ABUSE_HMAC_SECRET_ENV) &&
      (!secretIsDistinct(env, INTAKE_ABUSE_HMAC_SECRET_ENV, hmacSecret) || utf8Bytes(hmacSecret) < 32)) {
    invalid.push(INTAKE_ABUSE_HMAC_SECRET_ENV);
  }
  if (requested && !missing.includes(TURNSTILE_SECRET_KEY_ENV) &&
      (!/^[A-Za-z0-9_-]{20,128}$/.test(turnstileSecret) ||
       !secretIsDistinct(env, TURNSTILE_SECRET_KEY_ENV, turnstileSecret))) invalid.push(TURNSTILE_SECRET_KEY_ENV);

  const expectedHostname = String(env[TURNSTILE_EXPECTED_HOSTNAME_ENV] || '').toLowerCase();
  if (requested && !missing.includes(TURNSTILE_EXPECTED_HOSTNAME_ENV) &&
      (!HOSTNAME_PATTERN.test(expectedHostname) || expectedHostname !== env[TURNSTILE_EXPECTED_HOSTNAME_ENV])) {
    invalid.push(TURNSTILE_EXPECTED_HOSTNAME_ENV);
  }
  if (requested && !missing.includes(TURNSTILE_EXPECTED_ACTION_ENV) &&
      env[TURNSTILE_EXPECTED_ACTION_ENV] !== INTAKE_TURNSTILE_ACTION) invalid.push(TURNSTILE_EXPECTED_ACTION_ENV);
  const maxAgeSeconds = exactInteger(env[TURNSTILE_MAX_AGE_SECONDS_ENV], 60, 300);
  if (requested && !missing.includes(TURNSTILE_MAX_AGE_SECONDS_ENV) && maxAgeSeconds === null) {
    invalid.push(TURNSTILE_MAX_AGE_SECONDS_ENV);
  }

  const limits = {};
  for (const [scope, names] of Object.entries(INTAKE_ABUSE_LIMIT_ENV)) {
    const limit = exactInteger(env[names.limit], 1, 10_000);
    const windowSeconds = exactInteger(env[names.window], 60, 604_800);
    limits[scope] = Object.freeze({ limit, window_seconds: windowSeconds });
    if (requested && !missing.includes(names.limit) && limit === null) invalid.push(names.limit);
    if (requested && !missing.includes(names.window) && windowSeconds === null) invalid.push(names.window);
  }
  if (requested && Object.values(limits).every(({ limit, window_seconds: window }) => limit !== null && window !== null)) {
    if (limits.domain.limit < limits.recipient.limit) invalid.push(INTAKE_ABUSE_LIMIT_ENV.domain.limit);
    if (limits.global.limit < limits.domain.limit) invalid.push(INTAKE_ABUSE_LIMIT_ENV.global.limit);
  }

  return Object.freeze({
    enabled: requested && missing.length === 0 && invalid.length === 0,
    requested,
    missing: Object.freeze([...new Set(missing)].sort()),
    invalid: Object.freeze([...new Set(invalid)].sort()),
    expected_action: env[TURNSTILE_EXPECTED_ACTION_ENV] || null,
    expected_hostname: expectedHostname || null,
    max_age_seconds: maxAgeSeconds,
    limits: Object.freeze(limits),
  });
}

function configured(env) {
  const configuration = intakeAbuseProtectionConfiguration(env);
  if (!configuration.enabled) throw new IntakeAbuseProtectionError('INTAKE_ABUSE_PROTECTION_DISABLED');
  return configuration;
}

function exactlyOneText(formData, name, maximumBytes) {
  const values = formData.getAll(name);
  if (values.length !== 1 || typeof values[0] !== 'string' || utf8Bytes(values[0]) < 1 ||
      utf8Bytes(values[0]) > maximumBytes) throw new IntakeAbuseProtectionError('INTAKE_CHALLENGE_INVALID', 403);
  return values[0];
}

export function normalizeIntakeAbuseRecipient(value) {
  if (typeof value !== 'string') throw new IntakeAbuseProtectionError('INTAKE_IDENTITY_INVALID', 400);
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !EMAIL_PATTERN.test(email)) {
    throw new IntakeAbuseProtectionError('INTAKE_IDENTITY_INVALID', 400);
  }
  const separator = email.lastIndexOf('@');
  const local = email.slice(0, separator);
  const domain = domainToASCII(email.slice(separator + 1));
  if (!local || !domain || !HOSTNAME_PATTERN.test(domain) || `${local}@${domain}`.length > 254) {
    throw new IntakeAbuseProtectionError('INTAKE_IDENTITY_INVALID', 400);
  }
  return Object.freeze({ email: `${local}@${domain}`, domain });
}

function exactChallengeInput(formData) {
  const token = exactlyOneText(formData, INTAKE_TURNSTILE_RESPONSE_FIELD, 2_048);
  const requestId = exactlyOneText(formData, 'submission_request_id', 64).toLowerCase();
  const botFields = formData.getAll('bot-field');
  if (botFields.length !== 1 || typeof botFields[0] !== 'string' || botFields[0] !== '' ||
      !REQUEST_ID_PATTERN.test(requestId) || /[\u0000-\u001f\u007f]/.test(token)) {
    throw new IntakeAbuseProtectionError('INTAKE_CHALLENGE_INVALID', 403);
  }
  return Object.freeze({ token, request_id: requestId });
}

async function readBoundedJson(response) {
  if (!response || response.status !== 200) throw new IntakeAbuseProtectionError('TURNSTILE_UNAVAILABLE');
  const contentLength = response.headers?.get?.('content-length');
  if (contentLength && (!/^\d{1,8}$/.test(contentLength) || Number(contentLength) > MAX_TURNSTILE_RESPONSE_BYTES)) {
    throw new IntakeAbuseProtectionError('TURNSTILE_UNAVAILABLE');
  }
  const raw = await response.text();
  if (utf8Bytes(raw) < 2 || utf8Bytes(raw) > MAX_TURNSTILE_RESPONSE_BYTES) {
    throw new IntakeAbuseProtectionError('TURNSTILE_UNAVAILABLE');
  }
  try { return JSON.parse(raw); } catch { throw new IntakeAbuseProtectionError('TURNSTILE_UNAVAILABLE'); }
}

async function verifyTurnstile(input, request, configuration, env, adapters) {
  let requestHostname;
  try { requestHostname = new URL(request.url).hostname.toLowerCase(); } catch {
    throw new IntakeAbuseProtectionError('INTAKE_CHALLENGE_INVALID', 403);
  }
  if (requestHostname !== configuration.expected_hostname) {
    throw new IntakeAbuseProtectionError('INTAKE_CHALLENGE_INVALID', 403);
  }
  const body = new URLSearchParams({
    secret: env[TURNSTILE_SECRET_KEY_ENV],
    response: input.token,
    idempotency_key: input.request_id,
  });
  if (typeof adapters.ip === 'string' && isIP(adapters.ip)) body.set('remoteip', adapters.ip);
  const fetchImpl = adapters.fetch || globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new IntakeAbuseProtectionError('TURNSTILE_UNAVAILABLE');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TURNSTILE_VERIFY_TIMEOUT_MS);
  let response;
  try {
    response = await fetchImpl(TURNSTILE_SITEVERIFY_ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: body.toString(),
      redirect: 'error',
      signal: controller.signal,
    });
  } catch {
    throw new IntakeAbuseProtectionError('TURNSTILE_UNAVAILABLE');
  } finally {
    clearTimeout(timer);
  }
  const result = await readBoundedJson(response);
  const now = new Date(adapters.clock?.() || new Date());
  const challengeAt = typeof result.challenge_ts === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(result.challenge_ts)
    ? new Date(result.challenge_ts) : new Date(Number.NaN);
  const age = now.getTime() - challengeAt.getTime();
  if (!Number.isFinite(now.getTime()) || !Number.isFinite(challengeAt.getTime()) || result.success !== true ||
      result.hostname !== configuration.expected_hostname || result.action !== configuration.expected_action ||
      result.cdata !== input.request_id || age < 0 || age > configuration.max_age_seconds * 1_000) {
    throw new IntakeAbuseProtectionError('INTAKE_CHALLENGE_INVALID', 403);
  }
  return Object.freeze({ challenge_at: challengeAt.toISOString(), verified_at: now.toISOString() });
}

async function consumeChallengeReplayGuard(input, verification, env, store) {
  const tokenHmac = hmac(env[INTAKE_ABUSE_HMAC_SECRET_ENV], `arc-intake-turnstile-token-v1\n${input.token}`);
  const key = `challenge-replay/${tokenHmac}`;
  const record = Object.freeze({
    schema: 'arc-intake-turnstile-replay-v1',
    request_hmac_sha256: hmac(env[INTAKE_ABUSE_HMAC_SECRET_ENV], `arc-intake-request-v1\n${input.request_id}`),
    challenge_at: verification.challenge_at,
    consumed_at: verification.verified_at,
    expires_at: new Date(new Date(verification.challenge_at).getTime() + 300_000).toISOString(),
  });
  try {
    const created = await store.setJSON(key, record, { onlyIfNew: true });
    if (created?.modified !== true) throw new IntakeAbuseProtectionError('INTAKE_CHALLENGE_REPLAYED', 403);
  } catch (error) {
    if (error instanceof IntakeAbuseProtectionError) throw error;
    const current = (await store.getWithMetadata(key, { type: 'json', consistency: 'strong' }))?.data;
    if (canonicalJson(current) !== canonicalJson(record)) throw new IntakeAbuseProtectionError('TURNSTILE_UNAVAILABLE');
  }
  return tokenHmac;
}

function suppressionSignature(record, secret) {
  const { record_hmac_sha256: _ignored, ...unsigned } = record;
  return hmac(secret, `arc-intake-abuse-suppression-v1\n${canonicalJson(unsigned)}`);
}

export function buildIntakeAbuseSuppressionRecord(recipient, scope, reasonCode, issuedAt, expiresAt, env = process.env) {
  configured(env);
  const identity = normalizeIntakeAbuseRecipient(recipient);
  if (!['recipient', 'domain'].includes(scope) || !SUPPRESSION_REASONS.has(reasonCode)) {
    throw new TypeError('Suppression scope or reason is invalid.');
  }
  const issued = new Date(issuedAt);
  const expires = new Date(expiresAt);
  if (!Number.isFinite(issued.getTime()) || !Number.isFinite(expires.getTime()) || expires <= issued ||
      expires.getTime() - issued.getTime() > 366 * 24 * 60 * 60_000) throw new TypeError('Suppression lifetime is invalid.');
  const rawIdentity = scope === 'recipient' ? identity.email : identity.domain;
  const identityHmac = hmac(env[INTAKE_ABUSE_HMAC_SECRET_ENV], `arc-intake-abuse-${scope}-v1\n${rawIdentity}`);
  const unsigned = {
    schema: 'arc-intake-abuse-suppression-v1', scope, identity_hmac_sha256: identityHmac,
    reason_code: reasonCode, issued_at: issued.toISOString(), expires_at: expires.toISOString(),
  };
  const record = Object.freeze({ ...unsigned, record_hmac_sha256: suppressionSignature(unsigned, env[INTAKE_ABUSE_HMAC_SECRET_ENV]) });
  return Object.freeze({ key: `suppression/${scope}/${identityHmac}`, record });
}

function validSuppression(record, scope, identityHmac, now, secret) {
  if (!exactKeys(record, EXACT_SUPPRESSION_KEYS) || record.schema !== 'arc-intake-abuse-suppression-v1' ||
      record.scope !== scope || record.identity_hmac_sha256 !== identityHmac || !SUPPRESSION_REASONS.has(record.reason_code) ||
      !safeEqualHex(record.record_hmac_sha256, suppressionSignature(record, secret))) return null;
  const issued = new Date(record.issued_at);
  const expires = new Date(record.expires_at);
  if (!Number.isFinite(issued.getTime()) || !Number.isFinite(expires.getTime()) || issued > now || expires <= issued) return null;
  return expires > now;
}

function circuitSignature(record, secret) {
  const { record_hmac_sha256: _ignored, ...unsigned } = record;
  return hmac(secret, `arc-intake-abuse-circuit-v1\n${canonicalJson(unsigned)}`);
}

function validCircuit(record, now, secret) {
  if (!exactKeys(record, EXACT_CIRCUIT_KEYS) || record.schema !== 'arc-intake-abuse-circuit-v1' ||
      record.state !== 'OPEN' || record.reason_code !== 'GLOBAL_QUOTA' ||
      !safeEqualHex(record.record_hmac_sha256, circuitSignature(record, secret))) return null;
  const opened = new Date(record.opened_at);
  const expires = new Date(record.expires_at);
  if (!Number.isFinite(opened.getTime()) || !Number.isFinite(expires.getTime()) || opened > now || expires <= opened) return null;
  return expires > now;
}

async function assertNotSuppressed(identity, env, store, now) {
  for (const [scope, rawIdentity] of [['recipient', identity.email], ['domain', identity.domain]]) {
    const identityHmac = hmac(env[INTAKE_ABUSE_HMAC_SECRET_ENV], `arc-intake-abuse-${scope}-v1\n${rawIdentity}`);
    const current = (await store.getWithMetadata(`suppression/${scope}/${identityHmac}`, {
      type: 'json', consistency: 'strong',
    }))?.data;
    if (!current) continue;
    const active = validSuppression(current, scope, identityHmac, now, env[INTAKE_ABUSE_HMAC_SECRET_ENV]);
    if (active === null) throw new IntakeAbuseProtectionError('INTAKE_ABUSE_STATE_INVALID');
    if (active) throw new IntakeAbuseProtectionError('INTAKE_SUPPRESSED', 429);
  }
}

async function assertCircuitClosed(env, store, now) {
  const current = (await store.getWithMetadata('circuit-breaker/current-v1', {
    type: 'json', consistency: 'strong',
  }))?.data;
  if (!current) return;
  const active = validCircuit(current, now, env[INTAKE_ABUSE_HMAC_SECRET_ENV]);
  if (active === null) throw new IntakeAbuseProtectionError('INTAKE_ABUSE_STATE_INVALID');
  if (active) throw new IntakeAbuseProtectionError('INTAKE_CIRCUIT_OPEN', 429);
}

async function openGlobalCircuit(env, store, now, expiresAt) {
  const unsigned = {
    schema: 'arc-intake-abuse-circuit-v1', state: 'OPEN', reason_code: 'GLOBAL_QUOTA',
    opened_at: now.toISOString(), expires_at: expiresAt.toISOString(),
  };
  const record = { ...unsigned, record_hmac_sha256: circuitSignature(unsigned, env[INTAKE_ABUSE_HMAC_SECRET_ENV]) };
  try { await store.setJSON('circuit-breaker/current-v1', record); } catch {}
}

function quotaSignature(record, secret) {
  const { record_hmac_sha256: _ignored, ...unsigned } = record;
  return hmac(secret, `arc-intake-abuse-quota-slot-v1\n${canonicalJson(unsigned)}`);
}

function validQuotaSlot(record, expected, secret) {
  if (!exactKeys(record, EXACT_QUOTA_KEYS) || record.schema !== 'arc-intake-abuse-quota-slot-v1' ||
      record.scope !== expected.scope || record.identity_hmac_sha256 !== expected.identity_hmac_sha256 ||
      record.bucket_started_at !== expected.bucket_started_at || record.bucket_expires_at !== expected.bucket_expires_at ||
      record.slot !== expected.slot || !HEX_64.test(record.request_hmac_sha256 || '') ||
      !HEX_64.test(record.reservation_hmac_sha256 || '') ||
      !safeEqualHex(record.record_hmac_sha256, quotaSignature(record, secret))) return false;
  const started = new Date(record.bucket_started_at);
  const expires = new Date(record.bucket_expires_at);
  return Number.isFinite(started.getTime()) && Number.isFinite(expires.getTime()) && expires > started;
}

async function claimQuotaSlot(scope, rawIdentity, requestBinding, configuration, env, store, now, reservationHmac) {
  const { limit, window_seconds: windowSeconds } = configuration.limits[scope];
  const bucketMilliseconds = windowSeconds * 1_000;
  const bucketStart = Math.floor(now.getTime() / bucketMilliseconds) * bucketMilliseconds;
  const bucketExpires = new Date(bucketStart + bucketMilliseconds);
  const bucketStartedAt = new Date(bucketStart).toISOString();
  const bucketExpiresAt = bucketExpires.toISOString();
  const identityHmac = hmac(env[INTAKE_ABUSE_HMAC_SECRET_ENV], `arc-intake-abuse-${scope}-v1\n${rawIdentity}`);
  const requestHmac = hmac(env[INTAKE_ABUSE_HMAC_SECRET_ENV], `arc-intake-request-v1\n${requestBinding}`);
  for (let slot = 0; slot < limit; slot += 1) {
    const key = `quota/${scope}/${identityHmac}/${bucketStartedAt}/${String(slot).padStart(5, '0')}`;
    const unsigned = {
      schema: 'arc-intake-abuse-quota-slot-v1', scope, identity_hmac_sha256: identityHmac,
      request_hmac_sha256: requestHmac, reservation_hmac_sha256: reservationHmac,
      bucket_started_at: bucketStartedAt, bucket_expires_at: bucketExpiresAt, slot,
    };
    const record = { ...unsigned, record_hmac_sha256: quotaSignature(unsigned, env[INTAKE_ABUSE_HMAC_SECRET_ENV]) };
    const expected = { scope, identity_hmac_sha256: identityHmac, bucket_started_at: bucketStartedAt, bucket_expires_at: bucketExpiresAt, slot };
    try {
      const created = await store.setJSON(key, record, { onlyIfNew: true });
      if (created?.modified === true) return { key, created: true, bucket_expires_at: bucketExpires, identity_hmac_sha256: identityHmac };
    } catch (error) {
      const current = (await store.getWithMetadata(key, { type: 'json', consistency: 'strong' }))?.data;
      if (current && !validQuotaSlot(current, expected, env[INTAKE_ABUSE_HMAC_SECRET_ENV])) {
        throw new IntakeAbuseProtectionError('INTAKE_ABUSE_STATE_INVALID');
      }
      if (current?.reservation_hmac_sha256 === reservationHmac && current.request_hmac_sha256 === requestHmac) {
        return { key, created: true, bucket_expires_at: bucketExpires, identity_hmac_sha256: identityHmac };
      }
      if (!current) throw new IntakeAbuseProtectionError('INTAKE_ABUSE_STATE_UNAVAILABLE');
    }
    const current = (await store.getWithMetadata(key, { type: 'json', consistency: 'strong' }))?.data;
    if (!current || !validQuotaSlot(current, expected, env[INTAKE_ABUSE_HMAC_SECRET_ENV])) {
      throw new IntakeAbuseProtectionError('INTAKE_ABUSE_STATE_INVALID');
    }
    if (current.request_hmac_sha256 === requestHmac) {
      return { key, created: false, bucket_expires_at: bucketExpires, identity_hmac_sha256: identityHmac };
    }
  }
  throw new IntakeAbuseProtectionError(`INTAKE_${scope.toUpperCase()}_VELOCITY_EXCEEDED`, 429);
}

async function rollbackCreatedClaims(claims, store) {
  for (const claim of claims.reverse()) if (claim.created) {
    try { await store.delete(claim.key); } catch {}
  }
}

export async function reserveIntakeAbuseAdmission(input, env, store, adapters = {}) {
  const configuration = configured(env);
  if (!store || typeof store.setJSON !== 'function' || typeof store.getWithMetadata !== 'function') {
    throw new IntakeAbuseProtectionError('INTAKE_ABUSE_STATE_UNAVAILABLE');
  }
  const now = new Date(adapters.clock?.() || new Date());
  if (!Number.isFinite(now.getTime())) throw new IntakeAbuseProtectionError('INTAKE_ABUSE_STATE_UNAVAILABLE');
  const identity = normalizeIntakeAbuseRecipient(input.email);
  if (!REQUEST_ID_PATTERN.test(input.request_id || '')) throw new IntakeAbuseProtectionError('INTAKE_IDENTITY_INVALID', 400);
  await assertCircuitClosed(env, store, now);
  await assertNotSuppressed(identity, env, store, now);
  const randomBytes = adapters.randomBytes || nodeRandomBytes;
  const reservationEntropy = randomBytes(32);
  if (!Buffer.isBuffer(reservationEntropy) && !(reservationEntropy instanceof Uint8Array)) {
    throw new IntakeAbuseProtectionError('INTAKE_ABUSE_STATE_UNAVAILABLE');
  }
  const reservationHmac = hmac(env[INTAKE_ABUSE_HMAC_SECRET_ENV],
    `arc-intake-abuse-reservation-v1\n${Buffer.from(reservationEntropy).toString('base64url')}`);
  const requestBinding = `${input.request_id}\n${identity.email}\n${identity.domain}`;
  const claims = [];
  try {
    claims.push(await claimQuotaSlot('global', 'all-public-intake', requestBinding, configuration, env, store, now, reservationHmac));
    claims.push(await claimQuotaSlot('domain', identity.domain, requestBinding, configuration, env, store, now, reservationHmac));
    claims.push(await claimQuotaSlot('recipient', identity.email, requestBinding, configuration, env, store, now, reservationHmac));
  } catch (error) {
    await rollbackCreatedClaims(claims, store);
    if (error instanceof IntakeAbuseProtectionError && error.code === 'INTAKE_GLOBAL_VELOCITY_EXCEEDED') {
      const windowMs = configuration.limits.global.window_seconds * 1_000;
      const expires = new Date(Math.floor(now.getTime() / windowMs) * windowMs + windowMs);
      await openGlobalCircuit(env, store, now, expires);
    }
    throw error;
  }
  return Object.freeze({
    admitted: true,
    recipient_identity_hmac_sha256: claims[2].identity_hmac_sha256,
    domain_identity_hmac_sha256: claims[1].identity_hmac_sha256,
    request_hmac_sha256: hmac(env[INTAKE_ABUSE_HMAC_SECRET_ENV], `arc-intake-request-v1\n${requestBinding}`),
  });
}

export async function protectIntakeForm(formData, request, env, store, adapters = {}) {
  const configuration = configured(env);
  const input = exactChallengeInput(formData);
  const verification = await verifyTurnstile(input, request, configuration, env, adapters);
  await consumeChallengeReplayGuard(input, verification, env, store);
  // Customer identity is not decoded or normalized until the provider-bound
  // challenge has succeeded and its one-time token has been consumed locally.
  const email = exactlyOneText(formData, 'email', 254);
  const admission = await reserveIntakeAbuseAdmission({ ...input, email }, env, store, adapters);
  formData.delete(INTAKE_TURNSTILE_RESPONSE_FIELD);
  return Object.freeze({ ...admission, challenge_at: verification.challenge_at });
}
