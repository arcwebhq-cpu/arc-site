import { safeEqual, sha256Hex } from './arc2-handoff-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const STRIPE_ACCOUNT_VERIFICATION_KEY_ENV = 'ARC_STRIPE_ACCOUNT_VERIFICATION_KEY';
const ACCOUNT_ID_PATTERN = /^acct_[A-Za-z0-9]{6,128}$/;
const EVENT_ID_PATTERN = /^evt_[A-Za-z0-9_]{6,128}$/;
const STRIPE_OBJECT_ID_PATTERN = /^[a-z]+_[A-Za-z0-9_]{6,128}$/;
const RESTRICTED_KEY_PATTERN = /^rk_(test|live)_[A-Za-z0-9_]{16,240}$/;
const MAX_ACCOUNT_RESPONSE_BYTES = 256 * 1024;
const ACCOUNT_REQUEST_TIMEOUT_MS = 5_000;

export function stripeAccountVerificationConfigured(env = process.env) {
  const key = env[STRIPE_ACCOUNT_VERIFICATION_KEY_ENV];
  const match = typeof key === 'string' ? key.match(RESTRICTED_KEY_PATTERN) : null;
  const mode = env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true' ? 'live' :
    env.ARC_STRIPE_LIVE_MODE_ENABLED === 'false' ? 'test' : null;
  if (!match || !mode || match[1] !== mode || key.length > 256) return false;
  return sensitiveCredentialsAreIsolated(env, [STRIPE_ACCOUNT_VERIFICATION_KEY_ENV]);
}

async function readBoundedJson(response) {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null && (!/^\d{1,7}$/.test(declaredLength) || Number(declaredLength) > MAX_ACCOUNT_RESPONSE_BYTES)) {
    throw new Error('ARC_STRIPE_ACCOUNT_VERIFICATION_FAILED');
  }
  const reader = response.body?.getReader?.();
  if (!reader) throw new Error('ARC_STRIPE_ACCOUNT_VERIFICATION_FAILED');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error('ARC_STRIPE_ACCOUNT_VERIFICATION_FAILED');
      total += value.byteLength;
      if (total > MAX_ACCOUNT_RESPONSE_BYTES) {
        try { await reader.cancel(); } catch {}
        throw new Error('ARC_STRIPE_ACCOUNT_VERIFICATION_FAILED');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  try {
    return JSON.parse(Buffer.concat(chunks, total).toString('utf8'));
  } catch {
    throw new Error('ARC_STRIPE_ACCOUNT_VERIFICATION_FAILED');
  }
}

async function stripeGetJson(path, env, fetchImpl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ACCOUNT_REQUEST_TIMEOUT_MS);
  let value;
  try {
    const response = await fetchImpl(`https://api.stripe.com${path}`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${env[STRIPE_ACCOUNT_VERIFICATION_KEY_ENV]}`,
        'Stripe-Version': env.ARC_STRIPE_WEBHOOK_API_VERSION,
      },
      redirect: 'error',
      signal: controller.signal,
    });
    if (!response || response.status !== 200 ||
        (response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      throw new Error('ARC_STRIPE_ACCOUNT_VERIFICATION_FAILED');
    }
    value = await readBoundedJson(response);
  } catch (cause) {
    if (/^ARC_STRIPE_ACCOUNT_VERIFICATION_/.test(cause?.message || '')) throw cause;
    throw new Error('ARC_STRIPE_ACCOUNT_VERIFICATION_FAILED', { cause });
  } finally {
    clearTimeout(timer);
  }
  return value;
}

export async function verifyStripeAccountBinding(env = process.env, adapters = {}) {
  if (!stripeAccountVerificationConfigured(env)) throw new Error('ARC_STRIPE_ACCOUNT_VERIFICATION_DISABLED');
  const account = await stripeGetJson('/v1/account', env, adapters.fetch || fetch);
  if (!account || typeof account !== 'object' || Array.isArray(account) || account.object !== 'account' ||
      typeof account.id !== 'string' || !ACCOUNT_ID_PATTERN.test(account.id) ||
      !safeEqual(sha256Hex(account.id), env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256)) {
    throw new Error('ARC_STRIPE_ACCOUNT_BINDING_MISMATCH');
  }
  return {
    account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    verified: true,
  };
}

export async function verifyStripeEventOwnership(event, env = process.env, adapters = {}) {
  if (!event || typeof event !== 'object' || Array.isArray(event) || !EVENT_ID_PATTERN.test(String(event.eventId || '')) ||
      typeof event.eventType !== 'string' || event.eventType.length < 3 || event.eventType.length > 128 ||
      typeof event.livemode !== 'boolean' || !STRIPE_OBJECT_ID_PATTERN.test(String(event.objectId || '')) ||
      typeof event.objectType !== 'string' || event.objectType.length < 3 || event.objectType.length > 64) {
    throw new TypeError('Stripe event ownership input is invalid.');
  }
  await verifyStripeAccountBinding(env, adapters);
  const remote = await stripeGetJson(`/v1/events/${encodeURIComponent(event.eventId)}`, env, adapters.fetch || fetch);
  const remoteObject = remote?.data?.object;
  if (!remote || typeof remote !== 'object' || Array.isArray(remote) || remote.object !== 'event' ||
      remote.id !== event.eventId || remote.type !== event.eventType || remote.livemode !== event.livemode ||
      remote.api_version !== env.ARC_STRIPE_WEBHOOK_API_VERSION || !remoteObject || typeof remoteObject !== 'object' ||
      Array.isArray(remoteObject) || remoteObject.id !== event.objectId || remoteObject.object !== event.objectType ||
      (remote.account !== undefined && (typeof remote.account !== 'string' || !ACCOUNT_ID_PATTERN.test(remote.account) ||
        !safeEqual(sha256Hex(remote.account), env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256)))) {
    throw new Error('ARC_STRIPE_EVENT_OWNERSHIP_MISMATCH');
  }
  return {
    account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    event_id: event.eventId,
    verified: true,
  };
}
