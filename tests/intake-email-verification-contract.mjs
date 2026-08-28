import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  config as consumeConfig,
  createIntakeEmailVerificationConsumeHandler,
} from '../netlify/functions/intake-email-verification-consume.mjs';
import pageHandler, { config as pageConfig } from '../netlify/functions/intake-email-verification-page.mjs';
import {
  consumeIntakeEmailVerificationToken,
  consumeVerifiedIntakeForArc1,
  intakeEmailVerificationConfiguration,
  intakeEmailVerificationDispatchReady,
  reserveIntakeEmailVerification,
  validateIntakeEmailVerificationArc1Receipt,
} from '../netlify/lib/intake-email-verification-core.mjs';
import { testActivationAuthority } from './helpers/activation-authority.mjs';

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; this.throwAfterWritePrefix = null; }
  async getWithMetadata(key) {
    const item = this.values.get(key);
    return item ? { data: structuredClone(item.data), etag: item.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    if (options.onlyIfMatch && !current) return { modified: false };
    const etag = `etag-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    if (this.throwAfterWritePrefix && key.startsWith(this.throwAfterWritePrefix)) {
      this.throwAfterWritePrefix = null;
      throw new Error('synthetic ambiguous Blob write');
    }
    return { modified: true, etag };
  }
  async delete(key) { this.values.delete(key); }
}

const now = new Date();
const env = {
  ...testActivationAuthority(now),
  URL: 'https://arcweb.onl',
  ARC_INTAKE_EMAIL_VERIFICATION_ENABLED: 'true',
  ARC_INTAKE_EMAIL_VERIFICATION_STATE_SECRET: 'verification-state-secret-unique-0123456789',
  ARC_INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET: 'verification-token-secret-unique-0123456789',
  ARC_INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET: 'verification-recipient-secret-unique-012345',
  ARC_INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET: 'verification-release-secret-unique-01234567',
};
const source = {
  submission_id: '11111111-1111-4111-8111-111111111111',
  submission_data_sha256: createHash('sha256').update('exact-intake-source').digest('hex'),
  data: { email: 'Owner@Example.test' },
};

assert.equal(intakeEmailVerificationConfiguration(env).enabled, true);
assert.equal(intakeEmailVerificationConfiguration({ ...env, ARC_INTAKE_EMAIL_VERIFICATION_ENABLED: 'false' }).enabled, false);
assert.equal(intakeEmailVerificationConfiguration({
  ...env,
  ARC_INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET: env.ARC_INTAKE_EMAIL_VERIFICATION_STATE_SECRET,
}).enabled, false, 'Every verification HMAC authority must be distinct.');
assert.equal(intakeEmailVerificationConfiguration({
  ...env,
  ARC_OTHER_HMAC_SECRET: env.ARC_INTAKE_EMAIL_VERIFICATION_STATE_SECRET,
}).enabled, false, 'Verification authority reuse with another ARC secret must fail closed.');

const store = new FakeStore();
const reserved = await reserveIntakeEmailVerification(source, env, store, { clock: () => now });
assert.equal(reserved.created, true);
assert.equal(reserved.state, 'PENDING');
const verificationUrl = new URL(reserved.verification_url);
assert.equal(verificationUrl.origin, 'https://arcweb.onl');
assert.equal(verificationUrl.pathname, '/verify/');
assert.equal(verificationUrl.search, '');
assert.match(verificationUrl.hash, /^#arcv1\.[A-Za-z0-9_-]{43}$/);
const token = verificationUrl.hash.slice(1);
const serializedStore = JSON.stringify([...store.values.values()].map((entry) => entry.data));
assert.equal(serializedStore.includes('owner@example.test'), false, 'Raw recipients must not enter verification state.');
assert.equal(serializedStore.includes(token), false, 'Raw bearer tokens must not enter verification state.');
assert.equal([...store.values.keys()].every((key) => !key.includes(token)), true);

const replay = await reserveIntakeEmailVerification(source, env, store, {
  clock: () => new Date(now.getTime() + 2_000),
});
assert.deepEqual(replay, { ...reserved, created: false });
await assert.rejects(consumeVerifiedIntakeForArc1(source, env, store, {
  clock: () => new Date(now.getTime() + 3_000),
}), /VERIFICATION_REQUIRED/);
assert.equal(await intakeEmailVerificationDispatchReady(source, env, store, {
  clock: () => new Date(now.getTime() + 3_000),
}), false);

const verifiedAt = new Date(now.getTime() + 4_000);
const consumed = await consumeIntakeEmailVerificationToken(token, env, store, { clock: () => verifiedAt });
assert.deepEqual(consumed, {
  verified: true,
  submission_id: source.submission_id,
  source_submission_data_sha256: source.submission_data_sha256,
  verification_id_hmac_sha256: reserved.verification_id_hmac_sha256,
});
await assert.rejects(consumeIntakeEmailVerificationToken(token, env, store, {
  clock: () => new Date(now.getTime() + 5_000),
}), /VERIFICATION_REJECTED/, 'The email bearer is one-time and replay-safe.');
assert.equal(await intakeEmailVerificationDispatchReady(source, env, store, {
  clock: () => new Date(now.getTime() + 5_000),
}), true);

const releasedAt = new Date(now.getTime() + 6_000);
const release = await consumeVerifiedIntakeForArc1(source, env, store, { clock: () => releasedAt });
assert.equal(release.idempotent_replay, false);
assert.equal(validateIntakeEmailVerificationArc1Receipt(release.receipt, source, env,
  new Date(now.getTime() + 7_000)), true);
const releaseReplay = await consumeVerifiedIntakeForArc1(source, env, store, {
  clock: () => new Date(now.getTime() + 8_000),
});
assert.deepEqual(releaseReplay, { ...release, idempotent_replay: true });
assert.equal(validateIntakeEmailVerificationArc1Receipt({ ...release.receipt, submission_id:
  '22222222-2222-4222-8222-222222222222' }, source, env, new Date(now.getTime() + 9_000)), false);

const ambiguous = new FakeStore();
ambiguous.throwAfterWritePrefix = 'email-verification/state/';
const repaired = await reserveIntakeEmailVerification({
  ...source, submission_id: '33333333-3333-4333-8333-333333333333',
}, env, ambiguous, { clock: () => now });
assert.equal(repaired.state, 'PENDING', 'A strong read must recover an ambiguous create-only state write.');

await assert.rejects(reserveIntakeEmailVerification(source, {
  ...env, ARC_INTAKE_EMAIL_VERIFICATION_ENABLED: 'false',
}, new Proxy({}, { get() { throw new Error('Disabled verification touched storage.'); } })), /VERIFICATION_DISABLED/);

const pageResponse = await pageHandler(new Request('https://arcweb.onl/verify/'));
assert.equal(pageResponse.status, 200);
assert.equal(pageResponse.headers.get('referrer-policy'), 'no-referrer');
const page = await pageResponse.text();
assert.match(page, /location\.hash\.slice\(1\)/);
assert.ok(page.indexOf("history.replaceState(null, '', '/verify/')") < page.indexOf("fetch('/api/intake/verify'"),
  'The fragment bearer must be erased before any network request.');
assert.doesNotMatch(page, /location\.search|URLSearchParams/);
assert.equal((await pageHandler(new Request('https://arcweb.onl/verify/?token=forbidden'))).status, 404);

const handlerStore = new FakeStore();
const handlerSource = {
  ...source,
  submission_id: '44444444-4444-4444-8444-444444444444',
  submission_data_sha256: createHash('sha256').update('handler-source').digest('hex'),
};
const handlerReserved = await reserveIntakeEmailVerification(handlerSource, env, handlerStore, { clock: () => now });
const handlerToken = new URL(handlerReserved.verification_url).hash.slice(1);
const saved = { ...process.env };
try {
  Object.assign(process.env, env);
  let immediateDispatches = 0;
  const verifiedHandler = createIntakeEmailVerificationConsumeHandler(async (submissionId, _request, _env, adapters) => {
    immediateDispatches += 1;
    assert.equal(submissionId, handlerSource.submission_id);
    assert.equal(adapters.store, handlerStore);
    return { state: 'ACCEPTED' };
  });
  const request = new Request('https://arcweb.onl/api/intake/verify', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: 'https://arcweb.onl',
      'sec-fetch-site': 'same-origin',
    },
    body: JSON.stringify({ schema: 'arc-intake-email-verification-request-v1', token: handlerToken }),
  });
  assert.equal((await verifiedHandler(request, { intakeStore: handlerStore, clock: () => verifiedAt })).status, 200);
  assert.equal(immediateDispatches, 1, 'A consumed mailbox proof should immediately enqueue ARC1 once.');
  assert.equal((await verifiedHandler(new Request('https://arcweb.onl/api/intake/verify', {
    method: 'POST', headers: {
      'content-type': 'application/json', origin: 'https://evil.example', 'sec-fetch-site': 'cross-site',
    }, body: JSON.stringify({ schema: 'arc-intake-email-verification-request-v1', token: handlerToken }),
  }), { intakeStore: handlerStore })).status, 403);
  assert.equal(immediateDispatches, 1);
} finally {
  for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
  Object.assign(process.env, saved);
}

assert.equal(pageConfig.path, '/verify/');
assert.equal(pageConfig.method, 'GET');
assert.equal(consumeConfig.path, '/api/intake/verify');
assert.equal(consumeConfig.method, 'POST');
assert.equal(consumeConfig.rateLimit.windowLimit, 10);

console.log('ARC intake email ownership verification contract passed.');
