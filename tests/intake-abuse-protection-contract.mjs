import assert from 'node:assert/strict';

import { createIntakeSubmitHandler } from '../netlify/functions/intake-submit.mjs';
import {
  INTAKE_TURNSTILE_RESPONSE_FIELD,
  IntakeAbuseProtectionError,
  buildIntakeAbuseSuppressionRecord,
  intakeAbuseProtectionConfiguration,
  protectIntakeForm,
} from '../netlify/lib/intake-abuse-protection-core.mjs';
import {
  INTAKE_READINESS_BOOLEAN_FIELDS,
  INTAKE_READINESS_ENV,
  INTAKE_READINESS_SCHEMA,
  INTAKE_READINESS_VERSION,
} from '../netlify/lib/intake-readiness-core.mjs';
import { testActivationAuthority } from './helpers/activation-authority.mjs';

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; this.writes = 0; this.reads = 0; this.deletes = 0; }
  async getWithMetadata(key) {
    this.reads += 1;
    const current = this.values.get(key);
    return current ? { data: structuredClone(current.data), etag: current.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    this.writes += 1;
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    if (options.onlyIfMatch && !current) return { modified: false };
    const etag = `etag-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
  async delete(key) { this.deletes += 1; this.values.delete(key); }
}

const now = new Date('2026-08-28T12:00:00.000Z');
const baseEnv = {
  ARC_INTAKE_ABUSE_PROTECTION_ENABLED: 'true',
  ARC_INTAKE_ABUSE_HMAC_SECRET: 'abuse-hmac-secret-unique-0123456789-abcdef',
  ARC_TURNSTILE_SECRET_KEY: 'turnstile-secret-unique-0123456789-abcd',
  ARC_TURNSTILE_EXPECTED_HOSTNAME: 'arcweb.onl',
  ARC_TURNSTILE_EXPECTED_ACTION: 'arc_intake_submit',
  ARC_TURNSTILE_MAX_AGE_SECONDS: '300',
  ARC_INTAKE_ABUSE_RECIPIENT_LIMIT: '2',
  ARC_INTAKE_ABUSE_RECIPIENT_WINDOW_SECONDS: '86400',
  ARC_INTAKE_ABUSE_DOMAIN_LIMIT: '4',
  ARC_INTAKE_ABUSE_DOMAIN_WINDOW_SECONDS: '3600',
  ARC_INTAKE_ABUSE_GLOBAL_LIMIT: '10',
  ARC_INTAKE_ABUSE_GLOBAL_WINDOW_SECONDS: '3600',
};

const requestId = (digit) => `${digit.repeat(8)}-${digit.repeat(4)}-4${digit.repeat(3)}-8${digit.repeat(3)}-${digit.repeat(12)}`;
const challengeForm = ({ token = 'turnstile-token-value', id = requestId('1'), email = 'Owner@Example.test' } = {}) => {
  const form = new FormData();
  form.set(INTAKE_TURNSTILE_RESPONSE_FIELD, token);
  form.set('submission_request_id', id);
  form.set('email', email);
  form.set('bot-field', '');
  return form;
};
const request = (hostname = 'arcweb.onl') => new Request(`https://${hostname}/api/intake/submit`, {
  method: 'POST', headers: { origin: `https://${hostname}` },
});
const siteverify = (overrides = {}) => ({
  success: true,
  challenge_ts: new Date(now.getTime() - 10_000).toISOString(),
  hostname: 'arcweb.onl',
  action: 'arc_intake_submit',
  cdata: requestId('1'),
  ...overrides,
});
const fetchFor = (result, observe = () => {}) => async (url, options) => {
  observe(url, options);
  return new Response(JSON.stringify(result), {
    status: 200,
    headers: { 'content-type': 'application/json', 'content-length': String(JSON.stringify(result).length) },
  });
};

assert.equal(intakeAbuseProtectionConfiguration({}).enabled, false, 'Protection must default OFF and fail closed.');
assert.equal(intakeAbuseProtectionConfiguration({ ARC_INTAKE_ABUSE_PROTECTION_ENABLED: 'yes' }).enabled, false);
assert.equal(intakeAbuseProtectionConfiguration(baseEnv).enabled, true);
assert.equal(intakeAbuseProtectionConfiguration({
  ...baseEnv,
  ARC_INTAKE_ABUSE_HMAC_SECRET: baseEnv.ARC_TURNSTILE_SECRET_KEY,
}).enabled, false, 'The abuse HMAC and provider secret may not share authority.');
assert.equal(intakeAbuseProtectionConfiguration({
  ...baseEnv,
  ARC_INTAKE_ABUSE_HMAC_SECRET_ROTATED: baseEnv.ARC_INTAKE_ABUSE_HMAC_SECRET,
}).enabled, false, 'A renamed abuse credential copy must fail closed.');

const verifiedStore = new FakeStore();
const verifiedForm = challengeForm();
let providerRequest;
const verified = await protectIntakeForm(verifiedForm, request(), baseEnv, verifiedStore, {
  clock: () => now,
  ip: '203.0.113.8',
  randomBytes: () => Buffer.alloc(32, 7),
  fetch: fetchFor(siteverify(), (url, options) => { providerRequest = { url, options }; }),
});
assert.equal(verified.admitted, true);
assert.equal(verifiedForm.has(INTAKE_TURNSTILE_RESPONSE_FIELD), false,
  'The provider token must be removed before strict intake normalization and persistence.');
assert.equal(providerRequest.url, 'https://challenges.cloudflare.com/turnstile/v0/siteverify');
assert.equal(providerRequest.options.redirect, 'error');
const providerBody = new URLSearchParams(providerRequest.options.body);
assert.equal(providerBody.get('secret'), baseEnv.ARC_TURNSTILE_SECRET_KEY);
assert.equal(providerBody.get('response'), 'turnstile-token-value');
assert.equal(providerBody.get('idempotency_key'), requestId('1'));
assert.equal(providerBody.get('remoteip'), '203.0.113.8');
assert.equal(providerBody.has('email'), false);
const serializedVerifiedState = JSON.stringify([...verifiedStore.values.entries()]);
assert.equal(serializedVerifiedState.toLowerCase().includes('owner@example.test'), false);
assert.equal(serializedVerifiedState.includes('example.test'), false,
  'Quota, replay, and suppression state must contain only HMAC-keyed recipient identities.');
assert.equal(serializedVerifiedState.includes('turnstile-token-value'), false);

for (const [label, result] of [
  ['invalid', siteverify({ success: false })],
  ['expired', siteverify({ challenge_ts: new Date(now.getTime() - 300_001).toISOString() })],
  ['future', siteverify({ challenge_ts: new Date(now.getTime() + 1).toISOString() })],
  ['hostname', siteverify({ hostname: 'attacker.example' })],
  ['action', siteverify({ action: 'other_action' })],
  ['nonce', siteverify({ cdata: requestId('2') })],
]) {
  const store = new FakeStore();
  await assert.rejects(protectIntakeForm(challengeForm(), request(), baseEnv, store, {
    clock: () => now, fetch: fetchFor(result), randomBytes: () => Buffer.alloc(32, 3),
  }), (error) => error instanceof IntakeAbuseProtectionError && error.status === 403, label);
  assert.equal(store.writes, 0, `${label} challenge rejection must have zero Blob writes.`);
  assert.equal(store.values.size, 0, `${label} challenge rejection must leave zero durable side effects.`);
}

{
  const store = new FakeStore();
  let providerCalls = 0;
  await assert.rejects(protectIntakeForm(
    challengeForm({ email: 'not-an-email' }), request(), baseEnv, store,
    {
      clock: () => now,
      fetch: fetchFor(siteverify({ success: false }), () => { providerCalls += 1; }),
      randomBytes: () => Buffer.alloc(32, 8),
    },
  ), /INTAKE_CHALLENGE_INVALID/);
  assert.equal(providerCalls, 1,
    'The provider challenge must be decided before customer identity normalization.');
  assert.equal(store.writes, 0);
}

{
  const store = new FakeStore();
  let fetchCalls = 0;
  await assert.rejects(protectIntakeForm(challengeForm(), request('arcsites.netlify.app'), baseEnv, store, {
    clock: () => now,
    fetch: async () => { fetchCalls += 1; throw new Error('must not call'); },
  }), /INTAKE_CHALLENGE_INVALID/);
  assert.equal(fetchCalls, 0, 'An unexpected request host must fail before provider traffic.');
  assert.equal(store.writes, 0);
}

{
  const store = new FakeStore();
  const form = challengeForm();
  await protectIntakeForm(form, request(), baseEnv, store, {
    clock: () => now, fetch: fetchFor(siteverify()), randomBytes: () => Buffer.alloc(32, 4),
  });
  const sizeAfterFirst = store.values.size;
  await assert.rejects(protectIntakeForm(challengeForm(), request(), baseEnv, store, {
    clock: () => new Date(now.getTime() + 1_000),
    fetch: fetchFor(siteverify({ challenge_ts: new Date(now.getTime() - 9_000).toISOString() })),
    randomBytes: () => Buffer.alloc(32, 5),
  }), /INTAKE_CHALLENGE_REPLAYED/);
  assert.equal(store.values.size, sizeAfterFirst, 'A replayed challenge must not add quota or customer state.');
}

{
  const distributedEnv = {
    ...baseEnv,
    ARC_INTAKE_ABUSE_RECIPIENT_LIMIT: '1',
    ARC_INTAKE_ABUSE_DOMAIN_LIMIT: '2',
    ARC_INTAKE_ABUSE_GLOBAL_LIMIT: '3',
  };
  const store = new FakeStore();
  await protectIntakeForm(challengeForm({ token: 'distributed-token-one' }), request(), distributedEnv, store, {
    clock: () => now, ip: '198.51.100.10', fetch: fetchFor(siteverify()), randomBytes: () => Buffer.alloc(32, 1),
  });
  const secondId = requestId('2');
  await assert.rejects(protectIntakeForm(challengeForm({ token: 'distributed-token-two', id: secondId }), request(), distributedEnv, store, {
    clock: () => new Date(now.getTime() + 1_000), ip: '203.0.113.99',
    fetch: fetchFor(siteverify({ cdata: secondId, challenge_ts: new Date(now.getTime() - 5_000).toISOString() })),
    randomBytes: () => Buffer.alloc(32, 2),
  }), /INTAKE_RECIPIENT_VELOCITY_EXCEEDED/,
  'Changing IP addresses must not bypass the keyed per-recipient velocity limit.');
  const quotaKeys = [...store.values.keys()].filter((key) => key.startsWith('quota/'));
  assert.equal(quotaKeys.length, 3, 'Rejected multi-scope reservations must roll back all newly created quota slots.');
}

{
  const store = new FakeStore();
  await protectIntakeForm(challengeForm({ token: 'quota-integrity-token' }), request(), baseEnv, store, {
    clock: () => now, fetch: fetchFor(siteverify()), randomBytes: () => Buffer.alloc(32, 9),
  });
  const globalKey = [...store.values.keys()].find((key) => key.startsWith('quota/global/'));
  const current = store.values.get(globalKey);
  current.data.record_hmac_sha256 = '0'.repeat(64);
  const secondId = requestId('2');
  await assert.rejects(protectIntakeForm(
    challengeForm({ token: 'quota-integrity-token-two', id: secondId }), request(), baseEnv, store,
    {
      clock: () => new Date(now.getTime() + 1_000),
      fetch: fetchFor(siteverify({ cdata: secondId, challenge_ts: new Date(now.getTime() - 5_000).toISOString() })),
      randomBytes: () => Buffer.alloc(32, 10),
    },
  ), /INTAKE_ABUSE_STATE_INVALID/, 'A corrupted quota record must fail closed.');
}

{
  const store = new FakeStore();
  const suppression = buildIntakeAbuseSuppressionRecord(
    'Owner@Example.test', 'recipient', 'MANUAL_ABUSE', now, new Date(now.getTime() + 86_400_000), baseEnv,
  );
  await store.setJSON(suppression.key, suppression.record, { onlyIfNew: true });
  assert.equal(JSON.stringify(suppression).toLowerCase().includes('owner@example.test'), false);
  assert.equal(JSON.stringify(suppression).includes('example.test'), false);
  await assert.rejects(protectIntakeForm(challengeForm({ token: 'suppressed-token' }), request(), baseEnv, store, {
    clock: () => now, fetch: fetchFor(siteverify()), randomBytes: () => Buffer.alloc(32, 6),
  }), /INTAKE_SUPPRESSED/);
  assert.equal([...store.values.keys()].some((key) => key.startsWith('quota/')), false,
    'Suppression must reject before any velocity reservation.');
}

{
  const enabledMarker = Object.freeze({ schema: 'arc-intake-build-marker-v1', version: 1, intake_enabled: true });
  const handler = createIntakeSubmitHandler(enabledMarker, () => true);
  const forged = new Request('https://arcweb.onl/api/intake/submit', {
    method: 'POST', headers: { origin: 'https://evil.example' }, body: challengeForm(),
  });
  const response = await handler(forged, {
    get abuseStore() { throw new Error('Forged Origin touched abuse state.'); },
    get intakeStore() { throw new Error('Forged Origin touched intake state.'); },
  });
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: 'forbidden' });
}

{
  const handlerNow = new Date();
  const enabledMarker = Object.freeze({ schema: 'arc-intake-build-marker-v1', version: 1, intake_enabled: true });
  let imageDecoderCalls = 0;
  const handler = createIntakeSubmitHandler(enabledMarker, () => true, {
    intakeActivationReady: () => true,
    normalizeIntakeForm: async () => { imageDecoderCalls += 1; throw new Error('Image decoder reached.'); },
  });
  const handlerForm = challengeForm({ token: 'invalid-before-image-token' });
  handlerForm.append('logo_file', new Blob(['deliberately invalid image bytes'], { type: 'image/png' }), 'invalid.png');
  const handlerEnv = {
    ...baseEnv,
    ...testActivationAuthority(handlerNow),
    ARC_BUILD_INTAKE_ENABLED: 'true',
    ARC_INTAKE_IDEMPOTENCY_SECRET: 'intake-idempotency-secret-unique-0123456789',
    [INTAKE_READINESS_ENV]: JSON.stringify(Object.fromEntries([
      ['schema', INTAKE_READINESS_SCHEMA],
      ['version', INTAKE_READINESS_VERSION],
      ...INTAKE_READINESS_BOOLEAN_FIELDS.map((name) => [name, true]),
    ])),
  };
  const saved = Object.fromEntries(Object.keys(handlerEnv).map((key) => [key, process.env[key]]));
  try {
    Object.assign(process.env, handlerEnv);
    const abuseStore = new FakeStore();
    const response = await handler(new Request('https://arcweb.onl/api/intake/submit', {
      method: 'POST', headers: { origin: 'https://arcweb.onl' }, body: handlerForm,
    }), {
      abuseStore,
      clock: () => handlerNow,
      fetch: fetchFor(siteverify({
        success: false,
        challenge_ts: new Date(handlerNow.getTime() - 1_000).toISOString(),
      })),
      get intakeStore() { throw new Error('Rejected challenge touched intake Blob persistence.'); },
      get confirmationStore() { throw new Error('Rejected challenge touched confirmation email state.'); },
      get vaultStore() { throw new Error('Rejected challenge touched recipient state.'); },
    });
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: 'verification_required' });
    assert.equal(imageDecoderCalls, 0, 'Challenge verification must precede every image decoder.');
    assert.equal(abuseStore.writes, 0, 'An invalid challenge must precede and prevent every Blob write.');
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
}

console.log('ARC public intake abuse-protection contract passed.');
