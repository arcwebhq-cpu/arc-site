import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  ACTIVATION_EVIDENCE_BY_STAGE,
  ACTIVATION_MANIFEST_SCHEMA,
  ACTIVATION_MANIFEST_VERSION,
  signActivationManifest,
} from '../netlify/lib/activation-manifest-core.mjs';
import {
  assertClaimSandboxBootstrapBound,
  claimSandboxBootstrapConfiguration,
  reserveClaimSandboxBootstrap,
} from '../netlify/lib/claim-sandbox-bootstrap-core.mjs';

const now = new Date('2026-08-27T15:00:00.000Z');
const deploymentSha = '9'.repeat(40);
const activationSecret = 'claim-bootstrap-activation-secret-0123456789abcdef';
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const evidenceFor = (stage) => ACTIVATION_EVIDENCE_BY_STAGE[stage].map((kind) => ({
  kind,
  receipt_ref: `audit:${sha256(`claim-bootstrap:${kind}`).slice(0, 24)}`,
  sha256: sha256(`claim-bootstrap-evidence:${kind}`),
}));

function manifest(stage, authorityMode, evidence, overrides = {}) {
  return signActivationManifest({
    schema: ACTIVATION_MANIFEST_SCHEMA,
    version: ACTIVATION_MANIFEST_VERSION,
    stage,
    authority_mode: authorityMode,
    issued_at: new Date(now.getTime() - 60_000).toISOString(),
    expires_at: new Date(now.getTime() + 10 * 60_000).toISOString(),
    deployment_sha: deploymentSha,
    evidence,
    ...overrides,
  }, activationSecret);
}

const baseEnv = {
  ARC_ACTIVATION_MANIFEST_HMAC_SECRET: activationSecret,
  ARC_OTHER_SIGNING_SECRET: 'claim-bootstrap-other-signing-secret-0123456789abcdef',
  ARC_RUNTIME_ENVIRONMENT: 'sandbox',
  ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
  ARC_ALLOW_TEST_MODE_EVENTS: 'true',
  ARC_HANDOFF_ENABLED: 'false',
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_PUBLIC_ORIGIN: 'https://claim-sandbox.example.test/',
  SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  SITE_NAME: 'arc2-sandbox',
  URL: 'https://claim-sandbox.example.test/',
  ARC_STRIPE_REVIEW_SECRET_KEY: ['sk', 'test', 'claimBootstrapReviewKey0123456789'].join('_'),
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: ['rk', 'test', 'claimBootstrapAccountKey0123456789'].join('_'),
};
const claimBootstrapEnv = {
  ...baseEnv,
  ARC_ACTIVATION_MANIFEST: manifest(
    'CLAIM_SANDBOX',
    'TEST_BOOTSTRAP',
    evidenceFor('EMAIL_SANDBOX'),
  ),
};

function memoryStore() {
  const values = new Map();
  let revision = 0;
  return {
    values,
    async getWithMetadata(key) {
      const entry = values.get(key);
      return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
    },
    async setJSON(key, value, options = {}) {
      if (options.onlyIfNew && values.has(key)) return { modified: false };
      const etag = `etag-${++revision}`;
      values.set(key, { data: structuredClone(value), etag });
      return { modified: true, etag };
    },
  };
}

const configuration = claimSandboxBootstrapConfiguration(claimBootstrapEnv, now);
assert.equal(configuration.enabled, true);
assert.equal(configuration.activation_authority_valid, true);
assert.equal(configuration.bootstrap_requested, true);
assert.equal(configuration.bootstrap_active, true);
assert.equal(configuration.mode, 'sandbox');
assert.equal(configuration.stage, 'CLAIM_SANDBOX');

const firstHandoffId = '1'.repeat(64);
const secondHandoffId = '2'.repeat(64);
const store = memoryStore();
const first = await reserveClaimSandboxBootstrap(store, firstHandoffId, claimBootstrapEnv, now);
assert.deepEqual(first, { active: true, idempotent_replay: false });
assert.equal(store.values.size, 1, 'The manifest must create one durable binding.');
const replay = await reserveClaimSandboxBootstrap(
  store,
  firstHandoffId,
  claimBootstrapEnv,
  new Date(now.getTime() + 1000),
);
assert.deepEqual(replay, { active: true, idempotent_replay: true });
await assertClaimSandboxBootstrapBound(
  store,
  firstHandoffId,
  claimBootstrapEnv,
  new Date(now.getTime() + 2000),
);
await assert.rejects(reserveClaimSandboxBootstrap(
  store,
  secondHandoffId,
  claimBootstrapEnv,
  new Date(now.getTime() + 3000),
), /BOOTSTRAP_CONSUMED/,
'One bootstrap manifest must never seed a second handoff.');
await assert.rejects(assertClaimSandboxBootstrapBound(
  store,
  secondHandoffId,
  claimBootstrapEnv,
  new Date(now.getTime() + 3000),
), /BOOTSTRAP_BINDING_REQUIRED/,
'Continuation must remain bound to the handoff that consumed the bootstrap.');

const emailBootstrapEnv = {
  ...baseEnv,
  ARC_ACTIVATION_MANIFEST: manifest('EMAIL_SANDBOX', 'TEST_BOOTSTRAP', []),
};
assert.equal(claimSandboxBootstrapConfiguration(emailBootstrapEnv, now).enabled, false);
await assert.rejects(reserveClaimSandboxBootstrap(
  new Proxy({}, { get() { throw new Error('store must not be reached'); } }),
  firstHandoffId,
  emailBootstrapEnv,
  now,
), /CLAIM_MUTATION_AUTHORITY_REQUIRED/);

const rolloutEnv = {
  ...baseEnv,
  ARC_ACTIVATION_MANIFEST: manifest(
    'CLAIM_SANDBOX',
    'ROLLOUT',
    evidenceFor('CLAIM_SANDBOX'),
  ),
};
assert.equal(claimSandboxBootstrapConfiguration(rolloutEnv, now).bootstrap_active, false);
assert.deepEqual(await reserveClaimSandboxBootstrap(
  new Proxy({}, { get() { throw new Error('normal authority must not touch bootstrap storage'); } }),
  firstHandoffId,
  rolloutEnv,
  now,
), { active: false, idempotent_replay: false });

for (const unsafeEnv of [
  { ...claimBootstrapEnv, ARC_RUNTIME_ENVIRONMENT: 'production' },
  { ...claimBootstrapEnv, ARC_STRIPE_LIVE_MODE_ENABLED: 'true' },
  { ...claimBootstrapEnv, ARC_HANDOFF_ENABLED: 'true' },
  { ...claimBootstrapEnv, SITE_NAME: 'arcsites' },
  {
    ...claimBootstrapEnv,
    ARC_ACTIVATION_MANIFEST: manifest('CLAIM_SANDBOX', 'TEST_BOOTSTRAP',
      evidenceFor('EMAIL_SANDBOX'), { deployment_sha: '8'.repeat(40) }),
  },
]) {
  const unsafe = claimSandboxBootstrapConfiguration(unsafeEnv, now);
  assert.equal(unsafe.enabled, false);
  await assert.rejects(reserveClaimSandboxBootstrap(
    new Proxy({}, { get() { throw new Error('store must not be reached'); } }),
    firstHandoffId,
    unsafeEnv,
    now,
  ), /CLAIM_MUTATION_AUTHORITY_REQUIRED/);
}

const afterExpiry = new Date(now.getTime() + 11 * 60_000);
assert.equal(claimSandboxBootstrapConfiguration(claimBootstrapEnv, afterExpiry).enabled, false);
await assert.rejects(assertClaimSandboxBootstrapBound(
  store,
  firstHandoffId,
  claimBootstrapEnv,
  afterExpiry,
), /CLAIM_MUTATION_AUTHORITY_REQUIRED/);

assert.equal(JSON.stringify(configuration).includes(activationSecret), false);
assert.equal(JSON.stringify(configuration).includes(JSON.parse(
  claimBootstrapEnv.ARC_ACTIVATION_MANIFEST,
).signature), false);

console.log('ARC one-use claim sandbox bootstrap contract passed.');
