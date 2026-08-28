import { createHash } from 'node:crypto';

import {
  ACTIVATION_MANIFEST_ENV,
  ACTIVATION_NEXT_MANIFEST_ENV,
  validateActivationManifestEnvironment,
} from './activation-manifest-core.mjs';

export const CLAIM_SANDBOX_BOOTSTRAP_SCHEMA = 'arc-claim-sandbox-bootstrap-binding-v1';
export const CLAIM_SANDBOX_BOOTSTRAP_VERSION = 1;

const KEY_PREFIX = 'claim-sandbox-bootstrap/';
const KEY_DOMAIN = 'arc-claim-sandbox-bootstrap-key-v1\n';
const HEX_40 = /^[a-f0-9]{40}$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const RECORD_FIELDS = Object.freeze([
  'schema',
  'version',
  'authority_mode',
  'deployment_sha',
  'manifest_sha256',
  'handoff_id',
  'issued_at',
  'bound_at',
  'expires_at',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function clockDate(now) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new TypeError('Claim sandbox bootstrap clock is invalid.');
  }
  return now;
}

function exactMode(env) {
  if (env.ARC_RUNTIME_ENVIRONMENT === 'sandbox' &&
      env.ARC_STRIPE_LIVE_MODE_ENABLED === 'false' &&
      env.ARC_ALLOW_TEST_MODE_EVENTS === 'true' &&
      env.ARC_HANDOFF_ENABLED === 'false') return 'sandbox';
  if (env.ARC_RUNTIME_ENVIRONMENT === 'production' &&
      env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true' &&
      env.ARC_ALLOW_TEST_MODE_EVENTS === 'false' &&
      env.ARC_HANDOFF_ENABLED === 'true') return 'production';
  return null;
}

function exactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function selectedManifest(env, validation, minimumStage, now) {
  for (const raw of [env[ACTIVATION_MANIFEST_ENV], env[ACTIVATION_NEXT_MANIFEST_ENV]]) {
    if (typeof raw !== 'string' || raw.length === 0) continue;
    const scoped = validateActivationManifestEnvironment({
      ...env,
      [ACTIVATION_MANIFEST_ENV]: raw,
      [ACTIVATION_NEXT_MANIFEST_ENV]: '',
    }, { minimumStage, now });
    if (!scoped.valid || scoped.stage !== validation.stage ||
        scoped.authority_mode !== validation.authority_mode ||
        scoped.expires_at !== validation.expires_at) continue;
    try {
      const manifest = JSON.parse(raw);
      return { manifest, raw };
    } catch {
      return null;
    }
  }
  return null;
}

export function claimSandboxBootstrapConfiguration(env = process.env, now = new Date()) {
  clockDate(now);
  const bootstrapRequested = [env[ACTIVATION_MANIFEST_ENV], env[ACTIVATION_NEXT_MANIFEST_ENV]]
    .some((raw) => {
      if (typeof raw !== 'string' || raw.length === 0) return false;
      try {
        const value = JSON.parse(raw);
        return value?.authority_mode === 'TEST_BOOTSTRAP';
      } catch { return false; }
    });
  const mode = exactMode(env);
  const minimumStage = mode === 'production' ? 'LIVE_CHECKOUT' : 'CLAIM_SANDBOX';
  const activation = mode === null
    ? Object.freeze({ valid: false, stage: null, authority_mode: null, expires_at: null })
    : validateActivationManifestEnvironment(env, { minimumStage, now });
  const selected = activation.valid
    ? selectedManifest(env, activation, minimumStage, now)
    : null;
  const bootstrapActive = mode === 'sandbox' && bootstrapRequested &&
    activation.stage === 'CLAIM_SANDBOX' && selected !== null;
  return Object.freeze({
    activation_authority_valid: activation.valid,
    bootstrap_active: bootstrapActive,
    bootstrap_requested: bootstrapRequested,
    enabled: !bootstrapRequested || bootstrapActive,
    expires_at: activation.expires_at,
    mode,
    stage: activation.stage,
    authority_mode: activation.authority_mode,
    // Kept non-enumerable in reports by returning only from the private
    // resolver below. No manifest, signature, or binding value is exposed.
  });
}

function requireAuthority(env, now) {
  const configuration = claimSandboxBootstrapConfiguration(env, now);
  if (!configuration.bootstrap_requested) return { configuration, bootstrap: null };
  if (!configuration.enabled || !configuration.activation_authority_valid) {
    throw new Error('ARC_CLAIM_MUTATION_AUTHORITY_REQUIRED');
  }
  const minimumStage = 'CLAIM_SANDBOX';
  const activation = validateActivationManifestEnvironment(env, { minimumStage, now });
  const selected = selectedManifest(env, activation, minimumStage, now);
  if (!selected || selected.manifest.authority_mode !== 'TEST_BOOTSTRAP' ||
      selected.manifest.stage !== 'CLAIM_SANDBOX' ||
      !HEX_40.test(String(selected.manifest.deployment_sha || '')) ||
      !HEX_64.test(String(selected.manifest.signature || ''))) {
    throw new Error('ARC_CLAIM_MUTATION_AUTHORITY_REQUIRED');
  }
  return { configuration, bootstrap: selected };
}

// Runtime entry points that do not already use configuredEnvironment (the
// payment-to-ARC2 worker) call this before entering the handoff service.
export function assertClaimMutationActivationAuthority(env = process.env, now = new Date()) {
  const configuration = claimSandboxBootstrapConfiguration(env, now);
  if (!configuration.activation_authority_valid) {
    throw new Error('ARC_CLAIM_MUTATION_AUTHORITY_REQUIRED');
  }
  return configuration;
}

function bootstrapBinding(bootstrap, handoffId, now) {
  if (!HEX_64.test(String(handoffId || ''))) {
    throw new TypeError('Claim sandbox bootstrap handoff id is invalid.');
  }
  const manifestSha256 = sha256(bootstrap.raw);
  const key = `${KEY_PREFIX}${sha256(`${KEY_DOMAIN}${bootstrap.manifest.signature}`)}`;
  return {
    key,
    value: {
      schema: CLAIM_SANDBOX_BOOTSTRAP_SCHEMA,
      version: CLAIM_SANDBOX_BOOTSTRAP_VERSION,
      authority_mode: 'TEST_BOOTSTRAP',
      deployment_sha: bootstrap.manifest.deployment_sha,
      manifest_sha256: manifestSha256,
      handoff_id: handoffId,
      issued_at: bootstrap.manifest.issued_at,
      bound_at: now.toISOString(),
      expires_at: bootstrap.manifest.expires_at,
    },
  };
}

function validStoredBinding(value, expected, now) {
  if (!exactKeys(value, RECORD_FIELDS) ||
      value.schema !== CLAIM_SANDBOX_BOOTSTRAP_SCHEMA ||
      value.version !== CLAIM_SANDBOX_BOOTSTRAP_VERSION ||
      value.authority_mode !== 'TEST_BOOTSTRAP' ||
      value.deployment_sha !== expected.deployment_sha ||
      value.manifest_sha256 !== expected.manifest_sha256 ||
      value.handoff_id !== expected.handoff_id ||
      value.issued_at !== expected.issued_at ||
      value.expires_at !== expected.expires_at) return false;
  const issuedAt = Date.parse(value.issued_at);
  const boundAt = Date.parse(value.bound_at);
  const expiresAt = Date.parse(value.expires_at);
  return Number.isFinite(issuedAt) && Number.isFinite(boundAt) && Number.isFinite(expiresAt) &&
    new Date(issuedAt).toISOString() === value.issued_at &&
    new Date(boundAt).toISOString() === value.bound_at &&
    new Date(expiresAt).toISOString() === value.expires_at &&
    boundAt >= issuedAt && boundAt <= now.getTime() && expiresAt > now.getTime();
}

function requireStore(store) {
  if (!store?.getWithMetadata || !store?.setJSON) {
    throw new TypeError('Claim sandbox bootstrap store is unavailable.');
  }
  return store;
}

// Consumes the short-lived authority for exactly one deterministic handoff.
// An exact retry for that same handoff is allowed; a second handoff cannot use
// the manifest even while it is still current.
export async function reserveClaimSandboxBootstrap(store, handoffId, env = process.env,
  now = new Date()) {
  clockDate(now);
  const authority = requireAuthority(env, now);
  if (!authority.bootstrap) return Object.freeze({ active: false, idempotent_replay: false });
  requireStore(store);
  const binding = bootstrapBinding(authority.bootstrap, handoffId, now);
  const created = await store.setJSON(binding.key, binding.value, { onlyIfNew: true });
  if (created?.modified && created.etag) {
    return Object.freeze({ active: true, idempotent_replay: false });
  }
  const existing = await store.getWithMetadata(binding.key, { type: 'json', consistency: 'strong' });
  if (!existing || !validStoredBinding(existing.data, binding.value, now)) {
    throw new Error('ARC_CLAIM_SANDBOX_BOOTSTRAP_CONSUMED');
  }
  return Object.freeze({ active: true, idempotent_replay: true });
}

// Continuation mutations may proceed only for the handoff that atomically
// consumed this manifest in startReviewHandoff.
export async function assertClaimSandboxBootstrapBound(store, handoffId, env = process.env,
  now = new Date()) {
  clockDate(now);
  const authority = requireAuthority(env, now);
  if (!authority.bootstrap) return Object.freeze({ active: false });
  requireStore(store);
  const binding = bootstrapBinding(authority.bootstrap, handoffId, now);
  const existing = await store.getWithMetadata(binding.key, { type: 'json', consistency: 'strong' });
  if (!existing || !validStoredBinding(existing.data, binding.value, now)) {
    throw new Error('ARC_CLAIM_SANDBOX_BOOTSTRAP_BINDING_REQUIRED');
  }
  return Object.freeze({ active: true });
}
