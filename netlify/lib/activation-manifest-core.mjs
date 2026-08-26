import { createHmac, timingSafeEqual } from 'node:crypto';
import { ACTIVATION_BUILD_IDENTITY } from './activation-build-identity.mjs';

export const ACTIVATION_MANIFEST_ENV = 'ARC_ACTIVATION_MANIFEST';
export const ACTIVATION_MANIFEST_SECRET_ENV = 'ARC_ACTIVATION_MANIFEST_HMAC_SECRET';
export const ACTIVATION_NEXT_MANIFEST_ENV = 'ARC_ACTIVATION_MANIFEST_NEXT';
export const ACTIVATION_MANIFEST_SCHEMA = 'arc-ordered-activation-manifest-v2';
export const ACTIVATION_MANIFEST_VERSION = 2;
export const ACTIVATION_MANIFEST_MAX_BYTES = 16_384;
export const ACTIVATION_MANIFEST_MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;
export const ACTIVATION_MANIFEST_STEADY_MAX_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000;
export const ACTIVATION_MANIFEST_ROTATION_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
export const ACTIVATION_MANIFEST_CLOCK_SKEW_MS = 60 * 1000;

export const ACTIVATION_STAGES = Object.freeze([
  'OFF',
  'EMAIL_SANDBOX',
  'CLAIM_SANDBOX',
  'LIVE_CHECKOUT',
  'PUBLIC_INTAKE',
  'PILOT',
  'OUTREACH',
]);

const EVIDENCE_KINDS = Object.freeze([
  'email_sandbox_e2e',
  'claim_sandbox_e2e',
  'adult_legal_tax_approval',
  'checkout_test_e2e',
  'live_checkout_readback',
  'public_intake_privacy_retention_review',
  'public_intake_provider_e2e',
  'pilot_acceptance',
  'outreach_approval',
]);
export const ACTIVATION_STEADY_EVIDENCE_KINDS = Object.freeze([
  'steady_state_dual_control_review',
  'steady_state_rotation_rehearsal',
  'steady_state_alert_route_e2e',
]);

export const ACTIVATION_EVIDENCE_BY_STAGE = Object.freeze({
  OFF: Object.freeze([]),
  EMAIL_SANDBOX: Object.freeze(EVIDENCE_KINDS.slice(0, 1)),
  CLAIM_SANDBOX: Object.freeze(EVIDENCE_KINDS.slice(0, 2)),
  LIVE_CHECKOUT: Object.freeze(EVIDENCE_KINDS.slice(0, 5)),
  PUBLIC_INTAKE: Object.freeze(EVIDENCE_KINDS.slice(0, 7)),
  PILOT: Object.freeze(EVIDENCE_KINDS.slice(0, 8)),
  OUTREACH: Object.freeze(EVIDENCE_KINDS.slice(0, 9)),
});

const MANIFEST_KEYS = Object.freeze([
  'schema',
  'version',
  'stage',
  'authority_mode',
  'issued_at',
  'expires_at',
  'deployment_sha',
  'evidence',
  'signature',
]);
const EVIDENCE_KEYS = Object.freeze(['kind', 'receipt_ref', 'sha256']);
const SHA_256 = /^[a-f0-9]{64}$/;
const DEPLOYMENT_SHA = /^[a-f0-9]{40}$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const RECEIPT_REF = /^[a-z][a-z0-9-]{2,31}:[a-f0-9]{16,64}$/;
const SENSITIVE_ENV_NAME = /(?:_SECRET|_BEARER|_PAT|_TOKEN|_PASSWORD|_CREDENTIAL|_CREDENTIALS|_KEY)$/;
const SIGNATURE_DOMAIN = `${ACTIVATION_MANIFEST_SCHEMA}\n`;

const plainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;
const exactKeys = (value, expected) => plainObject(value) &&
  JSON.stringify(Object.keys(value)) === JSON.stringify(expected);
const byteLength = (value) => Buffer.byteLength(value, 'utf8');
const validSecret = (value) => typeof value === 'string' && byteLength(value) >= 32 && byteLength(value) <= 256;

function canonicalPayload(value) {
  return JSON.stringify({
    schema: value.schema,
    version: value.version,
    stage: value.stage,
    authority_mode: value.authority_mode,
    issued_at: value.issued_at,
    expires_at: value.expires_at,
    deployment_sha: value.deployment_sha,
    evidence: value.evidence.map((item) => ({
      kind: item.kind,
      receipt_ref: item.receipt_ref,
      sha256: item.sha256,
    })),
  });
}

function canonicalManifest(value) {
  return JSON.stringify({
    schema: value.schema,
    version: value.version,
    stage: value.stage,
    authority_mode: value.authority_mode,
    issued_at: value.issued_at,
    expires_at: value.expires_at,
    deployment_sha: value.deployment_sha,
    evidence: value.evidence.map((item) => ({
      kind: item.kind,
      receipt_ref: item.receipt_ref,
      sha256: item.sha256,
    })),
    signature: value.signature,
  });
}

function signatureFor(value, secret) {
  return createHmac('sha256', secret).update(`${SIGNATURE_DOMAIN}${canonicalPayload(value)}`).digest('hex');
}

function safeSignatureEqual(supplied, expected) {
  if (!SHA_256.test(String(supplied || '')) || !SHA_256.test(String(expected || ''))) return false;
  const suppliedBytes = Buffer.from(supplied, 'hex');
  const expectedBytes = Buffer.from(expected, 'hex');
  return suppliedBytes.length === expectedBytes.length && timingSafeEqual(suppliedBytes, expectedBytes);
}

function result({ reason = null, stage = null, authorityMode = null, expiresAt = null,
  rotationDue = false, minimumStage, checks = {} }) {
  const valid = reason === null;
  return Object.freeze({
    valid,
    stage: valid ? stage : null,
    authority_mode: valid ? authorityMode : null,
    expires_at: valid ? expiresAt : null,
    rotation_due: valid ? rotationDue : false,
    minimum_stage: minimumStage,
    reason_codes: Object.freeze(valid ? [] : [reason]),
    checks: Object.freeze({
      canonical: false,
      signature_valid: false,
      current: false,
      deployment_bound: false,
      evidence_complete: false,
      stage_sufficient: false,
      ...checks,
    }),
  });
}

export function activationStageAtLeast(stage, minimumStage) {
  const stageIndex = ACTIVATION_STAGES.indexOf(stage);
  const minimumIndex = ACTIVATION_STAGES.indexOf(minimumStage);
  return stageIndex >= 0 && minimumIndex >= 0 && stageIndex >= minimumIndex;
}

export function activationManifestSecretIsDistinct(env = {}) {
  const secret = env[ACTIVATION_MANIFEST_SECRET_ENV];
  if (!validSecret(secret)) return false;
  return !Object.entries(env).some(([name, value]) =>
    name !== ACTIVATION_MANIFEST_SECRET_ENV && SENSITIVE_ENV_NAME.test(name) &&
    typeof value === 'string' && value.length > 0 && value === secret);
}

export function signActivationManifest(unsigned, secret) {
  if (!validSecret(secret)) throw new TypeError('Activation manifest HMAC secret is invalid.');
  if (!exactKeys(unsigned, MANIFEST_KEYS.slice(0, -1)) || !Array.isArray(unsigned.evidence)) {
    throw new TypeError('Unsigned activation manifest shape is invalid.');
  }
  const value = { ...unsigned, signature: signatureFor(unsigned, secret) };
  return canonicalManifest(value);
}

export function validateActivationManifest(raw, {
  secret,
  deploymentSha,
  minimumStage = 'OFF',
  now = new Date(),
} = {}) {
  if (!ACTIVATION_STAGES.includes(minimumStage)) {
    return result({ reason: 'MINIMUM_STAGE_INVALID', minimumStage: 'INVALID' });
  }
  if (typeof raw !== 'string' || raw.length === 0) {
    return result({ reason: 'MANIFEST_MISSING', minimumStage });
  }
  if (byteLength(raw) > ACTIVATION_MANIFEST_MAX_BYTES) {
    return result({ reason: 'MANIFEST_TOO_LARGE', minimumStage });
  }
  if (!validSecret(secret)) {
    return result({ reason: 'SECRET_INVALID', minimumStage });
  }
  if (!DEPLOYMENT_SHA.test(String(deploymentSha || ''))) {
    return result({ reason: 'DEPLOYMENT_SHA_INVALID', minimumStage });
  }
  const nowMs = now instanceof Date ? now.getTime() : Number.NaN;
  if (!Number.isFinite(nowMs)) {
    return result({ reason: 'NOW_INVALID', minimumStage });
  }

  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    return result({ reason: 'MANIFEST_JSON_INVALID', minimumStage });
  }
  if (!exactKeys(value, MANIFEST_KEYS) || value.schema !== ACTIVATION_MANIFEST_SCHEMA ||
      value.version !== ACTIVATION_MANIFEST_VERSION || !ACTIVATION_STAGES.includes(value.stage) ||
      !['ROLLOUT', 'STEADY_STATE'].includes(value.authority_mode) ||
      !Array.isArray(value.evidence) || !SHA_256.test(String(value.signature || ''))) {
    return result({ reason: 'MANIFEST_SHAPE_INVALID', minimumStage });
  }
  if (value.evidence.some((item) => !exactKeys(item, EVIDENCE_KEYS) ||
      typeof item.kind !== 'string' || !RECEIPT_REF.test(String(item.receipt_ref || '')) ||
      !SHA_256.test(String(item.sha256 || '')))) {
    return result({ reason: 'EVIDENCE_SHAPE_INVALID', minimumStage });
  }
  if (raw !== canonicalManifest(value)) {
    return result({ reason: 'MANIFEST_NOT_CANONICAL', minimumStage });
  }
  const canonicalChecks = { canonical: true };
  if (value.authority_mode === 'STEADY_STATE' && !activationStageAtLeast(value.stage, 'PILOT')) {
    return result({ reason: 'STEADY_STATE_STAGE_INVALID', minimumStage, checks: canonicalChecks });
  }
  const requiredKinds = value.authority_mode === 'STEADY_STATE'
    ? [...ACTIVATION_EVIDENCE_BY_STAGE[value.stage], ...ACTIVATION_STEADY_EVIDENCE_KINDS]
    : ACTIVATION_EVIDENCE_BY_STAGE[value.stage];
  if (JSON.stringify(value.evidence.map((item) => item.kind)) !== JSON.stringify(requiredKinds)) {
    return result({ reason: 'EVIDENCE_INCOMPLETE', minimumStage, checks: canonicalChecks });
  }
  const evidenceChecks = { ...canonicalChecks, evidence_complete: true };
  const issuedMs = UTC_TIMESTAMP.test(String(value.issued_at || '')) ? Date.parse(value.issued_at) : Number.NaN;
  const expiresMs = UTC_TIMESTAMP.test(String(value.expires_at || '')) ? Date.parse(value.expires_at) : Number.NaN;
  const maximumLifetime = value.authority_mode === 'STEADY_STATE'
    ? ACTIVATION_MANIFEST_STEADY_MAX_LIFETIME_MS
    : ACTIVATION_MANIFEST_MAX_LIFETIME_MS;
  if (!Number.isFinite(issuedMs) || !Number.isFinite(expiresMs) || expiresMs <= issuedMs ||
      expiresMs - issuedMs > maximumLifetime ||
      issuedMs > nowMs + ACTIVATION_MANIFEST_CLOCK_SKEW_MS || expiresMs <= nowMs) {
    return result({ reason: 'MANIFEST_NOT_CURRENT', minimumStage, checks: evidenceChecks });
  }
  const currentChecks = { ...evidenceChecks, current: true };
  if (value.deployment_sha !== deploymentSha) {
    return result({ reason: 'DEPLOYMENT_SHA_MISMATCH', minimumStage, checks: currentChecks });
  }
  const deploymentChecks = { ...currentChecks, deployment_bound: true };
  const expectedSignature = signatureFor(value, secret);
  if (!safeSignatureEqual(value.signature, expectedSignature)) {
    return result({ reason: 'SIGNATURE_INVALID', minimumStage, checks: deploymentChecks });
  }
  const signatureChecks = { ...deploymentChecks, signature_valid: true };
  if (!activationStageAtLeast(value.stage, minimumStage)) {
    return result({ reason: 'STAGE_INSUFFICIENT', minimumStage, checks: signatureChecks });
  }
  return result({
    minimumStage,
    stage: value.stage,
    authorityMode: value.authority_mode,
    expiresAt: value.expires_at,
    rotationDue: value.authority_mode === 'STEADY_STATE' &&
      expiresMs - nowMs <= ACTIVATION_MANIFEST_ROTATION_WINDOW_MS,
    checks: { ...signatureChecks, stage_sufficient: true },
  });
}

export function validateActivationManifestEnvironment(env = {}, {
  minimumStage = 'OFF',
  now = new Date(),
} = {}) {
  const deploymentSha = ACTIVATION_BUILD_IDENTITY?.schema === 'arc-activation-build-identity-v1' &&
    ACTIVATION_BUILD_IDENTITY?.version === 1 &&
    DEPLOYMENT_SHA.test(String(ACTIVATION_BUILD_IDENTITY?.deployment_sha || ''))
    ? ACTIVATION_BUILD_IDENTITY.deployment_sha
    : null;
  const candidates = [env[ACTIVATION_MANIFEST_ENV], env[ACTIVATION_NEXT_MANIFEST_ENV]];
  const validations = candidates.map((raw) => validateActivationManifest(raw, {
    secret: env[ACTIVATION_MANIFEST_SECRET_ENV],
    deploymentSha,
    minimumStage,
    now,
  }));
  const validated = validations.find((item) => item.valid) || validations[0];
  if (!validated.valid) return Object.freeze({ ...validated, next_manifest_valid: validations[1].valid });
  if (activationManifestSecretIsDistinct(env)) {
    return Object.freeze({ ...validated, next_manifest_valid: validations[1].valid });
  }
  return result({
    reason: 'SECRET_NOT_DISTINCT',
    minimumStage,
    checks: validated.checks,
  });
}

export function publicIntakeAuthorityReady(env = {}, now = new Date()) {
  return validateActivationManifestEnvironment(env, { minimumStage: 'PUBLIC_INTAKE', now }).valid;
}

export function assertPublicIntakeAuthority(env = {}, now = new Date()) {
  if (!publicIntakeAuthorityReady(env, now)) throw new Error('ARC_PUBLIC_INTAKE_AUTHORITY_REQUIRED');
}
