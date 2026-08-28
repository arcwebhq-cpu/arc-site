import {
  INTAKE_ARC1_ADAPTER_PROOF_ENV,
  intakeArc1AdapterAttested,
  intakeArc1PublicAssetShapesImplemented,
} from './intake-arc1-bridge-core.mjs';
import {
  INTAKE_ARC1_ADAPTER_ENABLED_ENV,
  INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV,
  resolveArc1AdapterEnvironment,
} from './intake-arc1-adapter-core.mjs';
import { resolveSameDeployDispatcher } from './intake-arc1-dispatch-core.mjs';
import { arc1RecoveryAutomationEnabled } from './intake-arc1-adapter-recovery-runner-core.mjs';
import { INTAKE_PRIVATE_ASSET_ENABLED_ENV, resolvePrivateAssetEnvironment } from './intake-private-asset-core.mjs';
import { INTAKE_IDEMPOTENCY_SECRET_ENV, intakeIdempotencyConfigured } from './intake-submission-core.mjs';
import { publicIntakeAuthorityReady } from './activation-manifest-core.mjs';
import {
  INTAKE_ABUSE_HMAC_SECRET_ENV,
  TURNSTILE_SECRET_KEY_ENV,
  intakeAbuseProtectionConfiguration,
} from './intake-abuse-protection-core.mjs';
import {
  INTAKE_CONFIRMATION_CONSUMER_BEARER_ENV,
  INTAKE_CONFIRMATION_OUTBOX_SECRET_ENV,
  INTAKE_CONFIRMATION_RECEIPT_SECRET_ENV,
  intakeConfirmationRuntimeConfigured,
} from './intake-confirmation-outbox-core.mjs';
import {
  INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET_ENV,
  INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET_ENV,
  INTAKE_EMAIL_VERIFICATION_STATE_SECRET_ENV,
  INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET_ENV,
  intakeEmailVerificationConfiguration,
} from './intake-email-verification-core.mjs';
import {
  EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY_ENV,
  EMAIL_RECIPIENT_VAULT_HMAC_SECRET_ENV,
  emailRecipientVaultConfiguration,
} from './email-recipient-vault-core.mjs';

export const INTAKE_READINESS_ENV = 'ARC_INTAKE_READINESS_ATTESTATION';
export const INTAKE_READINESS_SCHEMA = 'arc-intake-readiness-attestation-v1';
export const INTAKE_READINESS_VERSION = 1;
export const INTAKE_BUILD_MARKER_SCHEMA = 'arc-intake-build-marker-v1';
export const INTAKE_BUILD_MARKER_VERSION = 1;

export const INTAKE_READINESS_BOOLEAN_FIELDS = Object.freeze([
  'intake_enabled',
  'route_verified',
  'recipient_verified',
  'dedupe_verified',
  'failure_alert_verified',
  'transactional_sender_verified',
  'adult_operator_verified',
  'legal_readiness_verified',
  'tax_readiness_verified',
  'payment_readiness_verified',
  'arc1_consumer_adapter_verified',
  'native_netlify_forms_disabled_verified',
  'retention_verified',
  'asset_pipeline_verified',
]);

const EXACT_KEYS = Object.freeze([
  'schema',
  'version',
  ...INTAKE_READINESS_BOOLEAN_FIELDS,
].sort());
const MAX_ATTESTATION_BYTES = 2048;

export function intakeEnabledFromBuildMarker(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['intake_enabled', 'schema', 'version'])) return false;
  return value.schema === INTAKE_BUILD_MARKER_SCHEMA && value.version === INTAKE_BUILD_MARKER_VERSION &&
    value.intake_enabled === true;
}

export function intakeEnabledFromAttestation(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || Buffer.byteLength(raw, 'utf8') > MAX_ATTESTATION_BYTES) {
    return false;
  }

  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    return false;
  }

  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(EXACT_KEYS)) return false;
  if (value.schema !== INTAKE_READINESS_SCHEMA || value.version !== INTAKE_READINESS_VERSION) return false;
  if (INTAKE_READINESS_BOOLEAN_FIELDS.some((field) => typeof value[field] !== 'boolean')) return false;

  return INTAKE_READINESS_BOOLEAN_FIELDS.every((field) => value[field] === true);
}

export function intakeArc1AdapterProofFromEnvironment(env = process.env, now = new Date()) {
  let assetEndpoint;
  try { assetEndpoint = resolvePrivateAssetEnvironment(env).endpoint; } catch { return false; }
  return intakeArc1AdapterAttested(
    env[INTAKE_ARC1_ADAPTER_PROOF_ENV],
    env.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET,
    now,
    env.ARC_INTAKE_ARC1_ENDPOINT,
    assetEndpoint,
    env.SITE_ID,
  );
}

export function intakeActivationReady(env = process.env, now = new Date()) {
  return publicIntakeAuthorityReady(env, now);
}

export function intakeArc1RuntimeReady(request, env = process.env, now = new Date()) {
  if (!intakeActivationReady(env, now)) return false;
  if (env.ARC_INTAKE_ARC1_BRIDGE_ENABLED !== 'true' || env.ARC_INTAKE_ARC1_DISPATCH_ENABLED !== 'true' ||
      env[INTAKE_ARC1_ADAPTER_ENABLED_ENV] !== 'true' || env[INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV] !== 'true' ||
      env.ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED !== 'true' ||
      env.ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED !== 'true' ||
      env[INTAKE_PRIVATE_ASSET_ENABLED_ENV] !== 'true' ||
      !arc1RecoveryAutomationEnabled(env) ||
      !intakeConfirmationRuntimeConfigured(env) ||
      !intakeEmailVerificationConfiguration(env).enabled ||
      !intakeAbuseProtectionConfiguration(env).enabled ||
      !emailRecipientVaultConfiguration(env).enabled ||
      !intakeArc1PublicAssetShapesImplemented(env, now) || !intakeArc1AdapterProofFromEnvironment(env, now)) return false;
  try {
    resolveSameDeployDispatcher(request, env);
    resolveArc1AdapterEnvironment(env);
    // Full endpoint/evidence/ack/state configuration and distinctness are
    // validated by the delivery environment resolver before readiness opens.
    const required = [
      'ARC_INTAKE_ARC1_DESTINATION_BEARER', 'ARC_INTAKE_ARC1_EVIDENCE_SECRET', 'ARC_INTAKE_ARC1_ACK_SECRET',
      'ARC_INTAKE_ARC1_STATE_SECRET', 'ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET', 'ARC_INTAKE_ARC1_DISPATCH_SECRET',
      'ARC_INTAKE_ARC1_RUN_SECRET',
      'ARC_INTAKE_ASSET_RETRIEVAL_SECRET',
      'ARC1_ASSET_RECEIPT_SECRET', 'ARC_INTAKE_ARC1_DOWNSTREAM_BEARER',
      'ARC_INTAKE_ARC1_PACKET_SECRET', 'ARC_INTAKE_ARC1_CONSUMER_BEARER',
      'ARC_INTAKE_ARC1_CONSUMER_RECEIPT_SECRET',
      INTAKE_CONFIRMATION_OUTBOX_SECRET_ENV,
      INTAKE_CONFIRMATION_CONSUMER_BEARER_ENV,
      INTAKE_CONFIRMATION_RECEIPT_SECRET_ENV,
      INTAKE_EMAIL_VERIFICATION_STATE_SECRET_ENV,
      INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET_ENV,
      INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET_ENV,
      INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET_ENV,
      EMAIL_RECIPIENT_VAULT_HMAC_SECRET_ENV,
      EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY_ENV,
      INTAKE_IDEMPOTENCY_SECRET_ENV,
      INTAKE_ABUSE_HMAC_SECRET_ENV,
      TURNSTILE_SECRET_KEY_ENV,
    ];
    const secrets = required.map((name) => env[name]);
    if (!intakeIdempotencyConfigured(env) ||
        secrets.some((value) => typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 32 || Buffer.byteLength(value, 'utf8') > 256) ||
        new Set(secrets).size !== secrets.length) return false;
    const endpoint = new URL(env.ARC_INTAKE_ARC1_ENDPOINT);
    return endpoint.protocol === 'https:' && !endpoint.username && !endpoint.password && !endpoint.port && endpoint.pathname !== '/' &&
      !endpoint.search && !endpoint.hash && /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(endpoint.hostname) &&
      /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5a-f][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(String(env.SITE_ID || '').toLowerCase()) &&
      env.SITE_ID === env.ARC_EXPECTED_NETLIFY_SITE_ID && env.SITE_NAME === 'arcsites';
  } catch { return false; }
}
