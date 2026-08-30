import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ACTIVATION_MANIFEST_ENV,
  ACTIVATION_MANIFEST_SECRET_ENV,
  activationManifestSecretIsDistinct,
  validateActivationManifestEnvironment,
} from '../netlify/lib/activation-manifest-core.mjs';
import { configuredEnvironment } from '../netlify/lib/arc2-handoff-core.mjs';
import { INTAKE_BUILD_MARKER } from '../netlify/lib/intake-build-marker.mjs';
import {
  INTAKE_READINESS_ENV,
  intakeArc1RuntimeReady,
  intakeEnabledFromAttestation,
  intakeEnabledFromBuildMarker,
} from '../netlify/lib/intake-readiness-core.mjs';
import { transactionalEmailWorkerConfiguration } from '../netlify/lib/transactional-email-worker-core.mjs';
import { previewReviewResendWorkerConfiguration } from '../netlify/lib/review-email-resend-core.mjs';
import {
  arc2TransactionalEmailConfiguration,
  resendProviderAccountHmacSha256,
} from '../netlify/lib/arc2-transactional-email-core.mjs';
import { intakeEmailVerificationConfiguration } from '../netlify/lib/intake-email-verification-core.mjs';
import { arc2ClaimLinkRenewalConfiguration } from '../netlify/lib/arc2-claim-link-renewal-core.mjs';
import { intakeAbuseProtectionConfiguration } from '../netlify/lib/intake-abuse-protection-core.mjs';
import { claimSandboxBootstrapConfiguration } from '../netlify/lib/claim-sandbox-bootstrap-core.mjs';
import { operationsAuditConfiguration } from '../netlify/lib/operations-audit-core.mjs';
import {
  firstPartyRetentionConfiguration,
  firstPartyRetentionReceiptFromEnvironment,
} from '../netlify/lib/first-party-retention-core.mjs';
import {
  RETENTION_GENERATION_FENCE_SECRET_ENV,
  retentionGenerationFenceConfiguration,
} from '../netlify/lib/retention-generation-fence-core.mjs';
import { sensitiveCredentialsAreIsolated } from '../netlify/lib/sensitive-credential-isolation.mjs';

export const LAUNCH_STATES = Object.freeze([
  'SAFE_OFF',
  'SANDBOX_CONFIGURED',
  'LIVE_BLOCKED',
  'LIVE_CONFIGURED',
  'INVALID',
]);

const reviewActivationContract = JSON.parse(readFileSync(
  new URL('../operations/review-activation-environment.json', import.meta.url),
  'utf8',
));
const canonicalLiveBlockedControls = reviewActivationContract?.profiles?.production?.blocked_controls;
if (!Array.isArray(canonicalLiveBlockedControls) || canonicalLiveBlockedControls.length === 0 ||
    canonicalLiveBlockedControls.some((value) => typeof value !== 'string' || value.length === 0) ||
    new Set(canonicalLiveBlockedControls).size !== canonicalLiveBlockedControls.length) {
  throw new Error('Canonical live release blockers are invalid.');
}

// The review-activation contract is the single release-blocker authority.
// Reading it directly prevents the launch and Checkout preflights from
// silently drifting onto different provider-evidence requirements.
export const LIVE_RELEASE_BLOCKED_CONTROLS = Object.freeze([...canonicalLiveBlockedControls]);

// Every local switch that can publish, deliver, process, retain, or collect
// customer data. Unset switches are fail-closed in the runtime and count as
// OFF here. Provider dashboards are intentionally not inferred from local env.
export const AUTOMATION_FLAG_NAMES = Object.freeze([
  'ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED',
  'ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED',
  'ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED',
  'ARC_ANALYTICS_COLLECTION_ENABLED',
  'ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED',
  'ARC_BUILD_ANALYTICS_ENABLED',
  'ARC_BUILD_INTAKE_ENABLED',
  'ARC_EMAIL_RECIPIENT_VAULT_ENABLED',
  'ARC_FIRST_PARTY_RETENTION_ENABLED',
  'ARC_HANDOFF_ENABLED',
  'ARC_INTAKE_ARC1_ADAPTER_ENABLED',
  'ARC_INTAKE_ARC1_BRIDGE_ENABLED',
  'ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED',
  'ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED',
  'ARC_INTAKE_ARC1_DISPATCH_ENABLED',
  'ARC_INTAKE_ARC1_DOWNSTREAM_ENABLED',
  'ARC_INTAKE_ARC1_LEGACY_MIGRATION_ENABLED',
  'ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED',
  'ARC_INTAKE_ASSET_RETRIEVAL_ENABLED',
  'ARC_INTAKE_ABUSE_PROTECTION_ENABLED',
  'ARC_INTAKE_CONFIRMATION_CONSUMER_ENABLED',
  'ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED',
  'ARC_INTAKE_EMAIL_VERIFICATION_ENABLED',
  'ARC_INTAKE_ENABLED',
  'ARC_OPERATIONS_ALERT_DELIVERY_ENABLED',
  'ARC_OPERATIONS_AUDIT_ENABLED',
  'ARC_PAYMENT_ARC2_BRIDGE_ENABLED',
  'ARC_PAYMENT_ARC2_WORKER_ENABLED',
  'ARC_RESEND_SEND_ENABLED',
  'ARC_RESEND_WEBHOOK_ENABLED',
  'ARC_REVIEW_CHECKOUT_ENABLED',
  'ARC_REVIEW_EMAIL_INTERNAL_API_ENABLED',
  'ARC_REVIEW_EMAIL_OUTBOX_ENABLED',
  'ARC_REVIEW_EMAIL_RESEND_CAPSULE_ENABLED',
  'ARC_REVIEW_EMAIL_RESEND_WORKER_ENABLED',
  'ARC_REVIEW_PORTAL_ENABLED',
  'ARC_REVIEW_REVISION_OUTBOX_ENABLED',
  'ARC_RETENTION_CLEANUP_ENABLED',
  'ARC_STRIPE_LIVE_MODE_ENABLED',
  'ARC_STRIPE_CHECKOUT_LEDGER_ENABLED',
  'ARC_STRIPE_REVERSAL_BINDING_ENABLED',
  'ARC_STRIPE_REVERSAL_RECHECK_ENABLED',
  'ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED',
  'ARC_STRIPE_REVIEW_CHECKOUT_ENABLED',
  'ARC_STRIPE_REVIEW_REVOCATION_ENABLED',
  'ARC_TRANSACTIONAL_EMAIL_ENABLED',
  'ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED',
  'ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED',
]);

const SANDBOX_ALLOWED_FLAG_NAMES = Object.freeze([
  'ARC_EMAIL_RECIPIENT_VAULT_ENABLED',
  'ARC_INTAKE_CONFIRMATION_CONSUMER_ENABLED',
  'ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED',
  'ARC_PAYMENT_ARC2_BRIDGE_ENABLED',
  'ARC_PAYMENT_ARC2_WORKER_ENABLED',
  'ARC_RESEND_SEND_ENABLED',
  'ARC_RESEND_WEBHOOK_ENABLED',
  'ARC_REVIEW_CHECKOUT_ENABLED',
  'ARC_REVIEW_EMAIL_INTERNAL_API_ENABLED',
  'ARC_REVIEW_EMAIL_OUTBOX_ENABLED',
  'ARC_REVIEW_EMAIL_RESEND_CAPSULE_ENABLED',
  'ARC_REVIEW_EMAIL_RESEND_WORKER_ENABLED',
  'ARC_REVIEW_PORTAL_ENABLED',
  'ARC_REVIEW_REVISION_OUTBOX_ENABLED',
  'ARC_STRIPE_CHECKOUT_LEDGER_ENABLED',
  'ARC_STRIPE_REVERSAL_BINDING_ENABLED',
  'ARC_STRIPE_REVERSAL_RECHECK_ENABLED',
  'ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED',
  'ARC_STRIPE_REVIEW_CHECKOUT_ENABLED',
  'ARC_STRIPE_REVIEW_REVOCATION_ENABLED',
  'ARC_TRANSACTIONAL_EMAIL_ENABLED',
  'ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED',
]);
const SANDBOX_FORBIDDEN_FLAG_NAMES = Object.freeze(AUTOMATION_FLAG_NAMES.filter((name) => ![
  ...SANDBOX_ALLOWED_FLAG_NAMES,
].includes(name)));

const TRANSACTIONAL_EMAIL_FLAG_NAMES = Object.freeze([
  'ARC_EMAIL_RECIPIENT_VAULT_ENABLED',
  'ARC_RESEND_SEND_ENABLED',
  'ARC_RESEND_WEBHOOK_ENABLED',
  'ARC_TRANSACTIONAL_EMAIL_ENABLED',
  'ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED',
]);
const REVIEW_RESEND_FLAG_NAMES = Object.freeze([
  'ARC_REVIEW_EMAIL_RESEND_CAPSULE_ENABLED',
  'ARC_REVIEW_EMAIL_RESEND_WORKER_ENABLED',
]);

const HANDOFF_BOOLEAN_FLAG_NAMES = Object.freeze([
  'ARC_ADULT_OPERATOR_VERIFIED',
  'ARC_ALLOW_TEST_MODE_EVENTS',
  'ARC_BUSINESS_LICENSE_VERIFIED',
  'ARC_DEVICE_QA_VERIFIED',
  'ARC_LEAD_ROUTE_VERIFIED',
  'ARC_POSTCLAIM_READBACK_VERIFIED',
  'ARC_RETENTION_CONTROL_VERIFIED',
  'ARC_STRIPE_REVERSAL_CONTROL_REQUIRED',
  'ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED',
  'ARC_TAX_REGISTRATION_VERIFIED',
  'ARC_TRANSACTIONAL_EMAIL_VERIFIED',
]);

const BOOLEAN_SUFFIX = /_(?:ENABLED|VERIFIED|REQUIRED)$/;
const FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV =
  'ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER';
const exactBoolean = (value) => value === 'true' || value === 'false';
const uniqueSorted = (names) => [...new Set(names)].sort();
const isPresent = (env, name) => typeof env[name] === 'string' && env[name].length > 0;

function retentionFenceSecretIsDistinct(env) {
  const secret = env[RETENTION_GENERATION_FENCE_SECRET_ENV];
  if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 32 ||
      Buffer.byteLength(secret, 'utf8') > 512) return false;
  return sensitiveCredentialsAreIsolated(env, [RETENTION_GENERATION_FENCE_SECRET_ENV]);
}

function booleanFlagNames(env) {
  return uniqueSorted([
    ...AUTOMATION_FLAG_NAMES,
    ...HANDOFF_BOOLEAN_FLAG_NAMES,
    ...Object.keys(env).filter((name) => name.startsWith('ARC_') && BOOLEAN_SUFFIX.test(name)),
  ]);
}

function exactMode(env, mode) {
  if (mode === 'sandbox') {
    return env.ARC_STRIPE_LIVE_MODE_ENABLED === 'false' &&
      env.ARC_ALLOW_TEST_MODE_EVENTS === 'true' &&
      env.ARC_HANDOFF_ENABLED === 'false' &&
      env.ARC_RUNTIME_ENVIRONMENT === 'sandbox';
  }
  return env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true' &&
    env.ARC_ALLOW_TEST_MODE_EVENTS === 'false' &&
    env.ARC_HANDOFF_ENABLED === 'true' &&
    env.ARC_RUNTIME_ENVIRONMENT === 'production';
}

function modeFieldProblems(env, mode) {
  const expected = mode === 'sandbox' ? {
    ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
    ARC_ALLOW_TEST_MODE_EVENTS: 'true',
    ARC_HANDOFF_ENABLED: 'false',
    ARC_RUNTIME_ENVIRONMENT: 'sandbox',
  } : {
    ARC_STRIPE_LIVE_MODE_ENABLED: 'true',
    ARC_ALLOW_TEST_MODE_EVENTS: 'false',
    ARC_HANDOFF_ENABLED: 'true',
    ARC_RUNTIME_ENVIRONMENT: 'production',
  };
  const missing = [];
  const invalid = [];
  for (const [name, value] of Object.entries(expected)) {
    if (!isPresent(env, name)) missing.push(name);
    else if (env[name] !== value) invalid.push(name);
  }
  return { missing, invalid };
}

function safeRuntimeReadiness(env, now, runtimeReady) {
  try {
    const origin = new URL(String(env.ARC_PUBLIC_ORIGIN || env.URL || 'https://arcweb.onl/'));
    return runtimeReady(new Request(new URL('/api/intake/readiness', origin)), env, now) === true;
  } catch {
    return false;
  }
}

export function createLaunchPreflightReport(env = process.env, options = {}) {
  const mode = options.mode || 'safety';
  const buildMarker = options.buildMarker || INTAKE_BUILD_MARKER;
  const runtimeReady = options.runtimeReady || intakeArc1RuntimeReady;
  const now = options.now || new Date();
  const allBooleanNames = booleanFlagNames(env);
  const malformedBooleanFlags = allBooleanNames.filter((name) => isPresent(env, name) && !exactBoolean(env[name]));
  const enabledFlags = AUTOMATION_FLAG_NAMES.filter((name) => env[name] === 'true');
  const offFlags = AUTOMATION_FLAG_NAMES.filter((name) => !isPresent(env, name) || env[name] === 'false');
  const automationFlagsValid = AUTOMATION_FLAG_NAMES.every((name) => !isPresent(env, name) || exactBoolean(env[name]));
  const intakeBuildMarkerEnabled = intakeEnabledFromBuildMarker(buildMarker);
  if (intakeBuildMarkerEnabled) enabledFlags.push('INTAKE_BUILD_MARKER');
  else offFlags.push('INTAKE_BUILD_MARKER');
  const automationOff = automationFlagsValid && enabledFlags.length === 0;

  const handoff = configuredEnvironment(env, now);
  const sandboxModeExact = exactMode(env, 'sandbox');
  const liveModeExact = exactMode(env, 'live');
  const intakeBuildFlagEnabled = env.ARC_BUILD_INTAKE_ENABLED === 'true';
  const intakeAttestationValid = intakeEnabledFromAttestation(env[INTAKE_READINESS_ENV]);
  const intakeConsumerClaimEnabled = env.ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED === 'true';
  const intakeConsumerCompletionEnabled = env.ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED === 'true';
  const intakeConsumerProtocolEnabled = intakeConsumerClaimEnabled && intakeConsumerCompletionEnabled;
  const intakeRecoveryAutomationEnabled = env.ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED === 'true';
  const intakeConfirmationOutboxEnabled = env.ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED === 'true';
  const intakeConfirmationConsumerEnabled = env.ARC_INTAKE_CONFIRMATION_CONSUMER_ENABLED === 'true';
  const intakeConfirmationProtocolEnabled = intakeConfirmationOutboxEnabled && intakeConfirmationConsumerEnabled;
  const intakeEmailVerificationEnabled = env.ARC_INTAKE_EMAIL_VERIFICATION_ENABLED === 'true';
  const intakeEmailVerificationReady = intakeEmailVerificationConfiguration(env).enabled;
  const intakeAbuseProtection = intakeAbuseProtectionConfiguration(env);
  const intakeAbuseProtectionReady = intakeAbuseProtection.enabled;
  const firstPartyRetention = firstPartyRetentionConfiguration(env);
  const firstPartyRetentionReceipt = firstPartyRetentionReceiptFromEnvironment(env, now);
  const firstPartyRetentionAlertQueueReady = !firstPartyRetention.requested ||
    operationsAuditConfiguration(env).enabled;
  const firstPartyRetentionReady = firstPartyRetention.enabled && Boolean(firstPartyRetentionReceipt) &&
    firstPartyRetentionAlertQueueReady;
  const legalHoldBearer = env[FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV];
  const legalHoldBearerValid = typeof legalHoldBearer === 'string' &&
    Buffer.byteLength(legalHoldBearer, 'utf8') >= 32 &&
    Buffer.byteLength(legalHoldBearer, 'utf8') <= 512;
  const legalHoldBearerDistinct = legalHoldBearerValid && sensitiveCredentialsAreIsolated(
    env,
    [FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV],
  );
  const firstPartyLegalHoldWriterReady = firstPartyRetention.enabled &&
    legalHoldBearerValid && legalHoldBearerDistinct;
  const retentionGenerationFence = retentionGenerationFenceConfiguration(env);
  const retentionGenerationFenceSecretDistinct = retentionFenceSecretIsDistinct(env);
  const retentionGenerationFenceReady = retentionGenerationFence.ready &&
    retentionGenerationFenceSecretDistinct;
  const requiredActivationStage = {
    sandbox: 'EMAIL_SANDBOX',
    live: 'PUBLIC_INTAKE',
  }[mode] || 'OFF';
  const activationManifest = validateActivationManifestEnvironment(env, {
    minimumStage: requiredActivationStage,
    now,
  });
  const activationManifestSecretDistinct = activationManifestSecretIsDistinct(env);
  const activationManifestReady = activationManifest.valid && activationManifestSecretDistinct;
  const claimSandboxBootstrap = claimSandboxBootstrapConfiguration(env, now);
  const claimSandboxBootstrapRequested = activationManifest.valid &&
    activationManifest.authority_mode === 'TEST_BOOTSTRAP' &&
    activationManifest.stage === 'CLAIM_SANDBOX';
  const claimSandboxBootstrapReady = !claimSandboxBootstrapRequested ||
    (claimSandboxBootstrap.enabled && claimSandboxBootstrap.bootstrap_active);
  const transactionalEmailRequested = TRANSACTIONAL_EMAIL_FLAG_NAMES.some((name) => env[name] === 'true');
  const transactionalEmailFlagsEnabled = TRANSACTIONAL_EMAIL_FLAG_NAMES.every((name) => env[name] === 'true');
  let transactionalEmailRuntimeEnabled = false;
  try { transactionalEmailRuntimeEnabled = transactionalEmailWorkerConfiguration(env).enabled; } catch {}
  const transactionalEmailProtocolEnabled = transactionalEmailFlagsEnabled && transactionalEmailRuntimeEnabled;
  const transactionalEmailStackCoherent = !transactionalEmailRequested || transactionalEmailProtocolEnabled;
  const reviewResendRequested = REVIEW_RESEND_FLAG_NAMES.some((name) => env[name] === 'true');
  const reviewResendFlagsEnabled = REVIEW_RESEND_FLAG_NAMES.every((name) => env[name] === 'true');
  let reviewResendRuntimeEnabled = false;
  try { reviewResendRuntimeEnabled = previewReviewResendWorkerConfiguration(env).enabled; } catch {}
  const reviewResendStackCoherent = !reviewResendRequested ||
    (reviewResendFlagsEnabled && transactionalEmailProtocolEnabled && reviewResendRuntimeEnabled);
  const arc2Email = arc2TransactionalEmailConfiguration(env);
  let resendProviderBindingValid = false;
  try {
    resendProviderBindingValid = /^[a-f0-9]{64}$/.test(resendProviderAccountHmacSha256(env));
  } catch {}
  const arc2EmailStackCoherent = arc2Email.flags_valid && (!arc2Email.requested ||
    (arc2Email.capsule_producer_enabled && resendProviderBindingValid));
  const claimLinkRenewal = arc2ClaimLinkRenewalConfiguration(env);
  const claimLinkRenewalStackCoherent = claimLinkRenewal.flag_valid &&
    (!claimLinkRenewal.requested || claimLinkRenewal.enabled);
  const transactionalEmailRetentionValid = env.ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED === 'true' &&
    /^(?:[7-9]|[1-9][0-9]|[12][0-9]{2}|3[0-5][0-9]|36[0-5])$/.test(
      String(env.ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS || ''),
    );
  const intakeRuntimeReady = intakeBuildFlagEnabled && intakeAttestationValid &&
    safeRuntimeReadiness(env, now, runtimeReady);
  const intakeReady = intakeBuildFlagEnabled && intakeBuildMarkerEnabled &&
    intakeAttestationValid && intakeRuntimeReady && intakeConsumerProtocolEnabled && intakeRecoveryAutomationEnabled &&
    intakeConfirmationProtocolEnabled && intakeEmailVerificationEnabled && intakeEmailVerificationReady &&
    intakeAbuseProtectionReady && firstPartyRetentionReady && transactionalEmailProtocolEnabled &&
    firstPartyLegalHoldWriterReady && activationManifestReady;
  const sandboxAutomationOff = SANDBOX_FORBIDDEN_FLAG_NAMES.every((name) =>
    !isPresent(env, name) || env[name] === 'false');

  let state = 'INVALID';
  if (malformedBooleanFlags.length === 0 && sandboxModeExact && activationManifestReady &&
      sandboxAutomationOff && transactionalEmailStackCoherent && reviewResendStackCoherent &&
      claimLinkRenewalStackCoherent && claimSandboxBootstrapReady &&
      retentionGenerationFenceReady && !intakeBuildMarkerEnabled) {
    state = 'SANDBOX_CONFIGURED';
  } else if (malformedBooleanFlags.length === 0 && handoff.enabled && liveModeExact && intakeReady &&
      retentionGenerationFenceReady) {
    state = LIVE_RELEASE_BLOCKED_CONTROLS.length > 0 ? 'LIVE_BLOCKED' : 'LIVE_CONFIGURED';
  } else if (malformedBooleanFlags.length === 0 && automationOff) {
    state = 'SAFE_OFF';
  }

  const missing = [];
  const invalid = [...malformedBooleanFlags];
  if (mode === 'safety') {
    if (!automationOff) invalid.push(...enabledFlags);
  } else if (mode === 'sandbox' || mode === 'live') {
    if (mode === 'live') {
      missing.push(...handoff.missing);
      invalid.push(...handoff.invalid);
    }
    const modeProblems = modeFieldProblems(env, mode);
    missing.push(...modeProblems.missing);
    invalid.push(...modeProblems.invalid);
    if (!isPresent(env, ACTIVATION_MANIFEST_ENV)) missing.push(ACTIVATION_MANIFEST_ENV);
    else if (!activationManifest.valid) invalid.push(ACTIVATION_MANIFEST_ENV);
    if (!isPresent(env, ACTIVATION_MANIFEST_SECRET_ENV)) missing.push(ACTIVATION_MANIFEST_SECRET_ENV);
    else if (!activationManifestSecretDistinct) invalid.push(ACTIVATION_MANIFEST_SECRET_ENV);
    if (!isPresent(env, RETENTION_GENERATION_FENCE_SECRET_ENV)) {
      missing.push(RETENTION_GENERATION_FENCE_SECRET_ENV);
    } else if (!retentionGenerationFence.ready) {
      invalid.push(retentionGenerationFence.invalid.includes(
        'ARC_FIRST_PARTY_RETENTION_FENCE_SECRET_SEPARATION')
        ? 'ARC_FIRST_PARTY_RETENTION_FENCE_SECRET_SEPARATION'
        : RETENTION_GENERATION_FENCE_SECRET_ENV);
    } else if (!retentionGenerationFenceSecretDistinct) {
      invalid.push('ARC_FIRST_PARTY_RETENTION_FENCE_SECRET_SEPARATION');
    }
    if (!activationManifest.checks.deployment_bound) invalid.push('ACTIVATION_BUILD_IDENTITY');
    if (mode === 'sandbox') {
      invalid.push(...SANDBOX_FORBIDDEN_FLAG_NAMES.filter((name) => env[name] === 'true'));
      if (!transactionalEmailStackCoherent) invalid.push('TRANSACTIONAL_EMAIL_RUNTIME_CONFIGURATION');
      if (!reviewResendStackCoherent) invalid.push('REVIEW_RESEND_RUNTIME_CONFIGURATION');
      if (!arc2EmailStackCoherent) invalid.push('ARC2_EMAIL_RUNTIME_CONFIGURATION');
      if (!claimLinkRenewalStackCoherent) invalid.push('ARC2_CLAIM_LINK_RENEWAL_RUNTIME_CONFIGURATION');
      if (!claimSandboxBootstrapReady) invalid.push('CLAIM_SANDBOX_BOOTSTRAP_CONFIGURATION');
      if (intakeBuildMarkerEnabled) invalid.push('INTAKE_BUILD_MARKER');
    } else {
      if (!isPresent(env, 'ARC_BUILD_INTAKE_ENABLED')) missing.push('ARC_BUILD_INTAKE_ENABLED');
      else if (!intakeBuildFlagEnabled) invalid.push('ARC_BUILD_INTAKE_ENABLED');
      if (!isPresent(env, INTAKE_READINESS_ENV)) missing.push(INTAKE_READINESS_ENV);
      else if (!intakeAttestationValid) invalid.push(INTAKE_READINESS_ENV);
      for (const name of ['ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED', 'ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED']) {
        if (!isPresent(env, name)) missing.push(name);
        else if (env[name] !== 'true') invalid.push(name);
      }
      for (const name of ['ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED', 'ARC_INTAKE_CONFIRMATION_CONSUMER_ENABLED']) {
        if (!isPresent(env, name)) missing.push(name);
        else if (env[name] !== 'true') invalid.push(name);
      }
      if (!isPresent(env, 'ARC_INTAKE_EMAIL_VERIFICATION_ENABLED')) {
        missing.push('ARC_INTAKE_EMAIL_VERIFICATION_ENABLED');
      } else if (!intakeEmailVerificationEnabled) {
        invalid.push('ARC_INTAKE_EMAIL_VERIFICATION_ENABLED');
      }
      if (!intakeEmailVerificationReady) invalid.push('INTAKE_EMAIL_VERIFICATION_RUNTIME_CONFIGURATION');
      if (!isPresent(env, 'ARC_INTAKE_ABUSE_PROTECTION_ENABLED')) {
        missing.push('ARC_INTAKE_ABUSE_PROTECTION_ENABLED');
      } else if (env.ARC_INTAKE_ABUSE_PROTECTION_ENABLED !== 'true') {
        invalid.push('ARC_INTAKE_ABUSE_PROTECTION_ENABLED');
      }
      if (!intakeAbuseProtectionReady) invalid.push('INTAKE_ABUSE_PROTECTION_RUNTIME_CONFIGURATION');
      if (!isPresent(env, 'ARC_FIRST_PARTY_RETENTION_ENABLED')) {
        missing.push('ARC_FIRST_PARTY_RETENTION_ENABLED');
      } else if (env.ARC_FIRST_PARTY_RETENTION_ENABLED !== 'true') {
        invalid.push('ARC_FIRST_PARTY_RETENTION_ENABLED');
      }
      if (!firstPartyRetention.enabled) invalid.push('FIRST_PARTY_RETENTION_RUNTIME_CONFIGURATION');
      if (!firstPartyRetentionAlertQueueReady) {
        invalid.push('FIRST_PARTY_RETENTION_ALERT_QUEUE_CONFIGURATION');
      }
      if (!firstPartyRetentionReceipt) invalid.push('ARC_FIRST_PARTY_RETENTION_RECEIPT');
      if (!isPresent(env, FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV)) {
        missing.push(FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV);
      } else if (!legalHoldBearerValid) {
        invalid.push(FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV);
      } else if (!legalHoldBearerDistinct) {
        invalid.push('FIRST_PARTY_RETENTION_LEGAL_HOLD_SECRET_SEPARATION');
      }
      for (const name of TRANSACTIONAL_EMAIL_FLAG_NAMES) {
        if (!isPresent(env, name)) missing.push(name);
        else if (env[name] !== 'true') invalid.push(name);
      }
      for (const name of REVIEW_RESEND_FLAG_NAMES) {
        if (!isPresent(env, name)) missing.push(name);
        else if (env[name] !== 'true') invalid.push(name);
      }
      for (const name of ['ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED', 'ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED']) {
        if (!isPresent(env, name)) missing.push(name);
        else if (env[name] !== 'true') invalid.push(name);
      }
      if (!isPresent(env, 'ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED')) {
        missing.push('ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED');
      } else if (env.ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED !== 'true') {
        invalid.push('ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED');
      }
      if (!isPresent(env, 'ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED')) {
        missing.push('ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED');
      } else if (env.ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED !== 'true') {
        invalid.push('ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED');
      }
      if (!isPresent(env, 'ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS')) {
        missing.push('ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS');
      } else if (!transactionalEmailRetentionValid) {
        invalid.push('ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS');
      }
      if (!transactionalEmailRuntimeEnabled) invalid.push('TRANSACTIONAL_EMAIL_RUNTIME_CONFIGURATION');
      if (!reviewResendStackCoherent) invalid.push('REVIEW_RESEND_RUNTIME_CONFIGURATION');
      if (!arc2EmailStackCoherent) invalid.push('ARC2_EMAIL_RUNTIME_CONFIGURATION');
      if (!claimLinkRenewalStackCoherent) invalid.push('ARC2_CLAIM_LINK_RENEWAL_RUNTIME_CONFIGURATION');
      if (!isPresent(env, 'ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED')) {
        missing.push('ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED');
      } else if (!intakeRecoveryAutomationEnabled) invalid.push('ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED');
      if (!intakeBuildMarkerEnabled) invalid.push('INTAKE_BUILD_MARKER');
      if (!intakeRuntimeReady) invalid.push('INTAKE_ARC1_RUNTIME_READINESS');
    }
  } else {
    invalid.push('CLI_MODE');
  }

  const expectedState = {
    safety: 'SAFE_OFF',
    sandbox: 'SANDBOX_CONFIGURED',
    live: 'LIVE_CONFIGURED',
  }[mode];
  const cleanMissing = uniqueSorted(missing);
  const cleanInvalid = uniqueSorted(invalid);
  const ok = state === expectedState && cleanMissing.length === 0 && cleanInvalid.length === 0;

  return {
    state,
    mode: ['safety', 'sandbox', 'live'].includes(mode) ? mode : 'INVALID',
    ok,
    checks: {
      exact_boolean_flags_valid: malformedBooleanFlags.length === 0,
      local_automation_off: automationOff,
      handoff_environment_configured: handoff.enabled,
      sandbox_mode_exact: sandboxModeExact,
      live_mode_exact: liveModeExact,
      intake_build_flag_enabled: intakeBuildFlagEnabled,
      intake_build_marker_enabled: intakeBuildMarkerEnabled,
      intake_attestation_valid: intakeAttestationValid,
      intake_consumer_claim_enabled: intakeConsumerClaimEnabled,
      intake_consumer_completion_enabled: intakeConsumerCompletionEnabled,
      intake_consumer_protocol_enabled: intakeConsumerProtocolEnabled,
      intake_recovery_automation_enabled: intakeRecoveryAutomationEnabled,
      intake_confirmation_outbox_enabled: intakeConfirmationOutboxEnabled,
      intake_confirmation_consumer_enabled: intakeConfirmationConsumerEnabled,
      intake_confirmation_protocol_enabled: intakeConfirmationProtocolEnabled,
      intake_email_verification_enabled: intakeEmailVerificationEnabled,
      intake_email_verification_runtime_ready: intakeEmailVerificationReady,
      intake_abuse_protection_runtime_ready: intakeAbuseProtectionReady,
      first_party_retention_runtime_ready: firstPartyRetention.enabled,
      first_party_retention_alert_queue_ready: firstPartyRetentionAlertQueueReady,
      first_party_retention_receipt_current: Boolean(firstPartyRetentionReceipt),
      first_party_retention_ready: firstPartyRetentionReady,
      first_party_retention_legal_hold_writer_ready: firstPartyLegalHoldWriterReady,
      retention_generation_fence_ready: retentionGenerationFenceReady,
      retention_generation_fence_secret_distinct: retentionGenerationFenceSecretDistinct,
      transactional_email_flags_enabled: transactionalEmailFlagsEnabled,
      transactional_email_runtime_enabled: transactionalEmailRuntimeEnabled,
      transactional_email_stack_coherent: transactionalEmailStackCoherent,
      review_resend_flags_enabled: reviewResendFlagsEnabled,
      review_resend_runtime_enabled: reviewResendRuntimeEnabled,
      review_resend_stack_coherent: reviewResendStackCoherent,
      arc2_email_stack_coherent: arc2EmailStackCoherent,
      claim_link_renewal_stack_coherent: claimLinkRenewalStackCoherent,
      claim_sandbox_bootstrap_active: claimSandboxBootstrap.bootstrap_active,
      claim_sandbox_bootstrap_ready: claimSandboxBootstrapReady,
      resend_provider_binding_valid: resendProviderBindingValid,
      transactional_email_retention_valid: transactionalEmailRetentionValid,
      intake_runtime_ready: intakeRuntimeReady,
      intake_ready: intakeReady,
      activation_manifest_required: mode === 'sandbox' || mode === 'live',
      activation_manifest_valid: activationManifest.valid,
      activation_manifest_current: activationManifest.checks.current,
      activation_manifest_deployment_bound: activationManifest.checks.deployment_bound,
      activation_manifest_evidence_complete: activationManifest.checks.evidence_complete,
      activation_manifest_stage_sufficient: activationManifest.checks.stage_sufficient,
      activation_manifest_secret_distinct: activationManifestSecretDistinct,
      activation_manifest_rotation_due: activationManifest.rotation_due,
      activation_manifest_next_valid: activationManifest.next_manifest_valid === true,
      external_provider_state_checked: false,
      secret_values_output: false,
    },
    enabled_flags: uniqueSorted(enabledFlags),
    off_flags: uniqueSorted(offFlags),
    missing: cleanMissing,
    invalid: cleanInvalid,
    blocked: mode === 'live' ? [...LIVE_RELEASE_BLOCKED_CONTROLS] : [],
    activation: {
      stage: activationManifest.stage,
      authority_mode: activationManifest.authority_mode,
      expires_at: activationManifest.expires_at,
      required_stage: requiredActivationStage,
    },
  };
}

function requestedMode(argv) {
  if (!Array.isArray(argv) || argv.length !== 1) return null;
  const match = /^--mode=(safety|sandbox|live)$/.exec(argv[0]);
  return match?.[1] || null;
}

export function runLaunchPreflightCli({
  argv = process.argv.slice(2),
  env = process.env,
  write = (value) => process.stdout.write(value),
  ...options
} = {}) {
  const mode = requestedMode(argv);
  const report = createLaunchPreflightReport(env, { ...options, mode: mode || 'INVALID' });
  write(`${JSON.stringify(report, null, 2)}\n`);
  if (!mode) return 2;
  return report.ok ? 0 : 1;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  process.exitCode = runLaunchPreflightCli();
}
