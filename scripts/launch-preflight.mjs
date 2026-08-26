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

export const LAUNCH_STATES = Object.freeze([
  'SAFE_OFF',
  'SANDBOX_CONFIGURED',
  'LIVE_CONFIGURED',
  'INVALID',
]);

// Every local switch that can publish, deliver, process, retain, or collect
// customer data. Unset switches are fail-closed in the runtime and count as
// OFF here. Provider dashboards are intentionally not inferred from local env.
export const AUTOMATION_FLAG_NAMES = Object.freeze([
  'ARC_ANALYTICS_COLLECTION_ENABLED',
  'ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED',
  'ARC_BUILD_ANALYTICS_ENABLED',
  'ARC_BUILD_INTAKE_ENABLED',
  'ARC_HANDOFF_ENABLED',
  'ARC_INTAKE_ARC1_ADAPTER_ENABLED',
  'ARC_INTAKE_ARC1_BRIDGE_ENABLED',
  'ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED',
  'ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED',
  'ARC_INTAKE_ARC1_DISPATCH_ENABLED',
  'ARC_INTAKE_ARC1_DOWNSTREAM_ENABLED',
  'ARC_INTAKE_ARC1_LEGACY_MIGRATION_ENABLED',
  'ARC_INTAKE_ASSET_RETRIEVAL_ENABLED',
  'ARC_INTAKE_ENABLED',
  'ARC_OPERATIONS_AUDIT_ENABLED',
  'ARC_RETENTION_CLEANUP_ENABLED',
  'ARC_STRIPE_LIVE_MODE_ENABLED',
  'ARC_STRIPE_CHECKOUT_LEDGER_ENABLED',
  'ARC_STRIPE_REVERSAL_BINDING_ENABLED',
  'ARC_STRIPE_REVERSAL_RECHECK_ENABLED',
  'ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED',
]);

const SANDBOX_FORBIDDEN_FLAG_NAMES = Object.freeze(AUTOMATION_FLAG_NAMES.filter((name) => ![
  'ARC_STRIPE_CHECKOUT_LEDGER_ENABLED',
  'ARC_STRIPE_REVERSAL_BINDING_ENABLED',
  'ARC_STRIPE_REVERSAL_RECHECK_ENABLED',
  'ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED',
].includes(name)));

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
const exactBoolean = (value) => value === 'true' || value === 'false';
const uniqueSorted = (names) => [...new Set(names)].sort();
const isPresent = (env, name) => typeof env[name] === 'string' && env[name].length > 0;

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
  const requiredActivationStage = {
    sandbox: 'CLAIM_SANDBOX',
    live: 'PUBLIC_INTAKE',
  }[mode] || 'OFF';
  const activationManifest = validateActivationManifestEnvironment(env, {
    minimumStage: requiredActivationStage,
    now,
  });
  const activationManifestSecretDistinct = activationManifestSecretIsDistinct(env);
  const activationManifestReady = activationManifest.valid && activationManifestSecretDistinct;
  const intakeRuntimeReady = intakeBuildFlagEnabled && intakeAttestationValid &&
    safeRuntimeReadiness(env, now, runtimeReady);
  const intakeReady = intakeBuildFlagEnabled && intakeBuildMarkerEnabled &&
    intakeAttestationValid && intakeRuntimeReady && intakeConsumerProtocolEnabled && activationManifestReady;
  const sandboxAutomationOff = SANDBOX_FORBIDDEN_FLAG_NAMES.every((name) =>
    !isPresent(env, name) || env[name] === 'false');

  let state = 'INVALID';
  if (malformedBooleanFlags.length === 0 && handoff.enabled && sandboxModeExact && activationManifestReady &&
      sandboxAutomationOff && !intakeBuildMarkerEnabled) {
    state = 'SANDBOX_CONFIGURED';
  } else if (malformedBooleanFlags.length === 0 && handoff.enabled && liveModeExact && intakeReady) {
    state = 'LIVE_CONFIGURED';
  } else if (malformedBooleanFlags.length === 0 && automationOff) {
    state = 'SAFE_OFF';
  }

  const missing = [];
  const invalid = [...malformedBooleanFlags];
  if (mode === 'safety') {
    if (!automationOff) invalid.push(...enabledFlags);
  } else if (mode === 'sandbox' || mode === 'live') {
    missing.push(...handoff.missing);
    invalid.push(...handoff.invalid);
    const modeProblems = modeFieldProblems(env, mode);
    missing.push(...modeProblems.missing);
    invalid.push(...modeProblems.invalid);
    if (!isPresent(env, ACTIVATION_MANIFEST_ENV)) missing.push(ACTIVATION_MANIFEST_ENV);
    else if (!activationManifest.valid) invalid.push(ACTIVATION_MANIFEST_ENV);
    if (!isPresent(env, ACTIVATION_MANIFEST_SECRET_ENV)) missing.push(ACTIVATION_MANIFEST_SECRET_ENV);
    else if (!activationManifestSecretDistinct) invalid.push(ACTIVATION_MANIFEST_SECRET_ENV);
    if (!activationManifest.checks.deployment_bound) invalid.push('ACTIVATION_BUILD_IDENTITY');
    if (mode === 'sandbox') {
      invalid.push(...SANDBOX_FORBIDDEN_FLAG_NAMES.filter((name) => env[name] === 'true'));
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
