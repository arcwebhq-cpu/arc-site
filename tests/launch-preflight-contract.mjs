import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
  createLaunchPreflightReport,
  runLaunchPreflightCli,
} from '../scripts/launch-preflight.mjs';
import {
  ACTIVATION_EVIDENCE_BY_STAGE,
  ACTIVATION_MANIFEST_SCHEMA,
  ACTIVATION_MANIFEST_VERSION,
  signActivationManifest,
} from '../netlify/lib/activation-manifest-core.mjs';
import {
  INTAKE_BUILD_MARKER_SCHEMA,
  INTAKE_BUILD_MARKER_VERSION,
  INTAKE_READINESS_BOOLEAN_FIELDS,
  INTAKE_READINESS_SCHEMA,
  INTAKE_READINESS_VERSION,
} from '../netlify/lib/intake-readiness-core.mjs';

const secretNames = [
  'ARC_CHECKOUT_BINDING_SECRET',
  'ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET',
  'ARC_LEAD_ROUTE_EVIDENCE_SECRET',
  'ARC_HANDOFF_STATE_SECRET',
  'ARC_HANDOFF_TRIGGER_SECRET',
  'ARC_CLAIM_TOKEN_SECRET',
  'ARC_CLAIM_STATE_EVIDENCE_SECRET',
  'ARC_EMAIL_CLAIM_BINDING_SECRET',
  'ARC_FINAL_DELIVERY_RECEIPT_SECRET',
  'ARC_FINAL_DELIVERY_ACK_SECRET',
  'ARC_INTAKE_ARC1_PACKET_SECRET',
  'ARC_INTAKE_ARC1_CONSUMER_BEARER',
  'ARC_INTAKE_ARC1_CONSUMER_RECEIPT_SECRET',
  'ARC_STRIPE_WEBHOOK_SIGNING_SECRET',
  'ARC_STRIPE_REVERSAL_HMAC_SECRET',
  'ARC_STRIPE_REVERSAL_BINDING_SECRET',
  'ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET',
  'ARC_STRIPE_REVERSAL_RECHECK_SECRET',
  'ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET',
  'NETLIFY_ADMIN_PAT',
  'NETLIFY_OAUTH_CLIENT_SECRET',
  'ARC_ACTIVATION_MANIFEST_HMAC_SECRET',
];
const secretMarkers = secretNames.map((_, index) =>
  `TOP_SECRET_MARKER_${String(index).padStart(2, '0')}_abcdefghijklmnopqrstuvwxyz`);
const secrets = Object.fromEntries(secretNames.map((name, index) => [name, secretMarkers[index]]));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const preflightNow = new Date();
const deploymentSha = '9'.repeat(40);
const activationEvidence = (stage) => ACTIVATION_EVIDENCE_BY_STAGE[stage].map((kind) => ({
  kind,
  receipt_ref: `audit:${sha256(`receipt:${kind}`).slice(0, 24)}`,
  sha256: sha256(`evidence:${kind}`),
}));
const activationManifest = (stage, overrides = {}) => signActivationManifest({
  schema: ACTIVATION_MANIFEST_SCHEMA,
  version: ACTIVATION_MANIFEST_VERSION,
  stage,
  authority_mode: 'ROLLOUT',
  issued_at: new Date(preflightNow.getTime() - 60_000).toISOString(),
  expires_at: new Date(preflightNow.getTime() + 60 * 60_000).toISOString(),
  deployment_sha: deploymentSha,
  evidence: activationEvidence(stage),
  ...overrides,
}, secrets.ARC_ACTIVATION_MANIFEST_HMAC_SECRET);

const common = {
  ...secrets,
  ARC_CHECKOUT_BINDING_KEY_ID: '01',
  ARC_RETIRED_CHECKOUT_BINDING_KEYS_JSON: '{}',
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256: sha256('acct_arc_launch_preflight'),
  ARC_ADULT_OPERATOR_VERIFIED: 'true',
  ARC_BUSINESS_LICENSE_VERIFIED: 'true',
  ARC_TAX_REGISTRATION_VERIFIED: 'true',
  ARC_TRANSACTIONAL_EMAIL_VERIFIED: 'true',
  ARC_RETENTION_CONTROL_VERIFIED: 'true',
  ARC_POSTCLAIM_READBACK_VERIFIED: 'true',
  ARC_DEVICE_QA_VERIFIED: 'true',
  ARC_LEAD_ROUTE_VERIFIED: 'true',
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'true',
  ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_BINDING_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_RECHECK_ENABLED: 'true',
  ARC_STRIPE_CHECKOUT_LEDGER_ENABLED: 'true',
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'false',
  ARC_STRIPE_WEBHOOK_API_VERSION: '2026-07-29.dahlia',
  ARC_PUBLIC_ORIGIN: 'https://arcweb.onl/',
  SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  URL: 'https://arcweb.onl/',
  NETLIFY_TEAM_SLUG: 'arc-team',
  NETLIFY_TEAM_ACCOUNT_ID: 'account-source-123',
  NETLIFY_OAUTH_CLIENT_ID: 'oauth-client-123',
  COMMIT_REF: deploymentSha,
};

const sandboxEnv = {
  ...common,
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: 'rk_' + 'test_TOP_SECRET_ACCOUNT_MARKER_0123456789',
  ARC_HANDOFF_ENABLED: 'false',
  ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
  ARC_ALLOW_TEST_MODE_EVENTS: 'true',
  ARC_RUNTIME_ENVIRONMENT: 'sandbox',
  SITE_NAME: 'arc2-sandbox',
  ARC_ACTIVATION_MANIFEST: activationManifest('CLAIM_SANDBOX'),
};

const completeIntakeAttestation = Object.fromEntries([
  ['schema', INTAKE_READINESS_SCHEMA],
  ['version', INTAKE_READINESS_VERSION],
  ...INTAKE_READINESS_BOOLEAN_FIELDS.map((name) => [name, true]),
]);
const enabledBuildMarker = Object.freeze({
  schema: INTAKE_BUILD_MARKER_SCHEMA,
  version: INTAKE_BUILD_MARKER_VERSION,
  intake_enabled: true,
});
const liveEnv = {
  ...common,
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: 'rk_' + 'live_TOP_SECRET_ACCOUNT_MARKER_0123456789',
  ARC_HANDOFF_ENABLED: 'true',
  ARC_STRIPE_LIVE_MODE_ENABLED: 'true',
  ARC_ALLOW_TEST_MODE_EVENTS: 'false',
  ARC_RUNTIME_ENVIRONMENT: 'production',
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'true',
  ARC_BUILD_INTAKE_ENABLED: 'true',
  ARC_INTAKE_ARC1_BRIDGE_ENABLED: 'true',
  ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED: 'true',
  ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED: 'true',
  ARC_INTAKE_ARC1_DISPATCH_ENABLED: 'true',
  ARC_INTAKE_ASSET_RETRIEVAL_ENABLED: 'true',
  ARC_INTAKE_READINESS_ATTESTATION: JSON.stringify(completeIntakeAttestation),
  SITE_NAME: 'arcsites',
  ARC_ACTIVATION_MANIFEST: activationManifest('PUBLIC_INTAKE'),
};

const safe = createLaunchPreflightReport({}, { mode: 'safety' });
assert.equal(safe.state, 'SAFE_OFF');
assert.equal(safe.ok, true);
assert.equal(safe.checks.local_automation_off, true);
assert.equal(safe.checks.external_provider_state_checked, false);
assert.deepEqual(safe.missing, []);
assert.deepEqual(safe.invalid, []);

for (const invalidValue of ['yes', '1']) {
  const invalidMarker = `DO_NOT_LEAK_BOOLEAN_${invalidValue}`;
  const report = createLaunchPreflightReport({
    ARC_HANDOFF_ENABLED: invalidValue,
    ARC_CHECKOUT_BINDING_SECRET: invalidMarker,
  }, { mode: 'safety' });
  assert.equal(report.state, 'INVALID');
  assert.equal(report.ok, false);
  assert.ok(report.invalid.includes('ARC_HANDOFF_ENABLED'));
  assert.equal(JSON.stringify(report).includes(invalidValue === '1' ? `"${invalidValue}"` : invalidValue), false);
  assert.equal(JSON.stringify(report).includes(invalidMarker), false);
}

const unexpectedlyActive = createLaunchPreflightReport({ ARC_BUILD_INTAKE_ENABLED: 'true' }, { mode: 'safety' });
assert.equal(unexpectedlyActive.state, 'INVALID');
assert.equal(unexpectedlyActive.ok, false);
assert.ok(unexpectedlyActive.enabled_flags.includes('ARC_BUILD_INTAKE_ENABLED'));
assert.ok(unexpectedlyActive.invalid.includes('ARC_BUILD_INTAKE_ENABLED'));

const sandbox = createLaunchPreflightReport(sandboxEnv, { mode: 'sandbox' });
assert.equal(sandbox.state, 'SANDBOX_CONFIGURED');
assert.equal(sandbox.ok, true);
assert.equal(sandbox.checks.sandbox_mode_exact, true);
assert.equal(sandbox.checks.live_mode_exact, false);
assert.deepEqual(sandbox.missing, []);
assert.deepEqual(sandbox.invalid, []);
assert.equal(sandbox.activation.stage, 'CLAIM_SANDBOX');
assert.equal(sandbox.checks.activation_manifest_current, true);
assert.equal(sandbox.checks.activation_manifest_deployment_bound, true);
const sandboxWithoutManifest = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_ACTIVATION_MANIFEST: '',
}, { mode: 'sandbox', now: preflightNow });
assert.equal(sandboxWithoutManifest.ok, false);
assert.ok(sandboxWithoutManifest.missing.includes('ARC_ACTIVATION_MANIFEST'));
const sandboxBelowStage = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_ACTIVATION_MANIFEST: activationManifest('EMAIL_SANDBOX'),
}, { mode: 'sandbox', now: preflightNow });
assert.equal(sandboxBelowStage.ok, false);
assert.equal(sandboxBelowStage.checks.activation_manifest_stage_sufficient, false);

const live = createLaunchPreflightReport(liveEnv, {
  mode: 'live',
  buildMarker: enabledBuildMarker,
  runtimeReady: () => true,
});
assert.equal(live.state, 'LIVE_CONFIGURED');
assert.equal(live.ok, true);
assert.equal(live.checks.intake_ready, true);
assert.equal(live.checks.intake_consumer_protocol_enabled, true);
assert.deepEqual(live.missing, []);
assert.deepEqual(live.invalid, []);
assert.equal(live.activation.stage, 'PUBLIC_INTAKE');
const liveBelowStage = createLaunchPreflightReport({
  ...liveEnv,
  ARC_ACTIVATION_MANIFEST: activationManifest('LIVE_CHECKOUT'),
}, {
  mode: 'live', now: preflightNow, buildMarker: enabledBuildMarker, runtimeReady: () => true,
});
assert.equal(liveBelowStage.ok, false);
assert.equal(liveBelowStage.checks.activation_manifest_stage_sufficient, false);
assert.equal(liveBelowStage.checks.intake_ready, false);
for (const name of ['ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED', 'ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED']) {
  const halfWired = createLaunchPreflightReport({ ...liveEnv, [name]: 'false' }, {
    mode: 'live', buildMarker: enabledBuildMarker, runtimeReady: () => true,
  });
  assert.equal(halfWired.ok, false, `${name}=false must block LIVE_CONFIGURED even with a stubbed runtime probe.`);
  assert.ok(halfWired.invalid.includes(name));
}
const liveWithoutCheckoutGate = createLaunchPreflightReport({
  ...liveEnv,
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'false',
}, {
  mode: 'live',
  buildMarker: enabledBuildMarker,
  runtimeReady: () => true,
});
assert.equal(liveWithoutCheckoutGate.ok, false);
assert.ok(liveWithoutCheckoutGate.invalid.includes('ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED'));

const defaultCompiledClosed = createLaunchPreflightReport(liveEnv, {
  mode: 'live',
  runtimeReady: () => true,
});
assert.equal(defaultCompiledClosed.state, 'INVALID');
assert.equal(defaultCompiledClosed.ok, false);
assert.ok(defaultCompiledClosed.invalid.includes('INTAKE_BUILD_MARKER'));

let cliOutput = '';
assert.equal(runLaunchPreflightCli({
  argv: ['--mode=safety'],
  env: {},
  write: (value) => { cliOutput += value; },
}), 0);
assert.equal(JSON.parse(cliOutput).state, 'SAFE_OFF');
assert.equal(runLaunchPreflightCli({ argv: [], env: {}, write: () => {} }), 2);
assert.equal(runLaunchPreflightCli({ argv: ['--mode=live'], env: {}, write: () => {} }), 1);
assert.equal(runLaunchPreflightCli({ argv: ['--mode=safety', '--mode=live'], env: {}, write: () => {} }), 2);

const spawned = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/launch-preflight.mjs', import.meta.url)), '--mode=sandbox'], {
  encoding: 'utf8',
  env: sandboxEnv,
});
assert.equal(spawned.status, 0, spawned.stderr);
assert.equal(spawned.stderr, '');
assert.equal(JSON.parse(spawned.stdout).state, 'SANDBOX_CONFIGURED');

for (const marker of secretMarkers) {
  assert.equal(JSON.stringify(sandbox).includes(marker), false);
  assert.equal(JSON.stringify(live).includes(marker), false);
  assert.equal(spawned.stdout.includes(marker), false);
  assert.equal(spawned.stderr.includes(marker), false);
}
for (const marker of [sandboxEnv.ARC_STRIPE_ACCOUNT_VERIFICATION_KEY, liveEnv.ARC_STRIPE_ACCOUNT_VERIFICATION_KEY]) {
  assert.equal(JSON.stringify(sandbox).includes(marker), false);
  assert.equal(JSON.stringify(live).includes(marker), false);
  assert.equal(spawned.stdout.includes(marker), false);
  assert.equal(spawned.stderr.includes(marker), false);
}

console.log('ARC launch preflight redaction contract passed.');
