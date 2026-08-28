import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  AUTOMATION_FLAG_NAMES,
  LIVE_RELEASE_BLOCKED_CONTROLS,
  createLaunchPreflightReport,
  runLaunchPreflightCli,
} from '../scripts/launch-preflight.mjs';
import {
  ACTIVATION_EVIDENCE_BY_STAGE,
  ACTIVATION_MANIFEST_SCHEMA,
  ACTIVATION_MANIFEST_VERSION,
  signActivationManifest,
} from '../netlify/lib/activation-manifest-core.mjs';
import { canonicalJson } from '../netlify/lib/arc2-handoff-core.mjs';
import { FIRST_PARTY_RETENTION_RECEIPT_SCHEMA } from '../netlify/lib/first-party-retention-core.mjs';
import {
  INTAKE_BUILD_MARKER_SCHEMA,
  INTAKE_BUILD_MARKER_VERSION,
  INTAKE_READINESS_BOOLEAN_FIELDS,
  INTAKE_READINESS_SCHEMA,
  INTAKE_READINESS_VERSION,
} from '../netlify/lib/intake-readiness-core.mjs';

const reviewActivationContract = JSON.parse(readFileSync(
  new URL('../operations/review-activation-environment.json', import.meta.url),
  'utf8',
));
assert.deepEqual(
  [...LIVE_RELEASE_BLOCKED_CONTROLS],
  reviewActivationContract.profiles.production.blocked_controls,
  'Launch preflight must use the canonical review-activation blocker set.',
);

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
  'ARC_INTAKE_CONFIRMATION_OUTBOX_SECRET',
  'ARC_INTAKE_CONFIRMATION_CONSUMER_BEARER',
  'ARC_INTAKE_CONFIRMATION_RECEIPT_SECRET',
  'ARC_INTAKE_EMAIL_VERIFICATION_STATE_SECRET',
  'ARC_INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET',
  'ARC_INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET',
  'ARC_INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET',
  'ARC_INTAKE_ABUSE_HMAC_SECRET',
  'ARC_TURNSTILE_SECRET_KEY',
  'ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET',
  'ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET',
  'ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET',
  'ARC_REVIEW_INVITE_HMAC_SECRET',
  'ARC_REVIEW_SESSION_HMAC_SECRET',
  'ARC_REVIEW_RECORD_HMAC_SECRET',
  'ARC_REVIEW_DECISION_HMAC_SECRET',
  'ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET',
  'ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET',
  'ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET',
  'ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET',
  'ARC_STRIPE_WEBHOOK_SIGNING_SECRET',
  'ARC_STRIPE_REVERSAL_HMAC_SECRET',
  'ARC_STRIPE_REVERSAL_BINDING_SECRET',
  'ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET',
  'ARC_STRIPE_REVERSAL_RECHECK_SECRET',
  'ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET',
  'ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET',
  'ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET',
  'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET',
  'ARC_FIRST_PARTY_RETENTION_HMAC_SECRET',
  'ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER',
  'ARC_OPERATIONS_AUDIT_SECRET',
  'ARC_OPERATIONS_ALERT_HMAC_SECRET',
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
const retentionCounts = Object.fromEntries([
  'intake_abuse',
  'review',
  'checkout',
  'handoff',
].map((family) => [family, {
  candidates: 0,
  deleted: 0,
  held: 0,
  inspected: 0,
  quarantined: 0,
}]));
const unsignedRetentionReceipt = {
  schema: FIRST_PARTY_RETENTION_RECEIPT_SCHEMA,
  version: 1,
  sweep_hmac_sha256: sha256('launch-preflight-first-party-retention-sweep'),
  deployment_sha: deploymentSha,
  families: ['intake_abuse', 'review', 'checkout', 'handoff'],
  started_at: new Date(preflightNow.getTime() - 120_000).toISOString(),
  completed_at: new Date(preflightNow.getTime() - 60_000).toISOString(),
  next_sweep_at: new Date(preflightNow.getTime() - 60_000 + 24 * 60 * 60_000).toISOString(),
  counts: retentionCounts,
  customer_data_stored: false,
};
const firstPartyRetentionReceipt = {
  ...unsignedRetentionReceipt,
  record_hmac_sha256: createHmac('sha256', secrets.ARC_FIRST_PARTY_RETENTION_HMAC_SECRET)
    .update(`arc-first-party-retention-completion-record-v1\n${canonicalJson(unsignedRetentionReceipt)}`)
    .digest('hex'),
};
const liveEnv = {
  ...common,
  ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED: 'true',
  ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED: 'true',
  ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED: 'true',
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
  ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED: 'true',
  ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED: 'true',
  ARC_INTAKE_CONFIRMATION_CONSUMER_ENABLED: 'true',
  ARC_INTAKE_EMAIL_VERIFICATION_ENABLED: 'true',
  ARC_INTAKE_ABUSE_PROTECTION_ENABLED: 'true',
  ARC_TURNSTILE_EXPECTED_HOSTNAME: 'arcweb.onl',
  ARC_TURNSTILE_EXPECTED_ACTION: 'arc_intake_submit',
  ARC_TURNSTILE_MAX_AGE_SECONDS: '300',
  ARC_INTAKE_ABUSE_RECIPIENT_LIMIT: '3',
  ARC_INTAKE_ABUSE_RECIPIENT_WINDOW_SECONDS: '86400',
  ARC_INTAKE_ABUSE_DOMAIN_LIMIT: '10',
  ARC_INTAKE_ABUSE_DOMAIN_WINDOW_SECONDS: '3600',
  ARC_INTAKE_ABUSE_GLOBAL_LIMIT: '100',
  ARC_INTAKE_ABUSE_GLOBAL_WINDOW_SECONDS: '3600',
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'true',
  ARC_RESEND_SEND_ENABLED: 'true',
  ARC_RESEND_WEBHOOK_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS: '30',
  ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED: 'true',
  ARC_FIRST_PARTY_RETENTION_ENABLED: 'true',
  ARC_FIRST_PARTY_RETENTION_UNPAID_DAYS: '730',
  ARC_FIRST_PARTY_RETENTION_PAID_DAYS: '2555',
  ARC_FIRST_PARTY_RETENTION_RECEIPT: JSON.stringify(firstPartyRetentionReceipt),
  ARC_OPERATIONS_AUDIT_ENABLED: 'true',
  ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
  ARC_REVIEW_EMAIL_RESEND_CAPSULE_ENABLED: 'true',
  ARC_REVIEW_EMAIL_RESEND_WORKER_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY: Buffer.alloc(32, 4).toString('base64url'),
  ARC_RESEND_API_KEY: 're_launchPreflightTransactionalKey0123456789',
  ARC_RESEND_WEBHOOK_SECRET: `whsec_${Buffer.alloc(32, 5).toString('base64')}`,
  ARC_RESEND_FROM: 'ARC <preview@send.arcweb.onl>',
  ARC_RESEND_PROVIDER_ACCOUNT_ID: 'resend-arc-launch-preflight',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
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

const newExternalDeliveryFlags = [
  'ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED',
  'ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED',
  'ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED',
  'ARC_EMAIL_RECIPIENT_VAULT_ENABLED',
  'ARC_FIRST_PARTY_RETENTION_ENABLED',
  'ARC_OPERATIONS_AUDIT_ENABLED',
  'ARC_OPERATIONS_ALERT_DELIVERY_ENABLED',
  'ARC_RESEND_SEND_ENABLED',
  'ARC_RESEND_WEBHOOK_ENABLED',
  'ARC_REVIEW_EMAIL_RESEND_CAPSULE_ENABLED',
  'ARC_REVIEW_EMAIL_RESEND_WORKER_ENABLED',
  'ARC_TRANSACTIONAL_EMAIL_ENABLED',
  'ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED',
  'ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED',
];
for (const name of newExternalDeliveryFlags) {
  assert.ok(AUTOMATION_FLAG_NAMES.includes(name), `${name} must be part of the complete safety inventory.`);
  const active = createLaunchPreflightReport({ [name]: 'true' }, { mode: 'safety' });
  assert.equal(active.ok, false, `${name}=true must independently break SAFE_OFF.`);
  assert.ok(active.enabled_flags.includes(name));
  assert.ok(active.invalid.includes(name));
}

const sandbox = createLaunchPreflightReport(sandboxEnv, { mode: 'sandbox' });
assert.equal(sandbox.state, 'SANDBOX_CONFIGURED', JSON.stringify(sandbox));
assert.equal(sandbox.ok, true);
assert.equal(sandbox.checks.sandbox_mode_exact, true);
assert.equal(sandbox.checks.live_mode_exact, false);
assert.deepEqual(sandbox.missing, []);
assert.deepEqual(sandbox.invalid, []);
assert.equal(sandbox.activation.stage, 'CLAIM_SANDBOX');
assert.equal(sandbox.checks.activation_manifest_current, true);
assert.equal(sandbox.checks.activation_manifest_deployment_bound, true);
assert.equal(sandbox.checks.retention_generation_fence_ready, true);
assert.equal(sandbox.checks.retention_generation_fence_secret_distinct, true);
const sandboxWithoutRetentionFence = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET: '',
}, { mode: 'sandbox', now: preflightNow });
assert.equal(sandboxWithoutRetentionFence.ok, false);
assert.ok(sandboxWithoutRetentionFence.missing.includes(
  'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET'));
const sandboxWithReusedRetentionFence = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET: sandboxEnv.ARC_REVIEW_SESSION_HMAC_SECRET,
}, { mode: 'sandbox', now: preflightNow });
assert.equal(sandboxWithReusedRetentionFence.ok, false);
assert.ok(sandboxWithReusedRetentionFence.invalid.includes(
  'ARC_FIRST_PARTY_RETENTION_FENCE_SECRET_SEPARATION'));
const sandboxWithMalformedRetentionFence = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET: 'too-short',
}, { mode: 'sandbox', now: preflightNow });
assert.equal(sandboxWithMalformedRetentionFence.ok, false);
assert.ok(sandboxWithMalformedRetentionFence.invalid.includes(
  'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET'));
const sandboxWithoutManifest = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_ACTIVATION_MANIFEST: '',
}, { mode: 'sandbox', now: preflightNow });
assert.equal(sandboxWithoutManifest.ok, false);
assert.ok(sandboxWithoutManifest.missing.includes('ARC_ACTIVATION_MANIFEST'));
const sandboxEmailStage = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_ACTIVATION_MANIFEST: activationManifest('EMAIL_SANDBOX'),
}, { mode: 'sandbox', now: preflightNow });
assert.equal(sandboxEmailStage.ok, true,
  'The sandbox preflight must accept EMAIL_SANDBOX so its E2E evidence can be collected before CLAIM_SANDBOX.');
const sandboxBootstrap = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_ACTIVATION_MANIFEST: activationManifest('EMAIL_SANDBOX', {
    authority_mode: 'TEST_BOOTSTRAP',
    expires_at: new Date(preflightNow.getTime() + 10 * 60_000).toISOString(),
    evidence: [],
  }),
}, { mode: 'sandbox', now: preflightNow });
assert.equal(sandboxBootstrap.ok, true);
assert.equal(sandboxBootstrap.activation.authority_mode, 'TEST_BOOTSTRAP');
const claimSandboxBootstrap = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_ACTIVATION_MANIFEST: activationManifest('CLAIM_SANDBOX', {
    authority_mode: 'TEST_BOOTSTRAP',
    expires_at: new Date(preflightNow.getTime() + 10 * 60_000).toISOString(),
    evidence: activationEvidence('EMAIL_SANDBOX'),
  }),
}, { mode: 'sandbox', now: preflightNow });
assert.equal(claimSandboxBootstrap.ok, true, JSON.stringify(claimSandboxBootstrap));
assert.equal(claimSandboxBootstrap.activation.authority_mode, 'TEST_BOOTSTRAP');
assert.equal(claimSandboxBootstrap.activation.stage, 'CLAIM_SANDBOX');
assert.equal(claimSandboxBootstrap.checks.claim_sandbox_bootstrap_active, true);
assert.equal(claimSandboxBootstrap.checks.claim_sandbox_bootstrap_ready, true);
const claimBootstrapMissingPriorEvidence = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_ACTIVATION_MANIFEST: activationManifest('CLAIM_SANDBOX', {
    authority_mode: 'TEST_BOOTSTRAP',
    expires_at: new Date(preflightNow.getTime() + 10 * 60_000).toISOString(),
    evidence: [],
  }),
}, { mode: 'sandbox', now: preflightNow });
assert.equal(claimBootstrapMissingPriorEvidence.ok, false);
assert.ok(claimBootstrapMissingPriorEvidence.invalid.includes('ARC_ACTIVATION_MANIFEST'));
const partialEmailSandbox = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_ACTIVATION_MANIFEST: activationManifest('EMAIL_SANDBOX', {
    authority_mode: 'TEST_BOOTSTRAP',
    expires_at: new Date(preflightNow.getTime() + 10 * 60_000).toISOString(),
    evidence: [],
  }),
  ARC_RESEND_SEND_ENABLED: 'true',
}, { mode: 'sandbox', now: preflightNow });
assert.equal(partialEmailSandbox.ok, false);
assert.ok(partialEmailSandbox.invalid.includes('TRANSACTIONAL_EMAIL_RUNTIME_CONFIGURATION'));
const alertSandbox = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_OPERATIONS_ALERT_DELIVERY_ENABLED: 'true',
}, { mode: 'sandbox', now: preflightNow });
assert.equal(alertSandbox.ok, false,
  'Operations alert delivery remains forbidden until its native delivery evidence is complete.');
assert.ok(alertSandbox.invalid.includes('ARC_OPERATIONS_ALERT_DELIVERY_ENABLED'));
const sandboxBelowStage = createLaunchPreflightReport({
  ...sandboxEnv,
  ARC_ACTIVATION_MANIFEST: activationManifest('OFF'),
}, { mode: 'sandbox', now: preflightNow });
assert.equal(sandboxBelowStage.ok, false);
assert.equal(sandboxBelowStage.checks.activation_manifest_stage_sufficient, false);

const live = createLaunchPreflightReport(liveEnv, {
  mode: 'live',
  buildMarker: enabledBuildMarker,
  runtimeReady: () => true,
});
assert.equal(live.state, 'LIVE_BLOCKED', JSON.stringify(live));
assert.equal(live.ok, false, JSON.stringify(live));
assert.equal(live.checks.intake_ready, true);
assert.equal(live.checks.intake_consumer_protocol_enabled, true);
assert.equal(live.checks.intake_recovery_automation_enabled, true);
assert.equal(live.checks.intake_confirmation_protocol_enabled, true);
assert.equal(live.checks.intake_email_verification_runtime_ready, true);
assert.equal(live.checks.first_party_retention_runtime_ready, true);
assert.equal(live.checks.first_party_retention_alert_queue_ready, true);
assert.equal(live.checks.first_party_retention_receipt_current, true);
assert.equal(live.checks.first_party_retention_ready, true);
assert.equal(live.checks.first_party_retention_legal_hold_writer_ready, true);
assert.equal(live.checks.retention_generation_fence_ready, true);
assert.deepEqual(live.missing, []);
assert.deepEqual(live.invalid, []);
assert.deepEqual(live.blocked, [...LIVE_RELEASE_BLOCKED_CONTROLS]);
assert.ok(live.blocked.includes('LIVE_PROVIDER_E2E_EVIDENCE'),
  'A locally complete configuration must not claim live readiness before provider E2E evidence exists.');
const liveWithoutRetentionAlertQueue = createLaunchPreflightReport({
  ...liveEnv,
  ARC_OPERATIONS_AUDIT_ENABLED: 'false',
}, {
  mode: 'live', now: preflightNow, buildMarker: enabledBuildMarker, runtimeReady: () => true,
});
assert.equal(liveWithoutRetentionAlertQueue.checks.first_party_retention_alert_queue_ready, false);
assert.ok(liveWithoutRetentionAlertQueue.invalid.includes(
  'FIRST_PARTY_RETENTION_ALERT_QUEUE_CONFIGURATION'));
assert.equal(live.activation.stage, 'PUBLIC_INTAKE');
const liveWithoutFirstPartyRetentionReceipt = createLaunchPreflightReport({
  ...liveEnv,
  ARC_FIRST_PARTY_RETENTION_RECEIPT: '',
}, {
  mode: 'live', now: preflightNow, buildMarker: enabledBuildMarker, runtimeReady: () => true,
});
assert.equal(liveWithoutFirstPartyRetentionReceipt.ok, false);
assert.equal(liveWithoutFirstPartyRetentionReceipt.checks.first_party_retention_receipt_current, false);
assert.equal(liveWithoutFirstPartyRetentionReceipt.checks.first_party_retention_ready, false);
assert.ok(liveWithoutFirstPartyRetentionReceipt.invalid.includes('ARC_FIRST_PARTY_RETENTION_RECEIPT'));
const liveWithoutLegalHoldBearer = createLaunchPreflightReport({
  ...liveEnv,
  ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER: '',
}, {
  mode: 'live', now: preflightNow, buildMarker: enabledBuildMarker, runtimeReady: () => true,
});
assert.equal(liveWithoutLegalHoldBearer.ok, false);
assert.equal(liveWithoutLegalHoldBearer.checks.first_party_retention_legal_hold_writer_ready, false);
assert.ok(liveWithoutLegalHoldBearer.missing.includes(
  'ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER'));
const staleFirstPartyRetentionReceipt = {
  ...unsignedRetentionReceipt,
  started_at: new Date(preflightNow.getTime() - 48 * 60 * 60_000).toISOString(),
  completed_at: new Date(preflightNow.getTime() - 47 * 60 * 60_000).toISOString(),
  next_sweep_at: new Date(preflightNow.getTime() - 23 * 60 * 60_000).toISOString(),
};
const signedStaleFirstPartyRetentionReceipt = {
  ...staleFirstPartyRetentionReceipt,
  record_hmac_sha256: createHmac('sha256', secrets.ARC_FIRST_PARTY_RETENTION_HMAC_SECRET)
    .update(`arc-first-party-retention-completion-record-v1\n${canonicalJson(staleFirstPartyRetentionReceipt)}`)
    .digest('hex'),
};
const liveWithStaleFirstPartyRetentionReceipt = createLaunchPreflightReport({
  ...liveEnv,
  ARC_FIRST_PARTY_RETENTION_RECEIPT: JSON.stringify(signedStaleFirstPartyRetentionReceipt),
}, {
  mode: 'live', now: preflightNow, buildMarker: enabledBuildMarker, runtimeReady: () => true,
});
assert.equal(liveWithStaleFirstPartyRetentionReceipt.ok, false);
assert.equal(liveWithStaleFirstPartyRetentionReceipt.checks.first_party_retention_receipt_current, false);
assert.ok(liveWithStaleFirstPartyRetentionReceipt.invalid.includes('ARC_FIRST_PARTY_RETENTION_RECEIPT'));
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
for (const name of ['ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED', 'ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED',
  'ARC_INTAKE_CONFIRMATION_CONSUMER_ENABLED', 'ARC_INTAKE_EMAIL_VERIFICATION_ENABLED']) {
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
let liveCliOutput = '';
assert.equal(runLaunchPreflightCli({
  argv: ['--mode=live'], env: liveEnv, now: preflightNow, buildMarker: enabledBuildMarker,
  runtimeReady: () => true, write: (value) => { liveCliOutput += value; },
}), 1);
assert.equal(JSON.parse(liveCliOutput).state, 'LIVE_BLOCKED');
assert.ok(JSON.parse(liveCliOutput).blocked.includes('LIVE_PROVIDER_E2E_EVIDENCE'));

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
