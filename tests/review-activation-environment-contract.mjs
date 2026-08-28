import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import {
  ACTIVATION_EVIDENCE_BY_STAGE,
  ACTIVATION_MANIFEST_SCHEMA,
  ACTIVATION_MANIFEST_VERSION,
  signActivationManifest,
} from '../netlify/lib/activation-manifest-core.mjs';
import {
  canonicalReviewActivationRuntimeJson,
  reviewActivationRuntimeAuthorityBinding,
} from '../netlify/lib/review-activation-runtime-readback-core.mjs';

import {
  REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT as contract,
  createReviewActivationEnvironmentReport,
  reviewActivationEnvironmentNamesSha256,
  reviewActivationRouteMatrixSha256,
  reviewActivationStripeWebhookEventSetSha256,
  runReviewActivationPreflightCli,
} from '../scripts/review-activation-preflight.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const now = new Date('2026-08-27T12:00:00.000Z');
const digest = (label) => sha256(`review-activation-contract:${label}`);
const runtimeVerifierPublicKey = generateKeyPairSync('ed25519').publicKey
  .export({ format: 'der', type: 'spki' }).toString('base64');

function firstPartyRetentionReceipt(env) {
  const fields = ['candidates', 'deleted', 'held', 'inspected', 'quarantined'];
  const families = ['intake_abuse', 'review', 'checkout', 'handoff'];
  const unsigned = {
    schema: 'arc-first-party-retention-completion-v1',
    version: 1,
    sweep_hmac_sha256: digest('first-party-retention-sweep'),
    deployment_sha: '9'.repeat(40),
    families,
    started_at: new Date(now.getTime() - 5 * 60_000).toISOString(),
    completed_at: new Date(now.getTime() - 60_000).toISOString(),
    next_sweep_at: new Date(now.getTime() - 60_000 + 24 * 60 * 60_000).toISOString(),
    counts: Object.fromEntries(families.map((family) => [family,
      Object.fromEntries(fields.map((field) => [field, 0]))])),
    customer_data_stored: false,
  };
  return JSON.stringify({
    ...unsigned,
    record_hmac_sha256: createHmac('sha256', env.ARC_FIRST_PARTY_RETENTION_HMAC_SECRET)
      .update(`arc-first-party-retention-completion-record-v1\n${canonicalReviewActivationRuntimeJson(unsigned)}`)
      .digest('hex'),
  });
}

assert.equal(contract.schema, 'arc-review-activation-environment-v1');
assert.equal(contract.version, 1);
assert.equal(contract.default_state, 'OFF');
assert.deepEqual(contract.activation_order, [
  'OFF', 'EMAIL_SANDBOX', 'CLAIM_SANDBOX', 'LIVE_CHECKOUT', 'PUBLIC_INTAKE', 'PILOT', 'OUTREACH',
]);
assert.equal(new Set(contract.activation_flags).size, contract.activation_flags.length);
for (const mode of ['sandbox', 'production']) {
  assert.deepEqual([...Object.keys(contract.profiles[mode].flags)].sort(),
    [...contract.activation_flags, 'ARC_RUNTIME_ENVIRONMENT'].sort());
}

const secretNames = contract.secrets.map(({ name }) => name);
assert.equal(new Set(secretNames).size, secretNames.length);
for (const secret of contract.secrets) {
  assert.deepEqual(Object.keys(secret).sort(),
    secret.modes ? ['authority', 'consumers', 'modes', 'name'] : ['authority', 'consumers', 'name']);
  assert.match(secret.name, /(?:SECRET|KEY|BEARER)$/);
  assert.equal(typeof secret.authority, 'string');
  assert.ok(Array.isArray(secret.consumers) && secret.consumers.length > 0);
}
assert.deepEqual(contract.secret_alias_groups, [{
  canonical: 'NETLIFY_ADMIN_PAT',
  aliases: ['NETLIFY_ACCESS_TOKEN'],
  policy: 'exactly_one',
  authority: 'netlify',
  consumers: ['netlify_handoff'],
}]);
assert.equal(JSON.stringify(contract.secrets).includes('"value"'), false,
  'The committed secret ownership contract must contain names only, never values.');
const retentionFenceSecret = contract.secrets.find(({ name }) =>
  name === 'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET');
assert.ok(retentionFenceSecret, 'The always-on global fence secret must be authoritative inventory.');
assert.equal(retentionFenceSecret.modes, undefined,
  'Sandbox and production mutators must both require the global fence secret.');
assert.deepEqual(new Set(retentionFenceSecret.consumers), new Set([
  'netlify_intake_submit', 'netlify_review_exchange', 'netlify_review_email_prepare',
  'netlify_review_email_reserve',
  'netlify_review_email_ack', 'netlify_review_decision', 'netlify_review_revision_claim',
  'netlify_review_revision_complete', 'netlify_review_checkout',
  'netlify_stripe_unified_webhook', 'netlify_stripe_reversal_binding',
  'netlify_stripe_reversal_recheck', 'netlify_payment_arc2_worker',
  'netlify_arc2_handoff_start', 'netlify_arc2_claim', 'netlify_arc2_claim_webhook',
  'netlify_arc2_claim_invitation_ready', 'netlify_arc2_claim_invitation_renew',
  'netlify_arc2_claim_link_renew', 'netlify_arc2_final_delivery_ack',
  'netlify_resend_webhook', 'netlify_transactional_email_worker',
  'netlify_operations_audit', 'netlify_operations_alert_reserve',
  'netlify_operations_alert_ack', 'netlify_legal_hold_writer',
  'netlify_first_party_retention_worker',
]));
const legalHoldBearer = contract.secrets.find(({ name }) =>
  name === 'ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER');
assert.deepEqual(legalHoldBearer, {
  name: 'ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER',
  authority: 'netlify_runtime',
  consumers: ['netlify_legal_hold_writer'],
  modes: ['production'],
});

const baseBindings = {
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_EXPECTED_PRICE_ID: 'price_arcReviewContract123456',
  ARC_EXPECTED_PRODUCT_ID: 'prod_arcReviewContract123456',
  ARC_EXPECTED_PRODUCT_NAME: 'ARC Fixed Five-Page Website',
  ARC_EXPECTED_PRODUCT_TAX_CODE: 'txcd_10000000',
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256: digest('stripe-account'),
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
  ARC_REVIEW_EMAIL_NATIVE_SUPPRESSION_ID_SHA256: digest('native-suppression-id'),
  ARC_REVIEW_EMAIL_NATIVE_WEBHOOK_ID_SHA256: digest('native-webhook-id'),
  ARC_REVIEW_EMAIL_PROVIDER: 'resend',
  ARC_REVIEW_EMAIL_PROVIDER_ACCOUNT_ID_SHA256: digest('email-provider-account'),
  ARC_REVIEW_EMAIL_SENDER_IDENTITY_SHA256: digest('email-sender'),
  ARC_RESEND_FROM: 'ARC <preview@send.arcweb.onl>',
  ARC_RESEND_PROVIDER_ACCOUNT_ID: 'resend-arc-production',
  ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS: '30',
  NETLIFY_ADMIN_PAT: 'netlify-admin-pat-review-contract-0123456789abcdef',
  ARC_STRIPE_CHECKOUT_CANCEL_URL: 'https://arcweb.onl/review/?checkout=cancelled',
  ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER: 'arc_review_checkout_qwertyui',
  ARC_STRIPE_CHECKOUT_OFFER_ID: 'arc-fixed-five-page-offer-v1',
  ARC_STRIPE_CHECKOUT_SUCCESS_URL:
    'https://arcweb.onl/payment-success/?session_id={CHECKOUT_SESSION_ID}',
  ARC_STRIPE_CHECKOUT_TERMS_VERSION: '2026-08-25',
  ARC_STRIPE_WEBHOOK_API_VERSION: '2026-07-29.dahlia',
  ARC_ZAPIER_PAYMENT_ARC2_WORKFLOW_ID_SHA256: digest('zapier-payment-workflow'),
  ARC_ZAPIER_REVIEW_CHECKOUT_REVOCATION_WORKFLOW_ID_SHA256: digest('zapier-revocation-workflow'),
  ARC_ZAPIER_REVIEW_EMAIL_WORKFLOW_ID_SHA256: digest('zapier-email-workflow'),
  ARC_ZAPIER_REVIEW_REVISION_WORKFLOW_ID_SHA256: digest('zapier-revision-workflow'),
  URL: 'https://arcweb.onl',
};

function secretEnvironment(mode) {
  const names = contract.secrets.filter((entry) => !entry.modes || entry.modes.includes(mode))
    .map(({ name }) => name);
  const values = Object.fromEntries(names.map((name, index) => [
    name,
    `review-activation-secret-${String(index).padStart(2, '0')}-abcdefghijklmnopqrstuvwxyz`,
  ]));
  values.ARC_STRIPE_REVIEW_SECRET_KEY = `sk_${mode === 'sandbox' ? 'test' : 'live'}_` +
    'reviewActivationCheckoutKey0123456789';
  values.ARC_STRIPE_ACCOUNT_VERIFICATION_KEY = `rk_${mode === 'sandbox' ? 'test' : 'live'}_` +
    'reviewActivationAccountKey0123456789';
  values.ARC_STRIPE_WEBHOOK_SIGNING_SECRET =
    'whsec_reviewActivationWebhookSecret0123456789';
  values.ARC_RESEND_API_KEY = 're_reviewActivationTransactionalKey0123456789';
  values.ARC_RESEND_WEBHOOK_SECRET = `whsec_${Buffer.alloc(32, 7).toString('base64')}`;
  values.ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY = Buffer.alloc(32, 9).toString('base64url');
  return values;
}

function activationManifest(mode, env, {
  bootstrap = mode === 'sandbox',
  bootstrapStage = 'EMAIL_SANDBOX',
  liveCheckoutReadbackSha256 = null,
} = {}) {
  const stage = mode === 'sandbox' ? (bootstrap ? bootstrapStage : 'EMAIL_SANDBOX') : 'LIVE_CHECKOUT';
  return signActivationManifest({
    schema: ACTIVATION_MANIFEST_SCHEMA,
    version: ACTIVATION_MANIFEST_VERSION,
    stage,
    authority_mode: bootstrap ? 'TEST_BOOTSTRAP' : 'ROLLOUT',
    issued_at: new Date(now.getTime() - 60_000).toISOString(),
    expires_at: new Date(now.getTime() + (bootstrap ? 10 : 60) * 60_000).toISOString(),
    deployment_sha: '9'.repeat(40),
    evidence: bootstrap
      ? (stage === 'CLAIM_SANDBOX' ? ACTIVATION_EVIDENCE_BY_STAGE.EMAIL_SANDBOX : []).map((kind) => ({
        kind,
        receipt_ref: `audit:${digest(`activation-receipt:${kind}`).slice(0, 24)}`,
        sha256: digest(`activation-evidence:${kind}`),
      }))
      : ACTIVATION_EVIDENCE_BY_STAGE[stage].map((kind) => ({
      kind,
      receipt_ref: `audit:${digest(`activation-receipt:${kind}`).slice(0, 24)}`,
      sha256: kind === 'live_checkout_readback' && liveCheckoutReadbackSha256
        ? liveCheckoutReadbackSha256 : digest(`activation-evidence:${kind}`),
    })),
  }, env.ARC_ACTIVATION_MANIFEST_HMAC_SECRET);
}

function readback(mode, env, overrides = {}) {
  const profile = contract.profiles[mode];
  return {
    schema: contract.readback.schema,
    version: 1,
    mode,
    minimum_stage: profile.minimum_stage,
    provider_controls_state: 'OFF',
    observed_at: new Date(now.getTime() - 60_000).toISOString(),
    expires_at: new Date(now.getTime() + 10 * 60_000).toISOString(),
    netlify: {
      deployment_sha: 'a'.repeat(40),
      env_name_set_readback_sha256: reviewActivationEnvironmentNamesSha256(mode, env),
      handoff_credential_environment_name: env.NETLIFY_ADMIN_PAT
        ? 'NETLIFY_ADMIN_PAT' : 'NETLIFY_ACCESS_TOKEN',
      route_matrix_readback_sha256: reviewActivationRouteMatrixSha256(),
      route_probe_receipt_sha256: digest(`${mode}:netlify-route-probe`),
      site_id_sha256: sha256(env.ARC_EXPECTED_NETLIFY_SITE_ID),
    },
    stripe: {
      account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
      catalog_readback_sha256: digest(`${mode}:stripe-catalog`),
      checkout_session_expire_capability_readback_sha256: digest(`${mode}:stripe-expire-capability`),
      checkout_session_retrieve_capability_readback_sha256: digest(`${mode}:stripe-retrieve-capability`),
      integration_identifier_sha256: sha256(env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER),
      price_id_sha256: sha256(env.ARC_EXPECTED_PRICE_ID),
      product_id_sha256: sha256(env.ARC_EXPECTED_PRODUCT_ID),
      webhook_destination_readback_sha256: digest(`${mode}:stripe-webhook`),
      webhook_endpoint_path: contract.stripe_webhook.endpoint_path,
      webhook_event_set_readback_sha256: reviewActivationStripeWebhookEventSetSha256(),
    },
    email: {
      native_suppression_id_sha256: env.ARC_REVIEW_EMAIL_NATIVE_SUPPRESSION_ID_SHA256,
      native_suppression_readback_sha256: digest(`${mode}:email-suppression-readback`),
      native_webhook_id_sha256: env.ARC_REVIEW_EMAIL_NATIVE_WEBHOOK_ID_SHA256,
      native_webhook_readback_sha256: digest(`${mode}:email-webhook-readback`),
      provider: env.ARC_REVIEW_EMAIL_PROVIDER,
      provider_account_id_sha256: env.ARC_REVIEW_EMAIL_PROVIDER_ACCOUNT_ID_SHA256,
      sandbox_delivery_receipt_sha256: digest(`${mode}:email-sandbox-delivery`),
      sender_identity_sha256: env.ARC_REVIEW_EMAIL_SENDER_IDENTITY_SHA256,
    },
    operations_alert: {
      audit_enabled: contract.profiles[mode].flags.ARC_OPERATIONS_AUDIT_ENABLED === 'true',
      delivery_enabled: false,
      failure_alert_verified: false,
      native_delivery_receipt_sha256: '0'.repeat(64),
      provider_event_type: 'email.delivered',
    },
    zapier: {
      checkout_revocation_worker_contract_receipt_sha256: digest(`${mode}:zapier-revocation-contract`),
      checkout_revocation_workflow_id_sha256:
        env.ARC_ZAPIER_REVIEW_CHECKOUT_REVOCATION_WORKFLOW_ID_SHA256,
      checkout_revocation_workflow_version_readback_sha256:
        digest(`${mode}:zapier-revocation-version`),
      claim_next_contract_receipt_sha256: digest(`${mode}:zapier-claim-next`),
      email_claim_next_path: '/api/internal/review-email/reserve',
      email_workflow_id_sha256: env.ARC_ZAPIER_REVIEW_EMAIL_WORKFLOW_ID_SHA256,
      email_workflow_version_readback_sha256: digest(`${mode}:zapier-email-version`),
      payment_arc2_claim_next_path: '/internal/payment-arc2/claim',
      payment_arc2_start_path: '/internal/payment-arc2/start',
      payment_arc2_start_contract_receipt_sha256: digest(`${mode}:payment-start-contract`),
      payment_arc2_workflow_id_sha256: env.ARC_ZAPIER_PAYMENT_ARC2_WORKFLOW_ID_SHA256,
      payment_arc2_workflow_version_readback_sha256: digest(`${mode}:zapier-payment-version`),
      revision_claim_next_path: '/api/internal/review-revision/claim',
      revision_workflow_id_sha256: env.ARC_ZAPIER_REVIEW_REVISION_WORKFLOW_ID_SHA256,
      revision_workflow_version_readback_sha256: digest(`${mode}:zapier-revision-version`),
    },
    ...overrides,
  };
}

function environment(mode, {
  bootstrap = mode === 'sandbox',
  bootstrapStage = 'EMAIL_SANDBOX',
} = {}) {
  const env = {
    ...baseBindings,
    ...contract.profiles[mode].flags,
    ...secretEnvironment(mode),
  };
  if (mode === 'sandbox' && bootstrap && bootstrapStage === 'CLAIM_SANDBOX') Object.assign(env, {
    ARC_PUBLIC_ORIGIN: 'https://arcweb.onl/',
    SITE_ID: env.ARC_EXPECTED_NETLIFY_SITE_ID,
    SITE_NAME: 'arc2-sandbox',
    URL: 'https://arcweb.onl',
  });
  if (mode === 'production') Object.assign(env, {
    ARC_FIRST_PARTY_RETENTION_UNPAID_DAYS: '730',
    ARC_FIRST_PARTY_RETENTION_PAID_DAYS: '2555',
    ARC_OPERATIONS_ALERT_RECIPIENT_EMAIL: 'arcwebhq@gmail.com',
    ARC_OPERATIONS_ALERT_EMAIL_PROVIDER: 'resend',
    ARC_OPERATIONS_ALERT_SENDER: 'alerts@send.arcweb.onl',
    ARC_REVIEW_ACTIVATION_VERIFIER_URL: 'https://verifier.arcweb.onl/readback',
    ARC_REVIEW_ACTIVATION_VERIFIER_ED25519_PUBLIC_KEY: runtimeVerifierPublicKey,
  });
  if (mode === 'production') {
    env.ARC_FIRST_PARTY_RETENTION_RECEIPT = firstPartyRetentionReceipt(env);
  }
  const runtimeAuthority = mode === 'production'
    ? reviewActivationRuntimeAuthorityBinding(env) : null;
  const runtimeAuthoritySha256 = runtimeAuthority
    ? sha256(canonicalReviewActivationRuntimeJson(runtimeAuthority)) : null;
  env.ARC_ACTIVATION_MANIFEST = activationManifest(mode, env, {
    bootstrap,
    bootstrapStage,
    liveCheckoutReadbackSha256: runtimeAuthoritySha256,
  });
  env.ARC_REVIEW_ACTIVATION_READBACK_JSON = JSON.stringify(readback(mode, env));
  return env;
}

const safe = createReviewActivationEnvironmentReport({}, { mode: 'off', now });
assert.equal(safe.ok, true);
assert.equal(safe.state, 'SAFE_OFF');
assert.deepEqual(safe.enabled_flags, []);

const leakMarker = 'DO_NOT_LEAK_REVIEW_ACTIVATION_SECRET_abcdefghijklmnopqrstuvwxyz';
const unexpectedlyEnabled = createReviewActivationEnvironmentReport({
  ARC_REVIEW_PORTAL_ENABLED: 'true',
  ARC_REVIEW_INVITE_HMAC_SECRET: leakMarker,
}, { mode: 'off', now });
assert.equal(unexpectedlyEnabled.ok, false);
assert.equal(unexpectedlyEnabled.state, 'INVALID');
assert.ok(unexpectedlyEnabled.invalid.includes('ARC_REVIEW_PORTAL_ENABLED'));
assert.equal(JSON.stringify(unexpectedlyEnabled).includes(leakMarker), false);

const sandboxEnv = environment('sandbox');
const sandbox = createReviewActivationEnvironmentReport(sandboxEnv, { mode: 'sandbox', now });
assert.equal(sandbox.ok, true, JSON.stringify(sandbox));
assert.equal(sandbox.state, 'SANDBOX_CONFIGURED');
assert.deepEqual(sandbox.missing, []);
assert.deepEqual(sandbox.invalid, []);
assert.deepEqual(sandbox.blocked, []);
assert.equal(sandbox.checks.external_controls_off, true);
assert.equal(sandbox.checks.provider_readback_current, true);
assert.equal(sandbox.checks.static_readback_reference_valid, true);
assert.equal(sandbox.checks.test_bootstrap_authority, true);
assert.equal(sandbox.checks.retention_generation_fence_ready, true);
assert.equal(contract.profiles.sandbox.flags.ARC_STRIPE_REVIEW_REVOCATION_ENABLED, 'true');
assert.ok(secretNames.includes('ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET'));

const claimBootstrapEnv = environment('sandbox', { bootstrapStage: 'CLAIM_SANDBOX' });
const claimBootstrap = createReviewActivationEnvironmentReport(
  claimBootstrapEnv,
  { mode: 'sandbox', now },
);
assert.equal(claimBootstrap.ok, true, JSON.stringify(claimBootstrap));
assert.equal(claimBootstrap.checks.test_bootstrap_authority, true);
assert.equal(claimBootstrap.checks.test_bootstrap_delivery_receipt_exempted, false);
assert.equal(claimBootstrap.checks.claim_sandbox_bootstrap_authority, true);
assert.equal(claimBootstrap.checks.claim_sandbox_bootstrap_ready, true);
const claimBootstrapWithoutEmailEvidence = environment('sandbox', {
  bootstrapStage: 'CLAIM_SANDBOX',
});
const claimBootstrapReadback = JSON.parse(
  claimBootstrapWithoutEmailEvidence.ARC_REVIEW_ACTIVATION_READBACK_JSON,
);
claimBootstrapReadback.email.sandbox_delivery_receipt_sha256 = '0'.repeat(64);
claimBootstrapWithoutEmailEvidence.ARC_REVIEW_ACTIVATION_READBACK_JSON =
  JSON.stringify(claimBootstrapReadback);
const claimBootstrapWithoutEmailReport = createReviewActivationEnvironmentReport(
  claimBootstrapWithoutEmailEvidence,
  { mode: 'sandbox', now },
);
assert.ok(claimBootstrapWithoutEmailReport.invalid.includes(
  'ARC_REVIEW_ACTIVATION_READBACK_JSON:email.sandbox_delivery_receipt_sha256',
), 'Claim bootstrap must retain the completed email-provider evidence.');
assert.equal(sandbox.checks.netlify_handoff_credential_exactly_one, true);

const missingRetentionFenceEnv = environment('sandbox');
delete missingRetentionFenceEnv.ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET;
const missingRetentionFence = createReviewActivationEnvironmentReport(
  missingRetentionFenceEnv, { mode: 'sandbox', now },
);
assert.ok(missingRetentionFence.missing.includes(
  'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET'));
assert.ok(missingRetentionFence.invalid.includes('RETENTION_GENERATION_FENCE_CONFIGURATION'));

const reusedRetentionFenceEnv = environment('sandbox');
reusedRetentionFenceEnv.ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET =
  reusedRetentionFenceEnv.ARC_REVIEW_SESSION_HMAC_SECRET;
const reusedRetentionFence = createReviewActivationEnvironmentReport(
  reusedRetentionFenceEnv, { mode: 'sandbox', now },
);
assert.ok(reusedRetentionFence.invalid.includes('SECRET_DISTINCTNESS'));
assert.equal(reusedRetentionFence.checks.retention_generation_fence_ready, false);

const oversizedRetentionFenceEnv = environment('sandbox');
oversizedRetentionFenceEnv.ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET = 'é'.repeat(300);
const oversizedRetentionFence = createReviewActivationEnvironmentReport(
  oversizedRetentionFenceEnv, { mode: 'sandbox', now },
);
assert.ok(oversizedRetentionFence.invalid.includes(
  'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET'));
assert.ok(oversizedRetentionFence.invalid.includes('RETENTION_GENERATION_FENCE_CONFIGURATION'));

const retiredTaxAliasEnv = environment('sandbox');
retiredTaxAliasEnv.ARC_EXPECTED_STRIPE_PRODUCT_TAX_CODE =
  retiredTaxAliasEnv.ARC_EXPECTED_PRODUCT_TAX_CODE;
const retiredTaxAlias = createReviewActivationEnvironmentReport(
  retiredTaxAliasEnv, { mode: 'sandbox', now },
);
assert.ok(retiredTaxAlias.invalid.includes('ARC_EXPECTED_STRIPE_PRODUCT_TAX_CODE'));

const duplicateNetlifyCredentialEnv = environment('sandbox');
duplicateNetlifyCredentialEnv.NETLIFY_ACCESS_TOKEN = duplicateNetlifyCredentialEnv.NETLIFY_ADMIN_PAT;
const duplicateNetlifyCredential = createReviewActivationEnvironmentReport(
  duplicateNetlifyCredentialEnv, { mode: 'sandbox', now },
);
assert.ok(duplicateNetlifyCredential.invalid.includes(
  'NETLIFY_ADMIN_PAT|NETLIFY_ACCESS_TOKEN:EXACTLY_ONE',
));

const aliasOnlyNetlifyCredentialEnv = environment('sandbox');
aliasOnlyNetlifyCredentialEnv.NETLIFY_ACCESS_TOKEN = aliasOnlyNetlifyCredentialEnv.NETLIFY_ADMIN_PAT;
delete aliasOnlyNetlifyCredentialEnv.NETLIFY_ADMIN_PAT;
aliasOnlyNetlifyCredentialEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON = JSON.stringify(
  readback('sandbox', aliasOnlyNetlifyCredentialEnv),
);
const aliasOnlyNetlifyCredential = createReviewActivationEnvironmentReport(
  aliasOnlyNetlifyCredentialEnv, { mode: 'sandbox', now },
);
assert.equal(aliasOnlyNetlifyCredential.ok, true, JSON.stringify(aliasOnlyNetlifyCredential));

const inventedFailureAlertEvidenceEnv = environment('sandbox');
const inventedFailureAlertEvidenceReadback = JSON.parse(
  inventedFailureAlertEvidenceEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON,
);
inventedFailureAlertEvidenceReadback.operations_alert.failure_alert_verified = true;
inventedFailureAlertEvidenceReadback.operations_alert.native_delivery_receipt_sha256 =
  digest('invented-operations-alert-proof');
inventedFailureAlertEvidenceEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON =
  JSON.stringify(inventedFailureAlertEvidenceReadback);
const inventedFailureAlertEvidence = createReviewActivationEnvironmentReport(
  inventedFailureAlertEvidenceEnv, { mode: 'sandbox', now },
);
assert.ok(inventedFailureAlertEvidence.invalid.includes(
  'ARC_REVIEW_ACTIVATION_READBACK_JSON:BINDINGS',
));

const bootstrapBeforeDeliveryEnv = environment('sandbox');
const bootstrapBeforeDeliveryReadback = JSON.parse(
  bootstrapBeforeDeliveryEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON,
);
bootstrapBeforeDeliveryReadback.email.sandbox_delivery_receipt_sha256 = '0'.repeat(64);
bootstrapBeforeDeliveryEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON =
  JSON.stringify(bootstrapBeforeDeliveryReadback);
const bootstrapBeforeDelivery = createReviewActivationEnvironmentReport(
  bootstrapBeforeDeliveryEnv, { mode: 'sandbox', now },
);
assert.equal(bootstrapBeforeDelivery.ok, true, JSON.stringify(bootstrapBeforeDelivery));
assert.equal(bootstrapBeforeDelivery.checks.test_bootstrap_delivery_receipt_exempted, true);

for (const [field, expectedInvalid] of [
  ['provider_account_id_sha256', 'ARC_REVIEW_ACTIVATION_READBACK_JSON:BINDINGS'],
  ['native_webhook_readback_sha256',
    'ARC_REVIEW_ACTIVATION_READBACK_JSON:email.native_webhook_readback_sha256'],
  ['native_suppression_readback_sha256',
    'ARC_REVIEW_ACTIVATION_READBACK_JSON:email.native_suppression_readback_sha256'],
]) {
  const missingProviderEvidenceEnv = environment('sandbox');
  const missingProviderEvidence = JSON.parse(
    missingProviderEvidenceEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON,
  );
  missingProviderEvidence.email.sandbox_delivery_receipt_sha256 = '0'.repeat(64);
  missingProviderEvidence.email[field] = '0'.repeat(64);
  missingProviderEvidenceEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON =
    JSON.stringify(missingProviderEvidence);
  const missingProviderEvidenceReport = createReviewActivationEnvironmentReport(
    missingProviderEvidenceEnv, { mode: 'sandbox', now },
  );
  assert.ok(missingProviderEvidenceReport.invalid.includes(expectedInvalid),
    `${field} must remain mandatory under TEST_BOOTSTRAP.`);
}

const malformedBootstrapDeliveryEnv = environment('sandbox');
const malformedBootstrapDeliveryReadback = JSON.parse(
  malformedBootstrapDeliveryEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON,
);
malformedBootstrapDeliveryReadback.email.sandbox_delivery_receipt_sha256 = 'not-a-sha256';
malformedBootstrapDeliveryEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON =
  JSON.stringify(malformedBootstrapDeliveryReadback);
const malformedBootstrapDelivery = createReviewActivationEnvironmentReport(
  malformedBootstrapDeliveryEnv, { mode: 'sandbox', now },
);
assert.ok(malformedBootstrapDelivery.invalid.includes(
  'ARC_REVIEW_ACTIVATION_READBACK_JSON:email.sandbox_delivery_receipt_sha256',
));

const rolloutBeforeDeliveryEnv = environment('sandbox', { bootstrap: false });
const rolloutBeforeDeliveryReadback = JSON.parse(
  rolloutBeforeDeliveryEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON,
);
rolloutBeforeDeliveryReadback.email.sandbox_delivery_receipt_sha256 = '0'.repeat(64);
rolloutBeforeDeliveryEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON =
  JSON.stringify(rolloutBeforeDeliveryReadback);
const rolloutBeforeDelivery = createReviewActivationEnvironmentReport(
  rolloutBeforeDeliveryEnv, { mode: 'sandbox', now },
);
assert.equal(rolloutBeforeDelivery.checks.test_bootstrap_authority, false);
assert.ok(rolloutBeforeDelivery.invalid.includes(
  'ARC_REVIEW_ACTIVATION_READBACK_JSON:email.sandbox_delivery_receipt_sha256',
));

const missingExpireCapabilityEnv = environment('sandbox');
const missingExpireCapability = JSON.parse(missingExpireCapabilityEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON);
missingExpireCapability.stripe.checkout_session_expire_capability_readback_sha256 = '0'.repeat(64);
missingExpireCapabilityEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON = JSON.stringify(missingExpireCapability);
const missingExpireCapabilityReport = createReviewActivationEnvironmentReport(
  missingExpireCapabilityEnv, { mode: 'sandbox', now },
);
assert.ok(missingExpireCapabilityReport.invalid.includes(
  'ARC_REVIEW_ACTIVATION_READBACK_JSON:stripe.checkout_session_expire_capability_readback_sha256',
));

assert.deepEqual(new Set(contract.stripe_webhook.events), new Set([
  'checkout.session.completed',
  'checkout.session.async_payment_succeeded',
  'checkout.session.async_payment_failed',
  'checkout.session.expired',
  'refund.created',
  'refund.updated',
  'refund.failed',
  'charge.refunded',
  'charge.dispute.created',
  'charge.dispute.updated',
  'charge.dispute.closed',
  'charge.dispute.funds_withdrawn',
  'charge.dispute.funds_reinstated',
]));
const wrongWebhookUnionEnv = environment('sandbox');
const wrongWebhookUnionReadback = JSON.parse(wrongWebhookUnionEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON);
wrongWebhookUnionReadback.stripe.webhook_event_set_readback_sha256 = digest('incomplete-webhook-set');
wrongWebhookUnionEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON = JSON.stringify(wrongWebhookUnionReadback);
const wrongWebhookUnion = createReviewActivationEnvironmentReport(
  wrongWebhookUnionEnv, { mode: 'sandbox', now },
);
assert.ok(wrongWebhookUnion.invalid.includes('ARC_REVIEW_ACTIVATION_READBACK_JSON:BINDINGS'));

const productionEnv = environment('production');
const production = createReviewActivationEnvironmentReport(productionEnv, { mode: 'production', now });
assert.equal(production.ok, false);
assert.equal(production.state, 'PRODUCTION_BLOCKED', JSON.stringify(production));
assert.deepEqual(production.missing, []);
assert.deepEqual(production.invalid, []);
assert.deepEqual(production.blocked, contract.profiles.production.blocked_controls);
assert.ok(production.blocked.includes('LIVE_PROVIDER_E2E_EVIDENCE'),
  'A locally complete production profile must remain blocked until provider E2E evidence is reviewed.');
assert.ok(production.blocked.includes('OPERATIONS_ALERT_PROVIDER_EVIDENCE'));
assert.ok(production.blocked.includes('STRIPE_WEBHOOK_UNIFIED_DESTINATION_EVIDENCE'));
assert.ok(production.blocked.includes('NETLIFY_HANDOFF_CREDENTIAL_EVIDENCE'));
assert.equal(production.checks.operations_alert_provider_evidence_verified, false);
assert.equal(production.checks.runtime_provider_readback_configured, true);
assert.equal(production.checks.provider_readback_current, false);
assert.equal(production.checks.static_readback_reference_valid, true);
assert.equal(production.checks.first_party_retention_configuration_valid, true);
assert.equal(production.checks.first_party_retention_alert_queue_ready, true);
assert.equal(production.checks.first_party_retention_receipt_current, true);
assert.equal(productionEnv.ARC_PAYMENT_ARC2_WORKER_ENABLED, 'true');
assert.equal(productionEnv.ARC_STRIPE_REVERSAL_CONTROL_REQUIRED, 'true');

const missingRetentionAlertQueueEnv = environment('production');
missingRetentionAlertQueueEnv.ARC_OPERATIONS_AUDIT_ENABLED = 'false';
const missingRetentionAlertQueue = createReviewActivationEnvironmentReport(
  missingRetentionAlertQueueEnv, { mode: 'production', now },
);
assert.equal(missingRetentionAlertQueue.checks.first_party_retention_alert_queue_ready, false);
assert.ok(missingRetentionAlertQueue.invalid.includes(
  'FIRST_PARTY_RETENTION_ALERT_QUEUE_CONFIGURATION'));

const missingFirstPartyRetentionReceiptEnv = environment('production');
delete missingFirstPartyRetentionReceiptEnv.ARC_FIRST_PARTY_RETENTION_RECEIPT;
const missingFirstPartyRetentionReceipt = createReviewActivationEnvironmentReport(
  missingFirstPartyRetentionReceiptEnv, { mode: 'production', now },
);
assert.ok(missingFirstPartyRetentionReceipt.missing.includes('ARC_FIRST_PARTY_RETENTION_RECEIPT'));
assert.ok(missingFirstPartyRetentionReceipt.invalid.includes('FIRST_PARTY_RETENTION_CURRENT_RECEIPT'));

const bypassedProduction = createReviewActivationEnvironmentReport({
  ...productionEnv,
  ARC_PAYMENT_ARC2_WORKER_ENABLED: 'false',
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'false',
}, { mode: 'production', now });
assert.ok(bypassedProduction.invalid.includes('ARC_PAYMENT_ARC2_WORKER_ENABLED'));
assert.ok(bypassedProduction.invalid.includes('ARC_STRIPE_REVERSAL_CONTROL_REQUIRED'));

const duplicateSecretEnv = environment('sandbox');
duplicateSecretEnv.ARC_REVIEW_EMAIL_INTERNAL_API_SECRET =
  duplicateSecretEnv.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET;
const duplicateSecret = createReviewActivationEnvironmentReport(duplicateSecretEnv, { mode: 'sandbox', now });
assert.ok(duplicateSecret.invalid.includes('SECRET_DISTINCTNESS'));
assert.equal(JSON.stringify(duplicateSecret).includes(duplicateSecretEnv.ARC_REVIEW_EMAIL_INTERNAL_API_SECRET), false);

const wrongKeyMode = createReviewActivationEnvironmentReport({
  ...sandboxEnv,
  ARC_STRIPE_REVIEW_SECRET_KEY: ['sk', 'live', 'wrongModeReviewActivationKey0123456789'].join('_'),
}, { mode: 'sandbox', now });
assert.ok(wrongKeyMode.invalid.includes('ARC_STRIPE_REVIEW_SECRET_KEY'));

const staleEnv = environment('sandbox');
const stale = readback('sandbox', staleEnv, {
  observed_at: new Date(now.getTime() - 16 * 60_000).toISOString(),
  expires_at: new Date(now.getTime() - 60_000).toISOString(),
});
staleEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON = JSON.stringify(stale);
const staleReport = createReviewActivationEnvironmentReport(staleEnv, { mode: 'sandbox', now });
assert.ok(staleReport.invalid.includes('ARC_REVIEW_ACTIVATION_READBACK_JSON:FRESHNESS'));

const staleProductionReferenceEnv = environment('production');
const staleProductionReference = readback('production', staleProductionReferenceEnv, {
  observed_at: new Date(now.getTime() - 24 * 60 * 60_000).toISOString(),
  expires_at: new Date(now.getTime() - 24 * 60 * 60_000 + 10 * 60_000).toISOString(),
});
staleProductionReferenceEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON =
  JSON.stringify(staleProductionReference);
const staleProductionReferenceReport = createReviewActivationEnvironmentReport(
  staleProductionReferenceEnv, { mode: 'production', now },
);
assert.equal(staleProductionReferenceReport.state, 'PRODUCTION_BLOCKED');
assert.deepEqual(staleProductionReferenceReport.invalid, []);
assert.equal(staleProductionReferenceReport.checks.provider_readback_current, false);
assert.equal(staleProductionReferenceReport.checks.static_readback_reference_valid, true);

const controlsOnEnv = environment('sandbox');
controlsOnEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON = JSON.stringify(readback('sandbox', controlsOnEnv, {
  provider_controls_state: 'ON',
}));
const controlsOn = createReviewActivationEnvironmentReport(controlsOnEnv, { mode: 'sandbox', now });
assert.ok(controlsOn.invalid.includes('ARC_REVIEW_ACTIVATION_READBACK_JSON:CONTRACT'));

const functionByPath = new Map([
  ['/api/review/exchange', 'review-exchange.mjs'],
  ['/api/review/status', 'review-status.mjs'],
  ['/api/review/decision', 'review-decision.mjs'],
  ['/api/review/checkout', 'review-checkout.mjs'],
  ['/api/internal/review-email/prepare', 'review-email-prepare.mjs'],
  ['/api/internal/review-email/reserve', 'review-email-reserve.mjs'],
  ['/api/internal/review-email/ack', 'review-email-ack.mjs'],
  ['/api/internal/review-revision/claim', 'review-revision-claim.mjs'],
  ['/api/internal/review-revision/complete', 'review-revision-complete.mjs'],
  ['/internal/payment-arc2/claim', 'payment-arc2-worker.mjs'],
  ['/internal/payment-arc2/start', 'payment-arc2-worker.mjs'],
  ['/internal/payment-arc2/complete', 'payment-arc2-worker.mjs'],
  ['/internal/stripe/reversal-webhook', 'stripe-reversal-webhook.mjs'],
  ['/internal/operations/audit', 'operations-audit.mjs'],
  ['/api/internal/operations-alert/reserve', 'operations-alert-reserve.mjs'],
  ['/api/internal/operations-alert/ack', 'operations-alert-ack.mjs'],
  ['/api/internal/retention/legal-hold', 'first-party-retention-legal-hold.mjs'],
]);
for (const routes of Object.values(contract.routes)) {
  for (const route of routes) {
    const source = await readFile(new URL(`../netlify/functions/${functionByPath.get(route.path)}`,
      import.meta.url), 'utf8');
    assert.ok(source.includes(`'${route.path}'`), `${route.path} must be deployed by its bound Function.`);
    assert.ok(source.includes(`method: '${route.method}'`) || source.includes(`method !== '${route.method}'`),
      `${route.path} must retain its exact ${route.method} method.`);
  }
}

const paymentWorkerSource = await readFile(
  new URL('../netlify/functions/payment-arc2-worker.mjs', import.meta.url), 'utf8');
assert.match(paymentWorkerSource,
  /createPaymentArc2ReviewEvidence[\s\S]+startReviewHandoff[\s\S]+startReceipt\.canonical[\s\S]+startReceipt\.signature/,
  'The production payment worker must bind provider evidence to a durable signed ARC2 start receipt.');
const stripeAdapterSource = await readFile(
  new URL('../netlify/lib/stripe-review-checkout-adapter.mjs', import.meta.url), 'utf8');
assert.match(stripeAdapterSource, /revocation\.enabled/,
  'Review Checkout creation must remain bound to revocation readiness.');
assert.match(stripeAdapterSource, /checkout\.sessions\.retrieve/);
assert.match(stripeAdapterSource, /checkout\.sessions\.expire/);
assert.match(stripeAdapterSource, /expireSuppressedRecipientReviewCheckouts/);
const runbook = await readFile(
  new URL('../operations/review-activation-environment.md', import.meta.url), 'utf8');
for (const stage of contract.activation_order) assert.ok(runbook.includes(stage));
assert.match(runbook, /OFF by default/);
assert.match(runbook, /provider's native webhook/);
assert.match(runbook, /provider's native suppression control/);
assert.match(runbook, /Never set the reversal-required flag false to bypass it/);
assert.match(runbook, /Set exactly one of\s+`NETLIFY_ADMIN_PAT` or `NETLIFY_ACCESS_TOKEN`/);
assert.match(runbook, /one destination per mode/);
assert.match(runbook, /failure_alert_verified` stays\s+false/);
assert.match(runbook, /ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET/);
assert.match(runbook, /ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER/);
assert.match(runbook, /POST \/api\/internal\/retention\/legal-hold/);
assert.match(runbook, /no deployed fence intent, completion\/finalize receipt, recovery alert/i);
const stripeRunbook = await readFile(
  new URL('../operations/stripe-reversal-control.md', import.meta.url), 'utf8');
for (const eventType of contract.stripe_webhook.events) assert.ok(stripeRunbook.includes(eventType));
assert.match(stripeRunbook, /Do not create a second Checkout webhook/);
const manualActivationRunbook = await readFile(
  new URL('../operations/manual-activation.md', import.meta.url), 'utf8');
assert.match(manualActivationRunbook, /"failure_alert_verified": false/);
assert.doesNotMatch(manualActivationRunbook,
  /failure_alert_verified[\s"':]+true/);
assert.match(manualActivationRunbook, /ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET/);
const retentionRunbook = await readFile(
  new URL('../operations/first-party-retention-sweep.md', import.meta.url), 'utf8');
assert.match(retentionRunbook, /OPEN\(N\) -> WRITING\(N\)/);
assert.match(retentionRunbook, /No signed fence intent[\s\S]+deployed runtime yet/);
const readiness = JSON.parse(await readFile(
  new URL('../operations/readiness.json', import.meta.url), 'utf8'));
assert.equal(readiness.data_retention.generation_fence.code_default_fail_closed, true);
assert.equal(readiness.data_retention.generation_fence.deployed_intent_or_receipt_verified, false);

let cliOutput = '';
assert.equal(runReviewActivationPreflightCli({
  argv: ['--mode=off'], env: {}, now, write: (value) => { cliOutput += value; },
}), 0);
assert.equal(JSON.parse(cliOutput).state, 'SAFE_OFF');
cliOutput = '';
assert.equal(runReviewActivationPreflightCli({
  argv: ['--mode=sandbox'], env: sandboxEnv, now, write: (value) => { cliOutput += value; },
}), 0);
assert.equal(JSON.parse(cliOutput).state, 'SANDBOX_CONFIGURED');
cliOutput = '';
assert.equal(runReviewActivationPreflightCli({
  argv: ['--mode=production'], env: productionEnv, now, write: (value) => { cliOutput += value; },
}), 1);
assert.equal(JSON.parse(cliOutput).state, 'PRODUCTION_BLOCKED');
assert.ok(JSON.parse(cliOutput).blocked.includes('LIVE_PROVIDER_E2E_EVIDENCE'));
assert.equal(runReviewActivationPreflightCli({ argv: [], env: {}, write: () => {} }), 2);

console.log('Review activation environment contract passed.');
