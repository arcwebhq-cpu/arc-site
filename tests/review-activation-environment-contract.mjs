import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import {
  REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT as contract,
  createReviewActivationEnvironmentReport,
  reviewActivationEnvironmentNamesSha256,
  reviewActivationRouteMatrixSha256,
  runReviewActivationPreflightCli,
} from '../scripts/review-activation-preflight.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const now = new Date('2026-08-27T12:00:00.000Z');
const digest = (label) => sha256(`review-activation-contract:${label}`);

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
  assert.deepEqual(Object.keys(secret).sort(), ['authority', 'consumers', 'name']);
  assert.match(secret.name, /(?:SECRET|KEY)$/);
  assert.equal(typeof secret.authority, 'string');
  assert.ok(Array.isArray(secret.consumers) && secret.consumers.length > 0);
}
assert.equal(JSON.stringify(contract.secrets).includes('"value"'), false,
  'The committed secret ownership contract must contain names only, never values.');

const baseBindings = {
  ARC_ACTIVATION_MANIFEST: 'signed-runtime-manifest-held-outside-git',
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
  ARC_REVIEW_EMAIL_PROVIDER: 'provider-sandbox',
  ARC_REVIEW_EMAIL_PROVIDER_ACCOUNT_ID_SHA256: digest('email-provider-account'),
  ARC_REVIEW_EMAIL_SENDER_IDENTITY_SHA256: digest('email-sender'),
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
};

function secretEnvironment(mode) {
  const values = Object.fromEntries(secretNames.map((name, index) => [
    name,
    `review-activation-secret-${String(index).padStart(2, '0')}-abcdefghijklmnopqrstuvwxyz`,
  ]));
  values.ARC_STRIPE_REVIEW_SECRET_KEY = `sk_${mode === 'sandbox' ? 'test' : 'live'}_` +
    'reviewActivationCheckoutKey0123456789';
  values.ARC_STRIPE_ACCOUNT_VERIFICATION_KEY = `rk_${mode === 'sandbox' ? 'test' : 'live'}_` +
    'reviewActivationAccountKey0123456789';
  values.ARC_STRIPE_WEBHOOK_SIGNING_SECRET =
    'whsec_reviewActivationWebhookSecret0123456789';
  return values;
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
      env_name_set_readback_sha256: reviewActivationEnvironmentNamesSha256(mode),
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

function environment(mode) {
  const env = {
    ...baseBindings,
    ...contract.profiles[mode].flags,
    ...secretEnvironment(mode),
  };
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
assert.equal(contract.profiles.sandbox.flags.ARC_STRIPE_REVIEW_REVOCATION_ENABLED, 'true');
assert.ok(secretNames.includes('ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET'));

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

const productionEnv = environment('production');
const production = createReviewActivationEnvironmentReport(productionEnv, { mode: 'production', now });
assert.equal(production.ok, true);
assert.equal(production.state, 'PRODUCTION_CONFIGURED');
assert.deepEqual(production.missing, []);
assert.deepEqual(production.invalid, []);
assert.deepEqual(production.blocked, []);
assert.equal(productionEnv.ARC_PAYMENT_ARC2_WORKER_ENABLED, 'true');
assert.equal(productionEnv.ARC_STRIPE_REVERSAL_CONTROL_REQUIRED, 'true');

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
}), 0);
assert.equal(JSON.parse(cliOutput).state, 'PRODUCTION_CONFIGURED');
assert.equal(runReviewActivationPreflightCli({ argv: [], env: {}, write: () => {} }), 2);

console.log('Review activation environment contract passed.');
