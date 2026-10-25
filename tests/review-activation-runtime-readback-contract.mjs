import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign,
} from 'node:crypto';

import {
  ACTIVATION_EVIDENCE_BY_STAGE,
  ACTIVATION_MANIFEST_SCHEMA,
  ACTIVATION_MANIFEST_VERSION,
  signActivationManifest,
} from '../netlify/lib/activation-manifest-core.mjs';
import {
  REVIEW_ACTIVATION_ROUTE_MATRIX_SHA256,
  REVIEW_ACTIVATION_STRIPE_WEBHOOK_EVENT_SET_SHA256,
  REVIEW_ACTIVATION_RUNTIME_READBACK_SCHEMA,
  REVIEW_ACTIVATION_RUNTIME_READBACK_STORE,
  REVIEW_ACTIVATION_RUNTIME_READBACK_VERSION,
  canonicalReviewActivationRuntimeJson,
  ensureReviewActivationRuntimeReadback,
  persistReviewActivationRuntimeReadback,
  readReviewActivationRuntimeReadback,
  reviewActivationRuntimeAuthorityBinding,
  reviewActivationRuntimeEnvironmentNamesSha256,
  reviewActivationRuntimeReadbackConfiguration,
  validateReviewActivationRuntimeEnvelope,
} from '../netlify/lib/review-activation-runtime-readback-core.mjs';
import {
  createReviewActivationRuntimeReadbackPreflightReport,
  runReviewActivationRuntimeReadbackPreflightCli,
} from '../scripts/review-activation-runtime-readback-preflight.mjs';
import {
  reviewActivationEnvironmentNamesSha256,
  reviewActivationRouteMatrixSha256,
  reviewActivationStripeWebhookEventSetSha256,
} from '../scripts/review-activation-preflight.mjs';
import reviewActivationReadbackRefreshHandler, { createReviewActivationReadbackRefreshHandler } from
  '../netlify/functions/review-activation-readback-refresh.mjs';

const now = new Date('2026-08-28T20:00:00.000Z');
const deploymentSha = '7'.repeat(40);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const digest = (label) => sha256(`runtime-readback-contract:${label}`);
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicKeyBase64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const manifestSecret = 'runtime-readback-manifest-secret-0123456789abcdef';

const env = {
  ARC_ACTIVATION_MANIFEST_HMAC_SECRET: manifestSecret,
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_EXPECTED_PRICE_ID: 'price_runtimeReadback123456',
  ARC_EXPECTED_PRODUCT_ID: 'prod_runtimeReadback123456',
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256: digest('stripe-account'),
  NETLIFY_ADMIN_PAT: 'netlify-runtime-readback-test-admin-pat-0123456789',
  ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED: 'true',
  ARC_REVIEW_ACTIVATION_VERIFIER_ED25519_PUBLIC_KEY: publicKeyBase64,
  ARC_REVIEW_ACTIVATION_VERIFIER_URL: 'https://verifier.arcweb.onl/runtime-readback',
  ARC_REVIEW_EMAIL_NATIVE_SUPPRESSION_ID_SHA256: digest('suppression-id'),
  ARC_REVIEW_EMAIL_NATIVE_WEBHOOK_ID_SHA256: digest('webhook-id'),
  ARC_REVIEW_EMAIL_PROVIDER: 'resend',
  ARC_REVIEW_EMAIL_PROVIDER_ACCOUNT_ID_SHA256: digest('resend-account'),
  ARC_REVIEW_EMAIL_SENDER_IDENTITY_SHA256: digest('sender'),
  ARC_OPERATIONS_AUDIT_ENABLED: 'true',
  ARC_RUNTIME_ENVIRONMENT: 'production',
  ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER: 'arc_review_checkout_qwertyui',
  ARC_ZAPIER_PAYMENT_ARC2_WORKFLOW_ID_SHA256: digest('payment-workflow'),
  ARC_ZAPIER_REVIEW_CHECKOUT_REVOCATION_WORKFLOW_ID_SHA256: digest('revocation-workflow'),
  ARC_ZAPIER_REVIEW_EMAIL_WORKFLOW_ID_SHA256: digest('email-workflow'),
  ARC_ZAPIER_REVIEW_REVISION_WORKFLOW_ID_SHA256: digest('revision-workflow'),
};

const authority = reviewActivationRuntimeAuthorityBinding(env, { deploymentSha });
assert.ok(authority);
const authoritySha256 = sha256(canonicalReviewActivationRuntimeJson(authority));
env.ARC_ACTIVATION_MANIFEST = signActivationManifest({
  schema: ACTIVATION_MANIFEST_SCHEMA,
  version: ACTIVATION_MANIFEST_VERSION,
  stage: 'LIVE_CHECKOUT',
  authority_mode: 'ROLLOUT',
  issued_at: new Date(now.getTime() - 60_000).toISOString(),
  expires_at: new Date(now.getTime() + 60 * 60_000).toISOString(),
  deployment_sha: deploymentSha,
  evidence: ACTIVATION_EVIDENCE_BY_STAGE.LIVE_CHECKOUT.map((kind) => ({
    kind,
    receipt_ref: `audit:${digest(`ref:${kind}`).slice(0, 24)}`,
    sha256: kind === 'live_checkout_readback' ? authoritySha256 : digest(`evidence:${kind}`),
  })),
}, manifestSecret);

function receipt(observedAt = new Date(now.getTime() - 60_000)) {
  return {
    schema: 'arc-review-activation-readback-v1',
    version: 1,
    mode: 'production',
    minimum_stage: 'LIVE_CHECKOUT',
    provider_controls_state: 'OFF',
    observed_at: observedAt.toISOString(),
    expires_at: new Date(observedAt.getTime() + 14 * 60_000).toISOString(),
    netlify: {
      deployment_sha: deploymentSha,
      env_name_set_readback_sha256: reviewActivationRuntimeEnvironmentNamesSha256(env),
      handoff_credential_environment_name: 'NETLIFY_ADMIN_PAT',
      route_matrix_readback_sha256: REVIEW_ACTIVATION_ROUTE_MATRIX_SHA256,
      route_probe_receipt_sha256: digest(`route-probe:${observedAt.toISOString()}`),
      site_id_sha256: sha256(env.ARC_EXPECTED_NETLIFY_SITE_ID),
    },
    stripe: {
      account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
      catalog_readback_sha256: digest(`catalog:${observedAt.toISOString()}`),
      checkout_session_expire_capability_readback_sha256: digest('expire-capability'),
      checkout_session_retrieve_capability_readback_sha256: digest('retrieve-capability'),
      integration_identifier_sha256: sha256(env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER),
      price_id_sha256: sha256(env.ARC_EXPECTED_PRICE_ID),
      product_id_sha256: sha256(env.ARC_EXPECTED_PRODUCT_ID),
      webhook_destination_readback_sha256: digest(`stripe-webhook:${observedAt.toISOString()}`),
      webhook_endpoint_path: '/internal/stripe/reversal-webhook',
      webhook_event_set_readback_sha256: REVIEW_ACTIVATION_STRIPE_WEBHOOK_EVENT_SET_SHA256,
    },
    operations_alert: {
      audit_enabled: true,
      delivery_enabled: false,
      failure_alert_verified: false,
      native_delivery_receipt_sha256: '0'.repeat(64),
      provider_event_type: 'email.delivered',
    },
    email: {
      native_suppression_id_sha256: env.ARC_REVIEW_EMAIL_NATIVE_SUPPRESSION_ID_SHA256,
      native_suppression_readback_sha256: digest(`suppression:${observedAt.toISOString()}`),
      native_webhook_id_sha256: env.ARC_REVIEW_EMAIL_NATIVE_WEBHOOK_ID_SHA256,
      native_webhook_readback_sha256: digest(`email-webhook:${observedAt.toISOString()}`),
      provider: env.ARC_REVIEW_EMAIL_PROVIDER,
      provider_account_id_sha256: env.ARC_REVIEW_EMAIL_PROVIDER_ACCOUNT_ID_SHA256,
      sandbox_delivery_receipt_sha256: digest('sandbox-delivery'),
      sender_identity_sha256: env.ARC_REVIEW_EMAIL_SENDER_IDENTITY_SHA256,
    },
    zapier: {
      checkout_revocation_worker_contract_receipt_sha256: digest('revocation-contract'),
      checkout_revocation_workflow_id_sha256:
        env.ARC_ZAPIER_REVIEW_CHECKOUT_REVOCATION_WORKFLOW_ID_SHA256,
      checkout_revocation_workflow_version_readback_sha256:
        digest(`revocation-version:${observedAt.toISOString()}`),
      claim_next_contract_receipt_sha256: digest('claim-next-contract'),
      email_claim_next_path: '/api/internal/review-email/reserve',
      email_workflow_id_sha256: env.ARC_ZAPIER_REVIEW_EMAIL_WORKFLOW_ID_SHA256,
      email_workflow_version_readback_sha256: digest(`email-version:${observedAt.toISOString()}`),
      payment_arc2_claim_next_path: '/internal/payment-arc2/claim',
      payment_arc2_start_path: '/internal/payment-arc2/start',
      payment_arc2_start_contract_receipt_sha256: digest('payment-start-contract'),
      payment_arc2_workflow_id_sha256: env.ARC_ZAPIER_PAYMENT_ARC2_WORKFLOW_ID_SHA256,
      payment_arc2_workflow_version_readback_sha256:
        digest(`payment-version:${observedAt.toISOString()}`),
      revision_claim_next_path: '/api/internal/review-revision/claim',
      revision_workflow_id_sha256: env.ARC_ZAPIER_REVIEW_REVISION_WORKFLOW_ID_SHA256,
      revision_workflow_version_readback_sha256:
        digest(`revision-version:${observedAt.toISOString()}`),
    },
  };
}

function envelope(value = receipt()) {
  const unsigned = {
    schema: REVIEW_ACTIVATION_RUNTIME_READBACK_SCHEMA,
    version: REVIEW_ACTIVATION_RUNTIME_READBACK_VERSION,
    authority_sha256: authoritySha256,
    key_sha256: sha256(publicKey.export({ format: 'der', type: 'spki' })),
    receipt: value,
  };
  return {
    ...unsigned,
    signature: sign(null, Buffer.from(`${REVIEW_ACTIVATION_RUNTIME_READBACK_SCHEMA}\n${
      canonicalReviewActivationRuntimeJson(unsigned)}`), privateKey).toString('base64'),
  };
}

class Store {
  constructor() {
    this.values = new Map();
    this.version = 0;
    this.reads = [];
    this.writes = [];
  }

  async getWithMetadata(key, options) {
    this.reads.push([key, structuredClone(options)]);
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }

  async setJSON(key, value, options = {}) {
    this.writes.push([key, structuredClone(options)]);
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    if (options.onlyIfMatch && !current) return { modified: false };
    const etag = `etag-${++this.version}`;
    this.values.set(key, { data: structuredClone(value), etag });
    return { modified: true, etag };
  }
}

const configuration = reviewActivationRuntimeReadbackConfiguration(env, now, { deploymentSha });
assert.equal(configuration.enabled, true);
assert.equal(configuration.manifest_bound, true);
assert.equal(configuration.authority_sha256, authoritySha256);
assert.equal(REVIEW_ACTIVATION_RUNTIME_READBACK_STORE,
  'arc-review-activation-runtime-readback-v1');
assert.equal(reviewActivationRuntimeEnvironmentNamesSha256(env),
  reviewActivationEnvironmentNamesSha256('production', env));
const accessAliasEnv = {
  ...env,
  NETLIFY_ACCESS_TOKEN: env.NETLIFY_ADMIN_PAT,
};
delete accessAliasEnv.NETLIFY_ADMIN_PAT;
assert.equal(reviewActivationRuntimeEnvironmentNamesSha256(accessAliasEnv),
  reviewActivationEnvironmentNamesSha256('production', accessAliasEnv));
assert.equal(REVIEW_ACTIVATION_ROUTE_MATRIX_SHA256, reviewActivationRouteMatrixSha256());
assert.equal(REVIEW_ACTIVATION_STRIPE_WEBHOOK_EVENT_SET_SHA256,
  reviewActivationStripeWebhookEventSetSha256());

const currentEnvelope = envelope();
assert.equal(validateReviewActivationRuntimeEnvelope(env, currentEnvelope, now, { deploymentSha }), true);
assert.equal(validateReviewActivationRuntimeEnvelope(env, {
  ...currentEnvelope,
  signature: `${currentEnvelope.signature.slice(0, -2)}AA`,
}, now, { deploymentSha }), false);
assert.equal(validateReviewActivationRuntimeEnvelope(env, envelope(receipt(
  new Date(now.getTime() - 16 * 60_000),
)), now, { deploymentSha }), false, 'A signed but stale receipt must fail closed.');
assert.equal(validateReviewActivationRuntimeEnvelope({
  ...env,
  ARC_EXPECTED_PRICE_ID: 'price_differentBinding123456',
}, currentEnvelope, now, { deploymentSha }), false, 'Provider binding drift must fail closed.');
assert.equal(reviewActivationRuntimeReadbackConfiguration({
  ...env,
  ARC_ACTIVATION_MANIFEST: '',
}, now, { deploymentSha }).enabled, false, 'The verifier key cannot replace manifest evidence.');
assert.equal(reviewActivationRuntimeReadbackConfiguration({
  ...env,
  ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED: 'false',
}, now, { deploymentSha }).enabled, false, 'The durable runtime path is default OFF.');
assert.equal(reviewActivationRuntimeReadbackConfiguration({
  ...env,
  NETLIFY_ACCESS_TOKEN: 'duplicate-netlify-credential-0123456789abcdef',
}, now, { deploymentSha }).enabled, false, 'Ambiguous Netlify handoff credentials must fail closed.');
for (const credentialName of [
  'NETLIFY_ADMIN_PAT',
  'ARC_ACTIVATION_MANIFEST_HMAC_SECRET',
]) {
  const aliased = {
    ...env,
    ARC_ROTATED_CREDENTIAL_V2: env[credentialName],
  };
  assert.equal(reviewActivationRuntimeAuthorityBinding(aliased, { deploymentSha }), null,
    `${credentialName} must reject an arbitrary configured alias before raw authority access.`);
  assert.equal(reviewActivationRuntimeReadbackConfiguration(
    aliased, now, { deploymentSha },
  ).enabled, false, `${credentialName} aliasing must disable runtime readback.`);
}

const productionPreflight = createReviewActivationRuntimeReadbackPreflightReport({
  ...env,
  ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_CANDIDATE_JSON: JSON.stringify(currentEnvelope),
}, { mode: 'production', now, deploymentSha });
assert.equal(productionPreflight.ok, true);
assert.equal(productionPreflight.checks.current_signed_candidate, true);
assert.equal(createReviewActivationRuntimeReadbackPreflightReport({}, { mode: 'off', now }).ok, true);
let cliOutput = '';
assert.equal(runReviewActivationRuntimeReadbackPreflightCli({
  argv: ['--mode=off'], env: {}, now, write: (value) => { cliOutput += value; },
}), 0);
assert.equal(JSON.parse(cliOutput).state, 'SAFE_OFF');

const store = new Store();
await persistReviewActivationRuntimeReadback(env, store, currentEnvelope, now, { deploymentSha });
assert.equal(store.writes.length, 1);
const durable = await readReviewActivationRuntimeReadback(env, store, now, { deploymentSha });
assert.ok(durable);
assert.deepEqual(durable.envelope, currentEnvelope);

let fetchCalls = 0;
const reused = await ensureReviewActivationRuntimeReadback(env, store, now, {
  deploymentSha,
  fetch: async () => { fetchCalls += 1; throw new Error('must not fetch'); },
});
assert.deepEqual(reused, currentEnvelope);
assert.equal(fetchCalls, 0, 'Checkout must strong-read a current durable receipt before refreshing.');

const laterObserved = new Date(now.getTime() + 60_000);
const laterEnvelope = envelope(receipt(laterObserved));
const staleAtLaterTime = new Date(now.getTime() + 14 * 60_000);
const refreshed = await ensureReviewActivationRuntimeReadback(env, store, staleAtLaterTime, {
  deploymentSha,
  fetch: async (url, init) => {
    fetchCalls += 1;
    assert.equal(url, env.ARC_REVIEW_ACTIVATION_VERIFIER_URL);
    assert.equal(init.method, 'GET');
    assert.equal(init.redirect, 'error');
    return new Response(JSON.stringify(laterEnvelope), {
      status: 200,
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
  },
});
assert.deepEqual(refreshed, laterEnvelope);
assert.equal(fetchCalls, 1, 'A stale record must refresh from the pinned signed verifier.');

const rollbackResult = await persistReviewActivationRuntimeReadback(
  env,
  store,
  currentEnvelope,
  new Date(now.getTime() + 2 * 60_000),
  { deploymentSha },
);
assert.deepEqual(rollbackResult, laterEnvelope, 'A valid older receipt must not replace a newer receipt.');

const equivocatedReceipt = receipt(laterObserved);
equivocatedReceipt.stripe.catalog_readback_sha256 = digest('equivocated-catalog');
await assert.rejects(persistReviewActivationRuntimeReadback(
  env,
  store,
  envelope(equivocatedReceipt),
  new Date(now.getTime() + 2 * 60_000),
  { deploymentSha },
), /EQUIVOCATION_REJECTED/, 'Two signed values at one observation time must fail closed.');

const offStore = new Store();
await assert.rejects(ensureReviewActivationRuntimeReadback({
  ...env,
  ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED: 'false',
}, offStore, now, {
  deploymentSha,
  fetch: async () => { throw new Error('must remain inert'); },
}), /CONFIGURATION_INVALID/);
assert.equal(offStore.reads.length, 0);
assert.equal(offStore.writes.length, 0);

const priorRuntimeFlag = process.env.ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED;
delete process.env.ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED;
try {
  const offResponse = await reviewActivationReadbackRefreshHandler(new Request('https://example.test'), {
    get retentionFenceStore() { throw new Error('The OFF handler must not create/read the fence store.'); },
    get readbackStore() { throw new Error('The OFF handler must not create/read a store.'); },
    fetch: async () => { throw new Error('The OFF handler must not use the network.'); },
  });
  assert.equal(offResponse.status, 204);
} finally {
  if (priorRuntimeFlag === undefined) delete process.env.ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED;
  else process.env.ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED = priorRuntimeFlag;
}

console.log('ARC durable signed runtime activation readback contract passed.');
