import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import reviewCheckoutHandler from '../netlify/functions/review-checkout.mjs';
import reviewEmailAckHandler from '../netlify/functions/review-email-ack.mjs';
import {
  ACTIVATION_EVIDENCE_BY_STAGE,
  ACTIVATION_MANIFEST_SCHEMA,
  ACTIVATION_MANIFEST_VERSION,
  signActivationManifest,
} from '../netlify/lib/activation-manifest-core.mjs';
import {
  STRIPE_REVIEW_CHECKOUT_API_VERSION,
  STRIPE_REVIEW_CHECKOUT_SCHEMA,
  createStripeReviewCheckout,
  expireSuppressedRecipientReviewCheckouts,
  stripeReviewCheckoutConfiguration,
  stripeReviewCheckoutConsumerReadiness,
  validateStripeReviewTaxReadiness,
} from '../netlify/lib/stripe-review-checkout-adapter.mjs';
import {
  reviewActivationEnvironmentNamesSha256,
  reviewActivationRouteMatrixSha256,
  reviewActivationStripeWebhookEventSetSha256,
} from '../scripts/review-activation-preflight.mjs';
import {
  acknowledgeReviewEmailReceipt,
  prepareReviewInviteEmail,
  reserveReviewEmailSend,
  reviewEmailReceiptContract,
} from '../netlify/lib/review-email-outbox-core.mjs';
import { signReviewEmailInternalRequest } from '../netlify/lib/review-email-http-core.mjs';
import {
  readReviewEmailRecipientControl,
  suppressReviewEmailRecipientControl,
} from '../netlify/lib/review-email-recipient-control-core.mjs';
import {
  assertReviewCheckoutFulfillmentAllowed,
  listReviewCheckoutBindingsForRecipient,
} from '../netlify/lib/review-checkout-revocation-core.mjs';
import {
  decideReview,
  exchangeReviewInvite,
  readReviewStatus,
} from '../netlify/lib/review-flow-core.mjs';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const canonicalJson = value => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
};
const accountId = 'acct_ArcSandboxContract';
const priceId = 'price_ArcFivePageContract';
const productId = 'prod_ArcFivePageContract';
const taxCodeId = 'txcd_10000000';
const now = new Date('2026-08-27T22:00:00.000Z');
const hex = character => character.repeat(64);
const stripeKey = (scope, mode, label) => [scope, mode, label].join('_');
const testSecretKey = stripeKey('sk', 'test', 'arc_review_checkout_0123456789abcdef');
const testRestrictedKey = stripeKey('rk', 'test', 'arc_account_verification_0123456789');
const liveSecretKey = stripeKey('sk', 'live', 'arc_review_checkout_0123456789abcdef');

const env = {
  ARC_ALLOW_TEST_MODE_EVENTS: 'true',
  ARC_EXPECTED_PRICE_ID: priceId,
  ARC_EXPECTED_PRODUCT_ID: productId,
  ARC_EXPECTED_PRODUCT_NAME: 'ARC Fixed Five-Page Website',
  ARC_EXPECTED_PRODUCT_TAX_CODE: taxCodeId,
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256: sha256(accountId),
  ARC_HANDOFF_ENABLED: 'false',
  ARC_PAYMENT_ARC2_BRIDGE_ENABLED: 'true',
  ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET: 'payment-arc2-producer-test-secret-0123456789abcdef',
  ARC_REVIEW_CHECKOUT_ENABLED: 'true',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
  ARC_REVIEW_DECISION_HMAC_SECRET: 'review-decision-producer-test-secret-0123456789abcdef',
  ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
  ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET: 'review-email-outbox-producer-test-secret-0123456789abcdef',
  ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET: 'review-email-receipt-producer-test-secret-0123456789abcdef',
  ARC_REVIEW_EMAIL_INTERNAL_API_ENABLED: 'true',
  ARC_REVIEW_EMAIL_INTERNAL_API_SECRET: 'review-email-internal-producer-test-secret-0123456789abcdef',
  ARC_REVIEW_INVITE_HMAC_SECRET: 'review-invite-producer-test-secret-0123456789abcdef',
  ARC_REVIEW_PORTAL_ENABLED: 'true',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
  ARC_REVIEW_RECORD_HMAC_SECRET: 'review-record-producer-test-secret-0123456789abcdef',
  ARC_REVIEW_SESSION_HMAC_SECRET: 'review-session-producer-test-secret-0123456789abcdef',
  ARC_RUNTIME_ENVIRONMENT: 'sandbox',
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: testRestrictedKey,
  ARC_STRIPE_CHECKOUT_LEDGER_ENABLED: 'true',
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'false',
  ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER: 'arc_review_checkout_qwertyui',
  ARC_STRIPE_CHECKOUT_OFFER_ID: 'arc-fixed-five-page-offer-v1',
  ARC_STRIPE_CHECKOUT_SUCCESS_URL: 'https://arcweb.onl/payment-success/?session_id={CHECKOUT_SESSION_ID}',
  ARC_STRIPE_CHECKOUT_CANCEL_URL: 'https://arcweb.onl/review/?checkout=cancelled',
  ARC_STRIPE_CHECKOUT_TERMS_VERSION: '2026-08-25',
  ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
  ARC_STRIPE_REVIEW_CHECKOUT_ENABLED: 'true',
  ARC_STRIPE_REVIEW_REVOCATION_ENABLED: 'true',
  ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET: 'stripe-review-revocation-test-secret-0123456789abcdef',
  ARC_STRIPE_REVIEW_SECRET_KEY: testSecretKey,
  ARC_STRIPE_REVERSAL_HMAC_SECRET: 'stripe-reversal-producer-test-secret-0123456789abcdef',
  ARC_STRIPE_WEBHOOK_API_VERSION: STRIPE_REVIEW_CHECKOUT_API_VERSION,
  ARC_STRIPE_WEBHOOK_SIGNING_SECRET: ['whsec', 'arc_producer_test_0123456789abcdef'].join('_'),
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'stripe-checkout-retention-fence-test-secret-0123456789abcdef',
};

const inviteHmac = hex('a');
const input = {
  approval_receipt_hmac_sha256: hex('b'),
  approval_receipt_sha256: hex('c'),
  checkout_expires_at: Math.floor(now.getTime() / 1000) + 23 * 60 * 60,
  idempotency_key: `arc_review_${createHmac('sha256', env.ARC_REVIEW_DECISION_HMAC_SECRET)
    .update(`arc-preview-checkout-idempotency-v1\n${inviteHmac}`).digest('hex')}`,
  invite_hmac_sha256: inviteHmac,
  preview_manifest_sha256: hex('d'),
  recipient_email_sha256: hex('e'),
  scope_version: 'arc-fixed-five-page-offer-v1',
};

function baseProduct() {
  return {
    active: true,
    default_price: priceId,
    id: productId,
    livemode: false,
    name: 'ARC Fixed Five-Page Website',
    object: 'product',
    shippable: false,
    tax_code: taxCodeId,
  };
}

function basePrice() {
  return {
    active: true,
    currency: 'usd',
    id: priceId,
    livemode: false,
    object: 'price',
    product: baseProduct(),
    recurring: null,
    tax_behavior: 'exclusive',
    type: 'one_time',
    unit_amount: 500_000,
  };
}

class GuardStore {
  constructor() {
    this.sequence = 0;
    this.values = new Map();
  }
  async getWithMetadata(key) {
    const value = this.values.get(key);
    return value ? { data: structuredClone(value.data), etag: value.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `checkout-guard-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { etag, modified: true };
  }
}

class CrashStore extends GuardStore {
  constructor() {
    super();
    this.failurePrefixes = [];
  }
  failNextWrite(prefix) {
    this.failurePrefixes.push(prefix);
  }
  async setJSON(key, data, options = {}) {
    const failureIndex = this.failurePrefixes.findIndex(prefix => key.startsWith(prefix));
    if (failureIndex !== -1) {
      this.failurePrefixes.splice(failureIndex, 1);
      throw new Error('SIMULATED_CHECKOUT_RESERVATION_CRASH');
    }
    return super.setJSON(key, data, options);
  }
}

function fakeStripe({ account = { id: accountId, object: 'account' }, beforeCreate,
  afterCreate, mutatePrice, mutateSession } = {}) {
  const observations = { accounts: 0, creates: [], expires: [], prices: [], retrieves: [] };
  const price = basePrice();
  mutatePrice?.(price);
  let currentSession = null;
  const client = {
    accounts: {
      retrieve: async () => {
        observations.accounts += 1;
        return structuredClone(account);
      },
    },
    checkout: {
      sessions: {
        create: async (parameters, options) => {
          observations.creates.push({ options: structuredClone(options), parameters: structuredClone(parameters) });
          await beforeCreate?.();
          const session = {
            amount_subtotal: 500_000,
            automatic_tax: { enabled: true, status: null },
            client_reference_id: parameters.client_reference_id,
            currency: 'usd',
            expires_at: parameters.expires_at,
            id: 'cs_test_ArcReviewContract',
            integration_identifier: parameters.integration_identifier,
            livemode: false,
            metadata: structuredClone(parameters.metadata),
            mode: 'payment',
            object: 'checkout.session',
            payment_link: null,
            payment_status: 'unpaid',
            status: 'open',
            ui_mode: 'hosted_page',
            url: 'https://checkout.stripe.com/c/pay/cs_test_ArcReviewContract',
          };
          mutateSession?.(session);
          currentSession = structuredClone(session);
          await afterCreate?.(currentSession);
          return session;
        },
        expire: async (sessionId, parameters, options) => {
          observations.expires.push({ sessionId, parameters: structuredClone(parameters), options: structuredClone(options) });
          if (!currentSession || currentSession.id !== sessionId) throw new Error('missing Session');
          currentSession.status = 'expired';
          currentSession.payment_status = 'unpaid';
          currentSession.url = null;
          return structuredClone(currentSession);
        },
        retrieve: async (sessionId) => {
          observations.retrieves.push(sessionId);
          if (!currentSession || currentSession.id !== sessionId) throw new Error('missing Session');
          return structuredClone(currentSession);
        },
      },
    },
    prices: {
      retrieve: async (...args) => {
        observations.prices.push(structuredClone(args));
        return structuredClone(price);
      },
    },
  };
  return {
    client,
    observations,
    remoteSession: () => structuredClone(currentSession),
    setRemoteSession: mutate => {
      if (!currentSession) throw new Error('missing Session');
      mutate(currentSession);
    },
  };
}

const readinessDeploymentSha = '7'.repeat(40);
const readinessSecret = 'review-activation-readiness-test-secret-0123456789abcdef';
const readinessDigest = label => sha256(`checkout-consumer-readiness:${label}`);
const productionReadinessEnv = {
  ...env,
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  NETLIFY_ADMIN_PAT: 'netlify-checkout-readiness-admin-pat-0123456789',
  ARC_PAYMENT_ARC2_WORKER_ENABLED: 'true',
  ARC_OPERATIONS_AUDIT_ENABLED: 'true',
  ARC_REVIEW_EMAIL_NATIVE_SUPPRESSION_ID_SHA256: readinessDigest('native-suppression-id'),
  ARC_REVIEW_EMAIL_NATIVE_WEBHOOK_ID_SHA256: readinessDigest('native-webhook-id'),
  ARC_REVIEW_EMAIL_PROVIDER: 'provider-production',
  ARC_REVIEW_EMAIL_PROVIDER_ACCOUNT_ID_SHA256: readinessDigest('email-provider-account'),
  ARC_REVIEW_EMAIL_SENDER_IDENTITY_SHA256: readinessDigest('email-sender'),
  ARC_RUNTIME_ENVIRONMENT: 'production',
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'true',
  ARC_ZAPIER_PAYMENT_ARC2_WORKFLOW_ID_SHA256: readinessDigest('payment-workflow'),
  ARC_ZAPIER_REVIEW_CHECKOUT_REVOCATION_WORKFLOW_ID_SHA256: readinessDigest('revocation-workflow'),
  ARC_ZAPIER_REVIEW_EMAIL_WORKFLOW_ID_SHA256: readinessDigest('email-workflow'),
  ARC_ZAPIER_REVIEW_REVISION_WORKFLOW_ID_SHA256: readinessDigest('revision-workflow'),
  ARC_ACTIVATION_MANIFEST_HMAC_SECRET: readinessSecret,
};
const readinessReadback = {
  schema: 'arc-review-activation-readback-v1',
  version: 1,
  mode: 'production',
  minimum_stage: 'LIVE_CHECKOUT',
  provider_controls_state: 'OFF',
  observed_at: new Date(now.getTime() - 60_000).toISOString(),
  expires_at: new Date(now.getTime() + 10 * 60_000).toISOString(),
  netlify: {
    deployment_sha: readinessDeploymentSha,
    env_name_set_readback_sha256:
      reviewActivationEnvironmentNamesSha256('production', productionReadinessEnv),
    handoff_credential_environment_name: 'NETLIFY_ADMIN_PAT',
    route_matrix_readback_sha256: reviewActivationRouteMatrixSha256(),
    route_probe_receipt_sha256: readinessDigest('route-probe'),
    site_id_sha256: sha256(productionReadinessEnv.ARC_EXPECTED_NETLIFY_SITE_ID),
  },
  stripe: {
    account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    catalog_readback_sha256: readinessDigest('stripe-catalog'),
    checkout_session_expire_capability_readback_sha256: readinessDigest('stripe-expire'),
    checkout_session_retrieve_capability_readback_sha256: readinessDigest('stripe-retrieve'),
    integration_identifier_sha256: sha256(env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER),
    price_id_sha256: sha256(priceId),
    product_id_sha256: sha256(productId),
    webhook_destination_readback_sha256: readinessDigest('stripe-webhook'),
    webhook_endpoint_path: '/internal/stripe/reversal-webhook',
    webhook_event_set_readback_sha256: reviewActivationStripeWebhookEventSetSha256(),
  },
  email: {
    native_suppression_id_sha256: productionReadinessEnv.ARC_REVIEW_EMAIL_NATIVE_SUPPRESSION_ID_SHA256,
    native_suppression_readback_sha256: readinessDigest('native-suppression-readback'),
    native_webhook_id_sha256: productionReadinessEnv.ARC_REVIEW_EMAIL_NATIVE_WEBHOOK_ID_SHA256,
    native_webhook_readback_sha256: readinessDigest('native-webhook-readback'),
    provider: productionReadinessEnv.ARC_REVIEW_EMAIL_PROVIDER,
    provider_account_id_sha256: productionReadinessEnv.ARC_REVIEW_EMAIL_PROVIDER_ACCOUNT_ID_SHA256,
    sandbox_delivery_receipt_sha256: readinessDigest('email-delivery'),
    sender_identity_sha256: productionReadinessEnv.ARC_REVIEW_EMAIL_SENDER_IDENTITY_SHA256,
  },
  operations_alert: {
    audit_enabled: true,
    delivery_enabled: false,
    failure_alert_verified: false,
    native_delivery_receipt_sha256: '0'.repeat(64),
    provider_event_type: 'email.delivered',
  },
  zapier: {
    checkout_revocation_worker_contract_receipt_sha256: readinessDigest('revocation-contract'),
    checkout_revocation_workflow_id_sha256:
      productionReadinessEnv.ARC_ZAPIER_REVIEW_CHECKOUT_REVOCATION_WORKFLOW_ID_SHA256,
    checkout_revocation_workflow_version_readback_sha256: readinessDigest('revocation-version'),
    claim_next_contract_receipt_sha256: readinessDigest('claim-next'),
    email_claim_next_path: '/api/internal/review-email/reserve',
    email_workflow_id_sha256: productionReadinessEnv.ARC_ZAPIER_REVIEW_EMAIL_WORKFLOW_ID_SHA256,
    email_workflow_version_readback_sha256: readinessDigest('email-version'),
    payment_arc2_claim_next_path: '/internal/payment-arc2/claim',
    payment_arc2_start_path: '/internal/payment-arc2/start',
    payment_arc2_start_contract_receipt_sha256: readinessDigest('payment-start-contract'),
    payment_arc2_workflow_id_sha256: productionReadinessEnv.ARC_ZAPIER_PAYMENT_ARC2_WORKFLOW_ID_SHA256,
    payment_arc2_workflow_version_readback_sha256: readinessDigest('payment-version'),
    revision_claim_next_path: '/api/internal/review-revision/claim',
    revision_workflow_id_sha256: productionReadinessEnv.ARC_ZAPIER_REVIEW_REVISION_WORKFLOW_ID_SHA256,
    revision_workflow_version_readback_sha256: readinessDigest('revision-version'),
  },
};
productionReadinessEnv.ARC_REVIEW_ACTIVATION_READBACK_JSON = JSON.stringify(readinessReadback);
const readinessEvidence = ACTIVATION_EVIDENCE_BY_STAGE.LIVE_CHECKOUT.map(kind => ({
  kind,
  receipt_ref: `proof:${sha256(kind).slice(0, 16)}`,
  sha256: kind === 'live_checkout_readback'
    ? sha256(canonicalJson(readinessReadback)) : readinessDigest(`manifest:${kind}`),
}));
productionReadinessEnv.ARC_ACTIVATION_MANIFEST = signActivationManifest({
  schema: ACTIVATION_MANIFEST_SCHEMA,
  version: ACTIVATION_MANIFEST_VERSION,
  stage: 'LIVE_CHECKOUT',
  authority_mode: 'ROLLOUT',
  issued_at: new Date(now.getTime() - 60_000).toISOString(),
  expires_at: new Date(now.getTime() + 10 * 60_000).toISOString(),
  deployment_sha: readinessDeploymentSha,
  evidence: readinessEvidence,
}, readinessSecret);

assert.equal(stripeReviewCheckoutConsumerReadiness(
  productionReadinessEnv, now, { deploymentSha: readinessDeploymentSha },
), true, 'Production consumer readiness must require a signed readback bound to the current deploy.');
for (const invalidReadiness of [
  { ...productionReadinessEnv, ARC_PAYMENT_ARC2_WORKER_ENABLED: 'false' },
  { ...productionReadinessEnv, ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'false' },
  { ...productionReadinessEnv, ARC_REVIEW_ACTIVATION_READBACK_JSON: '' },
  {
    ...productionReadinessEnv,
    ARC_REVIEW_ACTIVATION_READBACK_JSON: JSON.stringify({
      ...readinessReadback,
      observed_at: new Date(now.getTime() - 16 * 60_000).toISOString(),
      expires_at: new Date(now.getTime() - 1_000).toISOString(),
    }),
  },
  {
    ...productionReadinessEnv,
    ARC_REVIEW_ACTIVATION_READBACK_JSON: JSON.stringify({
      ...readinessReadback,
      zapier: { ...readinessReadback.zapier, payment_arc2_start_contract_receipt_sha256: '0'.repeat(64) },
    }),
  },
  {
    ...productionReadinessEnv,
    ARC_REVIEW_ACTIVATION_READBACK_JSON: JSON.stringify({
      ...readinessReadback,
      stripe: { ...readinessReadback.stripe, price_id_sha256: readinessDigest('wrong-price') },
    }),
  },
]) {
  assert.equal(stripeReviewCheckoutConsumerReadiness(
    invalidReadiness, now, { deploymentSha: readinessDeploymentSha },
  ), false);
}

assert.equal(stripeReviewCheckoutConfiguration({}).producerEnabled, false,
  'The Stripe Checkout producer must default off.');
await assert.rejects(createStripeReviewCheckout(input, {}, { stripeClient: fakeStripe().client }),
  /CHECKOUT_UNAVAILABLE_CONFIGURATION/);

const missingConsumerRuntime = {
  ...productionReadinessEnv,
  ARC_ADULT_OPERATOR_VERIFIED: 'true',
  ARC_ALLOW_TEST_MODE_EVENTS: 'false',
  ARC_BUSINESS_LICENSE_VERIFIED: 'true',
  ARC_HANDOFF_ENABLED: 'true',
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'true',
  ARC_STRIPE_LIVE_MODE_ENABLED: 'true',
  ARC_STRIPE_REVIEW_SECRET_KEY: liveSecretKey,
  ARC_TAX_REGISTRATION_VERIFIED: 'true',
  ARC_TRANSACTIONAL_EMAIL_VERIFIED: 'true',
  ARC_PAYMENT_ARC2_WORKER_SECRET: 'payment-worker-readiness-test-secret-0123456789abcdef',
  ARC_REVIEW_ACTIVATION_READBACK_JSON: '',
};
assert.equal(stripeReviewCheckoutConfiguration(missingConsumerRuntime, now).consumerReadinessValid, false);
assert.equal(stripeReviewCheckoutConfiguration({
  ...missingConsumerRuntime,
  ARC_REVIEW_ACTIVATION_READBACK_JSON: JSON.stringify(readinessReadback),
}, now).consumerReadinessValid, false,
'Production Checkout must not fall back to a current static environment receipt.');
assert.equal(stripeReviewCheckoutConfiguration(missingConsumerRuntime, now).taxReadbackRequired, true,
  'Production Checkout must re-read active Stripe Tax state before creating a Session.');
const missingConsumerProvider = fakeStripe();
await assert.rejects(createStripeReviewCheckout(input, missingConsumerRuntime, {
  clock: () => new Date(now), store: new GuardStore(), stripeClient: missingConsumerProvider.client,
}), /CHECKOUT_UNAVAILABLE_CONFIGURATION/);
assert.equal(missingConsumerProvider.observations.accounts, 0,
  'A missing production consumer receipt must fail before any Stripe read.');
assert.equal(missingConsumerProvider.observations.creates.length, 0);

const activeTaxSettings = {
  object: 'tax.settings',
  head_office: { address: { country: 'US' } },
  livemode: true,
  status: 'active',
};
const activeTaxRegistrations = {
  object: 'list',
  has_more: false,
  data: [{
    active_from: Math.floor(now.getTime() / 1000) - 60,
    country: 'US',
    country_options: {
      us: {
        state: 'WA',
        type: 'state_sales_tax',
      },
    },
    expires_at: null,
    id: 'taxreg_ArcLiveTaxContract',
    livemode: true,
    object: 'tax.registration',
    status: 'active',
  }],
};
assert.doesNotThrow(() => validateStripeReviewTaxReadiness(
  activeTaxSettings, activeTaxRegistrations, true, now,
));
for (const [settings, registrations] of [
  [{ ...activeTaxSettings, status: 'pending' }, activeTaxRegistrations],
  [{ ...activeTaxSettings, head_office: { address: {} } }, activeTaxRegistrations],
  [activeTaxSettings, { ...activeTaxRegistrations, data: [] }],
  [activeTaxSettings, { ...activeTaxRegistrations, has_more: true }],
  [activeTaxSettings, {
    ...activeTaxRegistrations,
    data: [{ ...activeTaxRegistrations.data[0], livemode: false }],
  }],
  [activeTaxSettings, {
    ...activeTaxRegistrations,
    data: [{
      ...activeTaxRegistrations.data[0],
      country: 'CA',
      country_options: { ca: { type: 'simplified' } },
    }],
  }],
  [activeTaxSettings, {
    ...activeTaxRegistrations,
    data: [{
      ...activeTaxRegistrations.data[0],
      country_options: { us: { state: 'OR', type: 'state_sales_tax' } },
    }],
  }],
  [activeTaxSettings, {
    ...activeTaxRegistrations,
    data: [{
      ...activeTaxRegistrations.data[0],
      country_options: { us: { state: 'WA', type: 'state_retail_delivery_fee' } },
    }],
  }],
  [activeTaxSettings, {
    ...activeTaxRegistrations,
    data: [{ ...activeTaxRegistrations.data[0], country_options: {} }],
  }],
  [activeTaxSettings, {
    ...activeTaxRegistrations,
    data: [{
      ...activeTaxRegistrations.data[0],
      active_from: Math.floor(now.getTime() / 1000) + 60,
      status: 'scheduled',
    }],
  }],
  [activeTaxSettings, {
    ...activeTaxRegistrations,
    data: [{
      ...activeTaxRegistrations.data[0],
      expires_at: Math.floor(now.getTime() / 1000),
    }],
  }],
]) {
  assert.throws(() => validateStripeReviewTaxReadiness(settings, registrations, true, now),
    /CHECKOUT_UNAVAILABLE_TAX_READBACK/);
}

const valid = fakeStripe();
const validStore = new GuardStore();
let factoryKey;
let factoryOptions;
const created = await createStripeReviewCheckout(input, env, {
  clock: () => new Date(now),
  store: validStore,
  stripeFactory: (key, options) => {
    factoryKey = key;
    factoryOptions = structuredClone(options);
    return valid.client;
  },
});
assert.equal(created.id, 'cs_test_ArcReviewContract');
assert.equal(created.url, 'https://checkout.stripe.com/c/pay/cs_test_ArcReviewContract');
assert.equal(factoryKey, env.ARC_STRIPE_REVIEW_SECRET_KEY);
assert.deepEqual(factoryOptions, {
  apiVersion: STRIPE_REVIEW_CHECKOUT_API_VERSION,
  maxNetworkRetries: 2,
  timeout: 10_000,
});
assert.equal(valid.observations.accounts, 1);
assert.deepEqual(valid.observations.prices, [[priceId, { expand: ['product'] }]]);
assert.equal(valid.observations.creates.length, 1);
const request = valid.observations.creates[0];
assert.deepEqual(request.options, { idempotencyKey: input.idempotency_key });
assert.equal('payment_method_types' in request.parameters, false,
  'Checkout must use Dashboard-managed dynamic payment methods.');
assert.equal('payment_method_configuration' in request.parameters, false);
assert.equal(request.parameters.ui_mode, 'hosted_page');
assert.equal(request.parameters.expires_at, input.checkout_expires_at,
  'Each private Session must have one deterministic approval-bound expiration.');
assert.equal(request.parameters.client_reference_id, input.approval_receipt_sha256,
  'The Session reconciliation reference must bind the durable approval receipt.');
assert.equal(request.parameters.integration_identifier, env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER);
assert.deepEqual(request.parameters.line_items, [{ price: priceId, quantity: 1 }]);
assert.deepEqual(request.parameters.automatic_tax, { enabled: true });
assert.equal('billing_address_collection' in request.parameters, false,
  'Checkout should collect only the address inputs automatic tax needs.');
assert.deepEqual(request.parameters.consent_collection, { terms_of_service: 'required' });
assert.equal(request.parameters.allow_promotion_codes, false);
assert.equal(request.parameters.invoice_creation.enabled, false);
assert.equal(request.parameters.phone_number_collection.enabled, false);
assert.equal(request.parameters.custom_fields.length, 1);
assert.equal(request.parameters.custom_fields[0].key, 'adultpurchaserack');
assert.deepEqual(request.parameters.custom_fields[0].dropdown.options,
  [{ label: 'I confirm I am 18+ and authorized to purchase.', value: 'accepted' }]);
assert.equal(request.parameters.metadata.schema, STRIPE_REVIEW_CHECKOUT_SCHEMA);
assert.equal(request.parameters.metadata.approval_receipt_sha256, input.approval_receipt_sha256);
assert.deepEqual(request.parameters.payment_intent_data.metadata, request.parameters.metadata);

const replay = await createStripeReviewCheckout(input, env, {
  stripeClient: valid.client, store: validStore, clock: () => new Date(now),
});
assert.equal(replay.url, created.url);
assert.equal(valid.observations.creates[1].options.idempotencyKey,
  valid.observations.creates[0].options.idempotencyKey,
  'Provider retries must converge on one deterministic idempotency key.');
assert.equal(valid.observations.creates[1].parameters.integration_identifier,
  valid.observations.creates[0].parameters.integration_identifier,
  'The configured integration identifier must remain stable across Sessions.');

await assert.rejects(createStripeReviewCheckout({ ...input, idempotency_key: `arc_review_${hex('f')}` }, env,
  { stripeClient: fakeStripe().client, store: new GuardStore(), clock: () => new Date(now) }), /idempotency binding is invalid/i);
await assert.rejects(createStripeReviewCheckout({ ...input, unexpected: true }, env,
  { stripeClient: fakeStripe().client, store: new GuardStore(), clock: () => new Date(now) }), /binding is invalid/i);
for (const checkoutExpiresAt of [
  Math.floor(now.getTime() / 1000),
  Math.floor(now.getTime() / 1000) + 24 * 60 * 60 + 1,
]) {
  const blocked = fakeStripe();
  await assert.rejects(createStripeReviewCheckout({
    ...input,
    checkout_expires_at: checkoutExpiresAt,
  }, env, {
    stripeClient: blocked.client, store: new GuardStore(), clock: () => new Date(now),
  }), /Session expiration is invalid/);
  assert.equal(blocked.observations.accounts, 0,
    'An invalid Session lifetime must fail before any Stripe read.');
  assert.equal(blocked.observations.creates.length, 0,
    'An invalid Session lifetime must fail before any Stripe write.');
}

for (const invalidEnvironment of [
  { ARC_PAYMENT_ARC2_BRIDGE_ENABLED: 'false' },
  { ARC_STRIPE_REVIEW_CHECKOUT_ENABLED: 'false' },
  { ARC_STRIPE_LIVE_MODE_ENABLED: 'true' },
  { ARC_STRIPE_REVIEW_SECRET_KEY: liveSecretKey },
  { ARC_STRIPE_CHECKOUT_SUCCESS_URL: 'https://evil.example/review/?checkout=success&session_id={CHECKOUT_SESSION_ID}' },
  { ARC_STRIPE_CHECKOUT_SUCCESS_URL: 'https://arcweb.onl/review/?checkout=success&session_id={CHECKOUT_SESSION_ID}' },
  { ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER: 'arc_review_checkout_short' },
  { ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER: 'arc_review_checkout_abcdefghi' },
  { ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER: 'arc_review_checkout_ABCDEFGH' },
  { ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER: 'other_review_checkout_abcdefgh' },
  { ARC_EXPECTED_PRODUCT_NAME: 'ARC Website Deposit' },
  { ARC_STRIPE_CHECKOUT_LEDGER_ENABLED: 'false' },
  { ARC_REVIEW_CHECKOUT_ENABLED: 'false' },
]) {
  const blocked = fakeStripe();
  await assert.rejects(createStripeReviewCheckout(input, { ...env, ...invalidEnvironment }, {
    stripeClient: blocked.client, clock: () => new Date(now),
  }), /CHECKOUT_UNAVAILABLE_CONFIGURATION/);
  assert.equal(blocked.observations.accounts, 0, 'Invalid configuration must fail before provider reads.');
  assert.equal(blocked.observations.creates.length, 0, 'Invalid configuration must fail before provider writes.');
}

assert.equal(stripeReviewCheckoutConfiguration({
  ...env,
  ARC_STRIPE_REVIEW_SECRET_KEY: stripeKey('rk', 'test', 'arc_review_checkout_0123456789abcdef'),
}).producerEnabled, true, 'A least-privilege restricted Stripe key must be supported.');

for (const mutatePrice of [
  price => { price.active = false; },
  price => { price.livemode = true; },
  price => { price.type = 'recurring'; price.recurring = { interval: 'month' }; },
  price => { price.currency = 'cad'; },
  price => { price.unit_amount = 499_999; },
  price => { price.tax_behavior = 'inclusive'; },
  price => { price.product.id = 'prod_WrongCatalogBinding'; },
  price => { price.product.active = false; },
  price => { price.product.name = 'ARC Website Deposit'; },
  price => { price.product.default_price = 'price_WrongCatalogBinding'; },
  price => { price.product.tax_code = 'txcd_99999999'; },
]) {
  const blocked = fakeStripe({ mutatePrice });
  await assert.rejects(createStripeReviewCheckout(input, env, {
    stripeClient: blocked.client, store: new GuardStore(), clock: () => new Date(now),
  }), /CHECKOUT_UNAVAILABLE_CATALOG_BINDING/);
  assert.equal(blocked.observations.creates.length, 0, 'A mismatched catalog must never create a Session.');
}

const wrongAccount = fakeStripe({ account: { id: 'acct_WrongSandboxContract', object: 'account' } });
await assert.rejects(createStripeReviewCheckout(input, env, {
  stripeClient: wrongAccount.client, store: new GuardStore(), clock: () => new Date(now),
}), /CHECKOUT_UNAVAILABLE_ACCOUNT_BINDING/);
assert.equal(wrongAccount.observations.creates.length, 0);

for (const mutateSession of [
  session => { session.id = 'cs_live_ArcReviewContract'; },
  session => { session.mode = 'subscription'; },
  session => { session.ui_mode = 'embedded_page'; },
  session => { session.livemode = true; },
  session => { session.payment_link = 'plink_ArcReusableLink'; },
  session => { session.status = 'complete'; },
  session => { session.payment_status = 'paid'; },
  session => { session.amount_subtotal = 100; },
  session => { session.expires_at += 1; },
  session => { session.client_reference_id = input.invite_hmac_sha256; },
  session => { session.integration_identifier = 'arc_review_checkout_asdfghjk'; },
  session => { delete session.integration_identifier; },
  session => { session.metadata.preview_manifest_sha256 = hex('f'); },
  session => { session.url = 'https://evil.example/c/pay/cs_test_ArcReviewContract'; },
]) {
  const blocked = fakeStripe({ mutateSession });
  await assert.rejects(createStripeReviewCheckout(input, env, {
    stripeClient: blocked.client, store: new GuardStore(), clock: () => new Date(now),
  }), /CHECKOUT_UNAVAILABLE_PROVIDER_RESPONSE/);
  assert.equal(blocked.observations.creates.length, 1);
}

function raceInput(label, recipientLabel = label, recipientDigest = null) {
  const invite = sha256(`checkout-race-invite:${label}`);
  return {
    approval_receipt_hmac_sha256: sha256(`checkout-race-approval-hmac:${label}`),
    approval_receipt_sha256: sha256(`checkout-race-approval:${label}`),
    checkout_expires_at: Math.floor(now.getTime() / 1000) + 23 * 60 * 60,
    idempotency_key: `arc_review_${createHmac('sha256', env.ARC_REVIEW_DECISION_HMAC_SECRET)
      .update(`arc-preview-checkout-idempotency-v1\n${invite}`).digest('hex')}`,
    invite_hmac_sha256: invite,
    preview_manifest_sha256: sha256(`checkout-race-preview:${label}`),
    recipient_email_sha256: recipientDigest || sha256(`checkout-race-recipient:${recipientLabel}`),
    scope_version: 'arc-fixed-five-page-offer-v1',
  };
}

function complaintFor(value, label) {
  return {
    recipient_email_sha256: value.recipient_email_sha256,
    suppression_receipt_sha256: sha256(`checkout-race-complaint:${label}`),
    suppression_status: 'complained',
    suppressed_at: now.toISOString(),
    source_invite_hmac_sha256: value.invite_hmac_sha256,
    source_outbox_hmac_sha256: sha256(`checkout-race-outbox:${label}`),
  };
}

// Binding creation must precede recipient-index publication. A crash on the
// first binding write cannot leave the old index -> missing-binding orphan.
{
  const value = raceInput('binding-first-crash');
  const store = new CrashStore();
  const provider = fakeStripe();
  store.failNextWrite('review-checkout-binding/');
  await assert.rejects(createStripeReviewCheckout(value, env, {
    clock: () => new Date(now), store, stripeClient: provider.client,
  }), /SIMULATED_CHECKOUT_RESERVATION_CRASH/);
  assert.equal([...store.values.keys()].some(key => key.startsWith('review-checkout-binding/')), false);
  assert.equal([...store.values.keys()].some(key => key.startsWith('review-checkout-recipient-index/')), false,
    'An index must never publish before its binding exists.');
  assert.equal(provider.observations.creates.length, 0);
}

// A crash after durable CREATING but before index publication is recoverable:
// retry converges the missing index before the sole provider create call.
{
  const value = raceInput('index-recovery-crash');
  const store = new CrashStore();
  const provider = fakeStripe();
  store.failNextWrite('review-checkout-recipient-index/');
  await assert.rejects(createStripeReviewCheckout(value, env, {
    clock: () => new Date(now), store, stripeClient: provider.client,
  }), /SIMULATED_CHECKOUT_RESERVATION_CRASH/);
  assert.equal([...store.values.keys()].some(key => key.startsWith('review-checkout-binding/')), true);
  assert.equal([...store.values.keys()].some(key => key.startsWith('review-checkout-recipient-index/')), false);
  assert.equal(provider.observations.creates.length, 0,
    'Stripe must not be called until binding and recipient index both converge.');
  const recovered = await createStripeReviewCheckout(value, env, {
    clock: () => new Date(now), store, stripeClient: provider.client,
  });
  assert.match(recovered.url, /^https:\/\/checkout\.stripe\.com\//);
  assert.equal(provider.observations.creates.length, 1);
  const indexed = await listReviewCheckoutBindingsForRecipient(store,
    value.recipient_email_sha256, env);
  assert.equal(indexed.complete, true);
  assert.equal(indexed.records.length, 1);
  assert.equal(indexed.records[0].state, 'OPEN');
}

// If suppression wins while the harmless unindexed CREATING orphan exists,
// revocation discovery is complete (there is no provider Session), checkout
// retry remains blocked, and the recipient is never permanently stuck on an
// index entry whose target is missing.
{
  const value = raceInput('unindexed-suppression-crash');
  const store = new CrashStore();
  const provider = fakeStripe();
  store.failNextWrite('review-checkout-recipient-index/');
  await assert.rejects(createStripeReviewCheckout(value, env, {
    clock: () => new Date(now), store, stripeClient: provider.client,
  }), /SIMULATED_CHECKOUT_RESERVATION_CRASH/);
  const complaint = complaintFor(value, 'unindexed-suppression-crash');
  await suppressReviewEmailRecipientControl(store, complaint, env, now);
  assert.deepEqual(await expireSuppressedRecipientReviewCheckouts(store, complaint, env, {
    clock: () => new Date(now), stripeClient: provider.client,
  }), { complete: true, pending: false, revoked: 0 });
  await assert.rejects(createStripeReviewCheckout(value, env, {
    clock: () => new Date(now), store, stripeClient: provider.client,
  }), /RECIPIENT_SUPPRESSED/);
  assert.equal(provider.observations.creates.length, 0);
}

// Complaint committed before authorization: provider access must never begin.
{
  const value = raceInput('before-create');
  const store = new GuardStore();
  const provider = fakeStripe();
  await suppressReviewEmailRecipientControl(store, complaintFor(value, 'before-create'), env, now);
  await assert.rejects(createStripeReviewCheckout(value, env, {
    clock: () => new Date(now), store, stripeClient: provider.client,
  }), /RECIPIENT_SUPPRESSED/);
  assert.equal(provider.observations.accounts, 0);
  assert.equal(provider.observations.creates.length, 0);
}

// A process can disappear after Stripe commits the idempotent create but before
// the raw Session id is bound. Once suppression wins after the abandoned lease,
// retry may replay only that exact idempotent create, bind it, expire it, verify
// it, and still must never return the Checkout URL.
{
  const recoveryRecipientEmail = 'post-provider-pre-bind@example.test';
  const value = raceInput('post-provider-pre-bind-crash', 'post-provider-pre-bind-crash',
    sha256(recoveryRecipientEmail));
  const store = new CrashStore();
  const recoveryInviteToken = 'K'.repeat(43);
  const recoveryEmail = await prepareReviewInviteEmail(store, {
    brief_sha256: hex('1'),
    expires_at: new Date(now.getTime() + 24 * 60 * 60_000).toISOString(),
    invite_token: recoveryInviteToken,
    page_bindings: [
      'about/index.html', 'contact/index.html', 'index.html', 'process/index.html', 'services/index.html',
    ].map((path, index) => ({ path, sha256: String(index + 2).repeat(64) })),
    preview_content_sha256: hex('7'),
    preview_manifest_sha256: hex('8'),
    preview_source_commit_sha: 'f'.repeat(40),
    preview_source_repository: 'arcwebhq-cpu/arc-previews',
    preview_url: 'https://arcwebhq-cpu.github.io/arc-previews/recovery-source/',
    prior_invite_hmac_sha256: null,
    recipient_email_sha256: value.recipient_email_sha256,
    scope_version: 'arc-fixed-five-page-offer-v1',
  }, env, { clock: () => new Date(now) });
  await reserveReviewEmailSend(store, {
    invite_token: recoveryInviteToken,
    recipient_email: recoveryRecipientEmail,
  }, env, { clock: () => new Date(now) });
  let crashInjected = false;
  const provider = fakeStripe({
    afterCreate: async () => {
      if (crashInjected) return;
      crashInjected = true;
      store.failNextWrite('review-checkout-binding/');
      store.failNextWrite('review-email-recipient-control/');
    },
  });
  await assert.rejects(createStripeReviewCheckout(value, env, {
    clock: () => new Date(now), store, stripeClient: provider.client,
  }), /SIMULATED_CHECKOUT_RESERVATION_CRASH/);
  assert.equal(provider.observations.creates.length, 1);
  assert.equal(provider.remoteSession().status, 'open');
  const orphan = await listReviewCheckoutBindingsForRecipient(store,
    value.recipient_email_sha256, env);
  assert.equal(orphan.records[0].state, 'CREATING');
  assert.equal(orphan.records[0].session_id, null);

  const recoveryTime = new Date(now.getTime() + 61_000);
  const recoveryReceipt = {
    schema: reviewEmailReceiptContract.schema,
    version: reviewEmailReceiptContract.version,
    outbox_hmac_sha256: recoveryEmail.outbox.outbox_hmac_sha256,
    invite_hmac_sha256: recoveryEmail.invite.invite_hmac_sha256,
    recipient_email_sha256: value.recipient_email_sha256,
    preview_manifest_sha256: recoveryEmail.invite.preview_manifest_sha256,
    provider: 'provider-test',
    provider_account_hmac_sha256: hex('a'),
    provider_event_id: 'event-post-provider-pre-bind-crash',
    provider_message_id: 'message-post-provider-pre-bind-crash',
    event_type: 'message.complained',
    delivery_status: 'complained',
    event_at: recoveryTime.toISOString(),
    issued_at: recoveryTime.toISOString(),
  };
  const recoveryEvidence = canonicalJson(recoveryReceipt);
  const recoveryReceiptSignature = createHmac('sha256', env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET)
    .update(reviewEmailReceiptContract.signaturePrefix + recoveryEvidence).digest('hex');
  const recoveryBody = JSON.stringify({
    delivery_receipt_evidence: recoveryEvidence,
    delivery_receipt_evidence_hmac_sha256: recoveryReceiptSignature,
  });
  const recoveryRequestSignature = signReviewEmailInternalRequest({
    body: recoveryBody,
    method: 'POST',
    path: '/api/internal/review-email/ack',
    timestamp: recoveryTime.toISOString(),
  }, env.ARC_REVIEW_EMAIL_INTERNAL_API_SECRET);
  const ackEnvironmentKeys = Object.keys(env);
  const ackSavedEnvironment = Object.fromEntries(
    ackEnvironmentKeys.map(key => [key, process.env[key]]),
  );
  Object.assign(process.env, env);
  const recoveryResponse = await reviewEmailAckHandler(new Request(
    'https://arcweb.onl/api/internal/review-email/ack', {
      body: recoveryBody,
      headers: {
        'content-type': 'application/json',
        'x-arc-review-email-signature': recoveryRequestSignature,
        'x-arc-review-email-timestamp': recoveryTime.toISOString(),
      },
      method: 'POST',
    },
  ), {
    clock: () => new Date(recoveryTime),
    retentionFenceStore: new GuardStore(),
    reviewStore: store,
    stripeRevocationClient: provider.client,
  });
  for (const key of ackEnvironmentKeys) {
    if (ackSavedEnvironment[key] === undefined) delete process.env[key];
    else process.env[key] = ackSavedEnvironment[key];
  }
  assert.equal(recoveryResponse.status, 200, await recoveryResponse.clone().text());
  const recoveryResult = await recoveryResponse.json();
  assert.equal(recoveryResult.state, 'COMPLAINED');
  assert.equal(JSON.stringify(recoveryResult).includes('checkout.stripe.com'), false,
    'Suppression recovery must never expose the replayed Checkout URL.');
  assert.equal(provider.observations.creates.length, 2,
    'ACK recovery must replay the exact Stripe idempotency request once.');
  assert.equal(provider.observations.creates[1].options.idempotencyKey,
    provider.observations.creates[0].options.idempotencyKey);
  assert.deepEqual(provider.observations.creates[1].parameters,
    provider.observations.creates[0].parameters);
  assert.equal(provider.observations.expires.length, 1);
  assert.equal(provider.remoteSession().status, 'expired');
  assert.equal(provider.remoteSession().url, null);
  const recovered = await listReviewCheckoutBindingsForRecipient(store,
    value.recipient_email_sha256, env);
  assert.equal(recovered.records[0].state, 'EXPIRED');
  assert.equal(recovered.records[0].fulfillment_halted, true);
}

// Complaint attached while Stripe is creating: the returned Session is durably bound,
// expired and verified, and its URL is never returned to the caller.
{
  let releaseCreate;
  let reachedCreate;
  const reached = new Promise(resolve => { reachedCreate = resolve; });
  const released = new Promise(resolve => { releaseCreate = resolve; });
  const value = raceInput('during-create');
  const store = new GuardStore();
  const provider = fakeStripe({
    afterCreate: async () => {
      reachedCreate();
      await released;
    },
  });
  const creating = createStripeReviewCheckout(value, env, {
    clock: () => new Date(now), store, stripeClient: provider.client,
  });
  await reached;
  const pending = await suppressReviewEmailRecipientControl(
    store, complaintFor(value, 'during-create'), env, now,
  );
  assert.equal(pending.pending, true);
  releaseCreate();
  await assert.rejects(creating, /RECIPIENT_SUPPRESSED/);
  assert.equal(provider.observations.expires.length, 1);
  assert.equal(provider.remoteSession().status, 'expired');
  assert.equal(provider.remoteSession().url, null);
  const bound = await listReviewCheckoutBindingsForRecipient(store, value.recipient_email_sha256, env);
  assert.equal(bound.records[0].state, 'EXPIRED');
  assert.equal(bound.records[0].fulfillment_halted, true);
}

// Complaint after a URL was returned: every open bound Session is retrieved,
// expired with a deterministic key, retrieved again, then marked unusable.
{
  const value = raceInput('after-create');
  const store = new GuardStore();
  const provider = fakeStripe();
  const returned = await createStripeReviewCheckout(value, env, {
    clock: () => new Date(now), store, stripeClient: provider.client,
  });
  assert.match(returned.url, /^https:\/\/checkout\.stripe\.com\//);
  const complaint = complaintFor(value, 'after-create');
  const suppressed = await suppressReviewEmailRecipientControl(store, complaint, env, now);
  assert.equal(suppressed.pending, false);
  const revoked = await expireSuppressedRecipientReviewCheckouts(store, complaint, env, {
    clock: () => new Date(now), stripeClient: provider.client,
  });
  assert.deepEqual(revoked, { complete: true, pending: false, revoked: 1 });
  assert.equal(provider.observations.expires.length, 1);
  assert.ok(provider.observations.retrieves.length >= 2);
  assert.equal(provider.remoteSession().status, 'expired');
  await assert.rejects(
    assertReviewCheckoutFulfillmentAllowed(store, value.approval_receipt_sha256, env),
    /REVIEW_REQUIRED/,
  );
}

// A paid race is never called revoked: fulfillment halts and a durable refund/manual-review
// alert is created because Checkout can no longer be expired.
{
  const value = raceInput('paid-race');
  const store = new GuardStore();
  const provider = fakeStripe();
  await createStripeReviewCheckout(value, env, {
    clock: () => new Date(now), store, stripeClient: provider.client,
  });
  provider.setRemoteSession(session => {
    session.status = 'complete';
    session.payment_status = 'paid';
    session.url = null;
  });
  const complaint = complaintFor(value, 'paid-race');
  await suppressReviewEmailRecipientControl(store, complaint, env, now);
  await assert.rejects(expireSuppressedRecipientReviewCheckouts(store, complaint, env, {
    clock: () => new Date(now), stripeClient: provider.client,
  }), /REFUND_REVIEW_REQUIRED/);
  assert.equal(provider.observations.expires.length, 0);
  const bound = await listReviewCheckoutBindingsForRecipient(store, value.recipient_email_sha256, env);
  assert.equal(bound.records[0].state, 'REVIEW_REQUIRED');
  assert.equal(bound.records[0].alert_code, 'REFUND_REVIEW_REQUIRED');
  assert.equal(bound.records[0].fulfillment_halted, true);
  assert.ok([...store.values.keys()].some(key => key.startsWith('review-checkout-revocation-alert/')));
  await assert.rejects(
    assertReviewCheckoutFulfillmentAllowed(store, value.approval_receipt_sha256, env),
    /REVIEW_REQUIRED/,
  );
}

class FakeStore {
  constructor() {
    this.sequence = 0;
    this.values = new Map();
  }
  async getWithMetadata(key) {
    const value = this.values.get(key);
    return value ? { data: structuredClone(value.data), etag: value.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `checkout-producer-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { etag, modified: true };
  }
}

const reviewStore = new FakeStore();
const inviteToken = 'P'.repeat(43);
const recipientEmail = 'producer-checkout@example.test';
const prepared = await prepareReviewInviteEmail(reviewStore, {
  brief_sha256: hex('1'),
  expires_at: new Date(now.getTime() + 24 * 60 * 60_000).toISOString(),
  invite_token: inviteToken,
  page_bindings: [
    'about/index.html', 'contact/index.html', 'index.html', 'process/index.html', 'services/index.html',
  ].map((path, index) => ({ path, sha256: String(index + 3).repeat(64) })),
  preview_content_sha256: hex('8'),
  preview_manifest_sha256: hex('9'),
  preview_source_commit_sha: 'a'.repeat(40),
  preview_source_repository: 'arcwebhq-cpu/arc-previews',
  preview_url: 'https://arcwebhq-cpu.github.io/arc-previews/producer-contract-a1b2c3d4/',
  recipient_email_sha256: sha256(recipientEmail),
  scope_version: 'arc-fixed-five-page-offer-v1',
}, env, { clock: () => new Date(now) });
await reserveReviewEmailSend(reviewStore, {
  invite_token: inviteToken,
  recipient_email: recipientEmail,
}, env, { clock: () => new Date(now) });
const deliveredReceipt = {
  schema: reviewEmailReceiptContract.schema,
  version: reviewEmailReceiptContract.version,
  outbox_hmac_sha256: prepared.outbox.outbox_hmac_sha256,
  invite_hmac_sha256: prepared.invite.invite_hmac_sha256,
  recipient_email_sha256: prepared.invite.recipient_email_sha256,
  preview_manifest_sha256: prepared.invite.preview_manifest_sha256,
  provider: 'provider-test',
  provider_account_hmac_sha256: hex('2'),
  provider_event_id: 'producer-checkout-delivered-event',
  provider_message_id: 'producer-checkout-delivered-message',
  event_type: 'message.delivered',
  delivery_status: 'delivered',
  event_at: new Date(now.getTime() + 1_000).toISOString(),
  issued_at: new Date(now.getTime() + 2_000).toISOString(),
};
const deliveredEvidence = canonicalJson(deliveredReceipt);
const deliveredSignature = createHmac('sha256', env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET)
  .update(reviewEmailReceiptContract.signaturePrefix + deliveredEvidence).digest('hex');
await acknowledgeReviewEmailReceipt(reviewStore, deliveredEvidence, deliveredSignature, env, {
  clock: () => new Date(now.getTime() + 2_000),
});
const exchanged = await exchangeReviewInvite(reviewStore, inviteToken, env, {
  clock: () => new Date(now.getTime() + 3_000), randomBytes: () => Buffer.alloc(32, 31),
});
const reviewStatus = await readReviewStatus(
  reviewStore, exchanged.session_token, env, new Date(now.getTime() + 3_000),
);
await decideReview(reviewStore, exchanged.session_token, {
  action: 'APPROVE_AND_PAY',
  expected_revision: reviewStatus.record_revision,
  idempotency_key: '12345678-1234-4234-8234-123456789abc',
}, env, { clock: () => new Date(now.getTime() + 3_000) });

const environmentKeys = Object.keys(env);
const savedEnvironment = Object.fromEntries(environmentKeys.map(key => [key, process.env[key]]));
Object.assign(process.env, env);
const runtimeStripe = fakeStripe();
const response = await reviewCheckoutHandler(new Request('https://arcweb.onl/api/review/checkout', {
  body: '{}',
  headers: {
    'Content-Type': 'application/json',
    Cookie: `__Host-arc_review_session=${exchanged.session_token}`,
    Origin: 'https://arcweb.onl',
  },
  method: 'POST',
}), {
  clock: () => new Date(now),
  retentionFenceStore: new GuardStore(),
  reviewStore,
  stripeClient: runtimeStripe.client,
});
assert.equal(response.status, 200, await response.clone().text());
assert.equal((await response.json()).checkout_url,
  'https://checkout.stripe.com/c/pay/cs_test_ArcReviewContract');
assert.equal(runtimeStripe.observations.creates.length, 1,
  'The handler must use the default reviewed Stripe adapter without a createCheckout injection.');
for (const key of environmentKeys) {
  if (savedEnvironment[key] === undefined) delete process.env[key];
  else process.env[key] = savedEnvironment[key];
}

console.log('Stripe review Checkout producer contract passed.');
