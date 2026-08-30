import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import Stripe from 'stripe';

import { ACTIVATION_BUILD_IDENTITY } from './activation-build-identity.mjs';
import {
  ACTIVATION_MANIFEST_ENV,
  ACTIVATION_MANIFEST_SECRET_ENV,
  ACTIVATION_NEXT_MANIFEST_ENV,
  validateActivationManifest,
  validateActivationManifestEnvironment,
} from './activation-manifest-core.mjs';
import { paymentArc2BridgeConfiguration } from './payment-arc2-bridge-core.mjs';
import {
  acquireReviewEmailRecipientAuthority,
  readReviewEmailRecipientControl,
  releaseReviewEmailRecipientAuthority,
} from './review-email-recipient-control-core.mjs';
import {
  bindReviewCheckoutSession,
  listReviewCheckoutBindingsForRecipient,
  markReviewCheckoutExpired,
  markReviewCheckoutManualReview,
  requestReviewCheckoutRevocation,
  reserveReviewCheckoutBinding,
  reviewCheckoutExpiryIdempotencyKey,
  reviewCheckoutRevocationConfiguration,
} from './review-checkout-revocation-core.mjs';
import {
  REVIEW_ACTIVATION_ROUTE_MATRIX_SHA256,
  REVIEW_ACTIVATION_STRIPE_WEBHOOK_EVENT_SET_SHA256,
  ensureReviewActivationRuntimeReadback,
  reviewActivationRuntimeEnvironmentNamesSha256,
  reviewActivationRuntimeReadbackConfiguration,
  selectedNetlifyCredentialName,
} from './review-activation-runtime-readback-core.mjs';
import { reviewPortalConfiguration } from './review-flow-core.mjs';
import { stripeAccountVerificationConfigured } from './stripe-account-verification.mjs';
import { ARC_STRIPE_API_VERSION } from './stripe-api-version.mjs';
import { stripeCheckoutConfiguration } from './stripe-checkout-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const STRIPE_REVIEW_CHECKOUT_API_VERSION = ARC_STRIPE_API_VERSION;
export const STRIPE_REVIEW_CHECKOUT_SCHEMA = 'arc-review-checkout-session-v1';

const CHECKOUT_IDEMPOTENCY_PREFIX = 'arc-preview-checkout-idempotency-v1\n';
const OFFER_CONTRACT_ID = 'arc-fixed-five-page-offer-v1';
const TERMS_VERSION = '2026-08-25';
const PRODUCT_NAME = 'ARC Fixed Five-Page Website';
const CHECKOUT_ORIGIN = 'https://checkout.stripe.com';
const SUBTOTAL_MINOR_UNITS = 500_000;
const HEX_64 = /^[a-f0-9]{64}$/;
const ACCOUNT_ID = /^acct_[A-Za-z0-9]{6,128}$/;
const PRICE_ID = /^price_[A-Za-z0-9_]{6,128}$/;
const PRODUCT_ID = /^prod_[A-Za-z0-9_]{6,128}$/;
const TAX_CODE_ID = /^txcd_[0-9]{8}$/;
const RESTRICTED_KEY = /^rk_(test|live)_[A-Za-z0-9_]{16,240}$/;
const SESSION_ID = /^cs_(test|live)_[A-Za-z0-9_]{6,128}$/;
const INTEGRATION_IDENTIFIER = /^arc_review_checkout_[a-z]{8}$/;
const DEPLOYMENT_SHA = /^[a-f0-9]{40}$/;
const READBACK_MAXIMUM_AGE_MS = 15 * 60_000;
const SANDBOX_RETURN_ORIGINS = new Set([
  'https://arc2-sandbox.netlify.app',
  'https://arcweb.onl',
  'https://arcsites.netlify.app',
]);
const PRODUCTION_RETURN_ORIGINS = new Set(['https://arcweb.onl']);
const INPUT_KEYS = Object.freeze([
  'approval_receipt_hmac_sha256',
  'approval_receipt_sha256',
  'checkout_expires_at',
  'idempotency_key',
  'invite_hmac_sha256',
  'preview_manifest_sha256',
  'recipient_email_sha256',
  'scope_version',
]);
const METADATA_KEYS = Object.freeze([
  'approval_receipt_hmac_sha256',
  'approval_receipt_sha256',
  'invite_hmac_sha256',
  'offer_contract_id',
  'preview_manifest_sha256',
  'recipient_email_sha256',
  'schema',
  'scope_version',
  'terms_version',
]);
const READBACK_TOP_FIELDS = Object.freeze([
  'schema', 'version', 'mode', 'minimum_stage', 'provider_controls_state', 'observed_at',
  'expires_at', 'netlify', 'stripe', 'email', 'operations_alert', 'zapier',
]);
const READBACK_NETLIFY_FIELDS = Object.freeze([
  'deployment_sha', 'env_name_set_readback_sha256', 'route_matrix_readback_sha256',
  'route_probe_receipt_sha256', 'site_id_sha256', 'handoff_credential_environment_name',
]);
const READBACK_STRIPE_FIELDS = Object.freeze([
  'account_id_sha256', 'catalog_readback_sha256',
  'checkout_session_expire_capability_readback_sha256',
  'checkout_session_retrieve_capability_readback_sha256', 'integration_identifier_sha256',
  'price_id_sha256', 'product_id_sha256', 'webhook_destination_readback_sha256',
  'webhook_endpoint_path', 'webhook_event_set_readback_sha256',
]);
const READBACK_EMAIL_FIELDS = Object.freeze([
  'native_suppression_id_sha256', 'native_suppression_readback_sha256',
  'native_webhook_id_sha256', 'native_webhook_readback_sha256', 'provider',
  'provider_account_id_sha256', 'sandbox_delivery_receipt_sha256', 'sender_identity_sha256',
]);
const READBACK_ZAPIER_FIELDS = Object.freeze([
  'checkout_revocation_worker_contract_receipt_sha256',
  'checkout_revocation_workflow_id_sha256', 'checkout_revocation_workflow_version_readback_sha256',
  'claim_next_contract_receipt_sha256', 'email_claim_next_path', 'email_workflow_id_sha256',
  'email_workflow_version_readback_sha256', 'payment_arc2_claim_next_path',
  'payment_arc2_start_path', 'payment_arc2_start_contract_receipt_sha256',
  'payment_arc2_workflow_id_sha256', 'payment_arc2_workflow_version_readback_sha256',
  'revision_claim_next_path', 'revision_workflow_id_sha256',
  'revision_workflow_version_readback_sha256',
]);
const READBACK_OPERATIONS_ALERT_FIELDS = Object.freeze([
  'audit_enabled', 'delivery_enabled', 'failure_alert_verified',
  'native_delivery_receipt_sha256', 'provider_event_type',
]);

function exactBoolean(value) {
  return value === 'true' || value === 'false';
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, keys) {
  return plainObject(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const output = JSON.stringify(value);
  if (output === undefined) throw new TypeError('Canonical JSON does not support undefined.');
  return output;
}

function hmac256(secret, value) {
  return createHmac('sha256', secret).update(value).digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function nonzeroSha256(value) {
  return typeof value === 'string' && HEX_64.test(value) && value !== '0'.repeat(64);
}

function valueAtPath(value, path) {
  return path.split('.').reduce((current, key) => current?.[key], value);
}

function signedReadbackBoundToDeployment(env, readback, deploymentSha, now) {
  if (!sensitiveCredentialsAreIsolated(env, [ACTIVATION_MANIFEST_SECRET_ENV])) return false;
  const digest = sha256(canonicalJson(readback));
  for (const name of [ACTIVATION_MANIFEST_ENV, ACTIVATION_NEXT_MANIFEST_ENV]) {
    const raw = env[name];
    const validation = validateActivationManifest(raw, {
      secret: env[ACTIVATION_MANIFEST_SECRET_ENV],
      deploymentSha,
      minimumStage: 'LIVE_CHECKOUT',
      now,
    });
    if (!validation.valid) continue;
    let manifest;
    try { manifest = JSON.parse(raw); } catch { continue; }
    const receipt = manifest.evidence?.find(item => item.kind === 'live_checkout_readback');
    if (receipt?.sha256 === digest) return true;
  }
  return false;
}

export function stripeReviewCheckoutConsumerReadiness(env = process.env, nowValue = new Date(), options = {}) {
  const now = nowValue instanceof Date ? new Date(nowValue.getTime()) : new Date(nowValue);
  if (!Number.isFinite(now.getTime())) return false;
  if (env.ARC_RUNTIME_ENVIRONMENT !== 'production') return env.ARC_RUNTIME_ENVIRONMENT === 'sandbox';
  if (env.ARC_PAYMENT_ARC2_WORKER_ENABLED !== 'true' ||
      env.ARC_STRIPE_REVERSAL_CONTROL_REQUIRED !== 'true') return false;
  const deploymentSha = options.deploymentSha ?? ACTIVATION_BUILD_IDENTITY?.deployment_sha;
  if (!DEPLOYMENT_SHA.test(String(deploymentSha || ''))) return false;
  let readback;
  try { readback = JSON.parse(env.ARC_REVIEW_ACTIVATION_READBACK_JSON); } catch { return false; }
  if (!exactKeys(readback, READBACK_TOP_FIELDS) ||
      !exactKeys(readback.netlify, READBACK_NETLIFY_FIELDS) ||
      !exactKeys(readback.stripe, READBACK_STRIPE_FIELDS) ||
      !exactKeys(readback.email, READBACK_EMAIL_FIELDS) ||
      !exactKeys(readback.operations_alert, READBACK_OPERATIONS_ALERT_FIELDS) ||
      !exactKeys(readback.zapier, READBACK_ZAPIER_FIELDS) ||
      readback.schema !== 'arc-review-activation-readback-v1' || readback.version !== 1 ||
      readback.mode !== 'production' || readback.minimum_stage !== 'LIVE_CHECKOUT' ||
      readback.provider_controls_state !== 'OFF') return false;
  const observedAt = Date.parse(readback.observed_at);
  const expiresAt = Date.parse(readback.expires_at);
  if (!Number.isFinite(observedAt) || !Number.isFinite(expiresAt) ||
      new Date(observedAt).toISOString() !== readback.observed_at ||
      new Date(expiresAt).toISOString() !== readback.expires_at ||
      observedAt > now.getTime() + 60_000 || now.getTime() - observedAt > READBACK_MAXIMUM_AGE_MS ||
      expiresAt <= now.getTime() || expiresAt - observedAt > READBACK_MAXIMUM_AGE_MS) return false;
  const requiredReceipts = [
    'netlify.env_name_set_readback_sha256', 'netlify.route_matrix_readback_sha256',
    'netlify.route_probe_receipt_sha256', 'stripe.catalog_readback_sha256',
    'stripe.checkout_session_expire_capability_readback_sha256',
    'stripe.checkout_session_retrieve_capability_readback_sha256',
    'stripe.webhook_destination_readback_sha256', 'stripe.webhook_event_set_readback_sha256',
    'email.native_webhook_readback_sha256',
    'email.native_suppression_readback_sha256', 'email.sandbox_delivery_receipt_sha256',
    'zapier.email_workflow_version_readback_sha256',
    'zapier.revision_workflow_version_readback_sha256',
    'zapier.payment_arc2_workflow_version_readback_sha256',
    'zapier.payment_arc2_start_contract_receipt_sha256',
    'zapier.checkout_revocation_workflow_version_readback_sha256',
    'zapier.checkout_revocation_worker_contract_receipt_sha256',
    'zapier.claim_next_contract_receipt_sha256',
  ];
  if (requiredReceipts.some(path => !nonzeroSha256(valueAtPath(readback, path)))) return false;
  const bindingsValid = readback.netlify.deployment_sha === deploymentSha &&
    readback.netlify.site_id_sha256 === sha256(String(env.ARC_EXPECTED_NETLIFY_SITE_ID || '')) &&
    readback.netlify.env_name_set_readback_sha256 ===
      reviewActivationRuntimeEnvironmentNamesSha256(env) &&
    readback.netlify.route_matrix_readback_sha256 === REVIEW_ACTIVATION_ROUTE_MATRIX_SHA256 &&
    readback.netlify.handoff_credential_environment_name === selectedNetlifyCredentialName(env) &&
    readback.stripe.account_id_sha256 === env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 &&
    readback.stripe.price_id_sha256 === sha256(String(env.ARC_EXPECTED_PRICE_ID || '')) &&
    readback.stripe.product_id_sha256 === sha256(String(env.ARC_EXPECTED_PRODUCT_ID || '')) &&
    readback.stripe.integration_identifier_sha256 ===
      sha256(String(env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER || '')) &&
    readback.stripe.webhook_endpoint_path === '/internal/stripe/reversal-webhook' &&
    readback.stripe.webhook_event_set_readback_sha256 ===
      REVIEW_ACTIVATION_STRIPE_WEBHOOK_EVENT_SET_SHA256 &&
    readback.email.provider === env.ARC_REVIEW_EMAIL_PROVIDER &&
    readback.email.provider_account_id_sha256 === env.ARC_REVIEW_EMAIL_PROVIDER_ACCOUNT_ID_SHA256 &&
    readback.email.sender_identity_sha256 === env.ARC_REVIEW_EMAIL_SENDER_IDENTITY_SHA256 &&
    readback.email.native_webhook_id_sha256 === env.ARC_REVIEW_EMAIL_NATIVE_WEBHOOK_ID_SHA256 &&
    readback.email.native_suppression_id_sha256 === env.ARC_REVIEW_EMAIL_NATIVE_SUPPRESSION_ID_SHA256 &&
    readback.zapier.email_workflow_id_sha256 === env.ARC_ZAPIER_REVIEW_EMAIL_WORKFLOW_ID_SHA256 &&
    readback.zapier.revision_workflow_id_sha256 === env.ARC_ZAPIER_REVIEW_REVISION_WORKFLOW_ID_SHA256 &&
    readback.zapier.payment_arc2_workflow_id_sha256 === env.ARC_ZAPIER_PAYMENT_ARC2_WORKFLOW_ID_SHA256 &&
    readback.zapier.checkout_revocation_workflow_id_sha256 ===
      env.ARC_ZAPIER_REVIEW_CHECKOUT_REVOCATION_WORKFLOW_ID_SHA256 &&
    readback.zapier.email_claim_next_path === '/api/internal/review-email/reserve' &&
    readback.zapier.revision_claim_next_path === '/api/internal/review-revision/claim' &&
    readback.zapier.payment_arc2_claim_next_path === '/internal/payment-arc2/claim' &&
    readback.zapier.payment_arc2_start_path === '/internal/payment-arc2/start' &&
    env.ARC_OPERATIONS_AUDIT_ENABLED === 'true' &&
    readback.operations_alert.audit_enabled === true &&
    readback.operations_alert.delivery_enabled === false &&
    readback.operations_alert.failure_alert_verified === false &&
    readback.operations_alert.native_delivery_receipt_sha256 === '0'.repeat(64) &&
    readback.operations_alert.provider_event_type === 'email.delivered';
  return bindingsValid && signedReadbackBoundToDeployment(env, readback, deploymentSha, now);
}

function stripeId(value) {
  return typeof value === 'string' ? value : value?.id;
}

function checkoutReturnUrl(value, kind, mode) {
  let url;
  try { url = new URL(value); } catch { return null; }
  const allowedOrigins = mode === 'production' ? PRODUCTION_RETURN_ORIGINS : SANDBOX_RETURN_ORIGINS;
  if (value !== url.href || url.protocol !== 'https:' || !allowedOrigins.has(url.origin) ||
      url.username || url.password || url.hash) return null;
  const keys = [...url.searchParams.keys()].sort();
  if (kind === 'success') {
    if (url.pathname !== '/payment-success/' || JSON.stringify(keys) !== JSON.stringify(['session_id']) ||
        url.searchParams.get('session_id') !== '{CHECKOUT_SESSION_ID}') return null;
  } else if (url.pathname !== '/review/' || JSON.stringify(keys) !== JSON.stringify(['checkout']) ||
      url.searchParams.get('checkout') !== 'cancelled') return null;
  return url.href;
}

function exactMode(env) {
  const booleansValid = [
    env.ARC_STRIPE_LIVE_MODE_ENABLED,
    env.ARC_ALLOW_TEST_MODE_EVENTS,
    env.ARC_HANDOFF_ENABLED,
    env.ARC_STRIPE_CHECKOUT_LEDGER_ENABLED,
    env.ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED,
  ].every(exactBoolean);
  if (!booleansValid) return null;
  if (env.ARC_RUNTIME_ENVIRONMENT === 'sandbox' && env.ARC_STRIPE_LIVE_MODE_ENABLED === 'false' &&
      env.ARC_ALLOW_TEST_MODE_EVENTS === 'true' && env.ARC_HANDOFF_ENABLED === 'false' &&
      env.ARC_STRIPE_CHECKOUT_LEDGER_ENABLED === 'true' &&
      env.ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED === 'false') return 'sandbox';
  if (env.ARC_RUNTIME_ENVIRONMENT === 'production' && env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true' &&
      env.ARC_ALLOW_TEST_MODE_EVENTS === 'false' && env.ARC_HANDOFF_ENABLED === 'true' &&
      env.ARC_STRIPE_CHECKOUT_LEDGER_ENABLED === 'true' &&
      env.ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED === 'true') return 'production';
  return null;
}

function resolveConfiguration(env, now = new Date()) {
  const mode = exactMode(env);
  const keyMatch = typeof env.ARC_STRIPE_REVIEW_SECRET_KEY === 'string'
    ? env.ARC_STRIPE_REVIEW_SECRET_KEY.match(RESTRICTED_KEY) : null;
  const keyMode = mode === 'production' ? 'live' : mode === 'sandbox' ? 'test' : null;
  const review = reviewPortalConfiguration(env);
  const ledger = stripeCheckoutConfiguration(env);
  const paymentBridge = paymentArc2BridgeConfiguration(env);
  const revocation = reviewCheckoutRevocationConfiguration(env);
  const runtimeReadback = reviewActivationRuntimeReadbackConfiguration(env, now);
  // Production never falls back to the legacy one-shot environment receipt.
  // It must bind the verifier authority and every Checkout request must strong-
  // read a current signed receipt before any customer/provider mutation.
  const consumerReadinessValid = mode === 'production'
    ? runtimeReadback.enabled
    : stripeReviewCheckoutConsumerReadiness(env, now);
  const successUrl = checkoutReturnUrl(env.ARC_STRIPE_CHECKOUT_SUCCESS_URL, 'success', mode);
  const cancelUrl = checkoutReturnUrl(env.ARC_STRIPE_CHECKOUT_CANCEL_URL, 'cancel', mode);
  const producerFlagValid = exactBoolean(env.ARC_STRIPE_REVIEW_CHECKOUT_ENABLED);
  const reviewFlagsExact = env.ARC_REVIEW_PORTAL_ENABLED === 'true' &&
    env.ARC_REVIEW_CHECKOUT_ENABLED === 'true' && review.enabled && review.checkoutEnabled;
  const identifiersValid = PRICE_ID.test(String(env.ARC_EXPECTED_PRICE_ID || '')) &&
    PRODUCT_ID.test(String(env.ARC_EXPECTED_PRODUCT_ID || '')) &&
    TAX_CODE_ID.test(String(env.ARC_EXPECTED_PRODUCT_TAX_CODE || '')) &&
    HEX_64.test(String(env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 || ''));
  const offerValid = env.ARC_STRIPE_CHECKOUT_OFFER_ID === OFFER_CONTRACT_ID &&
    env.ARC_STRIPE_CHECKOUT_TERMS_VERSION === TERMS_VERSION &&
    env.ARC_EXPECTED_PRODUCT_NAME === PRODUCT_NAME;
  const integrationIdentifierValid = INTEGRATION_IDENTIFIER.test(
    String(env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER || ''));
  const urlsValid = review.checkoutOrigin === CHECKOUT_ORIGIN && successUrl !== null && cancelUrl !== null &&
    new URL(successUrl).origin === new URL(cancelUrl).origin;
  const knownSecretNames = [
    'ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET',
    'ARC_STRIPE_REVIEW_SECRET_KEY',
    'ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET',
    'ARC_STRIPE_ACCOUNT_VERIFICATION_KEY',
    'ARC_STRIPE_WEBHOOK_SIGNING_SECRET',
    'ARC_STRIPE_REVERSAL_HMAC_SECRET',
    'ARC_REVIEW_INVITE_HMAC_SECRET',
    'ARC_REVIEW_SESSION_HMAC_SECRET',
    'ARC_REVIEW_RECORD_HMAC_SECRET',
    'ARC_REVIEW_DECISION_HMAC_SECRET',
    'ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET',
    'ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET',
  ];
  if (mode === 'production') knownSecretNames.push(
    'ARC_ACTIVATION_MANIFEST_HMAC_SECRET',
    'ARC_PAYMENT_ARC2_WORKER_SECRET',
  );
  const configuredNetlifyCredentials = ['NETLIFY_ADMIN_PAT', 'NETLIFY_ACCESS_TOKEN']
    .filter((name) => typeof env[name] === 'string' && env[name].length > 0);
  if (mode === 'production' && configuredNetlifyCredentials.length === 1) {
    knownSecretNames.push(configuredNetlifyCredentials[0]);
  }
  const secretsDistinct = knownSecretNames.every((name) => {
    const value = env[name];
    return typeof value === 'string' && value.length >= 32 && value.length <= 512;
  }) && (mode !== 'production' || configuredNetlifyCredentials.length === 1) &&
    sensitiveCredentialsAreIsolated(env, knownSecretNames);
  const authorityValid = mode !== 'production' || validateActivationManifestEnvironment(env, {
    minimumStage: 'LIVE_CHECKOUT', now,
  }).valid;
  const productionAttestationsValid = mode !== 'production' || [
    env.ARC_ADULT_OPERATOR_VERIFIED,
    env.ARC_BUSINESS_LICENSE_VERIFIED,
    env.ARC_TAX_REGISTRATION_VERIFIED,
    env.ARC_TRANSACTIONAL_EMAIL_VERIFIED,
  ].every(value => value === 'true');
  const taxReadbackRequired = mode === 'production' && env.ARC_TAX_REGISTRATION_VERIFIED === 'true';
  const ledgerValid = ledger.webhookOperational && (mode !== 'production' || ledger.enabled);
  const apiVersionValid = env.ARC_STRIPE_WEBHOOK_API_VERSION === STRIPE_REVIEW_CHECKOUT_API_VERSION;
  const keyValid = keyMatch !== null && keyMatch[1] === keyMode;
  const configured = mode !== null && producerFlagValid && reviewFlagsExact && identifiersValid && offerValid &&
    integrationIdentifierValid &&
    urlsValid && secretsDistinct && authorityValid && productionAttestationsValid && ledgerValid && paymentBridge.enabled &&
    revocation.enabled && consumerReadinessValid &&
    apiVersionValid && keyValid;
  return {
    accountIdSha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    apiVersionValid,
    authorityValid,
    cancelUrl,
    configured,
    consumerReadinessValid,
    expectedLivemode: mode === 'production',
    integrationIdentifier: env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER,
    integrationIdentifierValid,
    keyMode,
    keyValid,
    ledgerValid,
    mode,
    offerValid,
    paymentBridgeEnabled: paymentBridge.enabled,
    priceId: env.ARC_EXPECTED_PRICE_ID,
    producerEnabled: configured && env.ARC_STRIPE_REVIEW_CHECKOUT_ENABLED === 'true',
    producerFlagValid,
    productId: env.ARC_EXPECTED_PRODUCT_ID,
    productName: env.ARC_EXPECTED_PRODUCT_NAME,
    productionAttestationsValid,
    reviewFlagsExact,
    runtimeReadbackConfigured: runtimeReadback.enabled,
    runtimeReadbackRequested: runtimeReadback.requested,
    revocationEnabled: revocation.enabled,
    secretKey: env.ARC_STRIPE_REVIEW_SECRET_KEY,
    secretsDistinct,
    successUrl,
    taxCodeId: env.ARC_EXPECTED_PRODUCT_TAX_CODE,
    taxReadbackRequired,
    urlsValid,
  };
}

export function stripeReviewCheckoutConfiguration(env = process.env, now = new Date()) {
  const configuration = resolveConfiguration(env, now);
  return Object.freeze({
    apiVersionValid: configuration.apiVersionValid,
    authorityValid: configuration.authorityValid,
    configured: configuration.configured,
    consumerReadinessValid: configuration.consumerReadinessValid,
    integrationIdentifierValid: configuration.integrationIdentifierValid,
    keyMode: configuration.keyMode,
    keyValid: configuration.keyValid,
    ledgerValid: configuration.ledgerValid,
    mode: configuration.mode,
    offerValid: configuration.offerValid,
    paymentBridgeEnabled: configuration.paymentBridgeEnabled,
    producerEnabled: configuration.producerEnabled,
    producerFlagValid: configuration.producerFlagValid,
    productionAttestationsValid: configuration.productionAttestationsValid,
    reviewFlagsExact: configuration.reviewFlagsExact,
    revocationEnabled: configuration.revocationEnabled,
    runtimeReadbackConfigured: configuration.runtimeReadbackConfigured,
    runtimeReadbackRequested: configuration.runtimeReadbackRequested,
    secretsDistinct: configuration.secretsDistinct,
    taxReadbackRequired: configuration.taxReadbackRequired,
    urlsValid: configuration.urlsValid,
  });
}

function normalizeInput(input, env) {
  if (!exactKeys(input, INPUT_KEYS) || !INPUT_KEYS.filter(key => key.endsWith('_sha256'))
    .every(key => HEX_64.test(String(input[key] || ''))) ||
      input.scope_version !== OFFER_CONTRACT_ID ||
      !Number.isSafeInteger(input.checkout_expires_at) || input.checkout_expires_at < 1 ||
      !/^arc_review_[a-f0-9]{64}$/.test(String(input.idempotency_key || ''))) {
    throw new TypeError('ARC review Checkout binding is invalid.');
  }
  const expectedIdempotencyKey = `arc_review_${hmac256(env.ARC_REVIEW_DECISION_HMAC_SECRET,
    CHECKOUT_IDEMPOTENCY_PREFIX + input.invite_hmac_sha256)}`;
  if (!safeEqual(input.idempotency_key, expectedIdempotencyKey)) {
    throw new TypeError('ARC review Checkout idempotency binding is invalid.');
  }
  return Object.freeze({ ...input });
}

function validateAccount(account, configuration) {
  if (!account || typeof account !== 'object' || Array.isArray(account) || account.object !== 'account' ||
      !ACCOUNT_ID.test(String(account.id || '')) || !safeEqual(sha256(account.id), configuration.accountIdSha256)) {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_ACCOUNT_BINDING');
  }
}

function validateCatalog(price, configuration) {
  const product = price?.product;
  if (!price || typeof price !== 'object' || Array.isArray(price) || price.object !== 'price' ||
      price.id !== configuration.priceId || price.active !== true ||
      price.livemode !== configuration.expectedLivemode || price.type !== 'one_time' || price.recurring !== null ||
      price.currency !== 'usd' || price.unit_amount !== SUBTOTAL_MINOR_UNITS ||
      price.tax_behavior !== 'exclusive' || !product || typeof product !== 'object' || Array.isArray(product) ||
      product.object !== 'product' || product.id !== configuration.productId || product.active !== true ||
      product.livemode !== configuration.expectedLivemode || product.name !== configuration.productName ||
      product.shippable === true || stripeId(product.default_price) !== configuration.priceId ||
      stripeId(product.tax_code) !== configuration.taxCodeId) {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_CATALOG_BINDING');
  }
}

export function validateStripeReviewTaxReadiness(settings, registrations, expectedLivemode,
  nowValue = new Date()) {
  const nowSeconds = Math.floor(new Date(nowValue).getTime() / 1000);
  if (typeof expectedLivemode !== 'boolean' || !Number.isSafeInteger(nowSeconds) ||
      !settings || typeof settings !== 'object' ||
      Array.isArray(settings) || settings.object !== 'tax.settings' ||
      settings.livemode !== expectedLivemode || settings.status !== 'active' ||
      !settings.head_office || typeof settings.head_office !== 'object' || Array.isArray(settings.head_office) ||
      !settings.head_office.address || typeof settings.head_office.address !== 'object' ||
      Array.isArray(settings.head_office.address) ||
      !/^[A-Z]{2}$/.test(String(settings.head_office.address.country || '')) ||
      !registrations || typeof registrations !== 'object' || Array.isArray(registrations) ||
      registrations.object !== 'list' || registrations.has_more !== false ||
      !Array.isArray(registrations.data) || registrations.data.length < 1 || registrations.data.length > 100 ||
      registrations.data.some((registration) => !registration || typeof registration !== 'object' ||
        Array.isArray(registration) || registration.object !== 'tax.registration' ||
        !/^taxreg_[A-Za-z0-9_]{6,128}$/.test(String(registration.id || '')) ||
        registration.livemode !== expectedLivemode || registration.status !== 'active' ||
        !Number.isSafeInteger(registration.active_from) || registration.active_from > nowSeconds ||
        (registration.expires_at !== null &&
          (!Number.isSafeInteger(registration.expires_at) || registration.expires_at <= nowSeconds)) ||
        !/^[A-Z]{2}$/.test(String(registration.country || '')))) {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_TAX_READBACK');
  }
  const washingtonStateSalesTaxActive = registrations.data.some((registration) =>
    registration.country === 'US' && plainObject(registration.country_options) &&
    plainObject(registration.country_options.us) &&
    registration.country_options.us.state === 'WA' &&
    registration.country_options.us.type === 'state_sales_tax');
  if (!washingtonStateSalesTaxActive) {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_TAX_READBACK');
  }
}

async function readCheckoutProviderBindings(client, configuration, now) {
  let account;
  let price;
  let settings = null;
  let registrations = null;
  try {
    const reads = [
      client.accounts.retrieve(),
      client.prices.retrieve(configuration.priceId, { expand: ['product'] }),
    ];
    if (configuration.taxReadbackRequired) {
      reads.push(client.tax.settings.retrieve());
      reads.push(client.tax.registrations.list({ status: 'active', limit: 100 }));
    }
    [account, price, settings, registrations] = await Promise.all(reads);
  } catch (cause) {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_PROVIDER_READ', { cause });
  }
  validateAccount(account, configuration);
  validateCatalog(price, configuration);
  if (configuration.taxReadbackRequired) {
    validateStripeReviewTaxReadiness(settings, registrations, configuration.expectedLivemode, now);
  }
}

function checkoutMetadata(input) {
  return Object.freeze({
    approval_receipt_hmac_sha256: input.approval_receipt_hmac_sha256,
    approval_receipt_sha256: input.approval_receipt_sha256,
    invite_hmac_sha256: input.invite_hmac_sha256,
    offer_contract_id: OFFER_CONTRACT_ID,
    preview_manifest_sha256: input.preview_manifest_sha256,
    recipient_email_sha256: input.recipient_email_sha256,
    schema: STRIPE_REVIEW_CHECKOUT_SCHEMA,
    scope_version: input.scope_version,
    terms_version: TERMS_VERSION,
  });
}

function checkoutParameters(input, configuration) {
  const metadata = checkoutMetadata(input);
  return {
    allow_promotion_codes: false,
    automatic_tax: { enabled: true },
    cancel_url: configuration.cancelUrl,
    client_reference_id: input.approval_receipt_sha256,
    consent_collection: { terms_of_service: 'required' },
    custom_fields: [{
      dropdown: { options: [{ label: 'I confirm I am 18+ and authorized to purchase.', value: 'accepted' }] },
      key: 'adultpurchaserack',
      label: { custom: 'Adult purchasing authority', type: 'custom' },
      optional: false,
      type: 'dropdown',
    }],
    customer_creation: 'always',
    expires_at: input.checkout_expires_at,
    invoice_creation: { enabled: false },
    integration_identifier: configuration.integrationIdentifier,
    line_items: [{ price: configuration.priceId, quantity: 1 }],
    metadata,
    mode: 'payment',
    payment_intent_data: { metadata },
    phone_number_collection: { enabled: false },
    submit_type: 'pay',
    success_url: configuration.successUrl,
    ui_mode: 'hosted_page',
  };
}

function validateSession(session, input, metadata, configuration) {
  const expectedSessionMode = configuration.expectedLivemode ? 'live' : 'test';
  let url;
  try { url = new URL(session?.url); } catch {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_PROVIDER_RESPONSE');
  }
  if (!session || typeof session !== 'object' || Array.isArray(session) || session.object !== 'checkout.session' ||
      !SESSION_ID.test(String(session.id || '')) || session.id.match(SESSION_ID)?.[1] !== expectedSessionMode ||
      session.mode !== 'payment' || session.ui_mode !== 'hosted_page' ||
      session.livemode !== configuration.expectedLivemode ||
      session.payment_link !== null || session.status !== 'open' || session.payment_status !== 'unpaid' ||
      session.currency !== 'usd' || session.amount_subtotal !== SUBTOTAL_MINOR_UNITS ||
      session.expires_at !== input.checkout_expires_at ||
      session.client_reference_id !== input.approval_receipt_sha256 ||
      session.integration_identifier !== configuration.integrationIdentifier ||
      session.automatic_tax?.enabled !== true || !exactKeys(session.metadata, METADATA_KEYS) ||
      METADATA_KEYS.some(key => !safeEqual(session.metadata[key], metadata[key])) ||
      url.protocol !== 'https:' || url.origin !== CHECKOUT_ORIGIN || url.username || url.password ||
      !url.pathname.split('/').includes(session.id)) {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_PROVIDER_RESPONSE');
  }
  return { id: session.id, url: url.href };
}

function stripeClient(configuration, adapters) {
  const options = {
    apiVersion: STRIPE_REVIEW_CHECKOUT_API_VERSION,
    maxNetworkRetries: 2,
    timeout: 10_000,
  };
  const client = adapters.stripeClient || (typeof adapters.stripeFactory === 'function'
    ? adapters.stripeFactory(configuration.secretKey, options)
    : new Stripe(configuration.secretKey, options));
  if (!client?.accounts || typeof client.accounts.retrieve !== 'function' ||
      !client?.prices || typeof client.prices.retrieve !== 'function' ||
      (configuration.taxReadbackRequired && (!client?.tax?.settings ||
        typeof client.tax.settings.retrieve !== 'function' || !client?.tax?.registrations ||
        typeof client.tax.registrations.list !== 'function')) ||
      !client?.checkout?.sessions || typeof client.checkout.sessions.create !== 'function' ||
      typeof client.checkout.sessions.retrieve !== 'function' ||
      typeof client.checkout.sessions.expire !== 'function') {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_PROVIDER_CLIENT');
  }
  return client;
}

function controlSuppression(record) {
  if (!record || record.suppression_receipt_sha256 === null) return null;
  return {
    recipient_email_sha256: record.recipient_email_sha256,
    source_invite_hmac_sha256: record.source_invite_hmac_sha256,
    source_outbox_hmac_sha256: record.source_outbox_hmac_sha256,
    suppressed_at: record.suppressed_at,
    suppression_receipt_sha256: record.suppression_receipt_sha256,
    suppression_status: record.suppression_status,
  };
}

function expectedMetadataFromBinding(binding) {
  return {
    approval_receipt_hmac_sha256: binding.approval_receipt_hmac_sha256,
    approval_receipt_sha256: binding.approval_receipt_sha256,
    invite_hmac_sha256: binding.invite_hmac_sha256,
    offer_contract_id: OFFER_CONTRACT_ID,
    preview_manifest_sha256: binding.preview_manifest_sha256,
    recipient_email_sha256: binding.recipient_email_sha256,
    schema: STRIPE_REVIEW_CHECKOUT_SCHEMA,
    scope_version: binding.scope_version,
    terms_version: TERMS_VERSION,
  };
}

function validateBoundProviderSession(session, binding, configuration) {
  const metadata = expectedMetadataFromBinding(binding);
  if (!session || typeof session !== 'object' || Array.isArray(session) || session.object !== 'checkout.session' ||
      session.id !== binding.session_id || session.mode !== 'payment' || session.ui_mode !== 'hosted_page' ||
      session.livemode !== binding.session_livemode || session.livemode !== configuration.expectedLivemode ||
      session.payment_link !== null || session.integration_identifier !== binding.integration_identifier ||
      session.client_reference_id !== binding.approval_receipt_sha256 || session.currency !== 'usd' ||
      session.expires_at !== binding.checkout_expires_at ||
      session.amount_subtotal !== SUBTOTAL_MINOR_UNITS || session.automatic_tax?.enabled !== true ||
      !exactKeys(session.metadata, METADATA_KEYS) ||
      METADATA_KEYS.some(key => !safeEqual(session.metadata[key], metadata[key])) ||
      !['open', 'expired', 'complete'].includes(session.status) ||
      !['unpaid', 'paid'].includes(session.payment_status)) {
    throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_PROVIDER_MISMATCH');
  }
  return session;
}

function checkoutInputFromBinding(binding, env) {
  return normalizeInput({
    approval_receipt_hmac_sha256: binding.approval_receipt_hmac_sha256,
    approval_receipt_sha256: binding.approval_receipt_sha256,
    checkout_expires_at: binding.checkout_expires_at,
    idempotency_key: `arc_review_${hmac256(env.ARC_REVIEW_DECISION_HMAC_SECRET,
      CHECKOUT_IDEMPOTENCY_PREFIX + binding.invite_hmac_sha256)}`,
    invite_hmac_sha256: binding.invite_hmac_sha256,
    preview_manifest_sha256: binding.preview_manifest_sha256,
    recipient_email_sha256: binding.recipient_email_sha256,
    scope_version: binding.scope_version,
  }, env);
}

async function recoverAmbiguousSuppressedSession(store, initial, suppression,
  configuration, client, env, adapters) {
  let binding = await requestReviewCheckoutRevocation(
    store, initial.binding_hmac_sha256, suppression, env,
    adapters.clock?.() || new Date(), { cancelCreating: true },
  );
  if (binding.state !== 'CANCELLED' || binding.session_id !== null) {
    throw new Error('ARC_REVIEW_CHECKOUT_SUPPRESSION_RECOVERY_STATE_INVALID');
  }
  const input = checkoutInputFromBinding(binding, env);
  await readCheckoutProviderBindings(client, configuration, adapters.clock?.() || new Date());
  const parameters = checkoutParameters(input, configuration);
  let session;
  try {
    // The deterministic key resolves both sides of the ambiguous-commit
    // window: Stripe returns the original Session when create committed, or
    // creates the one Session that is immediately revoked when it did not.
    session = await client.checkout.sessions.create(parameters,
      { idempotencyKey: input.idempotency_key });
  } catch (cause) {
    throw new Error('ARC_REVIEW_CHECKOUT_SUPPRESSION_RECOVERY_CREATE_REQUIRED', { cause });
  }
  const created = validateSession(session, input, parameters.metadata, configuration);
  binding = await bindReviewCheckoutSession(store, input.approval_receipt_sha256, {
    id: created.id,
    integration_identifier: session.integration_identifier,
    livemode: session.livemode,
    url: created.url,
  }, env, adapters.clock?.() || new Date());
  if (binding.state !== 'EXPIRY_PENDING') {
    throw new Error('ARC_REVIEW_CHECKOUT_SUPPRESSION_RECOVERY_STATE_INVALID');
  }
  return binding;
}

export async function expireSuppressedRecipientReviewCheckouts(store, rawSuppression,
  env = process.env, adapters = {}) {
  const configuration = resolveConfiguration(env, adapters.clock?.() || new Date());
  if (!configuration.producerEnabled || !store?.getWithMetadata || !store?.setJSON) {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_CONFIGURATION');
  }
  const client = stripeClient(configuration, adapters);
  let account;
  try { account = await client.accounts.retrieve(); } catch (cause) {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_PROVIDER_READ', { cause });
  }
  validateAccount(account, configuration);
  const discovered = await listReviewCheckoutBindingsForRecipient(
    store, rawSuppression.recipient_email_sha256, env,
  );
  if (!discovered.complete) return { complete: false, pending: true, revoked: 0 };
  const control = await readReviewEmailRecipientControl(
    store, rawSuppression.recipient_email_sha256, env,
  );
  const authorityStillActive = control?.record.state === 'AUTHORIZING' &&
    Date.parse(control.record.authority_expires_at) >
      (adapters.clock?.() || new Date()).getTime();
  let revoked = 0;
  for (const initial of discovered.records) {
    let binding;
    if (initial.session_id === null && ['CREATING', 'CANCELLED'].includes(initial.state)) {
      if (authorityStillActive) return { complete: false, pending: true, revoked };
      binding = await recoverAmbiguousSuppressedSession(store, initial, rawSuppression,
        configuration, client, env, adapters);
    } else {
      binding = await requestReviewCheckoutRevocation(
        store, initial.binding_hmac_sha256, rawSuppression, env, adapters.clock?.() || new Date(),
      );
    }
    if (binding.revocation_pending === true) return { complete: false, pending: true, revoked };
    if (binding.state === 'CANCELLED' || binding.state === 'EXPIRED') {
      revoked += 1;
      continue;
    }
    if (binding.state === 'REVIEW_REQUIRED') {
      throw new Error('ARC_REVIEW_CHECKOUT_REFUND_REVIEW_REQUIRED');
    }
    if (binding.state !== 'EXPIRY_PENDING') {
      throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_STATE_INVALID');
    }
    let remote;
    try {
      remote = validateBoundProviderSession(
        await client.checkout.sessions.retrieve(binding.session_id), binding, configuration,
      );
    } catch (cause) {
      if (/REVOCATION_PROVIDER_MISMATCH/.test(cause?.message || '')) throw cause;
      throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_PROVIDER_READ', { cause });
    }
    if (remote.status === 'complete' || remote.payment_status === 'paid') {
      await markReviewCheckoutManualReview(store, binding.binding_hmac_sha256, binding.session_id, {
        payment_status: remote.payment_status,
        status: remote.status,
      }, rawSuppression, env, adapters.clock?.() || new Date());
      throw new Error('ARC_REVIEW_CHECKOUT_REFUND_REVIEW_REQUIRED');
    }
    if (remote.status === 'open') {
      const idempotencyKey = reviewCheckoutExpiryIdempotencyKey(binding, env);
      try {
        await client.checkout.sessions.expire(binding.session_id, {}, { idempotencyKey });
      } catch (cause) {
        const recovered = await client.checkout.sessions.retrieve(binding.session_id).catch(() => null);
        if (!recovered || validateBoundProviderSession(recovered, binding, configuration).status !== 'expired') {
          throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_PROVIDER_EXPIRE', { cause });
        }
      }
      remote = validateBoundProviderSession(
        await client.checkout.sessions.retrieve(binding.session_id), binding, configuration,
      );
    }
    if (remote.status !== 'expired' || remote.payment_status !== 'unpaid') {
      await markReviewCheckoutManualReview(store, binding.binding_hmac_sha256, binding.session_id, {
        payment_status: remote.payment_status,
        status: remote.status,
      }, rawSuppression, env, adapters.clock?.() || new Date());
      throw new Error('ARC_REVIEW_CHECKOUT_REFUND_REVIEW_REQUIRED');
    }
    binding = await markReviewCheckoutExpired(
      store, binding.binding_hmac_sha256, binding.session_id, env, adapters.clock?.() || new Date(),
    );
    if (binding.state !== 'EXPIRED') throw new Error('ARC_REVIEW_CHECKOUT_REVOCATION_STATE_INVALID');
    revoked += 1;
  }
  return { complete: true, pending: false, revoked };
}

function stripeAuthorityClient(env, adapters) {
  if (!stripeAccountVerificationConfigured(env) ||
      env.ARC_STRIPE_WEBHOOK_API_VERSION !== STRIPE_REVIEW_CHECKOUT_API_VERSION ||
      !HEX_64.test(String(env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 || ''))) {
    throw new Error('ARC_REVIEW_CHECKOUT_AUTHORITY_UNAVAILABLE_CONFIGURATION');
  }
  const options = {
    apiVersion: STRIPE_REVIEW_CHECKOUT_API_VERSION,
    maxNetworkRetries: 2,
    timeout: 10_000,
  };
  const client = adapters.stripeClient || (typeof adapters.stripeFactory === 'function'
    ? adapters.stripeFactory(env.ARC_STRIPE_ACCOUNT_VERIFICATION_KEY, options)
    : new Stripe(env.ARC_STRIPE_ACCOUNT_VERIFICATION_KEY, options));
  if (!client?.accounts || typeof client.accounts.retrieve !== 'function' ||
      !client?.checkout?.sessions || typeof client.checkout.sessions.retrieve !== 'function') {
    throw new Error('ARC_REVIEW_CHECKOUT_AUTHORITY_UNAVAILABLE_PROVIDER_CLIENT');
  }
  return client;
}

export async function retrieveStripeReviewCheckoutAuthority(
  sessionId,
  options,
  env = process.env,
  adapters = {},
) {
  if (!SESSION_ID.test(String(sessionId || '')) || !plainObject(options) ||
      !exactKeys(options, ['expand']) || !Array.isArray(options.expand) ||
      options.expand.length !== 1 || options.expand[0] !== 'payment_intent') {
    throw new TypeError('ARC review Checkout authority request is invalid.');
  }
  const expectedMode = env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true' ? 'live' :
    env.ARC_STRIPE_LIVE_MODE_ENABLED === 'false' ? 'test' : null;
  if (expectedMode === null || sessionId.match(SESSION_ID)?.[1] !== expectedMode) {
    throw new TypeError('ARC review Checkout authority mode is invalid.');
  }
  const client = stripeAuthorityClient(env, adapters);
  try {
    const [account, session] = await Promise.all([
      client.accounts.retrieve(),
      client.checkout.sessions.retrieve(sessionId, { expand: ['payment_intent'] }),
    ]);
    return { account, session };
  } catch (cause) {
    throw new Error('ARC_REVIEW_CHECKOUT_AUTHORITY_UNAVAILABLE_PROVIDER_READ', { cause });
  }
}

async function ownedRecipientControl(store, input, authority, env) {
  const entry = await readReviewEmailRecipientControl(store, input.recipient_email_sha256, env);
  if (!entry) throw new Error('ARC_REVIEW_CHECKOUT_RECIPIENT_AUTHORITY_LOST');
  if (entry.record.state === 'SUPPRESSED') return entry.record;
  if (entry.record.state !== 'AUTHORIZING' ||
      !safeEqual(entry.record.authority_operation_hmac_sha256, authority.operation_hmac_sha256)) {
    throw new Error('ARC_REVIEW_CHECKOUT_RECIPIENT_AUTHORITY_LOST');
  }
  return entry.record;
}

async function revokeAfterRecipientSuppression(store, binding, suppression, env, adapters) {
  if (!binding || !suppression) return;
  if (binding.session_id === null) {
    await requestReviewCheckoutRevocation(store, binding.binding_hmac_sha256, suppression, env,
      adapters.clock?.() || new Date(), { cancelCreating: true });
    return;
  }
  await expireSuppressedRecipientReviewCheckouts(store, suppression, env, adapters);
}

function bindingMatchesInput(binding, input) {
  return binding && [
    'approval_receipt_hmac_sha256', 'approval_receipt_sha256', 'checkout_expires_at', 'invite_hmac_sha256',
    'preview_manifest_sha256', 'recipient_email_sha256', 'scope_version',
  ].every(field => safeEqual(binding[field], input[field]));
}

async function recoverSuppressedAmbiguousCreate(store, input, suppression, configuration, env, adapters) {
  const discovered = await listReviewCheckoutBindingsForRecipient(
    store, input.recipient_email_sha256, env,
  );
  if (!discovered.complete) throw new Error('ARC_REVIEW_CHECKOUT_SUPPRESSION_RECOVERY_INCOMPLETE');
  let binding = discovered.records.find(record =>
    record.approval_receipt_sha256 === input.approval_receipt_sha256);
  if (!binding) return false;
  if (!bindingMatchesInput(binding, input)) {
    throw new Error('ARC_REVIEW_CHECKOUT_SUPPRESSION_RECOVERY_BINDING_INVALID');
  }
  if (binding.state === 'REVIEW_REQUIRED') {
    throw new Error('ARC_REVIEW_CHECKOUT_REFUND_REVIEW_REQUIRED');
  }
  if (binding.state === 'EXPIRED') return true;
  if (binding.session_id === null) {
    binding = await requestReviewCheckoutRevocation(
      store, binding.binding_hmac_sha256, suppression, env,
      adapters.clock?.() || new Date(), { cancelCreating: true },
    );
    if (binding.state !== 'CANCELLED') {
      throw new Error('ARC_REVIEW_CHECKOUT_SUPPRESSION_RECOVERY_STATE_INVALID');
    }
    const client = stripeClient(configuration, adapters);
    await readCheckoutProviderBindings(client, configuration, adapters.clock?.() || new Date());
    const parameters = checkoutParameters(input, configuration);
    let session;
    try {
      session = await client.checkout.sessions.create(parameters, { idempotencyKey: input.idempotency_key });
    } catch (cause) {
      throw new Error('ARC_REVIEW_CHECKOUT_SUPPRESSION_RECOVERY_CREATE_REQUIRED', { cause });
    }
    const created = validateSession(session, input, parameters.metadata, configuration);
    binding = await bindReviewCheckoutSession(store, input.approval_receipt_sha256, {
      id: created.id,
      integration_identifier: session.integration_identifier,
      livemode: session.livemode,
      url: created.url,
    }, env, adapters.clock?.() || new Date());
    if (binding.state !== 'EXPIRY_PENDING') {
      throw new Error('ARC_REVIEW_CHECKOUT_SUPPRESSION_RECOVERY_STATE_INVALID');
    }
  }
  const revoked = await expireSuppressedRecipientReviewCheckouts(store, suppression, env, adapters);
  if (!revoked.complete || revoked.pending) {
    throw new Error('ARC_REVIEW_CHECKOUT_SUPPRESSION_RECOVERY_INCOMPLETE');
  }
  return true;
}

export async function createStripeReviewCheckout(rawInput, env = process.env, adapters = {}) {
  const configuration = resolveConfiguration(env, adapters.clock?.() || new Date());
  if (!configuration.producerEnabled || !adapters.store?.getWithMetadata || !adapters.store?.setJSON) {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_CONFIGURATION');
  }
  const input = normalizeInput(rawInput, env);
  if (configuration.mode === 'production' && configuration.runtimeReadbackRequested) {
    if (!configuration.runtimeReadbackConfigured ||
        !adapters.readbackStore?.getWithMetadata || !adapters.readbackStore?.setJSON) {
      throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_RUNTIME_READBACK');
    }
    try {
      await ensureReviewActivationRuntimeReadback(
        env,
        adapters.readbackStore,
        adapters.clock?.() || new Date(),
        { fetch: adapters.fetch },
      );
    } catch (cause) {
      throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_RUNTIME_READBACK', { cause });
    }
  }
  const store = adapters.store;
  let authority;
  try {
    authority = await acquireReviewEmailRecipientAuthority(
      store, input.recipient_email_sha256, input.idempotency_key, env, adapters.clock?.() || new Date(),
    );
  } catch (cause) {
    if (!/RECIPIENT_SUPPRESSED/.test(cause?.message || '')) throw cause;
    const control = await readReviewEmailRecipientControl(store, input.recipient_email_sha256, env)
      .catch(() => null);
    const suppression = controlSuppression(control?.record);
    if (suppression) {
      await recoverSuppressedAmbiguousCreate(store, input, suppression, configuration, env, adapters);
    }
    throw new Error('ARC_REVIEW_CHECKOUT_RECIPIENT_SUPPRESSED', { cause });
  }
  let binding = null;
  let authorityReleased = false;
  try {
    binding = await reserveReviewCheckoutBinding(store, {
      approval_receipt_hmac_sha256: input.approval_receipt_hmac_sha256,
      approval_receipt_sha256: input.approval_receipt_sha256,
      checkout_expires_at: input.checkout_expires_at,
      invite_hmac_sha256: input.invite_hmac_sha256,
      preview_manifest_sha256: input.preview_manifest_sha256,
      recipient_email_sha256: input.recipient_email_sha256,
      scope_version: input.scope_version,
    }, env, adapters.clock?.() || new Date());
    const client = stripeClient(configuration, adapters);
    await readCheckoutProviderBindings(client, configuration, adapters.clock?.() || new Date());
    const beforeCreate = await ownedRecipientControl(store, input, authority, env);
    if (controlSuppression(beforeCreate)) throw new Error('ARC_REVIEW_CHECKOUT_RECIPIENT_SUPPRESSED');
    const parameters = checkoutParameters(input, configuration);
    let session;
    try {
      session = await client.checkout.sessions.create(parameters, { idempotencyKey: input.idempotency_key });
    } catch (cause) {
      throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE_PROVIDER_CREATE', { cause });
    }
    const created = validateSession(session, input, parameters.metadata, configuration);
    binding = await bindReviewCheckoutSession(store, input.approval_receipt_sha256, {
      id: created.id,
      integration_identifier: session.integration_identifier,
      livemode: session.livemode,
      url: created.url,
    }, env, adapters.clock?.() || new Date());
    const beforeRelease = await ownedRecipientControl(store, input, authority, env);
    if (controlSuppression(beforeRelease)) throw new Error('ARC_REVIEW_CHECKOUT_RECIPIENT_SUPPRESSED');
    await releaseReviewEmailRecipientAuthority(store, input.recipient_email_sha256,
      authority.operation_hmac_sha256, env, adapters.clock?.() || new Date());
    authorityReleased = true;
    return created;
  } catch (cause) {
    let releaseError = null;
    if (!authorityReleased) {
      try {
        await releaseReviewEmailRecipientAuthority(store, input.recipient_email_sha256,
          authority.operation_hmac_sha256, env, adapters.clock?.() || new Date());
      } catch (error) {
        releaseError = error;
      }
      authorityReleased = true;
    }
    const control = await readReviewEmailRecipientControl(store, input.recipient_email_sha256, env)
      .catch(() => null);
    const suppression = controlSuppression(control?.record);
    if (suppression) {
      await revokeAfterRecipientSuppression(store, binding, suppression, env, adapters);
      throw new Error('ARC_REVIEW_CHECKOUT_RECIPIENT_SUPPRESSED', { cause: releaseError || cause });
    }
    if (releaseError) throw releaseError;
    throw cause;
  }
}

export function createStripeReviewCheckoutAdapter(env = process.env, adapters = {}) {
  const createCheckout = input => createStripeReviewCheckout(input, env, adapters);
  Object.defineProperty(createCheckout, 'ownsRecipientAuthority', {
    configurable: false,
    enumerable: false,
    value: true,
    writable: false,
  });
  return createCheckout;
}
