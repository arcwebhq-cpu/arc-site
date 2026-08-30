import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import {
  ACTIVATION_MANIFEST_ENV,
  ACTIVATION_MANIFEST_SECRET_ENV,
  activationManifestSecretIsDistinct,
  validateActivationManifestEnvironment,
} from '../netlify/lib/activation-manifest-core.mjs';
import { transactionalEmailWorkerConfiguration } from '../netlify/lib/transactional-email-worker-core.mjs';
import { arc2ClaimLinkRenewalConfiguration } from '../netlify/lib/arc2-claim-link-renewal-core.mjs';
import { previewReviewResendWorkerConfiguration } from '../netlify/lib/review-email-resend-core.mjs';
import {
  arc2TransactionalEmailConfiguration,
  resendProviderAccountHmacSha256,
} from '../netlify/lib/arc2-transactional-email-core.mjs';
import {
  reviewActivationRuntimeReadbackConfiguration,
} from '../netlify/lib/review-activation-runtime-readback-core.mjs';
import {
  firstPartyRetentionConfiguration,
  firstPartyRetentionReceiptFromEnvironment,
} from '../netlify/lib/first-party-retention-core.mjs';
import { operationsAuditConfiguration } from '../netlify/lib/operations-audit-core.mjs';
import { claimSandboxBootstrapConfiguration } from '../netlify/lib/claim-sandbox-bootstrap-core.mjs';
import { retentionGenerationFenceConfiguration } from '../netlify/lib/retention-generation-fence-core.mjs';
import { ARC_STRIPE_API_VERSION } from '../netlify/lib/stripe-api-version.mjs';
import { sensitiveCredentialsAreIsolated } from '../netlify/lib/sensitive-credential-isolation.mjs';

const CONTRACT_URL = new URL('../operations/review-activation-environment.json', import.meta.url);
export const REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT = Object.freeze(
  JSON.parse(readFileSync(CONTRACT_URL, 'utf8')),
);

const HEX_40 = /^[a-f0-9]{40}$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const PRICE_ID = /^price_[A-Za-z0-9_]{6,128}$/;
const PRODUCT_ID = /^prod_[A-Za-z0-9_]{6,128}$/;
const TAX_CODE_ID = /^txcd_[0-9]{8}$/;
const INTEGRATION_ID = /^arc_review_checkout_[a-z]{8}$/;
const PROVIDER = /^[a-z0-9][a-z0-9_.-]{1,63}$/;
const RETIRED_TAX_CODE_ENV = 'ARC_EXPECTED_STRIPE_PRODUCT_TAX_CODE';
const TEST_BOOTSTRAP_OPTIONAL_SHA256_FIELD = 'email.sandbox_delivery_receipt_sha256';
const EXACT_BINDINGS = Object.freeze({
  ARC_EXPECTED_PRODUCT_NAME: 'ARC Fixed Five-Page Website',
  ARC_REVIEW_EMAIL_PROVIDER: 'resend',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
  URL: 'https://arcweb.onl',
  ARC_STRIPE_CHECKOUT_CANCEL_URL: 'https://arcweb.onl/review/?checkout=cancelled',
  ARC_STRIPE_CHECKOUT_OFFER_ID: 'arc-fixed-five-page-offer-v1',
  ARC_STRIPE_CHECKOUT_SUCCESS_URL:
    'https://arcweb.onl/payment-success/?session_id={CHECKOUT_SESSION_ID}',
  ARC_STRIPE_CHECKOUT_TERMS_VERSION: '2026-08-25',
  ARC_STRIPE_WEBHOOK_API_VERSION: ARC_STRIPE_API_VERSION,
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function validSecret(value) {
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= 32 &&
    Buffer.byteLength(value, 'utf8') <= 512;
}

function exactBoolean(value) {
  return value === 'true' || value === 'false';
}

function nonzeroSha256(value) {
  return typeof value === 'string' && HEX_64.test(value) && value !== '0'.repeat(64);
}

function bindingValid(name, format, value) {
  if (Object.hasOwn(EXACT_BINDINGS, name)) return value === EXACT_BINDINGS[name];
  if (format === 'uuid') return typeof value === 'string' && UUID.test(value);
  if (format === 'sha256') return nonzeroSha256(value);
  if (format === 'stripe_price_id') return typeof value === 'string' && PRICE_ID.test(value);
  if (format === 'stripe_product_id') return typeof value === 'string' && PRODUCT_ID.test(value);
  if (format === 'stripe_tax_code') return typeof value === 'string' && TAX_CODE_ID.test(value);
  if (format === 'checkout_integration_id') return typeof value === 'string' && INTEGRATION_ID.test(value);
  if (format === 'provider_slug') return typeof value === 'string' && PROVIDER.test(value);
  if (format === 'provider_account_id') {
    return typeof value === 'string' && value === value.trim() && value.length >= 3 && value.length <= 128 &&
      !/[\u0000-\u001f\u007f]/.test(value);
  }
  if (format === 'canonical_https_url') {
    if (typeof value !== 'string' || value.length > 2_048) return false;
    try {
      const url = new URL(value);
      return url.href === value && url.protocol === 'https:' && !url.username && !url.password &&
        !url.search && !url.hash && !url.port && url.hostname.includes('.');
    } catch { return false; }
  }
  if (format === 'ed25519_spki_base64') {
    if (typeof value !== 'string' || value.length < 40 || value.length > 256) return false;
    try {
      const der = Buffer.from(value, 'base64');
      if (der.length === 0 || der.toString('base64') !== value) return false;
      const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
      return key.asymmetricKeyType === 'ed25519' &&
        key.export({ format: 'der', type: 'spki' }).equals(der);
    } catch { return false; }
  }
  if (format === 'retention_days') {
    return typeof value === 'string' && /^(?:[7-9]|[1-9][0-9]|[12][0-9]{2}|3[0-5][0-9]|36[0-5])$/.test(value);
  }
  if (format === 'first_party_unpaid_days') return value === '730';
  if (format === 'first_party_paid_days') return value === '2555';
  if (format === 'first_party_retention_receipt') {
    return typeof value === 'string' && Buffer.byteLength(value, 'utf8') > 0 &&
      Buffer.byteLength(value, 'utf8') <= 32_768;
  }
  if (format === 'email_sender') {
    return typeof value === 'string' && value === value.trim() && value.length <= 320 &&
      /^(?:[^<>\r\n]{1,80} <)?[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+>?$/.test(value);
  }
  if (format === 'email_recipient') {
    return typeof value === 'string' && value === value.trim() && value === value.toLowerCase() &&
      value.length <= 320 && /^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/.test(value);
  }
  return false;
}

function appliesToMode(entry, mode) {
  return !Array.isArray(entry.modes) || entry.modes.includes(mode);
}

function selectedSecretAliasNames(env, mode) {
  const selected = [];
  for (const group of REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.secret_alias_groups || []) {
    if (!appliesToMode(group, mode)) continue;
    const names = [group.canonical, ...(group.aliases || [])];
    const present = names.filter((name) => typeof env[name] === 'string' && env[name].length > 0);
    if (present.length === 1) selected.push(present[0]);
    else selected.push(group.canonical);
  }
  return selected;
}

function valueAtPath(value, path) {
  return path.split('.').reduce((current, key) => current?.[key], value);
}

export function reviewActivationRequiredEnvironmentNames(mode, env = {}) {
  const profile = REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.profiles[mode];
  if (!profile) throw new TypeError('Review activation mode is invalid.');
  return [...new Set([
    ...Object.keys(profile.flags),
    ...REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.secrets.filter((entry) => appliesToMode(entry, mode))
      .map(({ name }) => name),
    ...selectedSecretAliasNames(env, mode),
    ...REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.bindings.filter((entry) => appliesToMode(entry, mode))
      .map(({ name }) => name),
    REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.env_name,
    'ARC_ACTIVATION_MANIFEST',
  ])].sort();
}

export function reviewActivationRouteMatrixSha256() {
  return sha256(canonicalJson(REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.routes));
}

export function reviewActivationStripeWebhookEventSetSha256() {
  return sha256(canonicalJson([...REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.stripe_webhook.events].sort()));
}

export function reviewActivationEnvironmentNamesSha256(mode, env = {}) {
  return sha256(canonicalJson(reviewActivationRequiredEnvironmentNames(mode, env)));
}

function validateReadback(env, mode, profile, now, invalid, {
  allowMissingSandboxDeliveryReceipt = false,
  allowStaleReference = false,
} = {}) {
  const readbackName = REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.env_name;
  let value;
  try { value = JSON.parse(env[readbackName]); } catch {
    invalid.push(readbackName);
    return false;
  }
  const topFields = [
    'schema', 'version', 'mode', 'minimum_stage', 'provider_controls_state', 'observed_at',
    'expires_at', 'netlify', 'stripe', 'email', 'operations_alert', 'zapier',
  ];
  if (!exactKeys(value, topFields) ||
      value.schema !== REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.schema ||
      value.version !== 1 || value.mode !== mode || value.minimum_stage !== profile.minimum_stage ||
      value.provider_controls_state !== REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.provider_controls_state) {
    invalid.push(`${readbackName}:CONTRACT`);
    return false;
  }
  const observed = Date.parse(value.observed_at);
  const expires = Date.parse(value.expires_at);
  const maximumAge = REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.maximum_age_seconds * 1000;
  if (!Number.isFinite(observed) || !Number.isFinite(expires) ||
      new Date(observed).toISOString() !== value.observed_at ||
      new Date(expires).toISOString() !== value.expires_at || observed > now.getTime() + 60_000 ||
      expires <= observed || expires - observed > maximumAge ||
      (!allowStaleReference && (now.getTime() - observed > maximumAge || expires <= now.getTime()))) {
    invalid.push(`${readbackName}:FRESHNESS`);
  }

  const netlifyFields = [
    'deployment_sha', 'env_name_set_readback_sha256', 'route_matrix_readback_sha256',
    'route_probe_receipt_sha256', 'site_id_sha256', 'handoff_credential_environment_name',
  ];
  const stripeFields = [
    'account_id_sha256', 'catalog_readback_sha256',
    'checkout_session_expire_capability_readback_sha256',
    'checkout_session_retrieve_capability_readback_sha256', 'integration_identifier_sha256',
    'price_id_sha256', 'product_id_sha256', 'webhook_destination_readback_sha256',
    'webhook_endpoint_path', 'webhook_event_set_readback_sha256',
  ];
  const emailFields = [
    'native_suppression_id_sha256', 'native_suppression_readback_sha256',
    'native_webhook_id_sha256', 'native_webhook_readback_sha256', 'provider',
    'provider_account_id_sha256', 'sandbox_delivery_receipt_sha256', 'sender_identity_sha256',
  ];
  const zapierFields = [
    'checkout_revocation_worker_contract_receipt_sha256',
    'checkout_revocation_workflow_id_sha256', 'checkout_revocation_workflow_version_readback_sha256',
    'claim_next_contract_receipt_sha256', 'email_claim_next_path', 'email_workflow_id_sha256',
    'email_workflow_version_readback_sha256', 'payment_arc2_claim_next_path',
    'payment_arc2_start_path', 'payment_arc2_start_contract_receipt_sha256',
    'payment_arc2_workflow_id_sha256', 'payment_arc2_workflow_version_readback_sha256',
    'revision_claim_next_path', 'revision_workflow_id_sha256',
    'revision_workflow_version_readback_sha256',
  ];
  const operationsAlertFields = [
    'audit_enabled', 'delivery_enabled', 'failure_alert_verified',
    'native_delivery_receipt_sha256', 'provider_event_type',
  ];
  if (!exactKeys(value.netlify, netlifyFields) || !exactKeys(value.stripe, stripeFields) ||
      !exactKeys(value.email, emailFields) ||
      !exactKeys(value.operations_alert, operationsAlertFields) ||
      !exactKeys(value.zapier, zapierFields)) {
    invalid.push(`${readbackName}:FIELDS`);
    return false;
  }
  const bindingsValid =
    value.netlify.site_id_sha256 === sha256(env.ARC_EXPECTED_NETLIFY_SITE_ID) &&
    HEX_40.test(value.netlify.deployment_sha) &&
    value.netlify.env_name_set_readback_sha256 === reviewActivationEnvironmentNamesSha256(mode, env) &&
    value.netlify.route_matrix_readback_sha256 === reviewActivationRouteMatrixSha256() &&
    value.netlify.handoff_credential_environment_name === selectedSecretAliasNames(env, mode)[0] &&
    value.stripe.account_id_sha256 === env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 &&
    value.stripe.price_id_sha256 === sha256(env.ARC_EXPECTED_PRICE_ID) &&
    value.stripe.product_id_sha256 === sha256(env.ARC_EXPECTED_PRODUCT_ID) &&
    value.stripe.integration_identifier_sha256 === sha256(env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER) &&
    value.stripe.webhook_endpoint_path ===
      REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.stripe_webhook.endpoint_path &&
    value.stripe.webhook_event_set_readback_sha256 === reviewActivationStripeWebhookEventSetSha256() &&
    value.email.provider === env.ARC_REVIEW_EMAIL_PROVIDER &&
    value.email.provider_account_id_sha256 === env.ARC_REVIEW_EMAIL_PROVIDER_ACCOUNT_ID_SHA256 &&
    value.email.sender_identity_sha256 === env.ARC_REVIEW_EMAIL_SENDER_IDENTITY_SHA256 &&
    value.email.native_webhook_id_sha256 === env.ARC_REVIEW_EMAIL_NATIVE_WEBHOOK_ID_SHA256 &&
    value.email.native_suppression_id_sha256 === env.ARC_REVIEW_EMAIL_NATIVE_SUPPRESSION_ID_SHA256 &&
    value.zapier.email_workflow_id_sha256 === env.ARC_ZAPIER_REVIEW_EMAIL_WORKFLOW_ID_SHA256 &&
    value.zapier.revision_workflow_id_sha256 === env.ARC_ZAPIER_REVIEW_REVISION_WORKFLOW_ID_SHA256 &&
    value.zapier.payment_arc2_workflow_id_sha256 === env.ARC_ZAPIER_PAYMENT_ARC2_WORKFLOW_ID_SHA256 &&
    value.zapier.checkout_revocation_workflow_id_sha256 ===
      env.ARC_ZAPIER_REVIEW_CHECKOUT_REVOCATION_WORKFLOW_ID_SHA256 &&
    value.zapier.email_claim_next_path === '/api/internal/review-email/reserve' &&
    value.zapier.revision_claim_next_path === '/api/internal/review-revision/claim' &&
    value.zapier.payment_arc2_claim_next_path === '/internal/payment-arc2/claim' &&
    value.zapier.payment_arc2_start_path === '/internal/payment-arc2/start' &&
    value.operations_alert.audit_enabled ===
      (profile.flags.ARC_OPERATIONS_AUDIT_ENABLED === 'true') &&
    value.operations_alert.delivery_enabled ===
      (profile.flags.ARC_OPERATIONS_ALERT_DELIVERY_ENABLED === 'true') &&
    value.operations_alert.failure_alert_verified === false &&
    value.operations_alert.native_delivery_receipt_sha256 === '0'.repeat(64) &&
    value.operations_alert.provider_event_type ===
      REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.operations_alert.provider_event_type;
  if (!bindingsValid) invalid.push(`${readbackName}:BINDINGS`);
  for (const path of REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.required_sha256_fields) {
    const digestValue = valueAtPath(value, path);
    if (allowMissingSandboxDeliveryReceipt && path === TEST_BOOTSTRAP_OPTIONAL_SHA256_FIELD) {
      if (digestValue !== '0'.repeat(64) && !nonzeroSha256(digestValue)) {
        invalid.push(`${readbackName}:${path}`);
      }
      continue;
    }
    if (!nonzeroSha256(digestValue)) invalid.push(`${readbackName}:${path}`);
  }
  return !invalid.some((name) => name.startsWith(readbackName));
}

export function createReviewActivationEnvironmentReport(
  env = process.env,
  { mode = 'off', now = new Date() } = {},
) {
  if (!['off', 'sandbox', 'production'].includes(mode) ||
      !(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new TypeError('Review activation preflight options are invalid.');
  }
  const invalid = [];
  const missing = [];
  const enabledFlags = [];
  const activationFlags = REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.activation_flags;
  for (const name of activationFlags) {
    const value = env[name];
    if (value === 'true') enabledFlags.push(name);
    if (value !== undefined && value !== '' && !exactBoolean(value)) invalid.push(name);
  }
  if (mode === 'off') {
    invalid.push(...enabledFlags);
    const uniqueInvalid = [...new Set(invalid)].sort();
    return Object.freeze({
      schema: 'arc-review-activation-preflight-report-v1',
      mode,
      state: uniqueInvalid.length === 0 ? 'SAFE_OFF' : 'INVALID',
      ok: uniqueInvalid.length === 0,
      checks: Object.freeze({ all_controls_off: enabledFlags.length === 0 }),
      enabled_flags: Object.freeze([...enabledFlags].sort()),
      missing: Object.freeze([]),
      invalid: Object.freeze(uniqueInvalid),
      blocked: Object.freeze([]),
    });
  }

  const profile = REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.profiles[mode];
  for (const [name, expected] of Object.entries(profile.flags)) {
    if (env[name] === undefined || env[name] === '') missing.push(name);
    else if (env[name] !== expected) invalid.push(name);
  }
  if (env[RETIRED_TAX_CODE_ENV] !== undefined && env[RETIRED_TAX_CODE_ENV] !== '') {
    invalid.push(RETIRED_TAX_CODE_ENV);
  }
  const secretNames = REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.secrets
    .filter((entry) => appliesToMode(entry, mode)).map(({ name }) => name);
  for (const name of secretNames) {
    if (env[name] === undefined || env[name] === '') missing.push(name);
    else if (!validSecret(env[name])) invalid.push(name);
  }
  const selectedAliasSecretNames = [];
  for (const group of REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.secret_alias_groups || []) {
    if (!appliesToMode(group, mode)) continue;
    const names = [group.canonical, ...(group.aliases || [])];
    const present = names.filter((name) => typeof env[name] === 'string' && env[name].length > 0);
    const label = names.join('|');
    if (group.policy !== 'exactly_one') invalid.push(`${label}:POLICY`);
    else if (present.length === 0) missing.push(label);
    else if (present.length !== 1) invalid.push(`${label}:EXACTLY_ONE`);
    else if (!validSecret(env[present[0]])) invalid.push(present[0]);
    else selectedAliasSecretNames.push(present[0]);
  }
  const configuredSecretNames = [...secretNames, ...selectedAliasSecretNames];
  if (configuredSecretNames.every((name) => validSecret(env[name])) &&
      !sensitiveCredentialsAreIsolated(env, configuredSecretNames)) {
    invalid.push('SECRET_DISTINCTNESS');
  }
  const retentionGenerationFence = retentionGenerationFenceConfiguration(env);
  if (!retentionGenerationFence.ready) invalid.push('RETENTION_GENERATION_FENCE_CONFIGURATION');
  const keyMode = profile.stripe_key_mode;
  if (!new RegExp(`^rk_${keyMode}_[A-Za-z0-9_]{16,240}$`)
    .test(String(env.ARC_STRIPE_REVIEW_SECRET_KEY || ''))) invalid.push('ARC_STRIPE_REVIEW_SECRET_KEY');
  if (!new RegExp(`^rk_${keyMode}_[A-Za-z0-9_]{16,240}$`)
    .test(String(env.ARC_STRIPE_ACCOUNT_VERIFICATION_KEY || ''))) {
    invalid.push('ARC_STRIPE_ACCOUNT_VERIFICATION_KEY');
  }
  if (!/^whsec_[A-Za-z0-9_]{16,240}$/.test(String(env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET || ''))) {
    invalid.push('ARC_STRIPE_WEBHOOK_SIGNING_SECRET');
  }
  if (!/^re_[A-Za-z0-9_-]{16,252}$/.test(String(env.ARC_RESEND_API_KEY || ''))) {
    invalid.push('ARC_RESEND_API_KEY');
  }
  if (!/^whsec_[A-Za-z0-9+/]{20,256}={0,2}$/.test(String(env.ARC_RESEND_WEBHOOK_SECRET || ''))) {
    invalid.push('ARC_RESEND_WEBHOOK_SECRET');
  }
  for (const { name, format } of REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.bindings
    .filter((entry) => appliesToMode(entry, mode))) {
    if (env[name] === undefined || env[name] === '') missing.push(name);
    else if (!bindingValid(name, format, env[name])) invalid.push(name);
  }
  const activationAuthority = validateActivationManifestEnvironment(env, {
    minimumStage: profile.minimum_stage,
    now,
  });
  const testBootstrapAuthority = mode === 'sandbox' && activationAuthority.valid &&
    activationAuthority.authority_mode === 'TEST_BOOTSTRAP';
  const emailTestBootstrapAuthority = testBootstrapAuthority &&
    activationAuthority.stage === 'EMAIL_SANDBOX';
  const claimTestBootstrapAuthority = testBootstrapAuthority &&
    activationAuthority.stage === 'CLAIM_SANDBOX';
  const claimSandboxBootstrap = claimSandboxBootstrapConfiguration(env, now);
  const readbackName = REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.env_name;
  let staticReadbackValid = false;
  if (env[readbackName] === undefined || env[readbackName] === '') missing.push(readbackName);
  else staticReadbackValid = validateReadback(env, mode, profile, now, invalid, {
    allowMissingSandboxDeliveryReceipt: emailTestBootstrapAuthority,
    allowStaleReference: mode === 'production' &&
      env.ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED === 'true',
  });
  if (env[ACTIVATION_MANIFEST_ENV] === undefined || env[ACTIVATION_MANIFEST_ENV] === '') {
    missing.push(ACTIVATION_MANIFEST_ENV);
  }
  if (env[ACTIVATION_MANIFEST_SECRET_ENV] === undefined || env[ACTIVATION_MANIFEST_SECRET_ENV] === '') {
    missing.push(ACTIVATION_MANIFEST_SECRET_ENV);
  }
  if (!activationAuthority.valid || !activationManifestSecretIsDistinct(env)) {
    invalid.push('ACTIVATION_MANIFEST_AUTHORITY');
  }
  if (claimTestBootstrapAuthority &&
      (!claimSandboxBootstrap.enabled || !claimSandboxBootstrap.bootstrap_active)) {
    invalid.push('CLAIM_SANDBOX_BOOTSTRAP_CONFIGURATION');
  }
  const emailFlagNames = [
    'ARC_EMAIL_RECIPIENT_VAULT_ENABLED',
    'ARC_RESEND_SEND_ENABLED',
    'ARC_RESEND_WEBHOOK_ENABLED',
    'ARC_TRANSACTIONAL_EMAIL_ENABLED',
    'ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED',
  ];
  const emailFlagsCoherent = emailFlagNames.every((name) => env[name] === 'true');
  let transactionalEmailRuntimeEnabled = false;
  try { transactionalEmailRuntimeEnabled = transactionalEmailWorkerConfiguration(env).enabled; } catch {}
  if (!emailFlagsCoherent || !transactionalEmailRuntimeEnabled) {
    invalid.push('TRANSACTIONAL_EMAIL_RUNTIME_CONFIGURATION');
  }
  let reviewResendRuntimeEnabled = false;
  try { reviewResendRuntimeEnabled = previewReviewResendWorkerConfiguration(env).enabled; } catch {}
  if (!reviewResendRuntimeEnabled) invalid.push('REVIEW_RESEND_RUNTIME_CONFIGURATION');
  const arc2Email = arc2TransactionalEmailConfiguration(env);
  let resendProviderBindingValid = false;
  try { resendProviderBindingValid = HEX_64.test(resendProviderAccountHmacSha256(env)); } catch {}
  const arc2EmailRuntimeEnabled = arc2Email.flags_valid && (!arc2Email.requested ||
    (arc2Email.capsule_producer_enabled && resendProviderBindingValid));
  if (!arc2EmailRuntimeEnabled) invalid.push('ARC2_EMAIL_RUNTIME_CONFIGURATION');
  const claimLinkRenewalRuntimeEnabled = arc2ClaimLinkRenewalConfiguration(env).enabled;
  if (env.ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED === 'true' && !claimLinkRenewalRuntimeEnabled) {
    invalid.push('ARC2_CLAIM_LINK_RENEWAL_RUNTIME_CONFIGURATION');
  }
  const retentionConfigurationValid = env.ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED === 'false' ||
    (env.ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED === 'true' &&
      bindingValid('ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS', 'retention_days',
        env.ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS));
  if (!retentionConfigurationValid) invalid.push('TRANSACTIONAL_EMAIL_RETENTION_CONFIGURATION');
  let firstPartyRetentionConfigurationValid = mode !== 'production';
  let firstPartyRetentionReceiptCurrent = mode !== 'production';
  let firstPartyRetentionAlertQueueReady = mode !== 'production';
  if (mode === 'production') {
    try {
      firstPartyRetentionConfigurationValid = firstPartyRetentionConfiguration(env).enabled;
      firstPartyRetentionReceiptCurrent =
        firstPartyRetentionReceiptFromEnvironment(env, now) !== null;
      firstPartyRetentionAlertQueueReady = operationsAuditConfiguration(env).enabled;
    } catch {
      firstPartyRetentionConfigurationValid = false;
      firstPartyRetentionReceiptCurrent = false;
      firstPartyRetentionAlertQueueReady = false;
    }
    if (!firstPartyRetentionConfigurationValid) {
      invalid.push('FIRST_PARTY_RETENTION_CONFIGURATION');
    }
    if (!firstPartyRetentionReceiptCurrent) {
      invalid.push('FIRST_PARTY_RETENTION_CURRENT_RECEIPT');
    }
    if (!firstPartyRetentionAlertQueueReady) {
      invalid.push('FIRST_PARTY_RETENTION_ALERT_QUEUE_CONFIGURATION');
    }
  }
  let runtimeProviderReadbackConfigured = mode !== 'production';
  if (mode === 'production') {
    try {
      runtimeProviderReadbackConfigured = reviewActivationRuntimeReadbackConfiguration(env, now).configured;
    } catch { runtimeProviderReadbackConfigured = false; }
    if (!runtimeProviderReadbackConfigured) invalid.push('RUNTIME_PROVIDER_READBACK_CONFIGURATION');
  }

  const uniqueMissing = [...new Set(missing)].sort();
  const uniqueInvalid = [...new Set(invalid)].sort();
  const blocked = [...(profile.blocked_controls || [])];
  const configured = uniqueMissing.length === 0 && uniqueInvalid.length === 0;
  const ok = configured && blocked.length === 0;
  return Object.freeze({
    schema: 'arc-review-activation-preflight-report-v1',
    mode,
    state: !configured ? 'INVALID' : blocked.length ? `${mode.toUpperCase()}_BLOCKED` :
      `${mode.toUpperCase()}_CONFIGURED`,
    ok,
    checks: Object.freeze({
      bindings_valid: configured && !uniqueInvalid.some((name) => name.includes('BINDING')),
      exact_mode: configured && Object.entries(profile.flags).every(([name, value]) => env[name] === value),
      external_controls_off: configured,
      activation_authority_valid: activationAuthority.valid && activationManifestSecretIsDistinct(env),
      test_bootstrap_authority: testBootstrapAuthority,
      test_bootstrap_delivery_receipt_exempted: emailTestBootstrapAuthority,
      claim_sandbox_bootstrap_authority: claimTestBootstrapAuthority,
      claim_sandbox_bootstrap_ready: !claimTestBootstrapAuthority ||
        (claimSandboxBootstrap.enabled && claimSandboxBootstrap.bootstrap_active),
      provider_readback_current: mode === 'sandbox' && staticReadbackValid,
      static_readback_reference_valid: staticReadbackValid,
      secrets_distinct: !uniqueInvalid.includes('SECRET_DISTINCTNESS'),
      retention_generation_fence_ready: retentionGenerationFence.ready &&
        !uniqueInvalid.includes('SECRET_DISTINCTNESS'),
      transactional_email_runtime_enabled: transactionalEmailRuntimeEnabled,
      review_resend_runtime_enabled: reviewResendRuntimeEnabled,
      arc2_email_runtime_enabled: arc2EmailRuntimeEnabled,
      claim_link_renewal_runtime_enabled: claimLinkRenewalRuntimeEnabled,
      resend_provider_binding_valid: resendProviderBindingValid,
      transactional_email_retention_valid: retentionConfigurationValid,
      first_party_retention_configuration_valid: firstPartyRetentionConfigurationValid,
      first_party_retention_alert_queue_ready: firstPartyRetentionAlertQueueReady,
      first_party_retention_receipt_current: firstPartyRetentionReceiptCurrent,
      runtime_provider_readback_configured: runtimeProviderReadbackConfigured,
      netlify_handoff_credential_exactly_one: selectedAliasSecretNames.length === 1,
      operations_alert_provider_evidence_verified: false,
    }),
    enabled_flags: Object.freeze([...enabledFlags].sort()),
    missing: Object.freeze(uniqueMissing),
    invalid: Object.freeze(uniqueInvalid),
    blocked: Object.freeze(blocked),
  });
}

export function runReviewActivationPreflightCli({ argv = process.argv.slice(2), env = process.env,
  now = new Date(), write = (value) => process.stdout.write(value) } = {}) {
  const matches = argv.map((arg) => /^--mode=(off|sandbox|production)$/.exec(arg)).filter(Boolean);
  if (matches.length !== 1 || argv.length !== 1) return 2;
  const report = createReviewActivationEnvironmentReport(env, { mode: matches[0][1], now });
  write(`${JSON.stringify(report)}\n`);
  return report.ok ? 0 : 1;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = runReviewActivationPreflightCli();
}
