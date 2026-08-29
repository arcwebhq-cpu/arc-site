import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import {
  RESEND_FROM_IDENTITY,
  RESEND_RECONCILED_EVENT_TYPES,
  RESEND_REQUIRED_WEBHOOK_EVENT_TYPES,
  RESEND_SENDING_DOMAIN,
  RESEND_WEBHOOK_PATH,
} from '../netlify/lib/resend-transactional-provider-core.mjs';
import { ARC_STRIPE_API_VERSION } from '../netlify/lib/stripe-api-version.mjs';
import { AUTOMATION_FLAG_NAMES } from './launch-preflight.mjs';

const CONTRACT_URL = new URL('../operations/provider-sandbox-safe-off.json', import.meta.url);
const ACTIVATION_CONTRACT_URL = new URL('../operations/review-activation-environment.json', import.meta.url);

export const PROVIDER_SANDBOX_SAFE_OFF_CONTRACT = Object.freeze(
  JSON.parse(readFileSync(CONTRACT_URL, 'utf8')),
);

const ACTIVATION_CONTRACT = JSON.parse(readFileSync(ACTIVATION_CONTRACT_URL, 'utf8'));
const EXTRA_SAFE_OFF_FLAGS = Object.freeze([
  'ARC_ALLOW_TEST_MODE_EVENTS',
  'ARC_BUILD_TURNSTILE_ENABLED',
  'ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED',
]);
export const PROVIDER_SAFE_OFF_FLAG_NAMES = Object.freeze(
  [...new Set([...AUTOMATION_FLAG_NAMES, ...EXTRA_SAFE_OFF_FLAGS])].sort(),
);
const EXPECTED_NON_SECRET_ENVIRONMENT = Object.freeze({
  ARC_RUNTIME_ENVIRONMENT: 'sandbox',
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_PUBLIC_ORIGIN: 'https://arcweb.onl',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256:
    'd5930b33d3c47b0ec9dad6652a475da7a238e639e31259f558a9bfba8f4489b9',
  ARC_EXPECTED_PRODUCT_ID: 'prod_V9v4lUUnhp1sZN',
  ARC_EXPECTED_PRICE_ID: 'price_1U9bENGv1R7moOUqQAqMfyHY',
  ARC_EXPECTED_PRODUCT_NAME: 'ARC Fixed Five-Page Website',
  ARC_EXPECTED_PRODUCT_TAX_CODE: 'txcd_10701200',
  ARC_STRIPE_CHECKOUT_OFFER_ID: 'arc-fixed-five-page-offer-v1',
  ARC_STRIPE_CHECKOUT_TERMS_VERSION: '2026-08-25',
  ARC_STRIPE_WEBHOOK_API_VERSION: ARC_STRIPE_API_VERSION,
  ARC_STRIPE_CHECKOUT_SUCCESS_URL:
    'https://arcweb.onl/payment-success/?session_id={CHECKOUT_SESSION_ID}',
  ARC_STRIPE_CHECKOUT_CANCEL_URL: 'https://arcweb.onl/review/?checkout=cancelled',
  ARC_REVIEW_EMAIL_PROVIDER: 'resend',
  ARC_RESEND_FROM: RESEND_FROM_IDENTITY,
});
const EXPECTED_REVIEW_KEY_SCOPES = Object.freeze([
  'Products Read',
  'Prices Read',
  'Checkout Sessions Write',
  'Tax Settings/Registrations Read',
]);
const EXPECTED_REVIEW_KEY_RUNTIME_OPERATIONS = Object.freeze([
  'GET /v1/account',
  'GET /v1/prices/:id',
  'POST /v1/checkout/sessions',
  'GET /v1/checkout/sessions/:id',
  'POST /v1/checkout/sessions/:id/expire',
  'GET /v1/tax/settings',
  'GET /v1/tax/registrations',
]);
const EXPECTED_ACCOUNT_KEY_SCOPES = Object.freeze([
  'Events Read',
  'Payment Intents Read',
  'Checkout Sessions Read',
]);
const EXPECTED_ACCOUNT_KEY_RUNTIME_OPERATIONS = Object.freeze([
  'GET /v1/account',
  'GET /v1/events/:id',
  'GET /v1/checkout/sessions/:id',
]);
const EXPECTED_UNVERIFIED_RUNTIME_OPERATIONS = Object.freeze(['GET /v1/account']);
const EXPECTED_BLOCKERS = Object.freeze([
  'STRIPE_RESTRICTED_KEY_RUNTIME_SCOPE_MISMATCH',
  'STRIPE_WEBHOOK_NOT_CREATED',
  'PROVIDER_E2E_NOT_RUN',
]);
const POSSIBLE_SECRET = /(?:[sr]k_(?:test|live)|re_|whsec_)[A-Za-z0-9_+/=-]{16,}|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/;
const BOOLEAN_FLAG_SUFFIX = /_(?:ENABLED|VERIFIED|REQUIRED)$/;

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, keys) {
  return plainObject(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function exactArray(value, expected) {
  return Array.isArray(value) && JSON.stringify(value) === JSON.stringify(expected);
}

function sameObject(value, expected) {
  return exactKeys(value, Object.keys(expected)) &&
    Object.entries(expected).every(([name, expectedValue]) => value[name] === expectedValue);
}

function containsSecretMaterial(value) {
  if (typeof value === 'string') return POSSIBLE_SECRET.test(value);
  if (Array.isArray(value)) return value.some(containsSecretMaterial);
  if (plainObject(value)) return Object.values(value).some(containsSecretMaterial);
  return false;
}

export function createProviderSandboxSafeOffContractReport(
  contract = PROVIDER_SANDBOX_SAFE_OFF_CONTRACT,
) {
  const invalid = [];
  if (!exactKeys(contract, [
    'schema', 'version', 'state', 'launch_ready', 'safe_off_environment',
    'non_secret_environment', 'stripe', 'resend', 'blockers',
  ]) || contract.schema !== 'arc-provider-sandbox-safe-off-v1' ||
      contract.version !== 1 || contract.state !== 'SAFE_OFF' || contract.launch_ready !== false) {
    invalid.push('CONTRACT_SHAPE');
  }

  const safeOffNames = plainObject(contract.safe_off_environment)
    ? Object.keys(contract.safe_off_environment).sort() : [];
  if (!exactArray(safeOffNames, PROVIDER_SAFE_OFF_FLAG_NAMES) ||
      safeOffNames.some((name) => contract.safe_off_environment[name] !== 'false')) {
    invalid.push('SAFE_OFF_ENVIRONMENT');
  }
  if (!sameObject(contract.non_secret_environment, EXPECTED_NON_SECRET_ENVIRONMENT)) {
    invalid.push('NON_SECRET_ENVIRONMENT');
  }
  if (contract.non_secret_environment?.ARC_STRIPE_WEBHOOK_API_VERSION !== ARC_STRIPE_API_VERSION ||
      ACTIVATION_CONTRACT?.stripe_webhook?.api_version !== ARC_STRIPE_API_VERSION) {
    invalid.push('STRIPE_API_VERSION_BINDING');
  }
  if (containsSecretMaterial(contract)) invalid.push('SECRET_MATERIAL_FORBIDDEN');

  const catalog = contract.stripe?.catalog;
  if (!exactKeys(contract.stripe, [
    'mode', 'catalog', 'restricted_keys', 'webhook_contract_source',
    'webhook_status', 'tax_registration_action',
  ]) || contract.stripe.mode !== 'test' ||
      !exactKeys(catalog, [
        'product_id', 'price_id', 'product_name', 'description', 'currency', 'unit_amount',
        'price_type', 'tax_behavior', 'product_tax_code', 'product_active', 'price_active', 'livemode',
      ]) || catalog?.product_id !== EXPECTED_NON_SECRET_ENVIRONMENT.ARC_EXPECTED_PRODUCT_ID ||
      catalog?.price_id !== EXPECTED_NON_SECRET_ENVIRONMENT.ARC_EXPECTED_PRICE_ID ||
      catalog?.product_name !== EXPECTED_NON_SECRET_ENVIRONMENT.ARC_EXPECTED_PRODUCT_NAME ||
      catalog?.product_tax_code !== EXPECTED_NON_SECRET_ENVIRONMENT.ARC_EXPECTED_PRODUCT_TAX_CODE ||
      catalog?.currency !== 'usd' || catalog?.unit_amount !== 500_000 ||
      catalog?.price_type !== 'one_time' || catalog?.tax_behavior !== 'exclusive' ||
      catalog?.product_active !== true || catalog?.price_active !== true || catalog?.livemode !== false ||
      contract.stripe.webhook_contract_source !==
        'operations/review-activation-environment.json#stripe_webhook' ||
      contract.stripe.webhook_status !== 'NOT_CREATED' ||
      contract.stripe.tax_registration_action !== 'UNCHANGED') {
    invalid.push('STRIPE_SANDBOX_BINDING');
  }

  const [reviewKey, accountKey, ...extraKeys] = Array.isArray(contract.stripe?.restricted_keys)
    ? contract.stripe.restricted_keys : [];
  const keyShape = (value) => exactKeys(value, [
    'environment_name', 'required_prefix', 'storage_context', 'status', 'observed_scopes',
    'runtime_operations', 'unverified_runtime_operations',
  ]) && value.required_prefix === 'rk_test_' && value.status === 'STORED' &&
    value.storage_context === 'NETLIFY_DEPLOY_PREVIEW_ONLY';
  if (extraKeys.length !== 0 || !keyShape(reviewKey) || !keyShape(accountKey) ||
      reviewKey.environment_name !== 'ARC_STRIPE_REVIEW_SECRET_KEY' ||
      accountKey.environment_name !== 'ARC_STRIPE_ACCOUNT_VERIFICATION_KEY' ||
      !exactArray(reviewKey.observed_scopes, EXPECTED_REVIEW_KEY_SCOPES) ||
      !exactArray(reviewKey.runtime_operations, EXPECTED_REVIEW_KEY_RUNTIME_OPERATIONS) ||
      !exactArray(reviewKey.unverified_runtime_operations, EXPECTED_UNVERIFIED_RUNTIME_OPERATIONS) ||
      !exactArray(accountKey.observed_scopes, EXPECTED_ACCOUNT_KEY_SCOPES) ||
      !exactArray(accountKey.runtime_operations, EXPECTED_ACCOUNT_KEY_RUNTIME_OPERATIONS) ||
      !exactArray(accountKey.unverified_runtime_operations, EXPECTED_UNVERIFIED_RUNTIME_OPERATIONS)) {
    invalid.push('STRIPE_RESTRICTED_KEY_CAPABILITIES');
  }

  const resend = contract.resend;
  const sender = resend?.sender_identity;
  const apiKey = resend?.api_key;
  const webhook = resend?.webhook;
  const stripeWebhook = ACTIVATION_CONTRACT?.stripe_webhook;
  if (!exactKeys(resend, ['sending_domain', 'dns_status', 'sender_identity', 'api_key', 'webhook']) ||
      resend?.sending_domain !== RESEND_SENDING_DOMAIN || resend?.dns_status !== 'VERIFIED' ||
      !exactKeys(sender, ['status', 'storage_context', 'value']) ||
      sender?.status !== 'STAGED' || sender?.storage_context !== 'NETLIFY_PRODUCTION_ONLY' ||
      sender?.value !== EXPECTED_NON_SECRET_ENVIRONMENT.ARC_RESEND_FROM ||
      !exactKeys(apiKey, [
        'environment_name', 'required_prefix', 'domain_scope', 'permission', 'storage_context', 'status',
      ]) || apiKey?.environment_name !== 'ARC_RESEND_API_KEY' || apiKey?.required_prefix !== 're_' ||
      apiKey?.domain_scope !== RESEND_SENDING_DOMAIN || apiKey?.permission !== 'emails.send' ||
      apiKey?.storage_context !== 'NETLIFY_PRODUCTION_ONLY' || apiKey?.status !== 'STORED' ||
      !exactKeys(webhook, [
        'url', 'path', 'status', 'signing_secret_storage_context', 'required_events', 'subscribed_events',
      ]) ||
      webhook?.url !== `https://arcweb.onl${RESEND_WEBHOOK_PATH}` ||
      webhook?.path !== RESEND_WEBHOOK_PATH || webhook?.status !== 'ENABLED' ||
      webhook?.signing_secret_storage_context !== 'NETLIFY_PRODUCTION_ONLY' ||
      !exactArray(webhook?.required_events, RESEND_REQUIRED_WEBHOOK_EVENT_TYPES) ||
      !exactArray(webhook?.subscribed_events, RESEND_RECONCILED_EVENT_TYPES) ||
      stripeWebhook?.endpoint_path !== '/internal/stripe/reversal-webhook') {
    invalid.push('RESEND_PROVIDER_BINDING');
  }
  if (!exactArray(contract.blockers, EXPECTED_BLOCKERS)) invalid.push('BLOCKERS');

  const uniqueInvalid = [...new Set(invalid)].sort();
  return Object.freeze({
    schema: 'arc-provider-sandbox-safe-off-contract-report-v1',
    state: uniqueInvalid.length === 0 ? 'CONTRACT_VALID' : 'INVALID',
    ok: uniqueInvalid.length === 0,
    launch_ready: false,
    checks: Object.freeze({
      all_controls_off: !uniqueInvalid.includes('SAFE_OFF_ENVIRONMENT'),
      sandbox_catalog_bound: !uniqueInvalid.includes('STRIPE_SANDBOX_BINDING'),
      restricted_key_evidence_bound: !uniqueInvalid.includes('STRIPE_RESTRICTED_KEY_CAPABILITIES'),
      restricted_key_runtime_scope_match: false,
      stripe_api_version_bound: !uniqueInvalid.includes('STRIPE_API_VERSION_BINDING'),
      resend_provider_staged: !uniqueInvalid.includes('RESEND_PROVIDER_BINDING'),
      sender_staged: sender?.status === 'STAGED' &&
        sender?.value === EXPECTED_NON_SECRET_ENVIRONMENT.ARC_RESEND_FROM,
      secret_material_absent: !uniqueInvalid.includes('SECRET_MATERIAL_FORBIDDEN'),
    }),
    invalid: Object.freeze(uniqueInvalid),
    blocked: Object.freeze(exactArray(contract.blockers, EXPECTED_BLOCKERS)
      ? [...EXPECTED_BLOCKERS] : ['PROVIDER_SAFE_OFF_CONTRACT_INVALID']),
  });
}

function runtimeSafeOffFlagNames(env) {
  const suppliedNames = env && typeof env === 'object' && !Array.isArray(env)
    ? Object.keys(env) : [];
  return [...new Set([
    ...PROVIDER_SAFE_OFF_FLAG_NAMES,
    ...suppliedNames.filter((name) => name.startsWith('ARC_') && BOOLEAN_FLAG_SUFFIX.test(name)),
  ])].sort();
}

export function createProviderSandboxSafeOffReport(
  env = process.env,
  contract = PROVIDER_SANDBOX_SAFE_OFF_CONTRACT,
) {
  const contractReport = createProviderSandboxSafeOffContractReport(contract);
  const environment = env && typeof env === 'object' && !Array.isArray(env) ? env : {};
  const relevantFlags = runtimeSafeOffFlagNames(environment);
  const suppliedFlags = relevantFlags.filter((name) => Object.hasOwn(environment, name));
  const enabledFlags = suppliedFlags.filter((name) => environment[name] === 'true');
  const invalidFlags = suppliedFlags.filter((name) => environment[name] !== 'false');
  const runtimeControlsOff = invalidFlags.length === 0;
  const suppliedApiVersion = environment.ARC_STRIPE_WEBHOOK_API_VERSION;
  const runtimeApiVersionCompatible = suppliedApiVersion === undefined ||
    suppliedApiVersion === ARC_STRIPE_API_VERSION;
  const suppliedSender = environment.ARC_RESEND_FROM;
  const runtimeSenderCompatible = suppliedSender === undefined || suppliedSender === RESEND_FROM_IDENTITY;
  const invalid = [...contractReport.invalid];
  if (!runtimeControlsOff) invalid.push('RUNTIME_SAFE_OFF_ENVIRONMENT');
  if (!runtimeApiVersionCompatible) invalid.push('RUNTIME_STRIPE_API_VERSION_BINDING');
  if (!runtimeSenderCompatible) invalid.push('RUNTIME_RESEND_SENDER_IDENTITY');
  const uniqueInvalid = [...new Set(invalid)].sort();
  return Object.freeze({
    schema: 'arc-provider-sandbox-safe-off-preflight-v1',
    state: uniqueInvalid.length === 0 ? 'SAFE_OFF_STAGED' : 'INVALID',
    ok: uniqueInvalid.length === 0,
    launch_ready: false,
    checks: Object.freeze({
      ...contractReport.checks,
      actual_environment_controls_off: runtimeControlsOff,
      actual_stripe_api_version_compatible: runtimeApiVersionCompatible,
      actual_resend_sender_compatible: runtimeSenderCompatible,
    }),
    enabled_flags: Object.freeze(enabledFlags),
    invalid_flags: Object.freeze(invalidFlags),
    invalid: Object.freeze(uniqueInvalid),
    blocked: Object.freeze(contractReport.ok
      ? [...contractReport.blocked] : ['PROVIDER_SAFE_OFF_CONTRACT_INVALID']),
  });
}

export function runProviderSandboxSafeOffPreflightCli({
  argv = process.argv.slice(2),
  env = process.env,
  write = (value) => process.stdout.write(value),
} = {}) {
  if (argv.length !== 0) return 2;
  const report = createProviderSandboxSafeOffReport(env);
  write(`${JSON.stringify(report)}\n`);
  return report.ok ? 0 : 1;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = runProviderSandboxSafeOffPreflightCli();
}
