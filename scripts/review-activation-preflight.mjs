import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

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
const EXACT_BINDINGS = Object.freeze({
  ARC_EXPECTED_PRODUCT_NAME: 'ARC Fixed Five-Page Website',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
  ARC_STRIPE_CHECKOUT_CANCEL_URL: 'https://arcweb.onl/review/?checkout=cancelled',
  ARC_STRIPE_CHECKOUT_OFFER_ID: 'arc-fixed-five-page-offer-v1',
  ARC_STRIPE_CHECKOUT_SUCCESS_URL:
    'https://arcweb.onl/payment-success/?session_id={CHECKOUT_SESSION_ID}',
  ARC_STRIPE_CHECKOUT_TERMS_VERSION: '2026-08-25',
  ARC_STRIPE_WEBHOOK_API_VERSION: '2026-07-29.dahlia',
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
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
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
  return false;
}

function valueAtPath(value, path) {
  return path.split('.').reduce((current, key) => current?.[key], value);
}

export function reviewActivationRequiredEnvironmentNames(mode) {
  const profile = REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.profiles[mode];
  if (!profile) throw new TypeError('Review activation mode is invalid.');
  return [...new Set([
    ...Object.keys(profile.flags),
    ...REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.secrets.map(({ name }) => name),
    ...REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.bindings.map(({ name }) => name),
    REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.env_name,
    'ARC_ACTIVATION_MANIFEST',
  ])].sort();
}

export function reviewActivationRouteMatrixSha256() {
  return sha256(canonicalJson(REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.routes));
}

export function reviewActivationEnvironmentNamesSha256(mode) {
  return sha256(canonicalJson(reviewActivationRequiredEnvironmentNames(mode)));
}

function validateReadback(env, mode, profile, now, invalid) {
  const readbackName = REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.env_name;
  let value;
  try { value = JSON.parse(env[readbackName]); } catch {
    invalid.push(readbackName);
    return false;
  }
  const topFields = [
    'schema', 'version', 'mode', 'minimum_stage', 'provider_controls_state', 'observed_at',
    'expires_at', 'netlify', 'stripe', 'email', 'zapier',
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
      now.getTime() - observed > maximumAge || expires <= now.getTime() || expires - observed > maximumAge) {
    invalid.push(`${readbackName}:FRESHNESS`);
  }

  const netlifyFields = [
    'deployment_sha', 'env_name_set_readback_sha256', 'route_matrix_readback_sha256',
    'route_probe_receipt_sha256', 'site_id_sha256',
  ];
  const stripeFields = [
    'account_id_sha256', 'catalog_readback_sha256',
    'checkout_session_expire_capability_readback_sha256',
    'checkout_session_retrieve_capability_readback_sha256', 'integration_identifier_sha256',
    'price_id_sha256', 'product_id_sha256', 'webhook_destination_readback_sha256',
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
  if (!exactKeys(value.netlify, netlifyFields) || !exactKeys(value.stripe, stripeFields) ||
      !exactKeys(value.email, emailFields) || !exactKeys(value.zapier, zapierFields)) {
    invalid.push(`${readbackName}:FIELDS`);
    return false;
  }
  const bindingsValid =
    value.netlify.site_id_sha256 === sha256(env.ARC_EXPECTED_NETLIFY_SITE_ID) &&
    HEX_40.test(value.netlify.deployment_sha) &&
    value.netlify.env_name_set_readback_sha256 === reviewActivationEnvironmentNamesSha256(mode) &&
    value.netlify.route_matrix_readback_sha256 === reviewActivationRouteMatrixSha256() &&
    value.stripe.account_id_sha256 === env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 &&
    value.stripe.price_id_sha256 === sha256(env.ARC_EXPECTED_PRICE_ID) &&
    value.stripe.product_id_sha256 === sha256(env.ARC_EXPECTED_PRODUCT_ID) &&
    value.stripe.integration_identifier_sha256 === sha256(env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER) &&
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
    value.zapier.payment_arc2_start_path === '/internal/payment-arc2/start';
  if (!bindingsValid) invalid.push(`${readbackName}:BINDINGS`);
  for (const path of REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.required_sha256_fields) {
    if (!nonzeroSha256(valueAtPath(value, path))) invalid.push(`${readbackName}:${path}`);
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
  const secretNames = REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.secrets.map(({ name }) => name);
  for (const name of secretNames) {
    if (env[name] === undefined || env[name] === '') missing.push(name);
    else if (!validSecret(env[name])) invalid.push(name);
  }
  const presentSecrets = secretNames.filter((name) => validSecret(env[name])).map((name) => env[name]);
  if (new Set(presentSecrets).size !== presentSecrets.length) invalid.push('SECRET_DISTINCTNESS');
  const keyMode = profile.stripe_key_mode;
  if (!new RegExp(`^(?:sk|rk)_${keyMode}_[A-Za-z0-9_]{16,240}$`)
    .test(String(env.ARC_STRIPE_REVIEW_SECRET_KEY || ''))) invalid.push('ARC_STRIPE_REVIEW_SECRET_KEY');
  if (!new RegExp(`^rk_${keyMode}_[A-Za-z0-9_]{16,240}$`)
    .test(String(env.ARC_STRIPE_ACCOUNT_VERIFICATION_KEY || ''))) {
    invalid.push('ARC_STRIPE_ACCOUNT_VERIFICATION_KEY');
  }
  if (!/^whsec_[A-Za-z0-9_]{16,240}$/.test(String(env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET || ''))) {
    invalid.push('ARC_STRIPE_WEBHOOK_SIGNING_SECRET');
  }
  for (const { name, format } of REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.bindings) {
    if (env[name] === undefined || env[name] === '') missing.push(name);
    else if (!bindingValid(name, format, env[name])) invalid.push(name);
  }
  const readbackName = REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.env_name;
  if (env[readbackName] === undefined || env[readbackName] === '') missing.push(readbackName);
  else validateReadback(env, mode, profile, now, invalid);
  if (env.ARC_ACTIVATION_MANIFEST === undefined || env.ARC_ACTIVATION_MANIFEST === '') {
    missing.push('ARC_ACTIVATION_MANIFEST');
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
      provider_readback_current: configured,
      secrets_distinct: !uniqueInvalid.includes('SECRET_DISTINCTNESS'),
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
