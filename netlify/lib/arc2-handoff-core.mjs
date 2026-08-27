import {
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import {
  ACTIVATION_MANIFEST_ENV,
  ACTIVATION_MANIFEST_SECRET_ENV,
  validateActivationManifestEnvironment,
} from './activation-manifest-core.mjs';
import { imageTypeForPath, validateImageAsset } from './image-asset-validation.mjs';

export const HANDOFF_STORE = 'arc2-handoffs';
export const LEGACY_HANDOFF_SCHEMA = 'arc2-netlify-handoff-v1';
export const HANDOFF_SCHEMA = 'arc2-netlify-handoff-v2';
export const ARTIFACT_EVIDENCE_VERSION = 'arc2-handoff-artifact-evidence-v4';
export const ARTIFACT_EVIDENCE_SCOPE = 'netlify-claimable-deploy-artifacts';
export const ARTIFACT_SIGNATURE_PREFIX = 'arc2-handoff-artifact-evidence-signature-v4\n';
const LEGACY_ARTIFACT_EVIDENCE_VERSION = 'arc2-handoff-artifact-evidence-v3';
const LEGACY_ARTIFACT_SIGNATURE_PREFIX = 'arc2-handoff-artifact-evidence-signature-v3\n';
export const PAYMENT_EVIDENCE_VERSION = 'arc2-payment-evidence-v4';
export const PAYMENT_EVIDENCE_SCOPE = 'authoritative-stripe-checkout-session';
export const PAYMENT_SIGNATURE_PREFIX = 'arc2-payment-evidence-signature-v4\n';
export const REVIEW_PAYMENT_EVIDENCE_VERSION = 'arc2-review-session-payment-evidence-v1';
export const REVIEW_PAYMENT_EVIDENCE_SCOPE = 'authoritative-approved-review-paid-checkout-session';
export const REVIEW_PAYMENT_SIGNATURE_PREFIX = 'arc2-review-session-payment-evidence-signature-v1\n';
const LEGACY_PAYMENT_EVIDENCE_VERSION = 'arc2-payment-evidence-v3';
const LEGACY_PAYMENT_SIGNATURE_PREFIX = 'arc2-payment-evidence-signature-v3\n';
export const LEAD_RECIPIENT_PREFIX = 'arc-lead-route-recipient-v1\n';
export const CLAIM_STATE_EVIDENCE_VERSION = 'arc2-claim-state-evidence-v3';
export const CLAIM_STATE_EVIDENCE_SCOPE = 'netlify-deploy-and-claim-final-deploy';
export const CLAIM_STATE_SIGNATURE_PREFIX = 'arc2-claim-state-evidence-signature-v3\n';
const FINAL_DELIVERY_AUTHORIZATION_PREFIX = 'arc2-final-delivery-authorization-v1\n';
export const OUTBOX_CLAIM_VERSION = 'arc2-final-delivery-outbox-v1';
export const FINAL_DELIVERY_RECEIPT_VERSION = 'arc2-final-email-delivery-receipt-v1';
export const FINAL_DELIVERY_RECEIPT_SCOPE = 'authoritative-final-email-provider-delivery';
export const FINAL_DELIVERY_RECEIPT_SIGNATURE_PREFIX = 'arc2-final-email-delivery-receipt-signature-v1\n';
export const FINAL_DELIVERY_PROVIDER_EVENT_ID_PREFIX = 'arc2-final-delivery-provider-event-id-v1\n';
export const FINAL_DELIVERY_PROVIDER_MESSAGE_ID_PREFIX = 'arc2-final-delivery-provider-message-id-v1\n';
export const CLAIM_TOKEN_TTL_SECONDS = 30 * 60;
export const CLAIM_JWT_TTL_SECONDS = 60;
export const MAX_DEPLOY_POLL_ATTEMPTS = 20;
export const NETLIFY_REQUEST_TIMEOUT_MS = 10_000;
export const REQUIRED_STRIPE_WEBHOOK_API_VERSION = '2026-07-29.dahlia';

export const HANDOFF_STATES = Object.freeze([
  'PAYMENT_VERIFIED',
  'SITE_INTENT',
  'SITE_CREATED',
  'PRECLAIM_DEPLOY_READY',
  'LEAD_ROUTE_VERIFIED',
  'INVITATION_READY',
  'CLAIM_WRAPPER_CONSUMED',
  'CLAIM_CALLBACK_RECEIVED',
  'CLAIMED_VERIFIED',
  'FINAL_DEPLOY_READY',
  'DELIVERED',
]);

const TRANSITIONS = Object.freeze({
  PAYMENT_VERIFIED: new Set(['SITE_INTENT']),
  SITE_INTENT: new Set(['SITE_CREATED']),
  SITE_CREATED: new Set(['PRECLAIM_DEPLOY_READY']),
  PRECLAIM_DEPLOY_READY: new Set(['LEAD_ROUTE_VERIFIED', 'INVITATION_READY']),
  LEAD_ROUTE_VERIFIED: new Set(['INVITATION_READY']),
  INVITATION_READY: new Set(['CLAIM_WRAPPER_CONSUMED']),
  // An expired, abandoned wrapper may return to READY only through the
  // authenticated renewal service after authoritative source-account
  // readback proves the provider claim never completed.
  CLAIM_WRAPPER_CONSUMED: new Set(['INVITATION_READY', 'CLAIM_CALLBACK_RECEIVED']),
  CLAIM_CALLBACK_RECEIVED: new Set(['CLAIMED_VERIFIED']),
  CLAIMED_VERIFIED: new Set(['FINAL_DEPLOY_READY']),
  FINAL_DEPLOY_READY: new Set(['DELIVERED']),
  DELIVERED: new Set(),
});

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_64_PATTERN = /^[0-9a-f]{64}$/;
const PREVIEW_FOLDER_PATTERN = /^[a-z0-9][a-z0-9-]*-[a-f0-9]{8}$/;
const NETLIFY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/;
const SAFE_SITE_NAME_PATTERN = /^arc-lead-route-[a-f0-9]{24}$/;
const STORED_SITE_NAME_PATTERN = /^(?:arc-lead-route-|arc-)[a-f0-9]{24}$/;
const SAFE_FORM_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const ASSET_PATH_PATTERN = /^assets\/([a-f0-9]{64})\.(png|jpg|webp)$/;
const HTML_PATHS = Object.freeze([
  'about/index.html',
  'contact/index.html',
  'process/index.html',
  'services/index.html',
  'index.html',
]);
const HTML_PATH_SET = new Set(HTML_PATHS);
const SAFE_PATH_PATTERN = /^(?:index\.html|(?:about|contact|process|services)\/index\.html|_headers|assets\/[a-f0-9]{64}\.(?:png|jpg|webp))$/;
const MAX_ASSET_COUNT = 3;
const MAX_ASSET_BYTES = 3_000_000;
const MAX_HTML_FILE_BYTES = 150_000;
const MAX_HTML_BYTES = 500_000;
const MAX_ARTIFACT_BYTES = 3_510_000;
const MAX_DEPLOY_ARTIFACTS_JSON_BYTES = 4_700_000;

function artifactPathVectorValid(paths) {
  if (!Array.isArray(paths) || paths.length < 1 + HTML_PATHS.length || paths.length > 1 + MAX_ASSET_COUNT + HTML_PATHS.length ||
      paths[0] !== '_headers' || new Set(paths).size !== paths.length) return false;
  const htmlStart = paths.length - HTML_PATHS.length;
  const assetPaths = paths.slice(1, htmlStart);
  return JSON.stringify(paths.slice(htmlStart)) === JSON.stringify(HTML_PATHS) &&
    assetPaths.every(path => ASSET_PATH_PATTERN.test(path)) &&
    JSON.stringify(assetPaths) === JSON.stringify([...assetPaths].sort());
}

function legacyArtifactPathVectorValid(paths) {
  if (!Array.isArray(paths) || paths.length < 2 || paths.length > 2 + MAX_ASSET_COUNT ||
      paths[0] !== '_headers' || paths.at(-1) !== 'index.html' || new Set(paths).size !== paths.length) return false;
  const assetPaths = paths.slice(1, -1);
  return assetPaths.every(path => ASSET_PATH_PATTERN.test(path)) &&
    JSON.stringify(assetPaths) === JSON.stringify([...assetPaths].sort());
}

function htmlArtifacts(artifacts) {
  const pages = artifacts.filter(entry => HTML_PATH_SET.has(entry?.path));
  if (JSON.stringify(pages.map(entry => entry.path)) !== JSON.stringify(HTML_PATHS)) {
    throw new TypeError('Exactly five ordered website pages are required.');
  }
  return pages;
}

function productionContentSha256(artifacts) {
  const digest = createHash('sha256');
  for (const page of htmlArtifacts(artifacts)) digest.update(page.path).update('\0').update(page.bytes).update('\0');
  return digest.digest('hex');
}
export const ARC2_CONTENT_SECURITY_POLICY = "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; script-src-attr 'none'; connect-src 'none'; font-src 'self' data:; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
export const ARC2_PRODUCTION_HEADERS_FILE = `/*\n  Content-Security-Policy: ${ARC2_CONTENT_SECURITY_POLICY}\n  X-Content-Type-Options: nosniff\n  X-Frame-Options: DENY\n  Referrer-Policy: strict-origin-when-cross-origin\n  Permissions-Policy: camera=(), microphone=(), geolocation=()\n`;
export const ARC2_PRECLAIM_HEADERS_FILE = `${ARC2_PRODUCTION_HEADERS_FILE}  X-Robots-Tag: noindex, nofollow, noarchive\n`;
const LEGACY_PAYMENT_FIELDS = Object.freeze([
  'adult_purchaser_acknowledgement',
  'approval_content_sha256',
  'amount_total_minor_units',
  'artifact_manifest_sha256',
  'automatic_tax_enabled',
  'automatic_tax_status',
  'asset_publication_receipt_sha256',
  'bundle_fingerprint',
  'checkout_session_id',
  'checkout_config_snapshot',
  'checkout_config_snapshot_sha256',
  'client_reference_id',
  'client_reference_id_observation',
  'client_reference_id_sha256',
  'client_reference_mismatch_review_hmac_sha256',
  'client_reference_mismatch_review_record_key_hmac_sha256',
  'client_reference_mismatch_review_required',
  'client_reference_mismatch_review_sha256',
  'client_reference_mismatch_review_state',
  'currency',
  'customer_address_country',
  'customer_address_sha256',
  'customer_address_state',
  'customer_address_status',
  'claim_recipient_email_sha256',
  'handoff_artifact_evidence_sha256',
  'livemode',
  'mode',
  'payment_link_id',
  'payment_intent_id',
  'payment_status',
  'payer_email_sha256',
  'preview_folder',
  'preview_source_commit_sha',
  'preview_source_repository',
  'preview_source_tag_sha256',
  'price_id',
  'price_tax_behavior',
  'product_tax_code',
  'product_id',
  'production_content_sha256',
  'quantity',
  'scope',
  'status',
  'charge_id',
  'stripe_account_id_sha256',
  'subtotal_amount_minor_units',
  'tax_amount_minor_units',
  'tax_contract_version',
  'tax_registrations_sha256',
  'tax_registration_status',
  'terms_of_service_consent',
  'terms_version',
  'version',
]);
const PAYMENT_FIELDS = Object.freeze([
  ...LEGACY_PAYMENT_FIELDS,
  'taxability_reasons',
  'line_item_taxes_sha256',
]);
const REVIEW_PAYMENT_FIELDS = Object.freeze([
  'adult_purchaser_acknowledgement', 'amount_total_minor_units', 'approval_receipt_hmac_sha256',
  'approval_receipt_sha256', 'artifact_manifest_sha256', 'automatic_tax_enabled',
  'automatic_tax_status', 'bridge_immutable_binding_sha256', 'bridge_outbox_key_sha256',
  'brief_sha256', 'bundle_fingerprint', 'checkout_session_id',
  'checkout_session_id_hmac_sha256', 'claim_recipient_email_sha256',
  'client_reference_id_sha256', 'currency', 'customer_address_country',
  'customer_address_state', 'handoff_artifact_evidence_sha256', 'invite_hmac_sha256',
  'livemode', 'mode', 'payer_email_sha256', 'payment_intent_id',
  'payment_intent_id_hmac_sha256', 'payment_link_id', 'payment_status',
  'preview_content_sha256', 'preview_folder', 'preview_manifest_sha256',
  'preview_source_commit_sha', 'preview_source_repository', 'production_content_sha256',
  'review_session_binding_sha256', 'scope', 'status', 'stripe_account_id_sha256',
  'subtotal_amount_minor_units', 'tax_amount_minor_units', 'terms_of_service_consent', 'version',
]);

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) throw new TypeError(`${label} fields are invalid.`);
}

function stringValue(value, label, minimum = 1, maximum = 512) {
  if (typeof value !== 'string' || value.length < minimum || value.length > maximum || value !== value.trim()) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function identifier(value, label) {
  const output = stringValue(value, label, 6, 128);
  if (!NETLIFY_ID_PATTERN.test(output)) throw new TypeError(`${label} is invalid.`);
  return output;
}

function hex64(value, label) {
  const output = stringValue(value, label, 64, 64).toLowerCase();
  if (!HEX_64_PATTERN.test(output)) throw new TypeError(`${label} must be lowercase SHA-256.`);
  return output;
}

function isoTimestamp(value, label) {
  const output = stringValue(value, label, 20, 32);
  const parsed = Date.parse(output);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== output) throw new TypeError(`${label} must be an ISO timestamp.`);
  return output;
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const output = JSON.stringify(value);
  if (output === undefined) throw new TypeError('Canonical JSON does not support undefined.');
  return output;
}

export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function hmacHex(secret, value) {
  return createHmac('sha256', secret).update(value).digest('hex');
}

export function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

export function base64Url(value) {
  return Buffer.from(value).toString('base64url');
}

export function signJwtHS256(payload, secret) {
  plainObject(payload, 'JWT payload');
  stringValue(secret, 'OAuth client secret', 32, 512);
  const header = base64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64Url(JSON.stringify(payload));
  const signature = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

const HANDOFF_ENVIRONMENT_ALIASES = Object.freeze([
  Object.freeze({
    canonical: 'NETLIFY_ADMIN_PAT',
    alias: 'NETLIFY_ACCESS_TOKEN',
    conflict: 'NETLIFY_ADMIN_PAT_NETLIFY_ACCESS_TOKEN_CONFLICT',
  }),
]);

export function resolveHandoffEnvironment(env = process.env) {
  const source = env && typeof env === 'object' ? env : {};
  const environment = { ...source };
  const conflicts = [];
  for (const { canonical, alias, conflict } of HANDOFF_ENVIRONMENT_ALIASES) {
    const canonicalPresent = String(source[canonical] ?? '').length > 0;
    const aliasPresent = String(source[alias] ?? '').length > 0;
    if (canonicalPresent && aliasPresent && source[canonical] !== source[alias]) conflicts.push(conflict);
    if (!canonicalPresent && aliasPresent) environment[canonical] = source[alias];
  }
  return { environment, conflicts };
}

function requireResolvedHandoffEnvironment(env) {
  const resolved = resolveHandoffEnvironment(env);
  if (resolved.conflicts.length) throw new TypeError('Handoff environment aliases conflict.');
  return resolved.environment;
}

export function configuredEnvironment(env = process.env, now = new Date()) {
  const resolved = resolveHandoffEnvironment(env);
  env = resolved.environment;
  const required = [
    'ARC_CHECKOUT_BINDING_SECRET',
    'ARC_CHECKOUT_BINDING_KEY_ID',
    'ARC_RETIRED_CHECKOUT_BINDING_KEYS_JSON',
    'ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET',
    'ARC_LEAD_ROUTE_EVIDENCE_SECRET',
    'ARC_HANDOFF_STATE_SECRET',
    'ARC_HANDOFF_TRIGGER_SECRET',
    'ARC_CLAIM_TOKEN_SECRET',
    'ARC_CLAIM_STATE_EVIDENCE_SECRET',
    'ARC_EMAIL_CLAIM_BINDING_SECRET',
    'ARC_FINAL_DELIVERY_RECEIPT_SECRET',
    'ARC_FINAL_DELIVERY_ACK_SECRET',
    'ARC_STRIPE_WEBHOOK_SIGNING_SECRET',
    'ARC_STRIPE_ACCOUNT_VERIFICATION_KEY',
    'ARC_STRIPE_REVERSAL_HMAC_SECRET',
    'ARC_STRIPE_REVERSAL_BINDING_SECRET',
    'ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET',
    'ARC_STRIPE_REVERSAL_RECHECK_SECRET',
    'ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET',
    'ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256',
    'ARC_STRIPE_LIVE_MODE_ENABLED',
    'ARC_ALLOW_TEST_MODE_EVENTS',
    'ARC_RUNTIME_ENVIRONMENT',
    'ARC_EXPECTED_NETLIFY_SITE_ID',
    'ARC_HANDOFF_ENABLED',
    'ARC_ADULT_OPERATOR_VERIFIED',
    'ARC_BUSINESS_LICENSE_VERIFIED',
    'ARC_TAX_REGISTRATION_VERIFIED',
    'ARC_TRANSACTIONAL_EMAIL_VERIFIED',
    'ARC_RETENTION_CONTROL_VERIFIED',
    'ARC_POSTCLAIM_READBACK_VERIFIED',
    'ARC_DEVICE_QA_VERIFIED',
    'ARC_LEAD_ROUTE_VERIFIED',
    'ARC_STRIPE_REVERSAL_CONTROL_REQUIRED',
    'ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED',
    'ARC_STRIPE_REVERSAL_BINDING_ENABLED',
    'ARC_STRIPE_REVERSAL_RECHECK_ENABLED',
    'ARC_STRIPE_CHECKOUT_LEDGER_ENABLED',
    'ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED',
    'ARC_STRIPE_WEBHOOK_API_VERSION',
    'NETLIFY_ADMIN_PAT',
    'NETLIFY_TEAM_SLUG',
    'NETLIFY_TEAM_ACCOUNT_ID',
    'NETLIFY_OAUTH_CLIENT_ID',
    'NETLIFY_OAUTH_CLIENT_SECRET',
    ACTIVATION_MANIFEST_ENV,
    ACTIVATION_MANIFEST_SECRET_ENV,
  ];
  const missing = required.filter((name) => !String(env[name] || '').trim());
  const secretNames = required.filter((name) => /SECRET|TOKEN|PAT/.test(name) || name === 'ARC_STRIPE_ACCOUNT_VERIFICATION_KEY');
  const shortSecrets = secretNames.filter((name) => String(env[name] || '').length < 32 || String(env[name] || '').length > 512);
  const duplicateSecrets = new Set(secretNames.map((name) => String(env[name] || '')).filter(Boolean)).size !== secretNames.filter((name) => env[name]).length;
  const attestations = [
    'ARC_ADULT_OPERATOR_VERIFIED',
    'ARC_BUSINESS_LICENSE_VERIFIED',
    'ARC_TAX_REGISTRATION_VERIFIED',
    'ARC_TRANSACTIONAL_EMAIL_VERIFIED',
    'ARC_RETENTION_CONTROL_VERIFIED',
    'ARC_POSTCLAIM_READBACK_VERIFIED',
    'ARC_DEVICE_QA_VERIFIED',
    'ARC_LEAD_ROUTE_VERIFIED',
    'ARC_STRIPE_REVERSAL_CONTROL_REQUIRED',
    'ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED',
    'ARC_STRIPE_REVERSAL_BINDING_ENABLED',
    'ARC_STRIPE_REVERSAL_RECHECK_ENABLED',
    'ARC_STRIPE_CHECKOUT_LEDGER_ENABLED',
  ];
  const invalidAttestations = attestations.filter((name) => env[name] !== 'true');
  const liveModeSetting = String(env.ARC_STRIPE_LIVE_MODE_ENABLED || '');
  const allowTestModeSetting = String(env.ARC_ALLOW_TEST_MODE_EVENTS || '');
  const runtimeEnvironment = String(env.ARC_RUNTIME_ENVIRONMENT || '');
  const productionMode = liveModeSetting === 'true' && allowTestModeSetting === 'false' && env.ARC_HANDOFF_ENABLED === 'true' && runtimeEnvironment === 'production';
  const sandboxMode = liveModeSetting === 'false' && allowTestModeSetting === 'true' && env.ARC_HANDOFF_ENABLED === 'false' && runtimeEnvironment === 'sandbox';
  const liveModeValid = productionMode || sandboxMode;
  const activationManifest = validateActivationManifestEnvironment(env, {
    minimumStage: productionMode ? 'LIVE_CHECKOUT' : 'CLAIM_SANDBOX',
    now,
  });
  const stripeAccountVerificationKeyValid = new RegExp(`^rk_${productionMode ? 'live' : 'test'}_[A-Za-z0-9_]{16,240}$`)
    .test(String(env.ARC_STRIPE_ACCOUNT_VERIFICATION_KEY || ''));
  const checkoutLedgerRequiredSetting = String(env.ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED || '');
  const checkoutLedgerRequiredValid = productionMode
    ? checkoutLedgerRequiredSetting === 'true'
    : sandboxMode && (checkoutLedgerRequiredSetting === 'true' || checkoutLedgerRequiredSetting === 'false');
  const checkoutKeyId = String(env.ARC_CHECKOUT_BINDING_KEY_ID || '').trim().toLowerCase();
  const retiredRegistryRaw = String(env.ARC_RETIRED_CHECKOUT_BINDING_KEYS_JSON || '');
  let retiredCheckoutKeys;
  try { retiredCheckoutKeys = JSON.parse(retiredRegistryRaw); } catch {}
  const retiredCheckoutKeyValues = retiredCheckoutKeys && typeof retiredCheckoutKeys === 'object' && !Array.isArray(retiredCheckoutKeys)
    ? Object.values(retiredCheckoutKeys) : [];
  const checkoutKeyRegistryValid = /^[a-f0-9]{2}$/.test(checkoutKeyId) && retiredCheckoutKeys &&
    typeof retiredCheckoutKeys === 'object' && !Array.isArray(retiredCheckoutKeys) && canonicalJson(retiredCheckoutKeys) === retiredRegistryRaw &&
    Object.entries(retiredCheckoutKeys).every(([id, value]) => /^[a-f0-9]{2}$/.test(id) && id !== checkoutKeyId &&
      typeof value === 'string' && value.length >= 32 && value.length <= 256) &&
    new Set(retiredCheckoutKeyValues).size === retiredCheckoutKeyValues.length &&
    !retiredCheckoutKeyValues.includes(String(env.ARC_CHECKOUT_BINDING_SECRET || '')) &&
    String(env.ARC_CHECKOUT_BINDING_SECRET || '').length <= 256;
  const stripeWebhookApiVersionValid = env.ARC_STRIPE_WEBHOOK_API_VERSION === REQUIRED_STRIPE_WEBHOOK_API_VERSION;
  const identifiersValid = HEX_64_PATTERN.test(String(env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 || '')) &&
    NETLIFY_ID_PATTERN.test(String(env.NETLIFY_TEAM_ACCOUNT_ID || '')) &&
    NETLIFY_ID_PATTERN.test(String(env.NETLIFY_OAUTH_CLIENT_ID || '')) &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(env.ARC_EXPECTED_NETLIFY_SITE_ID || '')) &&
    /^[A-Za-z0-9][A-Za-z0-9-]{1,62}$/.test(String(env.NETLIFY_TEAM_SLUG || ''));
  const publicOrigin = String(env.ARC_PUBLIC_ORIGIN || '').trim();
  let originValid = false;
  try {
    const url = new URL(publicOrigin);
    originValid = url.protocol === 'https:' && url.pathname === '/' && !url.username && !url.password && !url.search && !url.hash;
  } catch {
    originValid = false;
  }
  const runtimeSiteValid = env.SITE_ID === env.ARC_EXPECTED_NETLIFY_SITE_ID &&
    (productionMode ? env.SITE_NAME === 'arcsites' : sandboxMode ? env.SITE_NAME === 'arc2-sandbox' : false);
  let runtimeOriginsValid = false;
  try {
    const expectedOrigin = new URL(publicOrigin).origin;
    runtimeOriginsValid = new URL(String(env.URL || '')).origin === expectedOrigin;
  } catch {
    runtimeOriginsValid = false;
  }
  return {
    enabled: resolved.conflicts.length === 0 && missing.length === 0 && shortSecrets.length === 0 && !duplicateSecrets && invalidAttestations.length === 0 &&
      activationManifest.valid &&
      liveModeValid && stripeAccountVerificationKeyValid && checkoutLedgerRequiredValid && checkoutKeyRegistryValid && stripeWebhookApiVersionValid && identifiersValid && originValid && runtimeSiteValid && runtimeOriginsValid,
    missing,
    invalid: [
      ...resolved.conflicts,
      ...shortSecrets,
      ...(duplicateSecrets ? ['ARC_SECRETS_MUST_BE_DISTINCT'] : []),
      ...invalidAttestations,
      ...(activationManifest.valid ? [] : ['ARC_ACTIVATION_MANIFEST_AUTHORITY']),
      ...(liveModeValid ? [] : ['ARC_STRIPE_MODE_OR_TEST_SANDBOX_CONTEXT']),
      ...(stripeAccountVerificationKeyValid ? [] : ['ARC_STRIPE_ACCOUNT_VERIFICATION_KEY']),
      ...(checkoutLedgerRequiredValid ? [] : ['ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED']),
      ...(checkoutKeyRegistryValid ? [] : ['ARC_CHECKOUT_BINDING_KEY_REGISTRY']),
      ...(stripeWebhookApiVersionValid ? [] : ['ARC_STRIPE_WEBHOOK_API_VERSION']),
      ...(identifiersValid ? [] : ['ARC_EXPECTED_IDS_OR_NETLIFY_IDS']),
      ...(originValid ? [] : ['ARC_PUBLIC_ORIGIN']),
      ...(runtimeSiteValid ? [] : ['ARC_PRODUCTION_SITE_BINDING']),
      ...(runtimeOriginsValid ? [] : ['ARC_PRODUCTION_ORIGIN_BINDING']),
    ],
  };
}

export function authenticateBearer(request, expectedSecret) {
  if (!expectedSecret || expectedSecret.length < 32) return false;
  const header = request.headers.get('authorization') || '';
  if (!header.startsWith('Bearer ')) return false;
  const token = header.slice(7);
  return token.length >= 32 && safeEqual(token, expectedSecret);
}

export function parseJsonBodyText(body, maximumBytes = 1_048_576) {
  if (typeof body !== 'string' || !body || Buffer.byteLength(body, 'utf8') > maximumBytes) {
    throw new TypeError('Request body is empty or too large.');
  }
  return plainObject(JSON.parse(body), 'Request body');
}

export function normalizeArtifactEvidence(raw, secret, now = new Date(), options = {}) {
  const canonical = stringValue(raw, 'Artifact evidence', 2, 100_000);
  const value = plainObject(JSON.parse(canonical), 'Artifact evidence');
  if (canonicalJson(value) !== canonical) throw new TypeError('Artifact evidence is not canonical JSON.');
  exactKeys(value, [
    'approval_content_sha256',
    'artifact_manifest_sha256',
    'artifacts',
    'asset_publication_receipt_sha256',
    'bundle_fingerprint',
    'checkout_binding_key_id',
    'checkout_config_snapshot_sha256',
    'checkout_reference_sha256',
    'issued_at',
    'lead_route_form_name',
    'lead_route_mode',
    'lead_route_recipient_hmac_sha256',
    'preview_folder',
    'preview_source_commit_sha',
    'preview_source_repository',
    'preview_source_tag_sha256',
    'production_content_sha256',
    'scope',
    'version',
  ], 'Artifact evidence');
  const legacyV3 = value.version === LEGACY_ARTIFACT_EVIDENCE_VERSION && options.allowLegacyV3 === true;
  if ((!legacyV3 && value.version !== ARTIFACT_EVIDENCE_VERSION) || value.scope !== ARTIFACT_EVIDENCE_SCOPE) {
    throw new TypeError('Artifact evidence version or scope is invalid.');
  }
  const leadRouteMode = stringValue(value.lead_route_mode, 'Artifact lead route mode', 8, 32);
  if (!['netlify_form', 'not_required'].includes(leadRouteMode) ||
      (leadRouteMode === 'netlify_form'
        ? (validateFormName(value.lead_route_form_name) !== value.lead_route_form_name ||
          !HEX_64_PATTERN.test(value.lead_route_recipient_hmac_sha256))
        : (value.lead_route_form_name !== '' || value.lead_route_recipient_hmac_sha256 !== ''))) {
    throw new TypeError('Artifact lead route binding is invalid.');
  }
  if (typeof value.preview_folder !== 'string' || !PREVIEW_FOLDER_PATTERN.test(value.preview_folder)) {
    throw new TypeError('Artifact preview folder is invalid.');
  }
  for (const [field, label] of [
    ['approval_content_sha256', 'Artifact approval digest'],
    ['asset_publication_receipt_sha256', 'Artifact publication receipt digest'],
    ['checkout_config_snapshot_sha256', 'Artifact checkout configuration digest'],
    ['checkout_reference_sha256', 'Artifact checkout reference digest'],
    ['preview_source_tag_sha256', 'Artifact source tag digest'],
  ]) hex64(value[field], label);
  if (!/^[a-f0-9]{2}$/.test(value.checkout_binding_key_id) || !/^[a-f0-9]{40}$/.test(value.preview_source_commit_sha) || value.preview_source_repository !== 'arcwebhq-cpu/arc-previews') {
    throw new TypeError('Artifact immutable preview source binding is invalid.');
  }
  const issuedAt = isoTimestamp(value.issued_at, 'Artifact issued_at');
  const issuedMs = Date.parse(issuedAt);
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || issuedMs > nowMs + 5 * 60_000) {
    throw new TypeError('Artifact evidence is stale or from the future.');
  }
  if (!Array.isArray(value.artifacts) || (legacyV3
    ? (value.artifacts.length < 2 || value.artifacts.length > 2 + MAX_ASSET_COUNT)
    : (value.artifacts.length < 1 + HTML_PATHS.length || value.artifacts.length > 1 + MAX_ASSET_COUNT + HTML_PATHS.length))) {
    throw new TypeError('Deploy artifact count is invalid.');
  }
  let totalArtifactBytes = 0;
  let totalAssetBytes = 0;
  let totalHtmlBytes = 0;
  const artifacts = value.artifacts.map((artifact) => {
    plainObject(artifact, 'Artifact');
    exactKeys(artifact, ['path', 'sha256', 'size'], 'Artifact');
    if (!SAFE_PATH_PATTERN.test(artifact.path)) throw new TypeError('Artifact path is not allowlisted.');
    const maximum = artifact.path === '_headers' ? 10_000
      : artifact.path === 'index.html' && legacyV3 ? 500_000
        : HTML_PATH_SET.has(artifact.path) ? MAX_HTML_FILE_BYTES : 1_250_000;
    if (!Number.isSafeInteger(artifact.size) || artifact.size < 1 || artifact.size > maximum) throw new TypeError('Artifact size is invalid.');
    const assetMatch = artifact.path.match(ASSET_PATH_PATTERN);
    if (assetMatch && artifact.sha256 !== assetMatch[1]) throw new TypeError('Asset path is not content-addressed by its signed digest.');
    totalArtifactBytes += artifact.size;
    if (assetMatch) totalAssetBytes += artifact.size;
    if (HTML_PATH_SET.has(artifact.path)) totalHtmlBytes += artifact.size;
    return { path: artifact.path, sha256: hex64(artifact.sha256, 'Artifact sha256'), size: artifact.size };
  });
  if (totalArtifactBytes > MAX_ARTIFACT_BYTES || totalAssetBytes > MAX_ASSET_BYTES || (!legacyV3 && totalHtmlBytes > MAX_HTML_BYTES)) {
    throw new TypeError('Deploy artifact aggregate size is invalid.');
  }
  const paths = artifacts.map(artifact => artifact.path);
  if (!(legacyV3 ? legacyArtifactPathVectorValid(paths) : artifactPathVectorValid(paths))) {
    throw new TypeError('Artifact paths must be sorted and exact.');
  }
  const manifest = canonicalJson(artifacts);
  if (sha256Hex(manifest) !== hex64(value.artifact_manifest_sha256, 'Artifact manifest sha256')) {
    throw new TypeError('Artifact manifest digest mismatch.');
  }
  hex64(value.production_content_sha256, 'Production content sha256');
  hex64(value.bundle_fingerprint, 'Bundle fingerprint');
  if (!secret || secret.length < 32) throw new TypeError('Artifact evidence secret is unavailable.');
  return { canonical, value, digest: sha256Hex(canonical), artifacts, legacyV3 };
}

export function verifyArtifactSignature(evidence, signature, secret, version = ARTIFACT_EVIDENCE_VERSION) {
  const supplied = hex64(signature, 'Artifact evidence signature');
  const prefix = version === ARTIFACT_EVIDENCE_VERSION ? ARTIFACT_SIGNATURE_PREFIX
    : version === LEGACY_ARTIFACT_EVIDENCE_VERSION ? LEGACY_ARTIFACT_SIGNATURE_PREFIX : '';
  return Boolean(prefix) && safeEqual(supplied, hmacHex(secret, `${prefix}${evidence}`));
}

export function normalizeDeployArtifacts(raw, expectedArtifacts) {
  const canonical = stringValue(raw, 'Deploy artifacts', 2, MAX_DEPLOY_ARTIFACTS_JSON_BYTES);
  const value = JSON.parse(canonical);
  if (!Array.isArray(value) || canonicalJson(value) !== canonical || value.length !== expectedArtifacts.length) {
    throw new TypeError('Deploy artifacts are invalid or not canonical.');
  }
  const artifacts = value.map((artifact, index) => {
    plainObject(artifact, 'Deploy artifact');
    exactKeys(artifact, ['content_base64', 'path'], 'Deploy artifact');
    const expected = expectedArtifacts[index];
    if (artifact.path !== expected.path || typeof artifact.content_base64 !== 'string' || artifact.content_base64.length > 1_700_000) {
      throw new TypeError('Deploy artifact path or content is invalid.');
    }
    const bytes = Buffer.from(artifact.content_base64, 'base64');
    if (bytes.toString('base64') !== artifact.content_base64 || bytes.length !== expected.size || sha256Hex(bytes) !== expected.sha256) {
      throw new TypeError('Deploy artifact bytes do not match signed evidence.');
    }
    if (ASSET_PATH_PATTERN.test(artifact.path)) validateImageAsset(bytes, imageTypeForPath(artifact.path));
    return { path: artifact.path, bytes };
  });
  return artifacts;
}

function validateProductionAssetReferences(pageArtifacts, artifacts) {
  const decodedPages = htmlArtifacts(pageArtifacts).map((entry) => {
    let html;
    try { html = new TextDecoder('utf-8', { fatal: true }).decode(entry.bytes); } catch {
      throw new TypeError('Production HTML must be valid UTF-8.');
    }
    if (/https:\/\/arcwebhq-cpu\.github\.io\/arc-previews(?:\/|["'?#]|$)/i.test(html)) {
      throw new TypeError('Production HTML still references the ARC preview host.');
    }
    if (/<base\b/i.test(html)) throw new TypeError('Production HTML base elements are forbidden.');
    return html;
  });
  const referenced = new Set();
  for (const html of decodedPages) {
    for (const match of html.matchAll(/assets\/[^"'()\s<>]*/gi)) {
      const slashIndex = match.index - 1;
      const preceding = slashIndex > 0 ? html[slashIndex - 1] : '';
      const candidate = slashIndex >= 0 && html[slashIndex] === '/' ? `/${match[0]}` : match[0];
      if (slashIndex < 0 || html[slashIndex] !== '/' || (slashIndex > 0 && !/["'(=,\s]/.test(preceding)) ||
          !/^\/assets\/[a-f0-9]{64}\.(?:png|jpg|webp)$/.test(candidate)) {
        throw new TypeError('Production HTML contains a non-root-relative or unbound local asset reference.');
      }
      referenced.add(candidate.slice(1));
    }
  }
  const included = new Set(artifacts.filter(entry => ASSET_PATH_PATTERN.test(entry.path)).map(entry => entry.path));
  if (referenced.size !== included.size || [...referenced].some(path => !included.has(path)) || [...included].some(path => !referenced.has(path))) {
    throw new TypeError('Production HTML asset references do not match the exact signed bundle.');
  }
}

function validateLegacyProductionAssetReferences(productionBytes, artifacts) {
  let html;
  try { html = new TextDecoder('utf-8', { fatal: true }).decode(productionBytes); } catch {
    throw new TypeError('Production HTML must be valid UTF-8.');
  }
  if (/https:\/\/arcwebhq-cpu\.github\.io\/arc-previews(?:\/|["'?#]|$)/i.test(html)) {
    throw new TypeError('Production HTML still references the ARC preview host.');
  }
  if (/<base\b/i.test(html)) throw new TypeError('Production HTML base elements are forbidden.');
  const referenced = new Set(html.match(/assets\/[a-f0-9]{64}\.(?:png|jpg|webp)/gi)?.map(value => value.toLowerCase()) || []);
  const included = new Set(artifacts.filter(entry => ASSET_PATH_PATTERN.test(entry.path)).map(entry => entry.path));
  if (referenced.size !== included.size || [...referenced].some(path => !included.has(path)) || [...included].some(path => !referenced.has(path))) {
    throw new TypeError('Production HTML asset references do not match the exact signed bundle.');
  }
  const suspicious = html.match(/(?:^|["'(=\s\/])assets\/[^"')\s?#]+/gi) || [];
  if (suspicious.some(value => !/assets\/[a-f0-9]{64}\.(?:png|jpg|webp)$/i.test(value.trim().replace(/^["'(=\s\/]+/, 'assets/')))) {
    throw new TypeError('Production HTML contains an unbound local asset reference.');
  }
}

function expectedLegacyNetlifyLiveHtml(sourceBytes, leadRouteMode) {
  let html;
  try { html = new TextDecoder('utf-8', { fatal: true }).decode(sourceBytes); } catch {
    throw new TypeError('Production HTML must be valid UTF-8.');
  }
  if (/https:\/\/arcwebhq-cpu\.github\.io\/arc-previews(?:\/|["'?#]|$)/i.test(html) || /<base\b/i.test(html)) {
    throw new TypeError('Legacy production HTML is invalid.');
  }
  if (leadRouteMode === 'not_required') return Buffer.from(html, 'utf8');
  if (leadRouteMode !== 'netlify_form') throw new TypeError('Production lead route mode is invalid.');
  const dataNetlify = html.match(/\sdata-netlify="true"/gi) || [];
  const honeypot = html.match(/\snetlify-honeypot="bot-field"/gi) || [];
  if (dataNetlify.length !== 1 || honeypot.length !== 1) throw new TypeError('Production form postprocessing contract is invalid.');
  return Buffer.from(html.replace(/\sdata-netlify="true"/i, '').replace(/\snetlify-honeypot="bot-field"/i, ''), 'utf8');
}

export function expectedNetlifyLiveHtml(sourceBytes, leadRouteMode, pagePath = 'index.html') {
  let html;
  try { html = new TextDecoder('utf-8', { fatal: true }).decode(sourceBytes); } catch {
    throw new TypeError('Production HTML must be valid UTF-8.');
  }
  if (/<base\b/i.test(html)) throw new TypeError('Production HTML base elements are forbidden.');
  if (leadRouteMode === 'not_required') return Buffer.from(html, 'utf8');
  if (leadRouteMode !== 'netlify_form') throw new TypeError('Production lead route mode is invalid.');
  if (pagePath !== 'contact/index.html') return Buffer.from(html, 'utf8');
  extractNetlifyFormName(sourceBytes);
  return Buffer.from(html
    .replace(/\sdata-netlify=(?:"true"|'true')/i, '')
    .replace(/\snetlify-honeypot=(?:"bot-field"|'bot-field')/i, ''), 'utf8');
}

function signedCspHeader(artifactBytes) {
  const headers = artifactBytes.find(item => item.path === '_headers')?.bytes?.toString('utf8') || '';
  const matches = [...headers.matchAll(/^\s*Content-Security-Policy:\s*(.+?)\s*$/gmi)].map(match => match[1]);
  if (matches.length !== 1 || !/(?:^|;)\s*base-uri\s+'none'\s*(?:;|$)/i.test(matches[0])) {
    throw new TypeError('Signed deploy headers lack an exact base-uri policy.');
  }
  return matches[0];
}

export function deployArtifactsForPhase(artifacts, phase) {
  if (!Array.isArray(artifacts) || !['preclaim', 'final'].includes(phase)) {
    throw new TypeError('Deploy artifact phase is invalid.');
  }
  const headersIndex = artifacts.findIndex(item => item.path === '_headers');
  if (headersIndex !== 0 || !Buffer.isBuffer(artifacts[0].bytes)) throw new TypeError('Signed headers artifact is invalid.');
  const signedHeaders = artifacts[0].bytes.toString('utf8');
  if (phase === 'preclaim' && signedHeaders !== ARC2_PRODUCTION_HEADERS_FILE) {
    throw new TypeError('Preclaim deploy must derive from exact signed production headers.');
  }
  if (phase === 'final' && ![ARC2_PRODUCTION_HEADERS_FILE, ARC2_PRECLAIM_HEADERS_FILE].includes(signedHeaders)) {
    throw new TypeError('Final deploy headers are not an exact signed or preclaim variant.');
  }
  return artifacts.map((item, index) => index === 0 ? {
    path: item.path,
    bytes: Buffer.from(phase === 'preclaim' ? ARC2_PRECLAIM_HEADERS_FILE : ARC2_PRODUCTION_HEADERS_FILE, 'utf8'),
  } : { path: item.path, bytes: Buffer.from(item.bytes) });
}

export function normalizePaymentEvidence(raw, signature, secret, artifactEvidence, env, options = {}) {
  env = requireResolvedHandoffEnvironment(env);
  const canonical = stringValue(raw, 'Payment evidence', 2, 100_000);
  const value = plainObject(JSON.parse(canonical), 'Payment evidence');
  const legacyPaymentVersion = value.version === LEGACY_PAYMENT_EVIDENCE_VERSION;
  exactKeys(value, legacyPaymentVersion ? LEGACY_PAYMENT_FIELDS : PAYMENT_FIELDS, 'Payment evidence');
  const legacyV3 = legacyPaymentVersion && options.allowLegacyV3 === true;
  if (canonicalJson(value) !== canonical || (!legacyV3 && value.version !== PAYMENT_EVIDENCE_VERSION) || value.scope !== PAYMENT_EVIDENCE_SCOPE ||
      (legacyV3 ? artifactEvidence.version !== LEGACY_ARTIFACT_EVIDENCE_VERSION : artifactEvidence.version !== ARTIFACT_EVIDENCE_VERSION)) {
    throw new TypeError('Payment evidence is invalid or not canonical.');
  }
  const protocol = legacyV3 ? 'v3' : 'v4';
  if (!new RegExp(`^${protocol}_[A-Za-z0-9_-]{135}$`).test(value.client_reference_id)) {
    throw new TypeError(`Checkout reference ${protocol} is invalid.`);
  }
  let referenceBytes;
  try { referenceBytes = Buffer.from(value.client_reference_id.slice(3), 'base64url'); } catch {}
  if (!referenceBytes || referenceBytes.length !== 101 || referenceBytes.toString('base64url') !== value.client_reference_id.slice(3)) {
    throw new TypeError(`Checkout reference ${protocol} is not canonical.`);
  }
  const referencePayload = referenceBytes.subarray(0, 69);
  const referenceKeyId = referencePayload.subarray(0, 1).toString('hex');
  const currentKeyId = String(env.ARC_CHECKOUT_BINDING_KEY_ID || '').trim().toLowerCase();
  const retiredKeysRaw = String(env.ARC_RETIRED_CHECKOUT_BINDING_KEYS_JSON || '');
  let retiredKeys;
  try { retiredKeys = JSON.parse(retiredKeysRaw); } catch {}
  if (!/^[a-f0-9]{2}$/.test(currentKeyId) || !retiredKeys || typeof retiredKeys !== 'object' || Array.isArray(retiredKeys) ||
      canonicalJson(retiredKeys) !== retiredKeysRaw || secret.length < 32 || secret.length > 256 ||
      Object.keys(retiredKeys).some((id) => !/^[a-f0-9]{2}$/.test(id) || id === currentKeyId || typeof retiredKeys[id] !== 'string' ||
        retiredKeys[id].length < 32 || retiredKeys[id].length > 256) ||
      new Set(Object.values(retiredKeys)).size !== Object.values(retiredKeys).length || Object.values(retiredKeys).includes(secret)) {
    throw new TypeError('Checkout binding key registry is invalid.');
  }
  const selectedSecret = referenceKeyId === currentKeyId ? secret : retiredKeys[referenceKeyId];
  const expectedStripeMode = env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true' ? 'live' : 'test';
  const paymentSignaturePrefix = legacyV3 ? LEGACY_PAYMENT_SIGNATURE_PREFIX : PAYMENT_SIGNATURE_PREFIX;
  if (!selectedSecret || !safeEqual(hex64(signature, 'Payment evidence signature'), hmacHex(selectedSecret, `${paymentSignaturePrefix}${expectedStripeMode}\n${canonical}`))) {
    throw new TypeError('Payment evidence signature mismatch or checkout key is not retained.');
  }
  const expectedMac = createHmac('sha256', selectedSecret)
    .update(`arc-checkout-reference-${protocol}\narcwebhq-cpu/arc-previews\narc-production\nstripe-${expectedStripeMode}\n`).update(referencePayload).digest();
  if (!timingSafeEqual(referenceBytes.subarray(69), expectedMac)) throw new TypeError(`Checkout reference ${protocol} MAC mismatch.`);
  const referencePrefix = referencePayload.subarray(1, 5).toString('hex');
  const referenceApprovalSha256 = referencePayload.subarray(5, 37).toString('hex');
  const referenceConfigSha256 = referencePayload.subarray(37, 69).toString('hex');
  if (!value.preview_folder.endsWith(`-${referencePrefix}`) || value.approval_content_sha256 !== referenceApprovalSha256 ||
      value.checkout_config_snapshot_sha256 !== referenceConfigSha256 || value.client_reference_id_sha256 !== sha256Hex(value.client_reference_id)) {
    throw new TypeError(`Checkout reference ${protocol} payload binding is invalid.`);
  }
  const snapshotCanonical = stringValue(value.checkout_config_snapshot, 'Private checkout policy', 200, 24_000);
  const snapshot = plainObject(JSON.parse(snapshotCanonical), 'Private checkout policy');
  const legacySnapshotFields = ['adult_acknowledgement_key','amount_subtotal_minor_units','approval_content_sha256','asset_publication_receipt_sha256','automatic_tax_enabled',
    'checkout_binding_key_id','checkout_redirect_url','claim_recipient_email_sha256','completed_sessions_limit','content_sha256','currency','customer_address_source',
    'lead_route_recipient_hmac_sha256','name_collection_required','offer_snapshot_sha256','preview_folder','preview_path','preview_source_repository',
    'price_id','price_tax_behavior','product_id','product_tax_code','published_html_sha256','quantity','readiness_core_sha256','recipient_reservation_sha256','scope',
    'source_commit_sha','source_tree_sha','stripe_account_id_sha256','stripe_api_version','stripe_mode','tax_contract_version','tax_registrations',
    'tax_registrations_sha256','terms_document_sha256','terms_version','version'];
  const v4SnapshotFields = ['adult_acknowledgement_key','amount_subtotal_minor_units','approval_content_sha256','asset_publication_receipt_sha256','automatic_tax_enabled',
    'checkout_binding_key_id','checkout_redirect_url','claim_recipient_email_sha256','completed_sessions_limit','content_sha256','currency','customer_address_source',
    'deliverable','lead_route_recipient_hmac_sha256','name_collection_required','offer_contract_id','offer_snapshot_sha256','page_count','preview_folder',
    'preview_paths','preview_source_repository','price_id','price_tax_behavior','product_id','product_tax_code','published_site_sha256','quantity','readiness_core_sha256',
    'recipient_reservation_sha256','scope','source_commit_sha','source_tree_sha','stripe_account_id_sha256','stripe_api_version','stripe_mode','tax_contract_version',
    'tax_registrations','tax_registrations_sha256','terms_document_sha256','terms_version','version'];
  const snapshotFields = legacyV3 ? legacySnapshotFields : v4SnapshotFields;
  exactKeys(snapshot, snapshotFields, 'Private checkout policy');
  const expectedPreviewPaths = HTML_PATHS.map(path => `${value.preview_folder}/${path}`);
  if (canonicalJson(snapshot) !== snapshotCanonical || sha256Hex(snapshotCanonical) !== referenceConfigSha256 ||
      snapshot.version !== (legacyV3 ? 'arc-private-checkout-policy-v1' : 'arc-private-checkout-policy-v2') ||
      snapshot.scope !== (legacyV3 ? 'one-approved-preview-one-private-payment-link' : 'one-approved-five-page-preview-one-private-payment-link') ||
      snapshot.checkout_binding_key_id !== referenceKeyId || snapshot.stripe_mode !== expectedStripeMode ||
      snapshot.preview_folder !== value.preview_folder || !snapshot.preview_folder.endsWith(`-${referencePrefix}`) ||
      (legacyV3 ? snapshot.preview_path !== `${value.preview_folder}/index.html`
        : (snapshot.offer_contract_id !== 'arc-fixed-five-page-offer-v1' || snapshot.deliverable !== 'fixed-five-page-marketing-website-v1' ||
          snapshot.page_count !== 5 || canonicalJson(snapshot.preview_paths) !== canonicalJson(expectedPreviewPaths) ||
          snapshot.published_site_sha256 !== artifactEvidence.production_content_sha256)) ||
      snapshot.preview_source_repository !== 'arcwebhq-cpu/arc-previews' ||
      snapshot.source_commit_sha !== artifactEvidence.preview_source_commit_sha ||
      snapshot.approval_content_sha256 !== referenceApprovalSha256) throw new TypeError('Private checkout policy is invalid or unbound.');
  const taxFields = ['country', 'id', 'state', 'type'];
  if (!Array.isArray(snapshot.tax_registrations) ||
      snapshot.tax_registrations.length < 1 || snapshot.tax_registrations.length > 100 ||
      snapshot.tax_registrations.some((registration) => {
        try { plainObject(registration, 'Checkout tax registration'); exactKeys(registration, taxFields, 'Checkout tax registration'); } catch { return true; }
        return !/^taxreg_[A-Za-z0-9]+$/.test(registration.id) || !/^[A-Z]{2}$/.test(registration.country) ||
          !/^[A-Z0-9-]{1,10}$/.test(registration.state) || !/^[a-z][a-z0-9_]{2,63}$/.test(registration.type);
      }) || canonicalJson([...snapshot.tax_registrations].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0)) !== canonicalJson(snapshot.tax_registrations) ||
      new Set(snapshot.tax_registrations.map((registration) => registration.id)).size !== snapshot.tax_registrations.length ||
      sha256Hex(canonicalJson(snapshot.tax_registrations)) !== snapshot.tax_registrations_sha256 ||
      !snapshot.tax_registrations.some((registration) => registration.country === 'US' && registration.state === 'WA' && registration.type === 'state_sales_tax')) {
    throw new TypeError('Private checkout policy tax registry is invalid.');
  }
  const staticSnapshotChecks = {
    price_id: /^price_[A-Za-z0-9]+$/.test(snapshot.price_id), product_id: /^prod_[A-Za-z0-9]+$/.test(snapshot.product_id),
    product_tax_code: /^txcd_[0-9]{8}$/.test(snapshot.product_tax_code), account: HEX_64_PATTERN.test(snapshot.stripe_account_id_sha256),
    subtotal: snapshot.amount_subtotal_minor_units === 500000, currency: snapshot.currency === 'usd', quantity: snapshot.quantity === 1,
    terms: (legacyV3 ? /^20\d\d-\d\d-\d\d$/.test(snapshot.terms_version) : snapshot.terms_version === '2026-08-25') &&
      HEX_64_PATTERN.test(snapshot.terms_document_sha256),
    automatic_tax: snapshot.automatic_tax_enabled === true, address_source: snapshot.customer_address_source === 'stripe_checkout_customer_details.address',
    tax_behavior: snapshot.price_tax_behavior === 'exclusive', tax_contract: snapshot.tax_contract_version === 'arc-tax-v1',
    adult: snapshot.adult_acknowledgement_key === 'adultpurchaserack',
    names: snapshot.name_collection_required === true, limit: snapshot.completed_sessions_limit === 1,
    redirect: snapshot.checkout_redirect_url === 'https://arcweb.onl/payment-success/?session_id={CHECKOUT_SESSION_ID}',
    api: snapshot.stripe_api_version === (legacyV3 ? '2026-06-24.dahlia' : '2026-07-29.dahlia'),
    receipt: HEX_64_PATTERN.test(snapshot.asset_publication_receipt_sha256),
    lead_recipient: /^(?:|[a-f0-9]{64})$/.test(snapshot.lead_route_recipient_hmac_sha256),
    claim_recipient: HEX_64_PATTERN.test(snapshot.claim_recipient_email_sha256),
    immutable_digests: ['content_sha256', legacyV3 ? 'published_html_sha256' : 'published_site_sha256',
      'readiness_core_sha256','offer_snapshot_sha256','recipient_reservation_sha256']
      .every((field) => HEX_64_PATTERN.test(snapshot[field])),
    immutable_commits: /^[a-f0-9]{40}$/.test(snapshot.source_commit_sha) && /^[a-f0-9]{40}$/.test(snapshot.source_tree_sha),
  };
  const failedSnapshotCheck = Object.entries(staticSnapshotChecks).find(([, valid]) => !valid)?.[0];
  if (failedSnapshotCheck) throw new TypeError(`Checkout configuration snapshot fixed business semantics are invalid (${failedSnapshotCheck}).`);
  const checkoutSessionPattern = expectedStripeMode === 'live' ? /^cs_live_[A-Za-z0-9_]+$/ : /^cs_test_[A-Za-z0-9_]+$/;
  const amountsValid = Number.isSafeInteger(value.subtotal_amount_minor_units) && value.subtotal_amount_minor_units === 500000 &&
    Number.isSafeInteger(value.tax_amount_minor_units) && value.tax_amount_minor_units >= 0 && value.tax_amount_minor_units <= 500000 &&
    Number.isSafeInteger(value.amount_total_minor_units) && value.amount_total_minor_units === value.subtotal_amount_minor_units + value.tax_amount_minor_units;
  const knownTaxabilityReasons = new Set(['customer_exempt', 'not_collecting', 'not_subject_to_tax', 'not_supported', 'portion_product_exempt', 'portion_reduced_rated',
    'portion_standard_rated', 'product_exempt', 'product_exempt_holiday', 'proportionally_rated', 'reduced_rated', 'reverse_charge', 'standard_rated',
    'taxable_basis_reduced', 'zero_rated']);
  const ratedTaxabilityReasons = new Set(['portion_reduced_rated', 'portion_standard_rated', 'proportionally_rated', 'reduced_rated', 'standard_rated', 'taxable_basis_reduced']);
  const taxabilityReasonsValid = legacyV3 || (
    Array.isArray(value.taxability_reasons) && value.taxability_reasons.length >= 1 &&
    value.taxability_reasons.length <= knownTaxabilityReasons.size &&
    value.taxability_reasons.every(reason => typeof reason === 'string' && knownTaxabilityReasons.has(reason)) &&
    JSON.stringify(value.taxability_reasons) === JSON.stringify([...new Set(value.taxability_reasons)].sort()) &&
    (value.tax_amount_minor_units > 0
      ? value.taxability_reasons.includes('standard_rated')
      : !value.taxability_reasons.some(reason => ratedTaxabilityReasons.has(reason)) &&
        !value.taxability_reasons.some(reason => ['customer_exempt', 'not_supported', 'reverse_charge'].includes(reason)) &&
        !(value.taxability_reasons.includes('not_collecting') && value.product_tax_code !== 'txcd_00000000'))
  );
  const countryValid = /^[A-Z]{2}$/.test(value.customer_address_country);
  const regionValid = value.customer_address_country === 'US'
    ? /^[A-Z]{2}$/.test(value.customer_address_state)
    : /^[A-Z0-9-]{0,10}$/.test(value.customer_address_state);
  const destinationValid = countryValid && regionValid &&
    !(value.customer_address_country === 'US' && value.customer_address_state === 'WA' && value.tax_amount_minor_units <= 0);
  if (value.preview_folder !== artifactEvidence.preview_folder ||
      value.production_content_sha256 !== artifactEvidence.production_content_sha256 ||
      value.artifact_manifest_sha256 !== artifactEvidence.artifact_manifest_sha256 ||
      value.handoff_artifact_evidence_sha256 !== sha256Hex(canonicalJson(artifactEvidence)) ||
      value.bundle_fingerprint !== artifactEvidence.bundle_fingerprint ||
      value.livemode !== (expectedStripeMode === 'live') || value.mode !== 'payment' || value.status !== 'complete' ||
      value.payment_status !== 'paid' || value.currency !== 'usd' || !amountsValid || !taxabilityReasonsValid ||
      value.automatic_tax_enabled !== true || value.automatic_tax_status !== 'complete' ||
      value.price_tax_behavior !== 'exclusive' || value.product_tax_code !== snapshot.product_tax_code || value.product_id !== snapshot.product_id ||
      value.tax_contract_version !== 'arc-tax-v1' || !destinationValid || value.customer_address_status !== 'verified' ||
      value.tax_registration_status !== 'historical_precheckout_snapshot' || value.quantity !== 1 ||
      !/^plink_[A-Za-z0-9]+$/.test(value.payment_link_id) || !/^pi_[A-Za-z0-9]+$/.test(value.payment_intent_id) || !/^ch_[A-Za-z0-9]+$/.test(value.charge_id) ||
      value.price_id !== snapshot.price_id ||
      !safeEqual(hex64(value.stripe_account_id_sha256, 'Stripe account id sha256'), snapshot.stripe_account_id_sha256) ||
      value.terms_of_service_consent !== 'accepted' || value.terms_version !== snapshot.terms_version ||
      value.adult_purchaser_acknowledgement !== 'accepted' ||
      !checkoutSessionPattern.test(value.checkout_session_id)) {
    throw new TypeError('Payment evidence bindings are invalid.');
  }
  hex64(value.claim_recipient_email_sha256, 'Claim recipient email sha256');
  hex64(value.payer_email_sha256, 'Payer email sha256');
  hex64(value.client_reference_id_sha256, 'Client reference id sha256');
  hex64(value.customer_address_sha256, 'Customer address sha256');
  if (!legacyV3) hex64(value.line_item_taxes_sha256, 'Line-item taxes sha256');
  hex64(value.tax_registrations_sha256, 'Tax registrations sha256');
  if (value.tax_registrations_sha256 !== snapshot.tax_registrations_sha256 ||
      snapshot.asset_publication_receipt_sha256 !== value.asset_publication_receipt_sha256 ||
      snapshot.checkout_binding_key_id !== artifactEvidence.checkout_binding_key_id ||
      snapshot.lead_route_recipient_hmac_sha256 !== artifactEvidence.lead_route_recipient_hmac_sha256 ||
      value.approval_content_sha256 !== artifactEvidence.approval_content_sha256 ||
      value.asset_publication_receipt_sha256 !== artifactEvidence.asset_publication_receipt_sha256 ||
      value.checkout_config_snapshot_sha256 !== artifactEvidence.checkout_config_snapshot_sha256 ||
      value.client_reference_id_sha256 !== artifactEvidence.checkout_reference_sha256 ||
      value.preview_source_tag_sha256 !== sha256Hex(`refs/tags/arc-checkout-ready-${protocol}/${value.client_reference_id_sha256}`) ||
      value.preview_source_commit_sha !== artifactEvidence.preview_source_commit_sha ||
      value.preview_source_repository !== artifactEvidence.preview_source_repository ||
      value.preview_source_tag_sha256 !== artifactEvidence.preview_source_tag_sha256 ||
      value.claim_recipient_email_sha256 !== snapshot.claim_recipient_email_sha256 ||
      !/^[a-f0-9]{40}$/.test(value.preview_source_commit_sha) || value.preview_source_repository !== 'arcwebhq-cpu/arc-previews') {
    throw new TypeError('Payment evidence immutable source bindings are invalid.');
  }
  const mismatch = value.client_reference_id_observation === 'MISMATCH_REVIEW_REQUIRED';
  if (!['ABSENT','MATCHED','MISMATCH_REVIEW_REQUIRED'].includes(value.client_reference_id_observation) || value.client_reference_mismatch_review_required !== mismatch) {
    throw new TypeError('Client-reference observation is invalid.');
  }
  if (!mismatch) {
    if ([value.client_reference_mismatch_review_record_key_hmac_sha256,value.client_reference_mismatch_review_state,
      value.client_reference_mismatch_review_sha256,value.client_reference_mismatch_review_hmac_sha256].some(Boolean)) {
      throw new TypeError('Unexpected client-reference mismatch review.');
    }
  } else {
    const reviewCanonical = stringValue(value.client_reference_mismatch_review_state, 'Client-reference mismatch review', 2, 4096);
    const review = plainObject(JSON.parse(reviewCanonical), 'Client-reference mismatch review');
    exactKeys(review,['checkout_policy_sha256','checkout_session_id_hmac_sha256','expected_checkout_reference_sha256','link_id_hmac_sha256',
      'link_receipt_sha256','observed_client_reference_sha256','record_key_hmac_sha256','scope','status','stripe_account_id_sha256','stripe_mode','version'],
    'Client-reference mismatch review');
    if (canonicalJson(review) !== reviewCanonical || review.version !== 'arc2-client-reference-mismatch-review-v1' ||
        review.scope !== 'buyer-supplied-client-reference-anomaly' || review.status !== 'REVIEW_REQUIRED' || review.stripe_mode !== expectedStripeMode ||
        review.record_key_hmac_sha256 !== value.client_reference_mismatch_review_record_key_hmac_sha256 || review.checkout_policy_sha256 !== referenceConfigSha256 ||
        review.expected_checkout_reference_sha256 !== value.client_reference_id_sha256 || review.stripe_account_id_sha256 !== value.stripe_account_id_sha256 ||
        !['checkout_session_id_hmac_sha256','link_id_hmac_sha256','link_receipt_sha256','observed_client_reference_sha256','record_key_hmac_sha256']
          .every((field) => HEX_64_PATTERN.test(review[field])) || sha256Hex(reviewCanonical) !== value.client_reference_mismatch_review_sha256 ||
        !safeEqual(hex64(value.client_reference_mismatch_review_hmac_sha256,'Client-reference mismatch review HMAC'),
          hmacHex(selectedSecret, `arc2-client-reference-mismatch-review-signature-v1\n${expectedStripeMode}\n${reviewCanonical}`))) {
      throw new TypeError('Client-reference mismatch review binding is invalid.');
    }
  }
  return { canonical, value, digest: sha256Hex(canonical), selectedCheckoutBindingSecret: selectedSecret, stripeMode: expectedStripeMode, legacyV3 };
}

export function normalizeReviewPaymentEvidence(raw, signature, secret, artifactEvidence, env) {
  env = requireResolvedHandoffEnvironment(env);
  const canonical = stringValue(raw, 'Review payment evidence', 2, 100_000);
  const value = plainObject(JSON.parse(canonical), 'Review payment evidence');
  exactKeys(value, REVIEW_PAYMENT_FIELDS, 'Review payment evidence');
  const stripeMode = env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true' ? 'live' : 'test';
  if (canonicalJson(value) !== canonical || value.version !== REVIEW_PAYMENT_EVIDENCE_VERSION ||
      value.scope !== REVIEW_PAYMENT_EVIDENCE_SCOPE || artifactEvidence.version !== ARTIFACT_EVIDENCE_VERSION ||
      typeof secret !== 'string' || secret.length < 32 || secret.length > 512 ||
      !safeEqual(hex64(signature, 'Review payment evidence signature'), hmacHex(secret,
        `${REVIEW_PAYMENT_SIGNATURE_PREFIX}${stripeMode}\n${canonical}`))) {
    throw new TypeError('Review payment evidence is invalid, unsigned, or not canonical.');
  }
  for (const field of REVIEW_PAYMENT_FIELDS.filter(name => name.endsWith('_sha256'))) {
    hex64(value[field], `Review payment ${field}`);
  }
  const checkoutPattern = stripeMode === 'live' ? /^cs_live_[A-Za-z0-9_]+$/ : /^cs_test_[A-Za-z0-9_]+$/;
  const amountValid = Number.isSafeInteger(value.subtotal_amount_minor_units) &&
    value.subtotal_amount_minor_units === 500_000 &&
    Number.isSafeInteger(value.tax_amount_minor_units) && value.tax_amount_minor_units >= 0 &&
    value.tax_amount_minor_units <= 500_000 && Number.isSafeInteger(value.amount_total_minor_units) &&
    value.amount_total_minor_units === value.subtotal_amount_minor_units + value.tax_amount_minor_units;
  if (!checkoutPattern.test(value.checkout_session_id) || !/^pi_[A-Za-z0-9_]{6,128}$/.test(value.payment_intent_id) ||
      value.payment_link_id !== null || value.livemode !== (stripeMode === 'live') || value.mode !== 'payment' ||
      value.status !== 'complete' || value.payment_status !== 'paid' || value.currency !== 'usd' || !amountValid ||
      value.automatic_tax_enabled !== true || value.automatic_tax_status !== 'complete' ||
      value.terms_of_service_consent !== 'accepted' || value.adult_purchaser_acknowledgement !== 'accepted' ||
      !/^[A-Z]{2}$/.test(value.customer_address_country) ||
      (value.customer_address_country === 'US' && !/^[A-Z]{2}$/.test(value.customer_address_state)) ||
      !/^[A-Z0-9-]{0,10}$/.test(value.customer_address_state) ||
      !/^[a-z0-9][a-z0-9-]*-[a-f0-9]{8}$/.test(value.preview_folder) ||
      value.preview_source_repository !== 'arcwebhq-cpu/arc-previews' ||
      !/^[a-f0-9]{40}$/.test(value.preview_source_commit_sha)) {
    throw new TypeError('Review payment provider semantics are invalid.');
  }
  if (!safeEqual(value.checkout_session_id_hmac_sha256, hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
    `stripe-checkout-session-id-v1\n${value.checkout_session_id}`)) ||
      !safeEqual(value.payment_intent_id_hmac_sha256, hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
        `stripe-checkout-payment-intent-id-v1\n${value.payment_intent_id}`)) ||
      !safeEqual(value.client_reference_id_sha256, sha256Hex(value.approval_receipt_sha256)) ||
      !safeEqual(value.artifact_manifest_sha256, artifactEvidence.artifact_manifest_sha256) ||
      !safeEqual(value.preview_manifest_sha256, artifactEvidence.artifact_manifest_sha256) ||
      !safeEqual(value.production_content_sha256, artifactEvidence.production_content_sha256) ||
      !safeEqual(value.preview_content_sha256, artifactEvidence.production_content_sha256) ||
      !safeEqual(value.handoff_artifact_evidence_sha256, sha256Hex(canonicalJson(artifactEvidence))) ||
      !safeEqual(value.bundle_fingerprint, artifactEvidence.bundle_fingerprint) ||
      value.preview_folder !== artifactEvidence.preview_folder ||
      value.preview_source_repository !== artifactEvidence.preview_source_repository ||
      value.preview_source_commit_sha !== artifactEvidence.preview_source_commit_sha ||
      !safeEqual(artifactEvidence.checkout_reference_sha256, sha256Hex(value.approval_receipt_sha256))) {
    throw new TypeError('Review payment immutable artifact or identity binding is invalid.');
  }
  return {
    canonical,
    value,
    digest: sha256Hex(canonical),
    selectedCheckoutBindingSecret: env.ARC_CHECKOUT_BINDING_SECRET,
    stripeMode,
    legacyV3: false,
    reviewSession: true,
  };
}

function exactQuotedAttribute(attributes, name) {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const mentions = [...attributes.matchAll(new RegExp(`(?:^|\\s)${escapedName}(?=\\s|=|$)`, 'gi'))];
  const assignments = [...attributes.matchAll(new RegExp(`(?:^|\\s)${escapedName}\\s*=\\s*(["'])([^"']*)\\1`, 'gi'))];
  if (mentions.length !== 1 || assignments.length !== 1) throw new TypeError('Netlify lead form attributes are invalid.');
  return assignments[0][2];
}

export function extractNetlifyFormName(contactBytes) {
  let html;
  try {
    html = new TextDecoder('utf-8', { fatal: true }).decode(contactBytes);
  } catch {
    throw new TypeError('Production HTML must be valid UTF-8.');
  }
  const forms = [...html.matchAll(/<form\b([^>]*)>[\s\S]*?<\/form\s*>/gi)];
  if (forms.length !== 1) throw new TypeError('Exactly one Netlify-enabled lead form is required.');
  if (/\bformaction\b/i.test(html)) throw new TypeError('Netlify lead form formaction overrides are forbidden.');
  const attributes = forms[0][1];
  const formName = validateFormName(exactQuotedAttribute(attributes, 'name'));
  if (exactQuotedAttribute(attributes, 'method').toUpperCase() !== 'POST' ||
      exactQuotedAttribute(attributes, 'data-netlify').toLowerCase() !== 'true' ||
      exactQuotedAttribute(attributes, 'netlify-honeypot') !== 'bot-field' ||
      exactQuotedAttribute(attributes, 'action') !== '/contact/?submitted=1') {
    throw new TypeError('Netlify lead form attributes are invalid.');
  }
  const formNameInputs = [...html.matchAll(/<input\b([^>]*)>/gi)]
    .filter(match => /(?:^|\s)name\s*=\s*(?:"form-name"|'form-name'|form-name)(?=\s|\/|$)/i.test(match[1]));
  if (formNameInputs.length !== 1) throw new TypeError('Exactly one hidden Netlify form-name binding is required.');
  const hiddenAttributes = formNameInputs[0][1];
  if (exactQuotedAttribute(hiddenAttributes, 'name') !== 'form-name' ||
      exactQuotedAttribute(hiddenAttributes, 'type').toLowerCase() !== 'hidden' ||
      exactQuotedAttribute(hiddenAttributes, 'value') !== formName) {
    throw new TypeError('Netlify hidden form-name binding is invalid.');
  }
  return formName;
}

function extractLegacyNetlifyFormName(indexBytes) {
  let html;
  try { html = new TextDecoder('utf-8', { fatal: true }).decode(indexBytes); } catch {
    throw new TypeError('Production HTML must be valid UTF-8.');
  }
  const forms = [...html.matchAll(/<form\b([^>]*)>[\s\S]*?<\/form\s*>/gi)]
    .filter(match => /\bdata-netlify\s*=\s*(["'])true\1/i.test(match[1]));
  if (forms.length !== 1) throw new TypeError('Exactly one Netlify-enabled lead form is required.');
  const nameMatch = forms[0][1].match(/\bname\s*=\s*(["'])([^"']+)\1/i);
  const methodMatch = forms[0][1].match(/\bmethod\s*=\s*(["'])([^"']+)\1/i);
  if (!nameMatch || !methodMatch || methodMatch[2].toUpperCase() !== 'POST') throw new TypeError('Netlify lead form attributes are invalid.');
  return validateFormName(nameMatch[2]);
}

function normalizeStartPayloadWithKind(input, env, now = new Date(), options = {}, kind = 'payment-link') {
  plainObject(input, 'Start payload');
  exactKeys(input, [
    'artifact_evidence',
    'artifact_evidence_hmac_sha256',
    'deploy_artifacts',
    'lead_notification_email',
    'lead_route_recipient_hmac_sha256',
    'payment_evidence',
    'payment_evidence_hmac_sha256',
  ], 'Start payload');
  const artifact = normalizeArtifactEvidence(input.artifact_evidence, env.ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET, now, options);
  if (!verifyArtifactSignature(artifact.canonical, input.artifact_evidence_hmac_sha256,
    env.ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET, artifact.value.version)) {
    throw new TypeError('Artifact evidence signature mismatch.');
  }
  const payment = kind === 'review-session'
    ? normalizeReviewPaymentEvidence(
      input.payment_evidence,
      input.payment_evidence_hmac_sha256,
      env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET,
      artifact.value,
      env,
    )
    : normalizePaymentEvidence(
      input.payment_evidence,
      input.payment_evidence_hmac_sha256,
      env.ARC_CHECKOUT_BINDING_SECRET,
      artifact.value,
      env,
      options,
    );
  const deployArtifacts = normalizeDeployArtifacts(input.deploy_artifacts, artifact.artifacts);
  const bundleHash = createHash('sha256');
  for (const artifactEntry of deployArtifacts) bundleHash.update(artifactEntry.path).update('\0').update(artifactEntry.bytes).update('\0');
  if (bundleHash.digest('hex') !== artifact.value.bundle_fingerprint) throw new TypeError('Deploy artifact bundle fingerprint mismatch.');
  const legacyV3 = artifact.legacyV3;
  const pages = legacyV3 ? [deployArtifacts.find(entry => entry.path === 'index.html')] : htmlArtifacts(deployArtifacts);
  const contact = legacyV3 ? null : pages.find((entry) => entry.path === 'contact/index.html');
  const headers = deployArtifacts.find((entry) => entry.path === '_headers');
  if (!headers || !headers.bytes.equals(Buffer.from(ARC2_PRODUCTION_HEADERS_FILE, 'utf8'))) {
    throw new TypeError('Signed production headers do not match the exact indexable security policy.');
  }
  if ((legacyV3 ? sha256Hex(pages[0].bytes) : productionContentSha256(pages)) !== artifact.value.production_content_sha256) {
    throw new TypeError('Production content digest mismatch.');
  }
  if (legacyV3) validateLegacyProductionAssetReferences(pages[0].bytes, deployArtifacts);
  else validateProductionAssetReferences(pages, deployArtifacts);
  const leadRouteMode = artifact.value.lead_route_mode;
  let leadEmail = '';
  let recipientHmac = '';
  let formName = '';
  if (leadRouteMode === 'netlify_form') {
    leadEmail = stringValue(input.lead_notification_email, 'Lead notification email', 3, 254).toLowerCase();
    recipientHmac = hex64(input.lead_route_recipient_hmac_sha256, 'Lead recipient HMAC');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(leadEmail) ||
        !safeEqual(recipientHmac, hmacHex(payment.selectedCheckoutBindingSecret, `arc-checkout-lead-recipient-v1\n${payment.stripeMode}\n${leadEmail}`)) ||
        recipientHmac !== artifact.value.lead_route_recipient_hmac_sha256) {
      throw new TypeError('Lead notification email is invalid or unbound.');
    }
    if (!legacyV3 && pages.some(page => page.path !== 'contact/index.html' &&
        /<form\b|\bformaction\b/i.test(page.bytes.toString('utf8')))) {
      throw new TypeError('The Netlify lead form is permitted only on the Contact page.');
    }
    formName = legacyV3 ? extractLegacyNetlifyFormName(pages[0].bytes) : extractNetlifyFormName(contact.bytes);
    if (formName !== artifact.value.lead_route_form_name) throw new TypeError('Lead form is not bound to signed artifact evidence.');
  } else {
    if (input.lead_notification_email !== '' || input.lead_route_recipient_hmac_sha256 !== '' ||
        pages.some(page => /<form\b/i.test(page.bytes.toString('utf8')))) {
      throw new TypeError('No-form handoff contains unexpected lead-route data.');
    }
  }
  return { artifact, payment, deployArtifacts, leadEmail, leadRouteRecipientHmacSha256: recipientHmac, formName, legacyV3 };
}

export function normalizeStartPayload(input, env, now = new Date(), options = {}) {
  return normalizeStartPayloadWithKind(input, env, now, options, 'payment-link');
}

export function normalizeReviewStartPayload(input, env, now = new Date(), options = {}) {
  return normalizeStartPayloadWithKind(input, env, now, options, 'review-session');
}

export function handoffKey(paymentEvidence, stateSecret) {
  stringValue(stateSecret, 'Handoff state secret', 32, 512);
  const stable = `${paymentEvidence.checkout_session_id}\n${paymentEvidence.preview_folder}\n${paymentEvidence.bundle_fingerprint}`;
  return `handoffs/${hmacHex(stateSecret, stable)}`;
}

export function deterministicSiteName(paymentEvidence, stateSecret) {
  return `arc-lead-route-${hmacHex(stateSecret, `site-name-v1\n${paymentEvidence.checkout_session_id}\n${paymentEvidence.bundle_fingerprint}`).slice(0, 24)}`;
}

export function createInitialRecord(normalized, env, key, now = new Date(), random = {}) {
  const timestamp = new Date(now).toISOString();
  const netlifySessionId = (random.uuid || randomUUID)();
  if (!UUID_PATTERN.test(netlifySessionId)) throw new TypeError('Secure randomness is unavailable.');
  const record = {
    schema: HANDOFF_SCHEMA,
    handoff_id: handoffIdFromKey(key),
    state: 'PAYMENT_VERIFIED',
    revision: 1,
    created_at: timestamp,
    updated_at: timestamp,
    payment_evidence_sha256: normalized.payment.digest,
    artifact_evidence_sha256: normalized.artifact.digest,
    artifact_manifest_sha256: normalized.artifact.value.artifact_manifest_sha256,
    bundle_fingerprint: normalized.artifact.value.bundle_fingerprint,
    production_content_sha256: normalized.artifact.value.production_content_sha256,
    customer_email_sha256: normalized.payment.value.claim_recipient_email_sha256,
    lead_notification_email_sha256: sha256Hex(normalized.leadEmail),
    lead_route_recipient_hmac_sha256: normalized.leadRouteRecipientHmacSha256,
    lead_route_mode: normalized.artifact.value.lead_route_mode,
    preview_folder: normalized.artifact.value.preview_folder,
    artifacts: normalized.artifact.artifacts,
    form_name: normalized.formName,
    netlify_session_id: netlifySessionId,
    netlify_site_name: deterministicSiteName(normalized.payment.value, env.ARC_HANDOFF_STATE_SECRET),
    netlify_source_account_id: env.NETLIFY_TEAM_ACCOUNT_ID,
    netlify_site_id: null,
    site_created_at: null,
    preclaim_deploy_attempted_at: null,
    preclaim_deploy_candidate_id: null,
    preclaim_deploy_id: null,
    final_deploy_attempted_at: null,
    final_deploy_candidate_id: null,
    final_deploy_id: null,
    email_hook_attempted_at: null,
    form_id: null,
    hook_id: null,
    destination_account_id: null,
    lead_route_receipt_sha256: null,
    claim_token_hmac_sha256: null,
    claim_invitation_generation: 0,
    claim_token_consumed_hmac_sha256: null,
    claim_token_expires_at: null,
    claim_token_used_at: null,
    claim_wrapper_consumed_at: null,
    claim_jwt_issued_at: null,
    claim_invitation_ready_at: null,
    lead_route_provider_message_id_sha256: null,
    claim_callback_received_at: null,
    claimed_verified_at: null,
    final_deploy_ready_at: null,
    production_url: null,
    outbox_claim_status: null,
    outbox_claim_key_hmac_sha256: null,
    final_delivery_receipt_sha256: null,
    final_delivery_provider: null,
    final_delivery_provider_account_hmac_sha256: null,
    final_delivery_provider_event_id_hmac_sha256: null,
    final_delivery_provider_message_id_hmac_sha256: null,
    final_delivery_event_type: null,
    final_delivery_status: null,
    final_delivery_receipt_issued_at: null,
    delivered_at: null,
  };
  if (!SAFE_SITE_NAME_PATTERN.test(record.netlify_site_name)) throw new TypeError('Deterministic site name is invalid.');
  return { record };
}

export function transitionRecord(record, nextState, patch = {}, now = new Date()) {
  plainObject(record, 'Handoff record');
  plainObject(patch, 'State patch');
  if (!HANDOFF_STATES.includes(record.state) || !HANDOFF_STATES.includes(nextState) || !TRANSITIONS[record.state].has(nextState)) {
    throw new TypeError(`Invalid handoff transition: ${record.state} -> ${nextState}.`);
  }
  if ('state' in patch || 'revision' in patch || 'schema' in patch || 'created_at' in patch) throw new TypeError('Reserved state field in patch.');
  return {
    ...record,
    ...patch,
    state: nextState,
    revision: record.revision + 1,
    updated_at: new Date(now).toISOString(),
  };
}

export function reviseRecord(record, patch = {}, now = new Date()) {
  plainObject(record, 'Handoff record');
  plainObject(patch, 'State patch');
  if ('state' in patch || 'revision' in patch || 'schema' in patch || 'created_at' in patch) throw new TypeError('Reserved state field in patch.');
  return { ...record, ...patch, revision: record.revision + 1, updated_at: new Date(now).toISOString() };
}

export function publicStatus(record, now = new Date()) {
  const nowMs = new Date(now).getTime();
  const status = {
    status: record.state,
    site_ready: ['PRECLAIM_DEPLOY_READY', 'LEAD_ROUTE_VERIFIED', 'INVITATION_READY', 'CLAIM_WRAPPER_CONSUMED', 'CLAIM_CALLBACK_RECEIVED', 'CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED'].includes(record.state),
    claim_available: record.state === 'INVITATION_READY' && Number.isFinite(nowMs) &&
      Date.parse(record.claim_token_expires_at) > nowMs,
    claim_verified: ['CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED'].includes(record.state),
    delivery_ready: ['FINAL_DEPLOY_READY', 'DELIVERED'].includes(record.state),
    delivered: record.state === 'DELIVERED',
    updated_at: record.updated_at,
  };
  if (record.state === 'FINAL_DEPLOY_READY' || record.state === 'DELIVERED') status.production_url = record.production_url;
  return status;
}

export function netlifyClaimUrl(record, env) {
  if (record.state !== 'CLAIM_WRAPPER_CONSUMED') throw new TypeError('Claim link is not available in the current state.');
  const claimWebhook = `${new URL(env.ARC_PUBLIC_ORIGIN).origin}/api/arc2/claim-webhook`;
  const issuedAt = record.claim_jwt_issued_at;
  const invitationExpiresAt = Math.floor(Date.parse(record.claim_token_expires_at) / 1000);
  const expiresAt = Math.min(invitationExpiresAt, issuedAt + CLAIM_JWT_TTL_SECONDS);
  if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt) {
    throw new TypeError('Claim JWT lifetime is invalid.');
  }
  const token = signJwtHS256({
    client_id: env.NETLIFY_OAUTH_CLIENT_ID,
    session_id: record.netlify_session_id,
    claim_webhook: claimWebhook,
    iat: issuedAt,
    exp: expiresAt,
  }, env.NETLIFY_OAUTH_CLIENT_SECRET);
  return `https://app.netlify.com/claim#${token}`;
}

export function responseHeaders(contentType = 'application/json; charset=utf-8') {
  return {
    'Cache-Control': 'no-store',
    'Content-Type': contentType,
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
  };
}

export function jsonResponse(status, value) {
  return new Response(JSON.stringify(value), { status, headers: responseHeaders() });
}

export function emptyResponse(status) {
  return new Response(null, { status, headers: responseHeaders() });
}

function boundedNetlifyResponse(response, timer, timedOut) {
  const finish = () => clearTimeout(timer);
  let wrappedBody;
  const consume = (method) => async (...args) => {
    try {
      return await response[method](...args);
    } catch (error) {
      if (timedOut()) throw new Error('Netlify response exceeded the bounded timeout.', { cause: error });
      throw error;
    } finally {
      finish();
    }
  };
  return new Proxy(response, {
    get(target, property) {
      if (property === 'body' && target.body) {
        if (!wrappedBody) {
          const reader = target.body.getReader();
          wrappedBody = new ReadableStream({
            async pull(controller) {
              try {
                const { done, value } = await reader.read();
                if (done) { finish(); controller.close(); }
                else controller.enqueue(value);
              } catch (error) {
                finish();
                controller.error(timedOut() ? new Error('Netlify response exceeded the bounded timeout.', { cause: error }) : error);
              }
            },
            async cancel(reason) {
              finish();
              try { await reader.cancel(reason); } catch {}
            },
          });
        }
        return wrappedBody;
      }
      if (['arrayBuffer', 'json', 'text'].includes(property) && typeof target[property] === 'function') {
        return consume(property);
      }
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

export async function netlifyRequest(path, options, env, fetchImpl = fetch, timeoutMs = NETLIFY_REQUEST_TIMEOUT_MS) {
  env = requireResolvedHandoffEnvironment(env);
  const url = `https://api.netlify.com/api/v1${path}`;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > NETLIFY_REQUEST_TIMEOUT_MS) {
    throw new TypeError('Netlify request timeout is invalid.');
  }
  const controller = new AbortController();
  let didTimeOut = false;
  const timer = setTimeout(() => {
    didTimeOut = true;
    controller.abort();
  }, timeoutMs);
  try {
    const response = await fetchImpl(url, {
      ...options,
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${env.NETLIFY_ADMIN_PAT}`,
        ...(options.headers || {}),
      },
      redirect: 'error',
      signal: controller.signal,
    });
    if (!response.ok) {
      clearTimeout(timer);
      controller.abort();
      throw new Error(`Netlify request failed with status ${response.status}.`);
    }
    return boundedNetlifyResponse(response, timer, () => didTimeOut);
  } catch (error) {
    clearTimeout(timer);
    if (didTimeOut) throw new Error('Netlify request exceeded the bounded timeout.', { cause: error });
    throw error;
  }
}

export async function readNetlifyJsonBounded(response, maximumBytes, label = 'Netlify JSON response') {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 2 || maximumBytes > 2_000_000) {
    throw new TypeError('Netlify JSON response cap is invalid.');
  }
  const declared = response.headers?.get?.('content-length');
  if (declared && (!/^\d{1,9}$/.test(declared) || Number(declared) > maximumBytes)) {
    try { await response.body?.cancel?.(); } catch {}
    throw new Error(`${label} exceeds the bounded response size.`);
  }
  const reader = response.body?.getReader?.();
  if (!reader) throw new Error(`${label} requires a streaming response body.`);
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error(`${label} returned an invalid response chunk.`);
      total += value.byteLength;
      if (total > maximumBytes) {
        try { await reader.cancel(); } catch {}
        throw new Error(`${label} exceeds the bounded response size.`);
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally { try { reader.releaseLock(); } catch {} }
  try { return JSON.parse(Buffer.concat(chunks, total).toString('utf8')); } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

function netlifyJsonCap(path) {
  if (/\/files(?:\?|$)/.test(path)) return 2_000_000;
  if (/\/(?:forms|hooks|deploys)(?:\?|$)/.test(path)) return 1_000_000;
  return 256_000;
}

export async function createClaimableSite(record, env, fetchImpl = fetch, timeoutMs = NETLIFY_REQUEST_TIMEOUT_MS) {
  const response = await netlifyRequest('/sites', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      account_slug: env.NETLIFY_TEAM_SLUG,
      created_via: 'arc',
      name: record.netlify_site_name,
      session_id: record.netlify_session_id,
    }),
  }, env, fetchImpl, timeoutMs);
  const site = await readNetlifyJsonBounded(response, 256_000, 'Netlify site creation response');
  if (!site || !identifier(site.id, 'Netlify site id') || site.name !== record.netlify_site_name ||
      site.session_id !== record.netlify_session_id || site.account_id !== env.NETLIFY_TEAM_ACCOUNT_ID ||
      site.account_slug !== env.NETLIFY_TEAM_SLUG) {
    throw new Error('Netlify site response did not match the handoff intent.');
  }
  return site;
}

export function createStoredZip(artifacts) {
  if (!Array.isArray(artifacts) || artifacts.length < 2 || artifacts.length > 1 + MAX_ASSET_COUNT + HTML_PATHS.length) {
    throw new TypeError('ZIP artifact count is invalid.');
  }
  const paths = artifacts.map(artifact => artifact?.path);
  if (!artifactPathVectorValid(paths) && !legacyArtifactPathVectorValid(paths)) {
    throw new TypeError('ZIP artifact paths are invalid.');
  }
  const local = [];
  const central = [];
  let offset = 0;
  const crcTable = createCrcTable();
  for (const artifact of artifacts) {
    const name = Buffer.from(artifact.path);
    const data = Buffer.from(artifact.bytes);
    const crc = crc32(data, crcTable);
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0x0800, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(data.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(name.length, 26);
    local.push(localHeader, name, data);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(data.length, 20);
    centralHeader.writeUInt32LE(data.length, 24);
    centralHeader.writeUInt16LE(name.length, 28);
    centralHeader.writeUInt32LE(offset, 42);
    central.push(centralHeader, name);
    offset += localHeader.length + name.length + data.length;
  }
  const centralDirectory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(artifacts.length, 8);
  end.writeUInt16LE(artifacts.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, centralDirectory, end]);
}

function createCrcTable() {
  return Array.from({ length: 256 }, (_, value) => {
    let current = value;
    for (let bit = 0; bit < 8; bit += 1) current = current & 1 ? 0xedb88320 ^ (current >>> 1) : current >>> 1;
    return current >>> 0;
  });
}

function crc32(buffer, table) {
  let value = 0xffffffff;
  for (const byte of buffer) value = table[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

export async function deployZip(siteId, zip, title, env, fetchImpl = fetch, timeoutMs = NETLIFY_REQUEST_TIMEOUT_MS) {
  identifier(siteId, 'Netlify site id');
  const response = await netlifyRequest(`/sites/${encodeURIComponent(siteId)}/deploys?title=${encodeURIComponent(title)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/zip' },
    body: zip,
  }, env, fetchImpl, timeoutMs);
  const deploy = await readNetlifyJsonBounded(response, 256_000, 'Netlify deploy creation response');
  if (!deploy || !identifier(deploy.id, 'Netlify deploy id') || deploy.site_id !== siteId) throw new Error('Netlify deploy response did not match the site.');
  return deploy;
}

export async function pollDeployReady(siteId, deployId, env, fetchImpl = fetch, options = {}) {
  const attempts = options.attempts || MAX_DEPLOY_POLL_ATTEMPTS;
  const wait = options.wait || (() => Promise.resolve());
  const deadlineMs = options.deadlineMs ?? Number.POSITIVE_INFINITY;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const remainingMs = deadlineMs - Date.now();
    if (remainingMs <= 0) throw new Error('Netlify deploy polling exceeded the operation deadline.');
    const response = await netlifyRequest(
      `/deploys/${encodeURIComponent(deployId)}`,
      { method: 'GET' },
      env,
      fetchImpl,
      Math.min(NETLIFY_REQUEST_TIMEOUT_MS, Math.max(1, Math.floor(remainingMs))),
    );
    const deploy = await readNetlifyJsonBounded(response, 256_000, 'Netlify deploy polling response');
    if (!deploy || deploy.id !== deployId || deploy.site_id !== siteId) throw new Error('Netlify deploy identity changed while polling.');
    if (deploy.state === 'ready') return deploy;
    if (deploy.state === 'error' || deploy.error_message) throw new Error('Netlify deploy failed.');
    await wait(attempt);
  }
  throw new Error('Netlify deploy did not become ready before the bounded timeout.');
}

function deadlineTimeout(deadlineMs) {
  if (!Number.isFinite(deadlineMs)) return NETLIFY_REQUEST_TIMEOUT_MS;
  const remainingMs = Math.floor(deadlineMs - Date.now());
  if (remainingMs <= 0) throw new Error('Netlify operation deadline exceeded.');
  return Math.min(NETLIFY_REQUEST_TIMEOUT_MS, remainingMs);
}

export async function createEmailHook(siteId, formId, email, env, fetchImpl = fetch, timeoutMs = NETLIFY_REQUEST_TIMEOUT_MS) {
  const body = { site_id: siteId, form_id: formId, type: 'email', event: 'submission_created', data: { email } };
  const response = await netlifyRequest(`/hooks?site_id=${encodeURIComponent(siteId)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, env, fetchImpl, timeoutMs);
  const hook = await readNetlifyJsonBounded(response, 256_000, 'Netlify hook creation response');
  if (!hook || !identifier(hook.id, 'Netlify hook id') || hook.site_id !== siteId || hook.type !== 'email' ||
      hook.event !== 'submission_created' || hook.disabled === true || hook.data?.email !== email) {
    throw new Error('Netlify hook response did not match the requested recipient.');
  }
  return hook;
}

async function netlifyJson(path, env, fetchImpl, deadlineMs = Number.POSITIVE_INFINITY) {
  const response = await netlifyRequest(path, { method: 'GET' }, env, fetchImpl, deadlineTimeout(deadlineMs));
  return readNetlifyJsonBounded(response, netlifyJsonCap(path), `Netlify ${path} response`);
}

export async function findNetlifyForm(siteId, formName, env, fetchImpl = fetch, options = {}) {
  identifier(siteId, 'Netlify site id');
  validateFormName(formName);
  const attempts = options.attempts || 8;
  const wait = options.wait || (() => Promise.resolve());
  const deadlineMs = options.deadlineMs ?? Number.POSITIVE_INFINITY;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const remainingMs = deadlineMs - Date.now();
    if (remainingMs <= 0) throw new Error('Netlify form polling exceeded the operation deadline.');
    const response = await netlifyRequest(
      `/sites/${encodeURIComponent(siteId)}/forms`,
      { method: 'GET' },
      env,
      fetchImpl,
      Math.min(NETLIFY_REQUEST_TIMEOUT_MS, Math.max(1, Math.floor(remainingMs))),
    );
    const forms = await readNetlifyJsonBounded(response, 1_000_000, 'Netlify form listing response');
    const matches = (Array.isArray(forms) ? forms : []).filter((form) => form.site_id === siteId && form.name === formName);
    if (matches.length > 1) throw new Error('Netlify returned duplicate matching forms.');
    if (matches.length === 1) {
      identifier(matches[0].id, 'Netlify form id');
      return matches[0];
    }
    await wait(attempt);
  }
  throw new Error('Netlify did not register the signed lead form before the bounded timeout.');
}

export async function ensureEmailHook(siteId, formId, email, env, fetchImpl = fetch, options = {}) {
  const deadlineMs = options.deadlineMs ?? Number.POSITIVE_INFINITY;
  const hooks = await netlifyJson(`/hooks?site_id=${encodeURIComponent(siteId)}`, env, fetchImpl, deadlineMs);
  const forForm = (Array.isArray(hooks) ? hooks : []).filter((hook) => hook.site_id === siteId && hook.form_id === formId &&
    hook.type === 'email' && hook.event === 'submission_created' && hook.disabled !== true);
  if (forForm.some((hook) => String(hook.data?.email || '').trim().toLowerCase() !== email)) {
    throw new Error('A conflicting Netlify email hook already exists for the lead form.');
  }
  if (forForm.length > 1) throw new Error('Duplicate Netlify email hooks exist for the lead form.');
  if (forForm.length === 1) {
    identifier(forForm[0].id, 'Netlify hook id');
    return forForm[0];
  }
  if (typeof options.beforeMutation === 'function') await options.beforeMutation();
  const timeoutMs = deadlineTimeout(deadlineMs);
  const mutationFetch = (...args) => {
    if (typeof options.onMutationFetch === 'function') options.onMutationFetch();
    return fetchImpl(...args);
  };
  const hook = await createEmailHook(siteId, formId, email, env, mutationFetch, timeoutMs);
  if (hook.form_id !== formId) throw new Error('Netlify hook response did not bind the expected form.');
  return hook;
}

export async function downloadVerifiedArtifacts(siteId, artifacts, env, fetchImpl = fetch, options = {}) {
  const deadlineMs = options.deadlineMs ?? Number.POSITIVE_INFINITY;
  const output = [];
  for (const artifact of artifacts) {
    const raw = await netlifyRequest(`/sites/${encodeURIComponent(siteId)}/files/${artifact.path}`, {
      method: 'GET',
      headers: {
        Accept: 'application/vnd.bitballoon.v1.raw',
        'Content-Type': 'application/vnd.bitballoon.v1.raw',
      },
    }, env, fetchImpl, deadlineTimeout(deadlineMs));
    const bytes = await readResponseBytesBounded(raw, artifact.size);
    if (bytes.length !== artifact.size || sha256Hex(bytes) !== artifact.sha256) throw new Error('Netlify raw source bytes mismatch.');
    output.push({ path: artifact.path, bytes });
  }
  return output;
}

async function readResponseBytesBounded(response, maximumBytes) {
  const declared = response.headers?.get?.('content-length');
  if (declared && (!/^\d{1,9}$/.test(declared) || Number(declared) > maximumBytes)) throw new Error('Response body exceeds signed artifact size.');
  const reader = response.body?.getReader?.();
  if (!reader) throw new Error('Streaming response body is required.');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error('Response body chunk is invalid.');
      total += value.byteLength;
      if (total > maximumBytes) {
        try { await reader.cancel(); } catch {}
        throw new Error('Response body exceeds signed artifact size.');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally { try { reader.releaseLock(); } catch {} }
  return Buffer.concat(chunks, total);
}

export async function verifyNetlifyHandoff(record, expected, env, fetchImpl = fetch, options = {}) {
  const deadlineMs = options.deadlineMs ?? Number.POSITIVE_INFINITY;
  const site = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl, deadlineMs);
  const account = await netlifyJson(`/accounts/${encodeURIComponent(expected.accountId)}`, env, fetchImpl, deadlineMs);
  const deployId = expected.deployId;
  const deploy = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}/deploys/${encodeURIComponent(deployId)}`, env, fetchImpl, deadlineMs);
  if (site.id !== record.netlify_site_id || site.name !== record.netlify_site_name || site.session_id !== record.netlify_session_id || account.id !== expected.accountId ||
      site.account_id !== expected.accountId || deploy.id !== deployId || deploy.site_id !== record.netlify_site_id ||
      deploy.state !== 'ready' || site.published_deploy?.id !== deployId) {
    throw new Error('Netlify site, account, session, or deploy binding failed.');
  }
  const files = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}/files`, env, fetchImpl, deadlineMs);
  if (!Array.isArray(files) || files.length !== expected.artifacts.length) throw new Error('Netlify deploy file count mismatch.');
  for (const artifact of expected.artifacts) {
    const file = files.find((item) => item.path === `/${artifact.path}`);
    if (!file || Number(file.size) !== artifact.size) throw new Error('Netlify deploy file metadata mismatch.');
  }
  const artifactBytes = await downloadVerifiedArtifacts(record.netlify_site_id, expected.artifacts, env, fetchImpl, { deadlineMs });
  const legacyV3 = legacyArtifactPathVectorValid(expected.artifacts.map(artifact => artifact?.path));
  const sourcePages = legacyV3
    ? [artifactBytes.find(item => item.path === 'index.html')]
    : htmlArtifacts(artifactBytes);
  const expectedLivePages = sourcePages.map(page => ({
    path: page.path,
    bytes: legacyV3
      ? expectedLegacyNetlifyLiveHtml(page.bytes, record.lead_route_mode)
      : expectedNetlifyLiveHtml(page.bytes, record.lead_route_mode, page.path),
  }));
  const expectedCsp = signedCspHeader(artifactBytes);
  let matchingForm = null;
  let matchingHook = null;
  if (record.lead_route_mode === 'netlify_form') {
    const forms = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}/forms`, env, fetchImpl, deadlineMs);
    const matchingForms = (Array.isArray(forms) ? forms : []).filter((form) => form.id === expected.formId && form.site_id === record.netlify_site_id && form.name === expected.formName);
    if (matchingForms.length !== 1) throw new Error('Netlify form binding failed.');
    const hooks = await netlifyJson(`/hooks?site_id=${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl, deadlineMs);
    const matchingHooks = (Array.isArray(hooks) ? hooks : []).filter((hook) => hook.id === expected.hookId && hook.site_id === record.netlify_site_id &&
      hook.form_id === expected.formId && hook.type === 'email' && hook.event === 'submission_created' && hook.disabled !== true &&
      sha256Hex(String(hook.data?.email || '').trim().toLowerCase()) === expected.leadEmailSha256);
    if (matchingHooks.length !== 1) throw new Error('Netlify hook binding failed.');
    [matchingForm] = matchingForms;
    [matchingHook] = matchingHooks;
  } else if (expected.formId !== null || expected.formName !== '' || expected.hookId !== null || expected.leadEmailSha256 !== sha256Hex('')) {
    throw new Error('No-form Netlify handoff has unexpected lead-route bindings.');
  }
  const productionUrl = canonicalNetlifySiteUrl(record.netlify_site_name);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), deadlineTimeout(deadlineMs));
  let publicPages;
  try {
    publicPages = await Promise.all(expectedLivePages.map(async (page) => {
      const route = page.path === 'index.html' ? '' : page.path.slice(0, -'index.html'.length);
      const pageUrl = new URL(route, productionUrl).toString();
      const response = await fetchImpl(pageUrl, { method: 'GET', redirect: 'error', signal: controller.signal });
      const robots = (response.headers.get('x-robots-tag') || '').trim().toLowerCase();
      const phase = expected.phase || 'preclaim';
      if (!response.ok || (phase === 'preclaim'
        ? robots !== 'noindex, nofollow, noarchive'
        : robots !== '')) throw new Error('Published handoff indexing policy mismatch.');
      if (response.url && response.url !== pageUrl) throw new Error('Published handoff redirected unexpectedly.');
      if ((response.headers.get('content-security-policy') || '').trim() !== expectedCsp) {
        throw new Error('Published handoff content security policy mismatch.');
      }
      if ((response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'text/html') {
        throw new Error('Published production HTML content type mismatch.');
      }
      const bytes = await readResponseBytesBounded(response, page.bytes.length);
      if (!bytes.equals(page.bytes)) throw new Error('Published production HTML bytes mismatch.');
      return { path: page.path, bytes };
    }));
  } finally {
    controller.abort();
    clearTimeout(timer);
  }
  if (legacyV3) validateLegacyProductionAssetReferences(publicPages[0].bytes, expected.artifacts);
  else validateProductionAssetReferences(publicPages, expected.artifacts);
  for (const artifact of expected.artifacts.filter(item => ASSET_PATH_PATTERN.test(item.path))) {
    const assetUrl = new URL(artifact.path, productionUrl).toString();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), deadlineTimeout(deadlineMs));
    let response;
    try {
      response = await fetchImpl(assetUrl, { method: 'GET', redirect: 'error', signal: controller.signal });
      if (!response.ok || (response.url && response.url !== assetUrl) ||
          (response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== imageTypeForPath(artifact.path)) {
        throw new Error('Published production asset response mismatch.');
      }
      const bytes = await readResponseBytesBounded(response, artifact.size);
      if (bytes.length !== artifact.size || sha256Hex(bytes) !== artifact.sha256) throw new Error('Published production asset bytes mismatch.');
      validateImageAsset(bytes, imageTypeForPath(artifact.path));
    } finally { clearTimeout(timer); }
  }
  return { site, account, deploy, form: matchingForm, hook: matchingHook, artifactBytes, productionUrl };
}

export function normalizeProductionUrl(value) {
  const url = new URL(stringValue(value, 'Netlify production URL', 12, 512));
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new TypeError('Netlify production URL must be a plain HTTPS root.');
  }
  return url.toString();
}

export function canonicalNetlifySiteUrl(siteName) {
  const value = stringValue(siteName, 'Netlify site name', 5, 63);
  if (!STORED_SITE_NAME_PATTERN.test(value)) throw new TypeError('Netlify site name is invalid.');
  return `https://${value}.netlify.app/`;
}

export function normalizeClaimWebhook(input) {
  plainObject(input, 'Claim webhook');
  exactKeys(input, ['claimed', 'destination_acc_id', 'site_id'], 'Claim webhook');
  if (input.claimed !== true) throw new TypeError('Claim webhook must report claimed=true.');
  return { siteId: identifier(input.site_id, 'Claim site id'), destinationAccountId: identifier(input.destination_acc_id, 'Destination account id') };
}

export function handoffIdFromKey(key) {
  const match = String(key).match(/^handoffs\/([a-f0-9]{64})$/);
  if (!match) throw new TypeError('Handoff key is invalid.');
  return match[1];
}

export function handoffKeyFromId(value) {
  return `handoffs/${hex64(value, 'Handoff id')}`;
}

export function siteIndexKey(siteId) {
  identifier(siteId, 'Netlify site id');
  return `site-index/${sha256Hex(siteId)}`;
}

export function createOutboxClaim(record, env) {
  if (record.state !== 'CLAIMED_VERIFIED') throw new TypeError('Outbox can only be claimed after ownership verification.');
  const canonical = canonicalJson({
    version: OUTBOX_CLAIM_VERSION,
    netlify_session_id: record.netlify_session_id,
    payment_evidence_sha256: record.payment_evidence_sha256,
    handoff_artifact_evidence_sha256: record.artifact_evidence_sha256,
    recipient_email_sha256: record.customer_email_sha256,
    production_url: normalizeProductionUrl(record.production_url),
  });
  const digest = hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET, canonical);
  return {
    key: `outbox/${digest}`,
    digest,
    value: {
      schema: OUTBOX_CLAIM_VERSION,
      status: 'CLAIMED',
      handoff_id: record.handoff_id,
      netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
      netlify_deploy_id_sha256: sha256Hex(record.final_deploy_id),
      outbox_claim_key_hmac_sha256: digest,
    },
  };
}

export function createClaimStateEvidence(record, env, authorizedAt = new Date()) {
  if (record.state !== 'FINAL_DEPLOY_READY' || record.outbox_claim_status !== 'CLAIMED') {
    throw new TypeError('Claim-state evidence is unavailable before final deploy and outbox claim.');
  }
  const providerObservedAt = new Date(authorizedAt).toISOString();
  if (Date.parse(providerObservedAt) < Date.parse(record.final_deploy_ready_at)) {
    throw new TypeError('Final delivery authorization predates the final deploy.');
  }
  const authorizationBinding = {
    bundle_fingerprint: record.bundle_fingerprint,
    netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
    netlify_deploy_id_sha256: sha256Hex(record.final_deploy_id),
    netlify_destination_account_id_sha256: sha256Hex(record.destination_account_id),
    outbox_claim_key_hmac_sha256: hex64(record.outbox_claim_key_hmac_sha256, 'Outbox claim key HMAC'),
    provider_observed_at: providerObservedAt,
  };
  const value = {
    version: CLAIM_STATE_EVIDENCE_VERSION,
    scope: CLAIM_STATE_EVIDENCE_SCOPE,
    status: 'FINAL_DEPLOY_READY',
    netlify_session_id: record.netlify_session_id,
    preview_folder: record.preview_folder,
    payment_evidence_sha256: record.payment_evidence_sha256,
    handoff_artifact_evidence_sha256: record.artifact_evidence_sha256,
    bundle_fingerprint: record.bundle_fingerprint,
    customer_email_sha256: record.customer_email_sha256,
    netlify_site_id_sha256: authorizationBinding.netlify_site_id_sha256,
    netlify_deploy_id_sha256: authorizationBinding.netlify_deploy_id_sha256,
    netlify_destination_account_id_sha256: authorizationBinding.netlify_destination_account_id_sha256,
    production_url: normalizeProductionUrl(record.production_url),
    claim_invitation_ready_at: isoTimestamp(record.claim_invitation_ready_at, 'Claim invitation ready timestamp'),
    claim_callback_received_at: isoTimestamp(record.claim_callback_received_at, 'Claim callback timestamp'),
    claimed_verified_at: isoTimestamp(record.claimed_verified_at, 'Claim verification timestamp'),
    final_deploy_ready_at: isoTimestamp(record.final_deploy_ready_at, 'Final deploy timestamp'),
    outbox_claim_status: 'CLAIMED',
    outbox_claim_key_hmac_sha256: authorizationBinding.outbox_claim_key_hmac_sha256,
    provider_observed_at: providerObservedAt,
    authorization_nonce_sha256: hmacHex(env.ARC_CLAIM_STATE_EVIDENCE_SECRET,
      `${FINAL_DELIVERY_AUTHORIZATION_PREFIX}${canonicalJson(authorizationBinding)}`),
    issued_at: providerObservedAt,
  };
  const orderedTimes = [value.claim_invitation_ready_at, value.claim_callback_received_at, value.claimed_verified_at,
    value.final_deploy_ready_at, value.provider_observed_at, value.issued_at]
    .map((timestamp) => Date.parse(timestamp));
  if (orderedTimes.some((timestamp, index) => index > 0 && timestamp < orderedTimes[index - 1])) {
    throw new TypeError('Claim-state timestamps are out of order.');
  }
  const canonical = canonicalJson(value);
  return {
    claim_state_evidence_private: canonical,
    claim_state_evidence_hmac_sha256: hmacHex(env.ARC_CLAIM_STATE_EVIDENCE_SECRET, `${CLAIM_STATE_SIGNATURE_PREFIX}${canonical}`),
  };
}

const LEGACY_HANDOFF_DEFAULTS = Object.freeze({
  claim_invitation_generation: 0,
  lead_route_mode: 'netlify_form',
  lead_route_recipient_hmac_sha256: null,
  lead_route_migration: null,
  final_delivery_receipt_sha256: null,
  final_delivery_provider: null,
  final_delivery_provider_account_hmac_sha256: null,
  final_delivery_provider_event_id_hmac_sha256: null,
  final_delivery_provider_message_id_hmac_sha256: null,
  final_delivery_event_type: null,
  final_delivery_status: null,
  final_delivery_receipt_issued_at: null,
});

export function normalizeStoredHandoffRecord(value) {
  const record = plainObject(value, 'Stored handoff record');
  if (record.schema === HANDOFF_SCHEMA) {
    const withGeneration = Object.hasOwn(record, 'claim_invitation_generation')
      ? record
      : { ...record, claim_invitation_generation: 0 };
    // Rows created before lead-route mode became a signed artifact field can be
    // identified only when their existing form bindings are internally exact.
    // Never infer no-form from missing fields: ambiguous rows fail closed.
    if (!Object.hasOwn(withGeneration, 'lead_route_mode') || withGeneration.lead_route_mode === undefined) {
      if (validateFormName(withGeneration.form_name) !== withGeneration.form_name ||
          !HEX_64_PATTERN.test(withGeneration.lead_route_recipient_hmac_sha256 || '')) {
        throw new TypeError('Stored handoff lead route mode is missing and cannot be inferred safely.');
      }
      return { ...withGeneration, lead_route_mode: 'netlify_form' };
    }
    return withGeneration;
  }
  if (record.schema !== LEGACY_HANDOFF_SCHEMA) throw new TypeError('Stored handoff record schema is invalid.');
  if (record.state === 'DELIVERED' && (!record.final_delivery_receipt_sha256 || !record.final_delivery_receipt_issued_at)) {
    throw new TypeError('Legacy delivered handoff lacks authoritative delivery evidence.');
  }
  return {
    ...LEGACY_HANDOFF_DEFAULTS,
    ...record,
    schema: HANDOFF_SCHEMA,
    // v1 was form-only. Preserve that historical fact explicitly, but never
    // infer it for an already-v2 row. The service quarantines this marker
    // before invitation; downstream v1 rows may finish without rewriting the
    // customer site namespace or fabricating a recipient binding.
    lead_route_migration: record.lead_route_recipient_hmac_sha256
      ? null
      : 'legacy_v1_form_recipient_unbound',
  };
}

export function validateExpectedBindings(value) {
  const record = normalizeStoredHandoffRecord(value);
  if (record.schema !== HANDOFF_SCHEMA || !HANDOFF_STATES.includes(record.state) || !Number.isSafeInteger(record.revision) || record.revision < 1 ||
      !UUID_PATTERN.test(record.netlify_session_id) || !STORED_SITE_NAME_PATTERN.test(record.netlify_site_name)) {
    throw new TypeError('Stored handoff record is invalid.');
  }
  const legacyUnboundFormRoute = record.lead_route_migration === 'legacy_v1_form_recipient_unbound' &&
    /^arc-[a-f0-9]{24}$/.test(record.netlify_site_name) && record.lead_route_mode === 'netlify_form' &&
    record.lead_route_recipient_hmac_sha256 === null;
  if (record.lead_route_migration !== null && record.lead_route_migration !== undefined && !legacyUnboundFormRoute) {
    throw new TypeError('Stored handoff lead route migration marker is invalid.');
  }
  for (const field of ['payment_evidence_sha256', 'artifact_evidence_sha256', 'artifact_manifest_sha256', 'bundle_fingerprint', 'production_content_sha256', 'customer_email_sha256', 'lead_notification_email_sha256']) {
    hex64(record[field], field);
  }
  if (record.lead_route_recipient_hmac_sha256 !== null && record.lead_route_recipient_hmac_sha256 !== '') {
    hex64(record.lead_route_recipient_hmac_sha256, 'lead_route_recipient_hmac_sha256');
  }
  if (record.claim_token_hmac_sha256 !== null) hex64(record.claim_token_hmac_sha256, 'claim_token_hmac_sha256');
  if (record.claim_token_consumed_hmac_sha256 !== null) hex64(record.claim_token_consumed_hmac_sha256, 'claim_token_consumed_hmac_sha256');
  if (record.lead_route_receipt_sha256 !== null) hex64(record.lead_route_receipt_sha256, 'lead_route_receipt_sha256');
  for (const field of ['preclaim_deploy_attempted_at', 'final_deploy_attempted_at', 'email_hook_attempted_at']) {
    if (record[field] !== null) isoTimestamp(record[field], field);
  }
  for (const field of ['preclaim_deploy_candidate_id', 'final_deploy_candidate_id']) {
    if (record[field] !== null) identifier(record[field], field);
  }
  if (record.preclaim_deploy_candidate_id !== null && record.preclaim_deploy_attempted_at === null) throw new TypeError('Preclaim deploy candidate lacks an attempt intent.');
  if (record.final_deploy_candidate_id !== null && record.final_deploy_attempted_at === null) throw new TypeError('Final deploy candidate lacks an attempt intent.');
  if (record.claim_invitation_ready_at === null) {
    if (record.claim_invitation_generation !== 0 || record.claim_token_hmac_sha256 !== null || record.claim_token_expires_at !== null || record.claim_token_used_at !== null ||
        record.claim_token_consumed_hmac_sha256 !== null || record.claim_wrapper_consumed_at !== null ||
        record.lead_route_provider_message_id_sha256 !== null || record.lead_route_receipt_sha256 !== null ||
        ['INVITATION_READY', 'CLAIM_WRAPPER_CONSUMED', 'CLAIM_CALLBACK_RECEIVED', 'CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED'].includes(record.state)) {
      throw new TypeError('Unissued claim token fields must be null.');
    }
  } else {
    if (!Number.isSafeInteger(record.claim_invitation_generation) || record.claim_invitation_generation < 0 || record.claim_invitation_generation > 1_000_000) {
      throw new TypeError('Claim invitation generation is invalid.');
    }
    hex64(record.lead_route_provider_message_id_sha256, 'lead_route_provider_message_id_sha256');
    const readyAt = Date.parse(isoTimestamp(record.claim_invitation_ready_at, 'claim_invitation_ready_at'));
    const expiresAt = Date.parse(isoTimestamp(record.claim_token_expires_at, 'claim_token_expires_at'));
    if (expiresAt <= readyAt || expiresAt - readyAt > CLAIM_TOKEN_TTL_SECONDS * 1000) {
      throw new TypeError('Claim token expiry ordering is invalid.');
    }
    if (record.lead_route_receipt_sha256 === null) throw new TypeError('Issued claim token lacks lead-route evidence.');
    if (record.state === 'INVITATION_READY' && (record.claim_token_hmac_sha256 === null || record.claim_token_consumed_hmac_sha256 !== null ||
        record.claim_token_used_at !== null || record.claim_wrapper_consumed_at !== null)) {
      throw new TypeError('Issued claim token fields are invalid.');
    }
    if (['CLAIM_WRAPPER_CONSUMED', 'CLAIM_CALLBACK_RECEIVED', 'CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED'].includes(record.state) &&
        (record.claim_token_hmac_sha256 !== null || record.claim_token_consumed_hmac_sha256 === null || !record.claim_token_used_at || !record.claim_wrapper_consumed_at)) {
      throw new TypeError('Consumed claim token fields are invalid.');
    }
  }
  if (!PREVIEW_FOLDER_PATTERN.test(record.preview_folder) || !Array.isArray(record.artifacts) ||
      (!artifactPathVectorValid(record.artifacts.map(artifact => artifact?.path)) &&
        !legacyArtifactPathVectorValid(record.artifacts.map(artifact => artifact?.path))) ||
      !['netlify_form', 'not_required'].includes(record.lead_route_mode) ||
      (record.lead_route_mode === 'netlify_form'
        ? (validateFormName(record.form_name) !== record.form_name ||
          (!HEX_64_PATTERN.test(record.lead_route_recipient_hmac_sha256 || '') && !legacyUnboundFormRoute))
        : (record.form_name !== '' || record.lead_route_recipient_hmac_sha256 !== ''))) {
    throw new TypeError('Stored artifact bindings are invalid.');
  }
  const stateRank = HANDOFF_STATES.indexOf(record.state);
  const atLeast = (state) => stateRank >= HANDOFF_STATES.indexOf(state);
  const requireIdentifier = (field, required) => {
    if (required) identifier(record[field], field);
    else if (record[field] !== null) throw new TypeError(`${field} must be null before its state transition.`);
  };
  const requireTimestamp = (field, required) => {
    if (required) isoTimestamp(record[field], field);
    else if (record[field] !== null) throw new TypeError(`${field} must be null before its state transition.`);
  };
  requireIdentifier('netlify_source_account_id', true);
  requireIdentifier('netlify_site_id', atLeast('SITE_CREATED'));
  requireTimestamp('site_created_at', atLeast('SITE_CREATED'));
  requireIdentifier('preclaim_deploy_id', atLeast('PRECLAIM_DEPLOY_READY'));
  for (const field of ['form_id', 'hook_id']) {
    if (record.lead_route_mode === 'netlify_form') {
      if (atLeast('INVITATION_READY') || record[field] !== null) identifier(record[field], field);
    } else if (record[field] !== null) throw new TypeError(`${field} must be null for a no-form handoff.`);
  }
  requireIdentifier('destination_account_id', atLeast('CLAIM_CALLBACK_RECEIVED'));
  requireTimestamp('claim_callback_received_at', atLeast('CLAIM_CALLBACK_RECEIVED'));
  requireTimestamp('claimed_verified_at', atLeast('CLAIMED_VERIFIED'));
  requireIdentifier('final_deploy_id', atLeast('FINAL_DEPLOY_READY'));
  requireTimestamp('final_deploy_ready_at', atLeast('FINAL_DEPLOY_READY'));
  requireTimestamp('delivered_at', record.state === 'DELIVERED');
  if (atLeast('CLAIM_CALLBACK_RECEIVED')) normalizeProductionUrl(record.production_url);
  else if (record.production_url !== null) throw new TypeError('production_url must be null before verified claim readback.');
  if (atLeast('CLAIM_WRAPPER_CONSUMED')) {
    if (!Number.isSafeInteger(record.claim_jwt_issued_at) || record.claim_jwt_issued_at < 1 ||
        record.claim_jwt_issued_at * 1000 < Date.parse(record.claim_invitation_ready_at) ||
        record.claim_jwt_issued_at * 1000 > Date.parse(record.claim_token_expires_at)) {
      throw new TypeError('claim_jwt_issued_at is invalid or out of order.');
    }
  } else if (record.claim_jwt_issued_at !== null) throw new TypeError('claim_jwt_issued_at must be null before claim exchange.');
  if (atLeast('FINAL_DEPLOY_READY')) {
    if (record.outbox_claim_status !== 'CLAIMED') throw new TypeError('Final deploy lacks a claimed delivery outbox.');
    hex64(record.outbox_claim_key_hmac_sha256, 'outbox_claim_key_hmac_sha256');
    if (record.final_deploy_candidate_id !== record.final_deploy_id) throw new TypeError('Final deploy candidate and verified deploy differ.');
  } else if (record.outbox_claim_status !== null || record.outbox_claim_key_hmac_sha256 !== null) {
    throw new TypeError('Delivery outbox must be null before final deploy verification.');
  }
  if (record.state === 'DELIVERED') {
    hex64(record.final_delivery_receipt_sha256, 'final_delivery_receipt_sha256');
    if (typeof record.final_delivery_provider !== 'string' || !/^[a-z0-9][a-z0-9_.-]{1,63}$/.test(record.final_delivery_provider)) {
      throw new TypeError('final_delivery_provider is invalid.');
    }
    hex64(record.final_delivery_provider_account_hmac_sha256, 'final_delivery_provider_account_hmac_sha256');
    hex64(record.final_delivery_provider_event_id_hmac_sha256, 'final_delivery_provider_event_id_hmac_sha256');
    hex64(record.final_delivery_provider_message_id_hmac_sha256, 'final_delivery_provider_message_id_hmac_sha256');
    if (record.final_delivery_event_type !== 'message.delivered' || record.final_delivery_status !== 'delivered') {
      throw new TypeError('Final delivery event type or status is invalid.');
    }
    const deliveredAt = Date.parse(record.delivered_at);
    const receiptIssuedAt = Date.parse(isoTimestamp(record.final_delivery_receipt_issued_at, 'final_delivery_receipt_issued_at'));
    if (receiptIssuedAt < deliveredAt) throw new TypeError('Final delivery receipt timestamps are out of order.');
  } else if (record.final_delivery_receipt_sha256 !== null || record.final_delivery_provider !== null ||
      record.final_delivery_provider_account_hmac_sha256 !== null || record.final_delivery_provider_event_id_hmac_sha256 !== null ||
      record.final_delivery_provider_message_id_hmac_sha256 !== null || record.final_delivery_event_type !== null ||
      record.final_delivery_status !== null || record.final_delivery_receipt_issued_at !== null) {
    throw new TypeError('Final delivery receipt must be null before provider acknowledgement.');
  }
  const orderedTimestamps = [
    record.created_at,
    record.site_created_at,
    record.claim_invitation_ready_at,
    record.claim_token_used_at,
    record.claim_callback_received_at,
    record.claimed_verified_at,
    record.final_deploy_ready_at,
    record.delivered_at,
    record.final_delivery_receipt_issued_at,
  ].filter(Boolean).map((value) => Date.parse(isoTimestamp(value, 'state timestamp')));
  if (orderedTimestamps.some((value, index) => index > 0 && value < orderedTimestamps[index - 1])) {
    throw new TypeError('Stored handoff timestamps are out of order.');
  }
  return record;
}

export function validateFormName(value) {
  if (typeof value !== 'string' || !SAFE_FORM_NAME_PATTERN.test(value)) throw new TypeError('Form name is invalid.');
  return value;
}
