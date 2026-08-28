import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';

import { ACTIVATION_BUILD_IDENTITY } from './activation-build-identity.mjs';
import {
  ACTIVATION_MANIFEST_ENV,
  ACTIVATION_MANIFEST_SECRET_ENV,
  ACTIVATION_NEXT_MANIFEST_ENV,
  validateActivationManifest,
} from './activation-manifest-core.mjs';
import REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT from
  '../../operations/review-activation-environment.json' with { type: 'json' };

export const REVIEW_ACTIVATION_RUNTIME_READBACK_STORE =
  'arc-review-activation-runtime-readback-v1';
export const REVIEW_ACTIVATION_RUNTIME_READBACK_SCHEMA =
  'arc-review-activation-runtime-readback-envelope-v1';
export const REVIEW_ACTIVATION_RUNTIME_READBACK_VERSION = 1;
export const REVIEW_ACTIVATION_RUNTIME_READBACK_MAXIMUM_AGE_MS = 15 * 60_000;
export const REVIEW_ACTIVATION_RUNTIME_READBACK_MAXIMUM_BYTES = 32_768;

const ENABLED_ENV = 'ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED';
const VERIFIER_URL_ENV = 'ARC_REVIEW_ACTIVATION_VERIFIER_URL';
const VERIFIER_PUBLIC_KEY_ENV = 'ARC_REVIEW_ACTIVATION_VERIFIER_ED25519_PUBLIC_KEY';
const DEPLOYMENT_SHA = /^[a-f0-9]{40}$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const PRICE_ID = /^price_[A-Za-z0-9_]{6,128}$/;
const PRODUCT_ID = /^prod_[A-Za-z0-9_]{6,128}$/;
const INTEGRATION_ID = /^arc_review_checkout_[a-z]{8}$/;
const PROVIDER = /^[a-z0-9][a-z0-9_.-]{1,63}$/;
const SIGNATURE_DOMAIN = `${REVIEW_ACTIVATION_RUNTIME_READBACK_SCHEMA}\n`;

// These are derived from the reviewed JSON bundled into the exact Function
// deployment. Runtime environment values cannot change either digest.
export const REVIEW_ACTIVATION_ROUTE_MATRIX_SHA256 =
  sha256(canonicalReviewActivationRuntimeJson(REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.routes));
export const REVIEW_ACTIVATION_STRIPE_WEBHOOK_EVENT_SET_SHA256 =
  sha256(canonicalReviewActivationRuntimeJson(
    [...REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.stripe_webhook.events].sort(),
  ));

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
const REQUIRED_RECEIPT_PATHS = Object.freeze([
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
]);
const ENVELOPE_FIELDS = Object.freeze([
  'schema', 'version', 'authority_sha256', 'key_sha256', 'receipt', 'signature',
]);

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, keys) {
  return plainObject(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

export function canonicalReviewActivationRuntimeJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalReviewActivationRuntimeJson).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalReviewActivationRuntimeJson(value[key])}`).join(',')}}`;
  }
  const output = JSON.stringify(value);
  if (output === undefined) throw new TypeError('Canonical JSON does not support undefined.');
  return output;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function nonzeroSha256(value) {
  return typeof value === 'string' && HEX_64.test(value) && value !== '0'.repeat(64);
}

function valueAtPath(value, path) {
  return path.split('.').reduce((current, key) => current?.[key], value);
}

function canonicalVerifierUrl(value) {
  if (typeof value !== 'string' || value.length > 2_048) return null;
  let url;
  try { url = new URL(value); } catch { return null; }
  if (url.href !== value || url.protocol !== 'https:' || url.username || url.password ||
      url.hash || url.search || url.port || !url.hostname.includes('.')) return null;
  return url.href;
}

function ed25519PublicKey(value) {
  if (typeof value !== 'string' || value.length < 40 || value.length > 256) return null;
  let der;
  try { der = Buffer.from(value, 'base64'); } catch { return null; }
  if (der.length === 0 || der.toString('base64') !== value) return null;
  try {
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    const canonical = key.export({ format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519' || !canonical.equals(der)) return null;
    return Object.freeze({ der, key, sha256: sha256(der) });
  } catch {
    return null;
  }
}

function expectedBindings(env) {
  return Object.freeze({
    email_native_suppression_id_sha256:
      String(env.ARC_REVIEW_EMAIL_NATIVE_SUPPRESSION_ID_SHA256 || ''),
    email_native_webhook_id_sha256:
      String(env.ARC_REVIEW_EMAIL_NATIVE_WEBHOOK_ID_SHA256 || ''),
    email_provider: String(env.ARC_REVIEW_EMAIL_PROVIDER || ''),
    email_provider_account_id_sha256:
      String(env.ARC_REVIEW_EMAIL_PROVIDER_ACCOUNT_ID_SHA256 || ''),
    email_sender_identity_sha256:
      String(env.ARC_REVIEW_EMAIL_SENDER_IDENTITY_SHA256 || ''),
    netlify_site_id_sha256: sha256(String(env.ARC_EXPECTED_NETLIFY_SITE_ID || '')),
    netlify_handoff_credential_environment_name: selectedNetlifyCredentialName(env) || '',
    stripe_account_id_sha256: String(env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 || ''),
    stripe_integration_identifier_sha256:
      sha256(String(env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER || '')),
    stripe_price_id_sha256: sha256(String(env.ARC_EXPECTED_PRICE_ID || '')),
    stripe_product_id_sha256: sha256(String(env.ARC_EXPECTED_PRODUCT_ID || '')),
    zapier_checkout_revocation_workflow_id_sha256:
      String(env.ARC_ZAPIER_REVIEW_CHECKOUT_REVOCATION_WORKFLOW_ID_SHA256 || ''),
    zapier_email_workflow_id_sha256:
      String(env.ARC_ZAPIER_REVIEW_EMAIL_WORKFLOW_ID_SHA256 || ''),
    zapier_payment_arc2_workflow_id_sha256:
      String(env.ARC_ZAPIER_PAYMENT_ARC2_WORKFLOW_ID_SHA256 || ''),
    zapier_revision_workflow_id_sha256:
      String(env.ARC_ZAPIER_REVIEW_REVISION_WORKFLOW_ID_SHA256 || ''),
  });
}

function bindingsComplete(bindings) {
  return bindings.email_provider.length >= 2 &&
    ['NETLIFY_ADMIN_PAT', 'NETLIFY_ACCESS_TOKEN'].includes(
      bindings.netlify_handoff_credential_environment_name) &&
    Object.entries(bindings)
    .filter(([name]) => !['email_provider', 'netlify_handoff_credential_environment_name'].includes(name))
    .every(([, value]) => nonzeroSha256(value));
}

export function selectedNetlifyCredentialName(env = process.env) {
  const present = ['NETLIFY_ADMIN_PAT', 'NETLIFY_ACCESS_TOKEN']
    .filter((name) => typeof env[name] === 'string' && env[name].length > 0);
  return present.length === 1 ? present[0] : null;
}

export function reviewActivationRuntimeEnvironmentNamesSha256(env = process.env) {
  const selected = selectedNetlifyCredentialName(env);
  if (!selected) return null;
  const mode = 'production';
  const appliesToMode = (entry) => !Array.isArray(entry.modes) || entry.modes.includes(mode);
  const names = [...new Set([
    ...Object.keys(REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.profiles[mode].flags),
    ...REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.secrets.filter(appliesToMode).map(({ name }) => name),
    selected,
    ...REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.bindings.filter(appliesToMode).map(({ name }) => name),
    REVIEW_ACTIVATION_ENVIRONMENT_CONTRACT.readback.env_name,
    ACTIVATION_MANIFEST_ENV,
  ])].sort();
  return sha256(canonicalReviewActivationRuntimeJson(names));
}

export function reviewActivationRuntimeAuthorityBinding(env = process.env, options = {}) {
  const deploymentSha = options.deploymentSha ?? ACTIVATION_BUILD_IDENTITY?.deployment_sha;
  const verifierUrl = canonicalVerifierUrl(env[VERIFIER_URL_ENV]);
  const publicKey = ed25519PublicKey(env[VERIFIER_PUBLIC_KEY_ENV]);
  const bindings = expectedBindings(env);
  const environmentNamesSha256 = reviewActivationRuntimeEnvironmentNamesSha256(env);
  const credentialName = selectedNetlifyCredentialName(env);
  const credential = credentialName ? env[credentialName] : null;
  const rawBindingsValid = UUID.test(String(env.ARC_EXPECTED_NETLIFY_SITE_ID || '')) &&
    PRICE_ID.test(String(env.ARC_EXPECTED_PRICE_ID || '')) &&
    PRODUCT_ID.test(String(env.ARC_EXPECTED_PRODUCT_ID || '')) &&
    INTEGRATION_ID.test(String(env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER || '')) &&
    PROVIDER.test(String(env.ARC_REVIEW_EMAIL_PROVIDER || '')) &&
    typeof credential === 'string' && credential.length >= 32 && credential.length <= 512;
  if (!DEPLOYMENT_SHA.test(String(deploymentSha || '')) || !verifierUrl || !publicKey ||
      !bindingsComplete(bindings) || !environmentNamesSha256 || !rawBindingsValid) return null;
  return Object.freeze({
    schema: 'arc-review-activation-runtime-authority-v1',
    version: 1,
    deployment_sha: deploymentSha,
    environment_names_sha256: environmentNamesSha256,
    maximum_age_seconds: REVIEW_ACTIVATION_RUNTIME_READBACK_MAXIMUM_AGE_MS / 1000,
    provider_bindings_sha256: sha256(canonicalReviewActivationRuntimeJson(bindings)),
    route_matrix_sha256: REVIEW_ACTIVATION_ROUTE_MATRIX_SHA256,
    verifier_key_sha256: publicKey.sha256,
    verifier_url_sha256: sha256(verifierUrl),
  });
}

function manifestBindsRuntimeAuthority(env, deploymentSha, authoritySha256, now) {
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
    const evidence = manifest.evidence?.find((item) => item.kind === 'live_checkout_readback');
    if (evidence?.sha256 === authoritySha256) return true;
  }
  return false;
}

export function reviewActivationRuntimeReadbackConfiguration(
  env = process.env,
  nowValue = new Date(),
  options = {},
) {
  const now = nowValue instanceof Date ? new Date(nowValue.getTime()) : new Date(nowValue);
  const requested = env[ENABLED_ENV] === 'true';
  const flagValid = env[ENABLED_ENV] === 'true' || env[ENABLED_ENV] === 'false' ||
    env[ENABLED_ENV] === undefined;
  const deploymentSha = options.deploymentSha ?? ACTIVATION_BUILD_IDENTITY?.deployment_sha;
  const authority = reviewActivationRuntimeAuthorityBinding(env, { deploymentSha });
  const authoritySha256 = authority
    ? sha256(canonicalReviewActivationRuntimeJson(authority))
    : null;
  const publicKey = ed25519PublicKey(env[VERIFIER_PUBLIC_KEY_ENV]);
  const verifierUrl = canonicalVerifierUrl(env[VERIFIER_URL_ENV]);
  const manifestBound = requested && Number.isFinite(now.getTime()) && authoritySha256 !== null &&
    manifestBindsRuntimeAuthority(env, deploymentSha, authoritySha256, now);
  const configured = requested && flagValid && env.ARC_RUNTIME_ENVIRONMENT === 'production' &&
    authority !== null && publicKey !== null && verifierUrl !== null && manifestBound;
  return Object.freeze({
    authority_sha256: authoritySha256,
    configured,
    deployment_sha: DEPLOYMENT_SHA.test(String(deploymentSha || '')) ? deploymentSha : null,
    enabled: configured,
    flag_valid: flagValid,
    key_sha256: publicKey?.sha256 || null,
    manifest_bound: manifestBound,
    public_key: publicKey?.key || null,
    requested,
    verifier_url: verifierUrl,
  });
}

export function validateReviewActivationReadbackReceipt(
  env,
  readback,
  nowValue = new Date(),
  options = {},
) {
  const now = nowValue instanceof Date ? new Date(nowValue.getTime()) : new Date(nowValue);
  const deploymentSha = options.deploymentSha ?? ACTIVATION_BUILD_IDENTITY?.deployment_sha;
  if (!Number.isFinite(now.getTime()) || !DEPLOYMENT_SHA.test(String(deploymentSha || '')) ||
      !exactKeys(readback, READBACK_TOP_FIELDS) ||
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
      observedAt > now.getTime() + 60_000 ||
      now.getTime() - observedAt > REVIEW_ACTIVATION_RUNTIME_READBACK_MAXIMUM_AGE_MS ||
      expiresAt <= now.getTime() || expiresAt <= observedAt ||
      expiresAt - observedAt > REVIEW_ACTIVATION_RUNTIME_READBACK_MAXIMUM_AGE_MS ||
      REQUIRED_RECEIPT_PATHS.some((path) => !nonzeroSha256(valueAtPath(readback, path)))) {
    return false;
  }
  return readback.netlify.deployment_sha === deploymentSha &&
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
    readback.email.native_suppression_id_sha256 ===
      env.ARC_REVIEW_EMAIL_NATIVE_SUPPRESSION_ID_SHA256 &&
    readback.zapier.email_workflow_id_sha256 === env.ARC_ZAPIER_REVIEW_EMAIL_WORKFLOW_ID_SHA256 &&
    readback.zapier.revision_workflow_id_sha256 ===
      env.ARC_ZAPIER_REVIEW_REVISION_WORKFLOW_ID_SHA256 &&
    readback.zapier.payment_arc2_workflow_id_sha256 ===
      env.ARC_ZAPIER_PAYMENT_ARC2_WORKFLOW_ID_SHA256 &&
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
}

function signedEnvelopePayload(envelope) {
  return canonicalReviewActivationRuntimeJson({
    schema: envelope.schema,
    version: envelope.version,
    authority_sha256: envelope.authority_sha256,
    key_sha256: envelope.key_sha256,
    receipt: envelope.receipt,
  });
}

export function validateReviewActivationRuntimeEnvelope(
  env,
  envelope,
  nowValue = new Date(),
  options = {},
) {
  const configuration = reviewActivationRuntimeReadbackConfiguration(env, nowValue, options);
  if (!configuration.enabled || !exactKeys(envelope, ENVELOPE_FIELDS) ||
      envelope.schema !== REVIEW_ACTIVATION_RUNTIME_READBACK_SCHEMA ||
      envelope.version !== REVIEW_ACTIVATION_RUNTIME_READBACK_VERSION ||
      envelope.authority_sha256 !== configuration.authority_sha256 ||
      envelope.key_sha256 !== configuration.key_sha256 ||
      typeof envelope.signature !== 'string') return false;
  let signature;
  try { signature = Buffer.from(envelope.signature, 'base64'); } catch { return false; }
  if (signature.length !== 64 || signature.toString('base64') !== envelope.signature) return false;
  let validSignature = false;
  try {
    validSignature = verifySignature(
      null,
      Buffer.from(`${SIGNATURE_DOMAIN}${signedEnvelopePayload(envelope)}`),
      configuration.public_key,
      signature,
    );
  } catch {
    return false;
  }
  return validSignature && validateReviewActivationReadbackReceipt(
    env,
    envelope.receipt,
    nowValue,
    { deploymentSha: configuration.deployment_sha },
  );
}

export function reviewActivationRuntimeReadbackStoreKey(configuration) {
  if (!configuration?.enabled || !DEPLOYMENT_SHA.test(String(configuration.deployment_sha || '')) ||
      !HEX_64.test(String(configuration.authority_sha256 || ''))) {
    throw new TypeError('Runtime readback configuration is unavailable.');
  }
  return `current/${configuration.deployment_sha}/${configuration.authority_sha256}`;
}

async function strongRead(store, key) {
  if (!store?.getWithMetadata) return null;
  try {
    return await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  } catch {
    return null;
  }
}

export async function readReviewActivationRuntimeReadback(
  env,
  store,
  nowValue = new Date(),
  options = {},
) {
  const configuration = reviewActivationRuntimeReadbackConfiguration(env, nowValue, options);
  if (!configuration.enabled) return null;
  const key = reviewActivationRuntimeReadbackStoreKey(configuration);
  const entry = await strongRead(store, key);
  if (!entry || !validateReviewActivationRuntimeEnvelope(env, entry.data, nowValue, options)) return null;
  return Object.freeze({ envelope: entry.data, etag: entry.etag, key });
}

async function responseBody(response) {
  if (!response || response.status !== 200) throw new Error('ARC_RUNTIME_READBACK_FETCH_FAILED');
  const contentType = response.headers?.get?.('content-type') || '';
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new Error('ARC_RUNTIME_READBACK_CONTENT_TYPE_INVALID');
  }
  const declared = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > REVIEW_ACTIVATION_RUNTIME_READBACK_MAXIMUM_BYTES) {
    throw new Error('ARC_RUNTIME_READBACK_RESPONSE_TOO_LARGE');
  }
  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > REVIEW_ACTIVATION_RUNTIME_READBACK_MAXIMUM_BYTES) {
    throw new Error('ARC_RUNTIME_READBACK_RESPONSE_TOO_LARGE');
  }
  try { return JSON.parse(text); } catch {
    throw new Error('ARC_RUNTIME_READBACK_JSON_INVALID');
  }
}

export async function fetchReviewActivationRuntimeReadback(
  env,
  nowValue = new Date(),
  options = {},
) {
  const configuration = reviewActivationRuntimeReadbackConfiguration(env, nowValue, options);
  if (!configuration.enabled) throw new Error('ARC_RUNTIME_READBACK_CONFIGURATION_INVALID');
  const fetcher = options.fetch || globalThis.fetch;
  if (typeof fetcher !== 'function') throw new Error('ARC_RUNTIME_READBACK_FETCH_UNAVAILABLE');
  let response;
  try {
    response = await fetcher(configuration.verifier_url, {
      headers: { Accept: 'application/json' },
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(8_000),
    });
  } catch (cause) {
    throw new Error('ARC_RUNTIME_READBACK_FETCH_FAILED', { cause });
  }
  const envelope = await responseBody(response);
  if (!validateReviewActivationRuntimeEnvelope(env, envelope, nowValue, options)) {
    throw new Error('ARC_RUNTIME_READBACK_ENVELOPE_INVALID');
  }
  return envelope;
}

export async function persistReviewActivationRuntimeReadback(
  env,
  store,
  envelope,
  nowValue = new Date(),
  options = {},
) {
  const configuration = reviewActivationRuntimeReadbackConfiguration(env, nowValue, options);
  if (!configuration.enabled || !store?.getWithMetadata || !store?.setJSON ||
      !validateReviewActivationRuntimeEnvelope(env, envelope, nowValue, options)) {
    throw new Error('ARC_RUNTIME_READBACK_PERSISTENCE_UNAVAILABLE');
  }
  const key = reviewActivationRuntimeReadbackStoreKey(configuration);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const current = await strongRead(store, key);
    if (current?.data) {
      const currentObserved = Date.parse(current.data?.receipt?.observed_at);
      const nextObserved = Date.parse(envelope.receipt.observed_at);
      const currentCanonical = canonicalReviewActivationRuntimeJson(current.data);
      const nextCanonical = canonicalReviewActivationRuntimeJson(envelope);
      if (Number.isFinite(currentObserved) && currentObserved > nextObserved) {
        if (validateReviewActivationRuntimeEnvelope(env, current.data, nowValue, options)) return current.data;
        throw new Error('ARC_RUNTIME_READBACK_ROLLBACK_REJECTED');
      }
      if (currentCanonical === nextCanonical) return current.data;
      if (Number.isFinite(currentObserved) && currentObserved === nextObserved) {
        throw new Error('ARC_RUNTIME_READBACK_EQUIVOCATION_REJECTED');
      }
    }
    try {
      const write = await store.setJSON(key, envelope, current?.etag
        ? { onlyIfMatch: current.etag }
        : { onlyIfNew: true });
      if (write?.modified === false) continue;
    } catch {
      continue;
    }
    const durable = await strongRead(store, key);
    if (durable && canonicalReviewActivationRuntimeJson(durable.data) ===
        canonicalReviewActivationRuntimeJson(envelope) &&
        validateReviewActivationRuntimeEnvelope(env, durable.data, nowValue, options)) {
      return durable.data;
    }
  }
  throw new Error('ARC_RUNTIME_READBACK_PERSISTENCE_FAILED');
}

export async function refreshReviewActivationRuntimeReadback(
  env,
  store,
  nowValue = new Date(),
  options = {},
) {
  const envelope = await fetchReviewActivationRuntimeReadback(env, nowValue, options);
  return persistReviewActivationRuntimeReadback(env, store, envelope, nowValue, options);
}

export async function ensureReviewActivationRuntimeReadback(
  env,
  store,
  nowValue = new Date(),
  options = {},
) {
  const current = await readReviewActivationRuntimeReadback(env, store, nowValue, options);
  if (current) return current.envelope;
  await refreshReviewActivationRuntimeReadback(env, store, nowValue, options);
  const durable = await readReviewActivationRuntimeReadback(env, store, nowValue, options);
  if (!durable) throw new Error('ARC_RUNTIME_READBACK_NOT_CURRENT');
  return durable.envelope;
}
