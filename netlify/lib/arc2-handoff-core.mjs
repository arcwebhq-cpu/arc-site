import {
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';

export const HANDOFF_STORE = 'arc2-handoffs';
export const HANDOFF_SCHEMA = 'arc2-netlify-handoff-v1';
export const ARTIFACT_EVIDENCE_VERSION = 'arc2-handoff-artifact-evidence-v1';
export const ARTIFACT_EVIDENCE_SCOPE = 'netlify-claimable-deploy-artifacts';
export const ARTIFACT_SIGNATURE_PREFIX = 'arc2-handoff-artifact-evidence-signature-v1\n';
export const PAYMENT_EVIDENCE_VERSION = 'arc2-payment-evidence-v1';
export const PAYMENT_EVIDENCE_SCOPE = 'authoritative-stripe-test-checkout-session';
export const PAYMENT_SIGNATURE_PREFIX = 'arc2-payment-evidence-signature-v1\n';
export const LEAD_RECIPIENT_PREFIX = 'arc-lead-route-recipient-v1\n';
export const CLAIM_STATE_EVIDENCE_VERSION = 'arc2-claim-state-evidence-v1';
export const CLAIM_STATE_EVIDENCE_SCOPE = 'netlify-deploy-and-claim-final-deploy';
export const CLAIM_STATE_SIGNATURE_PREFIX = 'arc2-claim-state-evidence-signature-v1\n';
export const OUTBOX_CLAIM_VERSION = 'arc2-final-delivery-outbox-v1';
export const CLAIM_TOKEN_TTL_SECONDS = 30 * 60;
export const MAX_DEPLOY_POLL_ATTEMPTS = 20;

export const HANDOFF_STATES = Object.freeze([
  'PAYMENT_VERIFIED',
  'SITE_INTENT',
  'SITE_CREATED',
  'PRECLAIM_DEPLOY_READY',
  'LEAD_ROUTE_VERIFIED',
  'CLAIM_INVITED',
  'CLAIM_CALLBACK_RECEIVED',
  'CLAIMED_VERIFIED',
  'FINAL_DEPLOY_READY',
  'DELIVERED',
]);

const TRANSITIONS = Object.freeze({
  PAYMENT_VERIFIED: new Set(['SITE_INTENT']),
  SITE_INTENT: new Set(['SITE_CREATED']),
  SITE_CREATED: new Set(['PRECLAIM_DEPLOY_READY']),
  PRECLAIM_DEPLOY_READY: new Set(['LEAD_ROUTE_VERIFIED']),
  LEAD_ROUTE_VERIFIED: new Set(['CLAIM_INVITED']),
  CLAIM_INVITED: new Set(['CLAIM_CALLBACK_RECEIVED']),
  CLAIM_CALLBACK_RECEIVED: new Set(['CLAIMED_VERIFIED']),
  CLAIMED_VERIFIED: new Set(['FINAL_DEPLOY_READY']),
  FINAL_DEPLOY_READY: new Set(['DELIVERED']),
  DELIVERED: new Set(),
});

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_64_PATTERN = /^[0-9a-f]{64}$/;
const PREVIEW_FOLDER_PATTERN = /^[a-z0-9][a-z0-9-]*-[a-f0-9]{8}$/;
const NETLIFY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/;
const SAFE_SITE_NAME_PATTERN = /^arc-[a-f0-9]{24}$/;
const SAFE_FORM_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const SAFE_PATH_PATTERN = /^(?:index\.html|_headers)$/;
const PAYMENT_FIELDS = Object.freeze([
  'adult_purchaser_acknowledgement',
  'amount_subtotal_minor_units',
  'amount_total_minor_units',
  'artifact_manifest_sha256',
  'bundle_fingerprint',
  'checkout_session_id',
  'client_reference_id_sha256',
  'currency',
  'customer_email_sha256',
  'handoff_artifact_evidence_sha256',
  'livemode',
  'mode',
  'payment_link_id',
  'payment_status',
  'preview_folder',
  'price_id',
  'production_content_sha256',
  'quantity',
  'scope',
  'status',
  'terms_of_service_consent',
  'terms_version',
  'version',
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

export function configuredEnvironment(env = process.env) {
  const required = [
    'ARC_CHECKOUT_BINDING_SECRET',
    'ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET',
    'ARC_LEAD_ROUTE_EVIDENCE_SECRET',
    'ARC_HANDOFF_STATE_SECRET',
    'ARC_HANDOFF_TRIGGER_SECRET',
    'ARC_CLAIM_TOKEN_SECRET',
    'ARC_CLAIM_STATE_EVIDENCE_SECRET',
    'ARC_EMAIL_CLAIM_BINDING_SECRET',
    'ARC_EXPECTED_PAYMENT_LINK_ID',
    'ARC_EXPECTED_PRICE_ID',
    'NETLIFY_ADMIN_PAT',
    'NETLIFY_TEAM_SLUG',
    'NETLIFY_TEAM_ACCOUNT_ID',
    'NETLIFY_OAUTH_CLIENT_ID',
    'NETLIFY_OAUTH_CLIENT_SECRET',
  ];
  const missing = required.filter((name) => !String(env[name] || '').trim());
  const secretNames = required.filter((name) => /SECRET|TOKEN|PAT/.test(name));
  const shortSecrets = secretNames.filter((name) => String(env[name] || '').length < 32 || String(env[name] || '').length > 512);
  const duplicateSecrets = new Set(secretNames.map((name) => String(env[name] || '')).filter(Boolean)).size !== secretNames.filter((name) => env[name]).length;
  const identifiersValid = /^plink_[A-Za-z0-9]+$/.test(String(env.ARC_EXPECTED_PAYMENT_LINK_ID || '')) &&
    /^price_[A-Za-z0-9]+$/.test(String(env.ARC_EXPECTED_PRICE_ID || '')) &&
    NETLIFY_ID_PATTERN.test(String(env.NETLIFY_TEAM_ACCOUNT_ID || '')) &&
    NETLIFY_ID_PATTERN.test(String(env.NETLIFY_OAUTH_CLIENT_ID || '')) &&
    /^[A-Za-z0-9][A-Za-z0-9-]{1,62}$/.test(String(env.NETLIFY_TEAM_SLUG || ''));
  const publicOrigin = String(env.ARC_PUBLIC_ORIGIN || '').trim();
  let originValid = false;
  try {
    const url = new URL(publicOrigin);
    originValid = url.protocol === 'https:' && url.pathname === '/' && !url.username && !url.password && !url.search && !url.hash;
  } catch {
    originValid = false;
  }
  return {
    enabled: missing.length === 0 && shortSecrets.length === 0 && !duplicateSecrets && identifiersValid && originValid,
    missing,
    invalid: [
      ...shortSecrets,
      ...(duplicateSecrets ? ['ARC_SECRETS_MUST_BE_DISTINCT'] : []),
      ...(identifiersValid ? [] : ['ARC_EXPECTED_IDS_OR_NETLIFY_IDS']),
      ...(originValid ? [] : ['ARC_PUBLIC_ORIGIN']),
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

export function normalizeArtifactEvidence(raw, secret, now = new Date()) {
  const canonical = stringValue(raw, 'Artifact evidence', 2, 100_000);
  const value = plainObject(JSON.parse(canonical), 'Artifact evidence');
  if (canonicalJson(value) !== canonical) throw new TypeError('Artifact evidence is not canonical JSON.');
  exactKeys(value, [
    'artifact_manifest_sha256',
    'artifacts',
    'bundle_fingerprint',
    'issued_at',
    'preview_folder',
    'production_content_sha256',
    'scope',
    'version',
  ], 'Artifact evidence');
  if (value.version !== ARTIFACT_EVIDENCE_VERSION || value.scope !== ARTIFACT_EVIDENCE_SCOPE) {
    throw new TypeError('Artifact evidence version or scope is invalid.');
  }
  if (typeof value.preview_folder !== 'string' || !PREVIEW_FOLDER_PATTERN.test(value.preview_folder)) {
    throw new TypeError('Artifact preview folder is invalid.');
  }
  const issuedAt = isoTimestamp(value.issued_at, 'Artifact issued_at');
  const issuedMs = Date.parse(issuedAt);
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || issuedMs > nowMs + 5 * 60_000 || issuedMs < nowMs - 24 * 60 * 60_000) {
    throw new TypeError('Artifact evidence is stale or from the future.');
  }
  if (!Array.isArray(value.artifacts) || value.artifacts.length !== 2) throw new TypeError('Exactly two deploy artifacts are required.');
  const artifacts = value.artifacts.map((artifact) => {
    plainObject(artifact, 'Artifact');
    exactKeys(artifact, ['path', 'sha256', 'size'], 'Artifact');
    if (!SAFE_PATH_PATTERN.test(artifact.path)) throw new TypeError('Artifact path is not allowlisted.');
    if (!Number.isSafeInteger(artifact.size) || artifact.size < 1 || artifact.size > 1_000_000) throw new TypeError('Artifact size is invalid.');
    return { path: artifact.path, sha256: hex64(artifact.sha256, 'Artifact sha256'), size: artifact.size };
  });
  if (artifacts[0].path !== '_headers' || artifacts[1].path !== 'index.html') throw new TypeError('Artifact paths must be sorted and exact.');
  const manifest = canonicalJson(artifacts);
  if (sha256Hex(manifest) !== hex64(value.artifact_manifest_sha256, 'Artifact manifest sha256')) {
    throw new TypeError('Artifact manifest digest mismatch.');
  }
  hex64(value.production_content_sha256, 'Production content sha256');
  hex64(value.bundle_fingerprint, 'Bundle fingerprint');
  if (!secret || secret.length < 32) throw new TypeError('Artifact evidence secret is unavailable.');
  return { canonical, value, digest: sha256Hex(canonical), artifacts };
}

export function verifyArtifactSignature(evidence, signature, secret) {
  const supplied = hex64(signature, 'Artifact evidence signature');
  return safeEqual(supplied, hmacHex(secret, `${ARTIFACT_SIGNATURE_PREFIX}${evidence}`));
}

export function normalizeDeployArtifacts(raw, expectedArtifacts) {
  const canonical = stringValue(raw, 'Deploy artifacts', 2, 2_000_000);
  const value = JSON.parse(canonical);
  if (!Array.isArray(value) || canonicalJson(value) !== canonical || value.length !== expectedArtifacts.length) {
    throw new TypeError('Deploy artifacts are invalid or not canonical.');
  }
  const artifacts = value.map((artifact, index) => {
    plainObject(artifact, 'Deploy artifact');
    exactKeys(artifact, ['content_base64', 'path'], 'Deploy artifact');
    const expected = expectedArtifacts[index];
    if (artifact.path !== expected.path || typeof artifact.content_base64 !== 'string' || artifact.content_base64.length > 1_500_000) {
      throw new TypeError('Deploy artifact path or content is invalid.');
    }
    const bytes = Buffer.from(artifact.content_base64, 'base64');
    if (bytes.toString('base64') !== artifact.content_base64 || bytes.length !== expected.size || sha256Hex(bytes) !== expected.sha256) {
      throw new TypeError('Deploy artifact bytes do not match signed evidence.');
    }
    return { path: artifact.path, bytes };
  });
  return artifacts;
}

export function normalizePaymentEvidence(raw, signature, secret, artifactEvidence, env) {
  const canonical = stringValue(raw, 'Payment evidence', 2, 100_000);
  const value = plainObject(JSON.parse(canonical), 'Payment evidence');
  exactKeys(value, PAYMENT_FIELDS, 'Payment evidence');
  if (canonicalJson(value) !== canonical || value.version !== PAYMENT_EVIDENCE_VERSION || value.scope !== PAYMENT_EVIDENCE_SCOPE) {
    throw new TypeError('Payment evidence is invalid or not canonical.');
  }
  if (!secret || secret.length < 32 || !safeEqual(hex64(signature, 'Payment evidence signature'), hmacHex(secret, `${PAYMENT_SIGNATURE_PREFIX}${canonical}`))) {
    throw new TypeError('Payment evidence signature mismatch.');
  }
  if (value.preview_folder !== artifactEvidence.preview_folder ||
      value.production_content_sha256 !== artifactEvidence.production_content_sha256 ||
      value.artifact_manifest_sha256 !== artifactEvidence.artifact_manifest_sha256 ||
      value.handoff_artifact_evidence_sha256 !== sha256Hex(canonicalJson(artifactEvidence)) ||
      value.bundle_fingerprint !== artifactEvidence.bundle_fingerprint ||
      value.livemode !== false || value.mode !== 'payment' || value.status !== 'complete' ||
      value.payment_status !== 'paid' || value.currency !== 'usd' || value.amount_total_minor_units !== 500000 ||
      value.amount_subtotal_minor_units !== 500000 || value.quantity !== 1 ||
      value.payment_link_id !== env.ARC_EXPECTED_PAYMENT_LINK_ID ||
      value.price_id !== env.ARC_EXPECTED_PRICE_ID ||
      value.terms_of_service_consent !== 'accepted' || value.terms_version !== '2026-08-11' ||
      value.adult_purchaser_acknowledgement !== 'accepted' ||
      !/^cs_test_[A-Za-z0-9_]+$/.test(value.checkout_session_id)) {
    throw new TypeError('Payment evidence bindings are invalid.');
  }
  hex64(value.customer_email_sha256, 'Customer email sha256');
  hex64(value.client_reference_id_sha256, 'Client reference id sha256');
  return { canonical, value, digest: sha256Hex(canonical) };
}

export function extractNetlifyFormName(indexBytes) {
  let html;
  try {
    html = new TextDecoder('utf-8', { fatal: true }).decode(indexBytes);
  } catch {
    throw new TypeError('Production HTML must be valid UTF-8.');
  }
  const forms = [...html.matchAll(/<form\b([^>]*)>[\s\S]*?<\/form\s*>/gi)]
    .filter((match) => /\bdata-netlify\s*=\s*(["'])true\1/i.test(match[1]));
  if (forms.length !== 1) throw new TypeError('Exactly one Netlify-enabled lead form is required.');
  const attributes = forms[0][1];
  const nameMatch = attributes.match(/\bname\s*=\s*(["'])([^"']+)\1/i);
  const methodMatch = attributes.match(/\bmethod\s*=\s*(["'])([^"']+)\1/i);
  if (!nameMatch || !methodMatch || methodMatch[2].toUpperCase() !== 'POST') throw new TypeError('Netlify lead form attributes are invalid.');
  return validateFormName(nameMatch[2]);
}

export function normalizeStartPayload(input, env, now = new Date()) {
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
  const artifact = normalizeArtifactEvidence(input.artifact_evidence, env.ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET, now);
  if (!verifyArtifactSignature(artifact.canonical, input.artifact_evidence_hmac_sha256, env.ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET)) {
    throw new TypeError('Artifact evidence signature mismatch.');
  }
  const payment = normalizePaymentEvidence(
    input.payment_evidence,
    input.payment_evidence_hmac_sha256,
    env.ARC_CHECKOUT_BINDING_SECRET,
    artifact.value,
    env,
  );
  const deployArtifacts = normalizeDeployArtifacts(input.deploy_artifacts, artifact.artifacts);
  const bundleHash = createHash('sha256');
  for (const artifactEntry of deployArtifacts) bundleHash.update(artifactEntry.path).update('\0').update(artifactEntry.bytes).update('\0');
  if (bundleHash.digest('hex') !== artifact.value.bundle_fingerprint) throw new TypeError('Deploy artifact bundle fingerprint mismatch.');
  const production = deployArtifacts.find((entry) => entry.path === 'index.html');
  if (!production || sha256Hex(production.bytes) !== artifact.value.production_content_sha256) {
    throw new TypeError('Production content digest mismatch.');
  }
  const leadEmail = stringValue(input.lead_notification_email, 'Lead notification email', 3, 254).toLowerCase();
  const recipientHmac = hex64(input.lead_route_recipient_hmac_sha256, 'Lead recipient HMAC');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(leadEmail) ||
      !safeEqual(recipientHmac, hmacHex(env.ARC_LEAD_ROUTE_EVIDENCE_SECRET, `${LEAD_RECIPIENT_PREFIX}${leadEmail}`))) {
    throw new TypeError('Lead notification email is invalid or unbound.');
  }
  const formName = extractNetlifyFormName(production.bytes);
  return { artifact, payment, deployArtifacts, leadEmail, formName };
}

export function handoffKey(paymentEvidence, stateSecret) {
  stringValue(stateSecret, 'Handoff state secret', 32, 512);
  const stable = `${paymentEvidence.checkout_session_id}\n${paymentEvidence.preview_folder}\n${paymentEvidence.bundle_fingerprint}`;
  return `handoffs/${hmacHex(stateSecret, stable)}`;
}

export function deterministicSiteName(paymentEvidence, stateSecret) {
  return `arc-${hmacHex(stateSecret, `site-name-v1\n${paymentEvidence.checkout_session_id}\n${paymentEvidence.bundle_fingerprint}`).slice(0, 24)}`;
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
    customer_email_sha256: normalized.payment.value.customer_email_sha256,
    lead_notification_email_sha256: sha256Hex(normalized.leadEmail),
    preview_folder: normalized.artifact.value.preview_folder,
    artifacts: normalized.artifact.artifacts,
    form_name: normalized.formName,
    netlify_session_id: netlifySessionId,
    netlify_site_name: deterministicSiteName(normalized.payment.value, env.ARC_HANDOFF_STATE_SECRET),
    netlify_source_account_id: env.NETLIFY_TEAM_ACCOUNT_ID,
    netlify_site_id: null,
    site_created_at: null,
    preclaim_deploy_id: null,
    final_deploy_id: null,
    form_id: null,
    hook_id: null,
    destination_account_id: null,
    claim_token_hmac_sha256: null,
    claim_token_expires_at: null,
    claim_token_used_at: null,
    claim_wrapper_consumed_at: null,
    claim_jwt_issued_at: null,
    claim_invitation_sent_at: null,
    claim_invitation_provider_message_id_sha256: null,
    claim_callback_received_at: null,
    claimed_verified_at: null,
    final_deploy_ready_at: null,
    production_url: null,
    outbox_claim_status: null,
    outbox_claim_key_hmac_sha256: null,
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
  const status = {
    status: record.state,
    site_ready: ['PRECLAIM_DEPLOY_READY', 'LEAD_ROUTE_VERIFIED', 'CLAIM_INVITED', 'CLAIM_CALLBACK_RECEIVED', 'CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED'].includes(record.state),
    // Invitation issuance and wrapper exchange are not implemented, so no
    // stored/fabricated state is externally claimable in this scaffold.
    claim_available: false,
    claim_verified: ['CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED'].includes(record.state),
    delivery_ready: ['FINAL_DEPLOY_READY', 'DELIVERED'].includes(record.state),
    delivered: record.state === 'DELIVERED',
    updated_at: record.updated_at,
  };
  if (record.state === 'FINAL_DEPLOY_READY' || record.state === 'DELIVERED') status.production_url = record.production_url;
  return status;
}

export function netlifyClaimUrl(record, env) {
  if (record.state !== 'CLAIM_INVITED') throw new TypeError('Claim link is not available in the current state.');
  const claimWebhook = `${new URL(env.ARC_PUBLIC_ORIGIN).origin}/api/arc2/claim-webhook`;
  const token = signJwtHS256({
    client_id: env.NETLIFY_OAUTH_CLIENT_ID,
    session_id: record.netlify_session_id,
    claim_webhook: claimWebhook,
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

async function netlifyRequest(path, options, env, fetchImpl = fetch) {
  const url = `https://api.netlify.com/api/v1${path}`;
  const response = await fetchImpl(url, {
    ...options,
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${env.NETLIFY_ADMIN_PAT}`,
      ...(options.headers || {}),
    },
    redirect: 'error',
  });
  if (!response.ok) throw new Error(`Netlify request failed with status ${response.status}.`);
  return response;
}

export async function createClaimableSite(record, env, fetchImpl = fetch) {
  const response = await netlifyRequest('/sites', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      account_slug: env.NETLIFY_TEAM_SLUG,
      created_via: 'arc',
      name: record.netlify_site_name,
      session_id: record.netlify_session_id,
    }),
  }, env, fetchImpl);
  const site = await response.json();
  if (!site || !identifier(site.id, 'Netlify site id') || site.name !== record.netlify_site_name ||
      site.session_id !== record.netlify_session_id || site.account_id !== env.NETLIFY_TEAM_ACCOUNT_ID ||
      site.account_slug !== env.NETLIFY_TEAM_SLUG) {
    throw new Error('Netlify site response did not match the handoff intent.');
  }
  return site;
}

export function createStoredZip(artifacts) {
  if (!Array.isArray(artifacts) || artifacts.length !== 2) throw new TypeError('Exactly two ZIP artifacts are required.');
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

export async function deployZip(siteId, zip, title, env, fetchImpl = fetch) {
  identifier(siteId, 'Netlify site id');
  const response = await netlifyRequest(`/sites/${encodeURIComponent(siteId)}/deploys?title=${encodeURIComponent(title)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/zip' },
    body: zip,
  }, env, fetchImpl);
  const deploy = await response.json();
  if (!deploy || !identifier(deploy.id, 'Netlify deploy id') || deploy.site_id !== siteId) throw new Error('Netlify deploy response did not match the site.');
  return deploy;
}

export async function pollDeployReady(siteId, deployId, env, fetchImpl = fetch, options = {}) {
  const attempts = options.attempts || MAX_DEPLOY_POLL_ATTEMPTS;
  const wait = options.wait || (() => Promise.resolve());
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const response = await netlifyRequest(`/deploys/${encodeURIComponent(deployId)}`, { method: 'GET' }, env, fetchImpl);
    const deploy = await response.json();
    if (!deploy || deploy.id !== deployId || deploy.site_id !== siteId) throw new Error('Netlify deploy identity changed while polling.');
    if (deploy.state === 'ready') return deploy;
    if (deploy.state === 'error' || deploy.error_message) throw new Error('Netlify deploy failed.');
    await wait(attempt);
  }
  throw new Error('Netlify deploy did not become ready before the bounded timeout.');
}

export async function createEmailHook(siteId, formId, email, env, fetchImpl = fetch) {
  const body = { site_id: siteId, form_id: formId, type: 'email', event: 'submission_created', data: { email } };
  const response = await netlifyRequest(`/hooks?site_id=${encodeURIComponent(siteId)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, env, fetchImpl);
  const hook = await response.json();
  if (!hook || !identifier(hook.id, 'Netlify hook id') || hook.site_id !== siteId || hook.type !== 'email' ||
      hook.event !== 'submission_created' || hook.disabled === true || hook.data?.email !== email) {
    throw new Error('Netlify hook response did not match the requested recipient.');
  }
  return hook;
}

async function netlifyJson(path, env, fetchImpl) {
  return (await netlifyRequest(path, { method: 'GET' }, env, fetchImpl)).json();
}

export async function findNetlifyForm(siteId, formName, env, fetchImpl = fetch, options = {}) {
  identifier(siteId, 'Netlify site id');
  validateFormName(formName);
  const attempts = options.attempts || 8;
  const wait = options.wait || (() => Promise.resolve());
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const forms = await netlifyJson(`/sites/${encodeURIComponent(siteId)}/forms`, env, fetchImpl);
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

export async function ensureEmailHook(siteId, formId, email, env, fetchImpl = fetch) {
  const hooks = await netlifyJson(`/hooks?site_id=${encodeURIComponent(siteId)}`, env, fetchImpl);
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
  const hook = await createEmailHook(siteId, formId, email, env, fetchImpl);
  if (hook.form_id !== formId) throw new Error('Netlify hook response did not bind the expected form.');
  return hook;
}

export async function downloadVerifiedArtifacts(siteId, artifacts, env, fetchImpl = fetch) {
  const output = [];
  for (const artifact of artifacts) {
    const raw = await netlifyRequest(`/sites/${encodeURIComponent(siteId)}/files/${artifact.path}`, {
      method: 'GET',
      headers: { Accept: 'application/vnd.bitballoon.v1.raw' },
    }, env, fetchImpl);
    const bytes = Buffer.from(await raw.arrayBuffer());
    if (bytes.length !== artifact.size || sha256Hex(bytes) !== artifact.sha256) throw new Error('Netlify raw source bytes mismatch.');
    output.push({ path: artifact.path, bytes });
  }
  return output;
}

export async function verifyNetlifyHandoff(record, expected, env, fetchImpl = fetch) {
  const site = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl);
  const account = await netlifyJson(`/accounts/${encodeURIComponent(expected.accountId)}`, env, fetchImpl);
  const deployId = expected.deployId;
  const deploy = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}/deploys/${encodeURIComponent(deployId)}`, env, fetchImpl);
  if (site.id !== record.netlify_site_id || site.session_id !== record.netlify_session_id || account.id !== expected.accountId ||
      site.account_id !== expected.accountId || deploy.id !== deployId || deploy.site_id !== record.netlify_site_id ||
      deploy.state !== 'ready' || site.published_deploy?.id !== deployId) {
    throw new Error('Netlify site, account, session, or deploy binding failed.');
  }
  const files = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}/files`, env, fetchImpl);
  if (!Array.isArray(files) || files.length !== expected.artifacts.length) throw new Error('Netlify deploy file count mismatch.');
  for (const artifact of expected.artifacts) {
    const file = files.find((item) => item.path === `/${artifact.path}`);
    if (!file || Number(file.size) !== artifact.size) throw new Error('Netlify deploy file metadata mismatch.');
  }
  const artifactBytes = await downloadVerifiedArtifacts(record.netlify_site_id, expected.artifacts, env, fetchImpl);
  const forms = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}/forms`, env, fetchImpl);
  const matchingForms = (Array.isArray(forms) ? forms : []).filter((form) => form.id === expected.formId && form.site_id === record.netlify_site_id && form.name === expected.formName);
  if (matchingForms.length !== 1) throw new Error('Netlify form binding failed.');
  const hooks = await netlifyJson(`/hooks?site_id=${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl);
  const matchingHooks = (Array.isArray(hooks) ? hooks : []).filter((hook) => hook.id === expected.hookId && hook.site_id === record.netlify_site_id &&
    hook.form_id === expected.formId && hook.type === 'email' && hook.event === 'submission_created' && hook.disabled !== true &&
    sha256Hex(String(hook.data?.email || '').trim().toLowerCase()) === expected.leadEmailSha256);
  if (matchingHooks.length !== 1) throw new Error('Netlify hook binding failed.');
  const productionUrl = normalizeProductionUrl(site.ssl_url || site.url);
  const publicResponse = await fetchImpl(productionUrl, { method: 'GET', redirect: 'error' });
  if (!publicResponse.ok || !(publicResponse.headers.get('x-robots-tag') || '').toLowerCase().includes('noindex')) {
    throw new Error('Published handoff is unavailable or missing noindex protection.');
  }
  return { site, account, deploy, form: matchingForms[0], hook: matchingHooks[0], artifactBytes, productionUrl };
}

export function normalizeProductionUrl(value) {
  const url = new URL(stringValue(value, 'Netlify production URL', 12, 512));
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new TypeError('Netlify production URL must be a plain HTTPS root.');
  }
  return url.toString();
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

export function createClaimStateEvidence(record, env, now = new Date()) {
  if (record.state !== 'FINAL_DEPLOY_READY' || record.outbox_claim_status !== 'CLAIMED') {
    throw new TypeError('Claim-state evidence is unavailable before final deploy and outbox claim.');
  }
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
    netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
    netlify_deploy_id_sha256: sha256Hex(record.final_deploy_id),
    netlify_destination_account_id_sha256: sha256Hex(record.destination_account_id),
    production_url: normalizeProductionUrl(record.production_url),
    claim_invitation_sent_at: isoTimestamp(record.claim_invitation_sent_at, 'Claim invitation timestamp'),
    claim_callback_received_at: isoTimestamp(record.claim_callback_received_at, 'Claim callback timestamp'),
    claimed_verified_at: isoTimestamp(record.claimed_verified_at, 'Claim verification timestamp'),
    final_deploy_ready_at: isoTimestamp(record.final_deploy_ready_at, 'Final deploy timestamp'),
    outbox_claim_status: 'CLAIMED',
    outbox_claim_key_hmac_sha256: hex64(record.outbox_claim_key_hmac_sha256, 'Outbox claim key HMAC'),
    issued_at: new Date(now).toISOString(),
  };
  const orderedTimes = [value.claim_invitation_sent_at, value.claim_callback_received_at, value.claimed_verified_at, value.final_deploy_ready_at, value.issued_at]
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

export function validateExpectedBindings(record) {
  if (record.schema !== HANDOFF_SCHEMA || !HANDOFF_STATES.includes(record.state) || !Number.isSafeInteger(record.revision) || record.revision < 1 ||
      !UUID_PATTERN.test(record.netlify_session_id) || !SAFE_SITE_NAME_PATTERN.test(record.netlify_site_name)) {
    throw new TypeError('Stored handoff record is invalid.');
  }
  for (const field of ['payment_evidence_sha256', 'artifact_evidence_sha256', 'artifact_manifest_sha256', 'bundle_fingerprint', 'production_content_sha256', 'customer_email_sha256', 'lead_notification_email_sha256']) {
    hex64(record[field], field);
  }
  if (record.claim_token_hmac_sha256 !== null) hex64(record.claim_token_hmac_sha256, 'claim_token_hmac_sha256');
  // Later claim states are externally unreachable in this scaffold. These
  // checks only ensure a manually introduced/future record fails closed; token
  // issuance and wrapper-consumption semantics are deliberately not modeled.
  if (record.claim_invitation_sent_at === null) {
    if (record.claim_token_hmac_sha256 !== null || record.claim_token_expires_at !== null || record.claim_token_used_at !== null ||
        record.claim_wrapper_consumed_at !== null || record.claim_invitation_provider_message_id_sha256 !== null ||
        ['CLAIM_INVITED', 'CLAIM_CALLBACK_RECEIVED', 'CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED'].includes(record.state)) {
      throw new TypeError('Unissued claim token fields must be null.');
    }
  } else {
    hex64(record.claim_invitation_provider_message_id_sha256, 'claim_invitation_provider_message_id_sha256');
    const sentAt = Date.parse(isoTimestamp(record.claim_invitation_sent_at, 'claim_invitation_sent_at'));
    const expiresAt = Date.parse(isoTimestamp(record.claim_token_expires_at, 'claim_token_expires_at'));
    if (expiresAt <= sentAt || expiresAt - sentAt > CLAIM_TOKEN_TTL_SECONDS * 1000) {
      throw new TypeError('Claim token expiry ordering is invalid.');
    }
    if (record.state === 'LEAD_ROUTE_VERIFIED' && record.claim_token_hmac_sha256 === null) {
      throw new TypeError('Issued claim token hash is missing.');
    }
    if (['CLAIM_INVITED', 'CLAIM_CALLBACK_RECEIVED', 'CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED'].includes(record.state) &&
        (record.claim_token_hmac_sha256 !== null || !record.claim_token_used_at || !record.claim_wrapper_consumed_at)) {
      throw new TypeError('Consumed claim token fields are invalid.');
    }
  }
  if (!PREVIEW_FOLDER_PATTERN.test(record.preview_folder) || !Array.isArray(record.artifacts) || record.artifacts.length !== 2 ||
      validateFormName(record.form_name) !== record.form_name) throw new TypeError('Stored artifact bindings are invalid.');
  return record;
}

export function validateFormName(value) {
  if (typeof value !== 'string' || !SAFE_FORM_NAME_PATTERN.test(value)) throw new TypeError('Form name is invalid.');
  return value;
}
