import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import {
  activationManifestEvidenceSha256Environment,
  assertPublicIntakeAuthority,
} from './activation-manifest-core.mjs';
import {
  ASSET_PERMISSION_CONFIRMATION,
  BUDGET_CONFIRMATION,
  INTAKE_ARC1_DELIVERY_SCHEMA,
  INTAKE_ARC1_DISPATCH_SCHEMA,
  INTAKE_FILE_FIELDS,
  INTAKE_MULTI_FIELDS,
  INTAKE_SINGLE_FIELDS,
  INTAKE_SUBMISSION_SCHEMA,
  OFFER_CONTRACT_ID,
  TERMS_CONFIRMATION,
  createInitialArc1DeliveryState,
  createInitialArc1DispatchState,
} from './intake-submission-core.mjs';
import {
  INTAKE_PRIVATE_ASSET_GRANT_SCHEMA,
  createPrivateAssetGrants,
  privateAssetIndexEntries,
  resolvePrivateAssetEnvironment,
} from './intake-private-asset-core.mjs';
import { validateImageAsset } from './image-asset-validation.mjs';
import { consumeVerifiedIntakeForArc1 } from './intake-email-verification-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const INTAKE_ARC1_BRIDGE_ENABLED_ENV = 'ARC_INTAKE_ARC1_BRIDGE_ENABLED';
export const INTAKE_ARC1_ADAPTER_PROOF_ENV = 'ARC_INTAKE_ARC1_ADAPTER_ATTESTATION';
export const INTAKE_ARC1_ADAPTER_PROOF_SCHEMA = 'arc-intake-arc1-adapter-attestation-v1';
export const INTAKE_ARC1_BRIDGE_EVIDENCE_SCHEMA = 'arc-intake-arc1-bridge-evidence-v1';
export const INTAKE_ARC1_BRIDGE_ENVELOPE_SCHEMA = 'arc-intake-arc1-bridge-envelope-v1';
export const INTAKE_ARC1_ACK_SCHEMA = 'arc-intake-arc1-consumer-ack-v1';
export const INTAKE_ARC1_CONSUMER_SCHEMA = 'arc1-function-intake-adapter-v1';
export const INTAKE_ARC1_REQUEST_SCHEMA = 'arc-intake-arc1-delivery-request-v1';
export const INTAKE_ARC1_MAX_ATTEMPTS = 5;
export const INTAKE_ARC1_LEASE_MS = 2 * 60_000;
export const INTAKE_ARC1_EVIDENCE_TTL_MS = 24 * 60 * 60_000;
export const INTAKE_ARC1_MAX_ACK_BYTES = 32 * 1024;
export const INTAKE_ARC1_CONTRACT_VERSION = 'arc-intake-to-arc1-contract-v2';
export const INTAKE_ARC1_CONTRACT_TEXT = [
  INTAKE_ARC1_CONTRACT_VERSION,
  INTAKE_SUBMISSION_SCHEMA,
  INTAKE_ARC1_BRIDGE_EVIDENCE_SCHEMA,
  INTAKE_ARC1_CONSUMER_SCHEMA,
  BUDGET_CONFIRMATION,
  TERMS_CONFIRMATION,
  ASSET_PERMISSION_CONFIRMATION,
  'create-only-ingress-claim-required-before-ack',
  INTAKE_PRIVATE_ASSET_GRANT_SCHEMA,
  'authenticated-content-addressed-private-asset-retrieval',
  'folder-link-intake-rejected-until-private-provider-adapter',
  'signed-asset-receipt-required-before-ingress-claim-and-ack',
  'arc1-asset-visual-review-v1',
  'arc-deterministic-image-screen-v1',
  'authority-pinned-human-review-required-before-publication',
  'immutable-evidence-replay',
].join('\n');
export const INTAKE_ARC1_CONTRACT_SHA256 = createHash('sha256').update(INTAKE_ARC1_CONTRACT_TEXT).digest('hex');

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const SAFE_EXTERNAL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/;
const DATA_FIELDS = new Set([...INTAKE_MULTI_FIELDS, ...INTAKE_SINGLE_FIELDS].filter((field) => field !== 'bot-field'));
const DELIVERY_FIELDS = Object.freeze([
  'acknowledged_at', 'acknowledgement_sha256', 'alert_code', 'alert_status', 'alert_updated_at',
  'attempt_count', 'consumer_claim_key_hmac_sha256', 'dead_lettered_at', 'evidence_expires_at',
  'evidence_issued_at', 'evidence_sha256', 'last_attempt_at', 'lease_expires_at', 'lease_hmac_sha256',
  'next_attempt_at', 'schema', 'status',
]);
const RECORD_FIELDS = Object.freeze([
  'arc1_consumer_compatible', 'arc1_delivery', 'arc1_dispatch', 'asset_manifest', 'assets', 'data', 'form_name',
  'received_at', 'schema', 'source', 'submission_data_sha256', 'submission_id',
]);
const DISPATCH_FIELDS = Object.freeze([
  'accepted_at', 'alert_code', 'alert_status', 'alert_updated_at', 'attempt_count', 'attempt_lease_expires_at',
  'attempt_lease_hmac_sha256', 'last_attempt_at', 'schema', 'status',
]);
const EVIDENCE_FIELDS = Object.freeze([
  'asset_manifest', 'asset_retrieval_endpoint', 'bridge_contract_sha256', 'data', 'delivery_id', 'evidence_expires_at',
  'evidence_issued_at', 'received_at', 'scope', 'site_id_sha256', 'source_form_name', 'source_key_hmac_sha256',
  'source_schema', 'submission_data_sha256', 'submission_id', 'version',
]);
const ACK_FIELDS = Object.freeze([
  'ack_id', 'asset_receipt_sha256', 'bridge_contract_sha256', 'consumer_claim_key_hmac_sha256', 'consumer_schema', 'delivery_id',
  'evidence_sha256', 'received_at', 'schema', 'status', 'version',
]);
const ADAPTER_PROOF_FIELDS = Object.freeze([
  'asset_pipeline_verified', 'asset_producer_consumer_tests_sha256', 'asset_retrieval_endpoint_sha256',
  'bridge_contract_sha256', 'bridge_schema', 'consumer_schema', 'default_off_verified', 'expires_at',
  'endpoint_sha256', 'schema', 'site_id_sha256', 'source_schema', 'tests_passed', 'verified_at', 'version',
]);

function canonicalBridgeEndpoint(value) {
  let endpoint;
  try { endpoint = new URL(value); } catch { throw new TypeError('ARC1 bridge endpoint is invalid.'); }
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.port || endpoint.search || endpoint.hash || endpoint.pathname === '/' ||
      !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(endpoint.hostname)) {
    throw new TypeError('ARC1 bridge endpoint must be an exact public HTTPS path.');
  }
  return endpoint.toString();
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Non-finite JSON value.');
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('Plain JSON is required.');
}

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const exactKeys = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
const iso = (value, label) => {
  if (typeof value !== 'string' || new Date(value).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return value;
};
const nullableIso = (value, label) => value === null ? null : iso(value, label);
const requiredSha = (value, label) => {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
};
const nullableSha = (value, label) => value === null ? null : requiredSha(value, label);
const safeEqual = (left, right) => {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
};
const secret = (value, label) => {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 32 || Buffer.byteLength(value, 'utf8') > 256) {
    throw new TypeError(`${label} must be 32-256 UTF-8 bytes.`);
  }
  return value;
};

export function validateArc1DeliveryState(value) {
  if (!exactKeys(value, DELIVERY_FIELDS) || value.schema !== INTAKE_ARC1_DELIVERY_SCHEMA ||
      !['PENDING', 'CLAIMED', 'ACKED', 'DEAD_LETTER'].includes(value.status) ||
      !Number.isSafeInteger(value.attempt_count) || value.attempt_count < 0 || value.attempt_count > INTAKE_ARC1_MAX_ATTEMPTS ||
      !['NONE', 'PENDING', 'RESOLVED'].includes(value.alert_status) ||
      ![null, 'DELIVERY_HTTP_FAILURE', 'DELIVERY_UNAVAILABLE', 'DELIVERY_INDEX_CONFLICT', 'INVALID_ACK', 'ACK_INDEX_CONFLICT', 'EVIDENCE_EXPIRED', 'MAX_ATTEMPTS'].includes(value.alert_code)) {
    throw new TypeError('ARC1 delivery state is invalid.');
  }
  iso(value.next_attempt_at, 'next_attempt_at');
  for (const field of ['lease_expires_at', 'last_attempt_at', 'evidence_issued_at', 'evidence_expires_at', 'acknowledged_at', 'dead_lettered_at', 'alert_updated_at']) {
    nullableIso(value[field], field);
  }
  for (const field of ['lease_hmac_sha256', 'evidence_sha256', 'acknowledgement_sha256', 'consumer_claim_key_hmac_sha256']) nullableSha(value[field], field);
  if (value.status === 'PENDING' && (value.lease_hmac_sha256 !== null || value.lease_expires_at !== null || value.acknowledged_at !== null || value.dead_lettered_at !== null)) {
    throw new TypeError('Pending ARC1 delivery fields are inconsistent.');
  }
  if (value.status === 'CLAIMED' && (!value.lease_hmac_sha256 || !value.lease_expires_at || !value.evidence_sha256 || !value.evidence_issued_at || !value.evidence_expires_at)) {
    throw new TypeError('Claimed ARC1 delivery fields are incomplete.');
  }
  if (value.status === 'ACKED' && (!value.acknowledged_at || !value.acknowledgement_sha256 || !value.consumer_claim_key_hmac_sha256 || value.lease_hmac_sha256 !== null || value.dead_lettered_at !== null)) {
    throw new TypeError('Acknowledged ARC1 delivery fields are incomplete.');
  }
  if (value.status === 'DEAD_LETTER' && (!value.dead_lettered_at || value.alert_status !== 'PENDING' || !value.alert_code || value.lease_hmac_sha256 !== null)) {
    throw new TypeError('Dead-letter ARC1 delivery fields are incomplete.');
  }
  return value;
}

export function validateArc1DispatchState(value) {
  if (!exactKeys(value, DISPATCH_FIELDS) || value.schema !== INTAKE_ARC1_DISPATCH_SCHEMA ||
      !['PENDING', 'ACCEPTED', 'DEAD_LETTER'].includes(value.status) || !Number.isSafeInteger(value.attempt_count) || value.attempt_count < 0 ||
      value.attempt_count > INTAKE_ARC1_MAX_ATTEMPTS || !['NONE', 'PENDING', 'RESOLVED'].includes(value.alert_status) ||
      ![null, 'DISPATCH_UNAVAILABLE', 'DISPATCH_REJECTED', 'DISPATCH_MAX_ATTEMPTS'].includes(value.alert_code)) throw new TypeError('ARC1 dispatch state is invalid.');
  for (const field of ['last_attempt_at', 'accepted_at', 'alert_updated_at']) nullableIso(value[field], field);
  nullableIso(value.attempt_lease_expires_at, 'attempt_lease_expires_at');
  nullableSha(value.attempt_lease_hmac_sha256, 'attempt_lease_hmac_sha256');
  if ((value.attempt_lease_hmac_sha256 === null) !== (value.attempt_lease_expires_at === null)) throw new TypeError('ARC1 dispatch lease is incomplete.');
  if (value.status === 'PENDING' && value.accepted_at !== null) throw new TypeError('Pending ARC1 dispatch is inconsistent.');
  if (value.status === 'ACCEPTED' && (!value.accepted_at || value.attempt_count < 1 || value.attempt_lease_hmac_sha256 !== null)) throw new TypeError('Accepted ARC1 dispatch is incomplete.');
  if (value.status === 'DEAD_LETTER' && (value.accepted_at !== null || value.attempt_count !== INTAKE_ARC1_MAX_ATTEMPTS ||
      value.alert_status !== 'PENDING' || value.alert_code !== 'DISPATCH_MAX_ATTEMPTS' ||
      value.attempt_lease_hmac_sha256 !== null)) throw new TypeError('Dead-letter ARC1 dispatch is incomplete.');
  return value;
}

export function validateIntakeSubmissionForBridge(value) {
  if (!exactKeys(value, RECORD_FIELDS) || value.schema !== INTAKE_SUBMISSION_SCHEMA || value.source !== 'first-party-netlify-function' ||
      value.form_name !== 'arc-preview-function-v1' || value.arc1_consumer_compatible !== false || !UUID_PATTERN.test(value.submission_id) ||
      !value.data || typeof value.data !== 'object' || Array.isArray(value.data) || Object.getPrototypeOf(value.data) !== Object.prototype ||
      !Array.isArray(value.asset_manifest) || !Array.isArray(value.assets) || value.asset_manifest.length !== value.assets.length ||
      value.assets.length > INTAKE_FILE_FIELDS.length) throw new TypeError('Intake submission bridge record is invalid.');
  iso(value.received_at, 'received_at');
  requiredSha(value.submission_data_sha256, 'submission_data_sha256');
  validateArc1DeliveryState(value.arc1_delivery);
  validateArc1DispatchState(value.arc1_dispatch);
  for (const [field, data] of Object.entries(value.data)) {
    if (!DATA_FIELDS.has(field)) throw new TypeError('Unexpected intake data field.');
    if (INTAKE_MULTI_FIELDS.includes(field)) {
      if (!Array.isArray(data) || data.length > 16 || data.some((item) => typeof item !== 'string')) throw new TypeError('Invalid multi-value intake data.');
    } else if (typeof data !== 'string') throw new TypeError('Invalid scalar intake data.');
  }
  if (value.data.intake_version !== 'arc-intake-v8' || value.data.offer_contract_id !== OFFER_CONTRACT_ID ||
      value.data.budget_confirmed !== BUDGET_CONFIRMATION || value.data.terms_accepted !== TERMS_CONFIRMATION) {
    throw new TypeError('Intake consent binding is invalid.');
  }
  let previousRole = '';
  for (let index = 0; index < value.assets.length; index += 1) {
    const manifest = value.asset_manifest[index];
    const asset = value.assets[index];
    const commonFields = ['content_type', 'kind', 'role', 'schema', 'sha256', 'size'];
    const contentField = 'content_base64';
    if (!exactKeys(manifest, commonFields) || !exactKeys(asset, [...commonFields, contentField]) ||
        canonicalJson(manifest) !== canonicalJson(Object.fromEntries(Object.entries(asset).filter(([key]) => key !== contentField))) ||
        asset.schema !== 'arc-intake-private-asset-reference-v1' || asset.kind !== 'UPLOAD' ||
        !INTAKE_FILE_FIELDS.includes(asset.role) || asset.role <= previousRole ||
        !Number.isSafeInteger(asset.size) || asset.size < 1 || asset.size > 1_250_000 ||
        !SHA256_PATTERN.test(asset.sha256)) throw new TypeError('Intake asset binding is invalid.');
    const bytes = Buffer.from(asset.content_base64, 'base64');
    if ((typeof asset.content_base64 !== 'string' || bytes.toString('base64') !== asset.content_base64) ||
        bytes.length !== asset.size || sha256(bytes) !== asset.sha256) throw new TypeError('Intake asset bytes are invalid.');
    validateImageAsset(bytes, asset.content_type);
    previousRole = asset.role;
  }
  const digest = sha256(canonicalJson({ data: value.data, asset_manifest: value.asset_manifest }));
  if (!safeEqual(digest, value.submission_data_sha256)) throw new TypeError('Intake submission digest mismatch.');
  return value;
}

export function normalizeStoredIntakeSubmissionForBridge(value) {
  if (value && typeof value === 'object' && !Array.isArray(value) &&
      !Object.hasOwn(value, 'arc1_delivery') && !Object.hasOwn(value, 'arc1_dispatch')) {
    const legacyKeys = RECORD_FIELDS.filter((field) => !['arc1_delivery', 'arc1_dispatch'].includes(field));
    if (exactKeys(value, legacyKeys) && typeof value.received_at === 'string') {
      value = {
        ...value,
        arc1_delivery: createInitialArc1DeliveryState(value.received_at),
        arc1_dispatch: createInitialArc1DispatchState(),
      };
    }
  }
  return validateIntakeSubmissionForBridge(value);
}

export function createAdapterAttestation(value, secretValue) {
  const canonical = canonicalJson(value);
  return canonicalJson({
    attestation: value,
    hmac_sha256: hmac(secret(secretValue, 'adapter proof secret'), `arc-intake-arc1-adapter-attestation-v1\n${canonical}`),
  });
}

function validatedArc1AdapterAttestation(
  raw,
  secretValue,
  now = new Date(),
  expectedEndpoint,
  expectedAssetEndpoint,
  expectedSiteId,
) {
  try {
    const wrapper = JSON.parse(raw);
    if (!exactKeys(wrapper, ['attestation', 'hmac_sha256']) || !exactKeys(wrapper.attestation, ADAPTER_PROOF_FIELDS)) return null;
    const value = wrapper.attestation;
    const canonical = canonicalJson(value);
    if (canonicalJson(wrapper) !== raw || value.schema !== INTAKE_ARC1_ADAPTER_PROOF_SCHEMA || value.version !== 1 ||
        value.source_schema !== INTAKE_SUBMISSION_SCHEMA || value.bridge_schema !== INTAKE_ARC1_BRIDGE_EVIDENCE_SCHEMA ||
        value.consumer_schema !== INTAKE_ARC1_CONSUMER_SCHEMA || value.bridge_contract_sha256 !== INTAKE_ARC1_CONTRACT_SHA256 ||
        value.tests_passed !== true || value.default_off_verified !== true || value.asset_pipeline_verified !== true ||
        !SHA256_PATTERN.test(value.asset_producer_consumer_tests_sha256) || !SHA256_PATTERN.test(value.endpoint_sha256) ||
        !SHA256_PATTERN.test(value.asset_retrieval_endpoint_sha256) || !SHA256_PATTERN.test(value.site_id_sha256) ||
        !expectedEndpoint || !safeEqual(value.endpoint_sha256, sha256(canonicalBridgeEndpoint(expectedEndpoint))) ||
        !expectedAssetEndpoint || !safeEqual(value.asset_retrieval_endpoint_sha256, sha256(expectedAssetEndpoint)) ||
        !expectedSiteId || !safeEqual(value.site_id_sha256, sha256(String(expectedSiteId).toLowerCase())) ||
        !SHA256_PATTERN.test(wrapper.hmac_sha256)) return null;
    const verified = Date.parse(iso(value.verified_at, 'verified_at'));
    const expires = Date.parse(iso(value.expires_at, 'expires_at'));
    const nowMs = new Date(now).getTime();
    if (!Number.isFinite(nowMs) || verified > nowMs + 60_000 || expires <= nowMs || expires > verified + 24 * 60 * 60_000) return null;
    if (!safeEqual(wrapper.hmac_sha256, hmac(secret(secretValue, 'adapter proof secret'),
      `arc-intake-arc1-adapter-attestation-v1\n${canonical}`))) return null;
    return Object.freeze({ ...value });
  } catch { return null; }
}

export function intakeArc1AdapterAttested(raw, secretValue, now = new Date(), expectedEndpoint, expectedAssetEndpoint, expectedSiteId) {
  return validatedArc1AdapterAttestation(
    raw, secretValue, now, expectedEndpoint, expectedAssetEndpoint, expectedSiteId,
  ) !== null;
}

// Public asset readiness is bound twice: the adapter's own HMAC-signed
// producer/consumer attestation and the external provider-E2E receipt embedded
// in the deployment-bound activation manifest must name the same digest. With
// either proof absent, stale, mismatched, or unsigned, the gate remains OFF.
export function intakeArc1PublicAssetShapesImplemented(env = process.env, now = new Date()) {
  let assetEndpoint;
  try { assetEndpoint = resolvePrivateAssetEnvironment(env).endpoint; } catch { return false; }
  const adapter = validatedArc1AdapterAttestation(
    env[INTAKE_ARC1_ADAPTER_PROOF_ENV],
    env.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET,
    now,
    env.ARC_INTAKE_ARC1_ENDPOINT,
    assetEndpoint,
    env.SITE_ID,
  );
  if (!adapter) return false;
  const providerEvidenceSha256 = activationManifestEvidenceSha256Environment(env, {
    kind: 'public_intake_provider_e2e',
    minimumStage: 'PUBLIC_INTAKE',
    now,
  });
  return safeEqual(adapter.asset_producer_consumer_tests_sha256, providerEvidenceSha256);
}

export function resolveArc1BridgeEnvironment(env) {
  const names = [
    'ARC_INTAKE_ARC1_RUN_SECRET', 'ARC_INTAKE_ARC1_DESTINATION_BEARER', 'ARC_INTAKE_ARC1_EVIDENCE_SECRET',
    'ARC_INTAKE_ARC1_ACK_SECRET', 'ARC_INTAKE_ARC1_STATE_SECRET', 'ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET',
    'ARC_INTAKE_ASSET_RETRIEVAL_SECRET',
  ];
  const values = Object.fromEntries(names.map((name) => [name, secret(env[name], name)]));
  if (!sensitiveCredentialsAreIsolated(env, names)) throw new TypeError('ARC1 bridge secrets must be distinct.');
  const endpoint = canonicalBridgeEndpoint(env.ARC_INTAKE_ARC1_ENDPOINT);
  const privateAssets = resolvePrivateAssetEnvironment(env);
  const siteId = String(env.SITE_ID || '').toLowerCase();
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5a-f][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(siteId) ||
      siteId !== String(env.ARC_EXPECTED_NETLIFY_SITE_ID || '').toLowerCase() || env.SITE_NAME !== 'arcsites') {
    throw new TypeError('Exact Netlify site identity is required.');
  }
  return { ...values, endpoint, siteId, privateAssets };
}

const deliveryId = (record, resolved) => hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET,
  `arc-intake-arc1-delivery-id-v1\n${record.submission_id}\n${record.submission_data_sha256}`);
const sourceKeyHmac = (record, resolved) => hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET,
  `arc-intake-arc1-source-key-v1\nsubmissions/${record.submission_id}`);

export function createBridgeEvidence(record, delivery, resolved) {
  validateIntakeSubmissionForBridge(record);
  validateArc1DeliveryState(delivery);
  if (!delivery.evidence_issued_at || !delivery.evidence_expires_at) throw new TypeError('Immutable evidence timing is missing.');
  const assetManifest = createPrivateAssetGrants(record, resolved.privateAssets);
  const data = { ...record.data };
  return {
    version: 1,
    scope: 'authenticated-first-party-arc-intake',
    bridge_contract_sha256: INTAKE_ARC1_CONTRACT_SHA256,
    source_schema: INTAKE_SUBMISSION_SCHEMA,
    site_id_sha256: sha256(resolved.siteId),
    source_form_name: record.form_name,
    source_key_hmac_sha256: sourceKeyHmac(record, resolved),
    delivery_id: deliveryId(record, resolved),
    submission_id: record.submission_id,
    received_at: record.received_at,
    submission_data_sha256: sha256(canonicalJson({ data, asset_manifest: assetManifest })),
    data,
    asset_manifest: assetManifest,
    asset_retrieval_endpoint: resolved.privateAssets.endpoint,
    evidence_issued_at: delivery.evidence_issued_at,
    evidence_expires_at: delivery.evidence_expires_at,
  };
}

async function readBoundedText(response, maximumBytes) {
  const reader = response.body?.getReader?.();
  if (!reader) throw new TypeError('ARC1 acknowledgement body is unavailable.');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new TypeError('ARC1 acknowledgement body is invalid.');
      total += value.byteLength;
      if (total > maximumBytes) {
        try { await reader.cancel(); } catch {}
        throw new TypeError('ARC1 acknowledgement is too large.');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally { try { reader.releaseLock(); } catch {} }
  return Buffer.concat(chunks, total).toString('utf8');
}

export function createBridgeEnvelope(record, delivery, resolved) {
  const evidence = createBridgeEvidence(record, delivery, resolved);
  if (!exactKeys(evidence, EVIDENCE_FIELDS)) throw new TypeError('Bridge evidence fields are invalid.');
  const evidenceRaw = canonicalJson(evidence);
  const envelope = {
    schema: INTAKE_ARC1_BRIDGE_ENVELOPE_SCHEMA,
    evidence,
    hmac_sha256: hmac(resolved.ARC_INTAKE_ARC1_EVIDENCE_SECRET, `arc-intake-arc1-bridge-evidence-v1\n${evidenceRaw}`),
  };
  return { envelope, raw: canonicalJson(envelope), evidenceSha256: sha256(evidenceRaw), deliveryId: evidence.delivery_id };
}

function validateAcknowledgement(raw, expected, resolved, now) {
  if (Buffer.byteLength(raw, 'utf8') > INTAKE_ARC1_MAX_ACK_BYTES) throw new TypeError('ARC1 acknowledgement is too large.');
  let wrapper;
  try { wrapper = JSON.parse(raw); } catch { throw new TypeError('ARC1 acknowledgement is not JSON.'); }
  if (!exactKeys(wrapper, ['acknowledgement', 'hmac_sha256']) || !exactKeys(wrapper.acknowledgement, ACK_FIELDS) || canonicalJson(wrapper) !== raw) {
    throw new TypeError('ARC1 acknowledgement fields are invalid.');
  }
  const ack = wrapper.acknowledgement;
  const canonical = canonicalJson(ack);
  if (ack.schema !== INTAKE_ARC1_ACK_SCHEMA || ack.version !== 1 || ack.status !== 'ACCEPTED' || ack.consumer_schema !== INTAKE_ARC1_CONSUMER_SCHEMA ||
      ack.bridge_contract_sha256 !== INTAKE_ARC1_CONTRACT_SHA256 || ack.delivery_id !== expected.deliveryId || ack.evidence_sha256 !== expected.evidenceSha256 ||
      !SAFE_EXTERNAL_ID_PATTERN.test(ack.ack_id) || !SHA256_PATTERN.test(ack.asset_receipt_sha256) ||
      !SHA256_PATTERN.test(ack.consumer_claim_key_hmac_sha256) || !SHA256_PATTERN.test(wrapper.hmac_sha256)) {
    throw new TypeError('ARC1 acknowledgement binding is invalid.');
  }
  const receivedMs = Date.parse(iso(ack.received_at, 'acknowledgement received_at'));
  const nowMs = new Date(now).getTime();
  if (receivedMs < Date.parse(expected.evidenceIssuedAt) - 60_000 || receivedMs > nowMs + 60_000) throw new TypeError('ARC1 acknowledgement time is invalid.');
  const signature = hmac(resolved.ARC_INTAKE_ARC1_ACK_SECRET, `arc-intake-arc1-consumer-ack-v1\n${canonical}`);
  if (!safeEqual(wrapper.hmac_sha256, signature)) throw new TypeError('ARC1 acknowledgement signature mismatch.');
  return { ack, digest: sha256(canonical) };
}

async function readSubmission(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  return entry ? { record: normalizeStoredIntakeSubmissionForBridge(entry.data), etag: entry.etag } : null;
}

async function replaceSubmission(store, key, entry, record) {
  validateIntakeSubmissionForBridge(record);
  const result = await store.setJSON(key, record, { onlyIfMatch: entry.etag });
  if (!result?.modified || !result.etag) throw new Error('ARC1_BRIDGE_STATE_CONTENTION');
  return { record, etag: result.etag };
}

async function ensureIndex(store, key, value) {
  const existing = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (existing) {
    if (canonicalJson(existing.data) !== canonicalJson(value)) throw new Error('ARC1_BRIDGE_INDEX_CONFLICT');
    return;
  }
  const result = await store.setJSON(key, value, { onlyIfNew: true });
  if (result?.modified) return;
  const raced = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!raced || canonicalJson(raced.data) !== canonicalJson(value)) throw new Error('ARC1_BRIDGE_INDEX_CONFLICT');
}

const retryDelayMs = (attempt) => [60_000, 5 * 60_000, 30 * 60_000, 2 * 60 * 60_000][Math.min(Math.max(attempt - 1, 0), 3)];
const clearLease = (delivery) => ({ ...delivery, lease_hmac_sha256: null, lease_expires_at: null });

async function failDelivery(store, key, entry, code, now) {
  const delivery = entry.record.arc1_delivery;
  const terminal = delivery.attempt_count >= INTAKE_ARC1_MAX_ATTEMPTS || code === 'EVIDENCE_EXPIRED' ||
    code === 'DELIVERY_INDEX_CONFLICT' || code === 'ACK_INDEX_CONFLICT';
  const next = terminal ? {
    ...clearLease(delivery), status: 'DEAD_LETTER', dead_lettered_at: now.toISOString(), next_attempt_at: now.toISOString(),
    alert_status: 'PENDING', alert_code: delivery.attempt_count >= INTAKE_ARC1_MAX_ATTEMPTS ? 'MAX_ATTEMPTS' : code,
    alert_updated_at: now.toISOString(),
  } : {
    ...clearLease(delivery), status: 'PENDING', next_attempt_at: new Date(now.getTime() + retryDelayMs(delivery.attempt_count)).toISOString(),
    alert_status: 'PENDING', alert_code: code, alert_updated_at: now.toISOString(),
  };
  const replaced = await replaceSubmission(store, key, entry, { ...entry.record, arc1_delivery: next });
  return { state: replaced.record.arc1_delivery.status, retryAt: next.next_attempt_at, code: next.alert_code };
}

export async function deliverIntakeToArc1(submissionId, env, adapters = {}) {
  assertPublicIntakeAuthority(env);
  const clock = adapters.clock || (() => new Date());
  let now = new Date(clock());
  submissionId = String(submissionId || '').toLowerCase();
  if (!UUID_PATTERN.test(submissionId)) throw new TypeError('Submission identity is invalid.');
  if (env[INTAKE_ARC1_BRIDGE_ENABLED_ENV] !== 'true') throw new Error('ARC1_BRIDGE_DISABLED');
  if (!Number.isFinite(now.getTime())) throw new TypeError('Bridge clock is invalid.');
  const store = adapters.store;
  if (!store) throw new TypeError('ARC1 bridge store is required.');
  const fetchImpl = adapters.fetch || fetch;
  const uuid = adapters.uuid || randomUUID;
  const key = `submissions/${submissionId}`;
  let entry = await readSubmission(store, key);
  if (!entry) return { state: 'NOT_FOUND' };
  // Terminal replay is a local durable fact. It must not require live secrets,
  // retrieval, proof, or network after a revocation.
  const storedDelivery = entry.record.arc1_delivery;
  if (storedDelivery.status === 'ACKED') return { state: 'ACKED', idempotentReplay: true };
  if (storedDelivery.status === 'DEAD_LETTER') return { state: 'DEAD_LETTER', idempotentReplay: true };
  if (env.ARC_INTAKE_ASSET_RETRIEVAL_ENABLED !== 'true') throw new Error('ARC1_ASSET_RETRIEVAL_DISABLED');
  const resolved = resolveArc1BridgeEnvironment(env);
  if (!intakeArc1AdapterAttested(env[INTAKE_ARC1_ADAPTER_PROOF_ENV], env.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET, now,
    resolved.endpoint, resolved.privateAssets.endpoint, resolved.siteId)) throw new Error('ARC1_ADAPTER_PROOF_INVALID');
  const current = entry.record.arc1_delivery;
  if (current.status === 'CLAIMED' && Date.parse(current.lease_expires_at) > now.getTime()) return { state: 'IN_PROGRESS', retryAt: current.lease_expires_at };
  if (current.status === 'PENDING' && Date.parse(current.next_attempt_at) > now.getTime()) return { state: 'RETRY_PENDING', retryAt: current.next_attempt_at };
  if (current.evidence_expires_at && Date.parse(current.evidence_expires_at) <= now.getTime()) return failDelivery(store, key, entry, 'EVIDENCE_EXPIRED', now);
  if (current.attempt_count >= INTAKE_ARC1_MAX_ATTEMPTS) return failDelivery(store, key, entry, 'MAX_ATTEMPTS', now);

  // This is the final local boundary before ARC1 evidence, durable delivery
  // state, or network. A signed mailbox verification release is mandatory even
  // if another dispatcher bypasses the foreground intake route.
  await consumeVerifiedIntakeForArc1(entry.record, env, store, { clock });

  const evidenceIssuedAt = current.evidence_issued_at || now.toISOString();
  const evidenceExpiresAt = current.evidence_expires_at || new Date(now.getTime() + INTAKE_ARC1_EVIDENCE_TTL_MS).toISOString();
  const provisional = {
    ...current, status: 'CLAIMED', attempt_count: current.attempt_count + 1, next_attempt_at: now.toISOString(),
    lease_hmac_sha256: hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET, `arc-intake-arc1-lease-v1\n${uuid()}`),
    lease_expires_at: new Date(now.getTime() + INTAKE_ARC1_LEASE_MS).toISOString(), last_attempt_at: now.toISOString(),
    evidence_issued_at: evidenceIssuedAt, evidence_expires_at: evidenceExpiresAt, evidence_sha256: '0'.repeat(64),
  };
  const provisionalRecord = { ...entry.record, arc1_delivery: provisional };
  const firstEnvelope = createBridgeEnvelope(provisionalRecord, provisional, resolved);
  provisional.evidence_sha256 = firstEnvelope.evidenceSha256;
  const claimedRecord = { ...entry.record, arc1_delivery: provisional };
  const envelope = createBridgeEnvelope(claimedRecord, provisional, resolved);
  if (envelope.evidenceSha256 !== provisional.evidence_sha256) throw new Error('ARC1_BRIDGE_EVIDENCE_UNSTABLE');
  entry = await replaceSubmission(store, key, entry, claimedRecord);

  // Make exact immutable grants retrievable before delivery. Create-only or
  // exact replay means an ambiguous retry cannot redirect a grant to new bytes.
  try {
    for (const index of privateAssetIndexEntries(entry.record, envelope.envelope.evidence.asset_manifest, {
      deliveryId: envelope.deliveryId, evidenceSha256: envelope.evidenceSha256, expiresAt: evidenceExpiresAt,
    })) await ensureIndex(store, index.key, index.value);
  } catch {
    now = new Date(clock());
    return failDelivery(store, key, entry, 'DELIVERY_INDEX_CONFLICT', now);
  }

  const deliveryIndexKey = `arc1-delivery-index/${hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET, `arc-intake-arc1-delivery-index-v1\n${envelope.deliveryId}`)}`;
  try {
    await ensureIndex(store, deliveryIndexKey, {
      schema: 'arc-intake-arc1-delivery-index-v1', delivery_id_sha256: sha256(envelope.deliveryId), evidence_sha256: envelope.evidenceSha256,
      source_key_hmac_sha256: sourceKeyHmac(entry.record, resolved),
    });
  } catch {
    now = new Date(clock());
    return failDelivery(store, key, entry, 'DELIVERY_INDEX_CONFLICT', now);
  }

  let response;
  try {
    response = await fetchImpl(resolved.endpoint, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(30_000),
      headers: {
        Authorization: `Bearer ${resolved.ARC_INTAKE_ARC1_DESTINATION_BEARER}`,
        'Content-Type': 'application/json; charset=utf-8', 'Idempotency-Key': envelope.deliveryId,
        'X-ARC-Bridge-Contract': INTAKE_ARC1_CONTRACT_SHA256,
      },
      body: envelope.raw,
    });
  } catch {
    now = new Date(clock());
    return failDelivery(store, key, entry, 'DELIVERY_UNAVAILABLE', now);
  }
  if (!response || response.status < 200 || response.status >= 300 || response.url && response.url !== resolved.endpoint) {
    now = new Date(clock());
    return failDelivery(store, key, entry, 'DELIVERY_HTTP_FAILURE', now);
  }
  const declaredLength = response.headers?.get?.('content-length');
  if (declaredLength && (!/^\d{1,8}$/.test(declaredLength) || Number(declaredLength) > INTAKE_ARC1_MAX_ACK_BYTES)) {
    now = new Date(clock());
    return failDelivery(store, key, entry, 'INVALID_ACK', now);
  }
  let acknowledgement;
  try {
    acknowledgement = validateAcknowledgement(await readBoundedText(response, INTAKE_ARC1_MAX_ACK_BYTES), {
      deliveryId: envelope.deliveryId, evidenceSha256: envelope.evidenceSha256, evidenceIssuedAt,
    }, resolved, clock());
  } catch {
    now = new Date(clock());
    return failDelivery(store, key, entry, 'INVALID_ACK', now);
  }
  const ackIndexKey = `arc1-ack-index/${hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET, `arc-intake-arc1-ack-index-v1\n${acknowledgement.ack.ack_id}`)}`;
  try {
    await ensureIndex(store, ackIndexKey, {
      schema: 'arc-intake-arc1-ack-index-v1', delivery_id_sha256: sha256(envelope.deliveryId), evidence_sha256: envelope.evidenceSha256,
      acknowledgement_sha256: acknowledgement.digest,
    });
  } catch {
    now = new Date(clock());
    return failDelivery(store, key, entry, 'ACK_INDEX_CONFLICT', now);
  }
  now = new Date(clock());
  const acknowledged = {
    ...clearLease(entry.record.arc1_delivery), status: 'ACKED', next_attempt_at: now.toISOString(), acknowledged_at: now.toISOString(),
    acknowledgement_sha256: acknowledgement.digest, consumer_claim_key_hmac_sha256: acknowledgement.ack.consumer_claim_key_hmac_sha256,
    alert_status: entry.record.arc1_delivery.alert_status === 'PENDING' ? 'RESOLVED' : 'NONE', alert_code: null,
    alert_updated_at: entry.record.arc1_delivery.alert_status === 'PENDING' ? now.toISOString() : null,
  };
  entry = await replaceSubmission(store, key, entry, { ...entry.record, arc1_delivery: acknowledged });
  return { state: 'ACKED', idempotentReplay: false, deliveryId: envelope.deliveryId };
}

export function authorizeBridgeRun(request, env) {
  try {
    const expected = secret(env.ARC_INTAKE_ARC1_RUN_SECRET, 'ARC_INTAKE_ARC1_RUN_SECRET');
    const supplied = request.headers.get('authorization');
    return supplied?.startsWith('Bearer ') === true && safeEqual(supplied.slice(7), expected);
  } catch { return false; }
}
