import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';

import {
  INTAKE_ARC1_ACK_SCHEMA,
  INTAKE_ARC1_ADAPTER_PROOF_ENV,
  INTAKE_ARC1_CONSUMER_SCHEMA,
  INTAKE_ARC1_CONTRACT_SHA256,
  canonicalJson,
  createBridgeEnvelope,
  intakeArc1AdapterAttested,
  normalizeStoredIntakeSubmissionForBridge,
  resolveArc1BridgeEnvironment,
} from './intake-arc1-bridge-core.mjs';
import { createPrivateAssetGrants, retrievePrivateAsset } from './intake-private-asset-core.mjs';

export const INTAKE_ARC1_ADAPTER_ENABLED_ENV = 'ARC_INTAKE_ARC1_ADAPTER_ENABLED';
export const INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV = 'ARC_INTAKE_ARC1_DOWNSTREAM_ENABLED';
export const INTAKE_ARC1_ADAPTER_STORE = 'arc-intake-arc1-adapter';
export const INTAKE_ARC1_ADAPTER_RECORD_SCHEMA = 'arc-intake-arc1-adapter-ingress-v1';
export const INTAKE_ARC1_ADAPTER_DISPATCH_SCHEMA = 'arc-intake-arc1-adapter-dispatch-v1';
export const INTAKE_ARC1_ADAPTER_PACKET_SCHEMA = 'arc-intake-arc1-downstream-dispatch-v1';
export const INTAKE_ARC1_ADAPTER_PENDING_INDEX_SCHEMA = 'arc-intake-arc1-adapter-pending-index-v1';
export const INTAKE_ARC1_ADAPTER_BACKGROUND_SCHEMA = 'arc-intake-arc1-adapter-background-request-v1';
export const INTAKE_ARC1_ADAPTER_ENDPOINT_PATH = '/internal/intake/arc1/adapter';
export const INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS = 5;
export const INTAKE_ARC1_ADAPTER_LEASE_MS = 2 * 60_000;
export const INTAKE_ARC1_ADAPTER_MAX_PACKET_BYTES = 1_000_000;
export const INTAKE_ARC1_ADAPTER_RECOVERY_MAX_READS = 100;
export const INTAKE_ARC1_ADAPTER_RECOVERY_MAX_ATTEMPTS = 20;
export const INTAKE_ARC1_ADAPTER_RECOVERY_MAX_PAGES = 20;
export const INTAKE_ARC1_ADAPTER_RECOVERY_BUDGET_MS = 8_000;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const RECOVERY_CURSOR_VERSION = 1;
const RECOVERY_SHARD_COUNT = 256;
const ADAPTER_RECORD_FIELDS = Object.freeze([
  'acknowledgement_json', 'acknowledgement_sha256', 'asset_count', 'asset_receipt_hmac_sha256',
  'asset_receipt_sha256', 'bridge_evidence_sha256', 'claim_created_at', 'consumer_claim_key_hmac_sha256',
  'contains_direct_customer_content', 'delivery_id', 'dispatch', 'envelope_sha256', 'ingress_state_digest_sha256',
  'ingress_state_key', 'packet_sha256', 'schema', 'source_submission_id', 'total_asset_bytes',
]);
const DISPATCH_FIELDS = Object.freeze([
  'accepted_at', 'alert_code', 'alert_status', 'alert_updated_at', 'attempt_count', 'last_attempt_at',
  'lease_expires_at', 'lease_hmac_sha256', 'next_attempt_at', 'schema', 'status',
]);
const PENDING_INDEX_FIELDS = Object.freeze(['delivery_id_sha256', 'ingress_key', 'schema']);

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const exactKeys = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
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
const retryDelayMs = (attempt) => [60_000, 5 * 60_000, 30 * 60_000, 2 * 60 * 60_000][Math.min(Math.max(attempt - 1, 0), 3)];

function wallNow(adapters) {
  const value = (adapters.wallClock || Date.now)();
  if (!Number.isFinite(value)) throw new TypeError('ARC1 adapter recovery wall clock is invalid.');
  return value;
}

function recoverySequenceInitial(resolved, shard, prefix) {
  return hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET,
    `arc-intake-arc1-adapter-recovery-sequence-v1\n${shard}\n${prefix}`);
}

function recoverySequenceNext(resolved, previous, key) {
  return hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET,
    `arc-intake-arc1-adapter-recovery-sequence-step-v1\n${previous}\n${Buffer.byteLength(key, 'utf8')}\n${key}`);
}

function encodeRecoveryCursor(value, resolved) {
  if (!Number.isInteger(value.shard) || value.shard < 0 || value.shard >= RECOVERY_SHARD_COUNT ||
      !Number.isSafeInteger(value.position) || value.position < 0 ||
      !(value.sequence_hmac_sha256 === null ? value.position === 0 : value.position > 0 && SHA256_PATTERN.test(value.sequence_hmac_sha256))) {
    throw new TypeError('ARC1 adapter recovery cursor is invalid.');
  }
  const raw = Buffer.from(canonicalJson({
    version: RECOVERY_CURSOR_VERSION, shard: value.shard, position: value.position,
    sequence_hmac_sha256: value.sequence_hmac_sha256,
  }), 'utf8').toString('base64url');
  return `${raw}.${hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET, `arc-intake-arc1-adapter-recovery-cursor-v1\n${raw}`)}`;
}

function decodeRecoveryCursor(token, resolved) {
  if (token === null || token === undefined || token === '') return { shard: 0, position: 0, sequence_hmac_sha256: null };
  if (typeof token !== 'string' || token.length > 512 || !/^[A-Za-z0-9_-]+\.[a-f0-9]{64}$/.test(token)) {
    throw new TypeError('ARC1 adapter recovery cursor is invalid.');
  }
  const [raw, supplied] = token.split('.');
  if (!safeEqual(supplied, hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET,
    `arc-intake-arc1-adapter-recovery-cursor-v1\n${raw}`))) throw new TypeError('ARC1 adapter recovery cursor signature mismatch.');
  let value;
  try { value = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')); } catch { throw new TypeError('ARC1 adapter recovery cursor is invalid.'); }
  if (!exactKeys(value, ['position', 'sequence_hmac_sha256', 'shard', 'version']) || value.version !== RECOVERY_CURSOR_VERSION ||
      !Number.isInteger(value.shard) || value.shard < 0 || value.shard >= RECOVERY_SHARD_COUNT ||
      !Number.isSafeInteger(value.position) || value.position < 0 ||
      !(value.sequence_hmac_sha256 === null ? value.position === 0 : value.position > 0 && SHA256_PATTERN.test(value.sequence_hmac_sha256))) {
    throw new TypeError('ARC1 adapter recovery cursor is invalid.');
  }
  return { shard: value.shard, position: value.position, sequence_hmac_sha256: value.sequence_hmac_sha256 };
}

function requestRecoveryCursor(request, adapters) {
  if (Object.hasOwn(adapters, 'cursor')) return adapters.cursor;
  let url;
  try { url = new URL(request.url); } catch { throw new TypeError('ARC1 adapter recovery request URL is invalid.'); }
  const values = url.searchParams.getAll('cursor');
  if (values.length > 1) throw new TypeError('ARC1 adapter recovery cursor is ambiguous.');
  return values[0] || null;
}

function exactOrigin(value, label) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError(`${label} is invalid.`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.pathname !== '/' || url.search || url.hash ||
      !['arcweb.onl', 'arcsites.netlify.app'].includes(url.hostname)) throw new TypeError(`${label} is invalid.`);
  return url.origin;
}

function exactDownstreamEndpoint(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('ARC1 downstream endpoint is invalid.'); }
  if (url.protocol !== 'https:' || url.hostname !== 'hooks.zapier.com' || url.username || url.password || url.port || url.search || url.hash ||
      !/^\/hooks\/catch\/[1-9][0-9]{0,19}\/[A-Za-z0-9_-]{5,128}\/$/.test(url.pathname)) {
    throw new TypeError('ARC1 downstream endpoint must be one exact Zapier Catch Hook URL.');
  }
  return url.toString();
}

export function resolveArc1AdapterEnvironment(env) {
  const bridge = resolveArc1BridgeEnvironment(env);
  const origin = exactOrigin(env.URL, 'ARC1 adapter origin');
  if (bridge.endpoint !== `${origin}${INTAKE_ARC1_ADAPTER_ENDPOINT_PATH}`) {
    throw new TypeError('ARC1 bridge endpoint must be the first-party adapter.');
  }
  const assetReceiptSecret = secret(env.ARC1_ASSET_RECEIPT_SECRET, 'ARC1_ASSET_RECEIPT_SECRET');
  const downstreamBearer = secret(env.ARC_INTAKE_ARC1_DOWNSTREAM_BEARER, 'ARC_INTAKE_ARC1_DOWNSTREAM_BEARER');
  const dispatchSecret = secret(env.ARC_INTAKE_ARC1_DISPATCH_SECRET, 'ARC_INTAKE_ARC1_DISPATCH_SECRET');
  const downstreamEndpoint = exactDownstreamEndpoint(env.ARC_INTAKE_ARC1_DOWNSTREAM_ENDPOINT);
  const allSecrets = [
    bridge.ARC_INTAKE_ARC1_RUN_SECRET, bridge.ARC_INTAKE_ARC1_DESTINATION_BEARER,
    bridge.ARC_INTAKE_ARC1_EVIDENCE_SECRET, bridge.ARC_INTAKE_ARC1_ACK_SECRET,
    bridge.ARC_INTAKE_ARC1_STATE_SECRET, bridge.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET,
    bridge.ARC_INTAKE_ASSET_RETRIEVAL_SECRET, assetReceiptSecret, downstreamBearer, dispatchSecret,
  ];
  if (new Set(allSecrets).size !== allSecrets.length) throw new TypeError('ARC1 adapter secrets must be distinct.');
  return { ...bridge, origin, assetReceiptSecret, downstreamBearer, dispatchSecret, downstreamEndpoint };
}

export function validateArc1AdapterDispatch(value) {
  if (!exactKeys(value, DISPATCH_FIELDS) || value.schema !== INTAKE_ARC1_ADAPTER_DISPATCH_SCHEMA ||
      !['PENDING', 'CLAIMED', 'HOOK_ACCEPTED', 'DEAD_LETTER'].includes(value.status) ||
      !Number.isSafeInteger(value.attempt_count) || value.attempt_count < 0 || value.attempt_count > INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS ||
      !['NONE', 'PENDING', 'RESOLVED'].includes(value.alert_status) ||
      ![null, 'QUEUE_UNAVAILABLE', 'DOWNSTREAM_UNAVAILABLE', 'DOWNSTREAM_REJECTED', 'DOWNSTREAM_SOURCE_UNAVAILABLE',
        'DOWNSTREAM_RECONSTRUCTION_CONFLICT', 'DOWNSTREAM_MAX_ATTEMPTS'].includes(value.alert_code)) {
    throw new TypeError('ARC1 adapter dispatch state is invalid.');
  }
  iso(value.next_attempt_at, 'adapter next_attempt_at');
  for (const field of ['accepted_at', 'alert_updated_at', 'last_attempt_at', 'lease_expires_at']) nullableIso(value[field], field);
  nullableSha(value.lease_hmac_sha256, 'adapter lease_hmac_sha256');
  if ((value.lease_hmac_sha256 === null) !== (value.lease_expires_at === null)) throw new TypeError('ARC1 adapter lease is incomplete.');
  if (value.status === 'PENDING' && (value.accepted_at !== null || value.lease_hmac_sha256 !== null)) {
    throw new TypeError('Pending ARC1 adapter dispatch is inconsistent.');
  }
  if (value.status === 'CLAIMED' && (!value.lease_hmac_sha256 || !value.lease_expires_at || !value.last_attempt_at)) {
    throw new TypeError('Claimed ARC1 adapter dispatch is incomplete.');
  }
  if (value.status === 'CLAIMED' && value.accepted_at !== null) throw new TypeError('Claimed ARC1 adapter dispatch is inconsistent.');
  if (value.status === 'HOOK_ACCEPTED' && (!value.accepted_at || value.attempt_count < 1 || value.lease_hmac_sha256 !== null ||
      value.alert_code !== null || value.alert_status === 'PENDING')) {
    throw new TypeError('Accepted ARC1 adapter dispatch is incomplete.');
  }
  if (value.status === 'DEAD_LETTER' && (value.attempt_count !== INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS || value.accepted_at !== null ||
      value.lease_hmac_sha256 !== null || value.alert_status !== 'PENDING' || value.alert_code !== 'DOWNSTREAM_MAX_ATTEMPTS')) {
    throw new TypeError('Dead-letter ARC1 adapter dispatch is incomplete.');
  }
  return value;
}

export function validateArc1AdapterRecord(value) {
  if (!exactKeys(value, ADAPTER_RECORD_FIELDS) || value.schema !== INTAKE_ARC1_ADAPTER_RECORD_SCHEMA ||
      !SHA256_PATTERN.test(value.delivery_id) || !SHA256_PATTERN.test(value.bridge_evidence_sha256) ||
      !UUID_PATTERN.test(value.source_submission_id) || !/^arc1-function-ingress-v1:[a-f0-9]{64}$/.test(value.ingress_state_key) ||
      value.ingress_state_key !== `arc1-function-ingress-v1:${value.ingress_state_digest_sha256}` ||
      ![value.envelope_sha256, value.ingress_state_digest_sha256, value.asset_receipt_sha256, value.asset_receipt_hmac_sha256,
        value.consumer_claim_key_hmac_sha256, value.acknowledgement_sha256, value.packet_sha256].every((item) => SHA256_PATTERN.test(item)) ||
      typeof value.acknowledgement_json !== 'string' || sha256(value.acknowledgement_json) !== value.acknowledgement_sha256 ||
      !Number.isSafeInteger(value.asset_count) || value.asset_count < 0 || value.asset_count > 3 ||
      !Number.isSafeInteger(value.total_asset_bytes) || value.total_asset_bytes < 0 || value.total_asset_bytes > 3_020_000 ||
      value.contains_direct_customer_content !== false) throw new TypeError('ARC1 adapter record is invalid.');
  iso(value.claim_created_at, 'adapter claim_created_at');
  validateArc1AdapterDispatch(value.dispatch);
  return value;
}

function adapterKey(deliveryId, resolved) {
  return `ingress/${hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET, `arc-intake-arc1-adapter-record-v1\n${deliveryId}`)}`;
}

function pendingKey(deliveryId, resolved) {
  return `pending/${hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET, `arc-intake-arc1-adapter-pending-v1\n${deliveryId}`)}`;
}

function initialDispatch(now) {
  return {
    schema: INTAKE_ARC1_ADAPTER_DISPATCH_SCHEMA, status: 'PENDING', attempt_count: 0,
    next_attempt_at: now.toISOString(), lease_hmac_sha256: null, lease_expires_at: null,
    last_attempt_at: null, accepted_at: null, alert_status: 'NONE', alert_code: null, alert_updated_at: null,
  };
}

function deriveAdapterArtifacts(record, envelopeRaw, resolved, claimCreatedAt, now) {
  record = normalizeStoredIntakeSubmissionForBridge(record);
  const rebuilt = createBridgeEnvelope(record, record.arc1_delivery, resolved);
  if (!safeEqual(rebuilt.raw, envelopeRaw)) throw new Error('ARC1_ADAPTER_ENVELOPE_CONFLICT');
  const envelope = rebuilt.envelope;
  const evidence = envelope.evidence;
  const nowMs = new Date(now).getTime();
  const receivedMs = Date.parse(evidence.received_at);
  const issuedMs = Date.parse(evidence.evidence_issued_at);
  const expiresMs = Date.parse(evidence.evidence_expires_at);
  if (!Number.isFinite(nowMs) || receivedMs < nowMs - 24 * 60 * 60_000 || receivedMs > nowMs + 5 * 60_000 ||
      issuedMs < receivedMs - 5 * 60_000 || issuedMs > nowMs + 5 * 60_000 || expiresMs <= nowMs ||
      expiresMs > issuedMs + 24 * 60 * 60_000) throw new Error('ARC1_ADAPTER_EVIDENCE_STALE');
  const evidenceRaw = canonicalJson(evidence);
  const bridgeEvidenceSha256 = sha256(evidenceRaw);
  const expectedSiteHash = sha256(resolved.siteId);
  const grants = createPrivateAssetGrants(record, resolved.privateAssets);
  if (!safeEqual(canonicalJson(grants), canonicalJson(evidence.asset_manifest))) throw new Error('ARC1_ADAPTER_ASSET_CONFLICT');
  const assetManifest = grants.map((grant) => ({
    asset_id: grant.asset_id, kind: grant.kind, role: grant.role, content_type: grant.content_type,
    size_bytes: grant.size, sha256: grant.sha256, retrieval_endpoint_sha256: grant.retrieval_endpoint_sha256,
  }));
  const assetManifestSha256 = sha256(canonicalJson(assetManifest));
  const totalAssetBytes = grants.reduce((total, grant) => total + grant.size, 0);
  const publicFolderPrefix = sha256([
    'arc-preview-folder-v2', INTAKE_ARC1_CONTRACT_SHA256, expectedSiteHash, evidence.submission_id, evidence.received_at,
  ].join('\n')).slice(0, 8);
  const stateBinding = {
    version: 'arc1-intake-state-v2', bridge_contract_sha256: INTAKE_ARC1_CONTRACT_SHA256,
    site_id_sha256: expectedSiteHash, delivery_id: evidence.delivery_id, submission_id: evidence.submission_id,
    received_at: evidence.received_at, public_folder_prefix: publicFolderPrefix,
    submission_data_sha256: evidence.submission_data_sha256, asset_manifest: assetManifest,
  };
  const stateDigestSha256 = sha256(canonicalJson(stateBinding));
  const stateKey = `arc1-intake-claim-v2:${stateDigestSha256}`;
  const arc1Evidence = {
    version: 'arc1-intake-evidence-v2', scope: 'authoritative-first-party-function-intake',
    bridge_contract_sha256: INTAKE_ARC1_CONTRACT_SHA256, site_id_sha256: expectedSiteHash,
    source_schema: evidence.source_schema, source_form_name: evidence.source_form_name,
    source_key_hmac_sha256: evidence.source_key_hmac_sha256, delivery_id: evidence.delivery_id,
    submission_id: evidence.submission_id, received_at: evidence.received_at, intake_version: evidence.data.intake_version,
    budget_confirmed: evidence.data.budget_confirmed, terms_accepted: evidence.data.terms_accepted,
    asset_permission: grants.length > 0 ? evidence.data.asset_permission : '', public_folder_prefix: publicFolderPrefix,
    submission_data_sha256: evidence.submission_data_sha256, asset_manifest: assetManifest,
    asset_manifest_sha256: assetManifestSha256, total_asset_bytes: totalAssetBytes,
    state_key: stateKey, state_digest_sha256: stateDigestSha256, claim_required_before_build: true,
    issued_at: evidence.evidence_issued_at,
  };
  const arc1EvidenceSha256 = sha256(canonicalJson(arc1Evidence));
  const ingressStateDigestSha256 = sha256(canonicalJson({
    version: INTAKE_ARC1_CONSUMER_SCHEMA, bridge_contract_sha256: INTAKE_ARC1_CONTRACT_SHA256,
    delivery_id: evidence.delivery_id, bridge_evidence_sha256: bridgeEvidenceSha256,
    arc1_evidence_sha256: arc1EvidenceSha256, state_key: stateKey, state_digest_sha256: stateDigestSha256,
  }));
  const ingressStateKey = `arc1-function-ingress-v1:${ingressStateDigestSha256}`;
  const receipt = {
    version: 'arc1-private-asset-receipt-v1', scope: 'authenticated-content-addressed-intake-assets',
    bridge_contract_sha256: INTAKE_ARC1_CONTRACT_SHA256, delivery_id: evidence.delivery_id,
    bridge_evidence_sha256: bridgeEvidenceSha256, retrieval_endpoint_sha256: resolved.privateAssets.endpointSha256,
    asset_manifest_sha256: assetManifestSha256, asset_count: assetManifest.length,
    total_asset_bytes: totalAssetBytes, status: 'VERIFIED',
  };
  const assetReceiptPrivate = canonicalJson(receipt);
  const assetReceiptSha256 = sha256(assetReceiptPrivate);
  const assetReceiptHmacSha256 = hmac(resolved.assetReceiptSecret,
    `arc1-private-asset-receipt-signature-v1\n${assetReceiptPrivate}`);
  const consumerClaimKeyHmacSha256 = hmac(resolved.ARC_INTAKE_ARC1_ACK_SECRET,
    `arc1-function-intake-consumer-claim-v1\n${ingressStateKey}`);
  const ackIdentity = hmac(resolved.ARC_INTAKE_ARC1_ACK_SECRET,
    `arc1-function-intake-ack-id-v1\n${evidence.delivery_id}\n${bridgeEvidenceSha256}\n${assetReceiptSha256}`);
  const acknowledgement = {
    schema: INTAKE_ARC1_ACK_SCHEMA, version: 1, status: 'ACCEPTED', consumer_schema: INTAKE_ARC1_CONSUMER_SCHEMA,
    bridge_contract_sha256: INTAKE_ARC1_CONTRACT_SHA256, delivery_id: evidence.delivery_id,
    evidence_sha256: bridgeEvidenceSha256, asset_receipt_sha256: assetReceiptSha256,
    consumer_claim_key_hmac_sha256: consumerClaimKeyHmacSha256,
    ack_id: `arc1ack_${ackIdentity.slice(0, 40)}`, received_at: evidence.evidence_issued_at,
  };
  const acknowledgementRaw = canonicalJson(acknowledgement);
  const acknowledgementJson = canonicalJson({ acknowledgement, hmac_sha256: hmac(resolved.ARC_INTAKE_ARC1_ACK_SECRET,
    `arc-intake-arc1-consumer-ack-v1\n${acknowledgementRaw}`) });
  const packet = {
    schema: INTAKE_ARC1_ADAPTER_PACKET_SCHEMA, bridge_envelope_json: envelopeRaw,
    consumer_schema: INTAKE_ARC1_CONSUMER_SCHEMA, bridge_contract_sha256: INTAKE_ARC1_CONTRACT_SHA256,
    bridge_delivery_id: evidence.delivery_id, bridge_evidence_sha256: bridgeEvidenceSha256,
    bridge_evidence_expires_at: evidence.evidence_expires_at, bridge_evidence_issued_at: evidence.evidence_issued_at,
    asset_receipt_private: assetReceiptPrivate, asset_receipt_hmac_sha256: assetReceiptHmacSha256,
    asset_receipt_sha256: assetReceiptSha256, ingress_state_key: ingressStateKey,
    ingress_state_digest_sha256: ingressStateDigestSha256, ingress_claim_mode: 'CREATED',
    ingress_claim_status: 'CLAIMED', ingress_claim_state_key: ingressStateKey,
    ingress_claim_state_digest_sha256: ingressStateDigestSha256,
    ingress_claim_bridge_delivery_id: evidence.delivery_id,
    ingress_claim_bridge_evidence_sha256: bridgeEvidenceSha256,
    ingress_claim_asset_receipt_sha256: assetReceiptSha256, ingress_claim_created_at: claimCreatedAt,
  };
  const packetRaw = canonicalJson(packet);
  if (Buffer.byteLength(packetRaw, 'utf8') > INTAKE_ARC1_ADAPTER_MAX_PACKET_BYTES) throw new Error('ARC1_ADAPTER_PACKET_TOO_LARGE');
  return {
    acknowledgementJson, assetCount: assetManifest.length, assetReceiptHmacSha256, assetReceiptSha256,
    bridgeEvidenceSha256, consumerClaimKeyHmacSha256, ingressStateDigestSha256, ingressStateKey,
    packetRaw, packetSha256: sha256(packetRaw), totalAssetBytes,
  };
}

async function verifyAuthoritativePrivateAssets(record, evidence, env, resolved, sourceStore, now) {
  const grants = createPrivateAssetGrants(normalizeStoredIntakeSubmissionForBridge(record), resolved.privateAssets);
  for (const grant of grants) {
    const retrieved = await retrievePrivateAsset({
      schema: 'arc-intake-private-asset-request-v1', asset_id: grant.asset_id,
      delivery_id: evidence.delivery_id, evidence_sha256: sha256(canonicalJson(evidence)),
    }, env, { store: sourceStore, now });
    if (!safeEqual(canonicalJson(retrieved.grant), canonicalJson(grant))) throw new Error('ARC1_ADAPTER_ASSET_CONFLICT');
  }
}

async function readEntry(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  return entry ? { value: validateArc1AdapterRecord(entry.data), etag: entry.etag } : null;
}

async function replaceEntry(store, key, entry, value) {
  validateArc1AdapterRecord(value);
  const result = await store.setJSON(key, value, { onlyIfMatch: entry.etag });
  if (!result?.modified || !result.etag) throw new Error('ARC1_ADAPTER_STATE_CONTENTION');
  return { value, etag: result.etag };
}

async function ensurePendingIndex(store, deliveryId, resolved) {
  const key = pendingKey(deliveryId, resolved);
  const expected = { schema: INTAKE_ARC1_ADAPTER_PENDING_INDEX_SCHEMA, delivery_id_sha256: sha256(deliveryId), ingress_key: adapterKey(deliveryId, resolved) };
  const existing = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (existing) {
    if (!exactKeys(existing.data, PENDING_INDEX_FIELDS) || canonicalJson(existing.data) !== canonicalJson(expected)) {
      throw new Error('ARC1_ADAPTER_PENDING_INDEX_CONFLICT');
    }
    return;
  }
  const result = await store.setJSON(key, expected, { onlyIfNew: true });
  if (result?.modified) return;
  const raced = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!raced || !exactKeys(raced.data, PENDING_INDEX_FIELDS) || canonicalJson(raced.data) !== canonicalJson(expected)) {
    throw new Error('ARC1_ADAPTER_PENDING_INDEX_CONFLICT');
  }
}

async function removePendingIndex(store, deliveryId, resolved) {
  if (typeof store.delete === 'function') await store.delete(pendingKey(deliveryId, resolved));
}

function immutableRecordFrom(artifacts, evidence, envelopeRaw, claimCreatedAt) {
  return {
    schema: INTAKE_ARC1_ADAPTER_RECORD_SCHEMA, delivery_id: evidence.delivery_id,
    bridge_evidence_sha256: artifacts.bridgeEvidenceSha256, source_submission_id: evidence.submission_id,
    ingress_state_key: artifacts.ingressStateKey, ingress_state_digest_sha256: artifacts.ingressStateDigestSha256,
    claim_created_at: claimCreatedAt, asset_receipt_sha256: artifacts.assetReceiptSha256,
    asset_receipt_hmac_sha256: artifacts.assetReceiptHmacSha256, asset_count: artifacts.assetCount,
    total_asset_bytes: artifacts.totalAssetBytes, consumer_claim_key_hmac_sha256: artifacts.consumerClaimKeyHmacSha256,
    acknowledgement_json: artifacts.acknowledgementJson, acknowledgement_sha256: sha256(artifacts.acknowledgementJson),
    envelope_sha256: sha256(envelopeRaw), packet_sha256: artifacts.packetSha256,
    contains_direct_customer_content: false,
  };
}

function sameImmutableRecord(stored, expected) {
  const projection = (value) => Object.fromEntries(ADAPTER_RECORD_FIELDS.filter((field) => field !== 'dispatch').map((field) => [field, value[field]]));
  return safeEqual(canonicalJson(projection(stored)), canonicalJson(expected));
}

export async function acceptArc1AdapterEnvelope(envelopeRaw, request, env, stores, adapters = {}) {
  if (env[INTAKE_ARC1_ADAPTER_ENABLED_ENV] !== 'true' || env[INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV] !== 'true' ||
      env.ARC_INTAKE_ASSET_RETRIEVAL_ENABLED !== 'true') {
    throw new Error('ARC1_ADAPTER_DISABLED');
  }
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('ARC1 adapter clock is invalid.');
  const resolved = resolveArc1AdapterEnvironment(env);
  if (new URL(request.url).toString() !== resolved.endpoint) throw new TypeError('ARC1 adapter request endpoint mismatch.');
  const authorization = request.headers.get('authorization') || '';
  if (!authorization.startsWith('Bearer ') || !safeEqual(authorization.slice(7), resolved.ARC_INTAKE_ARC1_DESTINATION_BEARER)) {
    throw new Error('ARC1_ADAPTER_UNAUTHORIZED');
  }
  if (request.headers.get('x-arc-bridge-contract') !== INTAKE_ARC1_CONTRACT_SHA256) throw new TypeError('ARC1 adapter contract header mismatch.');
  let parsed;
  try { parsed = JSON.parse(envelopeRaw); } catch { throw new TypeError('ARC1 adapter envelope is not JSON.'); }
  if (canonicalJson(parsed) !== envelopeRaw || parsed?.schema !== 'arc-intake-arc1-bridge-envelope-v1' || !SHA256_PATTERN.test(parsed?.evidence?.delivery_id)) {
    throw new TypeError('ARC1 adapter envelope is invalid.');
  }
  if (!UUID_PATTERN.test(parsed?.evidence?.submission_id)) throw new TypeError('ARC1 adapter submission id is invalid.');
  if (request.headers.get('idempotency-key') !== parsed.evidence.delivery_id) throw new TypeError('ARC1 adapter idempotency key mismatch.');
  const evidenceRaw = canonicalJson(parsed.evidence);
  if (!safeEqual(parsed.hmac_sha256, hmac(resolved.ARC_INTAKE_ARC1_EVIDENCE_SECRET,
    `arc-intake-arc1-bridge-evidence-v1\n${evidenceRaw}`))) throw new Error('ARC1_ADAPTER_ENVELOPE_CONFLICT');
  const key = adapterKey(parsed.evidence.delivery_id, resolved);
  let existing = await readEntry(stores.adapter, key);
  if (existing) {
    if (!safeEqual(existing.value.envelope_sha256, sha256(envelopeRaw)) ||
        !safeEqual(existing.value.bridge_evidence_sha256, sha256(evidenceRaw)) ||
        existing.value.source_submission_id !== parsed.evidence.submission_id) throw new Error('ARC1_ADAPTER_INGRESS_CONFLICT');
    if (!['HOOK_ACCEPTED', 'DEAD_LETTER'].includes(existing.value.dispatch.status)) {
      await ensurePendingIndex(stores.adapter, parsed.evidence.delivery_id, resolved);
    }
    return { acknowledgementJson: existing.value.acknowledgement_json, created: false,
      deliveryId: parsed.evidence.delivery_id, record: existing.value };
  }
  if (!intakeArc1AdapterAttested(env[INTAKE_ARC1_ADAPTER_PROOF_ENV], resolved.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET, now,
    resolved.endpoint, resolved.privateAssets.endpoint, resolved.siteId)) throw new Error('ARC1_ADAPTER_PROOF_INVALID');
  const sourceEntry = await stores.source.getWithMetadata(`submissions/${parsed.evidence.submission_id}`, { type: 'json', consistency: 'strong' });
  if (!sourceEntry) throw new Error('ARC1_ADAPTER_SOURCE_MISSING');
  let claimCreatedAt = now.toISOString();
  let artifacts = deriveAdapterArtifacts(sourceEntry.data, envelopeRaw, resolved, claimCreatedAt, now);
  await verifyAuthoritativePrivateAssets(sourceEntry.data, parsed.evidence, env, resolved, stores.source, now);
  let immutable = immutableRecordFrom(artifacts, parsed.evidence, envelopeRaw, claimCreatedAt);
  let created = false;
  const value = { ...immutable, dispatch: initialDispatch(now) };
  validateArc1AdapterRecord(value);
  const result = await stores.adapter.setJSON(key, value, { onlyIfNew: true });
  if (result?.modified) {
    existing = { value, etag: result.etag };
    created = true;
  } else {
    existing = await readEntry(stores.adapter, key);
    if (existing) {
      claimCreatedAt = existing.value.claim_created_at;
      artifacts = deriveAdapterArtifacts(sourceEntry.data, envelopeRaw, resolved, claimCreatedAt, now);
      immutable = immutableRecordFrom(artifacts, parsed.evidence, envelopeRaw, claimCreatedAt);
    }
  }
  if (!existing || !sameImmutableRecord(existing.value, immutable)) throw new Error('ARC1_ADAPTER_INGRESS_CONFLICT');
  if (!['HOOK_ACCEPTED', 'DEAD_LETTER'].includes(existing.value.dispatch.status)) {
    await ensurePendingIndex(stores.adapter, parsed.evidence.delivery_id, resolved);
  }
  return { acknowledgementJson: existing.value.acknowledgement_json, created, deliveryId: parsed.evidence.delivery_id, record: existing.value };
}

async function convergeDispatch(store, key, mutate) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const current = await readEntry(store, key);
    if (!current) throw new Error('ARC1_ADAPTER_SOURCE_MISSING');
    const desired = mutate(current.value);
    if (desired === current.value) return current;
    try { return await replaceEntry(store, key, current, desired); } catch (error) {
      if (error?.message !== 'ARC1_ADAPTER_STATE_CONTENTION' || attempt === 3) throw error;
    }
  }
  throw new Error('ARC1_ADAPTER_STATE_CONTENTION');
}

export async function markArc1AdapterQueueUnavailable(deliveryId, env, store, adapters = {}) {
  const resolved = resolveArc1AdapterEnvironment(env);
  const now = new Date((adapters.clock || (() => new Date()))()).toISOString();
  return convergeDispatch(store, adapterKey(deliveryId, resolved), (record) => {
    if (['HOOK_ACCEPTED', 'DEAD_LETTER'].includes(record.dispatch.status)) return record;
    // A lost 202 response does not prove the background Function failed to
    // start. Preserve an active lease so the foreground caller cannot reopen
    // a record while its downstream request may already be in flight.
    if (record.dispatch.status === 'CLAIMED') return record;
    // A duplicate foreground retry must not erase a downstream failure or
    // pull its durable backoff forward merely because the new queue response
    // was ambiguous.
    if (record.dispatch.attempt_count > 0) return record;
    return { ...record, dispatch: { ...record.dispatch, status: 'PENDING', lease_hmac_sha256: null, lease_expires_at: null,
      next_attempt_at: now, alert_status: 'PENDING', alert_code: 'QUEUE_UNAVAILABLE', alert_updated_at: now } };
  });
}

export async function queueArc1AdapterDispatch(deliveryId, request, env, adapters = {}) {
  if (env[INTAKE_ARC1_ADAPTER_ENABLED_ENV] !== 'true' || env[INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV] !== 'true' ||
      env.ARC_INTAKE_ASSET_RETRIEVAL_ENABLED !== 'true') {
    return { state: 'ADAPTER_DISABLED' };
  }
  if (!SHA256_PATTERN.test(deliveryId)) throw new TypeError('ARC1 adapter delivery id is invalid.');
  const resolved = resolveArc1AdapterEnvironment(env);
  const requestOrigin = new URL(request.url).origin;
  if (requestOrigin !== resolved.origin) throw new TypeError('ARC1 adapter queue origin mismatch.');
  const endpoint = `${resolved.origin}/.netlify/functions/intake-arc1-adapter-background`;
  const body = canonicalJson({ schema: INTAKE_ARC1_ADAPTER_BACKGROUND_SCHEMA, delivery_id: deliveryId });
  try {
    const response = await (adapters.fetch || fetch)(endpoint, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(2_000),
      headers: { Authorization: `Bearer ${resolved.dispatchSecret}`, 'Content-Type': 'application/json; charset=utf-8' }, body,
    });
    if (response.status !== 202 || response.url && response.url !== endpoint) throw new Error('ARC1_ADAPTER_QUEUE_REJECTED');
    return { state: 'QUEUED' };
  } catch { return { state: 'QUEUE_UNAVAILABLE' }; }
}

export function authorizeArc1AdapterDispatch(request, env) {
  try {
    const supplied = request.headers.get('authorization') || '';
    return supplied.startsWith('Bearer ') && safeEqual(supplied.slice(7), secret(env.ARC_INTAKE_ARC1_DISPATCH_SECRET, 'dispatch secret'));
  } catch { return false; }
}

export function authorizeArc1AdapterIngress(request, env) {
  try {
    const supplied = request.headers.get('authorization') || '';
    return supplied.startsWith('Bearer ') && safeEqual(supplied.slice(7),
      secret(env.ARC_INTAKE_ARC1_DESTINATION_BEARER, 'destination bearer'));
  } catch { return false; }
}

export async function dispatchArc1AdapterRecord(deliveryId, env, stores, adapters = {}) {
  if (env[INTAKE_ARC1_ADAPTER_ENABLED_ENV] !== 'true' || env[INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV] !== 'true' ||
      env.ARC_INTAKE_ASSET_RETRIEVAL_ENABLED !== 'true') {
    return { state: 'ADAPTER_DISABLED' };
  }
  if (!SHA256_PATTERN.test(deliveryId)) throw new TypeError('ARC1 adapter delivery id is invalid.');
  const resolved = resolveArc1AdapterEnvironment(env);
  const key = adapterKey(deliveryId, resolved);
  let entry = await readEntry(stores.adapter, key);
  if (!entry) return { state: 'NOT_FOUND' };
  if (entry.value.dispatch.status === 'HOOK_ACCEPTED') return { state: 'HOOK_ACCEPTED', idempotentReplay: true };
  if (entry.value.dispatch.status === 'DEAD_LETTER') return { state: 'DEAD_LETTER', idempotentReplay: true };
  let now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('ARC1 adapter clock is invalid.');
  if (entry.value.dispatch.status === 'CLAIMED' && Date.parse(entry.value.dispatch.lease_expires_at) > now.getTime()) {
    return { state: 'IN_PROGRESS', retryAt: entry.value.dispatch.lease_expires_at };
  }
  if (entry.value.dispatch.status === 'CLAIMED') {
    entry = await replaceEntry(stores.adapter, key, entry, { ...entry.value, dispatch: { ...entry.value.dispatch,
      status: 'PENDING', lease_hmac_sha256: null, lease_expires_at: null, next_attempt_at: now.toISOString(),
      alert_status: 'PENDING', alert_code: 'DOWNSTREAM_UNAVAILABLE', alert_updated_at: now.toISOString() } });
  }
  if (Date.parse(entry.value.dispatch.next_attempt_at) > now.getTime()) {
    return { state: 'RETRY_PENDING', retryAt: entry.value.dispatch.next_attempt_at };
  }
  if (entry.value.dispatch.attempt_count >= INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS) {
    entry = await replaceEntry(stores.adapter, key, entry, { ...entry.value, dispatch: { ...entry.value.dispatch,
      status: 'DEAD_LETTER', lease_hmac_sha256: null, lease_expires_at: null, accepted_at: null,
      alert_status: 'PENDING', alert_code: 'DOWNSTREAM_MAX_ATTEMPTS', alert_updated_at: now.toISOString() } });
    await removePendingIndex(stores.adapter, deliveryId, resolved);
    return { state: 'DEAD_LETTER' };
  }
  const leaseHmac = hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET,
    `arc-intake-arc1-adapter-lease-v1\n${deliveryId}\n${now.toISOString()}\n${randomUUID()}`);
  entry = await replaceEntry(stores.adapter, key, entry, { ...entry.value, dispatch: { ...entry.value.dispatch,
    status: 'CLAIMED', attempt_count: entry.value.dispatch.attempt_count + 1, last_attempt_at: now.toISOString(),
    lease_hmac_sha256: leaseHmac, lease_expires_at: new Date(now.getTime() + INTAKE_ARC1_ADAPTER_LEASE_MS).toISOString() } });
  let accepted = false;
  let code = null;
  let artifacts;
  try {
    const source = await stores.source.getWithMetadata(`submissions/${entry.value.source_submission_id}`, { type: 'json', consistency: 'strong' });
    if (!source) throw new Error('ARC1_ADAPTER_SOURCE_MISSING');
    const normalizedSource = normalizeStoredIntakeSubmissionForBridge(source.data);
    const reconstructedEnvelope = createBridgeEnvelope(normalizedSource, normalizedSource.arc1_delivery, resolved).raw;
    artifacts = deriveAdapterArtifacts(source.data, reconstructedEnvelope, resolved, entry.value.claim_created_at, now);
    if (artifacts.packetSha256 !== entry.value.packet_sha256 || artifacts.acknowledgementJson !== entry.value.acknowledgement_json ||
        sha256(reconstructedEnvelope) !== entry.value.envelope_sha256) throw new Error('ARC1_ADAPTER_RECONSTRUCTION_CONFLICT');
  } catch (error) {
    code = error?.message === 'ARC1_ADAPTER_SOURCE_MISSING' ? 'DOWNSTREAM_SOURCE_UNAVAILABLE' : 'DOWNSTREAM_RECONSTRUCTION_CONFLICT';
  }
  if (!code) {
    try {
      const response = await (adapters.fetch || fetch)(resolved.downstreamEndpoint, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10_000),
        headers: {
          Authorization: `Bearer ${resolved.downstreamBearer}`, 'Content-Type': 'application/json; charset=utf-8',
          'Idempotency-Key': deliveryId, 'X-ARC-Bridge-Contract': INTAKE_ARC1_CONTRACT_SHA256,
        }, body: artifacts.packetRaw,
      });
      // Zapier's exact reviewed Catch Raw ingress response is HTTP 200. This
      // proves hook acceptance only, never completion of the asynchronous Zap.
      accepted = response.status === 200 && (!response.url || response.url === resolved.downstreamEndpoint);
      code = accepted ? null : 'DOWNSTREAM_REJECTED';
    } catch { code = 'DOWNSTREAM_UNAVAILABLE'; }
  }
  now = new Date((adapters.clock || (() => new Date()))());
  const exhausted = !accepted && entry.value.dispatch.attempt_count >= INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS;
  const dispatch = accepted ? {
    ...entry.value.dispatch, status: 'HOOK_ACCEPTED', next_attempt_at: now.toISOString(), lease_hmac_sha256: null,
    lease_expires_at: null, accepted_at: now.toISOString(), alert_status: entry.value.dispatch.alert_status === 'PENDING' ? 'RESOLVED' : 'NONE',
    alert_code: null, alert_updated_at: entry.value.dispatch.alert_status === 'PENDING' ? now.toISOString() : null,
  } : exhausted ? {
    ...entry.value.dispatch, status: 'DEAD_LETTER', next_attempt_at: now.toISOString(), lease_hmac_sha256: null,
    lease_expires_at: null, accepted_at: null, alert_status: 'PENDING', alert_code: 'DOWNSTREAM_MAX_ATTEMPTS', alert_updated_at: now.toISOString(),
  } : {
    ...entry.value.dispatch, status: 'PENDING', next_attempt_at: new Date(now.getTime() + retryDelayMs(entry.value.dispatch.attempt_count)).toISOString(),
    lease_hmac_sha256: null, lease_expires_at: null, accepted_at: null, alert_status: 'PENDING', alert_code: code, alert_updated_at: now.toISOString(),
  };
  entry = await replaceEntry(stores.adapter, key, entry, { ...entry.value, dispatch });
  if (['HOOK_ACCEPTED', 'DEAD_LETTER'].includes(dispatch.status)) await removePendingIndex(stores.adapter, deliveryId, resolved);
  return { state: dispatch.status, code: dispatch.alert_code, idempotentReplay: false };
}

export async function recoverPendingArc1AdapterDispatches(request, env, stores, adapters = {}) {
  if (env[INTAKE_ARC1_ADAPTER_ENABLED_ENV] !== 'true' || env[INTAKE_ARC1_DOWNSTREAM_ENABLED_ENV] !== 'true' ||
      env.ARC_INTAKE_ASSET_RETRIEVAL_ENABLED !== 'true') {
    return { state: 'ADAPTER_DISABLED', scanned: 0, attempted: 0, invalid: 0, next_cursor: null };
  }
  const resolved = resolveArc1AdapterEnvironment(env);
  const resume = decodeRecoveryCursor(requestRecoveryCursor(request, adapters), resolved);
  const startedAt = wallNow(adapters);
  const deadlineMs = startedAt + INTAKE_ARC1_ADAPTER_RECOVERY_BUDGET_MS;
  let scanned = 0;
  let attempted = 0;
  let invalid = 0;
  let processedPages = 0;
  let cursor = { ...resume };
  const initialCursor = (shard) => ({ shard, position: 0, sequence_hmac_sha256: null });
  const partial = () => ({ state: 'RECOVERY_PARTIAL', scanned, attempted, invalid, next_cursor: encodeRecoveryCursor(cursor, resolved) });
  const quarantine = async (key) => {
    const identity = hmac(resolved.ARC_INTAKE_ARC1_STATE_SECRET, `arc-intake-arc1-adapter-quarantine-v1\n${key}`);
    await stores.adapter.setJSON(`quarantine/${identity}`, {
      schema: 'arc-intake-arc1-adapter-quarantine-v1', source_key_hmac_sha256: identity,
      code: 'INVALID_PENDING_INDEX', detected_at: new Date((adapters.clock || (() => new Date()))()).toISOString(),
    }, { onlyIfNew: true });
    if (typeof stores.adapter.delete === 'function') await stores.adapter.delete(key);
  };
  let emptyShards = 0;
  for (let shard = resume.shard; shard < RECOVERY_SHARD_COUNT; shard += 1) {
    const prefix = `pending/${shard.toString(16).padStart(2, '0')}`;
    const checkpoint = shard === resume.shard ? resume : initialCursor(shard);
    cursor = { ...checkpoint };
    const iterable = stores.adapter.list({ prefix, paginate: true });
    if (!iterable || typeof iterable[Symbol.asyncIterator] !== 'function') throw new Error('ARC1_ADAPTER_RECOVERY_PAGINATION_REQUIRED');
    let position = 0;
    let sequence = recoverySequenceInitial(resolved, shard, prefix);
    let checkpointVerified = checkpoint.position === 0;
    let shardBlobCount = 0;
    for await (const page of iterable) {
      if (!page || !Array.isArray(page.blobs)) throw new Error('ARC1_ADAPTER_RECOVERY_PAGINATION_REQUIRED');
      if (wallNow(adapters) >= deadlineMs) return partial();
      shardBlobCount += page.blobs.length;
      let pageCounted = false;
      for (const blob of page.blobs) {
        if (typeof blob?.key !== 'string' || !/^pending\/[a-f0-9]{64}$/.test(blob.key)) {
          throw new Error('ARC1_ADAPTER_RECOVERY_PAGINATION_REQUIRED');
        }
        const nextSequence = recoverySequenceNext(resolved, sequence, blob.key);
        position += 1;
        if (!checkpointVerified) {
          sequence = nextSequence;
          if (wallNow(adapters) >= deadlineMs) return partial();
          if (position < checkpoint.position) continue;
          if (position === checkpoint.position && sequence === checkpoint.sequence_hmac_sha256) {
            checkpointVerified = true;
            continue;
          }
          cursor = initialCursor(shard);
          return partial();
        }
        if (!pageCounted) {
          processedPages += 1;
          pageCounted = true;
          if (processedPages > INTAKE_ARC1_ADAPTER_RECOVERY_MAX_PAGES) return partial();
        }
        if (scanned >= INTAKE_ARC1_ADAPTER_RECOVERY_MAX_READS || attempted >= INTAKE_ARC1_ADAPTER_RECOVERY_MAX_ATTEMPTS ||
            wallNow(adapters) >= deadlineMs) return partial();
        const advance = () => {
          sequence = nextSequence;
          cursor = { shard, position, sequence_hmac_sha256: sequence };
        };
        scanned += 1;
        let index;
        let entry;
        try {
          index = await stores.adapter.getWithMetadata(blob.key, { type: 'json', consistency: 'strong' });
          if (!index || !exactKeys(index.data, PENDING_INDEX_FIELDS) || index.data.schema !== INTAKE_ARC1_ADAPTER_PENDING_INDEX_SCHEMA ||
              !SHA256_PATTERN.test(index.data.delivery_id_sha256) || !/^ingress\/[a-f0-9]{64}$/.test(index.data.ingress_key)) {
            throw new Error('INVALID_INDEX');
          }
          entry = await readEntry(stores.adapter, index.data.ingress_key);
          if (!entry || sha256(entry.value.delivery_id) !== index.data.delivery_id_sha256 ||
              index.data.ingress_key !== adapterKey(entry.value.delivery_id, resolved) ||
              blob.key !== pendingKey(entry.value.delivery_id, resolved)) throw new Error('INVALID_INDEX');
        } catch {
          invalid += 1;
          await quarantine(blob.key);
          advance();
          continue;
        }
        if (['HOOK_ACCEPTED', 'DEAD_LETTER'].includes(entry.value.dispatch.status)) {
          if (typeof stores.adapter.delete === 'function') await stores.adapter.delete(blob.key);
          advance();
          continue;
        }
        const nowMs = new Date((adapters.clock || (() => new Date()))()).getTime();
        const due = entry.value.dispatch.status === 'CLAIMED' ? Date.parse(entry.value.dispatch.lease_expires_at) <= nowMs :
          Date.parse(entry.value.dispatch.next_attempt_at) <= nowMs;
        if (due) {
          attempted += 1;
          await dispatchArc1AdapterRecord(entry.value.delivery_id, env, stores, adapters);
        }
        advance();
        if (wallNow(adapters) >= deadlineMs) return partial();
      }
    }
    if (!checkpointVerified) {
      cursor = initialCursor(shard);
      return partial();
    }
    emptyShards = shardBlobCount === 0 ? emptyShards + 1 : 0;
    if (shard + 1 < RECOVERY_SHARD_COUNT) cursor = initialCursor(shard + 1);
    if (shard + 1 < RECOVERY_SHARD_COUNT && (emptyShards >= 64 || wallNow(adapters) >= deadlineMs)) return partial();
  }
  return { state: 'RECOVERY_COMPLETE', scanned, attempted, invalid, next_cursor: null };
}
