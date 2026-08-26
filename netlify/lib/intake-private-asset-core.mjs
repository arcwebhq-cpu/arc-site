import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { assertPublicIntakeAuthority } from './activation-manifest-core.mjs';
import { validateImageAsset } from './image-asset-validation.mjs';
import { ASSET_PERMISSION_CONFIRMATION } from './intake-submission-core.mjs';

export const INTAKE_PRIVATE_ASSET_ENABLED_ENV = 'ARC_INTAKE_ASSET_RETRIEVAL_ENABLED';
export const INTAKE_PRIVATE_ASSET_GRANT_SCHEMA = 'arc-intake-private-asset-grant-v1';
export const INTAKE_PRIVATE_ASSET_INDEX_SCHEMA = 'arc-intake-private-asset-index-v1';
export const INTAKE_PRIVATE_ASSET_REQUEST_SCHEMA = 'arc-intake-private-asset-request-v1';
export const INTAKE_PRIVATE_ASSET_ENDPOINT_PATH = '/internal/intake/arc1/assets/retrieve';
export const INTAKE_PRIVATE_ASSET_MAX_BYTES = 1_250_000;

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const ASSET_ID_PATTERN = /^[a-f0-9]{64}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ASSET_ROLES = new Set(['hero_image_file', 'logo_file', 'supporting_image_file']);

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

function configuredOrigin(env) {
  let url;
  try { url = new URL(env.URL); } catch { throw new TypeError('Private asset origin is invalid.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.pathname !== '/' || url.search || url.hash ||
      !['arcweb.onl', 'arcsites.netlify.app'].includes(url.hostname)) {
    throw new TypeError('Private asset origin must be an exact reviewed ARC origin.');
  }
  return url.origin;
}

export function resolvePrivateAssetEnvironment(env) {
  const retrievalSecret = secret(env.ARC_INTAKE_ASSET_RETRIEVAL_SECRET, 'ARC_INTAKE_ASSET_RETRIEVAL_SECRET');
  const stateSecret = secret(env.ARC_INTAKE_ARC1_STATE_SECRET, 'ARC_INTAKE_ARC1_STATE_SECRET');
  if (safeEqual(retrievalSecret, stateSecret)) throw new TypeError('Private asset and state secrets must be distinct.');
  const endpoint = `${configuredOrigin(env)}${INTAKE_PRIVATE_ASSET_ENDPOINT_PATH}`;
  return { endpoint, endpointSha256: sha256(endpoint), retrievalSecret, stateSecret };
}

export function authorizePrivateAssetRetrieval(request, env) {
  try {
    const supplied = request.headers.get('authorization');
    return supplied?.startsWith('Bearer ') === true &&
      safeEqual(supplied.slice(7), secret(env.ARC_INTAKE_ASSET_RETRIEVAL_SECRET, 'private asset retrieval secret'));
  } catch { return false; }
}

function metadata(asset) {
  const role = asset?.role || asset?.field;
  const kind = asset?.kind || 'UPLOAD';
  return {
    schema: 'arc-intake-private-asset-reference-v1',
    kind,
    role,
    content_type: asset?.content_type,
    size: asset?.size,
    sha256: asset?.sha256,
  };
}

export function createPrivateAssetGrants(record, resolved) {
  if (!record || !UUID_PATTERN.test(record.submission_id) || !Array.isArray(record.assets)) throw new TypeError('Asset source record is invalid.');
  return record.assets.map((asset) => {
    const value = metadata(asset);
    if (!ASSET_ROLES.has(value.role) || value.kind !== 'UPLOAD' ||
        !SHA256_PATTERN.test(value.sha256) || !Number.isSafeInteger(value.size) || value.size < 1 ||
        value.size > INTAKE_PRIVATE_ASSET_MAX_BYTES) {
      throw new TypeError('Private asset metadata is invalid.');
    }
    const assetId = hmac(resolved.stateSecret,
      `arc-intake-private-asset-id-v1\n${record.submission_id}\n${value.kind}\n${value.role}\n${value.sha256}\n${value.size}\n${value.content_type}`);
    return {
      schema: INTAKE_PRIVATE_ASSET_GRANT_SCHEMA,
      asset_id: assetId,
      kind: value.kind,
      role: value.role,
      content_type: value.content_type,
      size: value.size,
      sha256: value.sha256,
      retrieval_endpoint_sha256: resolved.endpointSha256,
    };
  });
}

export function privateAssetIndexEntries(record, grants, { deliveryId, evidenceSha256, expiresAt }) {
  if (!UUID_PATTERN.test(record?.submission_id) || !SHA256_PATTERN.test(deliveryId) || !SHA256_PATTERN.test(evidenceSha256) ||
      typeof expiresAt !== 'string' || new Date(expiresAt).toISOString() !== expiresAt || grants.length !== record.assets.length) {
    throw new TypeError('Private asset index binding is invalid.');
  }
  return grants.map((grant) => ({
    key: `arc1-asset-index/${grant.asset_id}`,
    value: {
      schema: INTAKE_PRIVATE_ASSET_INDEX_SCHEMA,
      source_key: `submissions/${record.submission_id}`,
      delivery_id_sha256: sha256(deliveryId),
      evidence_sha256: evidenceSha256,
      expires_at: expiresAt,
      grant,
    },
  }));
}

function validateGrant(value) {
  if (!exactKeys(value, ['asset_id', 'content_type', 'kind', 'retrieval_endpoint_sha256', 'role', 'schema', 'sha256', 'size']) ||
      value.schema !== INTAKE_PRIVATE_ASSET_GRANT_SCHEMA || !ASSET_ID_PATTERN.test(value.asset_id) ||
      !SHA256_PATTERN.test(value.retrieval_endpoint_sha256) || !SHA256_PATTERN.test(value.sha256) || !ASSET_ROLES.has(value.role) ||
      value.kind !== 'UPLOAD' ||
      !Number.isSafeInteger(value.size) || value.size < 1 ||
      value.size > INTAKE_PRIVATE_ASSET_MAX_BYTES) {
    throw new TypeError('Private asset grant is invalid.');
  }
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(value.content_type)) throw new TypeError('Private asset media type is invalid.');
  return value;
}

export async function retrievePrivateAsset(input, env, { store, now = new Date() } = {}) {
  assertPublicIntakeAuthority(env);
  if (!exactKeys(input, ['asset_id', 'delivery_id', 'evidence_sha256', 'schema']) ||
      input.schema !== INTAKE_PRIVATE_ASSET_REQUEST_SCHEMA || !ASSET_ID_PATTERN.test(input.asset_id) ||
      !SHA256_PATTERN.test(input.delivery_id) || !SHA256_PATTERN.test(input.evidence_sha256)) throw new TypeError('Private asset request is invalid.');
  const resolved = resolvePrivateAssetEnvironment(env);
  if (!store) throw new TypeError('Private asset store is unavailable.');
  const indexed = await store.getWithMetadata(`arc1-asset-index/${input.asset_id}`, { type: 'json', consistency: 'strong' });
  const value = indexed?.data;
  if (!exactKeys(value, ['delivery_id_sha256', 'evidence_sha256', 'expires_at', 'grant', 'schema', 'source_key']) ||
      value.schema !== INTAKE_PRIVATE_ASSET_INDEX_SCHEMA || !/^submissions\/[0-9a-f-]{36}$/.test(value.source_key) ||
      !safeEqual(value.delivery_id_sha256, sha256(input.delivery_id)) || !safeEqual(value.evidence_sha256, input.evidence_sha256) ||
      Date.parse(value.expires_at) <= new Date(now).getTime()) throw new Error('ARC_INTAKE_ASSET_NOT_FOUND');
  const grant = validateGrant(value.grant);
  if (!safeEqual(grant.asset_id, input.asset_id) || !safeEqual(grant.retrieval_endpoint_sha256, resolved.endpointSha256)) {
    throw new Error('ARC_INTAKE_ASSET_BINDING_FAILED');
  }
  const source = await store.getWithMetadata(value.source_key, { type: 'json', consistency: 'strong' });
  const record = source?.data;
  if (!record || record.data?.asset_permission !== ASSET_PERMISSION_CONFIRMATION || !Array.isArray(record.assets)) throw new Error('ARC_INTAKE_ASSET_PERMISSION_REQUIRED');
  const matches = record.assets.filter((asset) => {
    const item = metadata(asset);
    return item.kind === grant.kind && item.role === grant.role && item.content_type === grant.content_type &&
      item.size === grant.size && item.sha256 === grant.sha256;
  });
  if (matches.length !== 1) throw new Error('ARC_INTAKE_ASSET_BINDING_FAILED');
  const sourceAsset = matches[0];
  if (typeof sourceAsset.content_base64 !== 'string') throw new Error('ARC_INTAKE_ASSET_BINDING_FAILED');
  const bytes = Buffer.from(sourceAsset.content_base64, 'base64');
  if (bytes.toString('base64') !== sourceAsset.content_base64) {
    throw new Error('ARC_INTAKE_ASSET_BINDING_FAILED');
  }
  try { validateImageAsset(bytes, grant.content_type); } catch { throw new Error('ARC_INTAKE_ASSET_BINDING_FAILED'); }
  if (bytes.length !== grant.size || !safeEqual(sha256(bytes), grant.sha256)) throw new Error('ARC_INTAKE_ASSET_BINDING_FAILED');
  return { bytes, grant };
}
