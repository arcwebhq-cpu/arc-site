import { getStore } from '@netlify/blobs';
import {
  INTAKE_PRIVATE_ASSET_ENABLED_ENV,
  INTAKE_PRIVATE_ASSET_REQUEST_SCHEMA,
  authorizePrivateAssetRetrieval,
  retrievePrivateAsset,
} from '../lib/intake-private-asset-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';

const json = (status, value) => new Response(JSON.stringify(value), { status, headers: {
  'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff',
} });

async function boundedJson(request) {
  const reader = request.body?.getReader?.();
  if (!reader) throw new TypeError('JSON body is required.');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > 4096) {
        try { await reader.cancel(); } catch {}
        throw new TypeError('JSON body is too large.');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally { try { reader.releaseLock(); } catch {} }
  return JSON.parse(Buffer.concat(chunks, total).toString('utf8'));
}

export function createIntakePrivateAssetHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' });
    if (!authorizePrivateAssetRetrieval(request, process.env)) return json(401, { error: 'unauthorized' });
    if (process.env[INTAKE_PRIVATE_ASSET_ENABLED_ENV] !== 'true') return json(503, { error: 'asset_retrieval_disabled' });
    const type = request.headers.get('content-type') || '';
    const length = request.headers.get('content-length');
    if (!type.toLowerCase().startsWith('application/json') || (length && (!/^\d{1,5}$/.test(length) || Number(length) > 4096))) {
      return json(400, { error: 'invalid_request' });
    }
    let input;
    try { input = await boundedJson(request); } catch { return json(400, { error: 'invalid_request' }); }
    if (input?.schema !== INTAKE_PRIVATE_ASSET_REQUEST_SCHEMA) return json(400, { error: 'invalid_request' });
    try {
      const result = await retrievePrivateAsset(input, process.env, {
        store: context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' }),
        now: context.clock?.() || new Date(),
      });
      return new Response(result.bytes, { status: 200, headers: {
        'Cache-Control': 'no-store',
        'Content-Type': result.grant.content_type,
        'Content-Length': String(result.bytes.length),
        'X-ARC-Asset-Id': result.grant.asset_id,
        'X-ARC-Asset-Kind': result.grant.kind,
        'X-ARC-Asset-Role': result.grant.role,
        'X-ARC-Asset-SHA256': result.grant.sha256,
        'X-Content-Type-Options': 'nosniff',
      } });
    } catch (error) {
      if (error instanceof TypeError) return json(400, { error: 'invalid_request' });
      if (error?.message === 'ARC_INTAKE_ASSET_NOT_FOUND') return json(404, { error: 'asset_not_found' });
      if (/ASSET_(?:BINDING_FAILED|PERMISSION_REQUIRED)/.test(error?.message || '')) return json(409, { error: 'asset_unavailable' });
      return json(503, { error: 'asset_unavailable' });
    }
  };
}

export default createIntakePrivateAssetHandler();
export const config = {
  path: '/internal/intake/arc1/assets/retrieve', method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
