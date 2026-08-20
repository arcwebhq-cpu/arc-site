import { getStore } from '@netlify/blobs';
import {
  authenticateBearer,
  jsonResponse,
  parseJsonBodyText,
} from '../lib/arc2-handoff-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';
import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';
import {
  RETENTION_CONTROL_STORE,
  retentionConfiguration,
  runRetentionManifest,
} from '../lib/retention-control-core.mjs';

export default async (request, context = {}) => {
  const configuration = retentionConfiguration(process.env);
  if (!configuration.enabled) return jsonResponse(503, { error: 'retention_cleanup_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_RETENTION_CLEANUP_SECRET)) return jsonResponse(401, { error: 'unauthorized' });
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return jsonResponse(415, { error: 'json_required' });
  }
  try {
    const body = parseJsonBodyText(await readBoundedRequestText(request, 250_000), 250_000);
    if (Object.keys(body).length !== 2 || typeof body.manifest !== 'string' || typeof body.manifest_hmac_sha256 !== 'string') {
      return jsonResponse(400, { error: 'invalid_retention_manifest' });
    }
    const stores = {
      control: context.retentionStore || getStore({ name: RETENTION_CONTROL_STORE, consistency: 'strong' }),
      intake: context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' }),
    };
    const result = await runRetentionManifest(body.manifest, body.manifest_hmac_sha256, process.env, stores, { clock: context.clock });
    return jsonResponse(200, {
      run_id: result.run_id,
      mode: result.mode,
      target_count: result.target_count,
      eligible: result.eligible,
      deleted: result.deleted,
      legal_hold: result.legal_hold,
      missing: result.missing,
      not_expired: result.not_expired,
      resumed: result.resumed,
      idempotent_replay: result.idempotent_replay,
      provider_cleanup_included: false,
    });
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) return jsonResponse(413, { error: 'retention_manifest_too_large' });
    if (error instanceof TypeError || error?.name === 'SyntaxError') return jsonResponse(400, { error: 'invalid_retention_manifest' });
    if (/DISABLED/.test(error?.message || '')) return jsonResponse(503, { error: 'retention_cleanup_disabled' });
    if (/CONFLICT|CHANGED|ORDER/.test(error?.message || '')) return jsonResponse(409, { error: 'retention_conflict' });
    return jsonResponse(503, { error: 'retention_cleanup_unavailable' });
  }
};

export const config = {
  path: '/internal/retention/cleanup',
  method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
