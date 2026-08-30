import { getStore } from '@netlify/blobs';

import {
  authenticateBearer,
  parseJsonBodyText,
} from '../lib/arc2-handoff-core.mjs';
import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';
import {
  firstPartyRetentionConfiguration,
} from '../lib/first-party-retention-core.mjs';
import {
  RETENTION_GENERATION_FENCE_STORE,
} from '../lib/retention-generation-fence-core.mjs';
import { enqueueRetentionGenerationFenceCriticalAlert } from
  '../lib/retention-generation-fence-alert-queue-core.mjs';
import { writeRetentionLegalHoldFenced } from '../lib/retention-fenced-route-core.mjs';
import { sensitiveCredentialsAreIsolated } from '../lib/sensitive-credential-isolation.mjs';

export const FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV =
  'ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER';

const MAX_BODY_BYTES = 4_096;
const INPUT_FIELDS = Object.freeze([
  'expires_at',
  'family',
  'issued_at',
  'reason_code',
  'subject_hmac_sha256',
]);
function response(status, value, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'Content-Type': 'application/json; charset=utf-8',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
    ...headers,
  } });
}

function validSecret(value) {
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= 32 &&
    Buffer.byteLength(value, 'utf8') <= 512;
}

export function firstPartyRetentionLegalHoldWriterConfiguration(env = process.env) {
  const retention = firstPartyRetentionConfiguration(env);
  const bearer = env[FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV];
  const bearerValid = validSecret(bearer);
  const bearerDistinct = bearerValid && sensitiveCredentialsAreIsolated(env,
    [FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV]);
  return Object.freeze({
    requested: retention.requested,
    enabled: retention.enabled && bearerValid && bearerDistinct,
    missing: Object.freeze([
      ...retention.missing,
      ...(!bearer ? [FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV] : []),
    ]),
    invalid: Object.freeze([
      ...retention.invalid,
      ...(bearer && !bearerValid ? [FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV] : []),
      ...(bearerValid && !bearerDistinct ? ['FIRST_PARTY_RETENTION_LEGAL_HOLD_SECRET_SEPARATION'] : []),
    ]),
  });
}

function exactLegalHoldInput(value) {
  return value && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(INPUT_FIELDS);
}

export function createFirstPartyRetentionLegalHoldWriterHandler() {
  return async (request, context = {}) => {
    const configuration = firstPartyRetentionLegalHoldWriterConfiguration(process.env);
    if (!configuration.enabled) {
      return response(503, { error: 'first_party_retention_legal_hold_disabled' });
    }
    if (request.method !== 'POST') return response(405, { error: 'method_not_allowed' });
    if (!authenticateBearer(request,
      process.env[FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV])) {
      return response(401, { error: 'unauthorized' });
    }
    const contentType = (request.headers.get('content-type') || '')
      .split(';', 1)[0].trim().toLowerCase();
    if (contentType !== 'application/json') return response(415, { error: 'json_required' });
    try {
      const input = parseJsonBodyText(await readBoundedRequestText(request, MAX_BODY_BYTES),
        MAX_BODY_BYTES);
      if (!exactLegalHoldInput(input)) {
        return response(400, { error: 'invalid_legal_hold' });
      }
      const store = context.retentionStore || getStore({
        name: RETENTION_GENERATION_FENCE_STORE,
        consistency: 'strong',
      });
      const result = await writeRetentionLegalHoldFenced(input, process.env, {
        store,
        clock: context.clock,
        staleAfterMs: context.staleAfterMs,
        heartbeatIntervalMs: context.retentionFenceHeartbeatIntervalMs,
        emitCriticalAlert: (alert) => {
          const alertStore = context.retentionFenceAlertStore || context.operationsAlertStore;
          return enqueueRetentionGenerationFenceCriticalAlert(alert, process.env, {
            clock: context.clock,
            ...(alertStore ? { store: alertStore } : {}),
          });
        },
        afterMutation: context.afterLegalHoldMutation,
      });
      if (result.retryable) {
        return response(503, {
          error: 'retention_generation_fence_contention',
          retryable: true,
        }, { 'Retry-After': '1' });
      }
      return response(200, {
        accepted: true,
        generation: result.generation,
        idempotent_replay: result.idempotent_replay,
        operation_hmac_sha256: result.operation_hmac_sha256,
      });
    } catch (error) {
      if (error instanceof RequestBodyTooLargeError) {
        return response(413, { error: 'legal_hold_too_large' });
      }
      if (error instanceof TypeError || error?.name === 'SyntaxError') {
        return response(400, { error: 'invalid_legal_hold' });
      }
      if (/DISABLED/.test(error?.message || '')) {
        return response(503, { error: 'first_party_retention_legal_hold_disabled' });
      }
      if (/CONTENTION|SOURCE_CHANGED/.test(error?.message || '')) {
        return response(503, {
          error: 'retention_generation_fence_contention',
          retryable: true,
        }, { 'Retry-After': '1' });
      }
      return response(503, { error: 'first_party_retention_legal_hold_unavailable' });
    }
  };
}

export default createFirstPartyRetentionLegalHoldWriterHandler();

export const config = {
  path: '/api/internal/retention/legal-hold',
  method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};

export const firstPartyRetentionLegalHoldWriterContract = Object.freeze({
  bearer_environment: FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER_ENV,
  body_maximum_bytes: MAX_BODY_BYTES,
  fence_store: RETENTION_GENERATION_FENCE_STORE,
  path: '/api/internal/retention/legal-hold',
});
