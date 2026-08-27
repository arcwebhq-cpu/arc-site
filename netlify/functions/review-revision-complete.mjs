import { getStore } from '@netlify/blobs';

import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import { readReviewJson, reviewJsonResponse } from '../lib/review-http-core.mjs';
import {
  REVIEW_REVISION_OUTBOX_STORE,
  completeReviewRevisionWork,
  reviewRevisionInternalWorkerAdapter,
  reviewRevisionOutboxConfiguration,
} from '../lib/review-revision-outbox-core.mjs';

const BODY_FIELDS = Object.freeze([
  'artifact_evidence', 'invite_reservation', 'lease_token', 'successor_commit_sha',
  'successor_manifest_sha256', 'successor_repository', 'work_hmac_sha256',
]);

function bearerSecret(request) {
  if (request.headers.has('origin')) return null;
  const value = request.headers.get('authorization');
  const match = typeof value === 'string' ? /^Bearer ([A-Za-z0-9._~+\/-]+=*)$/.exec(value) : null;
  return match && match[1].length >= 32 && match[1].length <= 512 ? match[1] : null;
}

function workerError(error) {
  if (/WORKER_UNAUTHORIZED/.test(error?.message || '')) return [401, 'unauthorized'];
  if (error instanceof TypeError || error?.name === 'SyntaxError') return [400, 'invalid_request'];
  if (/NOT_FOUND/.test(error?.message || '')) return [404, 'work_not_found'];
  if (/LEASE_|CONTENTION|CONFLICT|STALE|RENEWAL/.test(error?.message || '')) return [409, 'work_conflict'];
  return [503, 'revision_worker_unavailable'];
}

export default async (request, context = {}) => {
  if (!reviewRevisionOutboxConfiguration(process.env).enabled) {
    return reviewJsonResponse(503, { error: 'revision_worker_disabled' });
  }
  if (request.method !== 'POST') return reviewJsonResponse(405, { error: 'method_not_allowed' });
  const authorization = bearerSecret(request);
  if (!authorization) return reviewJsonResponse(401, { error: 'unauthorized' });
  try {
    const value = await readReviewJson(request, 50_000);
    if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...BODY_FIELDS].sort())) {
      throw new TypeError('Revision completion fields are invalid.');
    }
    const outboxStore = context.revisionStore || getStore({
      name: REVIEW_REVISION_OUTBOX_STORE, consistency: 'strong',
    });
    const reviewStore = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    const result = await completeReviewRevisionWork(outboxStore, reviewStore, value.work_hmac_sha256,
      authorization, {
        lease_token: value.lease_token,
        successor_repository: value.successor_repository,
        successor_commit_sha: value.successor_commit_sha,
        successor_manifest_sha256: value.successor_manifest_sha256,
      }, process.env, {
        clock: context.clock,
        authorizeInternalWorker: context.authorizeInternalWorker ||
          reviewRevisionInternalWorkerAdapter(process.env),
        reserveSuccessorInvite: context.reserveSuccessorInvite || (async () => value.invite_reservation),
        verifySuccessorArtifacts: context.verifySuccessorArtifacts || (async () => value.artifact_evidence),
      });
    return reviewJsonResponse(200, {
      idempotent_replay: result.idempotent_replay,
      state: result.record.state,
      successor_email_outbox_hmac_sha256: result.record.successor_email_outbox_hmac_sha256,
      successor_invite_hmac_sha256: result.record.successor_invite_hmac_sha256,
    });
  } catch (error) {
    const [status, code] = workerError(error);
    return reviewJsonResponse(status, { error: code });
  }
};

export const config = {
  path: '/api/internal/review-revision/complete', method: 'POST',
  rateLimit: { windowLimit: 20, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
