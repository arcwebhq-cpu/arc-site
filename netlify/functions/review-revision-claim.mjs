import { getStore } from '@netlify/blobs';

import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import { readReviewJson, reviewJsonResponse } from '../lib/review-http-core.mjs';
import {
  REVIEW_REVISION_OUTBOX_STORE,
  claimNextReviewRevisionWork,
  reviewRevisionInternalWorkerAdapter,
  reviewRevisionOutboxConfiguration,
} from '../lib/review-revision-outbox-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

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
  if (/LEASE_ACTIVE|CONTENTION|COMPLETED/.test(error?.message || '')) return [409, 'work_conflict'];
  return [503, 'revision_worker_unavailable'];
}

const handler = async (request, context = {}) => {
  if (!reviewRevisionOutboxConfiguration(process.env).enabled) {
    return reviewJsonResponse(503, { error: 'revision_worker_disabled' });
  }
  if (request.method !== 'POST') return reviewJsonResponse(405, { error: 'method_not_allowed' });
  const authorization = bearerSecret(request);
  if (!authorization) return reviewJsonResponse(401, { error: 'unauthorized' });
  try {
    const value = await readReviewJson(request, 2000);
    if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['cursor']) ||
        value.cursor !== null && typeof value.cursor !== 'string') {
      throw new TypeError('Revision claim fields are invalid.');
    }
    const outboxStore = context.revisionStore || getStore({
      name: REVIEW_REVISION_OUTBOX_STORE, consistency: 'strong',
    });
    const reviewStore = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    const result = await claimNextReviewRevisionWork(outboxStore, reviewStore, value.cursor,
      authorization, process.env, {
        clock: context.clock,
        authorizeInternalWorker: context.authorizeInternalWorker ||
          reviewRevisionInternalWorkerAdapter(process.env),
      });
    if (result.empty) return reviewJsonResponse(200, { empty: true, next_cursor: result.next_cursor });
    return reviewJsonResponse(200, {
      attempt_count: result.record.attempt_count,
      idempotent_replay: result.idempotent_replay,
      lease_expires_at: result.lease_expires_at,
      lease_token: result.lease_token,
      next_cursor: result.next_cursor,
      revision_input: result.revision_input,
      state: result.record.state,
    });
  } catch (error) {
    const [status, code] = workerError(error);
    return reviewJsonResponse(status, { error: code });
  }
};

export default createRetentionFencedRouteHandler({
  route: 'review-revision-claim',
  paths: ['/api/internal/review-revision/claim'],
  active: ({ env }) => reviewRevisionOutboxConfiguration(env).enabled,
  handler,
});

export const config = {
  path: '/api/internal/review-revision/claim', method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
