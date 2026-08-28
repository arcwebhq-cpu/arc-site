import { getStore } from '@netlify/blobs';
import {
  REVIEW_STORE,
  authorizeReviewSession,
  decideReview,
  reviewPortalConfiguration,
} from '../lib/review-flow-core.mjs';
import {
  REVIEW_REVISION_INTERNAL_AUTH_SECRET_ENV,
  REVIEW_REVISION_OUTBOX_STORE,
  prepareReviewRevisionPendingIndex,
  reserveReviewRevisionWork,
  reviewRevisionInternalWorkerAdapter,
  reviewRevisionOutboxConfiguration,
} from '../lib/review-revision-outbox-core.mjs';
import {
  readReviewJson,
  requestOriginAllowed,
  reviewHttpError,
  reviewJsonResponse,
  reviewSessionCookie,
} from '../lib/review-http-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const handler = async (request, context = {}) => {
  if (!reviewPortalConfiguration(process.env).enabled) return reviewJsonResponse(503, { error: 'review_disabled' });
  if (request.method !== 'POST') return reviewJsonResponse(405, { error: 'method_not_allowed' });
  if (!requestOriginAllowed(request, true)) return reviewJsonResponse(403, { error: 'forbidden' });
  const session = reviewSessionCookie(request);
  if (!session) return reviewJsonResponse(401, { error: 'review_credential_invalid' });
  try {
    const value = await readReviewJson(request, 5000);
    if (value.action === 'REQUEST_CHANGES' && !reviewRevisionOutboxConfiguration(process.env).enabled) {
      return reviewJsonResponse(503, { error: 'revision_automation_unavailable' });
    }
    const store = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    let revisionStore = null;
    let revisionSourceInviteHmac = null;
    const internalWorker = context.authorizeInternalWorker || reviewRevisionInternalWorkerAdapter(process.env);
    if (value.action === 'REQUEST_CHANGES') {
      const authorized = await authorizeReviewSession(store, session, process.env,
        context.clock?.() || new Date());
      revisionSourceInviteHmac = authorized.record.invite_hmac_sha256;
      revisionStore = context.revisionStore || getStore({
        name: REVIEW_REVISION_OUTBOX_STORE, consistency: 'strong',
      });
      await prepareReviewRevisionPendingIndex(revisionStore, revisionSourceInviteHmac,
        process.env[REVIEW_REVISION_INTERNAL_AUTH_SECRET_ENV], process.env, {
          clock: context.clock, authorizeInternalWorker: internalWorker,
        });
    }
    const result = await decideReview(store, session, value, process.env, { clock: context.clock });
    let revisionWorkReserved = false;
    if (value.action === 'REQUEST_CHANGES') {
      await reserveReviewRevisionWork(revisionStore, store, revisionSourceInviteHmac,
        process.env[REVIEW_REVISION_INTERNAL_AUTH_SECRET_ENV], process.env, {
          clock: context.clock, authorizeInternalWorker: internalWorker,
        });
      revisionWorkReserved = true;
    }
    return reviewJsonResponse(200, {
      idempotent_replay: result.idempotent_replay,
      record_revision: result.record_revision,
      revision_work_reserved: revisionWorkReserved,
      state: result.state,
    });
  } catch (error) {
    const [status, code] = reviewHttpError(error);
    return reviewJsonResponse(status, { error: code });
  }
};

export default createRetentionFencedRouteHandler({
  route: 'review-decision',
  paths: ['/api/review/decision'],
  active: ({ env }) => reviewPortalConfiguration(env).enabled,
  handler,
});

export const config = {
  path: '/api/review/decision', method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
