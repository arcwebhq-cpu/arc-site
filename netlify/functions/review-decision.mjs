import { getStore } from '@netlify/blobs';
import { REVIEW_STORE, decideReview, reviewPortalConfiguration } from '../lib/review-flow-core.mjs';
import {
  readReviewJson,
  requestOriginAllowed,
  reviewHttpError,
  reviewJsonResponse,
  reviewSessionCookie,
} from '../lib/review-http-core.mjs';

export default async (request, context = {}) => {
  if (!reviewPortalConfiguration(process.env).enabled) return reviewJsonResponse(503, { error: 'review_disabled' });
  if (request.method !== 'POST') return reviewJsonResponse(405, { error: 'method_not_allowed' });
  if (!requestOriginAllowed(request, true)) return reviewJsonResponse(403, { error: 'forbidden' });
  const session = reviewSessionCookie(request);
  if (!session) return reviewJsonResponse(401, { error: 'review_credential_invalid' });
  try {
    const value = await readReviewJson(request, 5000);
    const store = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    const result = await decideReview(store, session, value, process.env, { clock: context.clock });
    return reviewJsonResponse(200, {
      idempotent_replay: result.idempotent_replay,
      record_revision: result.record_revision,
      state: result.state,
    });
  } catch (error) {
    const [status, code] = reviewHttpError(error);
    return reviewJsonResponse(status, { error: code });
  }
};

export const config = {
  path: '/api/review/decision', method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
