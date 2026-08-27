import { getStore } from '@netlify/blobs';
import { REVIEW_STORE, readReviewStatus, reviewPortalConfiguration } from '../lib/review-flow-core.mjs';
import {
  requestOriginAllowed,
  reviewHttpError,
  reviewJsonResponse,
  reviewSessionCookie,
} from '../lib/review-http-core.mjs';

export default async (request, context = {}) => {
  if (!reviewPortalConfiguration(process.env).enabled) return reviewJsonResponse(503, { error: 'review_disabled' });
  if (request.method !== 'GET') return reviewJsonResponse(405, { error: 'method_not_allowed' });
  if (!requestOriginAllowed(request, false)) return reviewJsonResponse(403, { error: 'forbidden' });
  const session = reviewSessionCookie(request);
  if (!session) return reviewJsonResponse(401, { error: 'review_credential_invalid' });
  try {
    const store = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    return reviewJsonResponse(200, await readReviewStatus(store, session, process.env, context.clock?.() || new Date()));
  } catch (error) {
    const [status, code] = reviewHttpError(error);
    return reviewJsonResponse(status, { error: code });
  }
};

export const config = {
  path: '/api/review/status', method: 'GET',
  rateLimit: { windowLimit: 60, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
