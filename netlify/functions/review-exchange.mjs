import { randomBytes } from 'node:crypto';
import { getStore } from '@netlify/blobs';
import { REVIEW_STORE, exchangeReviewInvite, reviewPortalConfiguration } from '../lib/review-flow-core.mjs';
import {
  readReviewJson,
  requestOriginAllowed,
  reviewHttpError,
  reviewJsonResponse,
  sessionSetCookie,
} from '../lib/review-http-core.mjs';

export default async (request, context = {}) => {
  if (!reviewPortalConfiguration(process.env).enabled) return reviewJsonResponse(503, { error: 'review_disabled' });
  if (request.method !== 'POST') return reviewJsonResponse(405, { error: 'method_not_allowed' });
  if (!requestOriginAllowed(request, true)) return reviewJsonResponse(403, { error: 'forbidden' });
  try {
    const value = await readReviewJson(request, 512);
    if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['invite_token'])) throw new TypeError('Invite request fields are invalid.');
    const store = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    const exchanged = await exchangeReviewInvite(store, value.invite_token, process.env, {
      clock: context.clock,
      randomBytes: context.randomBytes || randomBytes,
    });
    return reviewJsonResponse(200, { exchanged: true }, {
      'Set-Cookie': sessionSetCookie(exchanged.session_token, exchanged.max_age),
    });
  } catch (error) {
    const [status, code] = reviewHttpError(error);
    return reviewJsonResponse(status, { error: code });
  }
};

export const config = {
  path: '/api/review/exchange', method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
