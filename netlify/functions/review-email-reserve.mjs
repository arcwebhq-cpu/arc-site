import { getStore } from '@netlify/blobs';

import {
  claimNextReviewEmail,
  reserveReviewEmailSend,
} from '../lib/review-email-outbox-core.mjs';
import {
  readAuthenticatedReviewEmailJson,
  reviewEmailInternalApiConfiguration,
  reviewEmailInternalHttpError,
} from '../lib/review-email-http-core.mjs';
import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import { reviewJsonResponse } from '../lib/review-http-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const PATH = '/api/internal/review-email/reserve';

function exactFields(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}

const handler = async (request, context = {}) => {
  if (!reviewEmailInternalApiConfiguration(process.env).enabled) {
    return reviewJsonResponse(503, { error: 'review_email_worker_disabled' });
  }
  if (request.method !== 'POST') return reviewJsonResponse(405, { error: 'method_not_allowed' });
  try {
    const value = await readAuthenticatedReviewEmailJson(request, PATH, 2_000, process.env, {
      clock: context.clock,
    });
    const claimNext = exactFields(value, ['claim_next']) && value.claim_next === true;
    if (!claimNext && !exactFields(value, ['invite_token', 'recipient_email'])) {
      throw new TypeError('Review email reservation fields are invalid.');
    }
    const store = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    if (claimNext) {
      const result = await claimNextReviewEmail(store, process.env, { clock: context.clock });
      return reviewJsonResponse(200, { claimed: result.found, ...result });
    }
    const result = await reserveReviewEmailSend(store, value, process.env, { clock: context.clock });
    return reviewJsonResponse(200, { reserved: true, ...result });
  } catch (error) {
    const [status, code] = reviewEmailInternalHttpError(error);
    return reviewJsonResponse(status, { error: code });
  }
};

export default createRetentionFencedRouteHandler({
  route: 'review-email-reserve',
  paths: [PATH],
  active: ({ env }) => reviewEmailInternalApiConfiguration(env).enabled,
  handler,
});

export const config = {
  path: '/api/internal/review-email/reserve', method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
