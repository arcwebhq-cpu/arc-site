import { getStore } from '@netlify/blobs';

import { acknowledgeReviewEmailReceipt } from '../lib/review-email-outbox-core.mjs';
import { expireSuppressedRecipientReviewCheckouts } from '../lib/stripe-review-checkout-adapter.mjs';
import {
  readAuthenticatedReviewEmailJson,
  reviewEmailInternalApiConfiguration,
  reviewEmailInternalHttpError,
} from '../lib/review-email-http-core.mjs';
import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import { reviewJsonResponse } from '../lib/review-http-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const PATH = '/api/internal/review-email/ack';

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
    const value = await readAuthenticatedReviewEmailJson(request, PATH, 24_000, process.env, {
      clock: context.clock,
    });
    if (!exactFields(value, ['delivery_receipt_evidence', 'delivery_receipt_evidence_hmac_sha256'])) {
      throw new TypeError('Review email acknowledgement fields are invalid.');
    }
    const store = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    const result = await acknowledgeReviewEmailReceipt(store, value.delivery_receipt_evidence,
      value.delivery_receipt_evidence_hmac_sha256, process.env, {
        clock: context.clock,
        expireRecipientCheckouts: context.expireRecipientCheckouts ||
          (process.env.ARC_STRIPE_REVIEW_REVOCATION_ENABLED === 'true'
            ? expireSuppressedRecipientReviewCheckouts : undefined),
        stripeFactory: context.stripeFactory,
        stripeRevocationClient: context.stripeRevocationClient || context.stripeClient,
      });
    return reviewJsonResponse(200, { acknowledged: true, ...result });
  } catch (error) {
    const [status, code] = reviewEmailInternalHttpError(error);
    return reviewJsonResponse(status, { error: code });
  }
};

export default createRetentionFencedRouteHandler({
  route: 'review-email-ack',
  paths: [PATH],
  active: ({ env }) => reviewEmailInternalApiConfiguration(env).enabled,
  handler,
});

export const config = {
  path: '/api/internal/review-email/ack', method: 'POST',
  rateLimit: { windowLimit: 60, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
