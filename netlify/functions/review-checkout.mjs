import { getStore } from '@netlify/blobs';
import { REVIEW_STORE, createApprovedCheckout, reviewPortalConfiguration } from '../lib/review-flow-core.mjs';
import {
  readReviewJson,
  requestOriginAllowed,
  reviewHttpError,
  reviewJsonResponse,
  reviewSessionCookie,
} from '../lib/review-http-core.mjs';

export default async (request, context = {}) => {
  const configuration = reviewPortalConfiguration(process.env);
  if (!configuration.enabled || !configuration.checkoutEnabled) return reviewJsonResponse(503, { error: 'checkout_unavailable' });
  if (request.method !== 'POST') return reviewJsonResponse(405, { error: 'method_not_allowed' });
  if (!requestOriginAllowed(request, true)) return reviewJsonResponse(403, { error: 'forbidden' });
  const session = reviewSessionCookie(request);
  if (!session) return reviewJsonResponse(401, { error: 'review_credential_invalid' });
  try {
    const value = await readReviewJson(request, 16);
    if (Object.keys(value).length !== 0) throw new TypeError('Checkout request fields are invalid.');
    const store = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    const result = await createApprovedCheckout(store, session, process.env, {
      clock: context.clock,
      // Deliberately absent in the default runtime. A reviewed, idempotent
      // Stripe Checkout producer must be injected before this endpoint opens.
      createCheckout: context.createCheckout,
    });
    return reviewJsonResponse(200, { checkout_url: result.checkout_url });
  } catch (error) {
    const [status, code] = reviewHttpError(error);
    return reviewJsonResponse(status, { error: code });
  }
};

export const config = {
  path: '/api/review/checkout', method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
