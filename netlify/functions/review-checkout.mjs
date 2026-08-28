import { getStore } from '@netlify/blobs';
import { REVIEW_STORE, createApprovedCheckout, reviewPortalConfiguration } from '../lib/review-flow-core.mjs';
import { REVIEW_ACTIVATION_RUNTIME_READBACK_STORE } from
  '../lib/review-activation-runtime-readback-core.mjs';
import { createStripeReviewCheckoutAdapter } from '../lib/stripe-review-checkout-adapter.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';
import {
  readReviewJson,
  requestOriginAllowed,
  reviewHttpError,
  reviewJsonResponse,
  reviewSessionCookie,
} from '../lib/review-http-core.mjs';

const handler = async (request, context = {}) => {
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
    const runtimeReadbackRequested = process.env.ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED === 'true';
    const readbackStore = context.readbackStore || (runtimeReadbackRequested
      ? getStore({ name: REVIEW_ACTIVATION_RUNTIME_READBACK_STORE, consistency: 'strong' })
      : undefined);
    const createCheckout = context.createCheckout || createStripeReviewCheckoutAdapter(process.env, {
      clock: context.clock,
      fetch: context.fetch,
      readbackStore,
      store,
      stripeClient: context.stripeClient,
      stripeFactory: context.stripeFactory,
    });
    const result = await createApprovedCheckout(store, session, process.env, {
      clock: context.clock,
      createCheckout,
    });
    return reviewJsonResponse(200, { checkout_url: result.checkout_url });
  } catch (error) {
    const [status, code] = reviewHttpError(error);
    return reviewJsonResponse(status, { error: code });
  }
};

export default createRetentionFencedRouteHandler({
  route: 'review-checkout',
  paths: ['/api/review/checkout'],
  active: ({ env }) => {
    const configuration = reviewPortalConfiguration(env);
    return configuration.enabled && configuration.checkoutEnabled;
  },
  handler,
});

export const config = {
  path: '/api/review/checkout', method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
