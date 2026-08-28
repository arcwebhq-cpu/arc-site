import { getStore } from '@netlify/blobs';

import {
  REVIEW_ACTIVATION_RUNTIME_READBACK_STORE,
  refreshReviewActivationRuntimeReadback,
  reviewActivationRuntimeReadbackConfiguration,
} from '../lib/review-activation-runtime-readback-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

export function createReviewActivationReadbackRefreshHandler() {
  return async (_request, context = {}) => {
    const now = context.clock?.() || new Date();
    const configuration = reviewActivationRuntimeReadbackConfiguration(process.env, now);
    // The scheduled surface is inert by default and does not create a Blob
    // handle or make a network request until the deployment-bound manifest,
    // verifier key, URL, and explicit production switch are all valid.
    if (!configuration.enabled) return new Response(null, { status: 204 });
    try {
      const store = context.readbackStore || getStore({
        name: REVIEW_ACTIVATION_RUNTIME_READBACK_STORE,
        consistency: 'strong',
      });
      await refreshReviewActivationRuntimeReadback(process.env, store, now, {
        fetch: context.fetch,
      });
      return new Response(null, {
        status: 204,
        headers: { 'Cache-Control': 'no-store' },
      });
    } catch {
      return new Response(JSON.stringify({ error: 'runtime_readback_refresh_unavailable' }), {
        status: 503,
        headers: {
          'Cache-Control': 'no-store',
          'Content-Type': 'application/json; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }
  };
}

const handler = createReviewActivationReadbackRefreshHandler();

export default createRetentionFencedRouteHandler({
  route: 'review-activation-readback-refresh',
  methods: null,
  active: ({ env, context }) =>
    env.ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED === 'true' &&
    reviewActivationRuntimeReadbackConfiguration(
      env, context.clock?.() || new Date(),
    ).enabled,
  handler,
});

export const config = { schedule: '*/5 * * * *' };
