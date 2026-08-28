import { getStore } from '@netlify/blobs';

import {
  arc2ClaimLinkRenewalConfiguration,
  requestClaimLinkRenewal,
  sameOriginClaimLinkRenewalRequest,
} from '../lib/arc2-claim-link-renewal-core.mjs';
import { HANDOFF_STORE, configuredEnvironment, jsonResponse } from '../lib/arc2-handoff-core.mjs';
import { EMAIL_SEND_ATTEMPT_STORE } from '../lib/email-send-attempt-core.mjs';
import { EMAIL_RECIPIENT_VAULT_STORE } from '../lib/email-recipient-vault-core.mjs';
import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

export function createClaimLinkRenewalHandler() {
  return async (request, context = {}) => {
    if (!configuredEnvironment(process.env).enabled ||
        !arc2ClaimLinkRenewalConfiguration(process.env).enabled) {
      return jsonResponse(503, { error: 'claim_link_renewal_disabled' });
    }
    if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
    if (!sameOriginClaimLinkRenewalRequest(request, process.env)) {
      return jsonResponse(403, { error: 'same_origin_required' });
    }
    const authorization = request.headers.get('authorization') || '';
    const handoffId = request.headers.get('x-arc-handoff-id') || '';
    if (!/^Bearer [A-Za-z0-9_-]{43}$/.test(authorization) ||
        !/^[a-f0-9]{64}$/.test(handoffId)) {
      return jsonResponse(401, { error: 'claim_bearer_invalid_or_expired' });
    }
    try {
      const stores = {
        ledger: context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' }),
        attempt: context.attemptStore || getStore({ name: EMAIL_SEND_ATTEMPT_STORE, consistency: 'strong' }),
        review: context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' }),
        vault: context.vaultStore || getStore({ name: EMAIL_RECIPIENT_VAULT_STORE, consistency: 'strong' }),
      };
      const result = await requestClaimLinkRenewal({
        handoff_id: handoffId,
        bearer: authorization.slice(7),
      }, process.env, stores, {
        clock: context.clock,
        fetch: context.fetch,
        stripeAccountFetch: context.stripeAccountFetch,
        stripeFactory: context.stripeFactory,
        stripeClient: context.stripeClient,
      });
      if (!result) return jsonResponse(404, { error: 'handoff_not_found' });
      return jsonResponse(202, { status: 'fresh_ownership_link_queued' });
    } catch (error) {
      const message = error?.message || '';
      if (/ARC2_CLAIM_RENEWAL_RECIPIENT_(?:SUPPRESSED|CONTINUITY_INVALID)/.test(message) ||
          /ARC2_(?:CLAIM_INVITATION|EMAIL)_NEGATIVE/.test(message) ||
          /ARC2_CLAIM_EMAIL_REVIEW_REQUIRED/.test(message) ||
          /ARC_PAYMENT_ARC2_REVIEW_REQUIRED/.test(message)) {
        return jsonResponse(409, { error: 'claim_link_delivery_blocked' });
      }
      if (/ARC_STRIPE_(?:REVERSAL_HALT|CHECKOUT_(?:LEDGER_HALT|HANDOFF_BINDING_CONFLICT|PAYMENT_NOT_PAID))/.test(message)) {
        return jsonResponse(409, { error: 'fulfillment_halted' });
      }
      if (/ARC_STRIPE_(?:CHECKOUT|ACCOUNT)_/.test(message)) {
        return jsonResponse(503, { error: 'payment_control_unavailable' });
      }
      if (/ARC2_CLAIM_RENEWAL_NOT_EXPIRED/.test(message)) {
        return jsonResponse(409, { error: 'claim_link_not_expired' });
      }
      if (/ARC2_CLAIM_BEARER_INVALID/.test(message)) {
        return jsonResponse(401, { error: 'claim_bearer_invalid_or_expired' });
      }
      return jsonResponse(503, { error: 'claim_link_renewal_unavailable' });
    }
  };
}

const handler = createClaimLinkRenewalHandler();

export default createRetentionFencedRouteHandler({
  route: 'arc2-claim-link-renew',
  paths: ['/api/arc2/claim-link-renew'],
  active: ({ env }) => configuredEnvironment(env).enabled &&
    arc2ClaimLinkRenewalConfiguration(env).enabled,
  handler,
});

export const config = {
  path: '/api/arc2/claim-link-renew',
  method: 'POST',
  rateLimit: { windowLimit: 2, windowSize: 3600, aggregateBy: ['ip', 'domain'] },
};
