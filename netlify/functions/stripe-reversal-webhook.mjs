import { getStore } from '@netlify/blobs';
import { HANDOFF_STORE, jsonResponse } from '../lib/arc2-handoff-core.mjs';
import {
  PAYMENT_ARC2_OUTBOX_STORE,
  createPaymentArc2StartOutbox,
  paymentArc2BridgeConfiguration,
} from '../lib/payment-arc2-bridge-core.mjs';
import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import {
  processStripeReversalEvent,
  stripeReversalConfiguration,
} from '../lib/stripe-reversal-core.mjs';
import {
  processStripeCheckoutEvent,
  stripeCheckoutConfiguration,
} from '../lib/stripe-checkout-core.mjs';
import { retrieveStripeReviewCheckoutAuthority } from '../lib/stripe-review-checkout-adapter.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const ALERT_STORE = 'arc-operations-alerts';

const handler = async (request, context = {}) => {
  const reversalConfiguration = stripeReversalConfiguration(process.env);
  const checkoutConfiguration = stripeCheckoutConfiguration(process.env);
  const paymentArc2Configuration = paymentArc2BridgeConfiguration(process.env);
  if (!reversalConfiguration.webhookOperational && !checkoutConfiguration.webhookOperational) {
    return jsonResponse(503, { error: 'stripe_webhook_control_disabled' });
  }
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return jsonResponse(415, { error: 'json_required' });
  }
  const contentLength = request.headers.get('content-length');
  if (contentLength !== null && (!/^\d{1,7}$/.test(contentLength) || Number(contentLength) > 1_048_576)) {
    return jsonResponse(413, { error: 'webhook_too_large' });
  }
  try {
    const reader = request.body?.getReader();
    if (!reader) return jsonResponse(400, { error: 'invalid_webhook' });
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 1_048_576) {
        await reader.cancel();
        return jsonResponse(413, { error: 'webhook_too_large' });
      }
      chunks.push(Buffer.from(value));
    }
    const body = Buffer.concat(chunks, size).toString('utf8');
    if (!body) return jsonResponse(400, { error: 'invalid_webhook' });
    const store = context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' });
    const alertStore = context.alertStore || getStore({ name: ALERT_STORE, consistency: 'strong' });
    let eventType;
    try { eventType = JSON.parse(body)?.type; } catch {}
    if (typeof eventType === 'string' && eventType.startsWith('checkout.session.')) {
      if (!checkoutConfiguration.webhookOperational) return jsonResponse(503, { error: 'stripe_checkout_control_disabled' });
      const result = await processStripeCheckoutEvent(
        body,
        request.headers.get('stripe-signature'),
        process.env,
        { store, alertStore, clock: context.clock, accountFetch: context.stripeAccountFetch },
      );
      let paymentArc2Outbox = null;
      const isPaidReviewCheckout = result.summary.state === 'PAID' &&
        result.summary.review_checkout_binding?.schema === 'arc-review-checkout-session-v1';
      if (isPaidReviewCheckout && !paymentArc2Configuration.enabled) {
        // The signed ledger/receipt is already durable. A retriable response is
        // required so Stripe redelivers after the default-off bridge is made
        // ready; returning 200 here would strand captured customer funds.
        throw new Error('ARC_PAYMENT_ARC2_BRIDGE_DISABLED');
      }
      if (isPaidReviewCheckout) {
        const reviewStore = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
        const bridgeStore = context.paymentArc2BridgeStore ||
          getStore({ name: PAYMENT_ARC2_OUTBOX_STORE, consistency: 'strong' });
        const retrieveCheckoutSessionAuthority = context.paymentArc2ProviderAuthority ||
          ((sessionId, options) => retrieveStripeReviewCheckoutAuthority(
            sessionId,
            options,
            process.env,
            { stripeClient: context.stripeCheckoutAuthorityClient },
          ));
        paymentArc2Outbox = await createPaymentArc2StartOutbox({
          review: reviewStore,
          ledger: store,
          bridge: bridgeStore,
        }, {
          invite_hmac_sha256: result.summary.review_checkout_binding.invite_hmac_sha256,
          checkout_session_id: result.event.sessionId,
        }, process.env, {
          clock: context.clock,
          retrieveCheckoutSessionAuthority,
        });
      }
      return jsonResponse(200, {
        accepted: true,
        checkout_state: result.summary.state,
        idempotent_replay: result.idempotentReplay,
        fulfillment_halted: result.summary.fulfillment_allowed !== true,
        ...(paymentArc2Outbox === null ? {} : {
          payment_arc2_outbox_state: paymentArc2Outbox.state,
          payment_arc2_outbox_idempotent_replay: paymentArc2Outbox.idempotent_replay,
        }),
      });
    }
    if (!reversalConfiguration.webhookOperational) return jsonResponse(503, { error: 'stripe_reversal_control_disabled' });
    const result = await processStripeReversalEvent(
      body,
      request.headers.get('stripe-signature'),
      process.env,
      { store, alertStore, clock: context.clock, accountFetch: context.stripeAccountFetch },
    );
    return jsonResponse(200, {
      accepted: true,
      handoff_id: result.handoffId,
      idempotent_replay: result.idempotentReplay,
      fulfillment_halted: true,
    });
  } catch (error) {
    if (error instanceof TypeError || error?.name === 'SyntaxError') return jsonResponse(400, { error: 'invalid_webhook' });
    if (/UNBOUND|MISSING/.test(error?.message || '')) return jsonResponse(409, { error: 'binding_not_ready' });
    if (/CONFLICT/.test(error?.message || '')) return jsonResponse(409, { error: 'webhook_conflict' });
    return jsonResponse(503, { error: 'webhook_unavailable' });
  }
};

export default createRetentionFencedRouteHandler({
  route: 'stripe-unified-webhook',
  paths: ['/internal/stripe/reversal-webhook'],
  maxRequestBytes: 1_048_576,
  active: ({ env }) => stripeReversalConfiguration(env).webhookOperational ||
    stripeCheckoutConfiguration(env).webhookOperational,
  handler,
});

export const config = {
  path: '/internal/stripe/reversal-webhook',
  method: 'POST',
  rateLimit: { windowLimit: 120, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
