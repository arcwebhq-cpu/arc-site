import { getStore } from '@netlify/blobs';

import { HANDOFF_STORE } from '../lib/arc2-handoff-core.mjs';
import { reconcileArc2TransactionalEmailEvent } from '../lib/arc2-transactional-email-worker-core.mjs';
import {
  EMAIL_SEND_ATTEMPT_ENABLED_ENV,
  EMAIL_SEND_ATTEMPT_STORE,
} from '../lib/email-send-attempt-core.mjs';
import { EMAIL_RECIPIENT_VAULT_STORE } from '../lib/email-recipient-vault-core.mjs';
import {
  OPERATIONS_ALERT_STORE,
  enqueueOperationsAlertCondition,
  operationsAuditConfiguration,
} from '../lib/operations-audit-core.mjs';
import {
  RESEND_WEBHOOK_PATH,
  resendProviderConfiguration,
  verifyAndNormalizeResendWebhook,
} from '../lib/resend-transactional-provider-core.mjs';
import { reconcileVerifiedResendWebhook } from '../lib/resend-webhook-core.mjs';
import { acknowledgePreviewReviewResendEvent } from '../lib/review-email-resend-core.mjs';
import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import { expireSuppressedRecipientReviewCheckouts } from '../lib/stripe-review-checkout-adapter.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

const MAX_BODY_BYTES = 65_536;
const headers = Object.freeze({
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'Content-Type': 'application/json; charset=utf-8',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
});
const json = (status, value) => new Response(JSON.stringify(value), { status, headers });

async function readRawBody(request) {
  const declared = request.headers.get('content-length');
  if (declared !== null && (!/^\d{1,10}$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) {
    throw new RangeError('Resend webhook body is too large.');
  }
  const reader = request.body?.getReader?.();
  if (!reader) throw new TypeError('Resend webhook body is unavailable.');
  const chunks = [];
  let total = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      try { await reader.cancel(); } catch {}
      throw new RangeError('Resend webhook body is too large.');
    }
    chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
  }
  return Buffer.concat(chunks, total);
}

export function createResendWebhookHandler() {
  return async (request, context = {}) => {
    if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' });
    const configuration = resendProviderConfiguration(process.env);
    if (!configuration.webhook_enabled || process.env[EMAIL_SEND_ATTEMPT_ENABLED_ENV] !== 'true') {
      return json(503, { error: 'webhook_disabled' });
    }
    if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return json(400, { error: 'invalid_request' });
    }
    let raw;
    let verified;
    try {
      raw = await readRawBody(request);
      // Signature verification consumes the exact bytes and happens before any
      // Blob store is created or read.
      verified = verifyAndNormalizeResendWebhook(raw, request.headers, process.env, { clock: context.clock });
    } catch (error) {
      if (error instanceof RangeError) return json(413, { error: 'payload_too_large' });
      if (/SIGNATURE|TIMESTAMP/.test(error?.message || '')) return json(401, { error: 'invalid_signature' });
      return json(400, { error: 'invalid_request' });
    }
    if (!verified.supported_event) {
      return json(200, { accepted: true, state: 'IGNORED_UNSUPPORTED', unlock_delivery: false });
    }
    try {
      const store = context.attemptStore || getStore({ name: EMAIL_SEND_ATTEMPT_STORE, consistency: 'strong' });
      const result = await reconcileVerifiedResendWebhook(verified, store, process.env, {
        onDelivered: context.onDelivered,
        onArc2Event: context.onArc2Event || (async (event) => {
          const arc2Store = context.arc2Store ||
            getStore({ name: HANDOFF_STORE, consistency: 'strong' });
          const reviewStore = context.reviewStore ||
            getStore({ name: REVIEW_STORE, consistency: 'strong' });
          const vaultStore = context.vaultStore ||
            getStore({ name: EMAIL_RECIPIENT_VAULT_STORE, consistency: 'strong' });
          let enqueueNegativeEvent = context.enqueueNegativeEvent;
          if (!enqueueNegativeEvent && operationsAuditConfiguration(process.env).enabled) {
            enqueueNegativeEvent = async (input) => enqueueOperationsAlertCondition(
              context.operationsAlertStore ||
                getStore({ name: OPERATIONS_ALERT_STORE, consistency: 'strong' }),
              input,
              process.env,
              { clock: context.clock },
            );
          }
          return reconcileArc2TransactionalEmailEvent({
            ledger: arc2Store,
            review: reviewStore,
            vault: vaultStore,
          }, event, process.env, {
            clock: context.clock,
            fetch: context.fetch,
            randomBytes: context.randomBytes,
            stripeAccountFetch: context.stripeAccountFetch,
            stripeFactory: context.stripeFactory,
            stripeClient: context.stripeClient,
            enqueueNegativeEvent,
          });
        }),
        onPreviewReviewEvent: context.onPreviewReviewEvent || (async (event) => {
          const reviewStore = context.reviewStore ||
            getStore({ name: REVIEW_STORE, consistency: 'strong' });
          return acknowledgePreviewReviewResendEvent(reviewStore, event, process.env, {
            clock: context.clock,
            vaultStore: context.vaultStore ||
              getStore({ name: EMAIL_RECIPIENT_VAULT_STORE, consistency: 'strong' }),
            expireRecipientCheckouts: context.expireRecipientCheckouts ||
              (process.env.ARC_STRIPE_REVIEW_REVOCATION_ENABLED === 'true'
                ? expireSuppressedRecipientReviewCheckouts : undefined),
            stripeFactory: context.stripeFactory,
            stripeRevocationClient: context.stripeRevocationClient || context.stripeClient,
          });
        }),
      });
      return json(200, {
        accepted: true,
        state: result.state,
        event_type: result.event_type,
        idempotent_replay: result.idempotent_replay,
        unlock_delivery: result.unlock_delivery,
      });
    } catch (error) {
      if (error?.message === 'ARC_RESEND_WEBHOOK_MESSAGE_UNMAPPED') {
        return json(503, { error: 'message_mapping_pending' });
      }
      return json(503, { error: 'webhook_unavailable' });
    }
  };
}

const handler = createResendWebhookHandler();

export default createRetentionFencedRouteHandler({
  route: 'resend-webhook',
  paths: [RESEND_WEBHOOK_PATH],
  active: ({ env }) => resendProviderConfiguration(env).webhook_enabled &&
    env[EMAIL_SEND_ATTEMPT_ENABLED_ENV] === 'true',
  handler,
});

export const config = {
  // Netlify's static extractor requires this path to remain an inline literal.
  path: '/api/webhooks/resend', method: 'POST',
  rateLimit: { windowLimit: 180, windowSize: 60, aggregateBy: ['domain'] },
};
