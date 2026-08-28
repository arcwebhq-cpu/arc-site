import { reconcileEmailProviderEvent } from './email-send-attempt-core.mjs';
import {
  verifyAndNormalizeResendWebhook,
} from './resend-transactional-provider-core.mjs';

export const RESEND_WEBHOOK_RESULT_SCHEMA = 'arc-resend-webhook-result-v1';

const REVIEW_EVENT_STATE = Object.freeze({
  'email.delivered': 'DELIVERED',
  'email.bounced': 'BOUNCED',
  'email.complained': 'COMPLAINED',
  'email.failed': 'FAILED',
  'email.suppressed': 'SUPPRESSED',
});

export async function reconcileVerifiedResendWebhook(verified, attemptStore, env = process.env, adapters = {}) {
  if (!verified.supported_event) {
    return Object.freeze({
      schema: RESEND_WEBHOOK_RESULT_SCHEMA,
      state: 'IGNORED_UNSUPPORTED',
      event_type: verified.event_type,
      idempotent_replay: false,
      unlock_delivery: false,
    });
  }
  const normalized = {
    provider: verified.provider,
    provider_event_id: verified.provider_event_id,
    provider_message_id: verified.provider_message_id,
    event_type: verified.event_type,
    occurred_at: verified.occurred_at,
    payload_sha256: verified.payload_sha256,
  };
  const reconciled = await reconcileEmailProviderEvent(attemptStore, normalized, env);
  if (reconciled.state === 'UNMAPPED') {
    throw new Error('ARC_RESEND_WEBHOOK_MESSAGE_UNMAPPED');
  }
  if (reconciled.job_kind === 'preview_review' &&
      REVIEW_EVENT_STATE[verified.event_type] === reconciled.state &&
      typeof adapters.onPreviewReviewEvent === 'function') {
    await adapters.onPreviewReviewEvent(Object.freeze({
      attempt_hmac_sha256: reconciled.attempt_hmac_sha256,
      provider: verified.provider,
      provider_event_id: verified.provider_event_id,
      provider_message_id: verified.provider_message_id,
      event_type: verified.event_type,
      occurred_at: verified.occurred_at,
      payload_sha256: verified.payload_sha256,
      idempotent_replay: reconciled.idempotent_replay,
    }));
  }
  if (['claim_invitation', 'final_delivery'].includes(reconciled.job_kind) &&
      REVIEW_EVENT_STATE[verified.event_type] === reconciled.state &&
      typeof adapters.onArc2Event === 'function') {
    await adapters.onArc2Event(Object.freeze({
      attempt_hmac_sha256: reconciled.attempt_hmac_sha256,
      job_kind: reconciled.job_kind,
      provider: verified.provider,
      provider_event_id: verified.provider_event_id,
      provider_message_id: verified.provider_message_id,
      event_type: verified.event_type,
      occurred_at: verified.occurred_at,
      payload_sha256: verified.payload_sha256,
      idempotent_replay: reconciled.idempotent_replay,
    }));
  }
  if (reconciled.unlock_delivery && typeof adapters.onDelivered === 'function') {
    await adapters.onDelivered(Object.freeze({
      attempt_hmac_sha256: reconciled.attempt_hmac_sha256,
      job_kind: reconciled.job_kind,
      provider: verified.provider,
      provider_event_id: verified.provider_event_id,
      provider_message_id: verified.provider_message_id,
      delivered_at: verified.occurred_at,
      idempotent_replay: reconciled.idempotent_replay,
    }));
  }
  return Object.freeze({
    schema: RESEND_WEBHOOK_RESULT_SCHEMA,
    state: reconciled.state,
    event_type: verified.event_type,
    idempotent_replay: reconciled.idempotent_replay,
    unlock_delivery: reconciled.unlock_delivery,
  });
}

export async function processResendWebhook(rawBody, headers, attemptStore, env = process.env, adapters = {}) {
  const verified = verifyAndNormalizeResendWebhook(rawBody, headers, env, { clock: adapters.clock });
  return reconcileVerifiedResendWebhook(verified, attemptStore, env, adapters);
}
