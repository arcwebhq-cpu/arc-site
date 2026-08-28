import { createHash, createHmac } from 'node:crypto';

import {
  EMAIL_SEND_ATTEMPT_HMAC_SECRET_ENV,
  emailSendAttemptConfiguration,
  markEmailProviderAccepted,
  reserveEmailSendAttempt,
} from './email-send-attempt-core.mjs';
import {
  emailRecipientVaultConfiguration,
  openEmailRecipientCapsule,
  sealEmailRecipientCapsule,
} from './email-recipient-vault-core.mjs';
import {
  INTAKE_CONFIRMATION_COMPLETION_REQUEST_SCHEMA,
  claimNextIntakeConfirmationOutbox,
  completeIntakeConfirmationOutbox,
  intakeConfirmationRuntimeConfigured,
} from './intake-confirmation-outbox-core.mjs';
import { canonicalJson } from './intake-arc1-bridge-core.mjs';
import {
  resendProviderConfiguration,
  sendResendTransactionalEmail,
} from './resend-transactional-provider-core.mjs';
import {
  previewReviewResendWorkerConfiguration,
  runPreviewReviewResendWorkerCycle,
} from './review-email-resend-core.mjs';
import { renderTransactionalEmail } from './transactional-email-template-core.mjs';
import { sealTransactionalEmailAttemptContext } from './transactional-email-attempt-context-core.mjs';
import {
  arc2TransactionalEmailWorkerConfiguration,
  runArc2TransactionalEmailWorkerCycle,
} from './arc2-transactional-email-worker-core.mjs';

export const TRANSACTIONAL_EMAIL_WORKER_ENABLED_ENV = 'ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED';
export const TRANSACTIONAL_EMAIL_WORKER_SCHEMA = 'arc-transactional-email-worker-result-v1';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export function transactionalEmailWorkerConfiguration(env = process.env) {
  const attempts = emailSendAttemptConfiguration(env);
  const vault = emailRecipientVaultConfiguration(env);
  const resend = resendProviderConfiguration(env);
  const masterEnabled = env[TRANSACTIONAL_EMAIL_WORKER_ENABLED_ENV] === 'true' && attempts.enabled && vault.enabled &&
    resend.send_enabled && resend.webhook_enabled;
  const intakeEnabled = masterEnabled && intakeConfirmationRuntimeConfigured(env);
  const previewReviewEnabled = masterEnabled && previewReviewResendWorkerConfiguration(env).enabled;
  const arc2 = arc2TransactionalEmailWorkerConfiguration(env);
  const claimInvitationEnabled = masterEnabled && arc2.claim_invitation_enabled;
  const finalDeliveryEnabled = masterEnabled && arc2.final_delivery_enabled;
  return Object.freeze({
    enabled: intakeEnabled || previewReviewEnabled || claimInvitationEnabled || finalDeliveryEnabled,
    intake_enabled: intakeEnabled,
    preview_review_enabled: previewReviewEnabled,
    claim_invitation_enabled: claimInvitationEnabled,
    final_delivery_enabled: finalDeliveryEnabled,
  });
}

function consumerAttemptId(outboxId, env) {
  return `arcconfirmattempt_${createHmac('sha256', env[EMAIL_SEND_ATTEMPT_HMAC_SECRET_ENV])
    .update(`arc-intake-confirmation-consumer-attempt-v1\n${outboxId}`).digest('hex').slice(0, 40)}`;
}

async function providerMessage(claim, vaultStore, env, adapters) {
  if (!claim.message || claim.message.template_id !== 'arc-intake-confirmation-v1') {
    throw new TypeError('Intake confirmation message is invalid.');
  }
  const capsule = await openEmailRecipientCapsule(vaultStore, {
    job_kind: 'intake_confirmation', job_key: claim.outbox_id,
  }, env, adapters);
  const value = capsule.private_payload;
  if (capsule.vault_hmac_sha256 !== claim.recipient_vault_hmac_sha256 || !value ||
      typeof value !== 'object' || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([
        'schema', 'source_submission_data_sha256', 'verification_id_hmac_sha256', 'verification_url',
      ]) || value.schema !== 'arc-intake-confirmation-private-v1' ||
      value.source_submission_data_sha256 !== claim.source_submission_data_sha256 ||
      value.verification_id_hmac_sha256 !== claim.verification_id_hmac_sha256) {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_CONFIRMATION_CAPSULE_INVALID');
  }
  const recipientIdentity = createHmac('sha256', env.ARC_INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET)
    .update(`arc-intake-email-verification-recipient-v1\n${capsule.recipient_email}`).digest('hex');
  if (recipientIdentity !== claim.recipient_identity_hmac_sha256) {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_CONFIRMATION_CAPSULE_INVALID');
  }
  const rendered = renderTransactionalEmail('intake_confirmation', {
    recipient_email: capsule.recipient_email,
    verification_url: value.verification_url,
  });
  return {
    to: rendered.to,
    subject: rendered.subject,
    text: rendered.text,
    html: rendered.html,
    tags: [{ name: 'arc_kind', value: 'intake_confirmation' }],
  };
}

function capsuleJobKey(outboxId) {
  return `${outboxId}:resend-acceptance-v1`;
}

async function persistAcceptanceCapsule(vaultStore, claim, accepted, recipientEmail, env, adapters) {
  await sealEmailRecipientCapsule(vaultStore, {
    job_kind: 'intake_confirmation',
    job_key: capsuleJobKey(claim.outbox_id),
    recipient_email: recipientEmail,
    private_payload: {
      accepted_at: accepted.accepted_at,
      provider_message_id: accepted.provider_message_id,
    },
    expires_at: claim.claim_expires_at,
  }, env, adapters);
}

async function recoverAcceptanceCapsule(vaultStore, claim, env, adapters) {
  const capsule = await openEmailRecipientCapsule(vaultStore, {
    job_kind: 'intake_confirmation',
    job_key: capsuleJobKey(claim.outbox_id),
  }, env, adapters);
  const value = capsule.private_payload;
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['accepted_at', 'provider_message_id']) ||
      typeof value.provider_message_id !== 'string' || typeof value.accepted_at !== 'string') {
    throw new Error('ARC_TRANSACTIONAL_EMAIL_ACCEPTANCE_CAPSULE_INVALID');
  }
  return { provider: 'resend', provider_message_id: value.provider_message_id, accepted_at: value.accepted_at };
}

async function completeIntakeClaim(confirmationStore, claim, accepted, env, adapters) {
  const raw = canonicalJson({
    schema: INTAKE_CONFIRMATION_COMPLETION_REQUEST_SCHEMA,
    submission_id: claim.submission_id,
    outbox_id: claim.outbox_id,
    consumer_attempt_id: claim.consumer_attempt_id,
    claim_token: claim.claim_token,
    provider: 'resend',
    provider_message_id: accepted.provider_message_id,
    sent_at: accepted.accepted_at,
  });
  const receiptSha = sha256(raw);
  const receiptHmac = createHmac('sha256', env.ARC_INTAKE_CONFIRMATION_RECEIPT_SECRET)
    .update(`arc-intake-confirmation-completion-v1\n${raw}`).digest('hex');
  const request = new Request(claim.completion_endpoint, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.ARC_INTAKE_CONFIRMATION_CONSUMER_BEARER}`,
      'content-type': 'application/json',
      'idempotency-key': `arcconfirmcomplete_${receiptSha.slice(0, 40)}`,
      'x-arc-intake-confirmation-receipt-hmac-sha256': receiptHmac,
    },
    body: raw,
  });
  return completeIntakeConfirmationOutbox(raw, request, env, confirmationStore, adapters);
}

export async function runIntakeConfirmationWorkerCycle(env, stores, adapters = {}) {
  if (!stores?.confirmation || !stores?.attempt || !stores?.vault) {
    throw new TypeError('Transactional email worker stores are invalid.');
  }
  const claim = await claimNextIntakeConfirmationOutbox(env, stores.confirmation, {
    clock: adapters.clock,
    consumerAttemptId: (record) => consumerAttemptId(record.outbox_id, env),
  });
  if (!claim.found) {
    return Object.freeze({ state: 'IDLE', processed: 0 });
  }
  const message = await providerMessage(claim, stores.vault, env, { clock: adapters.clock });
  const resend = resendProviderConfiguration(env);
  const reservation = await reserveEmailSendAttempt(stores.attempt, {
    job_kind: 'intake_confirmation',
    job_key: claim.outbox_id,
    provider_idempotency_key: claim.provider_idempotency_key,
    recipient_email_sha256: createHmac('sha256', env[EMAIL_SEND_ATTEMPT_HMAC_SECRET_ENV])
      .update(`arc-intake-confirmation-recipient-v1\n${message.to}`).digest('hex'),
    sender_sha256: sha256(resend.from),
    message_sha256: sha256(canonicalJson(message)),
  }, env, { clock: adapters.clock });
  await sealTransactionalEmailAttemptContext(stores.vault, {
    job_kind: 'intake_confirmation',
    job_key: claim.outbox_id,
    attempt_hmac_sha256: reservation.attempt_hmac_sha256,
    recipient_email: message.to,
    context: {
      recipient_identity_hmac_sha256: claim.recipient_identity_hmac_sha256,
      source_submission_data_sha256: claim.source_submission_data_sha256,
      verification_id_hmac_sha256: claim.verification_id_hmac_sha256,
    },
    expires_at: claim.claim_expires_at,
  }, env, { clock: adapters.clock, randomBytes: adapters.randomBytes });
  if (reservation.decision === 'REVIEW_REQUIRED') {
    return Object.freeze({ state: 'REVIEW_REQUIRED', processed: 0 });
  }
  let accepted;
  let recoveredAcceptance = reservation.decision === 'DO_NOT_SEND';
  if (reservation.decision === 'DO_NOT_SEND') {
    accepted = await recoverAcceptanceCapsule(stores.vault, claim, env, { clock: adapters.clock });
  } else {
    // A prior invocation may have persisted the exact provider response and
    // crashed before it could transition INTENT to PROVIDER_ACCEPTED. Recover
    // that capsule first; only a true NOT_FOUND is permission to call Resend.
    try {
      accepted = await recoverAcceptanceCapsule(stores.vault, claim, env, { clock: adapters.clock });
      recoveredAcceptance = true;
    } catch (error) {
      if (error?.message !== 'ARC_EMAIL_VAULT_NOT_FOUND') throw error;
      accepted = await sendResendTransactionalEmail(message, claim.provider_idempotency_key, env, {
        fetch: adapters.fetch,
        clock: adapters.clock,
      });
      await persistAcceptanceCapsule(stores.vault, claim, accepted, message.to, env, { clock: adapters.clock,
        randomBytes: adapters.randomBytes });
    }
    await markEmailProviderAccepted(stores.attempt, {
      attempt_hmac_sha256: reservation.attempt_hmac_sha256,
      provider_message_id: accepted.provider_message_id,
    }, env, { clock: adapters.clock });
  }
  const completion = await completeIntakeClaim(stores.confirmation, claim, accepted, env, { clock: adapters.clock });
  return Object.freeze({
    state: 'PROVIDER_ACCEPTED',
    processed: 1,
    intake_state: completion.status,
    idempotent_replay: recoveredAcceptance,
  });
}

function withSchema(result) {
  return Object.freeze({ schema: TRANSACTIONAL_EMAIL_WORKER_SCHEMA, ...result });
}

export function transactionalEmailChannelOrder(nowValue, configuration) {
  const now = nowValue instanceof Date ? new Date(nowValue.getTime()) : new Date(nowValue);
  if (!Number.isFinite(now.getTime())) throw new TypeError('Transactional email worker clock is invalid.');
  const names = ['intake_confirmation', 'preview_review', 'claim_invitation', 'final_delivery'];
  const enabled = {
    intake_confirmation: configuration.intake_enabled === true,
    preview_review: configuration.preview_review_enabled === true,
    claim_invitation: configuration.claim_invitation_enabled === true,
    final_delivery: configuration.final_delivery_enabled === true,
  };
  const start = Math.floor(now.getTime() / 60_000) % names.length;
  return Object.freeze([...names.slice(start), ...names.slice(0, start)].filter((name) => enabled[name]));
}

export async function runTransactionalEmailWorkerCycle(env, stores, adapters = {}) {
  const configuration = transactionalEmailWorkerConfiguration(env);
  if (!configuration.enabled) {
    return withSchema({ state: 'DISABLED', processed: 0 });
  }
  if (!stores?.attempt || !stores?.vault) {
    throw new TypeError('Transactional email worker stores are invalid.');
  }
  // Retention is intentionally orchestrated before this producer-only cycle
  // by the function entry point. It must acquire FROZEN independently; this
  // worker's sends remain under the outer WRITING route fence.
  const channelDefinitions = Object.freeze([
    Object.freeze({
      name: 'intake_confirmation', enabled: configuration.intake_enabled,
      run: () => runIntakeConfirmationWorkerCycle(env, stores, adapters),
    }),
    Object.freeze({
      name: 'preview_review', enabled: configuration.preview_review_enabled,
      run: () => runPreviewReviewResendWorkerCycle(env, stores, adapters),
    }),
    Object.freeze({
      name: 'claim_invitation', enabled: configuration.claim_invitation_enabled,
      run: () => runArc2TransactionalEmailWorkerCycle('claim_invitation', env, stores, adapters),
    }),
    Object.freeze({
      name: 'final_delivery', enabled: configuration.final_delivery_enabled,
      run: () => runArc2TransactionalEmailWorkerCycle('final_delivery', env, stores, adapters),
    }),
  ]);
  const enabled = channelDefinitions.filter((channel) => channel.enabled);
  if (enabled.length === 1) return withSchema(await enabled[0].run());

  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Transactional email worker clock is invalid.');
  // Rotate the first eligible channel every UTC minute. One successful send
  // ends the invocation, so a perpetually busy intake queue cannot starve
  // preview, claim, or final-delivery work.
  const orderByName = transactionalEmailChannelOrder(now, configuration);
  const order = orderByName.map((name) => channelDefinitions.find((channel) => channel.name === name));
  const states = Object.fromEntries(channelDefinitions.map((channel) =>
    [channel.name, channel.enabled ? 'NOT_RUN' : 'DISABLED']));
  const errors = [];
  let processed = 0;
  let reviewRequired = false;
  for (const channel of order) {
    try {
      const result = await channel.run();
      states[channel.name] = result.state;
      processed += result.processed;
      reviewRequired ||= result.state === 'REVIEW_REQUIRED';
      if (result.processed > 0) break;
    } catch (error) {
      states[channel.name] = 'ERROR';
      errors.push({ channel: channel.name, error });
    }
  }
  if (errors.length === enabled.length) {
    throw new AggregateError(errors.map((entry) => entry.error), 'Transactional email channels failed.');
  }
  const state = errors.length > 0 ? 'PARTIAL_FAILURE' : processed > 0 ? 'PROCESSED' :
    reviewRequired ? 'REVIEW_REQUIRED' : 'IDLE';
  return withSchema({
    state,
    processed,
    channels: Object.freeze(states),
    error_channels: Object.freeze(errors.map((entry) => entry.channel)),
  });
}
