import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import {
  arc2TransactionalEmailConfiguration,
  createFinalDeliveryReceiptEvidence,
  discoverNextClaimInvitationEmail,
  discoverNextFinalDeliveryEmail,
  prepareClaimInvitationEmailJob,
  prepareFinalDeliveryEmailJob,
} from './arc2-transactional-email-core.mjs';
import {
  assertArc2EmailNegativeStateAllows,
  persistArc2NegativeEmailState,
  recoverArc2NegativeAttemptBinding,
} from './arc2-negative-email-state-core.mjs';
import { acknowledgeFinalDelivery } from './arc2-handoff-service.mjs';
import {
  emailSendAttemptConfiguration,
  markEmailProviderAccepted,
  readEmailSendAttempt,
  reserveEmailSendAttempt,
} from './email-send-attempt-core.mjs';
import {
  emailRecipientVaultConfiguration,
  openEmailRecipientCapsule,
  sealEmailRecipientCapsule,
} from './email-recipient-vault-core.mjs';
import {
  resendProviderConfiguration,
  sendResendTransactionalEmail,
} from './resend-transactional-provider-core.mjs';
import { renderTransactionalEmail } from './transactional-email-template-core.mjs';

export const ARC2_EMAIL_ATTEMPT_CONTEXT_SCHEMA = 'arc2-email-attempt-context-v1';
export const ARC2_EMAIL_FINAL_RECEIPT_CAPSULE_SCHEMA = 'arc2-email-final-receipt-capsule-v1';

const HEX_64 = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const TERMINAL_ATTEMPT_STATES = new Set(['DELIVERED', 'BOUNCED', 'COMPLAINED', 'FAILED', 'SUPPRESSED']);
const NEGATIVE_EVENT_TYPES = new Set([
  'email.bounced', 'email.complained', 'email.failed', 'email.suppressed',
]);
const CONTEXT_FIELDS = Object.freeze([
  'attempt_hmac_sha256', 'handoff_id', 'job_key', 'job_key_sha256', 'message_sha256',
  'provider_idempotency_key_sha256', 'recipient_email_sha256', 'schema',
  'source_invite_hmac_sha256', 'version',
]);
const RECEIPT_FIELDS = Object.freeze([
  'delivered_at', 'delivery_receipt_evidence', 'delivery_receipt_evidence_hmac_sha256',
  'handoff_id', 'job_key', 'provider_event_id', 'provider_message_id', 'schema', 'version',
]);

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const exactKeys = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
const safeEqual = (left, right) => {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
};

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError('ARC2 email worker value is invalid.');
    }
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const result = JSON.stringify(value);
  if (result === undefined) throw new TypeError('ARC2 email worker value is invalid.');
  return result;
}

function validKind(kind) {
  if (!['claim_invitation', 'final_delivery'].includes(kind)) {
    throw new TypeError('ARC2 email worker kind is invalid.');
  }
  return kind;
}

function validClock(adapters) {
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('ARC2 email worker clock is invalid.');
  return now;
}

function contextJobKey(attemptHmac) {
  if (!HEX_64.test(String(attemptHmac || ''))) throw new TypeError('ARC2 email attempt is invalid.');
  return `attempt-context:${attemptHmac}`;
}

function acceptanceJobKey(attemptHmac) {
  if (!HEX_64.test(String(attemptHmac || ''))) throw new TypeError('ARC2 email attempt is invalid.');
  return `attempt-acceptance:${attemptHmac}`;
}

function receiptJobKey(attemptHmac, providerEventId) {
  if (!HEX_64.test(String(attemptHmac || '')) || typeof providerEventId !== 'string' ||
      providerEventId.length < 1 || Buffer.byteLength(providerEventId, 'utf8') > 512) {
    throw new TypeError('ARC2 final receipt capsule binding is invalid.');
  }
  return `final-receipt:${attemptHmac}:${sha256(providerEventId)}`;
}

export function arc2TransactionalEmailWorkerConfiguration(env = process.env) {
  const arc2 = arc2TransactionalEmailConfiguration(env);
  const attempts = emailSendAttemptConfiguration(env);
  const vault = emailRecipientVaultConfiguration(env);
  const resend = resendProviderConfiguration(env);
  const common = attempts.enabled && vault.enabled && resend.send_enabled && resend.webhook_enabled;
  return Object.freeze({
    enabled: common && (arc2.claim_invitation_enabled || arc2.final_delivery_enabled),
    claim_invitation_enabled: common && arc2.claim_invitation_enabled,
    final_delivery_enabled: common && arc2.final_delivery_enabled,
  });
}

function providerIdempotencyKey(kind, jobKey, env) {
  const attempt = emailSendAttemptConfiguration(env);
  if (!attempt.enabled) throw new Error('ARC_TRANSACTIONAL_EMAIL_DISABLED');
  return `arc2email_${hmac(attempt.hmacSecret,
    `arc2-resend-provider-idempotency-v1\n${kind}\n${jobKey}`).slice(0, 48)}`;
}

function attemptRecipientIdentity(recipientEmail, env) {
  const attempt = emailSendAttemptConfiguration(env);
  if (!attempt.enabled) throw new Error('ARC_TRANSACTIONAL_EMAIL_DISABLED');
  return hmac(attempt.hmacSecret,
    `arc2-transactional-email-recipient-v1\n${recipientEmail}`);
}

function outboundMessage(job) {
  const input = job.kind === 'claim_invitation'
    ? { recipient_email: job.recipient_email, claim_url: job.claim_url }
    : { recipient_email: job.recipient_email, production_url: job.production_url };
  const rendered = renderTransactionalEmail(job.kind, input);
  return Object.freeze({
    to: rendered.to,
    subject: rendered.subject,
    text: rendered.text,
    html: rendered.html,
    tags: [{ name: 'arc_kind', value: job.kind }],
  });
}

function contextPayload(job, reservation, idempotencyKey, message) {
  return {
    schema: ARC2_EMAIL_ATTEMPT_CONTEXT_SCHEMA,
    version: 1,
    attempt_hmac_sha256: reservation.attempt_hmac_sha256,
    handoff_id: job.handoff_id,
    job_key: job.job_key,
    job_key_sha256: sha256(job.job_key),
    recipient_email_sha256: job.recipient_email_sha256,
    source_invite_hmac_sha256: job.source_invite_hmac_sha256,
    provider_idempotency_key_sha256: sha256(idempotencyKey),
    message_sha256: sha256(canonicalJson(message)),
  };
}

function validateContextPayload(value, kind, recipientEmail) {
  if (!exactKeys(value, CONTEXT_FIELDS) || value.schema !== ARC2_EMAIL_ATTEMPT_CONTEXT_SCHEMA ||
      value.version !== 1 || !HEX_64.test(value.attempt_hmac_sha256) ||
      !HEX_64.test(value.handoff_id) || typeof value.job_key !== 'string' || value.job_key.length < 8 ||
      value.job_key_sha256 !== sha256(value.job_key) ||
      ![value.recipient_email_sha256, value.source_invite_hmac_sha256,
        value.provider_idempotency_key_sha256, value.message_sha256]
        .every((item) => HEX_64.test(String(item || ''))) ||
      value.recipient_email_sha256 !== sha256(recipientEmail) ||
      !['claim_invitation', 'final_delivery'].includes(kind)) {
    throw new Error('ARC2_EMAIL_ATTEMPT_CONTEXT_INVALID');
  }
  return value;
}

export async function sealArc2EmailAttemptContext(vaultStore, job, reservation,
  idempotencyKey, message, env = process.env, adapters = {}) {
  const kind = validKind(job?.kind);
  const payload = contextPayload(job, reservation, idempotencyKey, message);
  await sealEmailRecipientCapsule(vaultStore, {
    job_kind: kind,
    job_key: contextJobKey(reservation.attempt_hmac_sha256),
    recipient_email: job.recipient_email,
    private_payload: payload,
    expires_at: job.capsule_expires_at,
  }, env, { clock: adapters.clock, randomBytes: adapters.randomBytes });
  const opened = await openEmailRecipientCapsule(vaultStore, {
    job_kind: kind,
    job_key: contextJobKey(reservation.attempt_hmac_sha256),
  }, env, { clock: adapters.clock });
  const validated = validateContextPayload(opened.private_payload, kind, opened.recipient_email);
  if (opened.recipient_email !== job.recipient_email ||
      canonicalJson(validated) !== canonicalJson(payload)) {
    throw new Error('ARC2_EMAIL_ATTEMPT_CONTEXT_INVALID');
  }
  return Object.freeze({
    kind,
    recipient_email: opened.recipient_email,
    expires_at: opened.expires_at,
    ...structuredClone(validated),
  });
}

export async function openArc2EmailAttemptContext(vaultStore, input,
  env = process.env, adapters = {}) {
  const kind = validKind(input?.job_kind);
  const opened = await openEmailRecipientCapsule(vaultStore, {
    job_kind: kind,
    job_key: contextJobKey(input.attempt_hmac_sha256),
  }, env, { clock: adapters.clock });
  const payload = validateContextPayload(opened.private_payload, kind, opened.recipient_email);
  if (payload.attempt_hmac_sha256 !== input.attempt_hmac_sha256) {
    throw new Error('ARC2_EMAIL_ATTEMPT_CONTEXT_INVALID');
  }
  return Object.freeze({
    kind,
    recipient_email: opened.recipient_email,
    expires_at: opened.expires_at,
    ...structuredClone(payload),
  });
}

async function persistAcceptance(vaultStore, context, accepted, env, adapters) {
  await sealEmailRecipientCapsule(vaultStore, {
    job_kind: context.kind,
    job_key: acceptanceJobKey(context.attempt_hmac_sha256),
    recipient_email: context.recipient_email,
    private_payload: {
      accepted_at: accepted.accepted_at,
      provider_message_id: accepted.provider_message_id,
    },
    expires_at: context.expires_at,
  }, env, { clock: adapters.clock, randomBytes: adapters.randomBytes });
}

async function recoverAcceptance(vaultStore, context, env, adapters) {
  const opened = await openEmailRecipientCapsule(vaultStore, {
    job_kind: context.kind,
    job_key: acceptanceJobKey(context.attempt_hmac_sha256),
  }, env, { clock: adapters.clock });
  const value = opened.private_payload;
  if (opened.recipient_email !== context.recipient_email ||
      !exactKeys(value, ['accepted_at', 'provider_message_id']) ||
      !UUID.test(String(value.provider_message_id || '')) ||
      !Number.isFinite(Date.parse(value.accepted_at)) ||
      new Date(value.accepted_at).toISOString() !== value.accepted_at) {
    throw new Error('ARC2_EMAIL_ACCEPTANCE_CAPSULE_INVALID');
  }
  return Object.freeze({
    provider: 'resend',
    provider_message_id: value.provider_message_id.toLowerCase(),
    accepted_at: value.accepted_at,
  });
}

async function discover(kind, stores, env, adapters, skipped) {
  const method = kind === 'claim_invitation'
    ? adapters.discoverNextClaimInvitationEmail || discoverNextClaimInvitationEmail
    : adapters.discoverNextFinalDeliveryEmail || discoverNextFinalDeliveryEmail;
  const callerEligibility = adapters.is_candidate_eligible;
  return method(stores.ledger, env, {
    ...adapters,
    skip_handoff_ids: skipped,
    is_candidate_eligible: async (candidate) => {
      if (callerEligibility && await callerEligibility(candidate) !== true) return false;
      const existing = await (adapters.readEmailSendAttempt || readEmailSendAttempt)(stores.attempt, {
        job_kind: candidate.kind,
        job_key: candidate.job_key,
      }, env);
      return !existing || existing.state === 'INTENT';
    },
  });
}

async function prepare(kind, stores, candidate, env, adapters) {
  const method = kind === 'claim_invitation'
    ? adapters.prepareClaimInvitationEmailJob || prepareClaimInvitationEmailJob
    : adapters.prepareFinalDeliveryEmailJob || prepareFinalDeliveryEmailJob;
  return method(stores.ledger, stores.vault, candidate.handoff_id, env, {
    ...adapters,
    store: stores.ledger,
    reviewStore: stores.review,
  });
}

function enabledForKind(configuration, kind) {
  return kind === 'claim_invitation'
    ? configuration.claim_invitation_enabled
    : configuration.final_delivery_enabled;
}

export async function runArc2TransactionalEmailWorkerCycle(kind, env, stores, adapters = {}) {
  validKind(kind);
  const configuration = arc2TransactionalEmailWorkerConfiguration(env);
  if (!enabledForKind(configuration, kind)) {
    return Object.freeze({ state: 'DISABLED', processed: 0, channel: kind });
  }
  if (!stores?.ledger || !stores?.review || !stores?.attempt || !stores?.vault) {
    throw new TypeError('ARC2 transactional email worker stores are invalid.');
  }
  const now = validClock(adapters);
  const skipped = new Set();
  for (let scan = 0; scan < 100; scan += 1) {
    const candidate = await discover(kind, stores, env, adapters, skipped);
    if (!candidate.found) {
      return Object.freeze({
        state: skipped.size > 0 ? 'WAITING_WEBHOOK' : 'IDLE',
        processed: 0,
        channel: kind,
      });
    }
    if (candidate.kind !== kind || !HEX_64.test(String(candidate.handoff_id || '')) ||
        !HEX_64.test(String(candidate.job_key || ''))) {
      throw new Error('ARC2_EMAIL_DISCOVERY_BINDING_INVALID');
    }
    const existingAttempt = await (adapters.readEmailSendAttempt || readEmailSendAttempt)(stores.attempt, {
      job_kind: kind,
      job_key: candidate.job_key,
    }, env);
    if (existingAttempt && existingAttempt.state !== 'INTENT') {
      skipped.add(candidate.handoff_id);
      continue;
    }
    const job = await prepare(kind, stores, candidate, env, adapters);
    if (!job || job.kind !== kind || job.handoff_id !== candidate.handoff_id ||
        job.job_key !== candidate.job_key || !HEX_64.test(job.recipient_email_sha256) ||
        sha256(job.recipient_email) !== job.recipient_email_sha256 ||
        !HEX_64.test(job.source_invite_hmac_sha256) ||
        !Number.isFinite(Date.parse(job.capsule_expires_at))) {
      throw new Error('ARC2_EMAIL_SEND_AUTHORITY_INVALID');
    }
    const message = outboundMessage(job);
    const idempotencyKey = providerIdempotencyKey(kind, job.job_key, env);
    const resend = resendProviderConfiguration(env);
    const reservation = await (adapters.reserveEmailSendAttempt || reserveEmailSendAttempt)(stores.attempt, {
      job_kind: kind,
      job_key: job.job_key,
      provider_idempotency_key: idempotencyKey,
      recipient_email_sha256: attemptRecipientIdentity(job.recipient_email, env),
      sender_sha256: sha256(resend.from),
      message_sha256: sha256(canonicalJson(message)),
    }, env, { clock: () => now });
    const context = await sealArc2EmailAttemptContext(stores.vault, job, reservation,
      idempotencyKey, message, env, { clock: () => now, randomBytes: adapters.randomBytes });
    if (reservation.decision === 'REVIEW_REQUIRED') {
      return Object.freeze({ state: 'REVIEW_REQUIRED', processed: 0, channel: kind });
    }
    if (reservation.decision === 'DO_NOT_SEND') {
      if (TERMINAL_ATTEMPT_STATES.has(reservation.state) || reservation.state === 'PROVIDER_ACCEPTED') {
        skipped.add(candidate.handoff_id);
        continue;
      }
      throw new Error('ARC2_EMAIL_ATTEMPT_STATE_INVALID');
    }
    let accepted;
    let recoveredAcceptance = false;
    try {
      accepted = await recoverAcceptance(stores.vault, context, env, { clock: () => now });
      recoveredAcceptance = true;
    } catch (error) {
      if (error?.message !== 'ARC_EMAIL_VAULT_NOT_FOUND') throw error;
      // The encrypted attempt context is strongly read back above. Therefore a
      // webhook can always bind the provider message to this exact handoff,
      // even if the invocation fails immediately after the network request.
      accepted = await (adapters.sendResendTransactionalEmail || sendResendTransactionalEmail)(
        message, idempotencyKey, env, { fetch: adapters.fetch, clock: () => now });
      await persistAcceptance(stores.vault, context, accepted, env, {
        clock: () => now,
        randomBytes: adapters.randomBytes,
      });
    }
    await (adapters.markEmailProviderAccepted || markEmailProviderAccepted)(stores.attempt, {
      attempt_hmac_sha256: reservation.attempt_hmac_sha256,
      provider_message_id: accepted.provider_message_id,
    }, env, { clock: () => now });
    return Object.freeze({
      state: 'PROVIDER_ACCEPTED',
      processed: 1,
      channel: kind,
      idempotent_replay: recoveredAcceptance,
    });
  }
  return Object.freeze({ state: 'SCAN_LIMIT', processed: 0, channel: kind });
}

function validateTerminalEvent(event) {
  if (!event || !HEX_64.test(String(event.attempt_hmac_sha256 || '')) ||
      !['claim_invitation', 'final_delivery'].includes(event.job_kind) || event.provider !== 'resend' ||
      typeof event.provider_event_id !== 'string' || event.provider_event_id.length < 1 ||
      typeof event.provider_message_id !== 'string' || !UUID.test(event.provider_message_id) ||
      typeof event.event_type !== 'string' ||
      !['email.delivered', ...NEGATIVE_EVENT_TYPES].includes(event.event_type) ||
      typeof event.idempotent_replay !== 'boolean') {
    throw new TypeError('ARC2 terminal email event is invalid.');
  }
  const occurred = Date.parse(event.occurred_at);
  if (!Number.isFinite(occurred) || new Date(occurred).toISOString() !== event.occurred_at) {
    throw new TypeError('ARC2 terminal email event is invalid.');
  }
  return event;
}

function finalReceiptPayload(receipt, context, event) {
  return {
    schema: ARC2_EMAIL_FINAL_RECEIPT_CAPSULE_SCHEMA,
    version: 1,
    handoff_id: context.handoff_id,
    job_key: context.job_key,
    provider_event_id: event.provider_event_id,
    provider_message_id: event.provider_message_id,
    delivered_at: event.occurred_at,
    delivery_receipt_evidence: receipt.delivery_receipt_evidence,
    delivery_receipt_evidence_hmac_sha256: receipt.delivery_receipt_evidence_hmac_sha256,
  };
}

function validateFinalReceiptPayload(value, context, event) {
  if (!exactKeys(value, RECEIPT_FIELDS) || value.schema !== ARC2_EMAIL_FINAL_RECEIPT_CAPSULE_SCHEMA ||
      value.version !== 1 || value.handoff_id !== context.handoff_id || value.job_key !== context.job_key ||
      value.provider_event_id !== event.provider_event_id ||
      value.provider_message_id !== event.provider_message_id || value.delivered_at !== event.occurred_at ||
      typeof value.delivery_receipt_evidence !== 'string' ||
      !HEX_64.test(String(value.delivery_receipt_evidence_hmac_sha256 || ''))) {
    throw new Error('ARC2_FINAL_DELIVERY_RECEIPT_CAPSULE_INVALID');
  }
  return value;
}

async function recoverFinalReceipt(vaultStore, context, event, env, adapters) {
  const opened = await openEmailRecipientCapsule(vaultStore, {
    job_kind: 'final_delivery',
    job_key: receiptJobKey(context.attempt_hmac_sha256, event.provider_event_id),
  }, env, { clock: adapters.clock });
  if (opened.recipient_email !== context.recipient_email) {
    throw new Error('ARC2_FINAL_DELIVERY_RECEIPT_CAPSULE_INVALID');
  }
  return validateFinalReceiptPayload(opened.private_payload, context, event);
}

async function createAndPersistFinalReceipt(stores, context, event, env, adapters) {
  const job = await (adapters.prepareFinalDeliveryEmailJob || prepareFinalDeliveryEmailJob)(
    stores.ledger, stores.vault, context.handoff_id, env, {
      ...adapters,
      store: stores.ledger,
      reviewStore: stores.review,
    });
  if (!job || job.kind !== 'final_delivery' || job.handoff_id !== context.handoff_id ||
      job.job_key !== context.job_key || job.recipient_email !== context.recipient_email ||
      job.recipient_email_sha256 !== context.recipient_email_sha256) {
    throw new Error('ARC2_FINAL_DELIVERY_EMAIL_BINDING_INVALID');
  }
  const receipt = createFinalDeliveryReceiptEvidence({
    attempt_hmac_sha256: event.attempt_hmac_sha256,
    job_kind: 'final_delivery',
    provider: 'resend',
    provider_event_id: event.provider_event_id,
    provider_message_id: event.provider_message_id,
    delivered_at: event.occurred_at,
    idempotent_replay: event.idempotent_replay,
  }, job.final_authority, env, { clock: adapters.clock });
  const payload = finalReceiptPayload(receipt, context, event);
  await sealEmailRecipientCapsule(stores.vault, {
    job_kind: 'final_delivery',
    job_key: receiptJobKey(context.attempt_hmac_sha256, event.provider_event_id),
    recipient_email: context.recipient_email,
    private_payload: payload,
    expires_at: context.expires_at,
  }, env, { clock: adapters.clock, randomBytes: adapters.randomBytes });
  return recoverFinalReceipt(stores.vault, context, event, env, adapters);
}

export async function reconcileArc2TransactionalEmailEvent(stores, input,
  env = process.env, adapters = {}) {
  const event = validateTerminalEvent(input);
  if (!stores?.ledger || !stores?.review || !stores?.vault) {
    throw new TypeError('ARC2 transactional email event stores are invalid.');
  }
  let context;
  try {
    context = await openArc2EmailAttemptContext(stores.vault, {
      job_kind: event.job_kind,
      attempt_hmac_sha256: event.attempt_hmac_sha256,
    }, env, { clock: adapters.clock });
  } catch (error) {
    if (!NEGATIVE_EVENT_TYPES.has(event.event_type) ||
        error?.message !== 'ARC_EMAIL_VAULT_NOT_FOUND') throw error;
    // Negative reconciliation deletes every recipient-bearing capsule. Its
    // signed, PII-free attempt binding is the only replay recovery path.
    context = await recoverArc2NegativeAttemptBinding(stores.ledger, {
      job_kind: event.job_kind,
      attempt_hmac_sha256: event.attempt_hmac_sha256,
    }, env);
  }
  if (NEGATIVE_EVENT_TYPES.has(event.event_type)) {
    const persisted = await persistArc2NegativeEmailState(stores, context, event, env, {
      clock: adapters.clock,
    });
    return Object.freeze({
      state: persisted.state,
      unlock_delivery: false,
      job_kind: event.job_kind,
      idempotent_replay: persisted.idempotent_replay,
    });
  }
  // The signed manual-review latch is authoritative even if a prior negative
  // reconciliation crashed before deleting its encrypted attempt context.
  // A claim-stage negative also blocks every later final-delivery event for
  // the same handoff.
  await assertArc2EmailNegativeStateAllows(stores.ledger, context.handoff_id,
    event.job_kind, env);
  if (event.job_kind === 'final_delivery') {
    await assertArc2EmailNegativeStateAllows(stores.ledger, context.handoff_id,
      'claim_invitation', env);
  }
  if (event.job_kind === 'claim_invitation') {
    // Provider delivery proves only that the claim invitation reached the
    // mailbox. Ownership and final delivery remain separate state machines.
    return Object.freeze({ state: 'CLAIM_INVITATION_DELIVERED', unlock_delivery: false,
      job_kind: event.job_kind });
  }
  let receipt;
  try {
    receipt = await recoverFinalReceipt(stores.vault, context, event, env, adapters);
  } catch (error) {
    if (error?.message !== 'ARC_EMAIL_VAULT_NOT_FOUND') throw error;
    receipt = await createAndPersistFinalReceipt(stores, context, event, env, adapters);
  }
  const acknowledge = adapters.acknowledgeFinalDelivery || acknowledgeFinalDelivery;
  const result = await acknowledge(context.handoff_id,
    receipt.delivery_receipt_evidence,
    receipt.delivery_receipt_evidence_hmac_sha256,
    env, {
      ...adapters,
      store: stores.ledger,
      reviewStore: stores.review,
    });
  if (!result) throw new Error('ARC2_FINAL_DELIVERY_HANDOFF_NOT_FOUND');
  return Object.freeze({
    state: 'FINAL_DELIVERY_ACKNOWLEDGED',
    unlock_delivery: true,
    job_kind: event.job_kind,
    idempotent_replay: Boolean(result.idempotentReplay),
  });
}

export const arc2TransactionalEmailNegativeEventTypes = Object.freeze([...NEGATIVE_EVENT_TYPES]);
