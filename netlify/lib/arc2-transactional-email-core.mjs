import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import {
  deleteEmailRecipientCapsule,
  emailRecipientVaultConfiguration,
  openEmailRecipientCapsule,
  sealEmailRecipientCapsule,
} from './email-recipient-vault-core.mjs';
import {
  FINAL_DELIVERY_RECEIPT_SCOPE,
  FINAL_DELIVERY_RECEIPT_SIGNATURE_PREFIX,
  FINAL_DELIVERY_RECEIPT_VERSION,
  canonicalJson,
  validateExpectedBindings,
} from './arc2-handoff-core.mjs';
import {
  getClaimInvitationEmailAuthority,
  getFinalDeliveryEmailAuthority,
} from './arc2-handoff-service.mjs';
import {
  arc2NegativeEmailStateConfiguration,
  assertArc2EmailNegativeStateAllows,
} from './arc2-negative-email-state-core.mjs';
import { readReviewInviteForEmail } from './review-flow-core.mjs';

export const ARC2_CLAIM_INVITATION_EMAIL_ENABLED_ENV =
  'ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED';
export const ARC2_FINAL_DELIVERY_EMAIL_ENABLED_ENV =
  'ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED';
export const RESEND_PROVIDER_ACCOUNT_ID_ENV = 'ARC_RESEND_PROVIDER_ACCOUNT_ID';
export const RESEND_PROVIDER_BINDING_HMAC_SECRET_ENV =
  'ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET';
export const ARC2_EMAIL_CAPSULE_TTL_MS = 30 * 24 * 60 * 60_000;

const HEX_64 = /^[a-f0-9]{64}$/;
const HANDOFF_ID = HEX_64;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const INVITATION_CURRENT_SCHEMA = 'arc2-claim-invitation-current-v1';
const INVITATION_OUTBOX_VERSION = 'arc2-claim-invitation-ready-outbox-v2';
const INVITATION_CURRENT_PREFIX = 'invitation-ready-current/';
const FINAL_OUTBOX_PREFIX = 'outbox/';
const FINAL_OUTBOX_SCHEMA = 'arc2-final-delivery-outbox-v1';
const REVIEW_CAPSULE_FIELDS = Object.freeze([
  'invite_hmac_sha256', 'invite_token', 'outbox_hmac_sha256', 'preview_manifest_sha256',
  'recipient_email_sha256', 'review_url', 'template_version',
]);
const CLAIM_CURRENT_FIELDS = Object.freeze([
  'binding_hmac_sha256', 'claim_invitation_generation', 'claim_token_hmac_sha256',
  'expires_at', 'handoff_id', 'outbox_key_sha256', 'schema',
]);
const FINAL_OUTBOX_FIELDS = Object.freeze([
  'handoff_id', 'netlify_deploy_id_sha256', 'netlify_site_id_sha256',
  'outbox_claim_key_hmac_sha256', 'schema', 'status',
]);

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const safeEqual = (left, right) => {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
};
const exactKeys = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());

function exactBooleanOrUnset(value) {
  return value === undefined || value === 'true' || value === 'false';
}

function secret(value, label) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 32 ||
      Buffer.byteLength(value, 'utf8') > 256 || CONTROL.test(value)) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function iso(value, label) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new TypeError(`${label} is invalid.`);
  }
  return parsed;
}

function normalizedEmail(value) {
  if (typeof value !== 'string' || value !== value.trim().toLowerCase() || value.length > 254 ||
      CONTROL.test(value) || !EMAIL.test(value)) throw new TypeError('ARC2 email recipient is invalid.');
  return value;
}

export function arc2TransactionalEmailConfiguration(env = process.env) {
  const claimFlagValid = exactBooleanOrUnset(env[ARC2_CLAIM_INVITATION_EMAIL_ENABLED_ENV]);
  const finalFlagValid = exactBooleanOrUnset(env[ARC2_FINAL_DELIVERY_EMAIL_ENABLED_ENV]);
  const claimRequested = env[ARC2_CLAIM_INVITATION_EMAIL_ENABLED_ENV] === 'true';
  const finalRequested = env[ARC2_FINAL_DELIVERY_EMAIL_ENABLED_ENV] === 'true';
  const requested = claimRequested || finalRequested;
  const vault = emailRecipientVaultConfiguration(env);
  const negativeState = arc2NegativeEmailStateConfiguration(env);
  const commonEnabled = env.ARC_TRANSACTIONAL_EMAIL_ENABLED === 'true' && vault.enabled &&
    (!requested || negativeState.enabled);
  return Object.freeze({
    flags_valid: claimFlagValid && finalFlagValid,
    requested,
    capsule_producer_enabled: requested && claimFlagValid && finalFlagValid && commonEnabled,
    claim_invitation_enabled: claimRequested && claimFlagValid && commonEnabled,
    final_delivery_enabled: finalRequested && finalFlagValid && commonEnabled,
  });
}

function requireCapsuleProducer(env) {
  const configured = arc2TransactionalEmailConfiguration(env);
  if (!configured.capsule_producer_enabled) {
    throw new Error('ARC2_TRANSACTIONAL_EMAIL_CAPSULE_PRODUCER_DISABLED');
  }
  return configured;
}

function requireKind(env, kind) {
  const configured = arc2TransactionalEmailConfiguration(env);
  const enabled = kind === 'claim_invitation'
    ? configured.claim_invitation_enabled
    : configured.final_delivery_enabled;
  if (!enabled) throw new Error(`ARC2_${kind.toUpperCase()}_EMAIL_DISABLED`);
  return configured;
}

export function resendProviderAccountHmacSha256(env = process.env) {
  const accountId = env[RESEND_PROVIDER_ACCOUNT_ID_ENV];
  if (typeof accountId !== 'string' || accountId.length < 1 ||
      Buffer.byteLength(accountId, 'utf8') > 256 || accountId !== accountId.trim() || CONTROL.test(accountId)) {
    throw new TypeError(`${RESEND_PROVIDER_ACCOUNT_ID_ENV} is invalid.`);
  }
  const bindingSecret = secret(env[RESEND_PROVIDER_BINDING_HMAC_SECRET_ENV],
    RESEND_PROVIDER_BINDING_HMAC_SECRET_ENV);
  const related = [
    env.ARC_FINAL_DELIVERY_RECEIPT_SECRET,
    env.ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET,
    env.ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET,
  ].filter((value) => typeof value === 'string' && value.length > 0);
  if (related.some((value) => safeEqual(value, bindingSecret))) {
    throw new TypeError('Resend provider binding secret must be distinct.');
  }
  return hmac(bindingSecret, `arc-resend-provider-account-binding-v1\n${accountId}`);
}

// Opens the already-delivered preview-review capsule and binds its plaintext
// recipient to the exact paid review. This is the only point where ARC2 reads
// the raw customer address; the returned value is intended for immediate
// in-memory use by the paid worker.
export async function openPaidPreviewRecipientCapsule(vaultStore, reviewStore, input,
  env = process.env, adapters = {}) {
  requireCapsuleProducer(env);
  if (!exactKeys(input, ['invite_hmac_sha256', 'recipient_email_sha256']) ||
      !HEX_64.test(input.invite_hmac_sha256) || !HEX_64.test(input.recipient_email_sha256)) {
    throw new TypeError('Paid preview recipient binding is invalid.');
  }
  const readReview = adapters.readReviewInviteForEmail || readReviewInviteForEmail;
  const review = await readReview(reviewStore, input.invite_hmac_sha256, env);
  const outboxHmac = review.record.email_delivery_outbox_hmac_sha256;
  if (review.record.invite_hmac_sha256 !== input.invite_hmac_sha256 ||
      review.record.recipient_email_sha256 !== input.recipient_email_sha256 ||
      review.record.state !== 'APPROVED' || review.record.decision?.action !== 'APPROVE_AND_PAY' ||
      review.record.successor_invite_hmac_sha256 !== null ||
      review.record.email_delivery_binding_mode !== 'signed-outbox' ||
      review.record.email_suppression_receipt_sha256 !== null ||
      !HEX_64.test(String(outboxHmac || '')) || review.record.email_delivery_receipt_sha256 === null) {
    throw new Error('ARC2_PREVIEW_RECIPIENT_AUTHORITY_INVALID');
  }
  const capsule = await openEmailRecipientCapsule(vaultStore, {
    job_kind: 'preview_review',
    job_key: outboxHmac,
  }, env, { clock: adapters.clock });
  const payload = capsule.private_payload;
  if (!exactKeys(payload, REVIEW_CAPSULE_FIELDS) ||
      payload.invite_hmac_sha256 !== input.invite_hmac_sha256 ||
      payload.outbox_hmac_sha256 !== outboxHmac ||
      payload.recipient_email_sha256 !== input.recipient_email_sha256 ||
      payload.preview_manifest_sha256 !== review.record.preview_manifest_sha256 ||
      typeof payload.invite_token !== 'string' || typeof payload.review_url !== 'string' ||
      typeof payload.template_version !== 'string') {
    throw new Error('ARC2_PREVIEW_RECIPIENT_CAPSULE_INVALID');
  }
  const recipient = normalizedEmail(capsule.recipient_email);
  if (!safeEqual(sha256(recipient), input.recipient_email_sha256)) {
    throw new Error('ARC2_PREVIEW_RECIPIENT_CAPSULE_INVALID');
  }
  return Object.freeze({
    recipient_email: recipient,
    recipient_email_sha256: input.recipient_email_sha256,
    source_invite_hmac_sha256: input.invite_hmac_sha256,
    source_outbox_hmac_sha256: outboxHmac,
  });
}

// Deletes only the encrypted preview recipient capsule after the paid bridge
// is durably COMPLETED. The signed review record is used to recover the opaque
// vault key on a crash/replay, so no raw recipient or invite token is ever
// copied into the payment outbox.
export async function deletePaidPreviewRecipientCapsule(vaultStore, reviewStore, input,
  env = process.env) {
  if (!exactKeys(input, ['invite_hmac_sha256', 'recipient_email_sha256']) ||
      !HEX_64.test(input.invite_hmac_sha256) || !HEX_64.test(input.recipient_email_sha256)) {
    throw new TypeError('Paid preview recipient cleanup binding is invalid.');
  }
  const review = await readReviewInviteForEmail(reviewStore, input.invite_hmac_sha256, env);
  const outboxHmac = review.record.email_delivery_outbox_hmac_sha256;
  if (review.record.invite_hmac_sha256 !== input.invite_hmac_sha256 ||
      review.record.recipient_email_sha256 !== input.recipient_email_sha256 ||
      review.record.email_delivery_binding_mode !== 'signed-outbox' ||
      !HEX_64.test(String(outboxHmac || '')) || review.record.email_delivery_receipt_sha256 === null) {
    throw new Error('ARC2_PREVIEW_RECIPIENT_CLEANUP_AUTHORITY_INVALID');
  }
  const result = await deleteEmailRecipientCapsule(vaultStore, {
    job_kind: 'preview_review',
    job_key: outboxHmac,
  }, env);
  return Object.freeze({
    source_outbox_hmac_sha256: outboxHmac,
    source_capsule_deleted: result.deleted,
    idempotent_replay: result.idempotent_replay,
  });
}

function downstreamCapsuleInput(kind, handoff, source, expiresAt) {
  return {
    job_kind: kind,
    job_key: handoff.handoff_id,
    recipient_email: source.recipient_email,
    private_payload: {
      source_invite_hmac_sha256: source.source_invite_hmac_sha256,
    },
    expires_at: expiresAt,
  };
}

function verifyDownstreamCapsule(opened, source, expiresAt) {
  if (opened.recipient_email !== source.recipient_email || opened.expires_at !== expiresAt ||
      !exactKeys(opened.private_payload, ['source_invite_hmac_sha256']) ||
      opened.private_payload.source_invite_hmac_sha256 !== source.source_invite_hmac_sha256 ||
      !safeEqual(sha256(opened.recipient_email), source.recipient_email_sha256)) {
    throw new Error('ARC2_HANDOFF_EMAIL_CAPSULE_READBACK_INVALID');
  }
}

// Seals both downstream recipient capsules after startReviewHandoff has
// returned a durable handoff, but before the paid bridge may be completed.
// Expiry is derived from the immutable handoff creation time so retries use
// byte-identical vault input.
export async function sealArc2HandoffEmailCapsules(vaultStore, handoff, source,
  env = process.env, adapters = {}) {
  requireCapsuleProducer(env);
  if (!exactKeys(handoff, ['created_at', 'handoff_id']) || !HANDOFF_ID.test(handoff.handoff_id)) {
    throw new TypeError('ARC2 handoff capsule binding is invalid.');
  }
  const createdAt = iso(handoff.created_at, 'ARC2 handoff creation timestamp');
  if (!exactKeys(source, [
    'recipient_email', 'recipient_email_sha256', 'source_invite_hmac_sha256',
    'source_outbox_hmac_sha256',
  ]) || !HEX_64.test(source.recipient_email_sha256) ||
      !HEX_64.test(source.source_invite_hmac_sha256) || !HEX_64.test(source.source_outbox_hmac_sha256) ||
      sha256(normalizedEmail(source.recipient_email)) !== source.recipient_email_sha256) {
    throw new TypeError('ARC2 source recipient binding is invalid.');
  }
  const expiresAt = new Date(createdAt + ARC2_EMAIL_CAPSULE_TTL_MS).toISOString();
  const clock = adapters.clock || (() => new Date());
  const now = new Date(clock());
  if (!Number.isFinite(now.getTime()) || Date.parse(expiresAt) <= now.getTime()) {
    throw new Error('ARC2_HANDOFF_EMAIL_CAPSULE_EXPIRED');
  }
  const outputs = {};
  for (const kind of ['claim_invitation', 'final_delivery']) {
    const sealed = await sealEmailRecipientCapsule(vaultStore,
      downstreamCapsuleInput(kind, handoff, source, expiresAt), env,
      { clock: () => new Date(now), randomBytes: adapters.randomBytes });
    const opened = await openEmailRecipientCapsule(vaultStore, {
      job_kind: kind,
      job_key: handoff.handoff_id,
    }, env, { clock: () => new Date(now) });
    verifyDownstreamCapsule(opened, source, expiresAt);
    outputs[kind] = sealed.vault_hmac_sha256;
  }
  return Object.freeze({
    handoff_id: handoff.handoff_id,
    recipient_email_sha256: source.recipient_email_sha256,
    source_invite_hmac_sha256: source.source_invite_hmac_sha256,
    claim_invitation_vault_hmac_sha256: outputs.claim_invitation,
    final_delivery_vault_hmac_sha256: outputs.final_delivery,
    expires_at: expiresAt,
  });
}

function validatePaidCompletion(result) {
  if (!result || result.state !== 'COMPLETED' || typeof result.idempotent_replay !== 'boolean' ||
      !HEX_64.test(String(result.immutable_binding_sha256 || '')) ||
      !HEX_64.test(String(result.arc2_start_receipt_sha256 || '')) ||
      typeof result.outbox_key !== 'string' ||
      !/^payment-arc2-start-outbox\/[a-f0-9]{64}$/.test(result.outbox_key) ||
      !Number.isSafeInteger(result.claim_attempt_count) || result.claim_attempt_count < 1 ||
      result.lease_expires_at !== null) {
    throw new Error('ARC2_PAID_RECIPIENT_COMPLETION_INVALID');
  }
  return result;
}

// One ordered boundary for the paid recipient transition: downstream
// capsules are sealed and strong-read back, the payment ARC2 outbox is then
// durably completed, and only then may the source preview capsule be erased.
export async function completePaidRecipientCapsuleHandoff(vaultStore, reviewStore, input,
  env = process.env, adapters = {}) {
  requireCapsuleProducer(env);
  if (!exactKeys(input, ['handoff', 'source']) ||
      typeof adapters.completePaymentArc2StartOutbox !== 'function') {
    throw new TypeError('Paid recipient capsule handoff is invalid.');
  }
  const sealed = await sealArc2HandoffEmailCapsules(
    vaultStore, input.handoff, input.source, env, adapters,
  );
  const completion = validatePaidCompletion(await adapters.completePaymentArc2StartOutbox());
  const cleanup = await deletePaidPreviewRecipientCapsule(vaultStore, reviewStore, {
    invite_hmac_sha256: input.source.source_invite_hmac_sha256,
    recipient_email_sha256: input.source.recipient_email_sha256,
  }, env);
  return Object.freeze({
    completion: Object.freeze(structuredClone(completion)),
    downstream: sealed,
    cleanup,
  });
}

async function listFirst(store, prefix, validate) {
  if (!store || typeof store.list !== 'function') throw new Error('ARC2_EMAIL_DISCOVERY_UNAVAILABLE');
  const pages = store.list({ prefix, paginate: true });
  if (!pages || typeof pages[Symbol.asyncIterator] !== 'function') {
    throw new Error('ARC2_EMAIL_DISCOVERY_UNAVAILABLE');
  }
  for await (const page of pages) {
    if (!page || !Array.isArray(page.blobs)) throw new Error('ARC2_EMAIL_DISCOVERY_UNAVAILABLE');
    for (const blob of [...page.blobs].sort((left, right) => String(left?.key).localeCompare(String(right?.key)))) {
      const candidate = await validate(blob?.key);
      if (candidate) return Object.freeze({ found: true, ...candidate });
    }
  }
  return Object.freeze({ found: false });
}

function skippedHandoff(adapters, handoffId) {
  if (adapters.skip_handoff_ids === undefined) return false;
  if (!(adapters.skip_handoff_ids instanceof Set) ||
      [...adapters.skip_handoff_ids].some((value) => !HANDOFF_ID.test(String(value || '')))) {
    throw new TypeError('ARC2 email discovery skip set is invalid.');
  }
  return adapters.skip_handoff_ids.has(handoffId);
}

async function eligibleCandidate(adapters, candidate) {
  if (adapters.is_candidate_eligible === undefined) return true;
  if (typeof adapters.is_candidate_eligible !== 'function') {
    throw new TypeError('ARC2 email discovery eligibility adapter is invalid.');
  }
  return (await adapters.is_candidate_eligible(Object.freeze(structuredClone(candidate)))) === true;
}

async function readDiscoveryHandoff(ledgerStore, handoffId, adapters) {
  if (typeof adapters.readHandoff === 'function') return adapters.readHandoff(handoffId);
  const entry = await ledgerStore.getWithMetadata(`handoffs/${handoffId}`,
    { type: 'json', consistency: 'strong' });
  if (!entry) return null;
  return validateExpectedBindings(entry.data);
}

export async function discoverNextClaimInvitationEmail(ledgerStore, env = process.env, adapters = {}) {
  requireKind(env, 'claim_invitation');
  return listFirst(ledgerStore, INVITATION_CURRENT_PREFIX, async (key) => {
    if (typeof key !== 'string' || !new RegExp(`^${INVITATION_CURRENT_PREFIX}[a-f0-9]{64}$`).test(key)) {
      throw new Error('ARC2_CLAIM_INVITATION_DISCOVERY_CORRUPT');
    }
    const entry = await ledgerStore.getWithMetadata(key, { type: 'json', consistency: 'strong' });
    const value = entry?.data;
    const handoffId = key.slice(INVITATION_CURRENT_PREFIX.length);
    if (skippedHandoff(adapters, handoffId)) return null;
    if (!entry || !exactKeys(value, CLAIM_CURRENT_FIELDS) || value.schema !== INVITATION_CURRENT_SCHEMA ||
        value.handoff_id !== handoffId || !Number.isSafeInteger(value.claim_invitation_generation) ||
        value.claim_invitation_generation < 0 ||
        ![value.claim_token_hmac_sha256, value.outbox_key_sha256, value.binding_hmac_sha256]
          .every((item) => HEX_64.test(String(item || ''))) ||
        !Number.isFinite(Date.parse(value.expires_at))) {
      throw new Error('ARC2_CLAIM_INVITATION_DISCOVERY_CORRUPT');
    }
    const { binding_hmac_sha256: ignored, ...binding } = value;
    const expected = hmac(secret(env.ARC_EMAIL_CLAIM_BINDING_SECRET,
      'ARC_EMAIL_CLAIM_BINDING_SECRET'), `${INVITATION_CURRENT_SCHEMA}\n${canonicalJson(binding)}`);
    if (!safeEqual(value.binding_hmac_sha256, expected)) {
      throw new Error('ARC2_CLAIM_INVITATION_DISCOVERY_CORRUPT');
    }
    const handoff = await readDiscoveryHandoff(ledgerStore, handoffId, adapters);
    if (!handoff) throw new Error('ARC2_CLAIM_INVITATION_DISCOVERY_CORRUPT');
    await assertArc2EmailNegativeStateAllows(ledgerStore, handoffId, 'claim_invitation', env);
    if (handoff.state !== 'INVITATION_READY') return null;
    if (handoff.handoff_id !== handoffId ||
        handoff.customer_email_sha256.length !== 64) {
      throw new Error('ARC2_CLAIM_INVITATION_DISCOVERY_CORRUPT');
    }
    const jobKey = hmac(secret(env.ARC_EMAIL_CLAIM_BINDING_SECRET,
      'ARC_EMAIL_CLAIM_BINDING_SECRET'), canonicalJson({
      version: INVITATION_OUTBOX_VERSION,
      handoff_id: handoffId,
      recipient_email_sha256: handoff.customer_email_sha256,
      claim_invitation_generation: value.claim_invitation_generation,
      claim_token_hmac_sha256: value.claim_token_hmac_sha256,
      expires_at: value.expires_at,
    }));
    const candidate = {
      kind: 'claim_invitation',
      handoff_id: handoffId,
      job_key: jobKey,
      claim_invitation_generation: value.claim_invitation_generation,
      expires_at: value.expires_at,
    };
    return await eligibleCandidate(adapters, candidate) ? candidate : null;
  });
}

export async function discoverNextFinalDeliveryEmail(ledgerStore, env = process.env, adapters = {}) {
  requireKind(env, 'final_delivery');
  return listFirst(ledgerStore, FINAL_OUTBOX_PREFIX, async (key) => {
    if (typeof key !== 'string' || !new RegExp(`^${FINAL_OUTBOX_PREFIX}[a-f0-9]{64}$`).test(key)) {
      throw new Error('ARC2_FINAL_DELIVERY_DISCOVERY_CORRUPT');
    }
    const entry = await ledgerStore.getWithMetadata(key, { type: 'json', consistency: 'strong' });
    const value = entry?.data;
    if (!entry || !value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('ARC2_FINAL_DELIVERY_DISCOVERY_CORRUPT');
    }
    // Receipt reconciliation expands terminal/pending rows. They are valid
    // durable records but no longer actionable send work.
    if (value.status !== 'CLAIMED') return null;
    const jobKey = key.slice(FINAL_OUTBOX_PREFIX.length);
    if (!exactKeys(value, FINAL_OUTBOX_FIELDS) || value.schema !== FINAL_OUTBOX_SCHEMA ||
        value.outbox_claim_key_hmac_sha256 !== jobKey || !HANDOFF_ID.test(value.handoff_id) ||
        ![value.netlify_site_id_sha256, value.netlify_deploy_id_sha256].every((item) => HEX_64.test(item))) {
      throw new Error('ARC2_FINAL_DELIVERY_DISCOVERY_CORRUPT');
    }
    if (skippedHandoff(adapters, value.handoff_id)) return null;
    const handoff = await readDiscoveryHandoff(ledgerStore, value.handoff_id, adapters);
    if (!handoff) throw new Error('ARC2_FINAL_DELIVERY_DISCOVERY_CORRUPT');
    await assertArc2EmailNegativeStateAllows(ledgerStore, value.handoff_id, 'final_delivery', env);
    if (handoff.state !== 'FINAL_DEPLOY_READY') return null;
    if (handoff.outbox_claim_key_hmac_sha256 !== jobKey ||
        handoff.customer_email_sha256.length !== 64) {
      throw new Error('ARC2_FINAL_DELIVERY_DISCOVERY_CORRUPT');
    }
    const candidate = { kind: 'final_delivery', handoff_id: value.handoff_id, job_key: jobKey };
    return await eligibleCandidate(adapters, candidate) ? candidate : null;
  });
}

async function openHandoffCapsule(vaultStore, kind, handoffId, env, adapters) {
  const capsule = await openEmailRecipientCapsule(vaultStore, {
    job_kind: kind,
    job_key: handoffId,
  }, env, { clock: adapters.clock });
  const recipient = normalizedEmail(capsule.recipient_email);
  if (!exactKeys(capsule.private_payload, ['source_invite_hmac_sha256']) ||
      !HEX_64.test(capsule.private_payload.source_invite_hmac_sha256)) {
    throw new Error('ARC2_HANDOFF_EMAIL_CAPSULE_INVALID');
  }
  return { capsule, recipient };
}

export async function prepareClaimInvitationEmailJob(ledgerStore, vaultStore, handoffId,
  env = process.env, adapters = {}) {
  requireKind(env, 'claim_invitation');
  if (!HANDOFF_ID.test(handoffId)) throw new TypeError('ARC2 claim invitation handoff id is invalid.');
  await assertArc2EmailNegativeStateAllows(ledgerStore, handoffId, 'claim_invitation', env);
  const opened = await openHandoffCapsule(vaultStore, 'claim_invitation', handoffId, env, adapters);
  const authorityProvider = adapters.getClaimInvitationEmailAuthority ||
    getClaimInvitationEmailAuthority;
  const authority = await authorityProvider(handoffId, env, {
    ...adapters,
    store: ledgerStore,
  });
  if (!authority || authority.handoff_id !== handoffId ||
      !safeEqual(sha256(opened.recipient), authority.recipient_email_sha256)) {
    throw new Error('ARC2_CLAIM_INVITATION_EMAIL_BINDING_INVALID');
  }
  return Object.freeze({
    kind: 'claim_invitation',
    job_key: authority.job_key,
    handoff_id: handoffId,
    recipient_email: opened.recipient,
    recipient_email_sha256: authority.recipient_email_sha256,
    source_invite_hmac_sha256: opened.capsule.private_payload.source_invite_hmac_sha256,
    claim_url: authority.claim_url,
    expires_at: authority.expires_at,
    capsule_expires_at: opened.capsule.expires_at,
  });
}

export async function prepareFinalDeliveryEmailJob(ledgerStore, vaultStore, handoffId,
  env = process.env, adapters = {}) {
  requireKind(env, 'final_delivery');
  if (!HANDOFF_ID.test(handoffId)) throw new TypeError('ARC2 final delivery handoff id is invalid.');
  await assertArc2EmailNegativeStateAllows(ledgerStore, handoffId, 'final_delivery', env);
  const opened = await openHandoffCapsule(vaultStore, 'final_delivery', handoffId, env, adapters);
  const authorityProvider = adapters.getFinalDeliveryEmailAuthority ||
    getFinalDeliveryEmailAuthority;
  const authority = await authorityProvider(handoffId, env, {
    ...adapters,
    store: ledgerStore,
  });
  if (!authority || authority.handoff_id !== handoffId ||
      !safeEqual(sha256(opened.recipient), authority.recipient_email_sha256)) {
    throw new Error('ARC2_FINAL_DELIVERY_EMAIL_BINDING_INVALID');
  }
  return Object.freeze({
    kind: 'final_delivery',
    job_key: authority.job_key,
    handoff_id: handoffId,
    recipient_email: opened.recipient,
    recipient_email_sha256: authority.recipient_email_sha256,
    source_invite_hmac_sha256: opened.capsule.private_payload.source_invite_hmac_sha256,
    production_url: authority.production_url,
    final_authority: authority,
    capsule_expires_at: opened.capsule.expires_at,
  });
}

export function createFinalDeliveryReceiptEvidence(deliveredEvent, authority,
  env = process.env, adapters = {}) {
  const eventFields = [
    'attempt_hmac_sha256', 'delivered_at', 'idempotent_replay', 'job_kind', 'provider',
    'provider_event_id', 'provider_message_id',
  ];
  const authorityFields = [
    'authorized_at', 'claim_state_evidence_sha256', 'final_deploy_ready_at', 'handoff_id',
    'job_key', 'netlify_deploy_id_sha256', 'netlify_site_id_sha256', 'production_url',
    'production_url_sha256', 'recipient_email_sha256',
  ];
  if (!exactKeys(deliveredEvent, eventFields) || deliveredEvent.job_kind !== 'final_delivery' ||
      deliveredEvent.provider !== 'resend' || !HEX_64.test(deliveredEvent.attempt_hmac_sha256) ||
      typeof deliveredEvent.idempotent_replay !== 'boolean' ||
      typeof deliveredEvent.provider_event_id !== 'string' || deliveredEvent.provider_event_id.length < 1 ||
      deliveredEvent.provider_event_id.length > 512 || CONTROL.test(deliveredEvent.provider_event_id) ||
      typeof deliveredEvent.provider_message_id !== 'string' || deliveredEvent.provider_message_id.length < 1 ||
      deliveredEvent.provider_message_id.length > 512 || CONTROL.test(deliveredEvent.provider_message_id)) {
    throw new TypeError('Final delivery provider event is invalid.');
  }
  if (!exactKeys(authority, authorityFields) || !HANDOFF_ID.test(authority.handoff_id) ||
      authority.job_key !== authority.job_key.toLowerCase() || !HEX_64.test(authority.job_key) ||
      ![authority.recipient_email_sha256, authority.production_url_sha256,
        authority.netlify_site_id_sha256, authority.netlify_deploy_id_sha256,
        authority.claim_state_evidence_sha256].every((item) => HEX_64.test(item)) ||
      sha256(authority.production_url) !== authority.production_url_sha256) {
    throw new TypeError('Final delivery send authority is invalid.');
  }
  const deliveredAt = iso(deliveredEvent.delivered_at, 'Final delivery event timestamp');
  const finalReadyAt = iso(authority.final_deploy_ready_at, 'Final delivery ready timestamp');
  const authorizedAt = iso(authority.authorized_at, 'Final delivery authorization timestamp');
  const issuedAt = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(issuedAt.getTime()) || deliveredAt < finalReadyAt ||
      deliveredAt > issuedAt.getTime() + 60_000 || authorizedAt < finalReadyAt ||
      authorizedAt > issuedAt.getTime() + 60_000 || issuedAt.getTime() - authorizedAt > 60_000) {
    throw new Error('ARC2_FINAL_DELIVERY_RECEIPT_AUTHORITY_STALE');
  }
  const receiptSecret = secret(env.ARC_FINAL_DELIVERY_RECEIPT_SECRET,
    'ARC_FINAL_DELIVERY_RECEIPT_SECRET');
  const value = {
    version: FINAL_DELIVERY_RECEIPT_VERSION,
    scope: FINAL_DELIVERY_RECEIPT_SCOPE,
    handoff_id: authority.handoff_id,
    outbox_claim_key_hmac_sha256: authority.job_key,
    recipient_email_sha256: authority.recipient_email_sha256,
    production_url_sha256: authority.production_url_sha256,
    netlify_site_id_sha256: authority.netlify_site_id_sha256,
    netlify_deploy_id_sha256: authority.netlify_deploy_id_sha256,
    provider: 'resend',
    provider_account_hmac_sha256: resendProviderAccountHmacSha256(env),
    provider_event_id: deliveredEvent.provider_event_id,
    provider_message_id: deliveredEvent.provider_message_id,
    event_type: 'message.delivered',
    delivery_status: 'delivered',
    delivered_at: deliveredEvent.delivered_at,
    issued_at: issuedAt.toISOString(),
  };
  const canonical = canonicalJson(value);
  return Object.freeze({
    handoff_id: authority.handoff_id,
    delivery_receipt_evidence: canonical,
    delivery_receipt_evidence_hmac_sha256: hmac(receiptSecret,
      `${FINAL_DELIVERY_RECEIPT_SIGNATURE_PREFIX}${canonical}`),
  });
}
