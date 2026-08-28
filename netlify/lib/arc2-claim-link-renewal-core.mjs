import { createHash } from 'node:crypto';

import { renewClaimInvitationFromExpiredBearer } from './arc2-handoff-service.mjs';
import { assertArc2EmailNegativeStateAllows } from './arc2-negative-email-state-core.mjs';
import { arc2TransactionalEmailWorkerConfiguration } from './arc2-transactional-email-worker-core.mjs';
import { readEmailSendAttempt } from './email-send-attempt-core.mjs';
import { openEmailRecipientCapsule } from './email-recipient-vault-core.mjs';
import {
  readReviewInviteForEmail,
  readReviewRecipientSuppressionForAuthorization,
} from './review-flow-core.mjs';

export const ARC2_CLAIM_LINK_RENEWAL_ENABLED_ENV =
  'ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED';

const HEX_64 = /^[a-f0-9]{64}$/;
const NEGATIVE_ATTEMPT_STATES = new Set([
  'BOUNCED',
  'COMPLAINED',
  'FAILED',
  'SUPPRESSED',
]);
const CLAIM_LINK_RENEWAL_OPERATION_PREFIX = 'arc2-claim-link-renewal-operation-v1\n';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export function arc2ClaimLinkRenewalConfiguration(env = process.env) {
  const raw = env[ARC2_CLAIM_LINK_RENEWAL_ENABLED_ENV];
  const flagValid = raw === undefined || raw === 'true' || raw === 'false';
  const requested = raw === 'true';
  let claimEmailReady = false;
  try {
    claimEmailReady = arc2TransactionalEmailWorkerConfiguration(env).claim_invitation_enabled;
  } catch {}
  const sharedWorkerEnabled = env.ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED === 'true';
  return Object.freeze({
    flag_valid: flagValid,
    requested,
    enabled: flagValid && requested && sharedWorkerEnabled && claimEmailReady,
    claim_email_ready: claimEmailReady,
    shared_worker_enabled: sharedWorkerEnabled,
  });
}

function exactAuthority(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([
        'claim_invitation_generation',
        'expires_at',
        'handoff_id',
        'job_key',
        'recipient_email_sha256',
      ]) || !HEX_64.test(String(value.handoff_id || '')) ||
      !HEX_64.test(String(value.job_key || '')) ||
      !HEX_64.test(String(value.recipient_email_sha256 || '')) ||
      !Number.isSafeInteger(value.claim_invitation_generation) ||
      value.claim_invitation_generation < 0 ||
      !Number.isFinite(Date.parse(value.expires_at))) {
    throw new TypeError('ARC2 claim-link renewal authority is invalid.');
  }
  return value;
}

// Fail closed on both the original review recipient suppression control and
// terminal negative delivery state from the prior claim invitation. The raw
// recipient stays inside the encrypted capsule and is used only for an
// in-memory continuity check.
export async function assertClaimLinkRenewalEmailAllowed(
  stores,
  rawAuthority,
  env = process.env,
  adapters = {},
) {
  const authority = exactAuthority(rawAuthority);
  if (!stores?.attempt || !stores?.ledger || !stores?.review || !stores?.vault) {
    throw new TypeError('ARC2 claim-link renewal stores are invalid.');
  }
  const assertNegativeState = adapters.assertArc2EmailNegativeStateAllows ||
    assertArc2EmailNegativeStateAllows;
  await assertNegativeState(stores.ledger, authority.handoff_id, 'claim_invitation', env);
  const openCapsule = adapters.openEmailRecipientCapsule || openEmailRecipientCapsule;
  const capsule = await openCapsule(stores.vault, {
    job_kind: 'claim_invitation',
    job_key: authority.handoff_id,
  }, env, { clock: adapters.clock });
  const sourceInviteHmac = capsule?.private_payload?.source_invite_hmac_sha256;
  if (typeof capsule?.recipient_email !== 'string' ||
      sha256(capsule.recipient_email) !== authority.recipient_email_sha256 ||
      !HEX_64.test(String(sourceInviteHmac || ''))) {
    throw new Error('ARC2_CLAIM_RENEWAL_RECIPIENT_CONTINUITY_INVALID');
  }

  const readInvite = adapters.readReviewInviteForEmail || readReviewInviteForEmail;
  const readSuppression = adapters.readReviewRecipientSuppressionForAuthorization ||
    readReviewRecipientSuppressionForAuthorization;
  const [sourceInvite, recipientSuppression, priorAttempt] = await Promise.all([
    readInvite(stores.review, sourceInviteHmac, env),
    readSuppression(stores.review, authority.recipient_email_sha256, env),
    (adapters.readEmailSendAttempt || readEmailSendAttempt)(stores.attempt, {
      job_kind: 'claim_invitation',
      job_key: authority.job_key,
    }, env),
  ]);
  if (!sourceInvite?.record ||
      sourceInvite.record.invite_hmac_sha256 !== sourceInviteHmac ||
      sourceInvite.record.recipient_email_sha256 !== authority.recipient_email_sha256) {
    throw new Error('ARC2_CLAIM_RENEWAL_RECIPIENT_CONTINUITY_INVALID');
  }
  if (recipientSuppression || sourceInvite.record.email_suppression_receipt_sha256 !== null ||
      NEGATIVE_ATTEMPT_STATES.has(priorAttempt?.state)) {
    throw new Error('ARC2_CLAIM_RENEWAL_RECIPIENT_SUPPRESSED');
  }
  // Re-read the channel control after the recipient/attempt reads. If a
  // provider complaint raced this request, the fresh generation must never be
  // queued for delivery.
  await assertNegativeState(stores.ledger, authority.handoff_id, 'claim_invitation', env);
  return Object.freeze({
    recipient_email_sha256: authority.recipient_email_sha256,
    source_invite_hmac_sha256: sourceInviteHmac,
    prior_attempt_state: priorAttempt?.state || 'NOT_FOUND',
  });
}

export async function requestClaimLinkRenewal(input, env, stores, adapters = {}) {
  const configuration = arc2ClaimLinkRenewalConfiguration(env);
  if (!configuration.enabled) throw new Error('ARC2_CLAIM_LINK_RENEWAL_DISABLED');
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.getPrototypeOf(input) !== Object.prototype ||
      JSON.stringify(Object.keys(input).sort()) !== JSON.stringify(['bearer', 'handoff_id']) ||
      !HEX_64.test(String(input.handoff_id || '')) ||
      typeof input.bearer !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.bearer) ||
      !stores?.ledger || !stores?.attempt || !stores?.review || !stores?.vault) {
    throw new TypeError('ARC2 claim-link renewal request is invalid.');
  }
  const renew = adapters.renewClaimInvitationFromExpiredBearer ||
    renewClaimInvitationFromExpiredBearer;
  // Bind the customer recovery to the exact expired bearer request without
  // retaining or exposing that bearer. The handoff service persists only its
  // own HMAC of this opaque operation identity, allowing a route-marker crash
  // to replay the already-rotated generation instead of rejecting the prior
  // bearer or rotating a second time.
  const renewalOperationId = sha256(
    `${CLAIM_LINK_RENEWAL_OPERATION_PREFIX}${input.handoff_id}\n${input.bearer}`,
  );
  const result = await renew(input.handoff_id, input.bearer, env, {
    ...adapters,
    store: stores.ledger,
    reviewStore: stores.review,
    renewalOperationId,
    assertRenewalEmailAllowed: (authority) => assertClaimLinkRenewalEmailAllowed(
      stores,
      authority,
      env,
      adapters,
    ),
  });
  if (!result) return null;
  if (result.handoff_id !== input.handoff_id ||
      !HEX_64.test(String(result.job_key || '')) ||
      !HEX_64.test(String(result.previous_job_key || '')) ||
      result.job_key === result.previous_job_key ||
      !Number.isSafeInteger(result.claim_invitation_generation) ||
      result.claim_invitation_generation < 1 ||
      !Number.isFinite(Date.parse(result.expires_at)) ||
      typeof result.idempotent_replay !== 'boolean') {
    throw new Error('ARC2_CLAIM_RENEWAL_RESULT_INVALID');
  }
  return Object.freeze({
    accepted: true,
    claim_invitation_generation: result.claim_invitation_generation,
    expires_at: result.expires_at,
  });
}

export function sameOriginClaimLinkRenewalRequest(request, env = process.env) {
  let expected;
  try {
    const origin = new URL(env.ARC_PUBLIC_ORIGIN);
    if (origin.protocol !== 'https:' || origin.username || origin.password || origin.port ||
        origin.pathname !== '/' || origin.search || origin.hash) return false;
    expected = origin.origin;
  } catch {
    return false;
  }
  if (request.headers.get('origin') !== expected) return false;
  const fetchSite = request.headers.get('sec-fetch-site');
  if (fetchSite !== null && fetchSite !== 'same-origin') return false;
  return true;
}
