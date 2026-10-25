import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import {
  arc2ClaimLinkRenewalConfiguration,
  assertClaimLinkRenewalEmailAllowed,
  requestClaimLinkRenewal,
  sameOriginClaimLinkRenewalRequest,
} from '../netlify/lib/arc2-claim-link-renewal-core.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const handoffId = 'a'.repeat(64);
const oldJobKey = 'b'.repeat(64);
const newJobKey = 'c'.repeat(64);
const sourceInvite = 'd'.repeat(64);
const recipient = 'owner@example.test';
const recipientSha = sha256(recipient);
const expiresAt = '2026-08-28T12:30:00.000Z';

const env = {
  ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED: 'true',
  ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED: 'true',
  ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED: 'false',
  ARC_TRANSACTIONAL_EMAIL_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET: 'renewal-attempt-secret-0123456789abcdef',
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY: Buffer.alloc(32, 12).toString('base64url'),
  ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET: 'renewal-vault-secret-0123456789abcdef',
  ARC_RESEND_SEND_ENABLED: 'true',
  ARC_RESEND_WEBHOOK_ENABLED: 'true',
  ARC_RESEND_API_KEY: 're_renewal_contract_key_0123456789abcdef',
  ARC_RESEND_WEBHOOK_SECRET: `whsec_${Buffer.alloc(32, 13).toString('base64')}`,
  ARC_RESEND_FROM: 'ARC <preview@send.arcweb.onl>',
  ARC_RESEND_PROVIDER_ACCOUNT_ID: 'resend-account-arc-renewal',
  ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET: 'renewal-provider-binding-secret-0123456789',
  ARC_EMAIL_CLAIM_BINDING_SECRET: 'renewal-email-binding-secret-0123456789',
  ARC_FINAL_DELIVERY_RECEIPT_SECRET: 'renewal-final-receipt-secret-0123456789',
  ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET: 'renewal-negative-state-secret-0123456789',
  ARC_PUBLIC_ORIGIN: 'https://arcweb.onl/',
};

assert.deepEqual(arc2ClaimLinkRenewalConfiguration({}), {
  flag_valid: true,
  requested: false,
  enabled: false,
  claim_email_ready: false,
  shared_worker_enabled: false,
});
assert.equal(arc2ClaimLinkRenewalConfiguration(env).enabled, true);
assert.equal(arc2ClaimLinkRenewalConfiguration({
  ...env,
  ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED: 'yes',
}).flag_valid, false);
assert.equal(arc2ClaimLinkRenewalConfiguration({
  ...env,
  ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED: 'false',
}).enabled, false, 'Recovery must not rotate a bearer while the sender is disabled.');

assert.equal(sameOriginClaimLinkRenewalRequest(new Request('https://arcweb.onl/api/arc2/claim-link-renew', {
  method: 'POST',
  headers: { origin: 'https://arcweb.onl', 'sec-fetch-site': 'same-origin' },
}), env), true);
assert.equal(sameOriginClaimLinkRenewalRequest(new Request('https://arcweb.onl/api/arc2/claim-link-renew', {
  method: 'POST',
  headers: { origin: 'https://attacker.example', 'sec-fetch-site': 'cross-site' },
}), env), false);
assert.equal(sameOriginClaimLinkRenewalRequest(new Request('https://arcweb.onl/api/arc2/claim-link-renew', {
  method: 'POST',
  headers: { origin: 'https://arcweb.onl', 'sec-fetch-site': 'cross-site' },
}), env), false);

const stores = { attempt: {}, ledger: {}, review: {}, vault: {} };
const authority = {
  handoff_id: handoffId,
  job_key: oldJobKey,
  recipient_email_sha256: recipientSha,
  claim_invitation_generation: 1,
  expires_at: '2026-08-28T12:00:00.000Z',
};
const allowedAdapters = {
  assertArc2EmailNegativeStateAllows: async (_store, id, kind) => {
    assert.equal(id, handoffId);
    assert.equal(kind, 'claim_invitation');
    return { enabled: true, allowed: true };
  },
  openEmailRecipientCapsule: async () => ({
    recipient_email: recipient,
    private_payload: { source_invite_hmac_sha256: sourceInvite },
  }),
  readReviewInviteForEmail: async () => ({ record: {
    invite_hmac_sha256: sourceInvite,
    recipient_email_sha256: recipientSha,
    email_suppression_receipt_sha256: null,
  } }),
  readReviewRecipientSuppressionForAuthorization: async () => null,
  readEmailSendAttempt: async () => ({ state: 'DELIVERED' }),
};
assert.deepEqual(await assertClaimLinkRenewalEmailAllowed(stores, authority, env, allowedAdapters), {
  recipient_email_sha256: recipientSha,
  source_invite_hmac_sha256: sourceInvite,
  prior_attempt_state: 'DELIVERED',
});

for (const state of ['BOUNCED', 'COMPLAINED', 'FAILED', 'SUPPRESSED']) {
  await assert.rejects(assertClaimLinkRenewalEmailAllowed(stores, authority, env, {
    ...allowedAdapters,
    readEmailSendAttempt: async () => ({ state }),
  }), /RECIPIENT_SUPPRESSED/, `${state} must block a fresh claim email.`);
}
await assert.rejects(assertClaimLinkRenewalEmailAllowed(stores, authority, env, {
  ...allowedAdapters,
  readReviewRecipientSuppressionForAuthorization: async () => ({ record: { suppression_status: 'complained' } }),
}), /RECIPIENT_SUPPRESSED/, 'The source recipient suppression control must block claim recovery.');
await assert.rejects(assertClaimLinkRenewalEmailAllowed(stores, authority, env, {
  ...allowedAdapters,
  assertArc2EmailNegativeStateAllows: async () => {
    throw new Error('ARC2_CLAIM_EMAIL_REVIEW_REQUIRED');
  },
}), /CLAIM_EMAIL_REVIEW_REQUIRED/,
'A durable ARC2 negative-email control must block renewal before delivery.');
await assert.rejects(assertClaimLinkRenewalEmailAllowed(stores, authority, env, {
  ...allowedAdapters,
  openEmailRecipientCapsule: async () => ({
    recipient_email: 'different@example.test',
    private_payload: { source_invite_hmac_sha256: sourceInvite },
  }),
}), /CONTINUITY_INVALID/, 'Recovery must not change the paid recipient.');

let renewalCalls = 0;
let renewalOperationId = null;
const requestResult = await requestClaimLinkRenewal({
  handoff_id: handoffId,
  bearer: 'q'.repeat(43),
}, env, stores, {
  ...allowedAdapters,
  renewClaimInvitationFromExpiredBearer: async (id, bearer, _env, adapters) => {
    renewalCalls += 1;
    assert.equal(id, handoffId);
    assert.equal(bearer, 'q'.repeat(43));
    assert.equal(adapters.reviewStore, stores.review,
      'Paid review authority must be available to every renewal payment recheck.');
    assert.match(adapters.renewalOperationId, /^[a-f0-9]{64}$/);
    renewalOperationId ||= adapters.renewalOperationId;
    assert.equal(adapters.renewalOperationId, renewalOperationId,
      'An exact lost-response retry must retain one deterministic operation identity.');
    await adapters.assertRenewalEmailAllowed(authority);
    return {
      handoff_id: handoffId,
      claim_invitation_generation: 2,
      previous_job_key: oldJobKey,
      job_key: newJobKey,
      expires_at: expiresAt,
      idempotent_replay: renewalCalls > 1,
    };
  },
});
assert.deepEqual(requestResult, {
  accepted: true,
  claim_invitation_generation: 2,
  expires_at: expiresAt,
});
assert.equal(renewalCalls, 1);
assert.doesNotMatch(JSON.stringify(requestResult), /q{43}|owner@example\.test|b{64}|c{64}/,
  'The customer response must not expose a bearer, recipient, or provider job key.');

const lostResponseReplay = await requestClaimLinkRenewal({
  handoff_id: handoffId,
  bearer: 'q'.repeat(43),
}, env, stores, {
  ...allowedAdapters,
  renewClaimInvitationFromExpiredBearer: async (id, bearer, _env, adapters) => {
    renewalCalls += 1;
    assert.equal(id, handoffId);
    assert.equal(bearer, 'q'.repeat(43));
    assert.equal(adapters.renewalOperationId, renewalOperationId);
    return {
      handoff_id: handoffId,
      claim_invitation_generation: 2,
      previous_job_key: oldJobKey,
      job_key: newJobKey,
      expires_at: expiresAt,
      idempotent_replay: true,
    };
  },
});
assert.deepEqual(lostResponseReplay, requestResult,
  'A post-mutation route-marker loss must reproduce the same accepted generation.');
assert.equal(renewalCalls, 2);

await assert.rejects(requestClaimLinkRenewal({
  handoff_id: handoffId,
  bearer: 'q'.repeat(43),
}, { ...env, ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED: 'false' }, new Proxy({}, {
  get() { throw new Error('disabled recovery touched storage'); },
})), /RENEWAL_DISABLED/);

const [functionSource, pageSource, browserSource] = await Promise.all([
  readFile(new URL('../netlify/functions/arc2-claim-link-renew.mjs', import.meta.url), 'utf8'),
  readFile(new URL('../claim/index.html', import.meta.url), 'utf8'),
  readFile(new URL('../claim/claim.js', import.meta.url), 'utf8'),
]);
assert.match(functionSource, /path:\s*'\/api\/arc2\/claim-link-renew'/);
assert.match(functionSource, /windowLimit:\s*2,\s*windowSize:\s*3600/,
  'The customer recovery endpoint must have a tight provider-edge hourly limit.');
assert.match(functionSource, /sameOriginClaimLinkRenewalRequest/);
assert.match(pageSource, />Email me a fresh ownership link</);
assert.match(browserSource, /addEventListener\('click'/,
  'Claim recovery must require a customer action rather than run on a timer.');
assert.doesNotMatch(browserSource, /setInterval|setTimeout/,
  'Claim recovery must never auto-spam on the 30-minute token schedule.');

console.log('ARC2 claim-link renewal contract passed.');
