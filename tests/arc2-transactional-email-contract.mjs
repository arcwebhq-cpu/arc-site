import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import {
  ARC2_CLAIM_INVITATION_EMAIL_ENABLED_ENV,
  ARC2_FINAL_DELIVERY_EMAIL_ENABLED_ENV,
  arc2TransactionalEmailConfiguration,
  createFinalDeliveryReceiptEvidence,
  discoverNextClaimInvitationEmail,
  discoverNextFinalDeliveryEmail,
  openPaidPreviewRecipientCapsule,
  prepareClaimInvitationEmailJob,
  prepareFinalDeliveryEmailJob,
  resendProviderAccountHmacSha256,
  sealArc2HandoffEmailCapsules,
} from '../netlify/lib/arc2-transactional-email-core.mjs';
import {
  openEmailRecipientCapsule,
  sealEmailRecipientCapsule,
} from '../netlify/lib/email-recipient-vault-core.mjs';
import {
  FINAL_DELIVERY_RECEIPT_SIGNATURE_PREFIX,
  canonicalJson,
} from '../netlify/lib/arc2-handoff-core.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; }
  async getWithMetadata(key) {
    const value = this.values.get(key);
    return value ? { data: structuredClone(value.data), etag: value.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `e-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
  list(options = {}) {
    const blobs = [...this.values.keys()].filter((key) => key.startsWith(options.prefix || ''))
      .sort().map((key) => ({ key }));
    return { async *[Symbol.asyncIterator]() { yield { blobs }; } };
  }
}

const now = new Date('2026-08-27T18:00:00.000Z');
const handoffId = 'a'.repeat(64);
const sourceInvite = 'b'.repeat(64);
const sourceOutbox = 'c'.repeat(64);
const recipient = 'owner@example.test';
const recipientSha = sha256(recipient);
const env = {
  ARC_TRANSACTIONAL_EMAIL_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY: Buffer.alloc(32, 17).toString('base64url'),
  ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET: 'arc2-recipient-vault-hmac-secret-0123456789',
  [ARC2_CLAIM_INVITATION_EMAIL_ENABLED_ENV]: 'true',
  [ARC2_FINAL_DELIVERY_EMAIL_ENABLED_ENV]: 'true',
  ARC_EMAIL_CLAIM_BINDING_SECRET: 'arc2-claim-email-binding-secret-0123456789',
  ARC_FINAL_DELIVERY_RECEIPT_SECRET: 'arc2-final-delivery-receipt-secret-0123456789',
  ARC_RESEND_PROVIDER_ACCOUNT_ID: 'resend-account-arc-production',
  ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET: 'arc2-resend-account-binding-secret-0123456789',
  ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET: 'arc2-email-attempt-secret-0123456789abcdef',
  ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET: 'arc2-negative-state-secret-0123456789abcdef',
};

assert.deepEqual(arc2TransactionalEmailConfiguration({}), {
  flags_valid: true,
  requested: false,
  capsule_producer_enabled: false,
  claim_invitation_enabled: false,
  final_delivery_enabled: false,
});
assert.equal(arc2TransactionalEmailConfiguration({
  ...env,
  [ARC2_CLAIM_INVITATION_EMAIL_ENABLED_ENV]: 'yes',
}).flags_valid, false);
assert.equal(arc2TransactionalEmailConfiguration({
  ...env,
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'false',
}).capsule_producer_enabled, false);
assert.equal(arc2TransactionalEmailConfiguration({
  ...env,
  ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET: '',
}).capsule_producer_enabled, false,
'ARC2 email cannot send unless its mandatory negative-event state is durable.');
assert.equal(arc2TransactionalEmailConfiguration({
  ...env,
  [ARC2_FINAL_DELIVERY_EMAIL_ENABLED_ENV]: 'false',
}).claim_invitation_enabled, true, 'ARC2 email stages must have independent switches.');

const vault = new FakeStore();
await sealEmailRecipientCapsule(vault, {
  job_kind: 'preview_review',
  job_key: sourceOutbox,
  recipient_email: recipient,
  private_payload: {
    invite_token: 'private-preview-invite-token-0123456789',
    invite_hmac_sha256: sourceInvite,
    outbox_hmac_sha256: sourceOutbox,
    preview_manifest_sha256: 'd'.repeat(64),
    recipient_email_sha256: recipientSha,
    review_url: 'https://arcweb.onl/review/#invite=private-preview-invite-token-0123456789',
    template_version: 'arc-preview-ready-v1',
  },
  expires_at: new Date(now.getTime() + 24 * 60 * 60_000).toISOString(),
}, env, { clock: () => now, randomBytes: () => Buffer.alloc(12, 1) });

const source = await openPaidPreviewRecipientCapsule(vault, {}, {
  invite_hmac_sha256: sourceInvite,
  recipient_email_sha256: recipientSha,
}, env, {
  clock: () => now,
  readReviewInviteForEmail: async () => ({
    record: {
      state: 'APPROVED',
      decision: { action: 'APPROVE_AND_PAY' },
      invite_hmac_sha256: sourceInvite,
      recipient_email_sha256: recipientSha,
      email_delivery_outbox_hmac_sha256: sourceOutbox,
      email_delivery_receipt_sha256: 'e'.repeat(64),
      email_delivery_binding_mode: 'signed-outbox',
      email_suppression_receipt_sha256: null,
      preview_manifest_sha256: 'd'.repeat(64),
      successor_invite_hmac_sha256: null,
    },
  }),
});
assert.equal(source.recipient_email, recipient);
assert.equal(source.source_invite_hmac_sha256, sourceInvite);

const sealed = await sealArc2HandoffEmailCapsules(vault, {
  handoff_id: handoffId,
  created_at: now.toISOString(),
}, source, env, { clock: () => now, randomBytes: () => Buffer.alloc(12, 2) });
assert.match(sealed.claim_invitation_vault_hmac_sha256, /^[a-f0-9]{64}$/);
assert.match(sealed.final_delivery_vault_hmac_sha256, /^[a-f0-9]{64}$/);
assert.notEqual(sealed.claim_invitation_vault_hmac_sha256, sealed.final_delivery_vault_hmac_sha256);
assert.deepEqual(await sealArc2HandoffEmailCapsules(vault, {
  handoff_id: handoffId,
  created_at: now.toISOString(),
}, source, env, { clock: () => now }), sealed, 'Capsule production must be exact-replay safe.');

for (const kind of ['claim_invitation', 'final_delivery']) {
  const opened = await openEmailRecipientCapsule(vault, {
    job_kind: kind,
    job_key: handoffId,
  }, env, { clock: () => now });
  assert.equal(opened.recipient_email, recipient);
  assert.deepEqual(opened.private_payload, { source_invite_hmac_sha256: sourceInvite });
}
const durableVault = JSON.stringify([...vault.values.values()].map((entry) => entry.data));
assert.doesNotMatch(durableVault, /owner@example\.test|private-preview-invite-token|https:\/\/arcweb\.onl\/review/,
  'Raw PII and private URLs must remain encrypted.');

const ledger = new FakeStore();
const currentBase = {
  schema: 'arc2-claim-invitation-current-v1',
  handoff_id: handoffId,
  claim_invitation_generation: 1,
  claim_token_hmac_sha256: '1'.repeat(64),
  expires_at: new Date(now.getTime() + 20 * 60_000).toISOString(),
  outbox_key_sha256: '2'.repeat(64),
};
await ledger.setJSON(`invitation-ready-current/${handoffId}`, {
  ...currentBase,
  binding_hmac_sha256: hmac(env.ARC_EMAIL_CLAIM_BINDING_SECRET,
    `arc2-claim-invitation-current-v1\n${canonicalJson(currentBase)}`),
}, { onlyIfNew: true });
const finalJobKey = '3'.repeat(64);
await ledger.setJSON(`outbox/${finalJobKey}`, {
  schema: 'arc2-final-delivery-outbox-v1',
  status: 'CLAIMED',
  handoff_id: handoffId,
  netlify_site_id_sha256: '4'.repeat(64),
  netlify_deploy_id_sha256: '5'.repeat(64),
  outbox_claim_key_hmac_sha256: finalJobKey,
}, { onlyIfNew: true });
assert.deepEqual(await discoverNextClaimInvitationEmail(ledger, env, {
  readHandoff: async () => ({
    handoff_id: handoffId, state: 'INVITATION_READY', customer_email_sha256: recipientSha,
  }),
}), {
  found: true,
  kind: 'claim_invitation',
  handoff_id: handoffId,
  job_key: hmac(env.ARC_EMAIL_CLAIM_BINDING_SECRET, JSON.stringify({
    claim_invitation_generation: 1,
    claim_token_hmac_sha256: '1'.repeat(64),
    expires_at: currentBase.expires_at,
    handoff_id: handoffId,
    recipient_email_sha256: recipientSha,
    version: 'arc2-claim-invitation-ready-outbox-v2',
  })),
  claim_invitation_generation: 1,
  expires_at: currentBase.expires_at,
});
assert.deepEqual(await discoverNextClaimInvitationEmail(ledger, env, {
  readHandoff: async () => ({
    handoff_id: handoffId, state: 'INVITATION_READY', customer_email_sha256: recipientSha,
  }),
  is_candidate_eligible: async () => false,
}), { found: false }, 'Provider-accepted jobs must be skippable during discovery so later work cannot starve.');
assert.deepEqual(await discoverNextFinalDeliveryEmail(ledger, env, {
  readHandoff: async () => ({
    handoff_id: handoffId, state: 'FINAL_DEPLOY_READY', customer_email_sha256: recipientSha,
    outbox_claim_key_hmac_sha256: finalJobKey,
  }),
}), {
  found: true,
  kind: 'final_delivery',
  handoff_id: handoffId,
  job_key: finalJobKey,
});
assert.doesNotMatch(JSON.stringify([...ledger.values.values()]), /owner@example\.test|https?:\/\//);

const claimJobKey = '6'.repeat(64);
const claimUrl = `https://arcweb.onl/claim/#arc2.${handoffId}.private-claim-bearer`;
const claimJob = await prepareClaimInvitationEmailJob(ledger, vault, handoffId, env, {
  clock: () => now,
  getClaimInvitationEmailAuthority: async () => ({
    handoff_id: handoffId,
    job_key: claimJobKey,
    recipient_email_sha256: recipientSha,
    claim_invitation_generation: 1,
    claim_token_hmac_sha256: '1'.repeat(64),
    claim_url: claimUrl,
    expires_at: currentBase.expires_at,
  }),
});
assert.equal(claimJob.job_key, claimJobKey,
  'Claim email generic attempt authority must be the invitation outbox digest.');
assert.equal(claimJob.claim_url, claimUrl);

const finalAuthority = {
  handoff_id: handoffId,
  job_key: finalJobKey,
  recipient_email_sha256: recipientSha,
  production_url: 'https://customer-site.netlify.app/',
  production_url_sha256: sha256('https://customer-site.netlify.app/'),
  netlify_site_id_sha256: '4'.repeat(64),
  netlify_deploy_id_sha256: '5'.repeat(64),
  final_deploy_ready_at: new Date(now.getTime() - 60_000).toISOString(),
  authorized_at: new Date(now.getTime() - 10_000).toISOString(),
  claim_state_evidence_sha256: '7'.repeat(64),
};
const finalJob = await prepareFinalDeliveryEmailJob(ledger, vault, handoffId, env, {
  clock: () => now,
  getFinalDeliveryEmailAuthority: async () => finalAuthority,
});
assert.equal(finalJob.job_key, finalJobKey,
  'Final email generic attempt authority must be the final outbox claim HMAC.');
assert.equal(finalJob.production_url, finalAuthority.production_url);

const providerAccountHmac = resendProviderAccountHmacSha256(env);
assert.equal(providerAccountHmac, hmac(env.ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET,
  `arc-resend-provider-account-binding-v1\n${env.ARC_RESEND_PROVIDER_ACCOUNT_ID}`));
const deliveredEvent = {
  attempt_hmac_sha256: '8'.repeat(64),
  job_kind: 'final_delivery',
  provider: 'resend',
  provider_event_id: 'msg_delivery_event_123',
  provider_message_id: '11111111-2222-4333-8444-555555555555',
  delivered_at: new Date(now.getTime() - 5_000).toISOString(),
  idempotent_replay: false,
};
const receipt = createFinalDeliveryReceiptEvidence(deliveredEvent, finalAuthority, env, {
  clock: () => now,
});
const receiptValue = JSON.parse(receipt.delivery_receipt_evidence);
assert.equal(receiptValue.provider_account_hmac_sha256, providerAccountHmac);
assert.equal(receiptValue.outbox_claim_key_hmac_sha256, finalJobKey);
assert.equal(receiptValue.event_type, 'message.delivered');
assert.equal(receiptValue.delivery_status, 'delivered');
assert.equal(receipt.delivery_receipt_evidence_hmac_sha256,
  hmac(env.ARC_FINAL_DELIVERY_RECEIPT_SECRET,
    `${FINAL_DELIVERY_RECEIPT_SIGNATURE_PREFIX}${receipt.delivery_receipt_evidence}`));
assert.throws(() => createFinalDeliveryReceiptEvidence(deliveredEvent, {
  ...finalAuthority,
  authorized_at: new Date(now.getTime() - 61_000).toISOString(),
}, env, { clock: () => now }), /AUTHORITY_STALE/);
assert.throws(() => createFinalDeliveryReceiptEvidence({
  ...deliveredEvent,
  job_kind: 'claim_invitation',
}, finalAuthority, env, { clock: () => now }), /provider event is invalid/i);

const workerSource = await readFile(new URL('../netlify/functions/payment-arc2-worker.mjs', import.meta.url), 'utf8');
assert.match(workerSource, /completePaidRecipientCapsuleHandoff/,
  'The paid bridge must use the ordered recipient lifecycle boundary.');
const lifecycleSource = await readFile(new URL('../netlify/lib/arc2-transactional-email-core.mjs', import.meta.url), 'utf8');
const sealPosition = lifecycleSource.indexOf('const sealed = await sealArc2HandoffEmailCapsules');
const completePosition = lifecycleSource.indexOf('await adapters.completePaymentArc2StartOutbox()', sealPosition);
const cleanupPosition = lifecycleSource.indexOf('await deletePaidPreviewRecipientCapsule', completePosition);
assert.ok(sealPosition > 0 && completePosition > sealPosition && cleanupPosition > completePosition,
  'The paid bridge must seal and strong-readback downstream capsules, durably complete, then erase the source.');
assert.match(workerSource, /openPaidPreviewRecipientCapsule/);
const serviceSource = await readFile(new URL('../netlify/lib/arc2-handoff-service.mjs', import.meta.url), 'utf8');
assert.match(serviceSource, /getHandoffStatus\(handoffId, env, adapters, \{ includePrivate: true \}\)/,
  'Final send authority must use the private handoff status path.');
assert.match(serviceSource, /STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS/,
  'Claim invitation send authority must require a fresh reversal observation.');

console.log('ARC2 native transactional email contract passed.');
