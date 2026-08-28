import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  ARC2_CLAIM_EMAIL_REVIEW_REQUIRED,
  ARC2_DELIVERY_REVIEW_REQUIRED,
  ARC2_EMAIL_LOCAL_ALERT_PREFIX,
  ARC2_EMAIL_NEGATIVE_CONTROL_PREFIX,
  ARC2_EMAIL_NEGATIVE_EVENT_PREFIX,
  arc2NegativeEmailStateConfiguration,
  assertArc2EmailNegativeStateAllows,
} from '../netlify/lib/arc2-negative-email-state-core.mjs';
import {
  OUTBOX_CLAIM_VERSION,
  canonicalJson,
  hmacHex,
  sha256Hex,
} from '../netlify/lib/arc2-handoff-core.mjs';
import {
  exchangeClaimBearer,
  leadRouteReceiptContract,
  markClaimInvitationReady,
} from '../netlify/lib/arc2-handoff-service.mjs';
import {
  EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA,
  openEmailRecipientCapsule,
  sealEmailRecipientCapsule,
} from '../netlify/lib/email-recipient-vault-core.mjs';
import {
  reconcileArc2TransactionalEmailEvent,
  sealArc2EmailAttemptContext,
} from '../netlify/lib/arc2-transactional-email-worker-core.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

class FakeStore {
  constructor() {
    this.values = new Map();
    this.sequence = 0;
    this.deleteFailures = 0;
    this.tombstoneFailures = 0;
  }

  async getWithMetadata(key) {
    const value = this.values.get(key);
    return value ? { data: structuredClone(value.data), etag: value.etag } : null;
  }

  async setJSON(key, data, options = {}) {
    if (this.tombstoneFailures > 0 && options.onlyIfMatch &&
        data?.schema === EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA) {
      this.tombstoneFailures -= 1;
      throw new Error('SIMULATED_DELETE_FAILURE');
    }
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `e-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }

  async delete(key) {
    if (this.deleteFailures > 0) {
      this.deleteFailures -= 1;
      throw new Error('SIMULATED_DELETE_FAILURE');
    }
    this.values.delete(key);
  }

  failNextDelete() {
    this.deleteFailures += 1;
  }

  failNextVaultTombstone() {
    this.tombstoneFailures += 1;
  }

  list(options = {}) {
    const blobs = [...this.values.keys()]
      .filter((key) => key.startsWith(options.prefix || ''))
      .sort()
      .map((key) => ({ key }));
    if (!options.paginate) return { blobs };
    return { async *[Symbol.asyncIterator]() { yield { blobs }; } };
  }
}

const startedAt = new Date('2026-08-28T12:00:00.000Z');
const claimHandoffId = 'a'.repeat(64);
const finalHandoffId = 'f'.repeat(64);
const recipient = 'owner@example.test';
const sourceInvite = 'b'.repeat(64);
const capsuleExpiresAt = new Date(startedAt.getTime() + 24 * 60 * 60_000).toISOString();
const env = {
  ARC_TRANSACTIONAL_EMAIL_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY: Buffer.alloc(32, 31).toString('base64url'),
  ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET: 'negative-state-vault-secret-0123456789abcdef',
  ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED: 'true',
  ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED: 'true',
  ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET: 'negative-state-control-secret-0123456789abcdef',
  ARC_CLAIM_TOKEN_SECRET: 'negative-state-claim-secret-0123456789abcdef',
  ARC_LEAD_ROUTE_EVIDENCE_SECRET: 'negative-state-route-secret-0123456789abcdef',
  ARC_EMAIL_CLAIM_BINDING_SECRET: 'negative-state-binding-secret-0123456789abcdef',
  ARC_PUBLIC_ORIGIN: 'https://arcweb.onl/',
  NETLIFY_OAUTH_CLIENT_ID: 'oauth-client-123',
  NETLIFY_OAUTH_CLIENT_SECRET: 'negative-state-oauth-secret-0123456789abcdef',
  NETLIFY_ADMIN_PAT: 'negative-state-netlify-pat-0123456789abcdef',
  NETLIFY_TEAM_ACCOUNT_ID: 'source-account-123',
  NETLIFY_TEAM_SLUG: 'arc-team',
  ARC_STRIPE_CHECKOUT_LEDGER_ENABLED: 'false',
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'false',
  ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
  ARC_ALLOW_TEST_MODE_EVENTS: 'true',
  ARC_HANDOFF_ENABLED: 'false',
  ARC_RUNTIME_ENVIRONMENT: 'sandbox',
};

assert.deepEqual(arc2NegativeEmailStateConfiguration({
  ...env,
  ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET: '',
}), { requested: true, enabled: false },
'Enabling either ARC2 email channel without its negative-state secret must fail closed.');
assert.deepEqual(await assertArc2EmailNegativeStateAllows(new FakeStore(), claimHandoffId,
  'claim_invitation', {
    ...env,
    ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED: 'false',
    ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET: '',
  }), { enabled: false, allowed: true },
'A never-enabled channel with no negative control remains inert by default.');

function basePreclaimRecord() {
  return {
    schema: 'arc2-netlify-handoff-v1', handoff_id: claimHandoffId,
    state: 'PRECLAIM_DEPLOY_READY', revision: 8,
    created_at: startedAt.toISOString(), updated_at: startedAt.toISOString(),
    payment_evidence_sha256: '1'.repeat(64), artifact_evidence_sha256: '2'.repeat(64),
    artifact_manifest_sha256: '3'.repeat(64), bundle_fingerprint: '4'.repeat(64),
    production_content_sha256: '5'.repeat(64), customer_email_sha256: sha256(recipient),
    lead_notification_email_sha256: sha256Hex('leads@example.test'),
    lead_route_recipient_hmac_sha256: hmacHex(env.ARC_LEAD_ROUTE_EVIDENCE_SECRET,
      'arc-lead-route-recipient-v1\nleads@example.test'),
    preview_folder: 'sample-roofing-a1b2c3d4',
    artifacts: [
      { path: '_headers', sha256: '7'.repeat(64), size: 10 },
      { path: 'about/index.html', sha256: '8'.repeat(64), size: 20 },
      { path: 'contact/index.html', sha256: '9'.repeat(64), size: 20 },
      { path: 'process/index.html', sha256: 'a'.repeat(64), size: 20 },
      { path: 'services/index.html', sha256: 'b'.repeat(64), size: 20 },
      { path: 'index.html', sha256: 'c'.repeat(64), size: 20 },
    ],
    form_name: 'sample-lead', netlify_session_id: '11111111-1111-4111-8111-111111111111',
    netlify_site_name: `arc-lead-route-${'b'.repeat(24)}`,
    netlify_source_account_id: 'source-account-123', netlify_site_id: 'c'.repeat(24),
    site_created_at: startedAt.toISOString(), preclaim_deploy_attempted_at: startedAt.toISOString(),
    preclaim_deploy_candidate_id: 'd'.repeat(24), preclaim_deploy_id: 'd'.repeat(24),
    final_deploy_attempted_at: null, final_deploy_candidate_id: null, final_deploy_id: null,
    email_hook_attempted_at: startedAt.toISOString(), form_id: 'e'.repeat(24), hook_id: 'f'.repeat(24),
    destination_account_id: null, lead_route_receipt_sha256: null, claim_token_hmac_sha256: null,
    claim_token_consumed_hmac_sha256: null, claim_token_expires_at: null, claim_token_used_at: null,
    claim_wrapper_consumed_at: null, claim_jwt_issued_at: null, claim_invitation_ready_at: null,
    lead_route_provider_message_id_sha256: null, claim_callback_received_at: null,
    claimed_verified_at: null, final_deploy_ready_at: null, production_url: null,
    outbox_claim_status: null, outbox_claim_key_hmac_sha256: null,
    final_delivery_receipt_sha256: null, final_delivery_provider_message_id_sha256: null,
    final_delivery_receipt_issued_at: null, delivered_at: null,
  };
}

function claimReceipt(record) {
  const value = {
    version: leadRouteReceiptContract.version, scope: leadRouteReceiptContract.scope,
    handoff_id: claimHandoffId, netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
    form_id_sha256: sha256Hex(record.form_id), hook_id_sha256: sha256Hex(record.hook_id),
    recipient_email_sha256: record.lead_notification_email_sha256,
    provider_message_id_sha256: sha256Hex('provider-message'),
    inbox_receipt_id_sha256: sha256Hex('inbox-receipt'),
    received_at: new Date(startedAt.getTime() - 30_000).toISOString(), issued_at: startedAt.toISOString(),
  };
  const evidence = canonicalJson(value);
  return { evidence, signature: hmacHex(env.ARC_LEAD_ROUTE_EVIDENCE_SECRET,
    `${leadRouteReceiptContract.signaturePrefix}${evidence}`) };
}

function claimJobKey(record) {
  return hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET, canonicalJson({
    version: 'arc2-claim-invitation-ready-outbox-v2', handoff_id: record.handoff_id,
    recipient_email_sha256: record.customer_email_sha256,
    claim_invitation_generation: record.claim_invitation_generation,
    claim_token_hmac_sha256: record.claim_token_hmac_sha256, expires_at: record.claim_token_expires_at,
  }));
}

async function sealPrimaryAndContext(vault, kind, handoffId, jobKey, attemptHmac, clock) {
  await sealEmailRecipientCapsule(vault, {
    job_kind: kind, job_key: handoffId, recipient_email: recipient,
    private_payload: { source_invite_hmac_sha256: sourceInvite }, expires_at: capsuleExpiresAt,
  }, env, { clock, randomBytes: () => Buffer.alloc(12, kind === 'claim_invitation' ? 11 : 21) });
  const job = {
    kind, handoff_id: handoffId, job_key: jobKey, recipient_email: recipient,
    recipient_email_sha256: sha256(recipient), source_invite_hmac_sha256: sourceInvite,
    capsule_expires_at: capsuleExpiresAt,
  };
  await sealArc2EmailAttemptContext(vault, job, { attempt_hmac_sha256: attemptHmac },
    `arc2-test-${kind}`, { subject: kind }, env, {
      clock, randomBytes: () => Buffer.alloc(12, kind === 'claim_invitation' ? 12 : 22),
    });
}

function negativeEvent(kind, attemptHmac, eventType, eventId, messageId, occurredAt) {
  return {
    attempt_hmac_sha256: attemptHmac, job_kind: kind, provider: 'resend',
    provider_event_id: eventId, provider_message_id: messageId, event_type: eventType,
    occurred_at: occurredAt, idempotent_replay: false,
  };
}

const claimLedger = new FakeStore();
const claimVault = new FakeStore();
const preclaim = basePreclaimRecord();
await claimLedger.setJSON(`handoffs/${claimHandoffId}`, preclaim, { onlyIfNew: true });
const receipt = claimReceipt(preclaim);
const issued = await markClaimInvitationReady(claimHandoffId, receipt.evidence, receipt.signature, env, {
  store: claimLedger, clock: () => new Date(startedAt),
});
const originalGeneration = issued.record.claim_invitation_generation;
const originalBearer = issued.claimBearer;
const claimAttempt = 'd'.repeat(64);
await sealPrimaryAndContext(claimVault, 'claim_invitation', claimHandoffId,
  claimJobKey(issued.record), claimAttempt, () => new Date(startedAt));
await sealEmailRecipientCapsule(claimVault, {
  job_kind: 'final_delivery', job_key: claimHandoffId, recipient_email: recipient,
  private_payload: { source_invite_hmac_sha256: sourceInvite }, expires_at: capsuleExpiresAt,
}, env, { clock: () => new Date(startedAt), randomBytes: () => Buffer.alloc(12, 13) });
const consumedBeforeBounce = await exchangeClaimBearer(claimHandoffId, originalBearer, env, {
  store: claimLedger, clock: () => new Date(startedAt.getTime() + 30_000),
});
assert.equal(consumedBeforeBounce.record.state, 'CLAIM_WRAPPER_CONSUMED');

const bounceAt = new Date(startedAt.getTime() + 60_000).toISOString();
const claimBounce = negativeEvent('claim_invitation', claimAttempt, 'email.bounced',
  'evt-claim-bounced-1', '11111111-2222-4333-8444-555555555555', bounceAt);
const claimStores = { ledger: claimLedger, review: new FakeStore(), vault: claimVault };
const firstClaimNegative = await reconcileArc2TransactionalEmailEvent(claimStores, claimBounce, env, {
  clock: () => new Date(bounceAt),
});
assert.equal(firstClaimNegative.state, ARC2_CLAIM_EMAIL_REVIEW_REQUIRED);
assert.equal(firstClaimNegative.unlock_delivery, false);
assert.equal([...claimLedger.values.keys()].filter((key) =>
  key.startsWith(ARC2_EMAIL_LOCAL_ALERT_PREFIX)).length, 1,
'A claim-invitation bounce must raise one local PII-free alert.');
assert.match(JSON.stringify([...claimLedger.values.entries()]
  .filter(([key]) => key.startsWith(ARC2_EMAIL_LOCAL_ALERT_PREFIX))),
  /claim-invitation-bounced/);
const rotatedClaim = (await claimLedger.getWithMetadata(`handoffs/${claimHandoffId}`)).data;
assert.equal(rotatedClaim.claim_invitation_generation, originalGeneration + 1);
assert.notEqual(rotatedClaim.claim_token_hmac_sha256, issued.record.claim_token_hmac_sha256);
assert.notEqual(rotatedClaim.claim_token_consumed_hmac_sha256,
  consumedBeforeBounce.record.claim_token_consumed_hmac_sha256,
'A negative event must invalidate an already-consumed replay bearer, not only an unconsumed link.');
assert.equal(await claimLedger.getWithMetadata(`invitation-ready-current/${claimHandoffId}`), null);
await assert.rejects(exchangeClaimBearer(claimHandoffId, originalBearer, env, {
  store: claimLedger, clock: () => new Date(bounceAt),
}), /CLAIM_(?:EMAIL_REVIEW_REQUIRED|BEARER_INVALID)/);
for (const binding of [
  { job_kind: 'claim_invitation', job_key: claimHandoffId },
  { job_kind: 'final_delivery', job_key: claimHandoffId },
  { job_kind: 'claim_invitation', job_key: `attempt-context:${claimAttempt}` },
]) {
  await assert.rejects(openEmailRecipientCapsule(claimVault, binding, env, {
    clock: () => new Date(bounceAt),
  }), /ARC_EMAIL_VAULT_NOT_FOUND/);
}
const claimReplay = await reconcileArc2TransactionalEmailEvent(claimStores, {
  ...claimBounce, idempotent_replay: true,
}, env, { clock: () => new Date(startedAt.getTime() + 2 * 60_000) });
assert.equal(claimReplay.idempotent_replay, true);
assert.equal((await claimLedger.getWithMetadata(`handoffs/${claimHandoffId}`)).data
  .claim_invitation_generation, originalGeneration + 1,
'Exact bounce replay must not keep rotating the claim bearer.');
await reconcileArc2TransactionalEmailEvent(claimStores, negativeEvent(
  'claim_invitation', claimAttempt, 'email.complained', 'evt-claim-complained-2',
  '11111111-2222-4333-8444-555555555555',
  new Date(startedAt.getTime() + 3 * 60_000).toISOString(),
), env, { clock: () => new Date(startedAt.getTime() + 3 * 60_000) });
assert.equal((await claimLedger.getWithMetadata(`handoffs/${claimHandoffId}`)).data
  .claim_invitation_generation, originalGeneration + 1,
'A later complaint must preserve the already-closed claim authority.');
assert.equal([...claimLedger.values.keys()].filter((key) =>
  key.startsWith(ARC2_EMAIL_LOCAL_ALERT_PREFIX)).length, 2,
'A later claim complaint must raise its own critical local alert.');

const disabledAfterControlEnv = {
  ...env,
  ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED: 'false',
};
await assert.rejects(assertArc2EmailNegativeStateAllows(claimLedger, claimHandoffId,
  'claim_invitation', disabledAfterControlEnv), /ARC2_CLAIM_EMAIL_REVIEW_REQUIRED/,
'Turning a channel OFF must never bypass an already-durable manual-review latch.');

const finalLedger = new FakeStore();
const finalVault = new FakeStore();
const finalJobKey = 'e'.repeat(64);
const finalAttempt = '9'.repeat(64);
await finalLedger.setJSON(`outbox/${finalJobKey}`, {
  schema: OUTBOX_CLAIM_VERSION, status: 'CLAIMED', handoff_id: finalHandoffId,
  netlify_site_id_sha256: '1'.repeat(64), netlify_deploy_id_sha256: '2'.repeat(64),
  outbox_claim_key_hmac_sha256: finalJobKey,
}, { onlyIfNew: true });
await sealPrimaryAndContext(finalVault, 'final_delivery', finalHandoffId,
  finalJobKey, finalAttempt, () => new Date(startedAt));
const finalStores = { ledger: finalLedger, review: new FakeStore(), vault: finalVault };
const finalBounce = negativeEvent('final_delivery', finalAttempt, 'email.bounced',
  'evt-final-bounced-1', '66666666-7777-4888-8999-000000000000', bounceAt);
const firstFinalNegative = await reconcileArc2TransactionalEmailEvent(finalStores, finalBounce, env, {
  clock: () => new Date(bounceAt),
});
assert.equal(firstFinalNegative.state, ARC2_DELIVERY_REVIEW_REQUIRED);
assert.equal(firstFinalNegative.unlock_delivery, false);
const lockedOutbox = (await finalLedger.getWithMetadata(`outbox/${finalJobKey}`)).data;
assert.equal(lockedOutbox.status, ARC2_DELIVERY_REVIEW_REQUIRED);
assert.match(lockedOutbox.negative_control_hmac_sha256, /^[a-f0-9]{64}$/);
assert.equal([...finalLedger.values.keys()].filter((key) =>
  key.startsWith(ARC2_EMAIL_LOCAL_ALERT_PREFIX)).length, 1);
assert.equal([...finalLedger.values.keys()].filter((key) =>
  key.startsWith(ARC2_EMAIL_NEGATIVE_CONTROL_PREFIX + 'by-handoff/')).length, 1);
assert.equal([...finalLedger.values.keys()].filter((key) =>
  key.startsWith(ARC2_EMAIL_NEGATIVE_EVENT_PREFIX)).length, 1);
const durableNegativeJson = JSON.stringify([...finalLedger.values.entries()]
  .filter(([key]) => key.startsWith('arc2-email-')));
assert.doesNotMatch(durableNegativeJson, /owner@example\.test|arc2\.[a-f0-9]{64}\./,
'Negative controls and local alerts must be PII-free and contain no bearer.');

const finalReplay = await reconcileArc2TransactionalEmailEvent(finalStores, {
  ...finalBounce, idempotent_replay: true,
}, env, { clock: () => new Date(startedAt.getTime() + 2 * 60_000) });
assert.equal(finalReplay.idempotent_replay, true);
assert.equal([...finalLedger.values.keys()].filter((key) =>
  key.startsWith(ARC2_EMAIL_LOCAL_ALERT_PREFIX)).length, 1,
'Exact bounce replay must reuse the same local alert.');
await reconcileArc2TransactionalEmailEvent(finalStores, negativeEvent(
  'final_delivery', finalAttempt, 'email.complained', 'evt-final-complained-2',
  '66666666-7777-4888-8999-000000000000',
  new Date(startedAt.getTime() + 3 * 60_000).toISOString(),
), env, { clock: () => new Date(startedAt.getTime() + 3 * 60_000) });
assert.equal([...finalLedger.values.keys()].filter((key) =>
  key.startsWith(ARC2_EMAIL_LOCAL_ALERT_PREFIX)).length, 2,
'A complaint after a bounce must get its own critical local alert without reopening delivery.');
assert.equal((await finalLedger.getWithMetadata(`outbox/${finalJobKey}`)).data.status,
  ARC2_DELIVERY_REVIEW_REQUIRED);

let lateAckCalled = false;
await assert.rejects(reconcileArc2TransactionalEmailEvent(finalStores, {
  attempt_hmac_sha256: finalAttempt, job_kind: 'final_delivery', provider: 'resend',
  provider_event_id: 'evt-final-delivered-late',
  provider_message_id: '66666666-7777-4888-8999-000000000000', event_type: 'email.delivered',
  occurred_at: new Date(startedAt.getTime() + 4 * 60_000).toISOString(), idempotent_replay: false,
}, env, {
  clock: () => new Date(startedAt.getTime() + 4 * 60_000),
  acknowledgeFinalDelivery: async () => { lateAckCalled = true; },
}), /ARC_EMAIL_VAULT_NOT_FOUND/);
assert.equal(lateAckCalled, false, 'Late delivered must not reopen a final delivery after a negative event.');
await assert.rejects(assertArc2EmailNegativeStateAllows(finalLedger, finalHandoffId,
  'final_delivery', env), /ARC2_DELIVERY_REVIEW_REQUIRED/);

async function exerciseAdditionalFinalNegative(eventType, marker) {
  const ledger = new FakeStore();
  const vault = new FakeStore();
  const handoffId = marker.repeat(64);
  const jobKey = (marker === 'c' ? '4' : '5').repeat(64);
  const attempt = (marker === 'c' ? '6' : '7').repeat(64);
  await ledger.setJSON(`outbox/${jobKey}`, {
    schema: OUTBOX_CLAIM_VERSION, status: 'CLAIMED', handoff_id: handoffId,
    netlify_site_id_sha256: '1'.repeat(64), netlify_deploy_id_sha256: '2'.repeat(64),
    outbox_claim_key_hmac_sha256: jobKey,
  }, { onlyIfNew: true });
  await sealPrimaryAndContext(vault, 'final_delivery', handoffId, jobKey, attempt,
    () => new Date(startedAt));
  const result = await reconcileArc2TransactionalEmailEvent({
    ledger, review: new FakeStore(), vault,
  }, negativeEvent('final_delivery', attempt, eventType, `evt-final-${marker}`,
    marker === 'c'
      ? '77777777-7777-4777-8777-777777777777'
      : '88888888-8888-4888-8888-888888888888',
    new Date(startedAt.getTime() + 5 * 60_000).toISOString()), env, {
    clock: () => new Date(startedAt.getTime() + 5 * 60_000),
  });
  assert.equal(result.state, ARC2_DELIVERY_REVIEW_REQUIRED);
  const alertJson = JSON.stringify([...ledger.values.entries()]
    .filter(([key]) => key.startsWith(ARC2_EMAIL_LOCAL_ALERT_PREFIX)));
  assert.match(alertJson, new RegExp(`final-delivery-${eventType.slice(6)}`));
  assert.equal((await ledger.getWithMetadata(`outbox/${jobKey}`)).data.status,
    ARC2_DELIVERY_REVIEW_REQUIRED);
}

await exerciseAdditionalFinalNegative('email.failed', 'c');
await exerciseAdditionalFinalNegative('email.suppressed', 'd');

// Simulate a crash after the signed review latch and alert are durable but
// before recipient-capsule cleanup. The surviving context must not let a late
// delivered webhook acknowledge the handoff.
const crashLedger = new FakeStore();
const crashVault = new FakeStore();
const crashHandoffId = 'e'.repeat(64);
const crashJobKey = '3'.repeat(64);
const crashAttempt = '2'.repeat(64);
await crashLedger.setJSON(`outbox/${crashJobKey}`, {
  schema: OUTBOX_CLAIM_VERSION, status: 'CLAIMED', handoff_id: crashHandoffId,
  netlify_site_id_sha256: '1'.repeat(64), netlify_deploy_id_sha256: '2'.repeat(64),
  outbox_claim_key_hmac_sha256: crashJobKey,
}, { onlyIfNew: true });
await sealPrimaryAndContext(crashVault, 'final_delivery', crashHandoffId,
  crashJobKey, crashAttempt, () => new Date(startedAt));
crashVault.failNextVaultTombstone();
const crashStores = { ledger: crashLedger, review: new FakeStore(), vault: crashVault };
await assert.rejects(reconcileArc2TransactionalEmailEvent(crashStores, negativeEvent(
  'final_delivery', crashAttempt, 'email.failed', 'evt-final-crash',
  '99999999-9999-4999-8999-999999999999',
  new Date(startedAt.getTime() + 6 * 60_000).toISOString(),
), env, { clock: () => new Date(startedAt.getTime() + 6 * 60_000) }),
/SIMULATED_DELETE_FAILURE/);
let crashLateAckCalled = false;
await assert.rejects(reconcileArc2TransactionalEmailEvent(crashStores, {
  attempt_hmac_sha256: crashAttempt, job_kind: 'final_delivery', provider: 'resend',
  provider_event_id: 'evt-final-crash-delivered',
  provider_message_id: '99999999-9999-4999-8999-999999999999',
  event_type: 'email.delivered',
  occurred_at: new Date(startedAt.getTime() + 7 * 60_000).toISOString(),
  idempotent_replay: false,
}, env, {
  clock: () => new Date(startedAt.getTime() + 7 * 60_000),
  acknowledgeFinalDelivery: async () => { crashLateAckCalled = true; },
}), /ARC2_DELIVERY_REVIEW_REQUIRED/);
assert.equal(crashLateAckCalled, false,
'A durable review latch must block late delivery even if capsule cleanup crashed.');

console.log('ARC2 durable claim/final negative email state, all negative events, alerts, crash recovery, and replay contract passed.');
