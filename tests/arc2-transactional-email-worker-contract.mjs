import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import {
  openArc2EmailAttemptContext,
  reconcileArc2TransactionalEmailEvent,
  runArc2TransactionalEmailWorkerCycle,
} from '../netlify/lib/arc2-transactional-email-worker-core.mjs';
import {
  markEmailProviderAccepted,
  readEmailSendAttempt,
} from '../netlify/lib/email-send-attempt-core.mjs';
import { reconcileVerifiedResendWebhook } from '../netlify/lib/resend-webhook-core.mjs';
import { transactionalEmailChannelOrder } from '../netlify/lib/transactional-email-worker-core.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

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
  async delete(key) { this.values.delete(key); }
  list(options = {}) {
    const blobs = [...this.values.keys()].filter((key) => key.startsWith(options.prefix || ''))
      .sort().map((key) => ({ key }));
    if (!options.paginate) return { blobs };
    return { async *[Symbol.asyncIterator]() { yield { blobs }; } };
  }
}

const now = new Date('2026-08-27T20:00:00.000Z');
const expiresAt = new Date(now.getTime() + 24 * 60 * 60_000).toISOString();
const env = {
  ARC_TRANSACTIONAL_EMAIL_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET: 'worker-attempt-hmac-secret-0123456789abcdef',
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY: Buffer.alloc(32, 22).toString('base64url'),
  ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET: 'worker-vault-hmac-secret-0123456789abcdef',
  ARC_RESEND_SEND_ENABLED: 'true',
  ARC_RESEND_WEBHOOK_ENABLED: 'true',
  ARC_RESEND_API_KEY: 're_worker_test_key_0123456789abcdef',
  ARC_RESEND_WEBHOOK_SECRET: `whsec_${Buffer.alloc(32, 19).toString('base64')}`,
  ARC_RESEND_FROM: 'ARC <preview@send.arcweb.onl>',
  ARC_RESEND_PROVIDER_ACCOUNT_ID: 'resend-account-arc-production',
  ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET: 'worker-provider-binding-secret-0123456789',
  ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED: 'true',
  ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED: 'true',
  ARC_EMAIL_CLAIM_BINDING_SECRET: 'worker-email-claim-binding-secret-0123456789',
  ARC_FINAL_DELIVERY_RECEIPT_SECRET: 'worker-final-delivery-receipt-secret-012345',
  ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET: 'worker-negative-state-secret-0123456789abcdef',
  ARC_CLAIM_TOKEN_SECRET: 'worker-claim-token-secret-0123456789abcdef',
};

const allChannels = {
  intake_enabled: true,
  preview_review_enabled: true,
  claim_invitation_enabled: true,
  final_delivery_enabled: true,
};
for (let minute = 0; minute < 4; minute += 1) {
  const order = transactionalEmailChannelOrder(new Date(minute * 60_000), allChannels);
  assert.equal(order[0], ['intake_confirmation', 'preview_review', 'claim_invitation', 'final_delivery'][minute]);
  assert.equal(new Set(order).size, 4);
}

for (const relative of [
  '../netlify/lib/transactional-email-worker-core.mjs',
  '../netlify/lib/review-email-resend-core.mjs',
]) {
  const source = await readFile(new URL(relative, import.meta.url), 'utf8');
  assert.ok(source.lastIndexOf('await sealTransactionalEmailAttemptContext') > 0 &&
    source.lastIndexOf('await sendResendTransactionalEmail') >
      source.lastIndexOf('await sealTransactionalEmailAttemptContext'),
  `${relative} must strong-readback encrypted attempt context before calling the provider.`);
}

const disabledStores = new Proxy({}, { get() { throw new Error('disabled ARC2 worker touched storage'); } });
assert.deepEqual(await runArc2TransactionalEmailWorkerCycle('claim_invitation', {
  ...env,
  ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED: 'false',
}, disabledStores), { state: 'DISABLED', processed: 0, channel: 'claim_invitation' });

function job(kind, suffix) {
  const recipient = `${kind.replaceAll('_', '-')}@example.test`;
  const handoffId = suffix.repeat(64);
  const jobKey = ((Number.parseInt(suffix, 16) + 1) % 16).toString(16).repeat(64);
  const base = {
    kind,
    handoff_id: handoffId,
    job_key: jobKey,
    recipient_email: recipient,
    recipient_email_sha256: sha256(recipient),
    source_invite_hmac_sha256: 'e'.repeat(64),
    capsule_expires_at: expiresAt,
  };
  return kind === 'claim_invitation'
    ? { ...base, claim_url: `https://arcweb.onl/claim/#arc2.${handoffId}.${'q'.repeat(43)}` }
    : {
      ...base,
      production_url: 'https://customer-site.netlify.app/',
      final_authority: {
        handoff_id: handoffId,
        job_key: jobKey,
        recipient_email_sha256: sha256(recipient),
        production_url: 'https://customer-site.netlify.app/',
        production_url_sha256: sha256('https://customer-site.netlify.app/'),
        netlify_site_id_sha256: '1'.repeat(64),
        netlify_deploy_id_sha256: '2'.repeat(64),
        final_deploy_ready_at: new Date(now.getTime() - 60_000).toISOString(),
        authorized_at: now.toISOString(),
        claim_state_evidence_sha256: '3'.repeat(64),
      },
    };
}

function workerAdapters(preparedJob, providerId, controls = {}) {
  return {
    clock: () => now,
    randomBytes: (() => {
      let counter = 0;
      return () => Buffer.alloc(12, ++counter);
    })(),
    discoverNextClaimInvitationEmail: async (_store, _env, adapters) =>
      adapters.skip_handoff_ids.has(preparedJob.handoff_id)
        ? { found: false }
        : { found: true, kind: preparedJob.kind, handoff_id: preparedJob.handoff_id,
          job_key: preparedJob.job_key },
    discoverNextFinalDeliveryEmail: async (_store, _env, adapters) =>
      adapters.skip_handoff_ids.has(preparedJob.handoff_id)
        ? { found: false }
        : { found: true, kind: preparedJob.kind, handoff_id: preparedJob.handoff_id,
          job_key: preparedJob.job_key },
    prepareClaimInvitationEmailJob: async () => {
      controls.prepare_count = (controls.prepare_count || 0) + 1;
      if (controls.prepare_error && controls.prepare_count === 2) throw controls.prepare_error;
      return controls.refreshed_job && controls.prepare_count === 2
        ? controls.refreshed_job : preparedJob;
    },
    prepareFinalDeliveryEmailJob: async () => {
      controls.prepare_count = (controls.prepare_count || 0) + 1;
      if (controls.prepare_error && controls.prepare_count === 2) throw controls.prepare_error;
      return controls.refreshed_job && controls.prepare_count === 2
        ? controls.refreshed_job : preparedJob;
    },
    sendResendTransactionalEmail: async (_message, _key, _env, _adapters) => {
      controls.send_count = (controls.send_count || 0) + 1;
      assert.ok([...controls.vault.values.keys()].some((key) => key.startsWith('capsules/')),
        'Attempt context must be durable before the provider request.');
      return { provider: 'resend', provider_message_id: providerId, accepted_at: now.toISOString() };
    },
    ...(controls.mark ? { markEmailProviderAccepted: controls.mark } : {}),
  };
}

const claimJob = job('claim_invitation', 'a');
const claimStores = { ledger: new FakeStore(), review: new FakeStore(),
  attempt: new FakeStore(), vault: new FakeStore() };
const claimControls = { vault: claimStores.vault, send_count: 0 };
const claimAdapters = workerAdapters(claimJob, '11111111-2222-4333-8444-555555555555', claimControls);
assert.deepEqual(await runArc2TransactionalEmailWorkerCycle('claim_invitation', env,
  claimStores, claimAdapters), {
  state: 'PROVIDER_ACCEPTED', processed: 1, channel: 'claim_invitation', idempotent_replay: false,
});
assert.equal(claimControls.send_count, 1);
assert.equal(claimControls.prepare_count, 2,
  'Claim invitation must refresh its authority immediately before the provider request.');
const claimAttempt = await readEmailSendAttempt(claimStores.attempt, {
  job_kind: 'claim_invitation', job_key: claimJob.job_key,
}, env);
const claimContext = await openArc2EmailAttemptContext(claimStores.vault, {
  job_kind: 'claim_invitation', attempt_hmac_sha256: claimAttempt.attempt_hmac_sha256,
}, env, { clock: () => now });
assert.equal(claimContext.handoff_id, claimJob.handoff_id);
assert.doesNotMatch(JSON.stringify([...claimStores.vault.values.values()]), /claim-invitation@example\.test|q{43}/);
assert.doesNotMatch(JSON.stringify([...claimStores.attempt.values.values()]), /claim-invitation@example\.test/);
assert.equal((await runArc2TransactionalEmailWorkerCycle('claim_invitation', env,
  claimStores, claimAdapters)).state, 'WAITING_WEBHOOK');
assert.equal(claimControls.send_count, 1, 'Provider-accepted claim work must not resend or starve a scan forever.');

const haltedClaimJob = job('claim_invitation', 'e');
const haltedClaimStores = { ledger: new FakeStore(), review: new FakeStore(),
  attempt: new FakeStore(), vault: new FakeStore() };
const haltedClaimControls = {
  vault: haltedClaimStores.vault,
  send_count: 0,
  prepare_error: new Error('ARC_PAYMENT_ARC2_REVIEW_REQUIRED'),
};
await assert.rejects(runArc2TransactionalEmailWorkerCycle('claim_invitation', env, haltedClaimStores,
  workerAdapters(haltedClaimJob, '66666666-7777-4888-8999-000000000000', haltedClaimControls)),
/ARC_PAYMENT_ARC2_REVIEW_REQUIRED/,
'A review revocation recorded after initial preparation must stop the claim Resend POST.');
assert.equal(haltedClaimControls.prepare_count, 2);
assert.equal(haltedClaimControls.send_count, 0);

const crashJob = job('claim_invitation', 'b');
const crashStores = { ledger: new FakeStore(), review: new FakeStore(),
  attempt: new FakeStore(), vault: new FakeStore() };
let failMark = true;
const crashControls = {
  vault: crashStores.vault,
  send_count: 0,
  mark: async (...args) => {
    if (failMark) { failMark = false; throw new Error('synthetic acceptance-latch crash'); }
    return markEmailProviderAccepted(...args);
  },
};
const crashAdapters = workerAdapters(crashJob, '22222222-3333-4444-8555-666666666666', crashControls);
await assert.rejects(runArc2TransactionalEmailWorkerCycle('claim_invitation', env,
  crashStores, crashAdapters), /synthetic acceptance-latch crash/);
assert.equal(crashControls.send_count, 1);
const recovered = await runArc2TransactionalEmailWorkerCycle('claim_invitation', env,
  crashStores, crashAdapters);
assert.equal(recovered.state, 'PROVIDER_ACCEPTED');
assert.equal(recovered.idempotent_replay, true);
assert.equal(crashControls.send_count, 1,
  'A crash after provider acceptance must recover the encrypted capsule without another request.');

const finalJob = job('final_delivery', 'c');
const finalStores = { ledger: new FakeStore(), review: new FakeStore(),
  attempt: new FakeStore(), vault: new FakeStore() };
const finalControls = { vault: finalStores.vault, send_count: 0 };
const finalAdapters = workerAdapters(finalJob, '33333333-4444-4555-8666-777777777777', finalControls);
await runArc2TransactionalEmailWorkerCycle('final_delivery', env, finalStores, finalAdapters);
assert.equal(finalControls.prepare_count, 2,
  'Final delivery must refresh its authority immediately before the provider request.');
const finalAttempt = await readEmailSendAttempt(finalStores.attempt, {
  job_kind: 'final_delivery', job_key: finalJob.job_key,
}, env);
const finalAuthority = {
  handoff_id: finalJob.handoff_id,
  job_key: finalJob.job_key,
  recipient_email_sha256: finalJob.recipient_email_sha256,
  production_url: finalJob.production_url,
  production_url_sha256: sha256(finalJob.production_url),
  netlify_site_id_sha256: '1'.repeat(64),
  netlify_deploy_id_sha256: '2'.repeat(64),
  final_deploy_ready_at: new Date(now.getTime() - 60_000).toISOString(),
  authorized_at: now.toISOString(),
  claim_state_evidence_sha256: '3'.repeat(64),
};

const haltedFinalJob = job('final_delivery', 'd');
const haltedFinalStores = { ledger: new FakeStore(), review: new FakeStore(),
  attempt: new FakeStore(), vault: new FakeStore() };
const haltedFinalControls = {
  vault: haltedFinalStores.vault,
  send_count: 0,
  prepare_error: new Error('ARC_STRIPE_REVERSAL_HALT'),
};
await assert.rejects(runArc2TransactionalEmailWorkerCycle('final_delivery', env, haltedFinalStores,
  workerAdapters(haltedFinalJob, '44444444-5555-4666-8777-888888888888', haltedFinalControls)),
/ARC_STRIPE_REVERSAL_HALT/,
'A reversal recorded after initial preparation must stop the final Resend POST.');
assert.equal(haltedFinalControls.prepare_count, 2);
assert.equal(haltedFinalControls.send_count, 0);

const changedFinalJob = job('final_delivery', '9');
const changedFinalStores = { ledger: new FakeStore(), review: new FakeStore(),
  attempt: new FakeStore(), vault: new FakeStore() };
const changedFinalControls = {
  vault: changedFinalStores.vault,
  send_count: 0,
  refreshed_job: {
    ...changedFinalJob,
    production_url: 'https://changed-customer-site.netlify.app/',
  },
};
await assert.rejects(runArc2TransactionalEmailWorkerCycle('final_delivery', env, changedFinalStores,
  workerAdapters(changedFinalJob, '77777777-8888-4999-8000-111111111111', changedFinalControls)),
/ARC2_EMAIL_SEND_AUTHORITY_CHANGED/,
'A changed delivery URL or rendered message after reservation must stop the provider POST.');
assert.equal(changedFinalControls.send_count, 0);

const staleFinalJob = job('final_delivery', 'f');
const staleFinalStores = { ledger: new FakeStore(), review: new FakeStore(),
  attempt: new FakeStore(), vault: new FakeStore() };
let staleClock = new Date(now);
const staleFinalControls = { vault: staleFinalStores.vault, send_count: 0 };
const staleFinalAdapters = workerAdapters(
  staleFinalJob, '55555555-6666-4777-8888-999999999999', staleFinalControls,
);
staleFinalAdapters.clock = () => staleClock;
staleFinalAdapters.prepareFinalDeliveryEmailJob = async () => {
  staleFinalControls.prepare_count = (staleFinalControls.prepare_count || 0) + 1;
  if (staleFinalControls.prepare_count === 2) {
    staleClock = new Date(now.getTime() + 60_001);
  }
  return staleFinalJob;
};
await assert.rejects(runArc2TransactionalEmailWorkerCycle('final_delivery', env, staleFinalStores,
  staleFinalAdapters), /ARC2_FINAL_DELIVERY_EMAIL_AUTHORITY_STALE/,
'A frozen cycle clock cannot extend final-delivery authority past one minute.');
assert.equal(staleFinalControls.send_count, 0);
let finalPrepareCount = 0;
let finalAckCount = 0;
let firstEvidence = null;
const finalEventAdapters = {
  clock: () => now,
  randomBytes: () => Buffer.alloc(12, 41),
  prepareFinalDeliveryEmailJob: async () => {
    finalPrepareCount += 1;
    return { ...finalJob, final_authority: finalAuthority };
  },
  acknowledgeFinalDelivery: async (handoffId, evidence, signature) => {
    finalAckCount += 1;
    assert.equal(handoffId, finalJob.handoff_id);
    assert.match(signature, /^[a-f0-9]{64}$/);
    if (firstEvidence === null) firstEvidence = evidence;
    else assert.equal(evidence, firstEvidence, 'Webhook replay must reuse the exact sealed final receipt.');
    return { handoffId, idempotentReplay: finalAckCount > 1 };
  },
};
const deliveredVerified = {
  provider: 'resend',
  provider_event_id: 'evt-final-delivered-1',
  provider_message_id: '33333333-4444-4555-8666-777777777777',
  event_type: 'email.delivered',
  occurred_at: new Date(now.getTime() - 1_000).toISOString(),
  payload_sha256: '4'.repeat(64),
  supported_event: true,
};
const reconcileFinal = () => reconcileVerifiedResendWebhook(deliveredVerified,
  finalStores.attempt, env, {
    onArc2Event: (event) => reconcileArc2TransactionalEmailEvent(finalStores, event, env, finalEventAdapters),
  });
assert.equal((await reconcileFinal()).state, 'DELIVERED');
assert.equal(finalAckCount, 1);
assert.equal((await reconcileFinal()).idempotent_replay, true);
assert.equal(finalAckCount, 2);
assert.equal(finalPrepareCount, 1,
  'A replay after final acknowledgement must recover the sealed receipt without refreshing send authority.');

let claimFinalAckCalled = false;
const claimDelivered = await reconcileVerifiedResendWebhook({
  ...deliveredVerified,
  provider_event_id: 'evt-claim-delivered-1',
  provider_message_id: '11111111-2222-4333-8444-555555555555',
  payload_sha256: '5'.repeat(64),
}, claimStores.attempt, env, {
  onArc2Event: (event) => reconcileArc2TransactionalEmailEvent(claimStores, event, env, {
    clock: () => now,
    acknowledgeFinalDelivery: async () => { claimFinalAckCalled = true; },
  }),
});
assert.equal(claimDelivered.state, 'DELIVERED');
assert.equal(claimFinalAckCalled, false, 'Claim invitation delivery must never acknowledge final delivery.');

console.log('ARC2 shared transactional worker fairness, crash/replay, and webhook bridge contract passed.');
