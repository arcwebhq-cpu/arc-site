import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import prepareHandler from '../netlify/functions/review-email-prepare.mjs';
import {
  completePaidRecipientCapsuleHandoff,
  deletePaidPreviewRecipientCapsule,
  openPaidPreviewRecipientCapsule,
} from '../netlify/lib/arc2-transactional-email-core.mjs';
import {
  EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA,
  openEmailRecipientCapsule,
} from '../netlify/lib/email-recipient-vault-core.mjs';
import { reviewEmailRecipientSha256 } from '../netlify/lib/review-email-outbox-core.mjs';
import {
  acknowledgePreviewReviewResendEvent,
  runPreviewReviewResendWorkerCycle,
} from '../netlify/lib/review-email-resend-core.mjs';
import {
  decideReview,
  exchangeReviewInvite,
  readReviewInviteForEmail,
  readReviewStatus,
} from '../netlify/lib/review-flow-core.mjs';
import { signReviewEmailInternalRequest } from '../netlify/lib/review-email-http-core.mjs';
import { verifyAndNormalizeResendWebhook } from '../netlify/lib/resend-transactional-provider-core.mjs';
import { reconcileVerifiedResendWebhook } from '../netlify/lib/resend-webhook-core.mjs';

class FakeStore {
  constructor(label) {
    this.label = label;
    this.values = new Map();
    this.sequence = 0;
    this.failTombstoneOnce = false;
  }

  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }

  async setJSON(key, data, options = {}) {
    if (this.failTombstoneOnce && options.onlyIfMatch &&
        data?.schema === EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA) {
      this.failTombstoneOnce = false;
      throw new Error('synthetic source capsule cleanup crash');
    }
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && (!current || current.etag !== options.onlyIfMatch)) {
      return { modified: false };
    }
    const etag = `${this.label}-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }

  async delete(key) {
    if (this.failDeleteOnce) {
      this.failDeleteOnce = false;
      throw new Error('synthetic source capsule cleanup crash');
    }
    this.values.delete(key);
  }

  async list({ prefix = '' } = {}) {
    return {
      blobs: [...this.values.keys()].filter((key) => key.startsWith(prefix))
        .sort().map((key) => ({ key })),
    };
  }
}

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const now = new Date('2026-08-28T01:00:00.000Z');
const webhookKey = Buffer.alloc(32, 29);
const env = {
  ARC_REVIEW_PORTAL_ENABLED: 'true',
  ARC_REVIEW_CHECKOUT_ENABLED: 'true',
  ARC_REVIEW_INVITE_HMAC_SECRET: 'lifecycle-review-invite-secret-0123456789abcdef',
  ARC_REVIEW_SESSION_HMAC_SECRET: 'lifecycle-review-session-secret-0123456789abcdef',
  ARC_REVIEW_RECORD_HMAC_SECRET: 'lifecycle-review-record-secret-0123456789abcdef',
  ARC_REVIEW_DECISION_HMAC_SECRET: 'lifecycle-review-decision-secret-0123456789abcdef',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
  ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
  ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET: 'lifecycle-review-outbox-secret-0123456789abcdef',
  ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET: 'lifecycle-review-receipt-secret-0123456789abcdef',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
  ARC_REVIEW_EMAIL_INTERNAL_API_ENABLED: 'true',
  ARC_REVIEW_EMAIL_INTERNAL_API_SECRET: 'lifecycle-review-internal-secret-0123456789abcdef',
  ARC_REVIEW_EMAIL_RESEND_CAPSULE_ENABLED: 'true',
  ARC_REVIEW_EMAIL_RESEND_WORKER_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET: 'lifecycle-attempt-secret-0123456789abcdefghijkl',
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY: Buffer.alloc(32, 31).toString('base64url'),
  ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET: 'lifecycle-vault-hmac-secret-0123456789abcdefgh',
  ARC_RESEND_SEND_ENABLED: 'true',
  ARC_RESEND_WEBHOOK_ENABLED: 'true',
  ARC_RESEND_API_KEY: 're_0123456789abcdefghijklmnopqrstuvwxyz',
  ARC_RESEND_WEBHOOK_SECRET: `whsec_${webhookKey.toString('base64')}`,
  ARC_RESEND_FROM: 'ARC Web <previews@arcweb.onl>',
  ARC_RESEND_PROVIDER_ACCOUNT_ID: 'resend-account-arc-lifecycle',
  ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET: 'lifecycle-resend-binding-secret-0123456789abcd',
  ARC_STRIPE_REVIEW_REVOCATION_ENABLED: 'false',
  ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED: 'true',
  ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED: 'true',
  ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET: 'lifecycle-negative-email-state-secret-0123456789',
  ARC_EMAIL_CLAIM_BINDING_SECRET: 'lifecycle-claim-email-binding-secret-0123456789',
  ARC_FINAL_DELIVERY_RECEIPT_SECRET: 'lifecycle-final-receipt-secret-0123456789abcdef',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'lifecycle-retention-fence-secret-0123456789abcdef',
};

function invite(token, recipientEmail, marker) {
  return {
    invite_token: token,
    brief_sha256: sha256(`brief-${marker}`),
    expires_at: new Date(now.getTime() + 7 * 24 * 60 * 60_000).toISOString(),
    page_bindings: [
      'about/index.html', 'contact/index.html', 'index.html', 'process/index.html', 'services/index.html',
    ].map((path) => ({ path, sha256: sha256(`${marker}:${path}`) })),
    preview_content_sha256: sha256(`content-${marker}`),
    preview_manifest_sha256: sha256(`manifest-${marker}`),
    preview_source_commit_sha: marker.toLowerCase().repeat(40),
    preview_source_repository: 'arcwebhq-cpu/arc-previews',
    preview_url: `https://arcwebhq-cpu.github.io/arc-previews/lifecycle-${marker}/`,
    prior_invite_hmac_sha256: null,
    recipient_email_sha256: reviewEmailRecipientSha256(recipientEmail),
    scope_version: 'arc-fixed-five-page-offer-v1',
  };
}

function prepareRequest(value, at = now) {
  const body = JSON.stringify(value);
  const path = '/api/internal/review-email/prepare';
  const timestamp = at.toISOString();
  return new Request(`https://arcweb.onl${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-arc-review-email-signature': signReviewEmailInternalRequest({
        body, method: 'POST', path, timestamp,
      }, env.ARC_REVIEW_EMAIL_INTERNAL_API_SECRET),
      'x-arc-review-email-timestamp': timestamp,
    },
    body,
  });
}

async function prepare(stores, token, recipientEmail, marker) {
  const input = invite(token, recipientEmail, marker);
  const response = await prepareHandler(prepareRequest({ invite: input, recipient_email: recipientEmail }), {
    reviewStore: stores.review,
    vaultStore: stores.vault,
    retentionFenceStore: stores.fence,
    clock: () => new Date(now),
    randomBytes: () => Buffer.alloc(12, marker.charCodeAt(0)),
  });
  assert.equal(response.status, 200);
  return { input, result: await response.json() };
}

let providerSequence = 0;
function providerFetch(counter) {
  return async (_url, options) => {
    counter.count += 1;
    assert.match(options.headers['Idempotency-Key'], /^arc_review_email_[a-f0-9]{64}$/);
    const id = `11111111-2222-4333-8444-${(++providerSequence).toString(16).padStart(12, '0')}`;
    return new Response(JSON.stringify({ id }), { status: 200 });
  };
}

function signedWebhook(type, providerMessageId, providerEventId, at) {
  const raw = JSON.stringify({
    created_at: at.toISOString(),
    data: {
      email_id: providerMessageId,
      from: env.ARC_RESEND_FROM,
      to: ['redacted@example.test'],
      subject: 'Your free website preview is ready',
    },
    type,
  });
  const timestamp = String(Math.floor(at.getTime() / 1000));
  const signature = createHmac('sha256', webhookKey)
    .update(`${providerEventId}.${timestamp}.`).update(raw).digest('base64');
  return verifyAndNormalizeResendWebhook(raw, new Headers({
    'svix-id': providerEventId,
    'svix-timestamp': timestamp,
    'svix-signature': `v1,${signature}`,
  }), env, { clock: () => at });
}

async function send(stores, marker) {
  const sends = { count: 0 };
  const result = await runPreviewReviewResendWorkerCycle(env, stores, {
    clock: () => new Date(now),
    fetch: providerFetch(sends),
    randomBytes: () => Buffer.alloc(12, marker.charCodeAt(0) + 7),
  });
  assert.equal(result.state, 'PROVIDER_ACCEPTED');
  assert.equal(sends.count, 1);
  return `11111111-2222-4333-8444-${providerSequence.toString(16).padStart(12, '0')}`;
}

async function reconcile(stores, verified, at) {
  return reconcileVerifiedResendWebhook(verified, stores.attempt, env, {
    onPreviewReviewEvent: (event) => acknowledgePreviewReviewResendEvent(
      stores.review, event, env, { clock: () => at, vaultStore: stores.vault },
    ),
  });
}

function storeSet(prefix) {
  return {
    review: new FakeStore(`${prefix}-review`),
    vault: new FakeStore(`${prefix}-vault`),
    attempt: new FakeStore(`${prefix}-attempt`),
    bridge: new FakeStore(`${prefix}-bridge`),
    fence: new FakeStore(`${prefix}-fence`),
  };
}

const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
Object.assign(process.env, env);
try {
  const stores = storeSet('paid');
  const recipientEmail = 'paid-owner@example.test';
  const token = 'P'.repeat(43);
  const prepared = await prepare(stores, token, recipientEmail, 'a');
  const providerMessageId = await send(stores, 'a');
  const deliveredAt = new Date(now.getTime() + 2_000);
  const delivered = signedWebhook('email.delivered', providerMessageId,
    'evt_paid_lifecycle_delivered', deliveredAt);
  assert.equal((await reconcile(stores, delivered, deliveredAt)).unlock_delivery, true);

  const primary = await openEmailRecipientCapsule(stores.vault, {
    job_kind: 'preview_review', job_key: prepared.result.outbox_hmac_sha256,
  }, env, { clock: () => deliveredAt });
  assert.equal(primary.recipient_email, recipientEmail,
    'Signed delivery must retain the encrypted source capsule for the paid handoff.');

  const exchanged = await exchangeReviewInvite(stores.review, token, env, {
    clock: () => deliveredAt,
    randomBytes: () => Buffer.alloc(32, 41),
  });
  const status = await readReviewStatus(stores.review, exchanged.session_token, env, deliveredAt);
  await decideReview(stores.review, exchanged.session_token, {
    action: 'APPROVE_AND_PAY',
    expected_revision: status.record_revision,
    idempotency_key: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  }, env, { clock: () => deliveredAt });
  const source = await openPaidPreviewRecipientCapsule(stores.vault, stores.review, {
    invite_hmac_sha256: prepared.result.invite_hmac_sha256,
    recipient_email_sha256: reviewEmailRecipientSha256(recipientEmail),
  }, env, { clock: () => deliveredAt });

  const handoff = {
    handoff_id: 'd'.repeat(64),
    created_at: deliveredAt.toISOString(),
  };
  const paymentOutboxKey = `payment-arc2-start-outbox/${'e'.repeat(64)}`;
  const completionRecord = {
    state: 'COMPLETED',
    outbox_key: paymentOutboxKey,
    idempotent_replay: false,
    immutable_binding_sha256: 'f'.repeat(64),
    claim_attempt_count: 1,
    lease_expires_at: null,
    arc2_start_receipt_sha256: '1'.repeat(64),
  };
  let completionCalls = 0;
  const completePayment = async () => {
    for (const kind of ['claim_invitation', 'final_delivery']) {
      assert.equal((await openEmailRecipientCapsule(stores.vault, {
        job_kind: kind, job_key: handoff.handoff_id,
      }, env, { clock: () => deliveredAt })).recipient_email, recipientEmail,
      'Both downstream capsules must strong-read before durable payment completion.');
    }
    const existing = await stores.bridge.getWithMetadata(paymentOutboxKey);
    if (!existing) {
      await stores.bridge.setJSON(paymentOutboxKey, completionRecord, { onlyIfNew: true });
    }
    const durable = await stores.bridge.getWithMetadata(paymentOutboxKey);
    assert.equal(durable?.data.state, 'COMPLETED');
    completionCalls += 1;
    return { ...durable.data, idempotent_replay: completionCalls > 1 };
  };

  stores.vault.failTombstoneOnce = true;
  await assert.rejects(completePaidRecipientCapsuleHandoff(stores.vault, stores.review, {
    handoff, source,
  }, env, {
    clock: () => deliveredAt,
    randomBytes: () => Buffer.alloc(12, 43),
    completePaymentArc2StartOutbox: completePayment,
  }), /synthetic source capsule cleanup crash/);
  assert.equal((await stores.bridge.getWithMetadata(paymentOutboxKey)).data.state, 'COMPLETED',
    'The payment completion must remain durable across a cleanup crash.');
  assert.equal((await openEmailRecipientCapsule(stores.vault, {
    job_kind: 'preview_review', job_key: prepared.result.outbox_hmac_sha256,
  }, env, { clock: () => deliveredAt })).recipient_email, recipientEmail);

  const replay = await completePaidRecipientCapsuleHandoff(stores.vault, stores.review, {
    handoff, source,
  }, env, {
    clock: () => deliveredAt,
    completePaymentArc2StartOutbox: completePayment,
  });
  assert.equal(replay.completion.idempotent_replay, true);
  assert.equal(replay.cleanup.source_capsule_deleted, true);
  await assert.rejects(openEmailRecipientCapsule(stores.vault, {
    job_kind: 'preview_review', job_key: prepared.result.outbox_hmac_sha256,
  }, env, { clock: () => deliveredAt }), /VAULT_NOT_FOUND/);
  for (const kind of ['claim_invitation', 'final_delivery']) {
    assert.equal((await openEmailRecipientCapsule(stores.vault, {
      job_kind: kind, job_key: handoff.handoff_id,
    }, env, { clock: () => deliveredAt })).recipient_email, recipientEmail);
  }
  assert.equal((await deletePaidPreviewRecipientCapsule(stores.vault, stores.review, {
    invite_hmac_sha256: prepared.result.invite_hmac_sha256,
    recipient_email_sha256: reviewEmailRecipientSha256(recipientEmail),
  }, env)).idempotent_replay, true,
  'A completed-worker replay must converge after source cleanup without reopening the source.');

  for (const [index, eventType] of [
    'email.bounced', 'email.complained', 'email.failed', 'email.suppressed',
  ].entries()) {
    const negative = storeSet(`negative-${index}`);
    const marker = String.fromCharCode(98 + index);
    const negativeToken = marker.toUpperCase().repeat(43);
    const negativeEmail = `${marker}-owner@example.test`;
    const negativePrepared = await prepare(negative, negativeToken, negativeEmail, marker);
    const negativeMessageId = await send(negative, marker);
    const negativeAt = new Date(now.getTime() + 10_000 + index * 1_000);
    await reconcile(negative, signedWebhook(eventType, negativeMessageId,
      `evt_paid_lifecycle_${marker}`, negativeAt), negativeAt);
    await assert.rejects(openEmailRecipientCapsule(negative.vault, {
      job_kind: 'preview_review', job_key: negativePrepared.result.outbox_hmac_sha256,
    }, env, { clock: () => negativeAt }), /VAULT_NOT_FOUND/,
    `${eventType} must immediately erase the source capsule.`);
    await assert.rejects(exchangeReviewInvite(negative.review, negativeToken, env, {
      clock: () => negativeAt,
      randomBytes: () => Buffer.alloc(32, 51 + index),
    }), /SUPPRESSED|REVOKED/,
    `${eventType} must prevent review exchange and therefore payment.`);
    await assert.rejects(openPaidPreviewRecipientCapsule(negative.vault, negative.review, {
      invite_hmac_sha256: negativePrepared.result.invite_hmac_sha256,
      recipient_email_sha256: reviewEmailRecipientSha256(negativeEmail),
    }, env, { clock: () => negativeAt }), /AUTHORITY_INVALID|VAULT_NOT_FOUND/,
    `${eventType} must never supply paid recipient authority.`);
    assert.equal((await readReviewInviteForEmail(negative.review,
      negativePrepared.result.invite_hmac_sha256, env)).record.state, 'REVOKED');
  }
} finally {
  for (const key of Object.keys(env)) {
    if (previous[key] === undefined) delete process.env[key];
    else process.env[key] = previous[key];
  }
}

console.log('Paid recipient same-store prepare, Resend, delivery, ARC2 completion, cleanup, and negative-event contract passed.');
