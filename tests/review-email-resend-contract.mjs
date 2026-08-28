import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import prepareHandler from '../netlify/functions/review-email-prepare.mjs';
import {
  pruneTerminalEmailSendAttempts,
} from '../netlify/lib/email-send-attempt-core.mjs';
import {
  EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA,
  pruneExpiredEmailRecipientCapsules,
  sealEmailRecipientCapsule,
  validateEmailRecipientVaultTombstone,
} from '../netlify/lib/email-recipient-vault-core.mjs';
import { readReviewEmailOutbox, reviewEmailRecipientSha256 } from '../netlify/lib/review-email-outbox-core.mjs';
import {
  acknowledgePreviewReviewResendEvent,
  previewReviewResendWorkerConfiguration,
  runPreviewReviewResendWorkerCycle,
} from '../netlify/lib/review-email-resend-core.mjs';
import { readReviewInviteForEmail } from '../netlify/lib/review-flow-core.mjs';
import {
  verifyAndNormalizeResendWebhook,
} from '../netlify/lib/resend-transactional-provider-core.mjs';
import { reconcileVerifiedResendWebhook } from '../netlify/lib/resend-webhook-core.mjs';
import { signReviewEmailInternalRequest } from '../netlify/lib/review-email-http-core.mjs';

class FakeStore {
  constructor() {
    this.values = new Map();
    this.sequence = 0;
    this.failProviderIndexOnce = false;
  }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && (!current || current.etag !== options.onlyIfMatch)) return { modified: false };
    if (this.failProviderIndexOnce && key.startsWith('provider-messages/resend/')) {
      this.failProviderIndexOnce = false;
      throw new Error('synthetic preview provider-index crash');
    }
    const etag = `review-resend-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
  async delete(key) { this.values.delete(key); }
  async list(options = {}) {
    return { blobs: [...this.values.keys()].filter((key) => key.startsWith(options.prefix || ''))
      .sort().map((key) => ({ key })) };
  }
}

const sha = (character) => character.repeat(64);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const liveVaultCapsules = (store) => [...store.values.entries()].filter(([key, entry]) =>
  key.startsWith('capsules/') && entry.data.schema !== EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA);
const now = new Date('2026-08-27T23:00:00.000Z');
const webhookKey = Buffer.alloc(32, 19);
const env = {
  ARC_REVIEW_PORTAL_ENABLED: 'true',
  ARC_REVIEW_CHECKOUT_ENABLED: 'false',
  ARC_REVIEW_INVITE_HMAC_SECRET: 'resend-review-invite-secret-unique-0123456789',
  ARC_REVIEW_SESSION_HMAC_SECRET: 'resend-review-session-secret-unique-0123456789',
  ARC_REVIEW_RECORD_HMAC_SECRET: 'resend-review-record-secret-unique-0123456789',
  ARC_REVIEW_DECISION_HMAC_SECRET: 'resend-review-decision-secret-unique-0123456789',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
  ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
  ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET: 'resend-review-outbox-secret-unique-0123456789',
  ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET: 'resend-review-receipt-secret-unique-0123456789',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
  ARC_REVIEW_EMAIL_INTERNAL_API_ENABLED: 'true',
  ARC_REVIEW_EMAIL_INTERNAL_API_SECRET: 'resend-review-internal-secret-unique-0123456789',
  ARC_REVIEW_EMAIL_RESEND_CAPSULE_ENABLED: 'true',
  ARC_REVIEW_EMAIL_RESEND_WORKER_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET: 'resend-attempt-secret-unique-0123456789012345',
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY: Buffer.alloc(32, 23).toString('base64url'),
  ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET: 'resend-vault-secret-unique-012345678901234567',
  ARC_RESEND_SEND_ENABLED: 'true',
  ARC_RESEND_WEBHOOK_ENABLED: 'true',
  ARC_RESEND_API_KEY: 're_0123456789abcdefghijklmnopqrstuvwxyz',
  ARC_RESEND_WEBHOOK_SECRET: `whsec_${webhookKey.toString('base64')}`,
  ARC_RESEND_FROM: 'ARC Web <previews@arcweb.onl>',
  ARC_RESEND_PROVIDER_ACCOUNT_ID: 'resend-account-arc-production',
  ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET: 'resend-provider-binding-secret-unique-01234567',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'resend-retention-fence-secret-unique-012345678901',
  ARC_STRIPE_REVIEW_REVOCATION_ENABLED: 'false',
};

const retentionFenceStore = new FakeStore();

function invite(token, recipientEmail, marker = '1') {
  return {
    invite_token: token,
    brief_sha256: sha(marker),
    expires_at: new Date(now.getTime() + 7 * 24 * 60 * 60_000).toISOString(),
    page_bindings: [
      'about/index.html', 'contact/index.html', 'index.html', 'process/index.html', 'services/index.html',
    ].map((path, index) => ({ path, sha256: String(index + 2).repeat(64) })),
    preview_content_sha256: sha(marker === 'f' ? 'e' : '7'),
    preview_manifest_sha256: sha(marker === 'f' ? 'd' : '8'),
    preview_source_commit_sha: marker.repeat(40),
    preview_source_repository: 'arcwebhq-cpu/arc-previews',
    preview_url: `https://arcwebhq-cpu.github.io/arc-previews/resend-${marker}/`,
    prior_invite_hmac_sha256: null,
    recipient_email_sha256: reviewEmailRecipientSha256(recipientEmail),
    scope_version: 'arc-fixed-five-page-offer-v1',
  };
}

function signedPrepareRequest(value, at = now) {
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

async function prepare(reviewStore, vaultStore, token, email, marker = '1') {
  const input = invite(token, email, marker);
  const response = await prepareHandler(signedPrepareRequest({ invite: input, recipient_email: email }), {
    reviewStore, vaultStore, retentionFenceStore, clock: () => new Date(now),
    retentionFenceClock: () => new Date(now),
    randomBytes: () => Buffer.alloc(12, marker.charCodeAt(0)),
  });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.capsule_sealed, true);
  return { input, result };
}

let providerSequence = 0;
function providerFetch(counter) {
  return async (_url, options) => {
    counter.count += 1;
    assert.match(options.headers['Idempotency-Key'], /^arc_review_email_[a-f0-9]{64}$/);
    const body = JSON.parse(options.body);
    assert.equal(body.to.length, 1);
    assert.match(body.html, /Review your preview/);
    const tail = (++providerSequence).toString(16).padStart(12, '0');
    return new Response(JSON.stringify({ id: `11111111-2222-4333-8444-${tail}` }), { status: 200 });
  };
}

function signedWebhook(type, providerMessageId, eventId, at) {
  const raw = JSON.stringify({
    created_at: at.toISOString(),
    data: { email_id: providerMessageId, from: env.ARC_RESEND_FROM,
      to: ['redacted-by-test@example.test'], subject: 'Your free website preview is ready' },
    type,
  });
  const timestamp = String(Math.floor(at.getTime() / 1000));
  const signature = createHmac('sha256', webhookKey)
    .update(`${eventId}.${timestamp}.`).update(raw).digest('base64');
  const headers = new Headers({
    'svix-id': eventId,
    'svix-timestamp': timestamp,
    'svix-signature': `v1,${signature}`,
  });
  return verifyAndNormalizeResendWebhook(raw, headers, env, { clock: () => at });
}

async function reconcile(verified, stores, at, callback = null) {
  return reconcileVerifiedResendWebhook(verified, stores.attempt, env, {
    onPreviewReviewEvent: callback || ((event) => acknowledgePreviewReviewResendEvent(
      stores.review, event, env, { clock: () => at, vaultStore: stores.vault })),
  });
}

const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
Object.assign(process.env, env);
try {
  assert.equal(previewReviewResendWorkerConfiguration({
    ...env,
    ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET: env.ARC_REVIEW_INVITE_HMAC_SECRET,
  }).enabled, false, 'Provider binding authority must not reuse any review token-authority secret.');
  const disabledStores = new Proxy({}, { get() { throw new Error('disabled review worker touched stores'); } });
  assert.deepEqual(await runPreviewReviewResendWorkerCycle({
    ...env, ARC_REVIEW_EMAIL_RESEND_WORKER_ENABLED: 'false',
  }, disabledStores), { state: 'DISABLED', processed: 0, channel: 'preview_review' });

  const stores = { review: new FakeStore(), vault: new FakeStore(), attempt: new FakeStore() };
  const email = 'preview-owner@example.test';
  const token = 'R'.repeat(43);
  const prepared = await prepare(stores.review, stores.vault, token, email);
  assert.equal(JSON.stringify(prepared.result).includes(token), false);
  assert.equal(JSON.stringify(prepared.result).includes(email), false);
  const durableBeforeSend = JSON.stringify([
    ...stores.review.values.values(), ...stores.vault.values.values(),
  ]);
  assert.doesNotMatch(durableBeforeSend, new RegExp(email.replace('.', '\\.')));
  assert.doesNotMatch(durableBeforeSend, new RegExp(token));
  assert.doesNotMatch(durableBeforeSend, /#invite=/);

  const sends = { count: 0 };
  const worker = () => runPreviewReviewResendWorkerCycle(env, stores, {
    clock: () => new Date(now), fetch: providerFetch(sends), randomBytes: () => Buffer.alloc(12, 31),
  });
  assert.equal((await worker()).state, 'PROVIDER_ACCEPTED');
  assert.equal(sends.count, 1);
  assert.equal((await worker()).idempotent_replay, true);
  assert.equal(sends.count, 1, 'Provider acceptance must be a durable no-resend boundary.');
  const providerMessageId = `11111111-2222-4333-8444-${providerSequence.toString(16).padStart(12, '0')}`;
  assert.doesNotMatch(JSON.stringify([...stores.attempt.values.values()]), /preview-owner|#invite=|11111111-2222/);
  assert.doesNotMatch(JSON.stringify([...stores.vault.values.values()]), /preview-owner|#invite=|11111111-2222/);

  const sentAt = new Date(now.getTime() + 1_000);
  const sent = signedWebhook('email.sent', providerMessageId, 'evt_review_sent', sentAt);
  assert.equal((await reconcile(sent, stores, sentAt)).unlock_delivery, false);
  assert.equal((await readReviewInviteForEmail(stores.review,
    prepared.result.invite_hmac_sha256, env)).record.email_delivery_receipt_sha256, null);

  const deliveryAt = new Date(now.getTime() + 2_000);
  const delivered = signedWebhook('email.delivered', providerMessageId, 'evt_review_delivered', deliveryAt);
  let crashBeforeAck = true;
  await assert.rejects(reconcile(delivered, stores, deliveryAt, async (event) => {
    if (crashBeforeAck) {
      crashBeforeAck = false;
      throw new Error('synthetic crash after provider event latch');
    }
    return acknowledgePreviewReviewResendEvent(stores.review, event, env, {
      clock: () => deliveryAt, vaultStore: stores.vault,
    });
  }), /synthetic crash/);
  assert.equal((await readReviewInviteForEmail(stores.review,
    prepared.result.invite_hmac_sha256, env)).record.email_delivery_receipt_sha256, null);
  assert.equal((await reconcile(delivered, stores, deliveryAt)).unlock_delivery, true,
    'Exact signed webhook retry must converge the review acknowledgement.');
  const deliveredInvite = await readReviewInviteForEmail(stores.review,
    prepared.result.invite_hmac_sha256, env);
  assert.match(deliveredInvite.record.email_delivery_receipt_sha256, /^[a-f0-9]{64}$/);
  assert.equal((await readReviewEmailOutbox(stores.review,
    prepared.result.outbox_hmac_sha256, env)).record.state, 'DELIVERED');
  assert.equal(liveVaultCapsules(stores.vault).length, 1,
    'Delivered review must retain only the encrypted paid-handoff recipient capsule.');

  const complaintAt = new Date(now.getTime() + 3_000);
  const complained = signedWebhook('email.complained', providerMessageId, 'evt_review_complained', complaintAt);
  assert.equal((await reconcile(complained, stores, complaintAt)).state, 'COMPLAINED');
  assert.equal((await readReviewEmailOutbox(stores.review,
    prepared.result.outbox_hmac_sha256, env)).record.state, 'COMPLAINED');
  assert.equal((await readReviewInviteForEmail(stores.review,
    prepared.result.invite_hmac_sha256, env)).record.state, 'REVOKED');
  assert.equal(liveVaultCapsules(stores.vault).length, 0,
    'A later complaint must revoke checkout and remove the retained recipient capsule.');
  for (const [key, entry] of [...stores.vault.values.entries()].filter(([key]) => key.startsWith('capsules/'))) {
    validateEmailRecipientVaultTombstone(entry.data, key, env);
    assert.equal(entry.data.customer_data_stored, false);
  }
  let lateDeliveryCallbacks = 0;
  const lateAt = new Date(now.getTime() + 4_000);
  const lateDelivery = signedWebhook('email.delivered', providerMessageId, 'evt_review_late_delivery', lateAt);
  assert.equal((await reconcile(lateDelivery, stores, lateAt, async () => {
    lateDeliveryCallbacks += 1;
  })).unlock_delivery, false);
  assert.equal(lateDeliveryCallbacks, 0, 'Delivery after complaint must never reopen review.');
  const attemptSnapshot = structuredClone([...stores.attempt.values.entries()]);
  await assert.rejects(pruneTerminalEmailSendAttempts(stores.attempt, {
    ...env,
    ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED: 'true',
    ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS: '30',
  }, { clock: () => new Date(now.getTime() + 31 * 24 * 60 * 60_000) }),
  /ARC_EMAIL_ATTEMPT_RETENTION_PRUNE_RETIRED_USE_FROZEN_SWEEP/);
  assert.deepEqual([...stores.attempt.values.entries()], attemptSnapshot,
    'The retired direct prune API must never mutate outside FROZEN.');

  const suppressionStores = { review: new FakeStore(), vault: new FakeStore(), attempt: new FakeStore() };
  const suppressionPrepared = await prepare(suppressionStores.review, suppressionStores.vault,
    'S'.repeat(43), 'suppressed-owner@example.test', 'f');
  const suppressionSends = { count: 0 };
  await runPreviewReviewResendWorkerCycle(env, suppressionStores, {
    clock: () => new Date(now), fetch: providerFetch(suppressionSends), randomBytes: () => Buffer.alloc(12, 37),
  });
  const suppressionMessageId = `11111111-2222-4333-8444-${providerSequence.toString(16).padStart(12, '0')}`;
  const suppressionAt = new Date(now.getTime() + 5_000);
  const suppressed = signedWebhook('email.suppressed', suppressionMessageId,
    'evt_review_suppressed', suppressionAt);
  assert.equal((await reconcile(suppressed, suppressionStores, suppressionAt)).state, 'SUPPRESSED');
  assert.equal((await readReviewEmailOutbox(suppressionStores.review,
    suppressionPrepared.result.outbox_hmac_sha256, env)).record.state, 'BOUNCED',
  'Native provider suppression must project to the review domain fail-closed suppression state.');
  assert.equal((await readReviewInviteForEmail(suppressionStores.review,
    suppressionPrepared.result.invite_hmac_sha256, env)).record.state, 'REVOKED');

  const failedStores = { review: new FakeStore(), vault: new FakeStore(), attempt: new FakeStore() };
  const failedPrepared = await prepare(failedStores.review, failedStores.vault,
    'D'.repeat(43), 'failed-owner@example.test', 'd');
  const failedSends = { count: 0 };
  await runPreviewReviewResendWorkerCycle(env, failedStores, {
    clock: () => new Date(now), fetch: providerFetch(failedSends), randomBytes: () => Buffer.alloc(12, 39),
  });
  const failedMessageId = `11111111-2222-4333-8444-${providerSequence.toString(16).padStart(12, '0')}`;
  const failedAt = new Date(now.getTime() + 6_000);
  const failed = signedWebhook('email.failed', failedMessageId, 'evt_review_failed', failedAt);
  assert.equal((await reconcile(failed, failedStores, failedAt)).state, 'FAILED');
  assert.equal((await readReviewEmailOutbox(failedStores.review,
    failedPrepared.result.outbox_hmac_sha256, env)).record.state, 'BOUNCED',
  'Native provider failure must terminalize review as a fail-closed delivery suppression.');
  assert.equal((await readReviewInviteForEmail(failedStores.review,
    failedPrepared.result.invite_hmac_sha256, env)).record.state, 'REVOKED');

  const crashStores = { review: new FakeStore(), vault: new FakeStore(), attempt: new FakeStore() };
  await prepare(crashStores.review, crashStores.vault,
    'C'.repeat(43), 'crash-owner@example.test', 'c');
  crashStores.attempt.failProviderIndexOnce = true;
  const crashSends = { count: 0 };
  const crashWorker = () => runPreviewReviewResendWorkerCycle(env, crashStores, {
    clock: () => new Date(now), fetch: providerFetch(crashSends), randomBytes: () => Buffer.alloc(12, 41),
  });
  await assert.rejects(crashWorker(), /provider-index crash|MESSAGE_INDEX_UNAVAILABLE/);
  assert.equal(crashSends.count, 1);
  assert.equal((await crashWorker()).idempotent_replay, true);
  assert.equal(crashSends.count, 1,
    'Encrypted provider acceptance recovery must prevent a second Resend call after an acceptance-latch crash.');

  const expiryVault = new FakeStore();
  await sealEmailRecipientCapsule(expiryVault, {
    job_kind: 'operations_alert',
    job_key: 'expired-review-resend-capsule',
    recipient_email: 'operations@example.test',
    private_payload: { alert: 'digest-only-test' },
    expires_at: new Date(now.getTime() + 1_000).toISOString(),
  }, env, { clock: () => now, randomBytes: () => Buffer.alloc(12, 43) });
  const expirySnapshot = structuredClone([...expiryVault.values.entries()]);
  await assert.rejects(pruneExpiredEmailRecipientCapsules(expiryVault, env, {
    clock: () => new Date(now.getTime() + 2_000),
  }), /ARC_EMAIL_VAULT_RETENTION_PRUNE_RETIRED_USE_FROZEN_SWEEP/);
  assert.equal(expiryVault.values.size, 1);
  assert.deepEqual([...expiryVault.values.entries()], expirySnapshot,
    'The retired direct vault prune API must never mutate outside FROZEN.');
} finally {
  for (const key of Object.keys(env)) {
    if (previous[key] === undefined) delete process.env[key];
    else process.env[key] = previous[key];
  }
}

console.log('ARC native Resend preview/review capsule, worker, receipt, suppression, and replay contract passed.');
