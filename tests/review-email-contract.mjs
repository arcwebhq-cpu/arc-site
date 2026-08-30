import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import {
  acknowledgeReviewEmailReceipt,
  claimNextReviewEmail,
  prepareReviewInviteEmail,
  REVIEW_EMAIL_RECEIPT_FRESHNESS_MS,
  readReviewEmailOutbox,
  readReviewEmailRecipientSuppression,
  readReviewEmailRenewal,
  renewExpiredReadyReviewEmail,
  reserveReviewEmailSend,
  reviewEmailOutboxConfiguration,
  reviewEmailOutboxKey,
  reviewEmailReceiptContract,
  reviewEmailRecipientSha256,
} from '../netlify/lib/review-email-outbox-core.mjs';
import {
  createApprovedCheckout,
  decideReview,
  exchangeReviewInvite,
  issueReviewInvite,
  readReviewInviteForEmail,
  readReviewStatus,
  reviewInviteHmac,
  reviewInviteKey,
} from '../netlify/lib/review-flow-core.mjs';
import {
  acquireReviewEmailRecipientAuthority,
  readReviewEmailRecipientControl,
  suppressReviewEmailRecipientControl,
} from '../netlify/lib/review-email-recipient-control-core.mjs';

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const output = JSON.stringify(value);
  if (output === undefined) throw new TypeError('Canonical JSON does not support undefined.');
  return output;
}

const sha256Hex = value => createHash('sha256').update(value).digest('hex');
const hmacHex = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');

class FakeStore {
  constructor() {
    this.values = new Map();
    this.sequence = 0;
    this.writes = [];
    this.failures = [];
    this.readBarrier = null;
  }
  failNextPrefix(prefix) {
    this.failures.push(key => key.startsWith(prefix));
  }
  failNextKey(expected) {
    this.failures.push(key => key === expected);
  }
  pauseNextReadPrefix(prefix) {
    let signalReached;
    let releaseRead;
    const reached = new Promise(resolve => { signalReached = resolve; });
    const released = new Promise(resolve => { releaseRead = resolve; });
    this.readBarrier = { prefix, released, releaseRead, signalReached };
    return { reached, release: () => releaseRead() };
  }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    const snapshot = entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
    if (this.readBarrier && key.startsWith(this.readBarrier.prefix)) {
      const barrier = this.readBarrier;
      this.readBarrier = null;
      barrier.signalReached();
      await barrier.released;
    }
    return snapshot;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const failureIndex = this.failures.findIndex(match => match(key));
    if (failureIndex !== -1) {
      this.failures.splice(failureIndex, 1);
      throw new Error('SIMULATED_PROCESS_CRASH');
    }
    const etag = `email-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    this.writes.push({ key, options: structuredClone(options) });
    return { modified: true, etag };
  }
}

const now = new Date('2026-08-27T20:00:00.000Z');
const at = milliseconds => new Date(now.getTime() + milliseconds).toISOString();
const sha = character => character.repeat(64);
const env = {
  ARC_REVIEW_PORTAL_ENABLED: 'true',
  ARC_REVIEW_CHECKOUT_ENABLED: 'true',
  ARC_REVIEW_INVITE_HMAC_SECRET: 'review-invite-secret-unique-0123456789abcdef',
  ARC_REVIEW_SESSION_HMAC_SECRET: 'review-session-secret-unique-0123456789abcdef',
  ARC_REVIEW_RECORD_HMAC_SECRET: 'review-record-secret-unique-0123456789abcdef',
  ARC_REVIEW_DECISION_HMAC_SECRET: 'review-decision-secret-unique-0123456789abcdef',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
  ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
  ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET: 'review-email-outbox-secret-unique-0123456789abcdef',
  ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET: 'review-email-receipt-secret-unique-0123456789abcdef',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
};

function inviteFor(token, recipientEmail, overrides = {}) {
  return {
    invite_token: token,
    brief_sha256: sha('1'),
    expires_at: at(7 * 24 * 60 * 60_000),
    page_bindings: [
      ['about/index.html', sha('3')],
      ['contact/index.html', sha('4')],
      ['index.html', sha('5')],
      ['process/index.html', sha('6')],
      ['services/index.html', sha('7')],
    ].map(([path, sha256]) => ({ path, sha256 })),
    preview_content_sha256: sha('8'),
    preview_manifest_sha256: sha('9'),
    preview_source_commit_sha: 'a'.repeat(40),
    preview_source_repository: 'arcwebhq-cpu/arc-previews',
    preview_url: 'https://arcwebhq-cpu.github.io/arc-previews/sample-roofing-a1b2c3d4/',
    prior_invite_hmac_sha256: null,
    recipient_email_sha256: reviewEmailRecipientSha256(recipientEmail),
    scope_version: 'arc-fixed-five-page-offer-v1',
    ...overrides,
  };
}

function receiptFor(prepared, identity, status = 'delivered', overrides = {}) {
  return {
    schema: reviewEmailReceiptContract.schema,
    version: reviewEmailReceiptContract.version,
    outbox_hmac_sha256: prepared.outbox.outbox_hmac_sha256,
    invite_hmac_sha256: prepared.invite.invite_hmac_sha256,
    recipient_email_sha256: prepared.invite.recipient_email_sha256,
    preview_manifest_sha256: prepared.invite.preview_manifest_sha256,
    provider: 'provider-test',
    provider_account_hmac_sha256: sha('a'),
    provider_event_id: `event-${identity}`,
    provider_message_id: `message-${identity}`,
    event_type: `message.${status}`,
    delivery_status: status,
    event_at: at(1_000),
    issued_at: at(2_000),
    ...overrides,
  };
}

function signedReceipt(value, environment = env) {
  const evidence = canonicalJson(value);
  const signature = hmacHex(environment.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET,
    reviewEmailReceiptContract.signaturePrefix + evidence);
  return { evidence, signature };
}

assert.equal(reviewEmailOutboxConfiguration({}).enabled, false, 'Review email must default off.');
assert.equal(reviewEmailOutboxConfiguration(env).enabled, true);
for (const credentialName of [
  'ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET',
  'ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET',
]) {
  assert.equal(reviewEmailOutboxConfiguration({
    ...env,
    ARC_ROTATED_CREDENTIAL_V2: env[credentialName],
  }).enabled, false, `${credentialName} must reject an arbitrary configured alias.`);
}
assert.equal(reviewEmailOutboxConfiguration({
  ...env,
  ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET: env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
}).enabled, false, 'Email outbox and receipt secrets must be distinct.');
await assert.rejects(readReviewEmailRecipientControl(
  new Proxy({}, { get() { throw new Error('aliased recipient control touched storage'); } }),
  sha('a'),
  { ...env, ARC_ROTATED_CREDENTIAL_V2: env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET },
), /OUTBOX_DISABLED/, 'Recipient control must reject an aliased signing credential before storage access.');

const rawEmail = 'Customer@Example.com';
const normalizedEmail = 'customer@example.com';
const token = 'R'.repeat(43);
const store = new FakeStore();
await assert.rejects(prepareReviewInviteEmail(store, inviteFor(token, rawEmail), {
  ...env, ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'false',
}, { clock: () => new Date(now) }), /OUTBOX_DISABLED/);
await assert.rejects(issueReviewInvite(new FakeStore(), {
  ...inviteFor(token, rawEmail),
  email_delivery_receipt_sha256: sha('f'),
}, env, { clock: () => new Date(now) }), /PREBOUND_DELIVERY_FORBIDDEN/,
  'Enabled outbox mode must reject producer-supplied delivery evidence.');

const prepared = await prepareReviewInviteEmail(store, inviteFor(token, rawEmail), env, {
  clock: () => new Date(now),
});
assert.equal(prepared.invite.email_delivery_receipt_sha256, null,
  'Invite creation must not invent a delivery receipt.');
assert.equal(prepared.outbox.state, 'READY');
const firstWriteKeys = store.writes.map(write => write.key);
assert.equal(firstWriteKeys[0].startsWith('review-email-recipient-control/'), true,
  'Recipient authority control must exist before an invite can become sendable.');
assert.ok(firstWriteKeys.findIndex(key => key.startsWith('review-invites/')) <
  firstWriteKeys.findIndex(key => key.startsWith('review-email-outbox/')));
assert.equal(firstWriteKeys.some(key => key.startsWith('review-email-outbox/')), true,
  'The create-only outbox must exist before send authority can be reserved.');
const durableBeforeSend = JSON.stringify([...store.values.entries()]);
assert.equal(durableBeforeSend.includes(token), false, 'Raw invite tokens must never be durable.');
assert.equal(durableBeforeSend.toLowerCase().includes(normalizedEmail), false, 'Raw email must never be durable.');
assert.equal(durableBeforeSend.includes('/review/'), false, 'The bearer review URL must never be durable.');
await assert.rejects(exchangeReviewInvite(store, token, env, {
  clock: () => new Date(now), randomBytes: () => Buffer.alloc(32, 1),
}), /DELIVERY_UNCONFIRMED/, 'An unsent invite must not authorize review exchange.');

const readyEtag = (await readReviewEmailOutbox(store, prepared.outbox.outbox_hmac_sha256, env)).etag;
const prepareReplay = await prepareReviewInviteEmail(store, inviteFor(token, rawEmail), env, {
  clock: () => new Date(now),
});
assert.equal(prepareReplay.idempotent_replay, true);
assert.equal((await readReviewEmailOutbox(store, prepared.outbox.outbox_hmac_sha256, env)).etag, readyEtag,
  'Create-only prepare replay must not rewrite its outbox.');
await assert.rejects(reserveReviewEmailSend(store, {
  invite_token: token, recipient_email: 'wrong@example.com',
}, env, { clock: () => new Date(now) }), /BINDING_INVALID/);

const authority = await reserveReviewEmailSend(store, {
  invite_token: token, recipient_email: rawEmail,
}, env, { clock: () => new Date(now) });
assert.equal(authority.idempotent_replay, false);
assert.equal(authority.recipient_email, normalizedEmail);
assert.equal(authority.review_url, `https://arcweb.onl/review/#invite=${token}`,
  'The review URL may be formed only while the caller still holds the raw token.');
assert.match(authority.provider_idempotency_key, /^arc_review_email_[a-f0-9]{64}$/);
const authorityReplay = await reserveReviewEmailSend(store, {
  invite_token: token, recipient_email: normalizedEmail,
}, env, { clock: () => new Date(now) });
assert.equal(authorityReplay.idempotent_replay, true);
assert.equal(authorityReplay.provider_idempotency_key, authority.provider_idempotency_key,
  'A crash-safe provider retry must reuse one deterministic idempotency key.');
const durableAfterReservation = JSON.stringify([...store.values.entries()]);
assert.equal(durableAfterReservation.includes(token), false);
assert.equal(durableAfterReservation.includes(normalizedEmail), false);
assert.equal(durableAfterReservation.includes(authority.review_url), false);
assert.equal(durableAfterReservation.includes(authority.provider_idempotency_key), false,
  'Only the provider idempotency digest may be stored.');

const deliveredValue = receiptFor(prepared, 'primary');
const delivered = signedReceipt(deliveredValue);
await assert.rejects(acknowledgeReviewEmailReceipt(store, delivered.evidence, '0'.repeat(64), env, {
  clock: () => new Date(at(2_000)),
}), /SIGNATURE_INVALID/);
const acknowledged = await acknowledgeReviewEmailReceipt(store, delivered.evidence, delivered.signature, env, {
  clock: () => new Date(at(2_000)),
});
assert.equal(acknowledged.state, 'DELIVERED');
assert.equal(acknowledged.idempotent_replay, false);
const deliveredOutbox = await readReviewEmailOutbox(store, prepared.outbox.outbox_hmac_sha256, env);
assert.equal(deliveredOutbox.record.delivery_receipt_sha256, sha256Hex(delivered.evidence));
const boundInvite = await readReviewInviteForEmail(store, prepared.invite.invite_hmac_sha256, env);
assert.equal(boundInvite.record.email_delivery_receipt_sha256, sha256Hex(delivered.evidence),
  'Only an exact signed delivered receipt may unlock review exchange.');
assert.equal(boundInvite.record.email_delivery_binding_mode, 'signed-outbox');
assert.equal(boundInvite.record.email_delivery_outbox_hmac_sha256, prepared.outbox.outbox_hmac_sha256);
const durableAfterDelivery = JSON.stringify([...store.values.entries()]);
assert.equal(durableAfterDelivery.includes(deliveredValue.provider_event_id), false);
assert.equal(durableAfterDelivery.includes(deliveredValue.provider_message_id), false,
  'Raw provider identities must never enter durable state.');

const exchanged = await exchangeReviewInvite(store, token, env, {
  clock: () => new Date(at(3_000)), randomBytes: () => Buffer.alloc(32, 2),
});
const status = await readReviewStatus(store, exchanged.session_token, env, new Date(at(3_000)));
const approved = await decideReview(store, exchanged.session_token, {
  action: 'APPROVE_AND_PAY',
  expected_revision: status.record_revision,
  idempotency_key: '11111111-1111-4111-8111-111111111111',
}, env, { clock: () => new Date(at(3_000)) });
assert.equal(approved.state, 'APPROVED');
const stripeFragmentUrl = 'https://checkout.stripe.com/c/pay/cs_test_reviewEmailHash12345#fidkdWxOYHwnPyd1blpxYHZxWjA0T3dQ';
const checkout = await createApprovedCheckout(store, exchanged.session_token, env, {
  clock: () => new Date(at(3_000)), createCheckout: async () => ({ url: stripeFragmentUrl }),
});
assert.equal(checkout.checkout_url, stripeFragmentUrl,
  'A real Stripe Checkout Session fragment must survive strict URL validation.');

const terminalEtag = deliveredOutbox.etag;
const deliveredReplay = await acknowledgeReviewEmailReceipt(store, delivered.evidence, delivered.signature, env, {
  clock: () => new Date(now.getTime() + 2 * 60 * 60_000),
});
assert.equal(deliveredReplay.idempotent_replay, true,
  'An exact durable retry may converge after the first-observation freshness window.');
assert.equal((await readReviewEmailOutbox(store, prepared.outbox.outbox_hmac_sha256, env)).etag, terminalEtag,
  'Terminal outbox replay must not rewrite or reopen the no-resend latch.');
const postDeliveryPrepareReplay = await prepareReviewInviteEmail(store, inviteFor(token, rawEmail), env, {
  clock: () => new Date(now.getTime() + 2 * 60 * 60_000),
});
assert.equal(postDeliveryPrepareReplay.idempotent_replay, true);

const conflictValue = receiptFor(prepared, 'conflict', 'delivered', { issued_at: at(3_000) });
const conflict = signedReceipt(conflictValue);
await assert.rejects(acknowledgeReviewEmailReceipt(store, conflict.evidence, conflict.signature, env, {
  clock: () => new Date(at(3_000)),
}), /RECEIPT_CONFLICT/);

// A later complaint monotonically supersedes delivery, revokes the already
// exchanged/approved invite, and retains both delivery and suppression proof.
const complaintAt = 12 * 60 * 60_000;
const complaintValue = receiptFor(prepared, 'late-complaint', 'complained', {
  provider_message_id: deliveredValue.provider_message_id,
  event_at: at(complaintAt + 1_000),
  issued_at: at(complaintAt + 2_000),
});
const complaint = signedReceipt(complaintValue);
const complained = await acknowledgeReviewEmailReceipt(store, complaint.evidence, complaint.signature, env, {
  clock: () => new Date(at(complaintAt + 2_000)),
});
assert.equal(complained.state, 'COMPLAINED');
const complainedOutbox = await readReviewEmailOutbox(store, prepared.outbox.outbox_hmac_sha256, env);
assert.equal(complainedOutbox.record.delivered_receipt_sha256, sha256Hex(delivered.evidence));
assert.equal(complainedOutbox.record.suppression_receipt_sha256, sha256Hex(complaint.evidence));
assert.equal(complainedOutbox.record.suppression_status, 'complained');
const complainedInvite = await readReviewInviteForEmail(store, prepared.invite.invite_hmac_sha256, env);
assert.equal(complainedInvite.record.state, 'REVOKED');
assert.equal(complainedInvite.record.email_delivery_receipt_sha256, sha256Hex(delivered.evidence));
assert.equal(complainedInvite.record.email_suppression_receipt_sha256, sha256Hex(complaint.evidence));
assert.equal(complainedInvite.record.email_suppression_outbox_hmac_sha256,
  prepared.outbox.outbox_hmac_sha256);
assert.equal(complainedInvite.record.email_suppression_status, 'complained');
await assert.rejects(readReviewStatus(store, exchanged.session_token, env,
  new Date(at(complaintAt + 3_000))), /EMAIL_SUPPRESSED/,
  'A late complaint must revoke an already-issued review session.');
let checkoutCalledAfterSuppression = false;
await assert.rejects(createApprovedCheckout(store, exchanged.session_token, env, {
  clock: () => new Date(at(complaintAt + 3_000)),
  createCheckout: async () => { checkoutCalledAfterSuppression = true; },
}), /EMAIL_SUPPRESSED/);
assert.equal(checkoutCalledAfterSuppression, false);
const complainedEtag = complainedOutbox.etag;
const oldDeliveryAfterComplaint = await acknowledgeReviewEmailReceipt(store, delivered.evidence,
  delivered.signature, env, { clock: () => new Date(at(complaintAt + 4_000)) });
assert.equal(oldDeliveryAfterComplaint.state, 'COMPLAINED');
assert.equal((await readReviewEmailOutbox(store, prepared.outbox.outbox_hmac_sha256, env)).etag, complainedEtag,
  'A delayed delivery replay must never downgrade suppression.');
assert.equal(JSON.stringify([...store.values.entries()]).includes(complaintValue.provider_event_id), false);
assert.equal(JSON.stringify([...store.values.entries()]).includes(complaintValue.provider_message_id), false);

// Delivery can escalate to bounce, and bounce can only escalate further to
// complaint. The existing session remains revoked throughout.
const bounceStore = new FakeStore();
const bounceToken = 'X'.repeat(43);
const bouncePrepared = await prepareReviewInviteEmail(bounceStore,
  inviteFor(bounceToken, 'late-bounce@example.com', { preview_manifest_sha256: sha('e') }), env,
  { clock: () => new Date(now) });
await reserveReviewEmailSend(bounceStore, {
  invite_token: bounceToken, recipient_email: 'late-bounce@example.com',
}, env, { clock: () => new Date(now) });
const bounceDeliveryValue = receiptFor(bouncePrepared, 'bounce-delivery');
const bounceDelivery = signedReceipt(bounceDeliveryValue);
await acknowledgeReviewEmailReceipt(bounceStore, bounceDelivery.evidence, bounceDelivery.signature, env, {
  clock: () => new Date(at(2_000)),
});
const bounceSession = await exchangeReviewInvite(bounceStore, bounceToken, env, {
  clock: () => new Date(at(3_000)), randomBytes: () => Buffer.alloc(32, 19),
});
const lateBounceValue = receiptFor(bouncePrepared, 'late-bounce', 'bounced', {
  provider_message_id: bounceDeliveryValue.provider_message_id,
  event_at: at(complaintAt + 10_000), issued_at: at(complaintAt + 11_000),
});
const lateBounce = signedReceipt(lateBounceValue);
assert.equal((await acknowledgeReviewEmailReceipt(bounceStore, lateBounce.evidence, lateBounce.signature, env, {
  clock: () => new Date(at(complaintAt + 11_000)),
})).state, 'BOUNCED');
await assert.rejects(readReviewStatus(bounceStore, bounceSession.session_token, env,
  new Date(at(complaintAt + 12_000))), /EMAIL_SUPPRESSED/);
const laterComplaintValue = receiptFor(bouncePrepared, 'later-complaint', 'complained', {
  provider_message_id: bounceDeliveryValue.provider_message_id,
  event_at: at(2 * complaintAt + 10_000), issued_at: at(2 * complaintAt + 11_000),
});
const laterComplaint = signedReceipt(laterComplaintValue);
assert.equal((await acknowledgeReviewEmailReceipt(bounceStore, laterComplaint.evidence,
  laterComplaint.signature, env, { clock: () => new Date(at(2 * complaintAt + 11_000)) })).state, 'COMPLAINED');
const twiceSuppressedOutbox = await readReviewEmailOutbox(bounceStore,
  bouncePrepared.outbox.outbox_hmac_sha256, env);
assert.equal(twiceSuppressedOutbox.record.delivered_receipt_sha256, sha256Hex(bounceDelivery.evidence));
assert.equal(twiceSuppressedOutbox.record.suppression_receipt_sha256, sha256Hex(laterComplaint.evidence));
assert.equal((await readReviewInviteForEmail(bounceStore, bouncePrepared.invite.invite_hmac_sha256, env))
  .record.email_suppression_status, 'complained');
await assert.rejects(acknowledgeReviewEmailReceipt(bounceStore, lateBounce.evidence, lateBounce.signature, env, {
  clock: () => new Date(at(2 * complaintAt + 12_000)),
}), /RECEIPT_CONFLICT/);
assert.equal((await readReviewEmailOutbox(bounceStore,
  bouncePrepared.outbox.outbox_hmac_sha256, env)).record.state, 'COMPLAINED');

// A crash after the receipt latch cannot cause a resend. Exact replay finishes
// provider identity reservations and terminal delivery without rechecking age.
const identityCrashStore = new FakeStore();
const identityToken = 'S'.repeat(43);
const identityPrepared = await prepareReviewInviteEmail(identityCrashStore,
  inviteFor(identityToken, 'identity@example.com', { preview_manifest_sha256: sha('c') }), env,
  { clock: () => new Date(now) });
await reserveReviewEmailSend(identityCrashStore, {
  invite_token: identityToken, recipient_email: 'identity@example.com',
}, env, { clock: () => new Date(now) });
const identityReceipt = signedReceipt(receiptFor(identityPrepared, 'identity-crash'));
identityCrashStore.failNextPrefix('review-email-provider-message/');
await assert.rejects(acknowledgeReviewEmailReceipt(identityCrashStore, identityReceipt.evidence,
  identityReceipt.signature, env, { clock: () => new Date(at(2_000)) }), /SIMULATED_PROCESS_CRASH/);
assert.equal((await readReviewEmailOutbox(identityCrashStore, identityPrepared.outbox.outbox_hmac_sha256, env)).record.state,
  'RECEIPT_BOUND');
await assert.rejects(reserveReviewEmailSend(identityCrashStore, {
  invite_token: identityToken, recipient_email: 'identity@example.com',
}, env, { clock: () => new Date(at(2_000)) }), /SEND_FINALIZED/);
const identityRecovered = await acknowledgeReviewEmailReceipt(identityCrashStore, identityReceipt.evidence,
  identityReceipt.signature, env, { clock: () => new Date(now.getTime() + 24 * 60 * 60_000) });
assert.equal(identityRecovered.state, 'DELIVERED');

// A crash after terminalizing the outbox leaves exchange closed. Replay only
// binds the invite and never rewrites the terminal no-resend latch.
const bindingCrashStore = new FakeStore();
const bindingToken = 'T'.repeat(43);
const bindingPrepared = await prepareReviewInviteEmail(bindingCrashStore,
  inviteFor(bindingToken, 'binding@example.com', { preview_manifest_sha256: sha('d') }), env,
  { clock: () => new Date(now) });
await reserveReviewEmailSend(bindingCrashStore, {
  invite_token: bindingToken, recipient_email: 'binding@example.com',
}, env, { clock: () => new Date(now) });
const bindingReceipt = signedReceipt(receiptFor(bindingPrepared, 'binding-crash'));
bindingCrashStore.failNextKey(reviewInviteKey(bindingPrepared.invite.invite_hmac_sha256));
await assert.rejects(acknowledgeReviewEmailReceipt(bindingCrashStore, bindingReceipt.evidence,
  bindingReceipt.signature, env, { clock: () => new Date(at(2_000)) }), /SIMULATED_PROCESS_CRASH/);
const terminalBeforeRecovery = await readReviewEmailOutbox(bindingCrashStore,
  bindingPrepared.outbox.outbox_hmac_sha256, env);
assert.equal(terminalBeforeRecovery.record.state, 'DELIVERED');
assert.equal((await readReviewInviteForEmail(bindingCrashStore, bindingPrepared.invite.invite_hmac_sha256, env))
  .record.email_delivery_receipt_sha256, null);
await assert.rejects(exchangeReviewInvite(bindingCrashStore, bindingToken, env, {
  clock: () => new Date(at(3_000)), randomBytes: () => Buffer.alloc(32, 3),
}), /DELIVERY_UNCONFIRMED/);
await acknowledgeReviewEmailReceipt(bindingCrashStore, bindingReceipt.evidence, bindingReceipt.signature, env, {
  clock: () => new Date(now.getTime() + 24 * 60 * 60_000),
});
assert.equal((await readReviewEmailOutbox(bindingCrashStore,
  bindingPrepared.outbox.outbox_hmac_sha256, env)).etag, terminalBeforeRecovery.etag);
assert.doesNotReject(exchangeReviewInvite(bindingCrashStore, bindingToken, env, {
  clock: () => new Date(at(3_000)), randomBytes: () => Buffer.alloc(32, 4),
}));

// Suppression is bound to the invite before the outbox transition. A crash in
// between must immediately revoke access/send replay, then converge later.
const suppressionCrashStore = new FakeStore();
const suppressionCrashToken = 'W'.repeat(43);
const suppressionCrashPrepared = await prepareReviewInviteEmail(suppressionCrashStore,
  inviteFor(suppressionCrashToken, 'suppression-crash@example.com', { preview_manifest_sha256: sha('b') }), env,
  { clock: () => new Date(now) });
await reserveReviewEmailSend(suppressionCrashStore, {
  invite_token: suppressionCrashToken, recipient_email: 'suppression-crash@example.com',
}, env, { clock: () => new Date(now) });
const suppressionCrashReceipt = signedReceipt(receiptFor(suppressionCrashPrepared,
  'suppression-crash', 'bounced'));
suppressionCrashStore.failNextKey(reviewEmailOutboxKey(
  suppressionCrashPrepared.outbox.outbox_hmac_sha256));
await assert.rejects(acknowledgeReviewEmailReceipt(suppressionCrashStore,
  suppressionCrashReceipt.evidence, suppressionCrashReceipt.signature, env,
  { clock: () => new Date(at(2_000)) }), /SIMULATED_PROCESS_CRASH/);
const revokedDuringCrash = await readReviewInviteForEmail(suppressionCrashStore,
  suppressionCrashPrepared.invite.invite_hmac_sha256, env);
assert.equal(revokedDuringCrash.record.state, 'REVOKED');
assert.equal(revokedDuringCrash.record.email_suppression_receipt_sha256,
  sha256Hex(suppressionCrashReceipt.evidence));
assert.equal((await readReviewEmailOutbox(suppressionCrashStore,
  suppressionCrashPrepared.outbox.outbox_hmac_sha256, env)).record.state, 'SEND_RESERVED');
await assert.rejects(reserveReviewEmailSend(suppressionCrashStore, {
  invite_token: suppressionCrashToken, recipient_email: 'suppression-crash@example.com',
}, env, { clock: () => new Date(at(3_000)) }), /SEND_FINALIZED/);
await assert.rejects(exchangeReviewInvite(suppressionCrashStore, suppressionCrashToken, env, {
  clock: () => new Date(at(3_000)), randomBytes: () => Buffer.alloc(32, 20),
}), /EMAIL_SUPPRESSED/);
assert.equal((await acknowledgeReviewEmailReceipt(suppressionCrashStore,
  suppressionCrashReceipt.evidence, suppressionCrashReceipt.signature, env,
  { clock: () => new Date(now.getTime() + 24 * 60 * 60_000) })).state, 'BOUNCED');

// Bounce and complaint events are terminal fail-closed outcomes. They never
// bind delivery to the invite and can never reopen provider send authority.
for (const [index, deliveryStatus] of ['bounced', 'complained'].entries()) {
  const negativeStore = new FakeStore();
  const negativeToken = String.fromCharCode(85 + index).repeat(43);
  const negativeEmail = `${deliveryStatus}@example.com`;
  const negativePrepared = await prepareReviewInviteEmail(negativeStore,
    inviteFor(negativeToken, negativeEmail, { preview_manifest_sha256: String(index + 1).repeat(64) }), env,
    { clock: () => new Date(now) });
  await reserveReviewEmailSend(negativeStore, {
    invite_token: negativeToken, recipient_email: negativeEmail,
  }, env, { clock: () => new Date(now) });
  const negativeReceipt = signedReceipt(receiptFor(negativePrepared, `negative-${index}`, deliveryStatus));
  const negativeResult = await acknowledgeReviewEmailReceipt(negativeStore, negativeReceipt.evidence,
    negativeReceipt.signature, env, { clock: () => new Date(at(2_000)) });
  assert.equal(negativeResult.state, deliveryStatus.toUpperCase());
  assert.equal((await readReviewInviteForEmail(negativeStore,
    negativePrepared.invite.invite_hmac_sha256, env)).record.email_delivery_receipt_sha256, null);
  const negativeInvite = await readReviewInviteForEmail(negativeStore,
    negativePrepared.invite.invite_hmac_sha256, env);
  assert.equal(negativeInvite.record.state, 'REVOKED');
  assert.equal(negativeInvite.record.email_suppression_status, deliveryStatus);
  assert.equal(negativeInvite.record.email_suppression_receipt_sha256,
    sha256Hex(negativeReceipt.evidence));
  assert.equal(negativeInvite.record.email_suppression_outbox_hmac_sha256,
    negativePrepared.outbox.outbox_hmac_sha256);
  await assert.rejects(exchangeReviewInvite(negativeStore, negativeToken, env, {
    clock: () => new Date(at(3_000)), randomBytes: () => Buffer.alloc(32, 5 + index),
  }), /EMAIL_SUPPRESSED/);
  await assert.rejects(reserveReviewEmailSend(negativeStore, {
    invite_token: negativeToken, recipient_email: negativeEmail,
  }, env, { clock: () => new Date(at(3_000)) }), /SEND_FINALIZED/);
}

// A successor may already be READY when its predecessor is later suppressed.
// Strong lineage and global recipient reads must revoke it before send. The
// HMAC-keyed latch also blocks a separate future invite for that recipient.
for (const [index, deliveryStatus] of ['bounced', 'complained'].entries()) {
  const successorStore = new FakeStore();
  const priorToken = String.fromCharCode(89 + index).repeat(43);
  const successorToken = String.fromCharCode(103 + index).repeat(43);
  const unrelatedToken = String.fromCharCode(107 + index).repeat(43);
  const recipient = `successor-${deliveryStatus}@example.com`;
  const priorPrepared = await prepareReviewInviteEmail(successorStore,
    inviteFor(priorToken, recipient, { preview_manifest_sha256: String(4 + index).repeat(64) }), env,
    { clock: () => new Date(now) });
  await reserveReviewEmailSend(successorStore, {
    invite_token: priorToken, recipient_email: recipient,
  }, env, { clock: () => new Date(now) });
  const priorDeliveryValue = receiptFor(priorPrepared, `successor-source-delivery-${index}`);
  const priorDelivery = signedReceipt(priorDeliveryValue);
  await acknowledgeReviewEmailReceipt(successorStore, priorDelivery.evidence, priorDelivery.signature, env, {
    clock: () => new Date(at(2_000)),
  });
  const priorSession = await exchangeReviewInvite(successorStore, priorToken, env, {
    clock: () => new Date(at(3_000)), randomBytes: () => Buffer.alloc(32, 24 + index),
  });
  const priorStatus = await readReviewStatus(successorStore, priorSession.session_token, env, new Date(at(3_000)));
  await decideReview(successorStore, priorSession.session_token, {
    action: 'REQUEST_CHANGES',
    expected_revision: priorStatus.record_revision,
    idempotency_key: index === 0
      ? '33333333-3333-4333-8333-333333333333'
      : '44444444-4444-4444-8444-444444444444',
    revision_notes: 'Use the shorter service list and replace the primary call to action.',
  }, env, { clock: () => new Date(at(4_000)) });
  const successorPrepared = await prepareReviewInviteEmail(successorStore, inviteFor(successorToken, recipient, {
    prior_invite_hmac_sha256: priorPrepared.invite.invite_hmac_sha256,
    preview_content_sha256: String(6 + index).repeat(64),
    preview_manifest_sha256: String(8 + index).repeat(64),
    preview_source_commit_sha: String.fromCharCode(100 + index).repeat(40),
  }), env, { clock: () => new Date(at(5_000)) });
  assert.equal(successorPrepared.outbox.state, 'READY');

  const sourceSuppressionValue = receiptFor(priorPrepared, `successor-source-suppression-${index}`,
    deliveryStatus, {
      provider_message_id: priorDeliveryValue.provider_message_id,
      event_at: at(6_000), issued_at: at(7_000),
    });
  const sourceSuppression = signedReceipt(sourceSuppressionValue);
  await acknowledgeReviewEmailReceipt(successorStore, sourceSuppression.evidence,
    sourceSuppression.signature, env, { clock: () => new Date(at(7_000)) });
  const globalSuppression = await readReviewEmailRecipientSuppression(successorStore,
    priorPrepared.invite.recipient_email_sha256, env);
  assert.equal(globalSuppression.record.suppression_status, deliveryStatus);
  assert.equal(globalSuppression.record.suppression_receipt_sha256, sha256Hex(sourceSuppression.evidence));
  assert.match(globalSuppression.record.recipient_suppression_hmac_sha256, /^[a-f0-9]{64}$/);

  await assert.rejects(reserveReviewEmailSend(successorStore, {
    invite_token: successorToken, recipient_email: recipient,
  }, env, { clock: () => new Date(at(8_000)) }), /RECIPIENT_SUPPRESSED/);
  const revokedSuccessor = await readReviewInviteForEmail(successorStore,
    successorPrepared.invite.invite_hmac_sha256, env);
  assert.equal(revokedSuccessor.record.state, 'REVOKED');
  assert.equal(revokedSuccessor.record.email_suppression_receipt_sha256,
    sha256Hex(sourceSuppression.evidence));
  assert.equal((await readReviewEmailOutbox(successorStore,
    successorPrepared.outbox.outbox_hmac_sha256, env)).record.state, 'READY');

  await assert.rejects(prepareReviewInviteEmail(successorStore, inviteFor(unrelatedToken, recipient, {
    preview_manifest_sha256: String.fromCharCode(97 + index).repeat(64),
    preview_content_sha256: String.fromCharCode(99 + index).repeat(64),
    preview_source_commit_sha: (index === 0 ? 'f' : '1').repeat(40),
  }), env, { clock: () => new Date(at(9_000)) }), /RECIPIENT_SUPPRESSED/);
  await assert.rejects(readReviewInviteForEmail(successorStore,
    reviewInviteHmac(unrelatedToken, env), env), /INVITE_NOT_FOUND/,
  'A known-suppressed recipient must be rejected before an orphan invite/outbox is created.');
  assert.equal(JSON.stringify([...successorStore.values.entries()]).includes(recipient), false,
    'Recipient suppression storage must not contain plaintext email.');
}

// An email can already be SEND_RESERVED when a different message for the same
// recipient is suppressed. A later delivered webhook must not unlock that
// invite after the global suppression latch exists.
const inFlightStore = new FakeStore();
const inFlightRecipient = 'in-flight-suppression@example.com';
const sourceToken = 'm'.repeat(43);
const inFlightToken = 'n'.repeat(43);
const sourcePrepared = await prepareReviewInviteEmail(inFlightStore,
  inviteFor(sourceToken, inFlightRecipient, { preview_manifest_sha256: sha('2') }), env,
  { clock: () => new Date(now) });
const inFlightPrepared = await prepareReviewInviteEmail(inFlightStore,
  inviteFor(inFlightToken, inFlightRecipient, {
    preview_manifest_sha256: sha('3'),
    preview_content_sha256: sha('4'),
    preview_source_commit_sha: '2'.repeat(40),
  }), env, { clock: () => new Date(at(500)) });
await reserveReviewEmailSend(inFlightStore, {
  invite_token: sourceToken, recipient_email: inFlightRecipient,
}, env, { clock: () => new Date(at(600)) });
await reserveReviewEmailSend(inFlightStore, {
  invite_token: inFlightToken, recipient_email: inFlightRecipient,
}, env, { clock: () => new Date(at(700)) });
const sourceComplaintValue = receiptFor(sourcePrepared, 'in-flight-source-complaint', 'complained', {
  event_at: at(2_000), issued_at: at(3_000),
});
const sourceComplaint = signedReceipt(sourceComplaintValue);
await acknowledgeReviewEmailReceipt(inFlightStore, sourceComplaint.evidence,
  sourceComplaint.signature, env, { clock: () => new Date(at(3_000)) });
const blockedDelivery = signedReceipt(receiptFor(inFlightPrepared, 'in-flight-delivery', 'delivered', {
  event_at: at(4_000), issued_at: at(5_000),
}));
await assert.rejects(acknowledgeReviewEmailReceipt(inFlightStore, blockedDelivery.evidence,
  blockedDelivery.signature, env, { clock: () => new Date(at(5_000)) }), /RECIPIENT_SUPPRESSED/);
const blockedInFlightInvite = await readReviewInviteForEmail(inFlightStore,
  inFlightPrepared.invite.invite_hmac_sha256, env);
assert.equal(blockedInFlightInvite.record.state, 'REVOKED');
assert.equal(blockedInFlightInvite.record.email_delivery_receipt_sha256, null);
assert.equal(blockedInFlightInvite.record.email_suppression_source_outbox_hmac_sha256,
  sourcePrepared.outbox.outbox_hmac_sha256);
assert.equal((await readReviewEmailOutbox(inFlightStore,
  inFlightPrepared.outbox.outbox_hmac_sha256, env)).record.state, 'SEND_RESERVED');
await assert.rejects(exchangeReviewInvite(inFlightStore, inFlightToken, env, {
  clock: () => new Date(at(6_000)), randomBytes: () => Buffer.alloc(32, 28),
}), /EMAIL_SUPPRESSED/);

// Two messages may both be in flight before either provider event arrives.
// Each signed negative receipt must terminalize its own outbox/invite even
// when a stronger recipient-level latch from the first event already exists.
const dualNegativeStore = new FakeStore();
const dualRecipient = 'dual-negative@example.com';
const firstNegativeToken = 'o'.repeat(43);
const secondNegativeToken = 'p'.repeat(43);
const firstNegativePrepared = await prepareReviewInviteEmail(dualNegativeStore,
  inviteFor(firstNegativeToken, dualRecipient, { preview_manifest_sha256: sha('5') }), env,
  { clock: () => new Date(now) });
const secondNegativePrepared = await prepareReviewInviteEmail(dualNegativeStore,
  inviteFor(secondNegativeToken, dualRecipient, {
    preview_manifest_sha256: sha('6'),
    preview_content_sha256: sha('7'),
    preview_source_commit_sha: '3'.repeat(40),
  }), env, { clock: () => new Date(at(500)) });
await reserveReviewEmailSend(dualNegativeStore, {
  invite_token: firstNegativeToken, recipient_email: dualRecipient,
}, env, { clock: () => new Date(at(600)) });
await reserveReviewEmailSend(dualNegativeStore, {
  invite_token: secondNegativeToken, recipient_email: dualRecipient,
}, env, { clock: () => new Date(at(700)) });
const firstComplaint = signedReceipt(receiptFor(firstNegativePrepared,
  'dual-first-complaint', 'complained', { event_at: at(2_000), issued_at: at(3_000) }));
const secondBounce = signedReceipt(receiptFor(secondNegativePrepared,
  'dual-second-bounce', 'bounced', { event_at: at(4_000), issued_at: at(5_000) }));
assert.equal((await acknowledgeReviewEmailReceipt(dualNegativeStore, firstComplaint.evidence,
  firstComplaint.signature, env, { clock: () => new Date(at(3_000)) })).state, 'COMPLAINED');
assert.equal((await acknowledgeReviewEmailReceipt(dualNegativeStore, secondBounce.evidence,
  secondBounce.signature, env, { clock: () => new Date(at(5_000)) })).state, 'BOUNCED');
const dualGlobal = await readReviewEmailRecipientSuppression(dualNegativeStore,
  firstNegativePrepared.invite.recipient_email_sha256, env);
assert.equal(dualGlobal.record.suppression_status, 'complained',
  'The stronger global complaint latch must remain monotonic.');
assert.equal(dualGlobal.record.source_outbox_hmac_sha256,
  firstNegativePrepared.outbox.outbox_hmac_sha256);
assert.equal((await readReviewInviteForEmail(dualNegativeStore,
  secondNegativePrepared.invite.invite_hmac_sha256, env)).record.email_suppression_status, 'bounced');
assert.equal((await readReviewEmailOutbox(dualNegativeStore,
  secondNegativePrepared.outbox.outbox_hmac_sha256, env)).record.state, 'BOUNCED');
assert.equal(JSON.stringify([...dualNegativeStore.values.entries()]).includes(dualRecipient), false);

// A reserved message awaiting a delayed provider webhook cannot starve a
// later READY job in the durable discovery queue.
const queueFairnessStore = new FakeStore();
const reservedQueueToken = 'x'.repeat(43);
const readyQueueToken = 'y'.repeat(43);
const reservedQueuePrepared = await prepareReviewInviteEmail(queueFairnessStore,
  inviteFor(reservedQueueToken, 'queue-reserved@example.com', { preview_manifest_sha256: sha('1') }), env,
  { clock: () => new Date(now), sourceReferenceHmacSha256: sha('a') });
await reserveReviewEmailSend(queueFairnessStore, {
  invite_token: reservedQueueToken, recipient_email: 'queue-reserved@example.com',
}, env, { clock: () => new Date(at(500)) });
const readyQueuePrepared = await prepareReviewInviteEmail(queueFairnessStore,
  inviteFor(readyQueueToken, 'queue-ready@example.com', {
    preview_manifest_sha256: sha('2'),
    preview_content_sha256: sha('3'),
    preview_source_commit_sha: '6'.repeat(40),
  }), env, { clock: () => new Date(at(1_000)), sourceReferenceHmacSha256: sha('b') });
const fairClaim = await claimNextReviewEmail(queueFairnessStore, env,
  { clock: () => new Date(at(2_000)) });
assert.equal(fairClaim.state, 'READY');
assert.equal(fairClaim.outbox_hmac_sha256, readyQueuePrepared.outbox.outbox_hmac_sha256);
assert.notEqual(fairClaim.outbox_hmac_sha256, reservedQueuePrepared.outbox.outbox_hmac_sha256);

// A crashed authority lease must never erase suppression evidence attached
// while it was active. Once the lease expires, acquisition converges the
// pending evidence to SUPPRESSED and rejects the new authority request.
const expiredLeaseStore = new FakeStore();
const expiredLeaseRecipient = reviewEmailRecipientSha256('expired-lease@example.com');
await acquireReviewEmailRecipientAuthority(expiredLeaseStore, expiredLeaseRecipient,
  'CHECKOUT:expired-lease-regression', env, new Date(now));
const pendingLeaseSuppression = await suppressReviewEmailRecipientControl(expiredLeaseStore, {
  recipient_email_sha256: expiredLeaseRecipient,
  suppression_receipt_sha256: sha('c'),
  suppression_status: 'complained',
  suppressed_at: at(1_000),
  source_invite_hmac_sha256: sha('d'),
  source_outbox_hmac_sha256: sha('e'),
}, env, new Date(at(1_000)));
assert.equal(pendingLeaseSuppression.pending, true);
await assert.rejects(acquireReviewEmailRecipientAuthority(expiredLeaseStore,
  expiredLeaseRecipient, 'CHECKOUT:must-not-reclaim', env, new Date(at(61_000))),
/RECIPIENT_SUPPRESSED/);
const finalizedExpiredLease = await readReviewEmailRecipientControl(expiredLeaseStore,
  expiredLeaseRecipient, env);
assert.equal(finalizedExpiredLease.record.state, 'SUPPRESSED');
assert.equal(finalizedExpiredLease.record.suppression_receipt_sha256, sha('c'));

// Deterministic TOCTOU regression: delivery snapshots an absent global latch,
// then a concurrent complaint commits recipient suppression before delivery
// resumes. Delivery binding and every later authority read must consume the
// shared latch, so exchange remains impossible even across different invites.
const concurrentStore = new FakeStore();
const concurrentRecipient = 'concurrent-suppression@example.com';
const concurrentComplaintToken = 'v'.repeat(43);
const concurrentDeliveryToken = 'w'.repeat(43);
const concurrentComplaintPrepared = await prepareReviewInviteEmail(concurrentStore,
  inviteFor(concurrentComplaintToken, concurrentRecipient, { preview_manifest_sha256: sha('e') }), env,
  { clock: () => new Date(now) });
const concurrentDeliveryPrepared = await prepareReviewInviteEmail(concurrentStore,
  inviteFor(concurrentDeliveryToken, concurrentRecipient, {
    preview_manifest_sha256: sha('f'),
    preview_content_sha256: sha('a'),
    preview_source_commit_sha: '5'.repeat(40),
  }), env, { clock: () => new Date(at(500)) });
await reserveReviewEmailSend(concurrentStore, {
  invite_token: concurrentComplaintToken, recipient_email: concurrentRecipient,
}, env, { clock: () => new Date(at(600)) });
await reserveReviewEmailSend(concurrentStore, {
  invite_token: concurrentDeliveryToken, recipient_email: concurrentRecipient,
}, env, { clock: () => new Date(at(700)) });
const concurrentComplaint = signedReceipt(receiptFor(concurrentComplaintPrepared,
  'concurrent-complaint', 'complained', { event_at: at(2_000), issued_at: at(3_000) }));
const concurrentDelivery = signedReceipt(receiptFor(concurrentDeliveryPrepared,
  'concurrent-delivery', 'delivered', { event_at: at(2_000), issued_at: at(3_000) }));
const barrier = concurrentStore.pauseNextReadPrefix('review-email-recipient-suppression/');
const deliveryAttempt = acknowledgeReviewEmailReceipt(concurrentStore, concurrentDelivery.evidence,
  concurrentDelivery.signature, env, { clock: () => new Date(at(3_000)) });
await barrier.reached;
assert.equal((await acknowledgeReviewEmailReceipt(concurrentStore, concurrentComplaint.evidence,
  concurrentComplaint.signature, env, { clock: () => new Date(at(3_000)) })).state, 'COMPLAINED');
barrier.release();
await assert.rejects(deliveryAttempt, /EMAIL_SUPPRESSED|RECIPIENT_SUPPRESSED/);
assert.equal((await readReviewEmailOutbox(concurrentStore,
  concurrentDeliveryPrepared.outbox.outbox_hmac_sha256, env)).record.state, 'DELIVERED');
assert.equal((await readReviewInviteForEmail(concurrentStore,
  concurrentDeliveryPrepared.invite.invite_hmac_sha256, env)).record.email_delivery_receipt_sha256, null);
await assert.rejects(exchangeReviewInvite(concurrentStore, concurrentDeliveryToken, env, {
  clock: () => new Date(at(4_000)), randomBytes: () => Buffer.alloc(32, 32),
}), /EMAIL_SUPPRESSED/,
'Global recipient suppression must be a required input to exchange authority, not only an invite-local projection.');

// If checkout work itself fails while a complaint is durably attached to its
// authority lease, suppression takes precedence over the provider failure and
// is projected onto the approved invite before any caller can retry payment.
const dualFailureStore = new FakeStore();
const dualFailureRecipient = 'checkout-dual-failure@example.com';
const dualFailureTargetToken = 'z'.repeat(43);
const dualFailureComplaintToken = '0'.repeat(43);
const dualFailureTarget = await prepareReviewInviteEmail(dualFailureStore,
  inviteFor(dualFailureTargetToken, dualFailureRecipient, { preview_manifest_sha256: sha('4') }), env,
  { clock: () => new Date(now) });
const dualFailureComplaintSource = await prepareReviewInviteEmail(dualFailureStore,
  inviteFor(dualFailureComplaintToken, dualFailureRecipient, {
    preview_manifest_sha256: sha('5'),
    preview_content_sha256: sha('6'),
    preview_source_commit_sha: '7'.repeat(40),
  }), env, { clock: () => new Date(at(500)) });
await reserveReviewEmailSend(dualFailureStore, {
  invite_token: dualFailureTargetToken, recipient_email: dualFailureRecipient,
}, env, { clock: () => new Date(at(600)) });
await reserveReviewEmailSend(dualFailureStore, {
  invite_token: dualFailureComplaintToken, recipient_email: dualFailureRecipient,
}, env, { clock: () => new Date(at(700)) });
const dualFailureDelivery = signedReceipt(receiptFor(dualFailureTarget,
  'dual-failure-target-delivery', 'delivered', { event_at: at(2_000), issued_at: at(3_000) }));
await acknowledgeReviewEmailReceipt(dualFailureStore, dualFailureDelivery.evidence,
  dualFailureDelivery.signature, env, { clock: () => new Date(at(3_000)) });
const dualFailureSession = await exchangeReviewInvite(dualFailureStore, dualFailureTargetToken, env, {
  clock: () => new Date(at(4_000)), randomBytes: () => Buffer.alloc(32, 34),
});
const dualFailureStatus = await readReviewStatus(dualFailureStore,
  dualFailureSession.session_token, env, new Date(at(4_000)));
await decideReview(dualFailureStore, dualFailureSession.session_token, {
  action: 'APPROVE_AND_PAY',
  expected_revision: dualFailureStatus.record_revision,
  idempotency_key: '66666666-6666-4666-8666-666666666666',
}, env, { clock: () => new Date(at(5_000)) });
let providerEntered;
let releaseProvider;
const providerStarted = new Promise(resolve => { providerEntered = resolve; });
const providerReleased = new Promise(resolve => { releaseProvider = resolve; });
const failedCheckout = createApprovedCheckout(dualFailureStore,
  dualFailureSession.session_token, env, {
    clock: () => new Date(at(6_000)),
    createCheckout: async () => {
      providerEntered();
      await providerReleased;
      throw new Error('SIMULATED_PROVIDER_FAILURE');
    },
  });
await providerStarted;
const dualFailureComplaint = signedReceipt(receiptFor(dualFailureComplaintSource,
  'dual-failure-source-complaint', 'complained', { event_at: at(7_000), issued_at: at(8_000) }));
await assert.rejects(acknowledgeReviewEmailReceipt(dualFailureStore,
  dualFailureComplaint.evidence, dualFailureComplaint.signature, env,
  { clock: () => new Date(at(8_000)) }), /AUTHORITY_CONTENTION/,
'Complaint evidence must remain pending on the in-flight checkout authority lease.');
releaseProvider();
await assert.rejects(failedCheckout, /EMAIL_SUPPRESSED/,
  'Suppression must take precedence when checkout and provider failure race.');
assert.equal((await readReviewInviteForEmail(dualFailureStore,
  dualFailureTarget.invite.invite_hmac_sha256, env)).record.state, 'REVOKED');
assert.equal((await acknowledgeReviewEmailReceipt(dualFailureStore,
  dualFailureComplaint.evidence, dualFailureComplaint.signature, env,
  { clock: () => new Date(at(9_000)) })).state, 'COMPLAINED');

// A negative provider receipt cannot finish until every durable Checkout
// binding for the recipient has been reconciled. The signed recipient control
// remains suppressed across the failed attempt, while webhook retry converges
// only after the expiry worker reports completion.
const revocationGateStore = new FakeStore();
const revocationGateRecipient = 'checkout-revocation-gate@example.com';
const revocationGateToken = '1'.repeat(43);
const revocationGatePrepared = await prepareReviewInviteEmail(revocationGateStore,
  inviteFor(revocationGateToken, revocationGateRecipient, {
    preview_manifest_sha256: sha('a'),
    preview_content_sha256: sha('b'),
    preview_source_commit_sha: 'c'.repeat(40),
  }), env, { clock: () => new Date(now) });
await reserveReviewEmailSend(revocationGateStore, {
  invite_token: revocationGateToken, recipient_email: revocationGateRecipient,
}, env, { clock: () => new Date(at(500)) });
const revocationGateComplaint = signedReceipt(receiptFor(revocationGatePrepared,
  'checkout-revocation-gate', 'complained', { event_at: at(1_000), issued_at: at(2_000) }));
let revocationAttempts = 0;
const expiryAdapter = async (_store, suppression) => {
  revocationAttempts += 1;
  assert.equal(suppression.recipient_email_sha256,
    revocationGatePrepared.invite.recipient_email_sha256);
  assert.equal(suppression.suppression_status, 'complained');
  return revocationAttempts === 1
    ? { complete: false, pending: true, revoked: 0 }
    : { complete: true, pending: false, revoked: 1 };
};
await assert.rejects(acknowledgeReviewEmailReceipt(revocationGateStore,
  revocationGateComplaint.evidence, revocationGateComplaint.signature, env, {
    clock: () => new Date(at(2_000)), expireRecipientCheckouts: expiryAdapter,
  }), /AUTHORITY_CONTENTION/);
assert.equal((await readReviewEmailOutbox(revocationGateStore,
  revocationGatePrepared.outbox.outbox_hmac_sha256, env)).record.state, 'SEND_RESERVED',
'The outbox must not terminalize before Checkout expiry finishes.');
assert.equal(await readReviewEmailRecipientSuppression(revocationGateStore,
  revocationGatePrepared.invite.recipient_email_sha256, env), null,
'The legacy recipient latch must not claim completion before provider expiry.');
assert.equal((await readReviewEmailRecipientControl(revocationGateStore,
  revocationGatePrepared.invite.recipient_email_sha256, env)).record.state, 'SUPPRESSED',
'Pending provider expiry must still leave an immediate fail-closed control latch.');
const alteredStaleComplaint = signedReceipt({
  ...JSON.parse(revocationGateComplaint.evidence),
  provider_event_id: 'event-checkout-revocation-gate-altered',
});
const afterFreshness = REVIEW_EMAIL_RECEIPT_FRESHNESS_MS + 60_000;
await assert.rejects(acknowledgeReviewEmailReceipt(revocationGateStore,
  alteredStaleComplaint.evidence, alteredStaleComplaint.signature, env, {
    clock: () => new Date(at(afterFreshness)), expireRecipientCheckouts: expiryAdapter,
  }), /RECEIPT_STALE/,
'A different stale provider event must not borrow another receipt control latch.');
assert.equal(revocationAttempts, 1,
'A stale changed event must fail before provider reconciliation.');
assert.equal((await acknowledgeReviewEmailReceipt(revocationGateStore,
  revocationGateComplaint.evidence, revocationGateComplaint.signature, env, {
    clock: () => new Date(at(afterFreshness)), expireRecipientCheckouts: expiryAdapter,
  })).state, 'COMPLAINED');
assert.equal((await readReviewInviteForEmail(revocationGateStore,
  revocationGatePrepared.invite.invite_hmac_sha256, env)).record.state, 'REVOKED');
assert.equal(revocationAttempts, 2, 'Webhook retry must resume provider reconciliation idempotently.');

// An initial invite whose outbox was never reserved can be replaced after
// expiry. The durable renewal plan contains only HMACs; only the caller keeps
// the fresh token needed to form and send the replacement URL.
const initialRenewalStore = new FakeStore();
const initialRenewalRecipient = 'initial-renewal@example.com';
const expiredInitialToken = 'q'.repeat(43);
const freshInitialToken = 'r'.repeat(43);
const expiredInitialPrepared = await prepareReviewInviteEmail(initialRenewalStore,
  inviteFor(expiredInitialToken, initialRenewalRecipient, { preview_manifest_sha256: sha('a') }), env,
  { clock: () => new Date(now) });
const renewalAt = 7 * 24 * 60 * 60_000 + 1_000;
await assert.rejects(reserveReviewEmailSend(initialRenewalStore, {
  invite_token: expiredInitialToken, recipient_email: initialRenewalRecipient,
}, env, { clock: () => new Date(at(renewalAt)) }), /OUTBOX_EXPIRED/);
const freshInitialInput = inviteFor(freshInitialToken, initialRenewalRecipient, {
  expires_at: at(renewalAt + 7 * 24 * 60 * 60_000),
  preview_manifest_sha256: sha('a'),
});
const initialRenewed = await renewExpiredReadyReviewEmail(initialRenewalStore,
  expiredInitialPrepared.invite.invite_hmac_sha256, freshInitialInput, env,
  { clock: () => new Date(at(renewalAt)) });
assert.equal(initialRenewed.idempotent_replay, false);
assert.equal(initialRenewed.outbox.state, 'READY');
assert.notEqual(initialRenewed.invite.invite_hmac_sha256,
  expiredInitialPrepared.invite.invite_hmac_sha256);
const initialRenewalLink = await readReviewEmailRenewal(initialRenewalStore,
  expiredInitialPrepared.invite.invite_hmac_sha256, env);
assert.equal(initialRenewalLink.record.state, 'READY');
assert.equal(initialRenewalLink.record.replacement_invite_hmac_sha256,
  initialRenewed.invite.invite_hmac_sha256);
const renewalWrites = initialRenewalStore.writes.length;
assert.equal((await renewExpiredReadyReviewEmail(initialRenewalStore,
  expiredInitialPrepared.invite.invite_hmac_sha256, freshInitialInput, env,
  { clock: () => new Date(at(renewalAt + 500)) })).idempotent_replay, true);
assert.equal(initialRenewalStore.writes.length, renewalWrites,
  'An exact renewal replay must not rewrite the plan, invite, or outbox.');
await reserveReviewEmailSend(initialRenewalStore, {
  invite_token: freshInitialToken, recipient_email: initialRenewalRecipient,
}, env, { clock: () => new Date(at(renewalAt + 1_000)) });
const renewedInitialDelivery = signedReceipt(receiptFor(initialRenewed, 'initial-renewed-delivery', 'delivered', {
  event_at: at(renewalAt + 2_000), issued_at: at(renewalAt + 3_000),
}));
await acknowledgeReviewEmailReceipt(initialRenewalStore, renewedInitialDelivery.evidence,
  renewedInitialDelivery.signature, env, { clock: () => new Date(at(renewalAt + 3_000)) });
assert.doesNotReject(exchangeReviewInvite(initialRenewalStore, freshInitialToken, env, {
  clock: () => new Date(at(renewalAt + 4_000)), randomBytes: () => Buffer.alloc(32, 29),
}));
const durableInitialRenewal = JSON.stringify([...initialRenewalStore.values.entries()]);
assert.equal(durableInitialRenewal.includes(freshInitialToken), false);
assert.equal(durableInitialRenewal.includes(initialRenewalRecipient), false);

// The same contract renews an expired unsent revision successor without
// increasing its revision round, and atomically relinks its predecessor.
const successorRenewalStore = new FakeStore();
const successorRenewalRecipient = 'successor-renewal@example.com';
const renewalSourceToken = 's'.repeat(43);
const expiredSuccessorToken = 't'.repeat(43);
const freshSuccessorToken = 'u'.repeat(43);
const renewalSource = await prepareReviewInviteEmail(successorRenewalStore,
  inviteFor(renewalSourceToken, successorRenewalRecipient, { preview_manifest_sha256: sha('b') }), env,
  { clock: () => new Date(now) });
await reserveReviewEmailSend(successorRenewalStore, {
  invite_token: renewalSourceToken, recipient_email: successorRenewalRecipient,
}, env, { clock: () => new Date(now) });
const renewalSourceDelivery = signedReceipt(receiptFor(renewalSource,
  'successor-renewal-source-delivery'));
await acknowledgeReviewEmailReceipt(successorRenewalStore, renewalSourceDelivery.evidence,
  renewalSourceDelivery.signature, env, { clock: () => new Date(at(2_000)) });
const renewalSourceSession = await exchangeReviewInvite(successorRenewalStore, renewalSourceToken, env, {
  clock: () => new Date(at(3_000)), randomBytes: () => Buffer.alloc(32, 30),
});
const renewalSourceStatus = await readReviewStatus(successorRenewalStore,
  renewalSourceSession.session_token, env, new Date(at(3_000)));
await decideReview(successorRenewalStore, renewalSourceSession.session_token, {
  action: 'REQUEST_CHANGES',
  expected_revision: renewalSourceStatus.record_revision,
  idempotency_key: '55555555-5555-4555-8555-555555555555',
  revision_notes: 'Replace the service headline and shorten the supporting copy for the final preview.',
}, env, { clock: () => new Date(at(4_000)) });
const successorOverrides = {
  prior_invite_hmac_sha256: renewalSource.invite.invite_hmac_sha256,
  preview_content_sha256: sha('c'),
  preview_manifest_sha256: sha('d'),
  preview_source_commit_sha: '4'.repeat(40),
};
const expiredSuccessor = await prepareReviewInviteEmail(successorRenewalStore,
  inviteFor(expiredSuccessorToken, successorRenewalRecipient, successorOverrides), env,
  { clock: () => new Date(at(5_000)) });
const freshSuccessorInput = inviteFor(freshSuccessorToken, successorRenewalRecipient, {
  ...successorOverrides,
  expires_at: at(renewalAt + 7 * 24 * 60 * 60_000),
});
const renewedSuccessor = await renewExpiredReadyReviewEmail(successorRenewalStore,
  expiredSuccessor.invite.invite_hmac_sha256, freshSuccessorInput, env,
  { clock: () => new Date(at(renewalAt)) });
assert.equal(renewedSuccessor.invite.revision_round, 1);
assert.equal((await readReviewInviteForEmail(successorRenewalStore,
  renewalSource.invite.invite_hmac_sha256, env)).record.successor_invite_hmac_sha256,
renewedSuccessor.invite.invite_hmac_sha256);
await reserveReviewEmailSend(successorRenewalStore, {
  invite_token: freshSuccessorToken, recipient_email: successorRenewalRecipient,
}, env, { clock: () => new Date(at(renewalAt + 1_000)) });
const renewedSuccessorDelivery = signedReceipt(receiptFor(renewedSuccessor,
  'successor-renewed-delivery', 'delivered', {
    event_at: at(renewalAt + 2_000), issued_at: at(renewalAt + 3_000),
  }));
await acknowledgeReviewEmailReceipt(successorRenewalStore, renewedSuccessorDelivery.evidence,
  renewedSuccessorDelivery.signature, env, { clock: () => new Date(at(renewalAt + 3_000)) });
assert.doesNotReject(exchangeReviewInvite(successorRenewalStore, freshSuccessorToken, env, {
  clock: () => new Date(at(renewalAt + 4_000)), randomBytes: () => Buffer.alloc(32, 31),
}));

assert.match(reviewEmailOutboxKey(prepared.outbox.outbox_hmac_sha256), /^review-email-outbox\/[a-f0-9]{64}$/);
assert.equal(reviewInviteHmac(token, env), prepared.invite.invite_hmac_sha256);

console.log('Review email outbox contract passed.');
