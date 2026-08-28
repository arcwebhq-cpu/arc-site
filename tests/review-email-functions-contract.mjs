import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import acknowledgeRouteHandler, { config as acknowledgeConfig } from '../netlify/functions/review-email-ack.mjs';
import prepareRouteHandler, { config as prepareConfig } from '../netlify/functions/review-email-prepare.mjs';
import reserveRouteHandler, { config as reserveConfig } from '../netlify/functions/review-email-reserve.mjs';
import {
  reviewEmailInternalApiConfiguration,
  signReviewEmailInternalRequest,
} from '../netlify/lib/review-email-http-core.mjs';
import {
  reviewEmailReceiptContract,
  reviewEmailRecipientSha256,
} from '../netlify/lib/review-email-outbox-core.mjs';
import { exchangeReviewInvite } from '../netlify/lib/review-flow-core.mjs';

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const output = JSON.stringify(value);
  if (output === undefined) throw new TypeError('Canonical JSON does not support undefined.');
  return output;
}

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `function-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
}

const now = new Date('2026-08-27T22:00:00.000Z');
const sha = character => character.repeat(64);
const sha256Hex = value => createHash('sha256').update(value).digest('hex');
const recipientEmail = 'function-customer@example.com';
const inviteToken = 'F'.repeat(43);
const sourceReference = sha256Hex('function-authoritative-source');
const managedEnv = {
  ARC_REVIEW_PORTAL_ENABLED: 'true',
  ARC_REVIEW_CHECKOUT_ENABLED: 'false',
  ARC_REVIEW_INVITE_HMAC_SECRET: 'function-review-invite-secret-0123456789abcdef',
  ARC_REVIEW_SESSION_HMAC_SECRET: 'function-review-session-secret-0123456789abcdef',
  ARC_REVIEW_RECORD_HMAC_SECRET: 'function-review-record-secret-0123456789abcdef',
  ARC_REVIEW_DECISION_HMAC_SECRET: 'function-review-decision-secret-0123456789abcdef',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
  ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
  ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET: 'function-email-outbox-secret-0123456789abcdef',
  ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET: 'function-email-receipt-secret-0123456789abcdef',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
  ARC_REVIEW_EMAIL_INTERNAL_API_ENABLED: 'true',
  ARC_REVIEW_EMAIL_INTERNAL_API_SECRET: 'function-email-internal-api-secret-0123456789abcdef',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'function-retention-fence-secret-0123456789abcdef',
  ARC_OPERATIONS_AUDIT_ENABLED: 'true',
  ARC_OPERATIONS_AUDIT_SECRET: 'function-operations-audit-secret-0123456789abcdef',
  ARC_OPERATIONS_ALERT_HMAC_SECRET: 'function-operations-alert-secret-0123456789abcdef',
  ARC_EMAIL_CLAIM_BINDING_SECRET: 'function-email-claim-binding-secret-0123456789abcdef',
  ARC_HANDOFF_STATE_SECRET: 'function-handoff-state-secret-0123456789abcdef',
};
const previous = Object.fromEntries(Object.keys(managedEnv).map(key => [key, process.env[key]]));
Object.assign(process.env, managedEnv);

const invite = {
  invite_token: inviteToken,
  brief_sha256: sha('1'),
  expires_at: new Date(now.getTime() + 7 * 24 * 60 * 60_000).toISOString(),
  page_bindings: [
    'about/index.html', 'contact/index.html', 'index.html', 'process/index.html', 'services/index.html',
  ].map((path, index) => ({ path, sha256: String(index + 2).repeat(64) })),
  preview_content_sha256: sha('7'),
  preview_manifest_sha256: sha('8'),
  preview_source_commit_sha: 'a'.repeat(40),
  preview_source_repository: 'arcwebhq-cpu/arc-previews',
  preview_url: 'https://arcwebhq-cpu.github.io/arc-previews/function-preview/',
  prior_invite_hmac_sha256: null,
  recipient_email_sha256: reviewEmailRecipientSha256(recipientEmail),
  scope_version: 'arc-fixed-five-page-offer-v1',
};

function requestFor(path, value, options = {}) {
  const body = JSON.stringify(value);
  const timestamp = options.timestamp || now.toISOString();
  const signature = options.signature || signReviewEmailInternalRequest({
    body, method: 'POST', path, timestamp,
  }, process.env.ARC_REVIEW_EMAIL_INTERNAL_API_SECRET);
  return new Request(`https://arcweb.onl${path}`, {
    method: 'POST',
    headers: {
      'content-type': options.contentType || 'application/json',
      'x-arc-review-email-signature': signature,
      'x-arc-review-email-timestamp': timestamp,
      ...(options.origin ? { origin: options.origin } : {}),
    },
    body,
  });
}

assert.deepEqual([prepareConfig.path, reserveConfig.path, acknowledgeConfig.path], [
  '/api/internal/review-email/prepare',
  '/api/internal/review-email/reserve',
  '/api/internal/review-email/ack',
]);
assert.equal(reviewEmailInternalApiConfiguration({}).enabled, false);
assert.equal(reviewEmailInternalApiConfiguration(managedEnv).enabled, true);
assert.equal(reviewEmailInternalApiConfiguration({
  ...managedEnv,
  ARC_REVIEW_EMAIL_INTERNAL_API_SECRET: managedEnv.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
}).enabled, false, 'Internal request auth must not reuse a durable-record secret.');

const sources = await Promise.all([
  '../netlify/functions/review-email-prepare.mjs',
  '../netlify/functions/review-email-reserve.mjs',
  '../netlify/functions/review-email-ack.mjs',
  '../netlify/lib/review-email-http-core.mjs',
].map(path => readFile(new URL(path, import.meta.url), 'utf8')));
for (const source of sources) {
  assert.doesNotMatch(source, /\bfetch\s*\(/,
    'The provider-neutral internal surface must not perform an email provider send.');
}
assert.match(sources[3], /ARC_REVIEW_EMAIL_INTERNAL_API_ENABLED/);
assert.match(sources[3], /x-arc-review-email-signature/);
assert.match(sources[3], /x-arc-review-email-timestamp/);

const store = new FakeStore();
const retentionFenceStore = new FakeStore();
const retentionFenceAlertStore = new FakeStore();
const fencedHandler = (handler) => (request, context = {}) => {
  const fencedContext = Object.create(context);
  fencedContext.retentionFenceStore = retentionFenceStore;
  fencedContext.retentionFenceAlertStore = retentionFenceAlertStore;
  return handler(request, fencedContext);
};
const acknowledgeHandler = fencedHandler(acknowledgeRouteHandler);
const prepareHandler = fencedHandler(prepareRouteHandler);
const reserveHandler = fencedHandler(reserveRouteHandler);
process.env.ARC_REVIEW_EMAIL_INTERNAL_API_ENABLED = 'false';
assert.equal((await prepareHandler(requestFor('/api/internal/review-email/prepare', { invite }), {
  reviewStore: store, clock: () => new Date(now),
})).status, 503, 'The production endpoint must default closed.');
process.env.ARC_REVIEW_EMAIL_INTERNAL_API_ENABLED = 'true';

assert.equal((await prepareHandler(requestFor('/api/internal/review-email/prepare', { invite }, {
  signature: '0'.repeat(64),
}), { reviewStore: store, clock: () => new Date(now) })).status, 401);
assert.equal((await prepareHandler(requestFor('/api/internal/review-email/prepare', { invite }, {
  timestamp: new Date(now.getTime() - 61_000).toISOString(),
}), { reviewStore: store, clock: () => new Date(now) })).status, 401);
assert.equal((await prepareHandler(requestFor('/api/internal/review-email/prepare', { invite }, {
  origin: 'https://arcweb.onl',
}), { reviewStore: store, clock: () => new Date(now) })).status, 401,
'Browser-originated requests must not reach this internal surface.');

const prepareResponse = await prepareHandler(requestFor('/api/internal/review-email/prepare', {
  invite,
  source_reference_hmac_sha256: sourceReference,
}), {
  reviewStore: store, clock: () => new Date(now),
});
assert.equal(prepareResponse.status, 200);
assert.equal(prepareResponse.headers.get('cache-control'), 'no-store');
const prepared = await prepareResponse.json();
assert.equal(prepared.prepared, true);
assert.equal(prepared.renewed, false);
assert.match(prepared.invite_hmac_sha256, /^[a-f0-9]{64}$/);
assert.match(prepared.outbox_hmac_sha256, /^[a-f0-9]{64}$/);
assert.equal(JSON.stringify(prepared).includes(inviteToken), false);
assert.equal(JSON.stringify(prepared).includes(recipientEmail), false);

const claimedReadyResponse = await reserveHandler(requestFor('/api/internal/review-email/reserve', {
  claim_next: true,
}), { reviewStore: store, clock: () => new Date(now) });
assert.equal(claimedReadyResponse.status, 200);
const claimedReady = await claimedReadyResponse.json();
assert.equal(claimedReady.claimed, true);
assert.equal(claimedReady.state, 'READY');
assert.equal(claimedReady.source_reference_hmac_sha256, sourceReference,
  'Claim-next must return the caller-provided authoritative reservation lookup reference.');
assert.equal(claimedReady.renewal_required, false);

const reserveResponse = await reserveHandler(requestFor('/api/internal/review-email/reserve', {
  invite_token: inviteToken,
  recipient_email: recipientEmail,
}), { reviewStore: store, clock: () => new Date(now) });
assert.equal(reserveResponse.status, 200);
const reserved = await reserveResponse.json();
assert.equal(reserved.recipient_email, recipientEmail);
assert.equal(reserved.review_url, `https://arcweb.onl/review/#invite=${inviteToken}`);
assert.match(reserved.provider_idempotency_key, /^arc_review_email_[a-f0-9]{64}$/);

const receipt = {
  schema: reviewEmailReceiptContract.schema,
  version: reviewEmailReceiptContract.version,
  outbox_hmac_sha256: prepared.outbox_hmac_sha256,
  invite_hmac_sha256: prepared.invite_hmac_sha256,
  recipient_email_sha256: invite.recipient_email_sha256,
  preview_manifest_sha256: invite.preview_manifest_sha256,
  provider: 'provider-test',
  provider_account_hmac_sha256: sha('a'),
  provider_event_id: 'function-provider-event',
  provider_message_id: 'function-provider-message',
  event_type: 'message.delivered',
  delivery_status: 'delivered',
  event_at: new Date(now.getTime() + 1_000).toISOString(),
  issued_at: new Date(now.getTime() + 2_000).toISOString(),
};
const evidence = canonicalJson(receipt);
const receiptSignature = createHmac('sha256', process.env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET)
  .update(reviewEmailReceiptContract.signaturePrefix + evidence).digest('hex');
const acknowledgeResponse = await acknowledgeHandler(requestFor('/api/internal/review-email/ack', {
  delivery_receipt_evidence: evidence,
  delivery_receipt_evidence_hmac_sha256: receiptSignature,
}, { timestamp: new Date(now.getTime() + 2_000).toISOString() }), {
  reviewStore: store, clock: () => new Date(now.getTime() + 2_000),
});
assert.equal(acknowledgeResponse.status, 200);
assert.deepEqual(await acknowledgeResponse.json(), {
  acknowledged: true,
  delivery_status: 'delivered',
  idempotent_replay: false,
  outbox_hmac_sha256: prepared.outbox_hmac_sha256,
  state: 'DELIVERED',
});
const emptyClaim = await reserveHandler(requestFor('/api/internal/review-email/reserve', {
  claim_next: true,
}, { timestamp: new Date(now.getTime() + 2_000).toISOString() }), {
  reviewStore: store, clock: () => new Date(now.getTime() + 2_000),
});
assert.deepEqual(await emptyClaim.json(), { claimed: false, found: false },
  'Delivered work must leave the durable pending index.');

// Full outage recovery: the worker is absent until a READY job expires.
// Claim-next still discovers it without key enumeration, returns only the
// authoritative source reference, and the signed prepare route replans a
// fresh token before reserve/delivery/exchange.
const outageToken = 'G'.repeat(43);
const renewedOutageToken = 'H'.repeat(43);
const outageSourceReference = sha256Hex('function-outage-authoritative-source');
const outageInvite = {
  ...invite,
  invite_token: outageToken,
  expires_at: new Date(now.getTime() + 10_000).toISOString(),
  preview_content_sha256: sha('b'),
  preview_manifest_sha256: sha('c'),
  preview_source_commit_sha: 'b'.repeat(40),
};
const outagePrepare = await prepareHandler(requestFor('/api/internal/review-email/prepare', {
  invite: outageInvite,
  source_reference_hmac_sha256: outageSourceReference,
}, { timestamp: new Date(now.getTime() + 3_000).toISOString() }), {
  reviewStore: store, clock: () => new Date(now.getTime() + 3_000),
});
assert.equal(outagePrepare.status, 200);
const outagePrepared = await outagePrepare.json();
const expiredClaimResponse = await reserveHandler(requestFor('/api/internal/review-email/reserve', {
  claim_next: true,
}, { timestamp: new Date(now.getTime() + 11_000).toISOString() }), {
  reviewStore: store, clock: () => new Date(now.getTime() + 11_000),
});
const expiredClaim = await expiredClaimResponse.json();
assert.equal(expiredClaim.claimed, true);
assert.equal(expiredClaim.state, 'READY');
assert.equal(expiredClaim.renewal_required, true);
assert.equal(expiredClaim.source_reference_hmac_sha256, outageSourceReference);
const renewedOutageInvite = {
  ...outageInvite,
  invite_token: renewedOutageToken,
  expires_at: new Date(now.getTime() + 7 * 24 * 60 * 60_000).toISOString(),
};
const renewedOutageResponse = await prepareHandler(requestFor('/api/internal/review-email/prepare', {
  invite: renewedOutageInvite,
  replaced_invite_hmac_sha256: outagePrepared.invite_hmac_sha256,
  source_reference_hmac_sha256: outageSourceReference,
}, { timestamp: new Date(now.getTime() + 11_000).toISOString() }), {
  reviewStore: store, clock: () => new Date(now.getTime() + 11_000),
});
assert.equal(renewedOutageResponse.status, 200);
const renewedOutage = await renewedOutageResponse.json();
assert.equal(renewedOutage.renewed, true);
const renewedClaimResponse = await reserveHandler(requestFor('/api/internal/review-email/reserve', {
  claim_next: true,
}, { timestamp: new Date(now.getTime() + 12_000).toISOString() }), {
  reviewStore: store, clock: () => new Date(now.getTime() + 12_000),
});
const renewedClaim = await renewedClaimResponse.json();
assert.equal(renewedClaim.outbox_hmac_sha256, renewedOutage.outbox_hmac_sha256);
assert.equal(renewedClaim.source_reference_hmac_sha256, outageSourceReference);
const outageReserve = await reserveHandler(requestFor('/api/internal/review-email/reserve', {
  invite_token: renewedOutageToken,
  recipient_email: recipientEmail,
}, { timestamp: new Date(now.getTime() + 12_000).toISOString() }), {
  reviewStore: store, clock: () => new Date(now.getTime() + 12_000),
});
assert.equal(outageReserve.status, 200);
const outageReceipt = {
  ...receipt,
  outbox_hmac_sha256: renewedOutage.outbox_hmac_sha256,
  invite_hmac_sha256: renewedOutage.invite_hmac_sha256,
  preview_manifest_sha256: outageInvite.preview_manifest_sha256,
  provider_event_id: 'function-outage-provider-event',
  provider_message_id: 'function-outage-provider-message',
  event_at: new Date(now.getTime() + 13_000).toISOString(),
  issued_at: new Date(now.getTime() + 14_000).toISOString(),
};
const outageEvidence = canonicalJson(outageReceipt);
const outageReceiptSignature = createHmac('sha256', process.env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET)
  .update(reviewEmailReceiptContract.signaturePrefix + outageEvidence).digest('hex');
const outageAck = await acknowledgeHandler(requestFor('/api/internal/review-email/ack', {
  delivery_receipt_evidence: outageEvidence,
  delivery_receipt_evidence_hmac_sha256: outageReceiptSignature,
}, { timestamp: new Date(now.getTime() + 14_000).toISOString() }), {
  reviewStore: store, clock: () => new Date(now.getTime() + 14_000),
});
assert.equal(outageAck.status, 200);
await assert.doesNotReject(exchangeReviewInvite(store, renewedOutageToken, process.env, {
  clock: () => new Date(now.getTime() + 15_000),
  randomBytes: () => Buffer.alloc(32, 33),
}));

// The authenticated ACK route must pass negative receipts through the
// provider-revocation hook before reporting terminal suppression.
const complaintRecipient = 'function-complaint@example.com';
const complaintToken = 'J'.repeat(43);
const complaintInvite = {
  ...invite,
  invite_token: complaintToken,
  recipient_email_sha256: reviewEmailRecipientSha256(complaintRecipient),
  preview_content_sha256: sha('d'),
  preview_manifest_sha256: sha('e'),
  preview_source_commit_sha: 'd'.repeat(40),
};
const complaintPrepareResponse = await prepareHandler(requestFor('/api/internal/review-email/prepare', {
  invite: complaintInvite,
  source_reference_hmac_sha256: sha256Hex('function-complaint-source'),
}, { timestamp: new Date(now.getTime() + 16_000).toISOString() }), {
  reviewStore: store, clock: () => new Date(now.getTime() + 16_000),
});
const complaintPrepared = await complaintPrepareResponse.json();
assert.equal(complaintPrepareResponse.status, 200);
assert.equal((await reserveHandler(requestFor('/api/internal/review-email/reserve', {
  invite_token: complaintToken,
  recipient_email: complaintRecipient,
}, { timestamp: new Date(now.getTime() + 17_000).toISOString() }), {
  reviewStore: store, clock: () => new Date(now.getTime() + 17_000),
})).status, 200);
const complaintReceipt = {
  ...receipt,
  outbox_hmac_sha256: complaintPrepared.outbox_hmac_sha256,
  invite_hmac_sha256: complaintPrepared.invite_hmac_sha256,
  recipient_email_sha256: complaintInvite.recipient_email_sha256,
  preview_manifest_sha256: complaintInvite.preview_manifest_sha256,
  provider_event_id: 'function-complaint-provider-event',
  provider_message_id: 'function-complaint-provider-message',
  event_type: 'message.complained',
  delivery_status: 'complained',
  event_at: new Date(now.getTime() + 18_000).toISOString(),
  issued_at: new Date(now.getTime() + 19_000).toISOString(),
};
const complaintEvidence = canonicalJson(complaintReceipt);
const complaintSignature = createHmac('sha256', process.env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET)
  .update(reviewEmailReceiptContract.signaturePrefix + complaintEvidence).digest('hex');
let expiryHookCalls = 0;
const expiryHook = async (_store, suppression) => {
  expiryHookCalls += 1;
  assert.equal(suppression.suppression_status, 'complained');
  return expiryHookCalls === 1
    ? { complete: false, pending: true, revoked: 0 }
    : { complete: true, pending: false, revoked: 1 };
};
const pendingComplaintAck = await acknowledgeHandler(requestFor('/api/internal/review-email/ack', {
  delivery_receipt_evidence: complaintEvidence,
  delivery_receipt_evidence_hmac_sha256: complaintSignature,
}, { timestamp: new Date(now.getTime() + 19_000).toISOString() }), {
  reviewStore: store,
  clock: () => new Date(now.getTime() + 19_000),
  expireRecipientCheckouts: expiryHook,
});
assert.equal(pendingComplaintAck.status, 503,
'Transient authority/provider reconciliation must use a retryable HTTP status.');
assert.deepEqual(await pendingComplaintAck.json(), { error: 'review_email_retry' });
const complaintAck = await acknowledgeHandler(requestFor('/api/internal/review-email/ack', {
  delivery_receipt_evidence: complaintEvidence,
  delivery_receipt_evidence_hmac_sha256: complaintSignature,
}, { timestamp: new Date(now.getTime() + 140_000).toISOString() }), {
  reviewStore: store,
  clock: () => new Date(now.getTime() + 140_000),
  expireRecipientCheckouts: expiryHook,
});
assert.equal(complaintAck.status, 200, await complaintAck.clone().text());
assert.equal((await complaintAck.json()).state, 'COMPLAINED');
assert.equal(expiryHookCalls, 2);
const durable = JSON.stringify([...store.values.entries()]);
assert.equal(durable.includes(inviteToken), false);
assert.equal(durable.includes(recipientEmail), false);
assert.equal(durable.includes(receipt.provider_event_id), false);
assert.equal(durable.includes(receipt.provider_message_id), false);

for (const [key, value] of Object.entries(previous)) {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

console.log('Review email internal Function contract passed.');
