import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  REVIEW_INVITE_SCHEMA,
  REVIEW_EMAIL_DELIVERY_BINDING_SCHEMA,
  REVIEW_MAX_REVISION_ROUNDS,
  authorizeReviewSession,
  createApprovedCheckout,
  decideReview,
  exchangeReviewInvite,
  issueReviewInvite,
  readReviewStatus,
  readReviewRecipientSuppressionForAuthorization,
  reviewInviteKey,
  reviewPortalConfiguration,
  signReviewEmailDeliveryBinding,
} from '../netlify/lib/review-flow-core.mjs';
import reviewCheckoutHandler, { config as checkoutConfig } from '../netlify/functions/review-checkout.mjs';
import reviewDecisionHandler, { config as decisionConfig } from '../netlify/functions/review-decision.mjs';
import reviewExchangeHandler, { config as exchangeConfig } from '../netlify/functions/review-exchange.mjs';
import reviewStatusHandler, { config as statusConfig } from '../netlify/functions/review-status.mjs';

class FakeStore {
  constructor() {
    this.values = new Map();
    this.sequence = 0;
  }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `review-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
}

const now = new Date('2026-08-27T20:00:00.000Z');
const at = (milliseconds) => new Date(now.getTime() + milliseconds).toISOString();
const sha = (character) => character.repeat(64);
const env = {
  ARC_REVIEW_PORTAL_ENABLED: 'true',
  ARC_REVIEW_CHECKOUT_ENABLED: 'true',
  ARC_REVIEW_INVITE_HMAC_SECRET: 'review-invite-secret-unique-0123456789abcdef',
  ARC_REVIEW_SESSION_HMAC_SECRET: 'review-session-secret-unique-0123456789abcdef',
  ARC_REVIEW_RECORD_HMAC_SECRET: 'review-record-secret-unique-0123456789abcdef',
  ARC_REVIEW_DECISION_HMAC_SECRET: 'review-decision-secret-unique-0123456789abcdef',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'review-flow-retention-fence-secret-unique-0123456789abcdef',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
};
const initialToken = 'A'.repeat(43);
const firstRevisionToken = 'B'.repeat(43);
const secondRevisionToken = 'C'.repeat(43);
const binding = {
  brief_sha256: sha('1'),
  email_delivery_receipt_sha256: sha('2'),
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
  recipient_email_sha256: sha('b'),
  scope_version: 'arc-fixed-five-page-offer-v1',
};

assert.equal(reviewPortalConfiguration({}).enabled, false, 'The portal must default off.');
assert.equal(reviewPortalConfiguration(env).enabled, true);
assert.equal(reviewPortalConfiguration({
  ...env,
  ARC_REVIEW_SESSION_HMAC_SECRET: env.ARC_REVIEW_INVITE_HMAC_SECRET,
}).enabled, false, 'Review secrets must be byte-distinct.');
for (const credentialName of [
  'ARC_REVIEW_INVITE_HMAC_SECRET',
  'ARC_REVIEW_SESSION_HMAC_SECRET',
  'ARC_REVIEW_RECORD_HMAC_SECRET',
  'ARC_REVIEW_DECISION_HMAC_SECRET',
]) {
  assert.equal(reviewPortalConfiguration({
    ...env,
    ARC_ROTATED_CREDENTIAL_V2: env[credentialName],
  }).enabled, false, `An arbitrary alias must not reuse ${credentialName}.`);
}
const emailEnv = {
  ...env,
  ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
  ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET: 'review-email-outbox-secret-unique-0123456789abcdef',
  ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET: 'review-email-receipt-secret-unique-0123456789abcdef',
};
await assert.rejects(readReviewRecipientSuppressionForAuthorization(
  new FakeStore(), sha('b'), {
    ...emailEnv,
    ARC_ROTATED_CREDENTIAL_V2: emailEnv.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
  },
), /OUTBOX_DISABLED/, 'A renamed outbox credential must fail before recipient-state access.');
const deliveryBinding = {
  schema: REVIEW_EMAIL_DELIVERY_BINDING_SCHEMA,
  invite_hmac_sha256: sha('1'),
  outbox_hmac_sha256: sha('2'),
  recipient_email_sha256: sha('3'),
  preview_manifest_sha256: sha('4'),
  delivery_receipt_sha256: sha('5'),
  delivery_status: 'delivered',
};
assert.throws(() => signReviewEmailDeliveryBinding(deliveryBinding, {
  ...emailEnv,
  ARC_ROTATED_CREDENTIAL_V2: emailEnv.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET,
}), /OUTBOX_DISABLED/, 'A renamed receipt credential must fail before signing delivery authority.');

const store = new FakeStore();
const initial = await issueReviewInvite(store, {
  ...binding,
  invite_token: initialToken,
}, env, { clock: () => new Date(now) });
assert.equal(initial.record.schema, REVIEW_INVITE_SCHEMA);
assert.equal(initial.record.revision_round, 0);
assert.equal(initial.record.state, 'OPEN');
assert.equal(initial.record.email_delivery_receipt_sha256, binding.email_delivery_receipt_sha256,
  'Legacy pre-bound receipt records remain compatible only when email outbox mode is not enabled.');
assert.equal(initial.record.email_delivery_binding_mode, 'legacy-prebound');
assert.equal(initial.record.email_delivery_outbox_hmac_sha256, null);
assert.equal(JSON.stringify([...store.values.values()]).includes(initialToken), false,
  'Raw invite credentials must never be stored.');
await assert.rejects(issueReviewInvite(store, {
  ...binding,
  invite_token: initialToken,
  preview_manifest_sha256: sha('c'),
}, env, { clock: () => new Date(now) }), /INVITE_CONFLICT/);

const legacyGateStore = new FakeStore();
await issueReviewInvite(legacyGateStore, { ...binding, invite_token: 'L'.repeat(43) }, env,
  { clock: () => new Date(now) });
await assert.rejects(exchangeReviewInvite(legacyGateStore, 'L'.repeat(43), {
  ...env, ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
}, { clock: () => new Date(now), randomBytes: () => Buffer.alloc(32, 12) }), /DELIVERY_UNCONFIRMED/,
  'Enabling two-phase outbox mode must not trust a legacy pre-bound digest.');

const exchanged = await exchangeReviewInvite(store, initialToken, env, {
  clock: () => new Date(now), randomBytes: () => Buffer.alloc(32, 13),
});
assert.doesNotMatch(exchanged.session_token, new RegExp(initialToken));
assert.equal(JSON.stringify([...store.values.values()]).includes(exchanged.session_token), false,
  'Raw review sessions must never be stored.');
const exchangedReplay = await exchangeReviewInvite(store, initialToken, env, {
  clock: () => new Date(now), randomBytes: () => Buffer.alloc(32, 14),
});
assert.deepEqual(exchangedReplay, exchanged,
  'An exact exchange retry must reconstruct the same session after an ambiguous response.');

const authorized = await authorizeReviewSession(store, exchanged.session_token, env, new Date(now));
assert.equal(authorized.record.state, 'OPEN');
assert.equal((await readReviewStatus(store, exchanged.session_token, env, new Date(now))).can_request_changes, true);
await assert.rejects(authorizeReviewSession(store, `${exchanged.session_token}x`, env, new Date(now)), /SESSION_INVALID/);

const changes = await decideReview(store, exchanged.session_token, {
  action: 'REQUEST_CHANGES',
  expected_revision: authorized.record.record_revision,
  idempotency_key: '11111111-1111-4111-8111-111111111111',
  revision_notes: 'Use a shorter headline and move the financing details below the quote form.',
}, env, { clock: () => new Date(now) });
assert.equal(changes.state, 'REVISION_REQUESTED');
assert.equal(changes.idempotent_replay, false);
const changesReplay = await decideReview(store, exchanged.session_token, {
  action: 'REQUEST_CHANGES',
  expected_revision: authorized.record.record_revision,
  idempotency_key: '22222222-2222-4222-8222-222222222222',
  revision_notes: 'Use a shorter headline and move the financing details below the quote form.',
}, env, { clock: () => new Date(now) });
assert.equal(changesReplay.idempotent_replay, true, 'A semantically exact retry must converge.');
await assert.rejects(decideReview(store, exchanged.session_token, {
  action: 'REQUEST_CHANGES',
  expected_revision: authorized.record.record_revision,
  idempotency_key: '33333333-3333-4333-8333-333333333333',
  revision_notes: 'A different revision list must not overwrite the first one.',
}, env, { clock: () => new Date(now) }), /DECISION_CONFLICT/);

const firstRevision = await issueReviewInvite(store, {
  ...binding,
  invite_token: firstRevisionToken,
  prior_invite_hmac_sha256: initial.record.invite_hmac_sha256,
  preview_content_sha256: sha('c'),
  preview_manifest_sha256: sha('d'),
  preview_source_commit_sha: 'b'.repeat(40),
  email_delivery_receipt_sha256: sha('e'),
}, env, { clock: () => new Date(now) });
assert.equal(firstRevision.record.revision_round, 1);
assert.equal((await authorizeReviewSession(store, exchanged.session_token, env, new Date(now))).record.state,
  'REVISION_SUPERSEDED', 'A new immutable preview must invalidate the old invite.');

const firstExchange = await exchangeReviewInvite(store, firstRevisionToken, env, {
  clock: () => new Date(now), randomBytes: () => Buffer.alloc(32, 15),
});
const firstStatus = await readReviewStatus(store, firstExchange.session_token, env, new Date(now));
await decideReview(store, firstExchange.session_token, {
  action: 'REQUEST_CHANGES', expected_revision: firstStatus.record_revision,
  idempotency_key: '44444444-4444-4444-8444-444444444444',
  revision_notes: 'Use the supplied team photo and change the primary service order.',
}, env, { clock: () => new Date(now) });

const secondRevision = await issueReviewInvite(store, {
  ...binding,
  invite_token: secondRevisionToken,
  prior_invite_hmac_sha256: firstRevision.record.invite_hmac_sha256,
  preview_content_sha256: sha('f'),
  preview_manifest_sha256: sha('0'),
  preview_source_commit_sha: 'c'.repeat(40),
  email_delivery_receipt_sha256: sha('a'),
}, env, { clock: () => new Date(now) });
assert.equal(secondRevision.record.revision_round, REVIEW_MAX_REVISION_ROUNDS);
const secondExchange = await exchangeReviewInvite(store, secondRevisionToken, env, {
  clock: () => new Date(now), randomBytes: () => Buffer.alloc(32, 16),
});
const secondStatus = await readReviewStatus(store, secondExchange.session_token, env, new Date(now));
assert.equal(secondStatus.can_request_changes, false);
await assert.rejects(decideReview(store, secondExchange.session_token, {
  action: 'REQUEST_CHANGES', expected_revision: secondStatus.record_revision,
  idempotency_key: '55555555-5555-4555-8555-555555555555',
  revision_notes: 'A third revision round must fail closed.',
}, env, { clock: () => new Date(now) }), /REVISION_LIMIT/);

const checkoutObservations = [];
const createCheckout = async (request) => {
  const current = (await store.getWithMetadata(reviewInviteKey(secondRevision.record.invite_hmac_sha256))).data;
  assert.equal(current.state, 'APPROVED', 'Checkout creation must happen only after approval is durable.');
  checkoutObservations.push(structuredClone(request));
  return { url: 'https://checkout.stripe.com/c/pay/cs_test_reviewContract' };
};
const approved = await decideReview(store, secondExchange.session_token, {
  action: 'APPROVE_AND_PAY', expected_revision: secondStatus.record_revision,
  idempotency_key: '66666666-6666-4666-8666-666666666666',
}, env, { clock: () => new Date(now) });
assert.equal(approved.state, 'APPROVED');
assert.equal(checkoutObservations.length, 0, 'The decision request must only make approval durable.');
const approvedReplay = await decideReview(store, secondExchange.session_token, {
  action: 'APPROVE_AND_PAY', expected_revision: secondStatus.record_revision,
  idempotency_key: '77777777-7777-4777-8777-777777777777',
}, env, { clock: () => new Date(now) });
assert.equal(approvedReplay.idempotent_replay, true);
assert.equal(checkoutObservations.length, 0);
const checkout = await createApprovedCheckout(store, secondExchange.session_token, env, {
  clock: () => new Date(now), createCheckout,
});
assert.equal(checkout.checkout_url, 'https://checkout.stripe.com/c/pay/cs_test_reviewContract');
const checkoutReplay = await createApprovedCheckout(store, secondExchange.session_token, env, {
  clock: () => new Date(now), createCheckout,
});
assert.equal(checkoutObservations.length, 2);
assert.equal(checkoutObservations[0].idempotency_key, checkoutObservations[1].idempotency_key,
  'Provider retries must use one deterministic checkout idempotency key.');
assert.equal(checkoutObservations[0].approval_receipt_sha256,
  checkoutObservations[1].approval_receipt_sha256, 'Checkout retries must stay bound to one approval.');
assert.equal(checkoutObservations[0].checkout_expires_at,
  Math.floor(now.getTime() / 1000) + 23 * 60 * 60,
  'A private Checkout Session must expire 23 hours after its durable approval.');
assert.equal(checkoutObservations[0].checkout_expires_at,
  checkoutObservations[1].checkout_expires_at,
  'Checkout retries must preserve the exact approval-bound expiration.');

const unavailableStore = new FakeStore();
const unavailable = await issueReviewInvite(unavailableStore, {
  ...binding, invite_token: 'D'.repeat(43),
}, env, { clock: () => new Date(now) });
const unavailableExchange = await exchangeReviewInvite(unavailableStore, 'D'.repeat(43), env, {
  clock: () => new Date(now), randomBytes: () => Buffer.alloc(32, 17),
});
await assert.rejects(decideReview(unavailableStore, unavailableExchange.session_token, {
  action: 'APPROVE_AND_PAY', expected_revision: unavailable.record.record_revision + 1,
  idempotency_key: '88888888-8888-4888-8888-888888888888',
}, { ...env, ARC_REVIEW_CHECKOUT_ENABLED: 'false' }, { clock: () => new Date(now) }), /CHECKOUT_UNAVAILABLE/);
assert.equal((await authorizeReviewSession(unavailableStore, unavailableExchange.session_token, env, new Date(now))).record.state,
  'OPEN', 'Unavailable checkout must not record approval.');

const persisted = await unavailableStore.getWithMetadata(reviewInviteKey(unavailable.record.invite_hmac_sha256));
persisted.data.preview_manifest_sha256 = sha('f');
unavailableStore.values.set(reviewInviteKey(unavailable.record.invite_hmac_sha256), persisted);
await assert.rejects(authorizeReviewSession(unavailableStore, unavailableExchange.session_token, env, new Date(now)),
  /RECORD_SIGNATURE_INVALID/, 'Changed preview bindings must invalidate the signed invite.');

assert.deepEqual([exchangeConfig.path, statusConfig.path, decisionConfig.path, checkoutConfig.path], [
  '/api/review/exchange', '/api/review/status', '/api/review/decision', '/api/review/checkout',
]);
const reviewEnvironmentKeys = Object.keys(env);
const savedEnvironment = Object.fromEntries(reviewEnvironmentKeys.map(key => [key, process.env[key]]));
for (const key of reviewEnvironmentKeys) delete process.env[key];
assert.equal((await reviewExchangeHandler(new Request('https://arcweb.onl/api/review/exchange', {
  method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://arcweb.onl' },
  body: JSON.stringify({ invite_token: 'E'.repeat(43) }),
}))).status, 503, 'The deployed review endpoints must default off.');
Object.assign(process.env, env);
const handlerStore = new FakeStore();
const retentionFenceStore = new FakeStore();
const routeContext = { retentionFenceStore, retentionFenceClock: () => new Date(now) };
const handlerInvite = await issueReviewInvite(handlerStore, {
  ...binding, invite_token: 'E'.repeat(43),
}, env, { clock: () => new Date(now) });
const wrongOrigin = await reviewExchangeHandler(new Request('https://arcweb.onl/api/review/exchange', {
  method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
  body: JSON.stringify({ invite_token: 'E'.repeat(43) }),
}), { ...routeContext, reviewStore: handlerStore, clock: () => new Date(now), randomBytes: () => Buffer.alloc(32, 18) });
assert.equal(wrongOrigin.status, 403);
const exchangeResponse = await reviewExchangeHandler(new Request('https://arcweb.onl/api/review/exchange', {
  method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://arcweb.onl' },
  body: JSON.stringify({ invite_token: 'E'.repeat(43) }),
}), { ...routeContext, reviewStore: handlerStore, clock: () => new Date(now), randomBytes: () => Buffer.alloc(32, 18) });
assert.equal(exchangeResponse.status, 200);
assert.equal((await exchangeResponse.clone().text()).includes('E'.repeat(43)), false);
const setCookie = exchangeResponse.headers.get('set-cookie');
assert.match(setCookie, /^__Host-arc_review_session=[^;]+; Path=\/; Max-Age=\d+; Secure; HttpOnly; SameSite=Strict$/);
const cookie = setCookie.split(';', 1)[0];
const statusResponse = await reviewStatusHandler(new Request('https://arcweb.onl/api/review/status', {
  headers: { Cookie: cookie },
}), { ...routeContext, reviewStore: handlerStore, clock: () => new Date(now) });
assert.equal(statusResponse.status, 200);
const handlerStatus = await statusResponse.json();
assert.equal(handlerStatus.preview_manifest_sha256, binding.preview_manifest_sha256);
const decisionResponse = await reviewDecisionHandler(new Request('https://arcweb.onl/api/review/decision', {
  method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: 'https://arcweb.onl' },
  body: JSON.stringify({ action: 'APPROVE_AND_PAY', expected_revision: handlerStatus.record_revision,
    idempotency_key: '99999999-9999-4999-8999-999999999999' }),
}), { retentionFenceStore: new FakeStore(), retentionFenceClock: () => new Date(now),
  reviewStore: handlerStore, clock: () => new Date(now) });
assert.equal(decisionResponse.status, 200);
const blockedCheckout = await reviewCheckoutHandler(new Request('https://arcweb.onl/api/review/checkout', {
  method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: 'https://arcweb.onl' }, body: '{}',
}), { reviewStore: handlerStore, clock: () => new Date(now) });
assert.equal(blockedCheckout.status, 503, 'No default provider adapter may create checkout.');
const handlerCheckout = await reviewCheckoutHandler(new Request('https://arcweb.onl/api/review/checkout', {
  method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: 'https://arcweb.onl' }, body: '{}',
}), {
  retentionFenceStore: new FakeStore(),
  retentionFenceClock: () => new Date(now),
  reviewStore: handlerStore,
  clock: () => new Date(now),
  createCheckout: async () => {
    const current = (await handlerStore.getWithMetadata(reviewInviteKey(handlerInvite.record.invite_hmac_sha256))).data;
    assert.equal(current.state, 'APPROVED');
    return { url: 'https://checkout.stripe.com/c/pay/cs_test_reviewHttpContract' };
  },
});
assert.equal(handlerCheckout.status, 200);
assert.equal((await handlerCheckout.json()).checkout_url, 'https://checkout.stripe.com/c/pay/cs_test_reviewHttpContract');
for (const key of reviewEnvironmentKeys) {
  if (savedEnvironment[key] === undefined) delete process.env[key];
  else process.env[key] = savedEnvironment[key];
}

const root = new URL('../', import.meta.url);
const [page, script, buildScript, netlifyConfig, robots, emailContract] = await Promise.all([
  readFile(new URL('review/index.html', root), 'utf8'),
  readFile(new URL('review/review.js', root), 'utf8'),
  readFile(new URL('scripts/build-site.mjs', root), 'utf8'),
  readFile(new URL('netlify.toml', root), 'utf8'),
  readFile(new URL('robots.txt', root), 'utf8'),
  readFile(new URL('operations/customer-email-contract.md', root), 'utf8'),
]);
assert.match(page, /Approve &amp; Pay/);
assert.match(page, /Request Changes/);
assert.doesNotMatch(page + script, /reply to (?:this )?email|email your changes|mailto:/i);
assert.match(script, /history\.replaceState\(null, '', location\.pathname \+ location\.search\)/,
  'The fragment credential must be cleared before exchange.');
assert.match(script, /\/api\/review\/exchange/);
assert.match(script, /\/api\/review\/decision/);
assert.match(script, /checkoutPath = \/\^\\\/c\\\/pay\\\/cs_/,
  'The browser must enforce the Stripe Checkout Session path before navigation.');
assert.match(script, /safeFragment = target\.hash === ''/,
  'The browser must allow Stripe Checkout fragments only through an explicit bounded validator.');
assert.doesNotMatch(script, /target\.password \|\| target\.hash\)/,
  'Valid Stripe Checkout Session fragments must not be rejected unconditionally.');
assert.match(buildScript, /'review'/);
assert.match(netlifyConfig, /for = "\/review\/\*"[\s\S]*?Cache-Control = "no-store"[\s\S]*?Referrer-Policy = "no-referrer"/);
assert.match(robots, /Disallow: \/review\//);
assert.match(emailContract, /\{\{review_url\}\}/);
assert.match(emailContract, /No reply needed\./);
assert.doesNotMatch(emailContract, /\{\{private_checkout_url\}\}|Reply to this email/i);

console.log('Review portal contract passed.');
