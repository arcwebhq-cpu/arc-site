import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import {
  authorizeReviewSession,
  decideReview,
  exchangeReviewInvite,
  issueReviewInvite,
  reviewInviteKey,
} from '../netlify/lib/review-flow-core.mjs';
import {
  acknowledgeReviewEmailReceipt,
  claimNextReviewEmail,
  prepareReviewInviteEmail,
  readReviewEmailOutbox,
  reserveReviewEmailSend,
  reviewEmailReceiptContract,
} from '../netlify/lib/review-email-outbox-core.mjs';
import {
  REVIEW_REVISION_ARTIFACT_EVIDENCE_SCHEMA,
  REVIEW_REVISION_ARTIFACT_EVIDENCE_SIGNATURE_PREFIX,
  REVIEW_REVISION_INVITE_RESERVATION_SCHEMA,
  REVIEW_REVISION_INVITE_RESERVATION_SIGNATURE_PREFIX,
  claimNextReviewRevisionWork,
  claimReviewRevisionWork,
  completeReviewRevisionWork,
  readReviewRevisionWork,
  reserveReviewRevisionWork,
  reviewRevisionInternalWorkerAdapter,
  reviewRevisionOutboxConfiguration,
} from '../netlify/lib/review-revision-outbox-core.mjs';
import reviewDecisionHandler from '../netlify/functions/review-decision.mjs';
import reviewRevisionClaimHandler, {
  config as revisionClaimConfig,
} from '../netlify/functions/review-revision-claim.mjs';
import reviewRevisionCompleteHandler, {
  config as revisionCompleteConfig,
} from '../netlify/functions/review-revision-complete.mjs';

class FakeStore {
  constructor() {
    this.values = new Map();
    this.sequence = 0;
    this.loseAtWrite = null;
    this.loseNextKey = null;
    this.loseNextPrefix = null;
  }

  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }

  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const write = ++this.sequence;
    const etag = `entry-${write}`;
    this.values.set(key, { data: structuredClone(data), etag });
    if (this.loseAtWrite === write || key === this.loseNextKey ||
        typeof this.loseNextPrefix === 'string' && key.startsWith(this.loseNextPrefix)) {
      this.loseAtWrite = null;
      this.loseNextKey = null;
      this.loseNextPrefix = null;
      throw new Error('SIMULATED_RESPONSE_LOST_AFTER_DURABLE_WRITE');
    }
    return { modified: true, etag };
  }

  async delete(key) {
    this.values.delete(key);
  }

  async list({ prefix } = {}) {
    return { blobs: [...this.values.keys()].filter(key => !prefix || key.startsWith(prefix)).map(key => ({ key })) };
  }
}

const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
};
const hmac = (secret, prefix, value) => createHmac('sha256', secret)
  .update(prefix + canonicalJson(value)).digest('hex');
const start = new Date('2026-08-27T20:00:00.000Z');
const plus = (milliseconds) => new Date(start.getTime() + milliseconds);
const at = (milliseconds) => plus(milliseconds).toISOString();
const sha = (character) => character.repeat(64);
const workerSha = sha('d');
const recipientEmail = 'revision-customer@example.com';
const recipientEmailSha256 = createHash('sha256').update(recipientEmail).digest('hex');
const env = {
  ARC_REVIEW_PORTAL_ENABLED: 'true',
  ARC_REVIEW_CHECKOUT_ENABLED: 'false',
  ARC_REVIEW_REVISION_OUTBOX_ENABLED: 'true',
  ARC_REVIEW_INVITE_HMAC_SECRET: 'review-invite-secret-unique-0123456789abcdef',
  ARC_REVIEW_SESSION_HMAC_SECRET: 'review-session-secret-unique-0123456789abcdef',
  ARC_REVIEW_RECORD_HMAC_SECRET: 'review-record-secret-unique-0123456789abcdef',
  ARC_REVIEW_DECISION_HMAC_SECRET: 'review-decision-secret-unique-0123456789abcdef',
  ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET: 'revision-outbox-secret-unique-0123456789abcdef',
  ARC_REVIEW_REVISION_SUPPLY_CHAIN_HMAC_SECRET: 'revision-supply-chain-secret-unique-0123456789abcdef',
  ARC_REVIEW_REVISION_INVITE_RESERVATION_HMAC_SECRET:
    'revision-invite-reservation-secret-unique-0123456789abcdef',
  ARC_REVIEW_REVISION_INTERNAL_AUTH_SECRET:
    'revision-internal-auth-secret-unique-0123456789abcdef',
  ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
  ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET: 'review-email-outbox-secret-unique-0123456789abcdef',
  ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET: 'review-email-receipt-secret-unique-0123456789abcdef',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'review-revision-fence-secret-unique-0123456789abcdef',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
};
const legacyEnv = { ...env, ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'false' };
const sourcePages = [
  ['about/index.html', sha('1')],
  ['contact/index.html', sha('2')],
  ['index.html', sha('3')],
  ['process/index.html', sha('4')],
  ['services/index.html', sha('5')],
].map(([path, sha256]) => ({ path, sha256 }));
const successorPages = [
  ['about/index.html', sha('a')],
  ['contact/index.html', sha('b')],
  ['index.html', sha('c')],
  ['process/index.html', sha('d')],
  ['services/index.html', sha('e')],
].map(([path, sha256]) => ({ path, sha256 }));
const baseBinding = {
  brief_sha256: sha('6'),
  email_delivery_receipt_sha256: sha('7'),
  expires_at: at(7 * 24 * 60 * 60_000),
  page_bindings: sourcePages,
  preview_content_sha256: sha('8'),
  preview_manifest_sha256: sha('9'),
  preview_source_commit_sha: 'a'.repeat(40),
  preview_source_repository: 'arcwebhq-cpu/arc-previews',
  preview_url: 'https://arcwebhq-cpu.github.io/arc-previews/revision-source-a1b2c3d4/',
  recipient_email_sha256: recipientEmailSha256,
  scope_version: 'arc-fixed-five-page-offer-v1',
};
const successor = {
  repository: baseBinding.preview_source_repository,
  commit_sha: 'b'.repeat(40),
  manifest_sha256: sha('a'),
  content_sha256: sha('b'),
  page_bindings: successorPages,
  preview_url: 'https://arcwebhq-cpu.github.io/arc-previews/revision-successor-b2c3d4e5/',
  invite_token: 'Z'.repeat(43),
  email_delivery_receipt_sha256: sha('c'),
};
const renewedSuccessorToken = 'R'.repeat(43);
const notes = 'Use the supplied team photo and move the strongest proof above the contact form.';

async function makeSource(store, tokenCharacter) {
  const token = tokenCharacter.repeat(43);
  const issued = await issueReviewInvite(store, { ...baseBinding, invite_token: token }, legacyEnv, {
    clock: () => plus(0),
  });
  const exchanged = await exchangeReviewInvite(store, token, legacyEnv, {
    clock: () => plus(1_000), randomBytes: () => Buffer.alloc(32, tokenCharacter.charCodeAt(0)),
  });
  const authorized = await authorizeReviewSession(store, exchanged.session_token, legacyEnv, plus(2_000));
  await decideReview(store, exchanged.session_token, {
    action: 'REQUEST_CHANGES',
    expected_revision: authorized.record.record_revision,
    idempotency_key: `${tokenCharacter.charCodeAt(0).toString(16).padStart(8, '0')}-1111-4111-8111-111111111111`,
    revision_notes: notes,
  }, legacyEnv, { clock: () => plus(3_000) });
  return { inviteHmac: issued.record.invite_hmac_sha256 };
}

async function makeOpenSource(store, tokenCharacter) {
  const token = tokenCharacter.repeat(43);
  const issued = await issueReviewInvite(store, { ...baseBinding, invite_token: token }, legacyEnv, {
    clock: () => plus(0),
  });
  const exchanged = await exchangeReviewInvite(store, token, legacyEnv, {
    clock: () => plus(1_000), randomBytes: () => Buffer.alloc(32, tokenCharacter.charCodeAt(0)),
  });
  const authorized = await authorizeReviewSession(store, exchanged.session_token, legacyEnv, plus(2_000));
  return { inviteHmac: issued.record.invite_hmac_sha256, sessionToken: exchanged.session_token,
    recordRevision: authorized.record.record_revision };
}

function adaptersFor(options = {}) {
  return {
    clock: () => plus(options.clockMs ?? 10_000),
    authorizeInternalWorker: async ({ authorization }) => ({
      authorized: authorization === 'internal-worker-proof',
      worker_id_sha256: workerSha,
    }),
    verifySuccessorArtifacts: options.omitVerifier ? undefined : async (request) => {
      assert.equal(request.revision_notes, notes, 'Notes must be retrieved from the signed private review record.');
      assert.equal(request.expected_commit_sha, successor.commit_sha);
      const unsigned = {
        schema: REVIEW_REVISION_ARTIFACT_EVIDENCE_SCHEMA,
        work_hmac_sha256: request.work_hmac_sha256,
        source_invite_hmac_sha256: request.source_invite_hmac_sha256,
        source_repository: request.source_repository,
        source_commit_sha: request.source_commit_sha,
        source_manifest_sha256: request.source_manifest_sha256,
        source_page_bindings_sha256: request.source_page_bindings_sha256,
        target_revision_round: request.target_revision_round,
        repository: successor.repository,
        commit_sha: successor.commit_sha,
        manifest_sha256: successor.manifest_sha256,
        content_sha256: successor.content_sha256,
        page_bindings: successor.page_bindings,
        preview_url: successor.preview_url,
        verified_at: at(9_000),
      };
      return {
        ...unsigned,
        authority_hmac_sha256: options.badEvidenceSignature ? sha('0') :
          hmac(env.ARC_REVIEW_REVISION_SUPPLY_CHAIN_HMAC_SECRET,
            REVIEW_REVISION_ARTIFACT_EVIDENCE_SIGNATURE_PREFIX, unsigned),
      };
    },
    reserveSuccessorInvite: options.omitReservation ? undefined : async (request) => {
      const renewal = request.issuance_generation > 1;
      const unsigned = {
        schema: REVIEW_REVISION_INVITE_RESERVATION_SCHEMA,
        work_hmac_sha256: request.work_hmac_sha256,
        artifact_authority_hmac_sha256: request.artifact_authority_hmac_sha256,
        invite_token: renewal ? renewedSuccessorToken : successor.invite_token,
        expires_at: renewal ? at(15 * 24 * 60 * 60_000) : at(7 * 24 * 60 * 60_000),
        email_delivery_receipt_sha256: successor.email_delivery_receipt_sha256,
        reserved_at: renewal ? at(8 * 24 * 60 * 60_000 + 500) : at(9_500),
      };
      return {
        ...unsigned,
        reservation_hmac_sha256: hmac(env.ARC_REVIEW_REVISION_INVITE_RESERVATION_HMAC_SECRET,
          REVIEW_REVISION_INVITE_RESERVATION_SIGNATURE_PREFIX, unsigned),
      };
    },
  };
}

const completionInput = (leaseToken) => ({
  lease_token: leaseToken,
  successor_repository: successor.repository,
  successor_commit_sha: successor.commit_sha,
  successor_manifest_sha256: successor.manifest_sha256,
});

assert.equal(reviewRevisionOutboxConfiguration({}).enabled, false, 'The outbox must default off.');
assert.equal(reviewRevisionOutboxConfiguration(env).enabled, true);
for (const credentialName of [
  'ARC_REVIEW_INVITE_HMAC_SECRET',
  'ARC_REVIEW_SESSION_HMAC_SECRET',
  'ARC_REVIEW_RECORD_HMAC_SECRET',
  'ARC_REVIEW_DECISION_HMAC_SECRET',
  'ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET',
  'ARC_REVIEW_REVISION_SUPPLY_CHAIN_HMAC_SECRET',
  'ARC_REVIEW_REVISION_INVITE_RESERVATION_HMAC_SECRET',
  'ARC_REVIEW_REVISION_INTERNAL_AUTH_SECRET',
  'ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET',
  'ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET',
]) {
  assert.equal(reviewRevisionOutboxConfiguration({
    ...env,
    ARC_ROTATED_CREDENTIAL_V2: env[credentialName],
  }).enabled, false, `${credentialName} must reject an arbitrary configured alias.`);
}
assert.deepEqual(await reviewRevisionInternalWorkerAdapter({
  ...env,
  ARC_ROTATED_CREDENTIAL_V2: env.ARC_REVIEW_REVISION_INTERNAL_AUTH_SECRET,
})({ authorization: env.ARC_REVIEW_REVISION_INTERNAL_AUTH_SECRET }), {
  authorized: false,
  worker_id_sha256: '0'.repeat(64),
});
assert.equal(reviewRevisionOutboxConfiguration({
  ...env,
  ARC_REVIEW_REVISION_SUPPLY_CHAIN_HMAC_SECRET: env.ARC_REVIEW_RECORD_HMAC_SECRET,
}).enabled, false, 'Every authority secret must be present and byte-distinct.');

const reviewStore = new FakeStore();
const outboxStore = new FakeStore();
const source = await makeSource(reviewStore, 'A');
await assert.rejects(reserveReviewRevisionWork(outboxStore, reviewStore, source.inviteHmac, null, env,
  adaptersFor()), /WORKER_UNAUTHORIZED/);
const reserved = await reserveReviewRevisionWork(outboxStore, reviewStore, source.inviteHmac,
  'internal-worker-proof', env, adaptersFor({ clockMs: 4_000 }));
assert.equal(reserved.record.state, 'PENDING');
const reserveReplay = await reserveReviewRevisionWork(outboxStore, reviewStore, source.inviteHmac,
  'internal-worker-proof', env, adaptersFor({ clockMs: 5_000 }));
assert.equal(reserveReplay.idempotent_replay, true);
assert.equal(reserveReplay.record.reserved_at, reserved.record.reserved_at);

const indexCrashReview = new FakeStore();
const indexCrashOutbox = new FakeStore();
const indexCrashSource = await makeSource(indexCrashReview, 'G');
indexCrashOutbox.loseAtWrite = 1;
await assert.rejects(reserveReviewRevisionWork(indexCrashOutbox, indexCrashReview,
  indexCrashSource.inviteHmac, 'internal-worker-proof', env, adaptersFor({ clockMs: 4_000 })),
/SIMULATED_RESPONSE_LOST/);
const indexClaimRecovered = await claimNextReviewRevisionWork(indexCrashOutbox, indexCrashReview, null,
  'internal-worker-proof', env, adaptersFor({ clockMs: 5_000 }));
assert.equal(indexClaimRecovered.record.state, 'CLAIMED',
  'Claim-next must recover work after a marker-first producer crash without a customer retry.');
const indexRecovered = await reserveReviewRevisionWork(indexCrashOutbox, indexCrashReview,
  indexCrashSource.inviteHmac, 'internal-worker-proof', env, adaptersFor({ clockMs: 6_000 }));
assert.equal((await claimNextReviewRevisionWork(indexCrashOutbox, indexCrashReview, 'f'.repeat(64),
  'internal-worker-proof', env, adaptersFor({ clockMs: 7_000 }))).next_cursor, null,
  'Exhausting a cursor must reset scanning so later lower-HMAC work cannot starve.');
assert.equal((await claimNextReviewRevisionWork(indexCrashOutbox, indexCrashReview, null,
  'internal-worker-proof', env, adaptersFor({ clockMs: 7_000 }))).record.work_hmac_sha256,
indexRecovered.record.work_hmac_sha256);

await assert.rejects(claimReviewRevisionWork(outboxStore, reviewStore, reserved.record.work_hmac_sha256,
  'wrong-proof', env, adaptersFor()), /WORKER_UNAUTHORIZED/);
const claim = await claimReviewRevisionWork(outboxStore, reviewStore, reserved.record.work_hmac_sha256,
  'internal-worker-proof', env, adaptersFor());
assert.equal(claim.record.state, 'CLAIMED');
assert.equal(claim.revision_input.revision_notes, notes);
assert.deepEqual(claim.revision_input.page_bindings, sourcePages);
assert.equal(JSON.stringify(claim.record).includes(notes), false);
assert.equal(JSON.stringify(claim.record).includes(claim.lease_token), false);

await assert.rejects(completeReviewRevisionWork(outboxStore, reviewStore, claim.record.work_hmac_sha256,
  'internal-worker-proof', completionInput(claim.lease_token), env, adaptersFor({ omitVerifier: true })),
/SUPPLY_CHAIN_UNAVAILABLE/);
await assert.rejects(completeReviewRevisionWork(outboxStore, reviewStore, claim.record.work_hmac_sha256,
  'internal-worker-proof', completionInput(claim.lease_token), env, adaptersFor({ badEvidenceSignature: true })),
/SUPPLY_CHAIN_EVIDENCE_INVALID/);
await assert.rejects(completeReviewRevisionWork(outboxStore, reviewStore, claim.record.work_hmac_sha256,
  'internal-worker-proof', completionInput(claim.lease_token), env, adaptersFor({ omitReservation: true })),
/INVITE_RESERVATION_UNAVAILABLE/);
assert.equal((await readReviewRevisionWork(outboxStore, claim.record.work_hmac_sha256, env)).record.state, 'CLAIMED');

const completed = await completeReviewRevisionWork(outboxStore, reviewStore, claim.record.work_hmac_sha256,
  'internal-worker-proof', completionInput(claim.lease_token), env, adaptersFor());
assert.equal(completed.record.state, 'COMPLETED');
const linkedSource = (await reviewStore.getWithMetadata(reviewInviteKey(source.inviteHmac))).data;
assert.equal(linkedSource.state, 'REVISION_SUPERSEDED');
assert.equal(linkedSource.successor_invite_hmac_sha256, completed.record.successor_invite_hmac_sha256);
const issuedSuccessor = (await reviewStore.getWithMetadata(
  reviewInviteKey(completed.record.successor_invite_hmac_sha256))).data;
assert.equal(issuedSuccessor.state, 'OPEN');
assert.equal(issuedSuccessor.preview_source_commit_sha, successor.commit_sha);
assert.equal(issuedSuccessor.preview_manifest_sha256, successor.manifest_sha256);
assert.equal(issuedSuccessor.revision_round, 1);
const successorPending = await claimNextReviewEmail(reviewStore, env, { clock: () => plus(10_500) });
assert.equal(successorPending.outbox_hmac_sha256,
  completed.record.successor_email_outbox_hmac_sha256);
assert.equal(successorPending.source_reference_hmac_sha256, claim.record.work_hmac_sha256,
  'Successor email recovery must expose the durable revision work lookup key, not an unresolvable derived HMAC.');
const completedReplay = await completeReviewRevisionWork(outboxStore, reviewStore, claim.record.work_hmac_sha256,
  'internal-worker-proof', completionInput(claim.lease_token), env, {
    clock: () => plus(11_000),
    authorizeInternalWorker: adaptersFor().authorizeInternalWorker,
  });
assert.equal(completedReplay.idempotent_replay, true, 'Exact completion must not require provider adapters again.');

const successorOutbox = await readReviewEmailOutbox(reviewStore,
  completed.record.successor_email_outbox_hmac_sha256, env);
assert.equal(successorOutbox.record.state, 'READY',
  'Revision completion requires the durable successor email outbox to exist first.');
assert.equal(successorOutbox.record.invite_hmac_sha256, completed.record.successor_invite_hmac_sha256);
const sendAuthority = await reserveReviewEmailSend(reviewStore, {
  invite_token: successor.invite_token,
  recipient_email: recipientEmail,
}, env, { clock: () => plus(11_000) });
assert.equal(sendAuthority.outbox_hmac_sha256, completed.record.successor_email_outbox_hmac_sha256);
assert.match(sendAuthority.review_url, /^https:\/\/arcweb\.onl\/review\/#invite=/);
const deliveredReceipt = {
  schema: reviewEmailReceiptContract.schema,
  version: reviewEmailReceiptContract.version,
  outbox_hmac_sha256: successorOutbox.record.outbox_hmac_sha256,
  invite_hmac_sha256: completed.record.successor_invite_hmac_sha256,
  recipient_email_sha256: recipientEmailSha256,
  preview_manifest_sha256: successor.manifest_sha256,
  provider: 'provider-test',
  provider_account_hmac_sha256: sha('a'),
  provider_event_id: 'event-revision-successor-delivered',
  provider_message_id: 'message-revision-successor-delivered',
  event_type: 'message.delivered',
  delivery_status: 'delivered',
  event_at: at(12_000),
  issued_at: at(13_000),
};
const deliveredEvidence = canonicalJson(deliveredReceipt);
const deliveredSignature = createHmac('sha256', env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET)
  .update(reviewEmailReceiptContract.signaturePrefix + deliveredEvidence).digest('hex');
const deliveredAck = await acknowledgeReviewEmailReceipt(reviewStore, deliveredEvidence, deliveredSignature, env, {
  clock: () => plus(13_000),
});
assert.equal(deliveredAck.state, 'DELIVERED');
assert.equal((await readReviewEmailOutbox(reviewStore,
  completed.record.successor_email_outbox_hmac_sha256, env)).record.state, 'DELIVERED');
const successorExchange = await exchangeReviewInvite(reviewStore, successor.invite_token, env, {
  clock: () => plus(14_000), randomBytes: () => Buffer.alloc(32, 31),
});
assert.equal(typeof successorExchange.session_token, 'string',
  'Only the signed DELIVERED binding may unlock the successor exchange.');
const durableEmailState = JSON.stringify([...reviewStore.values.entries()]);
assert.equal(durableEmailState.includes(successor.invite_token), false);
assert.equal(durableEmailState.includes(recipientEmail), false);
assert.equal(durableEmailState.includes(sendAuthority.review_url), false);

const persisted = JSON.stringify([...outboxStore.values.values()]);
for (const forbidden of [
  notes,
  successor.invite_token,
  successor.preview_url,
  baseBinding.preview_url,
  baseBinding.recipient_email_sha256,
  env.ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET,
  env.ARC_REVIEW_REVISION_SUPPLY_CHAIN_HMAC_SECRET,
]) assert.equal(persisted.includes(forbidden), false, 'The outbox must contain no PII, URLs, raw tokens, or secrets.');

const planCrashReview = new FakeStore();
const planCrashOutbox = new FakeStore();
const planCrashSource = await makeSource(planCrashReview, 'B');
const planReserved = await reserveReviewRevisionWork(planCrashOutbox, planCrashReview, planCrashSource.inviteHmac,
  'internal-worker-proof', env, adaptersFor({ clockMs: 4_000 }));
const planClaim = await claimReviewRevisionWork(planCrashOutbox, planCrashReview, planReserved.record.work_hmac_sha256,
  'internal-worker-proof', env, adaptersFor());
planCrashOutbox.loseAtWrite = planCrashOutbox.sequence + 1;
await assert.rejects(completeReviewRevisionWork(planCrashOutbox, planCrashReview,
  planClaim.record.work_hmac_sha256, 'internal-worker-proof', completionInput(planClaim.lease_token), env,
  adaptersFor()), /SIMULATED_RESPONSE_LOST/);
assert.equal((await readReviewRevisionWork(planCrashOutbox, planClaim.record.work_hmac_sha256, env)).record.state,
  'ISSUING', 'The durable issuance plan must survive an ambiguous response.');
const planRecovered = await completeReviewRevisionWork(planCrashOutbox, planCrashReview,
  planClaim.record.work_hmac_sha256, 'internal-worker-proof', completionInput(planClaim.lease_token), env,
  adaptersFor());
assert.equal(planRecovered.record.state, 'COMPLETED');

const linkCrashReview = new FakeStore();
const linkCrashOutbox = new FakeStore();
const linkCrashSource = await makeSource(linkCrashReview, 'C');
const linkReserved = await reserveReviewRevisionWork(linkCrashOutbox, linkCrashReview, linkCrashSource.inviteHmac,
  'internal-worker-proof', env, adaptersFor({ clockMs: 4_000 }));
const linkClaim = await claimReviewRevisionWork(linkCrashOutbox, linkCrashReview, linkReserved.record.work_hmac_sha256,
  'internal-worker-proof', env, adaptersFor());
linkCrashReview.loseNextKey = reviewInviteKey(linkCrashSource.inviteHmac);
await assert.rejects(completeReviewRevisionWork(linkCrashOutbox, linkCrashReview,
  linkClaim.record.work_hmac_sha256, 'internal-worker-proof', completionInput(linkClaim.lease_token), env,
  adaptersFor()), /SIMULATED_RESPONSE_LOST/);
assert.equal((await readReviewRevisionWork(linkCrashOutbox, linkClaim.record.work_hmac_sha256, env)).record.state,
  'ISSUING');
assert.equal((await linkCrashReview.getWithMetadata(reviewInviteKey(linkCrashSource.inviteHmac))).data.state,
  'REVISION_SUPERSEDED', 'A crash after source linkage must remain recoverable.');
const linkRecovered = await completeReviewRevisionWork(linkCrashOutbox, linkCrashReview,
  linkClaim.record.work_hmac_sha256, 'internal-worker-proof', completionInput(linkClaim.lease_token), env,
  adaptersFor());
assert.equal(linkRecovered.record.state, 'COMPLETED');

const emailCrashReview = new FakeStore();
const emailCrashOutbox = new FakeStore();
const emailCrashSource = await makeSource(emailCrashReview, 'E');
const emailReserved = await reserveReviewRevisionWork(emailCrashOutbox, emailCrashReview,
  emailCrashSource.inviteHmac, 'internal-worker-proof', env, adaptersFor({ clockMs: 4_000 }));
const emailClaim = await claimReviewRevisionWork(emailCrashOutbox, emailCrashReview,
  emailReserved.record.work_hmac_sha256, 'internal-worker-proof', env, adaptersFor());
emailCrashReview.loseNextPrefix = 'review-email-outbox/';
await assert.rejects(completeReviewRevisionWork(emailCrashOutbox, emailCrashReview,
  emailClaim.record.work_hmac_sha256, 'internal-worker-proof', completionInput(emailClaim.lease_token), env,
  adaptersFor()), /SIMULATED_RESPONSE_LOST/);
assert.equal((await readReviewRevisionWork(emailCrashOutbox, emailClaim.record.work_hmac_sha256, env)).record.state,
  'ISSUING', 'A lost email-outbox create response must not complete revision work.');
const afterInviteExpiry = 8 * 24 * 60 * 60_000;
const expiredRecoveryClaim = await claimReviewRevisionWork(emailCrashOutbox, emailCrashReview,
  emailClaim.record.work_hmac_sha256, 'internal-worker-proof', env,
  adaptersFor({ clockMs: afterInviteExpiry }));
const emailRecovered = await completeReviewRevisionWork(emailCrashOutbox, emailCrashReview,
  emailClaim.record.work_hmac_sha256, 'internal-worker-proof', completionInput(expiredRecoveryClaim.lease_token), env,
  adaptersFor({ clockMs: afterInviteExpiry + 1_000 }));
assert.equal(emailRecovered.record.state, 'COMPLETED');
assert.notEqual(emailRecovered.record.successor_invite_hmac_sha256,
  emailClaim.record.successor_invite_hmac_sha256, 'Expired issuance must be replanned to a fresh invite.');
const renewedOutbox = await readReviewEmailOutbox(emailCrashReview,
  emailRecovered.record.successor_email_outbox_hmac_sha256, env);
assert.equal(renewedOutbox.record.state, 'READY');
const renewedSend = await reserveReviewEmailSend(emailCrashReview, {
  invite_token: renewedSuccessorToken,
  recipient_email: recipientEmail,
}, env, { clock: () => plus(afterInviteExpiry + 2_000) });
assert.equal(renewedSend.outbox_hmac_sha256, renewedOutbox.record.outbox_hmac_sha256);
const renewedReceipt = {
  schema: reviewEmailReceiptContract.schema,
  version: reviewEmailReceiptContract.version,
  outbox_hmac_sha256: renewedOutbox.record.outbox_hmac_sha256,
  invite_hmac_sha256: emailRecovered.record.successor_invite_hmac_sha256,
  recipient_email_sha256: recipientEmailSha256,
  preview_manifest_sha256: successor.manifest_sha256,
  provider: 'provider-test',
  provider_account_hmac_sha256: sha('b'),
  provider_event_id: 'event-renewed-successor-delivered',
  provider_message_id: 'message-renewed-successor-delivered',
  event_type: 'message.delivered',
  delivery_status: 'delivered',
  event_at: at(afterInviteExpiry + 3_000),
  issued_at: at(afterInviteExpiry + 4_000),
};
const renewedEvidence = canonicalJson(renewedReceipt);
const renewedSignature = createHmac('sha256', env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET)
  .update(reviewEmailReceiptContract.signaturePrefix + renewedEvidence).digest('hex');
await acknowledgeReviewEmailReceipt(emailCrashReview, renewedEvidence, renewedSignature, env,
  { clock: () => plus(afterInviteExpiry + 4_000) });
const renewedExchange = await exchangeReviewInvite(emailCrashReview, renewedSuccessorToken, env, {
  clock: () => plus(afterInviteExpiry + 5_000), randomBytes: () => Buffer.alloc(32, 44),
});
assert.equal(typeof renewedExchange.session_token, 'string',
  'Post-expiry recovery must produce a sendable, delivered, exchangeable fresh invite.');

const staleReview = new FakeStore();
const staleOutbox = new FakeStore();
const staleSource = await makeSource(staleReview, 'D');
const staleReserved = await reserveReviewRevisionWork(staleOutbox, staleReview, staleSource.inviteHmac,
  'internal-worker-proof', env, adaptersFor({ clockMs: 4_000 }));
const staleClaim = await claimReviewRevisionWork(staleOutbox, staleReview, staleReserved.record.work_hmac_sha256,
  'internal-worker-proof', env, adaptersFor());
await issueReviewInvite(staleReview, {
  ...baseBinding,
  invite_token: 'Y'.repeat(43),
  prior_invite_hmac_sha256: staleSource.inviteHmac,
  preview_content_sha256: sha('c'),
  preview_manifest_sha256: sha('d'),
  preview_source_commit_sha: 'c'.repeat(40),
  email_delivery_receipt_sha256: sha('e'),
}, legacyEnv, { clock: () => plus(9_000) });
await assert.rejects(completeReviewRevisionWork(staleOutbox, staleReview, staleClaim.record.work_hmac_sha256,
  'internal-worker-proof', completionInput(staleClaim.lease_token), env, adaptersFor()), /STALE_SUCCESSOR/);

assert.deepEqual([revisionClaimConfig.path, revisionCompleteConfig.path], [
  '/api/internal/review-revision/claim', '/api/internal/review-revision/complete',
]);
const automatedReviewStore = new FakeStore();
const automatedRevisionStore = new FakeStore();
const automatedToken = 'Q'.repeat(43);
const { email_delivery_receipt_sha256: _legacyReceipt, ...automatedBinding } = baseBinding;
const automatedPrepared = await prepareReviewInviteEmail(automatedReviewStore, {
  ...automatedBinding, invite_token: automatedToken,
}, env, { clock: () => plus(0) });
const automatedSend = await reserveReviewEmailSend(automatedReviewStore, {
  invite_token: automatedToken, recipient_email: recipientEmail,
}, env, { clock: () => plus(1_000) });
const automatedReceipt = {
  schema: reviewEmailReceiptContract.schema,
  version: reviewEmailReceiptContract.version,
  outbox_hmac_sha256: automatedSend.outbox_hmac_sha256,
  invite_hmac_sha256: automatedPrepared.invite.invite_hmac_sha256,
  recipient_email_sha256: recipientEmailSha256,
  preview_manifest_sha256: baseBinding.preview_manifest_sha256,
  provider: 'provider-test', provider_account_hmac_sha256: sha('c'),
  provider_event_id: 'event-automated-source-delivered',
  provider_message_id: 'message-automated-source-delivered',
  event_type: 'message.delivered', delivery_status: 'delivered',
  event_at: at(2_000), issued_at: at(3_000),
};
const automatedEvidence = canonicalJson(automatedReceipt);
await acknowledgeReviewEmailReceipt(automatedReviewStore, automatedEvidence,
  createHmac('sha256', env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET)
    .update(reviewEmailReceiptContract.signaturePrefix + automatedEvidence).digest('hex'), env,
  { clock: () => plus(3_000) });
const automatedExchange = await exchangeReviewInvite(automatedReviewStore, automatedToken, env, {
  clock: () => plus(4_000), randomBytes: () => Buffer.alloc(32, 51),
});
const automatedAuthorized = await authorizeReviewSession(automatedReviewStore,
  automatedExchange.session_token, env, plus(5_000));
const envKeys = Object.keys(env);
const savedEnv = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));
Object.assign(process.env, env, { ARC_REVIEW_REVISION_OUTBOX_ENABLED: 'false' });
const decisionRequest = () => new Request('https://arcweb.onl/api/review/decision', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Cookie: `__Host-arc_review_session=${automatedExchange.session_token}`,
    Origin: 'https://arcweb.onl' },
  body: JSON.stringify({ action: 'REQUEST_CHANGES',
    expected_revision: automatedAuthorized.record.record_revision,
    idempotency_key: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', revision_notes: notes }),
});
const disabledDecision = await reviewDecisionHandler(decisionRequest(), {
  reviewStore: automatedReviewStore, revisionStore: automatedRevisionStore,
  retentionFenceStore: new FakeStore(), clock: () => plus(5_000),
});
assert.equal(disabledDecision.status, 503, 'Unavailable revision automation must fail before recording a decision.');
assert.equal((await authorizeReviewSession(automatedReviewStore, automatedExchange.session_token,
  env, plus(5_000))).record.state, 'OPEN');
Object.assign(process.env, env);
let failFinalizeRead = true;
const crashingRevisionStore = {
  setJSON: (...args) => automatedRevisionStore.setJSON(...args),
  delete: (...args) => automatedRevisionStore.delete(...args),
  list: (...args) => automatedRevisionStore.list(...args),
  getWithMetadata: (...args) => {
    if (failFinalizeRead) {
      failFinalizeRead = false;
      throw new Error('SIMULATED_CRASH_AFTER_DECISION_BEFORE_WORK_FINALIZE');
    }
    return automatedRevisionStore.getWithMetadata(...args);
  },
};
const crashedDecision = await reviewDecisionHandler(decisionRequest(), {
  reviewStore: automatedReviewStore, revisionStore: crashingRevisionStore,
  retentionFenceStore: new FakeStore(), clock: () => plus(5_000),
});
assert.equal(crashedDecision.status, 503);
assert.equal((await authorizeReviewSession(automatedReviewStore, automatedExchange.session_token,
  env, plus(6_000))).record.state, 'REVISION_REQUESTED',
  'The test crash must occur after the customer decision is durable.');
const rejectedBrowserClaim = await reviewRevisionClaimHandler(new Request(
  'https://arcweb.onl/api/internal/review-revision/claim', {
    method: 'POST', headers: { Authorization: `Bearer ${env.ARC_REVIEW_REVISION_INTERNAL_AUTH_SECRET}`,
      'Content-Type': 'application/json', Origin: 'https://arcweb.onl' }, body: JSON.stringify({ cursor: null }),
  }), { reviewStore: automatedReviewStore, revisionStore: automatedRevisionStore,
    retentionFenceStore: new FakeStore() });
assert.equal(rejectedBrowserClaim.status, 401, 'Internal revision workers must reject browser-origin requests.');
const claimResponse = await reviewRevisionClaimHandler(new Request(
  'https://arcweb.onl/api/internal/review-revision/claim', {
    method: 'POST', headers: { Authorization: `Bearer ${env.ARC_REVIEW_REVISION_INTERNAL_AUTH_SECRET}`,
      'Content-Type': 'application/json' }, body: JSON.stringify({ cursor: null }),
  }), { reviewStore: automatedReviewStore, revisionStore: automatedRevisionStore,
    retentionFenceStore: new FakeStore(), clock: () => plus(8_000) });
assert.equal(claimResponse.status, 200);
const discoveredClaim = await claimResponse.json();
assert.equal(discoveredClaim.empty, undefined);
assert.equal(discoveredClaim.revision_input.revision_notes, notes,
  'The worker must repair marker-first decision crashes without a browser retry or known store key.');
const endpointAdapters = adaptersFor({ clockMs: 10_000 });
const completeResponse = await reviewRevisionCompleteHandler(new Request(
  'https://arcweb.onl/api/internal/review-revision/complete', {
    method: 'POST', headers: { Authorization: `Bearer ${env.ARC_REVIEW_REVISION_INTERNAL_AUTH_SECRET}`,
      'Content-Type': 'application/json' },
    body: JSON.stringify({ work_hmac_sha256: discoveredClaim.revision_input.work_hmac_sha256,
      lease_token: discoveredClaim.lease_token, successor_repository: successor.repository,
      successor_commit_sha: successor.commit_sha, successor_manifest_sha256: successor.manifest_sha256,
      artifact_evidence: {}, invite_reservation: {} }),
  }), { reviewStore: automatedReviewStore, revisionStore: automatedRevisionStore, clock: () => plus(10_000),
    retentionFenceStore: new FakeStore(),
    verifySuccessorArtifacts: endpointAdapters.verifySuccessorArtifacts,
    reserveSuccessorInvite: endpointAdapters.reserveSuccessorInvite });
assert.equal(completeResponse.status, 200);
assert.equal((await completeResponse.json()).state, 'COMPLETED');
const emptyClaim = await reviewRevisionClaimHandler(new Request(
  'https://arcweb.onl/api/internal/review-revision/claim', {
    method: 'POST', headers: { Authorization: `Bearer ${env.ARC_REVIEW_REVISION_INTERNAL_AUTH_SECRET}`,
      'Content-Type': 'application/json' }, body: JSON.stringify({ cursor: null }),
  }), { reviewStore: automatedReviewStore, revisionStore: automatedRevisionStore,
    retentionFenceStore: new FakeStore(), clock: () => plus(11_000) });
assert.deepEqual(await emptyClaim.json(), { empty: true, next_cursor: null },
  'The pending index must be removed only after durable completion.');
for (const key of envKeys) {
  if (savedEnv[key] === undefined) delete process.env[key];
  else process.env[key] = savedEnv[key];
}

const coreSource = await readFile(new URL('../netlify/lib/review-revision-outbox-core.mjs', import.meta.url), 'utf8');
assert.doesNotMatch(coreSource, /authorizeReviewSession|sessionToken|\bfetch\s*\(/,
  'Workers must use internal authorization and private signed-record references, never customer sessions or direct fetch.');

console.log('Review revision outbox contract passed.');
