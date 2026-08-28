import assert from 'node:assert/strict';
import { BUDGET_CONFIRMATION, TERMS_CONFIRMATION, normalizeIntakeForm } from '../netlify/lib/intake-submission-core.mjs';
import { dispatchIntakeToArc1Background, recoverPendingArc1Dispatches, resolveSameDeployDispatcher } from '../netlify/lib/intake-arc1-dispatch-core.mjs';
import { consumeIntakeEmailVerificationToken, reserveIntakeEmailVerification } from '../netlify/lib/intake-email-verification-core.mjs';
import {
  config as backgroundConfig,
  createIntakeArc1BackgroundHandler,
} from '../netlify/functions/intake-arc1-background.mjs';
import {
  config as recoveryConfig,
  createIntakeArc1RecoveryHandler,
} from '../netlify/functions/intake-arc1-recovery.mjs';
import { testActivationAuthority } from './helpers/activation-authority.mjs';

const backgroundHandler = createIntakeArc1BackgroundHandler();
const recoveryHandler = createIntakeArc1RecoveryHandler();

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; this.autoVerify = true; }
  async getWithMetadata(key) { const value = this.values.get(key); return value ? { data: structuredClone(value.data), etag: value.etag } : null; }
  async setJSON(key, data, options = {}) { const current = this.values.get(key); if (options.onlyIfNew && current) return { modified: false }; if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false }; const etag = `e-${++this.sequence}`; this.values.set(key, { data: structuredClone(data), etag }); if (this.autoVerify && !current && key.startsWith('submissions/') && data?.schema === 'arc-intake-function-submission-v1') { const verification = await reserveIntakeEmailVerification(data, env, this, { clock: () => now }); await consumeIntakeEmailVerificationToken(new URL(verification.verification_url).hash.slice(1), env, this, { clock: () => new Date(now.getTime() + 1) }); } return { modified: true, etag }; }
  list({ prefix, paginate }) {
    const page = { blobs: [...this.values.keys()].filter(key => key.startsWith(prefix)).map(key => ({ key })) };
    if (!paginate) return Promise.resolve(page);
    return { async *[Symbol.asyncIterator]() { yield page; } };
  }
}

class ProviderSequenceRecoveryStore extends FakeStore {
  constructor(layouts) {
    super();
    this.layouts = layouts;
    this.shardCalls = 0;
  }
  list({ prefix, paginate }) {
    assert.equal(paginate, true);
    if (prefix !== 'submissions/00') {
      return { async *[Symbol.asyncIterator]() { yield { blobs: [] }; } };
    }
    const layout = this.layouts[Math.min(this.shardCalls, this.layouts.length - 1)];
    this.shardCalls += 1;
    return { async *[Symbol.asyncIterator]() {
      for (const page of layout) yield { blobs: page.map((key) => ({ key })) };
    } };
  }
}
const form = new FormData();
for (const [field, value] of Object.entries({ intake_version: 'arc-intake-v8', offer_contract_id: 'arc-fixed-five-page-offer-v1', name: 'Private Owner', email: 'private@example.test', business: 'Private Roofing', industry: 'Roofing', city: 'Everett, WA', main_services: 'Roofing', main_call_to_action: 'Contact', lead_form_needed: 'Yes', lead_notification_email: 'private@example.test', primary_style: 'Modern', budget_confirmed: BUDGET_CONFIRMATION, terms_accepted: TERMS_CONFIRMATION, 'bot-field': '' })) form.append(field, value);
form.append('goals', 'More calls');
form.append('lead_form_fields', 'Email');
form.append('sections', 'Contact or quote form');
const submissionId = '11111111-1111-4111-8111-111111111111'; const now = new Date('2026-08-13T19:00:00.000Z');
const normalized = await normalizeIntakeForm(form, now, () => submissionId);
const env = {
  ...testActivationAuthority(new Date()),
  ARC_INTAKE_ARC1_DISPATCH_ENABLED: 'true',
  ARC_INTAKE_ARC1_DISPATCH_SECRET: 'dispatch-secret-unique-0123456789-abcdefgh',
  ARC_INTAKE_ARC1_RUN_SECRET: 'run-secret-unique-0123456789-abcdefghijkl',
  ARC_INTAKE_EMAIL_VERIFICATION_ENABLED: 'true',
  ARC_INTAKE_EMAIL_VERIFICATION_STATE_SECRET: 'verification-state-secret-unique-0123456789',
  ARC_INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET: 'verification-token-secret-unique-0123456789',
  ARC_INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET: 'verification-recipient-secret-unique-012345',
  ARC_INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET: 'verification-release-secret-unique-01234567',
  URL: 'https://arcweb.onl',
};
const request = new Request('https://arcweb.onl/api/intake/submit', { method: 'POST' });
assert.equal(resolveSameDeployDispatcher(request, env).endpoint, 'https://arcweb.onl/.netlify/functions/intake-arc1-background');
assert.equal(resolveSameDeployDispatcher(new Request('https://arcsites.netlify.app/api/intake/submit'), env).endpoint,
  'https://arcweb.onl/.netlify/functions/intake-arc1-background',
  'Either fixed public alias may invoke, but the endpoint is derived only from the trusted configured URL.');
assert.throws(() => resolveSameDeployDispatcher(new Request('https://evil.example/api/intake/submit'), env), /origin mismatch/);
assert.throws(() => resolveSameDeployDispatcher(request, { ...env, ARC_INTAKE_ARC1_RUN_SECRET: env.ARC_INTAKE_ARC1_DISPATCH_SECRET }), /distinct/);
const disabled = await dispatchIntakeToArc1Background(submissionId, request, { ...env, ARC_INTAKE_ARC1_DISPATCH_ENABLED: 'false' }, { get store() { throw new Error('must not touch'); }, fetch: async () => { throw new Error('must not invoke'); } });
assert.equal(disabled.state, 'DISPATCH_DISABLED');
const unverifiedStore = new FakeStore();
unverifiedStore.autoVerify = false;
await unverifiedStore.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
let unverifiedCalls = 0;
assert.deepEqual(await dispatchIntakeToArc1Background(submissionId, request, env, {
  store: unverifiedStore, clock: () => now,
  fetch: async () => { unverifiedCalls += 1; throw new Error('unverified intake entered network'); },
}), { state: 'AWAITING_EMAIL_VERIFICATION' });
assert.equal(unverifiedCalls, 0, 'ARC1 dispatch must perform zero network I/O before mailbox ownership is proven.');
const unverifiedChallenge = await reserveIntakeEmailVerification(normalized.record, env, unverifiedStore, { clock: () => now });
await consumeIntakeEmailVerificationToken(new URL(unverifiedChallenge.verification_url).hash.slice(1), env,
  unverifiedStore, { clock: () => now });
assert.equal((await dispatchIntakeToArc1Background(submissionId, request, env, {
  store: unverifiedStore, clock: () => now, fetch: async (url) => { unverifiedCalls += 1; return { status: 202, url }; },
})).state, 'ACCEPTED');
assert.equal(unverifiedCalls, 1, 'Exactly one verified dispatch may enter network.');
const store = new FakeStore(); await store.setJSON(normalized.key, normalized.record, { onlyIfNew: true }); let calls = 0;
const accepted = await dispatchIntakeToArc1Background(submissionId, request, env, { store, clock: () => new Date(now), fetch: async (url, options) => { calls += 1; assert.equal(url, 'https://arcweb.onl/.netlify/functions/intake-arc1-background'); assert.equal(options.method, 'POST'); assert.equal(options.redirect, 'error'); assert.equal(options.headers.Authorization, `Bearer ${env.ARC_INTAKE_ARC1_DISPATCH_SECRET}`); assert.deepEqual(JSON.parse(options.body), { schema: 'arc-intake-arc1-delivery-request-v1', submission_id: submissionId }); assert.doesNotMatch(`${url}\n${JSON.stringify(options.headers)}\n${options.body}`, /private@example|Private Roofing|Everett/); return { status: 202, url }; } });
assert.equal(accepted.state, 'ACCEPTED'); assert.equal(store.values.get(normalized.key).data.arc1_dispatch.status, 'ACCEPTED'); assert.equal(store.values.get(normalized.key).data.arc1_dispatch.attempt_count, 1);
const replay = await dispatchIntakeToArc1Background(submissionId, request, env, { store, fetch: async () => { throw new Error('must not invoke'); } }); assert.equal(replay.idempotentReplay, true); assert.equal(calls, 1);
// Deterministic race: background delivery ACKs the shared record before the
// foreground dispatcher persists Netlify's 202. Both terminal facts converge.
const raceStore = new FakeStore(); await raceStore.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
const raced = await dispatchIntakeToArc1Background(submissionId, request, env, {
  store: raceStore, clock: () => new Date(now), fetch: async (url) => {
    const current = await raceStore.getWithMetadata(normalized.key);
    const delivery = {
      ...current.data.arc1_delivery, status: 'ACKED', attempt_count: 1, next_attempt_at: now.toISOString(),
      lease_hmac_sha256: null, lease_expires_at: null, last_attempt_at: now.toISOString(), acknowledged_at: now.toISOString(),
      acknowledgement_sha256: 'a'.repeat(64), consumer_claim_key_hmac_sha256: 'b'.repeat(64),
    };
    await raceStore.setJSON(normalized.key, { ...current.data, arc1_delivery: delivery }, { onlyIfMatch: current.etag });
    return { status: 202, url };
  },
});
assert.equal(raced.state, 'ACCEPTED');
assert.equal(raceStore.values.get(normalized.key).data.arc1_delivery.status, 'ACKED');
assert.equal(raceStore.values.get(normalized.key).data.arc1_dispatch.status, 'ACCEPTED');
const failedStore = new FakeStore(); await failedStore.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
const failed = await dispatchIntakeToArc1Background(submissionId, request, env, { store: failedStore, clock: () => new Date(now), fetch: async () => { throw new Error('timeout'); } });
assert.equal(failed.state, 'PENDING'); assert.equal(failed.code, 'DISPATCH_UNAVAILABLE'); assert.equal(failedStore.values.get(normalized.key).data.arc1_dispatch.alert_status, 'PENDING');
const recovered = await recoverPendingArc1Dispatches(request, env, { store: failedStore, clock: () => new Date(now.getTime() + 60_000), fetch: async (url) => ({ status: 202, url }) });
assert.equal(recovered.scanned, 1); assert.equal(recovered.attempted, 1); assert.equal(failedStore.values.get(normalized.key).data.arc1_dispatch.status, 'ACCEPTED'); assert.equal(failedStore.values.get(normalized.key).data.arc1_dispatch.alert_status, 'RESOLVED');
const acceptedDueStore = new FakeStore();
await acceptedDueStore.setJSON(normalized.key, {
  ...normalized.record,
  arc1_dispatch: {
    ...normalized.record.arc1_dispatch, status: 'ACCEPTED', attempt_count: 1,
    last_attempt_at: now.toISOString(), accepted_at: now.toISOString(),
  },
}, { onlyIfNew: true });
let acceptedDueCalls = 0;
let acceptedDueCursor = null;
do {
  const result = await recoverPendingArc1Dispatches(request, env, {
    store: acceptedDueStore, cursor: acceptedDueCursor, clock: () => new Date(now.getTime() + 60_000),
    fetch: async (url) => { acceptedDueCalls += 1; return { status: 202, url }; },
  });
  acceptedDueCursor = result.next_cursor;
} while (acceptedDueCursor);
assert.equal(acceptedDueCalls, 1, 'An ACCEPTED dispatch with due delivery must be validly re-enqueued exactly once.');
assert.equal(acceptedDueStore.values.get(normalized.key).data.arc1_dispatch.status, 'ACCEPTED');
assert.equal(acceptedDueStore.values.get(normalized.key).data.arc1_dispatch.attempt_count, 2);

const staleLeaseStore = new FakeStore();
await staleLeaseStore.setJSON(normalized.key, {
  ...normalized.record,
  arc1_dispatch: {
    ...normalized.record.arc1_dispatch, attempt_lease_hmac_sha256: 'f'.repeat(64),
    attempt_lease_expires_at: new Date(now.getTime() - 1_000).toISOString(), last_attempt_at: now.toISOString(),
  },
}, { onlyIfNew: true });
const staleLeaseRetry = await dispatchIntakeToArc1Background(submissionId, request, env, {
  store: staleLeaseStore, clock: () => new Date(now), force: true,
  fetch: async (url) => ({ status: 202, url }),
});
assert.equal(staleLeaseRetry.state, 'ACCEPTED');
assert.equal(staleLeaseStore.values.get(normalized.key).data.arc1_dispatch.attempt_count, 1,
  'An expired unconfirmed process lease must not count as a failed network attempt before its idempotent retry.');
const mixedStore = new FakeStore();
await mixedStore.setJSON('submissions/00000000-0000-4000-8000-000000000000', { malformed: true }, { onlyIfNew: true });
await mixedStore.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
const mixedRecovered = await recoverPendingArc1Dispatches(request, env, {
  store: mixedStore, clock: () => new Date(now.getTime() + 60_000), fetch: async (url) => ({ status: 202, url }),
});
assert.equal(mixedRecovered.invalid, 1); assert.equal(mixedRecovered.attempted, 1,
  'A malformed earlier record must be quarantined without starving a later valid dispatch.');
assert.equal([...mixedStore.values.keys()].some(key => key.startsWith('arc1-dispatch-quarantine/')), true);

const backlogStore = new FakeStore();
const backlogIds = [];
for (let index = 0; index < 45; index += 1) {
  const id = `00000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`;
  backlogIds.push(id);
  const item = await normalizeIntakeForm(form, now, () => id);
  await backlogStore.setJSON(item.key, item.record, { onlyIfNew: true });
}
const recoveredIds = [];
const recoverBatch = async (cursor = null) => recoverPendingArc1Dispatches(new Request(
  `https://arcweb.onl/internal/intake/arc1/recover${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`,
  { method: 'POST' },
), env, {
  store: backlogStore,
  clock: () => new Date(now.getTime() + 60_000),
  fetch: async (url, options) => {
    recoveredIds.push(JSON.parse(options.body).submission_id);
    return { status: 202, url };
  },
});
const batchOne = await recoverBatch();
assert.equal(batchOne.state, 'RECOVERY_PARTIAL');
assert.equal(batchOne.attempted, 20);
assert.match(batchOne.next_cursor, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
const batchTwo = await recoverBatch(batchOne.next_cursor);
assert.equal(batchTwo.state, 'RECOVERY_PARTIAL');
assert.equal(batchTwo.attempted, 20);
const batchThree = await recoverBatch(batchTwo.next_cursor);
assert.equal(batchThree.attempted, 5);
let completion = batchThree;
let completionCalls = 0;
while (completion.next_cursor) {
  completion = await recoverBatch(completion.next_cursor);
  completionCalls += 1;
  assert.ok(completionCalls < 5);
}
assert.equal(completion.state, 'RECOVERY_COMPLETE');
assert.deepEqual([...new Set(recoveredIds)].sort(), backlogIds.sort(),
  'Cursor-resumable recovery must process a backlog without retrying the head or starving later submissions.');
await assert.rejects(recoverBatch(`${batchOne.next_cursor.slice(0, -1)}x`), /cursor signature/i,
  'Recovery continuation must be authenticated and tamper-evident.');

const deadlineStore = new FakeStore();
for (let index = 0; index < 2; index += 1) {
  const id = `00000001-0000-4000-8000-${index.toString(16).padStart(12, '0')}`;
  const item = await normalizeIntakeForm(form, now, () => id);
  await deadlineStore.setJSON(item.key, item.record, { onlyIfNew: true });
}
let recoveryWallMs = 0;
const deadlineBatch = await recoverPendingArc1Dispatches(request, env, {
  store: deadlineStore,
  clock: () => new Date(now.getTime() + 60_000),
  wallClock: () => recoveryWallMs,
  fetch: async (url) => { recoveryWallMs = 8_001; return { status: 202, url }; },
});
assert.equal(deadlineBatch.state, 'RECOVERY_PARTIAL');
assert.equal(deadlineBatch.attempted, 1,
  'One shared wall-clock deadline must bound the entire recovery invocation, not each dispatch independently.');
assert.ok(deadlineBatch.next_cursor);

class DeepPagedStore extends FakeStore {
  list({ prefix, paginate }) {
    assert.equal(paginate, true);
    const keys = [...this.values.keys()].filter((key) => key.startsWith(prefix)).sort();
    return { async *[Symbol.asyncIterator]() {
      for (const key of keys) yield { blobs: [{ key }] };
    } };
  }
}
const deepPagedStore = new DeepPagedStore();
const deepIds = [];
for (let index = 0; index < 30; index += 1) {
  const id = `00000002-0000-4000-8000-${index.toString(16).padStart(12, '0')}`;
  deepIds.push(id);
  const item = await normalizeIntakeForm(form, now, () => id);
  await deepPagedStore.setJSON(item.key, item.record, { onlyIfNew: true });
}
let deepCursor = null;
const deepRecovered = [];
let deepCalls = 0;
do {
  const result = await recoverPendingArc1Dispatches(request, env, {
    store: deepPagedStore, cursor: deepCursor, clock: () => new Date(now.getTime() + 60_000),
    fetch: async (url, options) => { deepRecovered.push(JSON.parse(options.body).submission_id); return { status: 202, url }; },
  });
  deepCalls += 1;
  deepCursor = result.next_cursor;
  assert.ok(deepCalls < 10);
} while (deepCursor);
assert.deepEqual([...new Set(deepRecovered)].sort(), deepIds.sort(),
  'A continuation after page 20 must advance beyond earlier provider pages instead of looping forever.');

const latencyStore = new DeepPagedStore();
const latencyIds = [];
for (let index = 0; index < 30; index += 1) {
  const id = `00000003-0000-4000-8000-${index.toString(16).padStart(12, '0')}`;
  latencyIds.push(id);
  const item = await normalizeIntakeForm(form, now, () => id);
  await latencyStore.setJSON(item.key, item.record, { onlyIfNew: true });
}
let latencyCursor = null;
let latencyWall = 0;
const latencyRecovered = [];
let latencyCalls = 0;
do {
  latencyWall = 0;
  const result = await recoverPendingArc1Dispatches(request, env, {
    store: latencyStore, cursor: latencyCursor, clock: () => new Date(now.getTime() + 60_000),
    wallClock: () => { const current = latencyWall; latencyWall += 100; return current; },
    fetch: async (url, options) => { latencyRecovered.push(JSON.parse(options.body).submission_id); return { status: 202, url }; },
  });
  latencyCalls += 1;
  latencyCursor = result.next_cursor;
  assert.ok(latencyCalls < 50, 'Deep UUID prefixes must prevent old provider pages from consuming every continuation deadline.');
} while (latencyCursor);
assert.deepEqual([...new Set(latencyRecovered)].sort(), latencyIds.sort(),
  'Recovery must continue making progress even when each listed page consumes wall-clock budget.');

const providerHighIds = Array.from({ length: 20 }, (_, index) =>
  `00ff0000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`);
const providerLowerId = '00000000-0000-4000-8000-ffffffffffff';
const providerUnicodeKeys = [
  'submissions/00é-precomposed-malformed',
  'submissions/00e\u0301-combining-malformed',
  'submissions/00😀-astral-malformed',
];
const providerSequence = [
  ...providerHighIds.map((id) => `submissions/${id}`),
  ...providerUnicodeKeys,
  `submissions/${providerLowerId}`,
];
const providerSequenceStore = new ProviderSequenceRecoveryStore([
  [providerSequence.slice(0, 23), providerSequence.slice(23)],
  [
    providerSequence.slice(0, 7), providerSequence.slice(7, 16),
    providerSequence.slice(16, 22), providerSequence.slice(22),
  ],
]);
for (const id of [...providerHighIds, providerLowerId]) {
  const item = await normalizeIntakeForm(form, now, () => id);
  await providerSequenceStore.setJSON(item.key, item.record, { onlyIfNew: true });
}
let providerCursor = null;
let providerCalls = 0;
const providerRecovered = [];
do {
  const result = await recoverPendingArc1Dispatches(request, env, {
    store: providerSequenceStore, cursor: providerCursor, clock: () => new Date(now.getTime() + 60_000),
    fetch: async (url, options) => {
      providerRecovered.push(JSON.parse(options.body).submission_id);
      return { status: 202, url };
    },
  });
  providerCursor = result.next_cursor;
  providerCalls += 1;
  assert.ok(providerCalls < 8);
  if (providerCalls === 1) {
    assert.equal(result.attempted, 20);
    const cursorValue = JSON.parse(Buffer.from(providerCursor.split('.')[0], 'base64url').toString('utf8'));
    assert.deepEqual(Object.keys(cursorValue).sort(), ['position', 'sequence_hmac_sha256', 'shard', 'v']);
    assert.doesNotMatch(JSON.stringify(cursorValue), /00ff|é|😀|combining/,
      'Recovery cursors must bind provider order without exposing submission IDs or Unicode keys.');
  }
} while (providerCursor);
assert.deepEqual([...new Set(providerRecovered)].sort(), [...providerHighIds, providerLowerId].sort(),
  'A lower key on a later provider page must not be skipped after nonmonotonic/Unicode continuation and page reflow.');

const reorderedHighIds = Array.from({ length: 20 }, (_, index) =>
  `00aa0000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`);
const reorderedLowerId = '00000000-0000-4000-8000-eeeeeeeeeeee';
const originalProviderOrder = [
  ...reorderedHighIds.map((id) => `submissions/${id}`),
  `submissions/${reorderedLowerId}`,
];
const changedProviderOrder = [originalProviderOrder.at(-1), ...originalProviderOrder.slice(0, -1)];
const reorderedStore = new ProviderSequenceRecoveryStore([
  [originalProviderOrder.slice(0, 20), originalProviderOrder.slice(20)],
  [changedProviderOrder.slice(0, 11), changedProviderOrder.slice(11)],
  [changedProviderOrder.slice(0, 8), changedProviderOrder.slice(8)],
]);
for (const id of [...reorderedHighIds, reorderedLowerId]) {
  const item = await normalizeIntakeForm(form, now, () => id);
  await reorderedStore.setJSON(item.key, item.record, { onlyIfNew: true });
}
const reorderedRecovered = [];
const firstReorderedRun = await recoverPendingArc1Dispatches(request, env, {
  store: reorderedStore, clock: () => new Date(now.getTime() + 60_000),
  fetch: async (url, options) => { reorderedRecovered.push(JSON.parse(options.body).submission_id); return { status: 202, url }; },
});
const resetReorderedRun = await recoverPendingArc1Dispatches(request, env, {
  store: reorderedStore, cursor: firstReorderedRun.next_cursor, clock: () => new Date(now.getTime() + 60_000),
  fetch: async () => { throw new Error('Sequence verification must not dispatch.'); },
});
assert.equal(resetReorderedRun.state, 'RECOVERY_PARTIAL');
assert.equal(resetReorderedRun.attempted, 0,
  'Provider sequence drift before the checkpoint must reset this shard without skipping or dispatching.');
assert.equal(JSON.parse(Buffer.from(resetReorderedRun.next_cursor.split('.')[0], 'base64url').toString('utf8')).position, 0);
let reorderedCursor = resetReorderedRun.next_cursor;
let reorderedCalls = 0;
do {
  const result = await recoverPendingArc1Dispatches(request, env, {
    store: reorderedStore, cursor: reorderedCursor, clock: () => new Date(now.getTime() + 60_000),
    fetch: async (url, options) => { reorderedRecovered.push(JSON.parse(options.body).submission_id); return { status: 202, url }; },
  });
  reorderedCursor = result.next_cursor;
  reorderedCalls += 1;
  assert.ok(reorderedCalls < 8);
} while (reorderedCursor);
assert.deepEqual([...new Set(reorderedRecovered)].sort(), [...reorderedHighIds, reorderedLowerId].sort(),
  'A stable retry after provider reordering must eventually dispatch every exact pending submission.');

const expiredBeforeNetworkStore = new FakeStore();
await expiredBeforeNetworkStore.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
let deadlineFetchCalls = 0;
const deferred = await dispatchIntakeToArc1Background(submissionId, request, env, {
  store: expiredBeforeNetworkStore, deadlineMs: 10, wallClock: () => 11,
  clock: () => new Date(now), fetch: async () => { deadlineFetchCalls += 1; throw new Error('must not call'); }, force: true,
});
assert.equal(deferred.state, 'DISPATCH_DEFERRED');
assert.equal(deadlineFetchCalls, 0);
assert.equal(expiredBeforeNetworkStore.values.get(normalized.key).data.arc1_dispatch.attempt_count, 0,
  'Deadline failure before network entry must not burn a delivery attempt or create a dead letter.');
const deadStore = new FakeStore(); await deadStore.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
let deadNow = new Date(now);
for (let attempt = 1; attempt <= 5; attempt += 1) {
  const result = await dispatchIntakeToArc1Background(submissionId, request, env, {
    store: deadStore, clock: () => new Date(deadNow), fetch: async () => { throw new Error('unavailable'); }, force: true,
  });
  if (attempt < 5) assert.equal(result.state, 'PENDING');
  deadNow = new Date(deadNow.getTime() + 1_000);
}
assert.equal(deadStore.values.get(normalized.key).data.arc1_dispatch.status, 'DEAD_LETTER');
assert.equal(deadStore.values.get(normalized.key).data.arc1_dispatch.alert_code, 'DISPATCH_MAX_ATTEMPTS');
assert.equal(backgroundConfig.background, true); assert.equal(Object.hasOwn(backgroundConfig, 'schedule'), false); assert.equal(recoveryConfig.path, '/internal/intake/arc1/recover'); assert.equal(recoveryConfig.method, 'POST'); assert.equal(recoveryConfig.rateLimit.windowLimit, 1);
const saved = { ...process.env };
try {
  Object.assign(process.env, env, testActivationAuthority(new Date()));
  assert.equal((await backgroundHandler(new Request('https://arcweb.onl/.netlify/functions/intake-arc1-background', { method: 'POST' }))).status, 401);
  assert.equal((await recoveryHandler(new Request('https://arcweb.onl/internal/intake/arc1/recover', { method: 'POST' }))).status, 401);
  process.env.ARC_INTAKE_ARC1_DISPATCH_ENABLED = 'false';
  const revoked = await backgroundHandler(new Request('https://arcweb.onl/.netlify/functions/intake-arc1-background', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.ARC_INTAKE_ARC1_DISPATCH_SECRET}`, 'content-type': 'application/json' },
    body: JSON.stringify({ schema: 'arc-intake-arc1-delivery-request-v1', submission_id: submissionId }),
  }), {
    get intakeStore() { throw new Error('Revoked dispatch must not touch storage.'); },
    fetch: async () => { throw new Error('Revoked dispatch must not touch the network.'); },
  });
  assert.equal(revoked.status, 503, 'A queued invocation must honor dispatch revocation before delivery.');
  process.env.ARC_INTAKE_ARC1_DISPATCH_ENABLED = 'true';
  const oversized = await backgroundHandler({
    method: 'POST',
    headers: new Headers({ authorization: `Bearer ${env.ARC_INTAKE_ARC1_DISPATCH_SECRET}`, 'content-type': 'application/json', 'content-length': '2049' }),
    json() { throw new Error('Oversized background body must be rejected before parse.'); },
  });
  assert.equal(oversized.status, 400);
  const chunkedOversized = new Request('https://arcweb.onl/.netlify/functions/intake-arc1-background', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.ARC_INTAKE_ARC1_DISPATCH_SECRET}`, 'content-type': 'application/json' },
    body: new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(1024)); controller.enqueue(new Uint8Array(1025)); controller.close(); } }),
    duplex: 'half',
  });
  assert.equal((await backgroundHandler(chunkedOversized)).status, 400, 'Chunked oversized background JSON must be bounded before parse.');
  Object.assign(process.env, {
    ARC_INTAKE_ARC1_BRIDGE_ENABLED: 'true', ARC_INTAKE_ARC1_ENDPOINT: 'https://hooks.example.test/arc1/intake',
    ARC_INTAKE_ARC1_DESTINATION_BEARER: 'destination-bearer-unique-0123456789',
    ARC_INTAKE_ARC1_EVIDENCE_SECRET: 'evidence-secret-unique-0123456789-abcdef',
    ARC_INTAKE_ARC1_ACK_SECRET: 'ack-secret-unique-0123456789-abcdefghij',
    ARC_INTAKE_ARC1_STATE_SECRET: 'state-secret-unique-0123456789-abcdefgh',
    ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET: 'proof-secret-unique-0123456789-abcdefgh',
    SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  });
  const ackedRecord = { ...normalized.record, arc1_delivery: {
    ...normalized.record.arc1_delivery, status: 'ACKED', attempt_count: 1, next_attempt_at: now.toISOString(),
    last_attempt_at: now.toISOString(), acknowledged_at: now.toISOString(), acknowledgement_sha256: 'a'.repeat(64),
    consumer_claim_key_hmac_sha256: 'b'.repeat(64),
  } };
  const backgroundStore = new FakeStore(); await backgroundStore.setJSON(normalized.key, ackedRecord, { onlyIfNew: true });
  const backgroundSuccess = await backgroundHandler(new Request('https://arcweb.onl/.netlify/functions/intake-arc1-background', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.ARC_INTAKE_ARC1_DISPATCH_SECRET}`, 'content-type': 'application/json' },
    body: JSON.stringify({ schema: 'arc-intake-arc1-delivery-request-v1', submission_id: submissionId }),
  }), { intakeStore: backgroundStore });
  assert.equal(backgroundSuccess.status, 204, 'A completed background handler must return a bodyless 204.');
} finally { for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key]; Object.assign(process.env, saved); }
console.log('ARC same-deploy background intake dispatcher and authenticated recovery contract passed.');
