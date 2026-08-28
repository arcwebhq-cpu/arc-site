import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import {
  EMAIL_SEND_ATTEMPT_TOMBSTONE_SCHEMA,
  markEmailProviderAccepted,
  pruneTerminalEmailSendAttempts,
  reconcileEmailProviderEvent,
  reserveEmailSendAttempt,
  validateEmailSendAttemptRetentionTombstone,
} from '../netlify/lib/email-send-attempt-core.mjs';
import {
  EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA,
  pruneExpiredEmailRecipientCapsules,
  sealEmailRecipientCapsule,
  validateEmailRecipientVaultTombstone,
} from '../netlify/lib/email-recipient-vault-core.mjs';
import {
  TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_SCHEMA,
  TRANSACTIONAL_EMAIL_RETENTION_SWEEP_KEY,
  runTransactionalEmailRetentionSweepCycle,
  validateTransactionalEmailRetentionMissingSourceAnomaly,
  validateTransactionalEmailRetentionSweepReceipt,
  validateTransactionalEmailRetentionSweepState,
} from '../netlify/lib/transactional-email-retention-sweep-core.mjs';
import {
  RETENTION_FINALIZE_RECEIPT_SCHEMA,
  RETENTION_GENERATION_FENCE_STATE_SCHEMA,
  beginRetentionFreeze,
  ensureRetentionGenerationFence,
  readRetentionGenerationFence,
} from '../netlify/lib/retention-generation-fence-core.mjs';
import { firstPartyLegalHoldKey } from '../netlify/lib/first-party-retention-core.mjs';

class PagedStore {
  constructor(pageSize = 2) {
    this.values = new Map();
    this.sequence = 0;
    this.pageSize = pageSize;
    this.paginatedPrefixes = [];
    this.conditionalWrites = [];
    this.throwAfterConditionalWrites = new Set();
    this.vanishAfterList = new Set();
  }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    if (options.onlyIfMatch) this.conditionalWrites.push({ key, etag: options.onlyIfMatch });
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && (!current || current.etag !== options.onlyIfMatch)) return { modified: false };
    const etag = `retention-etag-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    if (options.onlyIfMatch && this.throwAfterConditionalWrites.delete(key)) {
      throw new Error('Synthetic ambiguous conditional-write response.');
    }
    return { modified: true, etag };
  }
  failAfterConditionalWrite(key) { this.throwAfterConditionalWrites.add(key); }
  vanishListedKey(key) { this.vanishAfterList.add(key); }
  async delete() { throw new Error('Unconditional retention delete is forbidden.'); }
  list({ prefix = '', paginate = false } = {}) {
    assert.equal(paginate, true, 'Retention sweeps must manually consume every provider page.');
    this.paginatedPrefixes.push(prefix);
    const keys = [...this.values.keys()].filter((key) => key.startsWith(prefix)).sort();
    const size = this.pageSize;
    const values = this.values;
    const vanishAfterList = this.vanishAfterList;
    return (async function *pages() {
      for (let index = 0; index < keys.length; index += size) {
        const pageKeys = keys.slice(index, index + size);
        for (const key of pageKeys) if (vanishAfterList.delete(key)) values.delete(key);
        yield { blobs: pageKeys.map((key) => ({ key })) };
      }
      if (keys.length === 0) yield { blobs: [] };
    }());
  }
}

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const canonicalJson = (value) => Array.isArray(value)
  ? `[${value.map(canonicalJson).join(',')}]`
  : value && typeof value === 'object'
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`
    : JSON.stringify(value);
const now = new Date();
const env = {
  ARC_TRANSACTIONAL_EMAIL_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET: 'retention-attempt-secret-unique-0123456789abcdef',
  ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS: '30',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'transactional-retention-fence-secret-unique-0123456789abcdef',
  ARC_FIRST_PARTY_RETENTION_HMAC_SECRET:
    'transactional-retention-hold-secret-unique-0123456789abcdef',
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY: Buffer.alloc(32, 17).toString('base64url'),
  ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET: 'retention-vault-secret-unique-0123456789abcdef',
};
const signedLegalHold = (family, subject, issuedAt, expiresAt = null) => {
  const unsigned = {
    schema: 'arc-first-party-retention-legal-hold-v1', version: 1,
    family, subject_hmac_sha256: subject, reason_code: 'LEGAL',
    issued_at: issuedAt.toISOString(), expires_at: expiresAt?.toISOString() || null,
    customer_data_stored: false,
  };
  return { ...unsigned, record_hmac_sha256: hmac(
    env.ARC_FIRST_PARTY_RETENTION_HMAC_SECRET,
    `arc-first-party-retention-legal-hold-record-v1\n${canonicalJson(unsigned)}`,
  ) };
};

const retentionControls = new WeakMap();
const retentionStores = (attempt, vault) => {
  if (!retentionControls.has(attempt)) retentionControls.set(attempt, new PagedStore());
  return { attempt, vault, control: retentionControls.get(attempt) };
};
assert.deepEqual(await runTransactionalEmailRetentionSweepCycle({
  ...env, ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED: 'false',
}, new Proxy({}, { get() { throw new Error('Disabled retention touched storage.'); } })), {
  state: 'DISABLED', next_cursor: null,
});

// A FROZEN gate owned by another retention family is ordinary contention. It
// must not be mistaken for a resumable transactional manifest or alert.
{
  const attempt = new PagedStore();
  const vault = new PagedStore();
  const control = new PagedStore();
  const frozenAt = new Date(now.getTime() + 500);
  await ensureRetentionGenerationFence(control, env, { clock: () => frozenAt });
  const foreign = {
    generation: 0,
    manifest_entry_count: 1,
    manifest_sha256: sha256('foreign-retention-manifest'),
    subject_hmac_sha256: sha256('foreign-retention-subject'),
  };
  assert.equal((await beginRetentionFreeze(control, foreign, env, {
    clock: () => frozenAt, staleAfterMs: 60_000,
  })).state, 'FROZEN');
  const alerts = [];
  const result = await runTransactionalEmailRetentionSweepCycle(env,
    { attempt, vault, control }, {
      clock: () => new Date(frozenAt.getTime() + 1_000),
      uuid: () => '05000000-0000-4000-8000-000000000001',
      emitCriticalAlert: async (alert) => alerts.push(alert),
    });
  assert.equal(result.state, 'IN_PROGRESS');
  assert.equal(alerts.length, 0);
  assert.equal(attempt.values.size, 0,
    'Foreign FROZEN contention must not initialize or mutate transactional retention state.');
  assert.equal((await readRetentionGenerationFence(control, env)).record.status, 'FROZEN');
}

const attemptInput = (jobKey) => ({
  job_kind: 'operations_alert',
  job_key: jobKey,
  provider_idempotency_key: `retention-provider-${jobKey}`,
  recipient_email_sha256: sha256(`recipient:${jobKey}`),
  sender_sha256: sha256('sender'),
  message_sha256: sha256(`message:${jobKey}`),
});
const pruneAt = new Date(now.getTime() + 31 * 86_400_000);
await assert.rejects(pruneExpiredEmailRecipientCapsules(),
  /ARC_EMAIL_VAULT_RETENTION_PRUNE_RETIRED_USE_FROZEN_SWEEP/);
await assert.rejects(pruneTerminalEmailSendAttempts(),
  /ARC_EMAIL_ATTEMPT_RETENTION_PRUNE_RETIRED_USE_FROZEN_SWEEP/);

const runnerAttemptStore = new PagedStore();
const runnerVaultStore = new PagedStore();
await sealEmailRecipientCapsule(runnerVaultStore, {
  job_kind: 'operations_alert', job_key: 'runner-vault-subject-0001',
  recipient_email: 'runner-vault@example.test', private_payload: { marker: 'runner' },
  expires_at: new Date(now.getTime() + 1_000).toISOString(),
}, env, { clock: () => now, randomBytes: () => Buffer.alloc(12, 41) });
const runnerReservation = await reserveEmailSendAttempt(runnerAttemptStore,
  attemptInput('runner-attempt-subject-0001'), env, { clock: () => now });
const runnerProviderId = '99999999-2222-4333-8444-555555555555';
await markEmailProviderAccepted(runnerAttemptStore, {
  attempt_hmac_sha256: runnerReservation.attempt_hmac_sha256,
  provider_message_id: runnerProviderId,
}, env, { clock: () => now });
await reconcileEmailProviderEvent(runnerAttemptStore, {
  provider: 'resend', provider_event_id: 'evt_runner_retention',
  provider_message_id: runnerProviderId, event_type: 'email.delivered',
  occurred_at: now.toISOString(), payload_sha256: sha256('runner-retention-event'),
}, env);
const runnerOptions = (offset, uuid) => ({
  clock: () => new Date(pruneAt.getTime() + offset), uuid: () => uuid,
});
assert.equal((await runTransactionalEmailRetentionSweepCycle(env,
  retentionStores(runnerAttemptStore, runnerVaultStore),
  runnerOptions(0, '11111111-1111-4111-8111-111111111111'))).state, 'PARTIAL');
assert.equal((await runTransactionalEmailRetentionSweepCycle(env,
  retentionStores(runnerAttemptStore, runnerVaultStore),
  runnerOptions(60_000, '22222222-2222-4222-8222-222222222222'))).state, 'PARTIAL');
assert.equal((await runTransactionalEmailRetentionSweepCycle(env,
  retentionStores(runnerAttemptStore, runnerVaultStore),
  runnerOptions(120_000, '33333333-3333-4333-8333-333333333333'))).state, 'PARTIAL');
const completedSweep = await runTransactionalEmailRetentionSweepCycle(env,
  retentionStores(runnerAttemptStore, runnerVaultStore),
  runnerOptions(180_000, '44444444-4444-4444-8444-444444444444'));
assert.equal(completedSweep.state, 'COMPLETE');
const sweepState = validateTransactionalEmailRetentionSweepState(
  runnerAttemptStore.values.get(TRANSACTIONAL_EMAIL_RETENTION_SWEEP_KEY).data,
  env.ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET,
);
assert.deepEqual(sweepState.vault_counts, { inspected: 1, deleted: 1 });
assert.deepEqual(sweepState.attempt_counts,
  { inspected: 1, deleted: 1, quarantined: 0, event_records_deleted: 1,
    provider_message_records_deleted: 1 });
const receiptEntry = [...runnerAttemptStore.values.entries()].find(([key]) =>
  key.startsWith('retention/completions/'))?.[1];
assert.ok(receiptEntry, 'A complete traversal must persist an immutable sweep receipt.');
const receipt = validateTransactionalEmailRetentionSweepReceipt(receiptEntry.data,
  env.ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET);
assert.equal(receipt.customer_data_stored, false);
assert.equal((await runTransactionalEmailRetentionSweepCycle(env,
  retentionStores(runnerAttemptStore, runnerVaultStore),
  runnerOptions(240_000, '55555555-5555-4555-8555-555555555555'))).idempotent_replay, true);

const anomalyEntries = (store) => [...store.values.entries()].filter(([key, entry]) =>
  key.startsWith('retention/missing-source/') &&
  entry.data.schema === TRANSACTIONAL_EMAIL_RETENTION_MISSING_SOURCE_SCHEMA);
const completionEntries = (store) => [...store.values.keys()].filter((key) =>
  key.startsWith('retention/completions/'));
const assertSignedMissingSource = (store, expectedKind, rawKey) => {
  const entries = anomalyEntries(store);
  assert.equal(entries.length, 1);
  const [key, entry] = entries[0];
  assert.match(key, /^retention\/missing-source\/[a-f0-9]{64}\/[a-f0-9]{64}$/);
  const anomaly = validateTransactionalEmailRetentionMissingSourceAnomaly(
    entry.data, env.ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET,
  );
  assert.equal(anomaly.source_kind, expectedKind);
  assert.equal(anomaly.customer_data_stored, false);
  assert.equal(completionEntries(store).length, 0,
    'A missing marked source must prevent the completion receipt.');
  assert.doesNotMatch(JSON.stringify(anomaly), new RegExp(rawKey.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  return anomaly;
};
const missingRunnerOptions = (clock, uuid) => ({ clock: () => clock, uuid: () => uuid, limit: 500 });
const advanceToAttemptPhase = async (attempt, vault, clock, uuid) => {
  const result = await runTransactionalEmailRetentionSweepCycle(env, retentionStores(attempt, vault),
    missingRunnerOptions(clock, uuid));
  assert.equal(result.state, 'PARTIAL');
  assert.equal(result.phase, 'attempt');
};
const seedTerminalAttempt = async (store, label, clock) => {
  const reservation = await reserveEmailSendAttempt(store, attemptInput(label), env, { clock: () => clock });
  const providerMessageId = `${sha256(label).slice(0, 8)}-2222-4333-8444-555555555555`;
  await markEmailProviderAccepted(store, {
    attempt_hmac_sha256: reservation.attempt_hmac_sha256,
    provider_message_id: providerMessageId,
  }, env, { clock: () => clock });
  await reconcileEmailProviderEvent(store, {
    provider: 'resend', provider_event_id: `evt_missing_${label}`,
    provider_message_id: providerMessageId, event_type: 'email.delivered',
    occurred_at: clock.toISOString(), payload_sha256: sha256(`missing:${label}`),
  }, env);
  return { providerMessageId, reservation };
};

const missingVaultAttemptStore = new PagedStore();
const missingVaultStore = new PagedStore();
await sealEmailRecipientCapsule(missingVaultStore, {
  job_kind: 'operations_alert', job_key: 'missing-vault-source',
  recipient_email: 'missing-vault@example.test', private_payload: { marker: 'missing-vault' },
  expires_at: new Date(now.getTime() - 1_000).toISOString(),
}, env, { clock: () => new Date(now.getTime() - 2_000), randomBytes: () => Buffer.alloc(12, 31) });
const missingVaultKey = [...missingVaultStore.values.keys()].find((key) => key.startsWith('capsules/'));
missingVaultStore.vanishListedKey(missingVaultKey);
await assert.rejects(runTransactionalEmailRetentionSweepCycle(env,
  retentionStores(missingVaultAttemptStore, missingVaultStore),
  missingRunnerOptions(now, '50000000-0000-4000-8000-000000000001')), /MISSING_SOURCE_BLOCKED/);
assertSignedMissingSource(missingVaultAttemptStore, 'vault-capsule', missingVaultKey);
await assert.rejects(runTransactionalEmailRetentionSweepCycle(env,
  retentionStores(missingVaultAttemptStore, missingVaultStore),
  missingRunnerOptions(new Date(now.getTime() + 10 * 60_000),
    '50000000-0000-4000-8000-000000000008')), /MISSING_SOURCE_BLOCKED/,
  'Exact retry must remain blocked by the durable anomaly after the source is no longer listed.');
assert.equal(anomalyEntries(missingVaultAttemptStore).length, 1,
  'Exact retry must reuse the immutable missing-source anomaly.');

const missingAttemptStore = new PagedStore();
const emptyAttemptVault = new PagedStore();
const missingAttemptReservation = await reserveEmailSendAttempt(
  missingAttemptStore, attemptInput('missing-attempt-source'), env,
  { clock: () => now },
);
await advanceToAttemptPhase(missingAttemptStore, emptyAttemptVault, pruneAt,
  '50000000-0000-4000-8000-000000000002');
const missingAttemptKey = `attempts/${missingAttemptReservation.attempt_hmac_sha256}`;
missingAttemptStore.vanishListedKey(missingAttemptKey);
await assert.rejects(runTransactionalEmailRetentionSweepCycle(env,
  retentionStores(missingAttemptStore, emptyAttemptVault),
  missingRunnerOptions(new Date(pruneAt.getTime() + 60_000),
    '50000000-0000-4000-8000-000000000003')), /MISSING_SOURCE_BLOCKED/);
assertSignedMissingSource(missingAttemptStore, 'email-attempt', missingAttemptKey);

const missingEventStore = new PagedStore();
const emptyEventVault = new PagedStore();
const missingEvent = await seedTerminalAttempt(missingEventStore, 'event001', now);
await advanceToAttemptPhase(missingEventStore, emptyEventVault, pruneAt,
  '50000000-0000-4000-8000-000000000004');
const missingEventKey = [...missingEventStore.values.entries()].find(([key, entry]) =>
  key.startsWith('provider-events/resend/') &&
  entry.data.attempt_hmac_sha256 === missingEvent.reservation.attempt_hmac_sha256)[0];
missingEventStore.vanishListedKey(missingEventKey);
await assert.rejects(runTransactionalEmailRetentionSweepCycle(env,
  retentionStores(missingEventStore, emptyEventVault),
  missingRunnerOptions(new Date(pruneAt.getTime() + 60_000),
    '50000000-0000-4000-8000-000000000005')), /MISSING_SOURCE_BLOCKED/);
assertSignedMissingSource(missingEventStore, 'provider-event-index', missingEventKey);

const missingMessageStore = new PagedStore();
const emptyMessageVault = new PagedStore();
const missingMessage = await seedTerminalAttempt(missingMessageStore, 'message1', now);
await advanceToAttemptPhase(missingMessageStore, emptyMessageVault, pruneAt,
  '50000000-0000-4000-8000-000000000006');
const missingMessageHmac = hmac(env.ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET,
  `arc-transactional-email-provider-message-id-v1\nresend\n${missingMessage.providerMessageId}`);
const missingMessageKey = `provider-messages/resend/${missingMessageHmac}`;
missingMessageStore.values.delete(missingMessageKey);
await assert.rejects(runTransactionalEmailRetentionSweepCycle(env,
  retentionStores(missingMessageStore, emptyMessageVault),
  missingRunnerOptions(new Date(pruneAt.getTime() + 60_000),
    '50000000-0000-4000-8000-000000000007')), /MISSING_SOURCE_BLOCKED/);
assertSignedMissingSource(missingMessageStore, 'provider-message-index', missingMessageKey);

for (const attempt of [missingVaultAttemptStore, missingAttemptStore, missingEventStore,
  missingMessageStore]) {
  const control = retentionControls.get(attempt);
  assert.equal((await readRetentionGenerationFence(control, env)).record.status, 'FROZEN',
    'A marked missing source must leave the global gate fail-closed.');
  assert.equal([...control.values.values()].filter(({ data }) =>
    data.schema === 'arc-first-party-retention-missing-source-anomaly-v1').length, 1,
  'Every transactional missing source must also persist signed global anomaly evidence.');
}

// Crash after a child CAS: exact stale retry must load the immutable manifest,
// validate the existing output, finish remaining children, and tombstone the
// subject primary last without rebuilding from live listings.
const crashAttemptStore = new PagedStore(1);
const crashVaultStore = new PagedStore(1);
const crashControlStore = new PagedStore(1);
const crashReservation = await reserveEmailSendAttempt(crashAttemptStore,
  attemptInput('frozen-crash-subject-0001'), env, { clock: () => now });
const crashProviderId = '77777777-2222-4333-8444-555555555555';
await markEmailProviderAccepted(crashAttemptStore, {
  attempt_hmac_sha256: crashReservation.attempt_hmac_sha256,
  provider_message_id: crashProviderId,
}, env, { clock: () => now });
for (const [index, type] of ['email.delivered', 'email.failed', 'email.bounced'].entries()) {
  await reconcileEmailProviderEvent(crashAttemptStore, {
    provider: 'resend', provider_event_id: `evt_frozen_crash_${index}`,
    provider_message_id: crashProviderId, event_type: type,
    occurred_at: new Date(now.getTime() + index).toISOString(),
    payload_sha256: sha256(`frozen-crash-payload-${index}`),
  }, env);
}
const crashStores = { attempt: crashAttemptStore, vault: crashVaultStore, control: crashControlStore };
const crashBase = new Date(pruneAt.getTime() + 30 * 60_000);
assert.equal((await runTransactionalEmailRetentionSweepCycle(env, crashStores, {
  clock: () => crashBase, uuid: () => '60000000-0000-4000-8000-000000000001', limit: 500,
})).phase, 'attempt');
const mutationOrder = [];
let crashInjected = false;
await assert.rejects(runTransactionalEmailRetentionSweepCycle(env, crashStores, {
  clock: () => new Date(crashBase.getTime() + 60_000),
  uuid: () => '60000000-0000-4000-8000-000000000002', limit: 500,
  afterSubjectMutation: async (entry) => {
    mutationOrder.push(entry.source_kind);
    if (!crashInjected && entry.source_kind === 'provider-event-index') {
      crashInjected = true;
      throw new Error('synthetic frozen child crash');
    }
  },
}), /synthetic frozen child crash/);
assert.equal((await readRetentionGenerationFence(crashControlStore, env)).record.status, 'FROZEN');
assert.equal(crashAttemptStore.values.get(
  `attempts/${crashReservation.attempt_hmac_sha256}`).data.schema,
  'arc-transactional-email-attempt-v1', 'A partial failure must not tombstone the primary.');
const resumedCrash = await runTransactionalEmailRetentionSweepCycle(env, crashStores, {
  clock: () => new Date(crashBase.getTime() + 4 * 60_000),
  uuid: () => '60000000-0000-4000-8000-000000000003', limit: 500,
  afterSubjectMutation: async (entry) => { mutationOrder.push(entry.source_kind); },
});
assert.equal(resumedCrash.state, 'PARTIAL');
assert.equal((await readRetentionGenerationFence(crashControlStore, env)).record.status, 'OPEN');
assert.equal(mutationOrder.at(-1), 'email-attempt', 'The subject primary must be the final CAS.');
assert.ok(mutationOrder.indexOf('sweep-state') < mutationOrder.lastIndexOf('email-attempt'));
assert.equal(crashAttemptStore.values.get(
  `attempts/${crashReservation.attempt_hmac_sha256}`).data.schema,
  EMAIL_SEND_ATTEMPT_TOMBSTONE_SCHEMA);
assert.ok(crashAttemptStore.paginatedPrefixes.filter((prefix) =>
  prefix === 'provider-events/resend/').length >= 1,
'The one-subject attempt manifest must consume all provider-event pages before FROZEN.');
assert.equal((await runTransactionalEmailRetentionSweepCycle(env, crashStores, {
  clock: () => new Date(crashBase.getTime() + 5 * 60_000),
  uuid: () => '60000000-0000-4000-8000-000000000004', limit: 500,
})).state, 'COMPLETE');
const frozenManifestRecords = [...crashControlStore.values.values()].filter(({ data }) =>
  data.schema === 'arc-transactional-email-retention-subject-manifest-v1');
assert.ok(frozenManifestRecords.length >= 2);
assert.doesNotMatch(JSON.stringify(frozenManifestRecords),
  /recipient_email|message_sha256|payload_sha256|provider_idempotency/,
'Persisted frozen manifests must remain PII-free.');
assert.ok([...crashControlStore.values.values()].some(({ data }) =>
  data.schema === RETENTION_FINALIZE_RECEIPT_SCHEMA),
'Every completed frozen subject must have an immutable global finalize receipt.');

// Each authority heartbeat must use a fresh clock value. A long subject apply
// therefore extends stale_at instead of repeatedly writing its start time.
const heartbeatAttemptStore = new PagedStore();
const heartbeatVaultStore = new PagedStore();
const heartbeatControlStore = new PagedStore(1);
for (let index = 0; index < 4; index += 1) {
  const subject = sha256(`unrelated-heartbeat-hold-${index}`);
  await heartbeatControlStore.setJSON(firstPartyLegalHoldKey('review', subject),
    signedLegalHold('review', subject, now), { onlyIfNew: true });
}
await sealEmailRecipientCapsule(heartbeatVaultStore, {
  job_kind: 'operations_alert', job_key: 'frozen-heartbeat-0001',
  recipient_email: 'heartbeat@example.test', private_payload: { marker: 'heartbeat' },
  expires_at: new Date(now.getTime() + 1_000).toISOString(),
}, env, { clock: () => now, randomBytes: () => Buffer.alloc(12, 61) });
let heartbeatTick = 0;
const heartbeatStaleAts = [];
await runTransactionalEmailRetentionSweepCycle(env, {
  attempt: heartbeatAttemptStore, vault: heartbeatVaultStore, control: heartbeatControlStore,
}, {
  clock: () => new Date(now.getTime() + 2_000 + heartbeatTick++ * 750),
  uuid: () => '65000000-0000-4000-8000-000000000001', staleAfterMs: 1_000,
  afterSubjectMutation: async () => {
    heartbeatStaleAts.push((await readRetentionGenerationFence(
      heartbeatControlStore, env)).record.stale_at);
  },
});
assert.equal(heartbeatStaleAts.length, 2);
assert.ok(Date.parse(heartbeatStaleAts[1]) > Date.parse(heartbeatStaleAts[0]),
'Authority renewal must advance stale_at during a long FROZEN mutation.');
assert.ok(heartbeatTick * 750 > 1_000 && heartbeatControlStore.paginatedPrefixes
  .filter((prefix) => prefix === 'first-party-retention/legal-holds/').length >= 2,
'Paginated hold recheck and output readbacks must keep renewing beyond the stale interval.');

// A signed hold that appears after the manifest snapshot but before the first
// CAS must be observed under FROZEN and leave the source untouched.
{
  const attempt = new PagedStore(1);
  const vault = new PagedStore(1);
  const control = new PagedStore(1);
  const handoff = sha256('transactional-late-hold-handoff');
  await sealEmailRecipientCapsule(vault, {
    job_kind: 'claim_invitation', job_key: 'late-hold-claim-job',
    recipient_email: 'late-hold@example.test', private_payload: { handoff_id: handoff },
    expires_at: new Date(now.getTime() + 1_000).toISOString(),
  }, env, { clock: () => now, randomBytes: () => Buffer.alloc(12, 71) });
  const capsuleKey = [...vault.values.keys()].find((key) => key.startsWith('capsules/'));
  await assert.rejects(runTransactionalEmailRetentionSweepCycle(env,
    { attempt, vault, control }, {
      clock: () => new Date(now.getTime() + 2_000),
      uuid: () => '66000000-0000-4000-8000-000000000001',
      afterSubjectFreeze: async () => {
        await control.setJSON(firstPartyLegalHoldKey('handoff', handoff),
          signedLegalHold('handoff', handoff, now), { onlyIfNew: true });
      },
    }), /ARC_TRANSACTIONAL_EMAIL_RETENTION_LEGAL_HOLD_BLOCKED/);
  assert.equal(vault.values.get(capsuleKey).data.schema, 'arc-email-recipient-vault-v1');
  assert.equal((await readRetentionGenerationFence(control, env)).record.status, 'FROZEN');
}

// Handoff holds bind to both vault and attempt job-key digests even when an
// auxiliary capsule does not contain a plaintext handoff_id.
{
  const handoff = sha256('transactional-vault-job-key-hold');
  const attempt = new PagedStore(1);
  const vault = new PagedStore(1);
  const control = new PagedStore(1);
  await control.setJSON(firstPartyLegalHoldKey('handoff', handoff),
    signedLegalHold('handoff', handoff, now), { onlyIfNew: true });
  await sealEmailRecipientCapsule(vault, {
    job_kind: 'claim_invitation', job_key: handoff,
    recipient_email: 'vault-job-hold@example.test',
    private_payload: { source_invite_hmac_sha256: sha256('source-review') },
    expires_at: new Date(now.getTime() + 1_000).toISOString(),
  }, env, { clock: () => now, randomBytes: () => Buffer.alloc(12, 73) });
  await assert.rejects(runTransactionalEmailRetentionSweepCycle(env,
    { attempt, vault, control }, {
      clock: () => new Date(now.getTime() + 2_000),
      uuid: () => '67000000-0000-4000-8000-000000000001',
    }), /ARC_TRANSACTIONAL_EMAIL_RETENTION_LEGAL_HOLD_BLOCKED/);
  assert.ok([...vault.values.values()].some(({ data }) =>
    data.schema === 'arc-email-recipient-vault-v1'));
}
{
  const handoff = sha256('transactional-attempt-job-key-hold');
  const attempt = new PagedStore(1);
  const vault = new PagedStore(1);
  const control = new PagedStore(1);
  await control.setJSON(firstPartyLegalHoldKey('handoff', handoff),
    signedLegalHold('handoff', handoff, now), { onlyIfNew: true });
  const reservation = await reserveEmailSendAttempt(attempt, {
    ...attemptInput(handoff), job_kind: 'final_delivery', job_key: handoff,
  }, env, { clock: () => now });
  const providerMessageId = '88888888-2222-4333-8444-555555555555';
  await markEmailProviderAccepted(attempt, {
    attempt_hmac_sha256: reservation.attempt_hmac_sha256,
    provider_message_id: providerMessageId,
  }, env, { clock: () => now });
  await reconcileEmailProviderEvent(attempt, {
    provider: 'resend', provider_event_id: 'evt_attempt_job_hold',
    provider_message_id: providerMessageId, event_type: 'email.delivered',
    occurred_at: now.toISOString(), payload_sha256: sha256('attempt-job-hold'),
  }, env);
  assert.equal((await runTransactionalEmailRetentionSweepCycle(env,
    { attempt, vault, control }, {
      clock: () => pruneAt, uuid: () => '68000000-0000-4000-8000-000000000001',
    })).phase, 'attempt');
  await assert.rejects(runTransactionalEmailRetentionSweepCycle(env,
    { attempt, vault, control }, {
      clock: () => new Date(pruneAt.getTime() + 60_000),
      uuid: () => '68000000-0000-4000-8000-000000000002',
    }), /ARC_TRANSACTIONAL_EMAIL_RETENTION_LEGAL_HOLD_BLOCKED/);
  assert.equal(attempt.values.get(`attempts/${reservation.attempt_hmac_sha256}`).data.schema,
    'arc-transactional-email-attempt-v1');
}

// A correctly signed but expired hold is evidence, not an active block.
{
  const handoff = sha256('transactional-expired-hold');
  const attempt = new PagedStore(1);
  const vault = new PagedStore(1);
  const control = new PagedStore(1);
  await control.setJSON(firstPartyLegalHoldKey('handoff', handoff),
    signedLegalHold('handoff', handoff, now, new Date(now.getTime() + 1_000)),
    { onlyIfNew: true });
  await sealEmailRecipientCapsule(vault, {
    job_kind: 'claim_invitation', job_key: handoff,
    recipient_email: 'expired-hold@example.test', private_payload: { handoff_id: handoff },
    expires_at: new Date(now.getTime() + 1_000).toISOString(),
  }, env, { clock: () => now, randomBytes: () => Buffer.alloc(12, 75) });
  assert.equal((await runTransactionalEmailRetentionSweepCycle(env,
    { attempt, vault, control }, {
      clock: () => new Date(now.getTime() + 2_000),
      uuid: () => '69000000-0000-4000-8000-000000000001',
    })).state, 'PARTIAL');
  assert.ok([...vault.values.values()].some(({ data }) =>
    data.schema === EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA));
}

// If an auxiliary preview capsule cannot be mapped to its signed outbox, any
// active signed review hold conservatively preserves it.
{
  const heldReview = sha256('transactional-unresolved-review-hold');
  const attempt = new PagedStore(1);
  const vault = new PagedStore(1);
  const control = new PagedStore(1);
  await control.setJSON(firstPartyLegalHoldKey('review', heldReview),
    signedLegalHold('review', heldReview, now), { onlyIfNew: true });
  await sealEmailRecipientCapsule(vault, {
    job_kind: 'preview_review', job_key: 'unresolved-review-acceptance',
    recipient_email: 'review-hold@example.test',
    private_payload: { accepted_at: now.toISOString(), provider_message_id: 'provider-review-hold' },
    expires_at: new Date(now.getTime() + 1_000).toISOString(),
  }, env, { clock: () => now, randomBytes: () => Buffer.alloc(12, 77) });
  await assert.rejects(runTransactionalEmailRetentionSweepCycle(env,
    { attempt, vault, control }, {
      clock: () => new Date(now.getTime() + 2_000),
      uuid: () => '6a000000-0000-4000-8000-000000000001',
    }), /ARC_TRANSACTIONAL_EMAIL_RETENTION_LEGAL_HOLD_BLOCKED/);
  assert.ok([...vault.values.values()].some(({ data }) =>
    data.schema === 'arc-email-recipient-vault-v1'));
}

// An exact source value with a changed ETag is still drift. The gate remains
// FROZEN and no overwrite is permitted.
const driftAttemptStore = new PagedStore();
const driftVaultStore = new PagedStore();
const driftControlStore = new PagedStore();
await sealEmailRecipientCapsule(driftVaultStore, {
  job_kind: 'operations_alert', job_key: 'frozen-etag-drift-0001',
  recipient_email: 'etag-drift@example.test', private_payload: { marker: 'etag-drift' },
  expires_at: new Date(now.getTime() + 1_000).toISOString(),
}, env, { clock: () => now, randomBytes: () => Buffer.alloc(12, 53) });
await assert.rejects(runTransactionalEmailRetentionSweepCycle(env, {
  attempt: driftAttemptStore, vault: driftVaultStore, control: driftControlStore,
}, {
  clock: () => new Date(now.getTime() + 2_000),
  uuid: () => '70000000-0000-4000-8000-000000000001',
  afterSubjectFreeze: async ({ manifest }) => {
    const source = manifest.entries.find((entry) => entry.source_kind === 'vault-capsule');
    const current = await driftVaultStore.getWithMetadata(source.source_key,
      { type: 'json', consistency: 'strong' });
    await driftVaultStore.setJSON(source.source_key, current.data, { onlyIfMatch: current.etag });
  },
}), /FROZEN_MANIFEST_DRIFT/);
assert.equal((await readRetentionGenerationFence(driftControlStore, env)).record.status, 'FROZEN');
assert.equal([...driftVaultStore.values.values()].filter(({ data }) =>
  data.schema === EMAIL_RECIPIENT_VAULT_TOMBSTONE_SCHEMA).length, 0,
'A same-value ETag race must never be overwritten.');

console.log('ARC transactional-email paginated retention, quarantine, and durable sweep contract passed.');
