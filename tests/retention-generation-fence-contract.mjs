import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  RETENTION_GENERATION_FENCE_ALERT_SCHEMA,
  RETENTION_GENERATION_FENCE_SECRET_ENV,
  RETENTION_GENERATION_FENCE_STATE_KEY,
  RETENTION_GENERATION_FENCE_STORE,
  RETENTION_MISSING_SOURCE_ANOMALY_SCHEMA,
  assertRetentionGenerationFenceAuthority,
  beginRetentionFreeze,
  beginRetentionProducerOperation,
  completeRetentionFreeze,
  completeRetentionProducerOperation,
  ensureRetentionGenerationFence,
  readRetentionGenerationFence,
  raiseRetentionGenerationFenceCriticalAlert,
  recordRetentionMissingSourceAnomaly,
  recoverStaleRetentionGenerationFence,
  renewRetentionGenerationFenceAuthority,
  retentionFreezeOperationHmac,
  retentionGenerationFenceConfiguration,
  retentionGenerationFenceContract,
  retentionGenerationFenceKeys,
  retentionProducerOperationHmac,
  runRetentionProducerOperation,
  validateRetentionFinalizeReceipt,
  validateRetentionFreezeIntent,
  validateRetentionGenerationFenceAlert,
  validateRetentionGenerationFenceState,
  validateRetentionMissingSourceAnomaly,
  validateRetentionProducerCompletionReceipt,
  validateRetentionProducerIntent,
} from '../netlify/lib/retention-generation-fence-core.mjs';

class FakeStore {
  constructor() {
    this.values = new Map();
    this.sequence = 0;
    this.stateReadBarrier = null;
    this.failNextStateCas = false;
  }

  async getWithMetadata(key, options = {}) {
    assert.equal(options.type, 'json');
    assert.equal(options.consistency, 'strong');
    const entry = this.values.get(key);
    const snapshot = entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
    const barrier = this.stateReadBarrier;
    if (barrier && key === barrier.key && barrier.remaining > 0) {
      barrier.remaining -= 1;
      if (barrier.remaining === 0) barrier.release();
      await barrier.promise;
      if (barrier.remaining === 0) this.stateReadBarrier = null;
    }
    return snapshot;
  }

  async setJSON(key, data, options = {}) {
    if (this.failNextStateCas && key === RETENTION_GENERATION_FENCE_STATE_KEY &&
        options.onlyIfMatch) {
      this.failNextStateCas = false;
      return { modified: false };
    }
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    if (options.onlyIfMatch && !current) return { modified: false };
    const etag = `fence-etag-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }

  list({ prefix, paginate }) {
    assert.equal(paginate, true);
    const keys = [...this.values.keys()].filter((key) => key.startsWith(prefix)).sort();
    return (async function *pages() {
      for (let index = 0; index < keys.length; index += 2) {
        yield { blobs: keys.slice(index, index + 2).map((key) => ({ key })) };
      }
      if (keys.length === 0) yield { blobs: [] };
    })();
  }

  barrierNextStateReads(count) {
    let release;
    const promise = new Promise((resolve) => { release = resolve; });
    this.stateReadBarrier = {
      key: RETENTION_GENERATION_FENCE_STATE_KEY,
      remaining: count,
      promise,
      release,
    };
  }

  tamper(key, mutate) {
    const current = this.values.get(key);
    assert.ok(current, `Missing test record ${key}`);
    const value = structuredClone(current.data);
    mutate(value);
    this.values.set(key, { data: value, etag: `fence-etag-${++this.sequence}` });
  }
}

const sha = (value) => createHash('sha256').update(value).digest('hex');
const at = (offsetMs = 0) => new Date(Date.parse('2036-08-28T12:00:00.000Z') + offsetMs);
const env = {
  [RETENTION_GENERATION_FENCE_SECRET_ENV]:
    'arc-first-party-retention-fence-hmac-secret-unique-0123456789abcdef',
  ARC_FIRST_PARTY_RETENTION_HMAC_SECRET:
    'arc-first-party-retention-evidence-secret-distinct-0123456789abcdef',
  ARC_HANDOFF_STATE_SECRET: 'arc-handoff-state-secret-distinct-0123456789abcdef',
  // There is deliberately no enable flag. A caller cannot bypass the fence by
  // toggling a runtime feature flag.
  ARC_FIRST_PARTY_RETENTION_FENCE_ENABLED: 'false',
};

const producer = (label) => ({
  route: `review/${label}`,
  subject_hmac_sha256: sha(`subject:${label}`),
  idempotency_key_sha256: sha(`idempotency:${label}`),
  source_record_sha256: sha(`source:${label}`),
  mutation_sha256: sha(`mutation:${label}`),
  output_record_sha256: sha(`output:${label}`),
});
const freeze = (generation, label) => ({
  generation,
  subject_hmac_sha256: sha(`retention-subject:${label}`),
  manifest_sha256: sha(`fully-paginated-one-subject-manifest:${label}`),
  manifest_entry_count: 7,
});
const finalizeEvidence = (label) => ({
  legal_hold_recheck_sha256: sha(`legal-hold-recheck:${label}`),
  tombstone_set_sha256: sha(`tombstone-set:${label}`),
  primary_tombstone_sha256: sha(`primary-tombstone:${label}`),
  output_readback_sha256: sha(`retention-output-readback:${label}`),
});
const authorityFrom = (value, status) => Object.freeze({
  status,
  generation: value.generation,
  operation_hmac_sha256: value.operation_hmac_sha256,
  intent_sha256: value.intent_sha256,
  authority_etag: value.authority_etag,
});

assert.equal(RETENTION_GENERATION_FENCE_STORE, 'arc-retention-control');
assert.equal(retentionGenerationFenceContract.store, 'arc-retention-control');
assert.equal(retentionGenerationFenceContract.secret_env,
  'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET');
assert.equal(retentionGenerationFenceConfiguration(env).ready, true,
  'The dedicated secret alone activates the always-on fence; an enable flag is ignored.');
assert.equal(retentionGenerationFenceConfiguration({}).ready, false);
assert.equal(retentionGenerationFenceConfiguration({
  [RETENTION_GENERATION_FENCE_SECRET_ENV]: 'too-short',
}).ready, false);
assert.equal(retentionGenerationFenceConfiguration({
  ...env,
  ARC_HANDOFF_STATE_SECRET: env[RETENTION_GENERATION_FENCE_SECRET_ENV],
}).ready, false, 'The fence secret must be distinct from every other secret.');
assert.equal(retentionGenerationFenceConfiguration({
  ...env,
  ARC_RESEND_API_KEY: env[RETENTION_GENERATION_FENCE_SECRET_ENV],
}).ready, false, 'The fence secret must also be distinct from key-named credentials.');

// State initialization is signed OPEN(0), and tampering is rejected.
{
  const store = new FakeStore();
  const initialized = await ensureRetentionGenerationFence(store, env, { clock: () => at() });
  assert.equal(initialized.record.status, 'OPEN');
  assert.equal(initialized.record.generation, 0);
  assert.doesNotThrow(() => validateRetentionGenerationFenceState(initialized.record, env));
  store.tamper(RETENTION_GENERATION_FENCE_STATE_KEY, (value) => { value.generation = 9; });
  await assert.rejects(readRetentionGenerationFence(store, env), /SIGNATURE_INVALID/);
}

// Operation identity is deterministic over the complete immutable binding.
{
  const first = producer('deterministic');
  assert.equal(retentionProducerOperationHmac(first, env),
    retentionProducerOperationHmac(structuredClone(first), env));
  assert.notEqual(retentionProducerOperationHmac(first, env),
    retentionProducerOperationHmac({ ...first, mutation_sha256: sha('different-mutation') }, env));
  const manifest = freeze(4, 'deterministic');
  assert.equal(retentionFreezeOperationHmac(manifest, env),
    retentionFreezeOperationHmac(structuredClone(manifest), env));
  assert.notEqual(retentionFreezeOperationHmac(manifest, env),
    retentionFreezeOperationHmac({ ...manifest, manifest_sha256: sha('drifted-manifest') }, env));
}

// OPEN(N) -> WRITING(N), strong source read, mutation, strong output readback,
// immutable completion receipt, then OPEN(N+1). Exact replay never mutates twice.
{
  const store = new FakeStore();
  const descriptor = producer('happy');
  let output = sha('absent-output');
  let mutations = 0;
  const trace = [];
  const adapters = {
    clock: () => at(),
    staleAfterMs: 5_000,
    readSource: async () => { trace.push('source-read'); return descriptor.source_record_sha256; },
    readOutput: async () => { trace.push('output-read'); return output; },
    mutate: async () => { trace.push('mutation'); mutations += 1; output = descriptor.output_record_sha256; },
  };
  const completed = await runRetentionProducerOperation(store, descriptor, env, adapters);
  assert.equal(completed.state, 'COMPLETE');
  assert.equal(completed.generation, 0);
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'OPEN');
  assert.equal((await readRetentionGenerationFence(store, env)).record.generation, 1);
  assert.deepEqual(trace, ['source-read', 'output-read', 'mutation', 'output-read']);
  assert.equal(mutations, 1);
  const intent = store.values.get(retentionGenerationFenceKeys.producerIntent(
    completed.operation_hmac_sha256)).data;
  const receipt = store.values.get(retentionGenerationFenceKeys.producerCompletion(
    completed.operation_hmac_sha256)).data;
  assert.doesNotThrow(() => validateRetentionProducerIntent(intent, env));
  assert.doesNotThrow(() => validateRetentionProducerCompletionReceipt(receipt, intent, env));
  const replay = await runRetentionProducerOperation(store, descriptor, env,
    { ...adapters, clock: () => at(1_000) });
  assert.equal(replay.state, 'COMPLETE');
  assert.equal(replay.idempotent_replay, true);
  assert.equal(mutations, 1, 'Exact operation replay must validate output rather than mutate twice.');
}

// Two different producers racing for OPEN(N) have one WRITING winner. The
// loser receives retryable contention and normal contention creates no alert.
{
  const store = new FakeStore();
  await ensureRetentionGenerationFence(store, env, { clock: () => at() });
  store.barrierNextStateReads(2);
  const raced = await Promise.all([
    beginRetentionProducerOperation(store, producer('race-a'), env,
      { clock: () => at(10), staleAfterMs: 5_000 }),
    beginRetentionProducerOperation(store, producer('race-b'), env,
      { clock: () => at(10), staleAfterMs: 5_000 }),
  ]);
  assert.equal(raced.filter((value) => value.acquired).length, 1);
  assert.equal(raced.filter((value) => value.state === 'RETRYABLE_CONTENTION').length, 1);
  assert.equal([...store.values.keys()].some((key) => key.includes('/critical-alerts/')), false);
}

// A mutation crash never releases WRITING. The exact same operation resumes
// and completes idempotently under the original operation identity.
{
  const store = new FakeStore();
  const descriptor = producer('partial-failure');
  let output = sha('partial-output');
  let mutationAttempts = 0;
  const base = {
    clock: () => at(),
    staleAfterMs: 5_000,
    readSource: async () => descriptor.source_record_sha256,
    readOutput: async () => output,
  };
  await assert.rejects(runRetentionProducerOperation(store, descriptor, env, {
    ...base,
    mutate: async () => { mutationAttempts += 1; throw new Error('injected partial mutation failure'); },
  }), /injected partial mutation failure/);
  let state = (await readRetentionGenerationFence(store, env)).record;
  assert.equal(state.status, 'WRITING');
  assert.equal(state.generation, 0);
  assert.equal(store.values.has(retentionGenerationFenceKeys.producerCompletion(
    retentionProducerOperationHmac(descriptor, env))), false);
  const activeRetry = await beginRetentionProducerOperation(store, descriptor, env,
    { clock: () => at(100), staleAfterMs: 5_000 });
  assert.equal(activeRetry.state, 'RETRYABLE_CONTENTION');
  assert.equal(activeRetry.retryable, true);
  const completed = await runRetentionProducerOperation(store, descriptor, env, {
    ...base,
    clock: () => at(5_000),
    mutate: async () => { mutationAttempts += 1; output = descriptor.output_record_sha256; },
  });
  assert.equal(completed.state, 'COMPLETE');
  assert.equal(mutationAttempts, 2);
  assert.equal([...store.values.keys()].filter((key) =>
    key.includes('/critical-alerts/')).length, 1);
  state = (await readRetentionGenerationFence(store, env)).record;
  assert.equal(state.status, 'OPEN');
  assert.equal(state.generation, 1);
}

// Completion cannot reopen the fence until the output strongly reads back.
{
  const store = new FakeStore();
  const descriptor = producer('readback-failure');
  const begun = await beginRetentionProducerOperation(store, descriptor, env,
    { clock: () => at(), staleAfterMs: 5_000 });
  await assert.rejects(completeRetentionProducerOperation(store, descriptor, env, {
    clock: () => at(100),
    authorityEtag: begun.authority_etag,
    readback: async () => sha('wrong-output'),
  }), /OUTPUT_READBACK_INVALID/);
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'WRITING');
  assert.equal(store.values.has(retentionGenerationFenceKeys.producerCompletion(
    retentionProducerOperationHmac(descriptor, env))), false);
  const completed = await completeRetentionProducerOperation(store, descriptor, env, {
    clock: () => at(200),
    authorityEtag: begun.authority_etag,
    readback: async () => descriptor.output_record_sha256,
  });
  assert.equal(completed.state, 'COMPLETE');
}

// A genuinely stale exact producer retry must CAS-refresh the signed lease.
// Two concurrent resumptions can never both receive mutation authority.
{
  const store = new FakeStore();
  const descriptor = producer('stale-resume-race');
  await beginRetentionProducerOperation(store, descriptor, env,
    { clock: () => at(), staleAfterMs: 1_000 });
  store.barrierNextStateReads(2);
  const raced = await Promise.all([
    beginRetentionProducerOperation(store, descriptor, env,
      { clock: () => at(1_000), staleAfterMs: 1_000 }),
    beginRetentionProducerOperation(store, descriptor, env,
      { clock: () => at(1_000), staleAfterMs: 1_000 }),
  ]);
  assert.equal(raced.filter((value) => value.acquired).length, 1);
  assert.equal(raced.filter((value) => value.state === 'RETRYABLE_CONTENTION').length, 1);
  const refreshed = (await readRetentionGenerationFence(store, env)).record;
  assert.equal(refreshed.status, 'WRITING');
  assert.equal(refreshed.entered_at, at(1_000).toISOString());
  assert.equal(refreshed.stale_at, at(2_000).toISOString());
  assert.equal([...store.values.keys()].filter((key) =>
    key.includes('/critical-alerts/')).length, 1);
}

// Refreshing or explicitly renewing a lease changes its CAS authority. A slow
// worker holding the old ETag can neither mutate further nor publish a receipt.
{
  const store = new FakeStore();
  const descriptor = producer('stale-authority-revoked');
  const original = await beginRetentionProducerOperation(store, descriptor, env,
    { clock: () => at(), staleAfterMs: 1_000 });
  const originalAuthority = authorityFrom(original, 'WRITING');
  const resumed = await beginRetentionProducerOperation(store, descriptor, env,
    { clock: () => at(1_000), staleAfterMs: 1_000 });
  assert.equal(resumed.acquired, true);
  await assert.rejects(assertRetentionGenerationFenceAuthority(store, originalAuthority, env),
    /FENCE_AUTHORITY_LOST/);
  await assert.rejects(completeRetentionProducerOperation(store, descriptor, env, {
    clock: () => at(1_001),
    authorityEtag: original.authority_etag,
    readback: async () => descriptor.output_record_sha256,
  }), /FENCE_AUTHORITY_LOST/);
  assert.doesNotReject(assertRetentionGenerationFenceAuthority(
    store, authorityFrom(resumed, 'WRITING'), env));
}

// A live worker can heartbeat before a long deterministic mutation. Renewal
// itself is CAS-bound and immediately revokes the prior authority token.
{
  const store = new FakeStore();
  const descriptor = producer('authority-renewal');
  const begun = await beginRetentionProducerOperation(store, descriptor, env,
    { clock: () => at(), staleAfterMs: 1_000 });
  const originalAuthority = authorityFrom(begun, 'WRITING');
  const renewed = await renewRetentionGenerationFenceAuthority(store, originalAuthority, env,
    { clock: () => at(900), staleAfterMs: 1_000 });
  assert.notEqual(renewed.authority_etag, originalAuthority.authority_etag);
  await assert.rejects(assertRetentionGenerationFenceAuthority(store, originalAuthority, env),
    /FENCE_AUTHORITY_LOST/);
  assert.doesNotReject(assertRetentionGenerationFenceAuthority(store, renewed, env));
  const prematureResume = await beginRetentionProducerOperation(store, descriptor, env,
    { clock: () => at(1_000), staleAfterMs: 1_000 });
  assert.equal(prematureResume.state, 'RETRYABLE_CONTENTION');
}

// runRetentionProducerOperation automatically renews WRITING while a slow
// mutation is in flight, then completes only under the latest exact ETag.
{
  const store = new FakeStore();
  const descriptor = producer('automatic-authority-heartbeat');
  let output = sha('automatic-heartbeat-output-absent');
  let clockTick = 0;
  let initialState;
  let latestState;
  let priorAuthorityRevoked = false;
  const completed = await runRetentionProducerOperation(store, descriptor, env, {
    clock: () => at(clockTick++ * 400),
    staleAfterMs: 1_000,
    heartbeatIntervalMs: 10,
    readSource: async () => descriptor.source_record_sha256,
    readOutput: async () => output,
    mutate: async () => {
      initialState = await readRetentionGenerationFence(store, env);
      await new Promise((resolve) => setTimeout(resolve, 45));
      latestState = await readRetentionGenerationFence(store, env);
      await assert.rejects(assertRetentionGenerationFenceAuthority(store, {
        status: initialState.record.status,
        generation: initialState.record.generation,
        operation_hmac_sha256: initialState.record.operation_hmac_sha256,
        intent_sha256: initialState.record.intent_sha256,
        authority_etag: initialState.etag,
      }, env), /FENCE_AUTHORITY_LOST/);
      priorAuthorityRevoked = true;
      output = descriptor.output_record_sha256;
    },
  });
  assert.equal(completed.state, 'COMPLETE');
  assert.ok(Date.parse(latestState.record.stale_at) > Date.parse(initialState.record.stale_at),
    'Periodic producer authority renewal must advance stale_at during a live mutation.');
  assert.equal(priorAuthorityRevoked, true,
    'The pre-heartbeat ETag must lose authority while WRITING remains active.');
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'OPEN');
}

// A failed heartbeat can never be ignored after the domain mutation returns.
// No completion receipt is published and WRITING remains closed for recovery.
{
  const store = new FakeStore();
  const descriptor = producer('automatic-heartbeat-failure');
  let output = sha('automatic-heartbeat-failure-output-absent');
  await assert.rejects(runRetentionProducerOperation(store, descriptor, env, {
    clock: () => at(),
    staleAfterMs: 1_000,
    heartbeatIntervalMs: 10,
    readSource: async () => descriptor.source_record_sha256,
    readOutput: async () => output,
    mutate: async () => {
      store.failNextStateCas = true;
      await new Promise((resolve) => setTimeout(resolve, 25));
      output = descriptor.output_record_sha256;
    },
  }), /FENCE_AUTHORITY_LOST/);
  const state = await readRetentionGenerationFence(store, env);
  assert.equal(state.record.status, 'WRITING');
  assert.equal(store.values.has(retentionGenerationFenceKeys.producerCompletion(
    retentionProducerOperationHmac(descriptor, env))), false);
}

// Crash after immutable producer completion/readback but before reopen is
// recoverable. Fresh work never alerts; genuinely stale completed work reopens.
{
  const store = new FakeStore();
  const descriptor = producer('producer-recovery');
  const alerts = [];
  const begun = await beginRetentionProducerOperation(store, descriptor, env,
    { clock: () => at(), staleAfterMs: 1_000 });
  await assert.rejects(completeRetentionProducerOperation(store, descriptor, env, {
    clock: () => at(100),
    authorityEtag: begun.authority_etag,
    readback: async () => descriptor.output_record_sha256,
    afterCompletionReceipt: async () => { throw new Error('crash after producer receipt'); },
  }), /crash after producer receipt/);
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'WRITING');
  const fresh = await recoverStaleRetentionGenerationFence(store, env, {
    clock: () => at(500), emitCriticalAlert: async (alert) => alerts.push(alert),
  });
  assert.equal(fresh.state, 'IN_PROGRESS');
  assert.equal(fresh.critical_alert, false);
  assert.equal(alerts.length, 0);
  const recovered = await recoverStaleRetentionGenerationFence(store, env, {
    clock: () => at(1_000),
    validateCompletion: async () => true,
    emitCriticalAlert: async (alert) => alerts.push(alert),
  });
  assert.equal(recovered.state, 'RECOVERED');
  assert.equal(recovered.critical_alert, false);
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'OPEN');
  assert.equal((await readRetentionGenerationFence(store, env)).record.generation, 1);
  assert.equal(alerts.length, 0);
}

// A genuinely stale WRITING state without a receipt is fail-closed and emits
// exactly one signed critical condition. It is never silently reopened.
{
  const store = new FakeStore();
  const descriptor = producer('stale-writing');
  const delivered = [];
  await beginRetentionProducerOperation(store, descriptor, env,
    { clock: () => at(), staleAfterMs: 1_000 });
  const fresh = await recoverStaleRetentionGenerationFence(store, env, {
    clock: () => at(999), emitCriticalAlert: async (alert) => delivered.push(alert),
  });
  assert.equal(fresh.state, 'IN_PROGRESS');
  const stale = await recoverStaleRetentionGenerationFence(store, env, {
    clock: () => at(1_000), emitCriticalAlert: async (alert) => delivered.push(alert),
  });
  assert.equal(stale.state, 'STALE_BLOCKED');
  assert.equal(stale.reason_code, 'FENCE_COMPLETION_RECEIPT_MISSING');
  assert.equal(stale.alert.schema, RETENTION_GENERATION_FENCE_ALERT_SCHEMA);
  assert.doesNotThrow(() => validateRetentionGenerationFenceAlert(stale.alert, env));
  assert.equal(delivered.length, 1);
  const replay = await recoverStaleRetentionGenerationFence(store, env, {
    clock: () => at(2_000), emitCriticalAlert: async (alert) => delivered.push(alert),
  });
  assert.equal(replay.alert_created, false);
  assert.equal(delivered.length, 2,
    'Existing immutable evidence must retry idempotent queue delivery after a transient failure.');
  assert.deepEqual(delivered[1], delivered[0]);
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'WRITING');
}

// A manifest is built against OPEN(N). Any producer drift to N+1 makes the old
// freeze request retryable; it can never freeze the stale manifest.
{
  const store = new FakeStore();
  await ensureRetentionGenerationFence(store, env, { clock: () => at() });
  const staleManifest = freeze(0, 'drift');
  const writer = producer('manifest-drift-writer');
  const begun = await beginRetentionProducerOperation(store, writer, env,
    { clock: () => at(10), staleAfterMs: 5_000 });
  await completeRetentionProducerOperation(store, writer, env, {
    clock: () => at(20), authorityEtag: begun.authority_etag,
    readback: async () => writer.output_record_sha256,
  });
  const drifted = await beginRetentionFreeze(store, staleManifest, env,
    { clock: () => at(30), staleAfterMs: 5_000 });
  assert.equal(drifted.state, 'RETRYABLE_DRIFT');
  assert.equal(drifted.observed_generation, 1);
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'OPEN');
  assert.equal([...store.values.keys()].some((key) => key.includes('/critical-alerts/')), false);
}

// FROZEN(N) excludes producers, binds the exact signed manifest, and only a
// strong finalize readback plus immutable finalize receipt opens N+1.
{
  const store = new FakeStore();
  await ensureRetentionGenerationFence(store, env, { clock: () => at() });
  const descriptor = freeze(0, 'happy-freeze');
  const frozen = await beginRetentionFreeze(store, descriptor, env,
    { clock: () => at(10), staleAfterMs: 5_000 });
  assert.equal(frozen.state, 'FROZEN');
  const intent = store.values.get(retentionGenerationFenceKeys.freezeIntent(
    frozen.operation_hmac_sha256)).data;
  assert.doesNotThrow(() => validateRetentionFreezeIntent(intent, env));
  const blockedWriter = await beginRetentionProducerOperation(store, producer('blocked-by-freeze'), env,
    { clock: () => at(20), staleAfterMs: 5_000 });
  assert.equal(blockedWriter.state, 'RETRYABLE_CONTENTION');
  const wrongManifest = await beginRetentionFreeze(store,
    { ...descriptor, manifest_sha256: sha('wrong-manifest') }, env,
    { clock: () => at(20), staleAfterMs: 5_000 });
  assert.equal(wrongManifest.state, 'RETRYABLE_CONTENTION');
  const evidence = finalizeEvidence('happy-freeze');
  await assert.rejects(completeRetentionFreeze(store, descriptor, evidence, env, {
    clock: () => at(30), authorityEtag: frozen.authority_etag,
    readback: async () => sha('wrong-retention-readback'),
  }), /FINALIZE_READBACK_INVALID/);
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'FROZEN');
  const complete = await completeRetentionFreeze(store, descriptor, evidence, env, {
    clock: () => at(40), authorityEtag: frozen.authority_etag,
    readback: async () => evidence.output_readback_sha256,
  });
  assert.equal(complete.state, 'COMPLETE');
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'OPEN');
  assert.equal((await readRetentionGenerationFence(store, env)).record.generation, 1);
  const receipt = store.values.get(retentionGenerationFenceKeys.finalizeReceipt(
    frozen.operation_hmac_sha256)).data;
  assert.doesNotThrow(() => validateRetentionFinalizeReceipt(receipt, intent, env));
  assert.equal([...store.values.keys()].some((key) => key.includes('/critical-alerts/')), false);
}

// A long finalize readback may heartbeat the FROZEN lease. Completion must
// adopt and verify the latest authority ETag before writing its receipt/open.
{
  const store = new FakeStore();
  const descriptor = freeze(0, 'heartbeat-readback');
  const frozen = await beginRetentionFreeze(store, descriptor, env,
    { clock: () => at(), staleAfterMs: 1_000 });
  const evidence = finalizeEvidence('heartbeat-readback');
  const complete = await completeRetentionFreeze(store, descriptor, evidence, env, {
    clock: () => at(900), authorityEtag: frozen.authority_etag,
    readback: async ({ authority: initial }) => {
      const first = await renewRetentionGenerationFenceAuthority(store, initial, env,
        { clock: () => at(300), staleAfterMs: 1_000 });
      const latest = await renewRetentionGenerationFenceAuthority(store, first, env,
        { clock: () => at(600), staleAfterMs: 1_000 });
      return { output_readback_sha256: evidence.output_readback_sha256,
        authority_etag: latest.authority_etag };
    },
  });
  assert.equal(complete.state, 'COMPLETE');
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'OPEN');
  const replay = await completeRetentionFreeze(store, descriptor, evidence, env, {
    clock: () => at(1_200),
    readback: async () => ({
      output_readback_sha256: evidence.output_readback_sha256,
      authority_etag: 'receipt-replay-no-live-authority',
    }),
  });
  assert.equal(replay.state, 'COMPLETE');
  assert.equal(replay.idempotent_replay, true);
}

// Stale FROZEN retry uses the same CAS-refresh rule: only one exact retry can
// resume tombstoning under the original signed intent.
{
  const store = new FakeStore();
  const descriptor = freeze(0, 'stale-freeze-race');
  await beginRetentionFreeze(store, descriptor, env,
    { clock: () => at(), staleAfterMs: 1_000 });
  store.barrierNextStateReads(2);
  const raced = await Promise.all([
    beginRetentionFreeze(store, descriptor, env,
      { clock: () => at(1_000), staleAfterMs: 1_000 }),
    beginRetentionFreeze(store, descriptor, env,
      { clock: () => at(1_000), staleAfterMs: 1_000 }),
  ]);
  assert.equal(raced.filter((value) => value.acquired).length, 1);
  assert.equal(raced.filter((value) => value.state === 'RETRYABLE_CONTENTION').length, 1);
  const refreshed = (await readRetentionGenerationFence(store, env)).record;
  assert.equal(refreshed.status, 'FROZEN');
  assert.equal(refreshed.entered_at, at(1_000).toISOString());
  assert.equal(refreshed.stale_at, at(2_000).toISOString());
}

// A marked source that disappears under FROZEN creates signed immutable
// anomaly evidence and permanently blocks finalize/reopen for that manifest.
{
  const store = new FakeStore();
  const descriptor = freeze(0, 'missing-source');
  const frozen = await beginRetentionFreeze(store, descriptor, env,
    { clock: () => at(), staleAfterMs: 1_000 });
  const anomaly = await recordRetentionMissingSourceAnomaly(store, descriptor, {
    family: 'review',
    source_key_hmac_sha256: sha('missing-source-key'),
    expected_source_record_sha256: sha('missing-source-record'),
  }, env, { clock: () => at(100), authorityEtag: frozen.authority_etag });
  assert.equal(anomaly.anomaly.schema, RETENTION_MISSING_SOURCE_ANOMALY_SCHEMA);
  const intent = store.values.get(retentionGenerationFenceKeys.freezeIntent(
    frozen.operation_hmac_sha256)).data;
  assert.doesNotThrow(() => validateRetentionMissingSourceAnomaly(anomaly.anomaly, intent, env));
  const queued = [];
  const authority = {
    status: 'FROZEN', generation: frozen.generation,
    operation_hmac_sha256: frozen.operation_hmac_sha256,
    intent_sha256: frozen.intent_sha256, authority_etag: frozen.authority_etag,
  };
  const raised = await raiseRetentionGenerationFenceCriticalAlert(
    store, authority, 'RETENTION_MISSING_SOURCE_BLOCKED', env,
    { emitCriticalAlert: async (alert) => queued.push(alert) },
  );
  const reraised = await raiseRetentionGenerationFenceCriticalAlert(
    store, authority, 'RETENTION_MISSING_SOURCE_BLOCKED', env,
    { emitCriticalAlert: async (alert) => queued.push(alert) },
  );
  assert.equal(raised.idempotent_replay, false);
  assert.equal(reraised.idempotent_replay, true);
  assert.equal(queued.length, 2, 'A deduplicated signed critical alert must be queued on every exact retry.');
  assert.deepEqual(queued[0], queued[1]);
  assert.doesNotThrow(() => validateRetentionGenerationFenceAlert(queued[0], env));
  assert.equal([...store.values.keys()].filter((key) => key.includes('/critical-alerts/')).length, 1);
  const evidence = finalizeEvidence('missing-source');
  await assert.rejects(completeRetentionFreeze(store, descriptor, evidence, env, {
    clock: () => at(200), authorityEtag: frozen.authority_etag,
    readback: async () => evidence.output_readback_sha256,
  }), /MISSING_SOURCE_BLOCKED/);
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'FROZEN');
  assert.equal(store.values.has(retentionGenerationFenceKeys.finalizeReceipt(
    frozen.operation_hmac_sha256)), false);
}

// Crash after a signed finalize receipt but before OPEN is recovered only once
// genuinely stale. A valid receipt never creates a permanent alert.
{
  const store = new FakeStore();
  const descriptor = freeze(0, 'freeze-recovery');
  const evidence = finalizeEvidence('freeze-recovery');
  const alerts = [];
  const begun = await beginRetentionFreeze(store, descriptor, env,
    { clock: () => at(), staleAfterMs: 1_000 });
  await assert.rejects(completeRetentionFreeze(store, descriptor, evidence, env, {
    clock: () => at(100),
    authorityEtag: begun.authority_etag,
    readback: async () => evidence.output_readback_sha256,
    afterCompletionReceipt: async () => { throw new Error('crash after finalize receipt'); },
  }), /crash after finalize receipt/);
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'FROZEN');
  const fresh = await recoverStaleRetentionGenerationFence(store, env, {
    clock: () => at(900), emitCriticalAlert: async (alert) => alerts.push(alert),
  });
  assert.equal(fresh.state, 'IN_PROGRESS');
  const recovered = await recoverStaleRetentionGenerationFence(store, env, {
    clock: () => at(1_000),
    validateCompletion: async () => true,
    emitCriticalAlert: async (alert) => alerts.push(alert),
  });
  assert.equal(recovered.state, 'RECOVERED');
  assert.equal(alerts.length, 0);
  assert.equal((await readRetentionGenerationFence(store, env)).record.status, 'OPEN');
  assert.equal((await readRetentionGenerationFence(store, env)).record.generation, 1);
}

// A stale lock with tampered intent or completion evidence never reopens and
// produces a signed critical integrity alert.
{
  const intentStore = new FakeStore();
  const descriptor = producer('tampered-intent');
  const begun = await beginRetentionProducerOperation(intentStore, descriptor, env,
    { clock: () => at(), staleAfterMs: 1_000 });
  intentStore.tamper(retentionGenerationFenceKeys.producerIntent(
    begun.operation_hmac_sha256), (value) => { value.route = 'review/tampered'; });
  const intentRecovery = await recoverStaleRetentionGenerationFence(intentStore, env,
    { clock: () => at(1_000) });
  assert.equal(intentRecovery.state, 'STALE_BLOCKED');
  assert.equal(intentRecovery.reason_code, 'FENCE_INTENT_INVALID');
  assert.equal((await readRetentionGenerationFence(intentStore, env)).record.status, 'WRITING');

  const receiptStore = new FakeStore();
  const receiptDescriptor = producer('tampered-receipt');
  const receiptBegin = await beginRetentionProducerOperation(receiptStore, receiptDescriptor, env,
    { clock: () => at(), staleAfterMs: 1_000 });
  await assert.rejects(completeRetentionProducerOperation(receiptStore, receiptDescriptor, env, {
    clock: () => at(100),
    authorityEtag: receiptBegin.authority_etag,
    readback: async () => receiptDescriptor.output_record_sha256,
    afterCompletionReceipt: async () => { throw new Error('receipt crash'); },
  }), /receipt crash/);
  receiptStore.tamper(retentionGenerationFenceKeys.producerCompletion(
    receiptBegin.operation_hmac_sha256), (value) => { value.output_record_sha256 = sha('forged-output'); });
  const receiptRecovery = await recoverStaleRetentionGenerationFence(receiptStore, env,
    { clock: () => at(1_000) });
  assert.equal(receiptRecovery.state, 'STALE_BLOCKED');
  assert.equal(receiptRecovery.reason_code, 'FENCE_COMPLETION_RECEIPT_INVALID');
  assert.equal((await readRetentionGenerationFence(receiptStore, env)).record.status, 'WRITING');
}

console.log('ARC signed global retention generation fence adversarial contract passed.');
