import assert from 'node:assert/strict';

import {
  config as runnerConfig,
  createIntakeArc1AdapterRecoveryRunnerHandler,
} from '../netlify/functions/intake-arc1-adapter-recovery-runner.mjs';
import {
  INTAKE_ARC1_RECOVERY_RUNNER_KEY,
  runArc1AdapterRecoveryCycle,
  validateArc1RecoveryRunnerState,
} from '../netlify/lib/intake-arc1-adapter-recovery-runner-core.mjs';
import { testActivationAuthority } from './helpers/activation-authority.mjs';

const runnerHandler = createIntakeArc1AdapterRecoveryRunnerHandler();

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
    if (options.onlyIfMatch && !current) return { modified: false };
    const etag = `etag-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
}

const now = new Date();
const env = {
  ...testActivationAuthority(now),
  ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED: 'true',
  ARC_INTAKE_ARC1_ADAPTER_ENABLED: 'true',
  ARC_INTAKE_ARC1_BRIDGE_ENABLED: 'true',
  ARC_INTAKE_ARC1_DISPATCH_ENABLED: 'true',
  ARC_INTAKE_ARC1_DOWNSTREAM_ENABLED: 'true',
  ARC_INTAKE_ASSET_RETRIEVAL_ENABLED: 'true',
  ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED: 'true',
  ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED: 'true',
  ARC_INTAKE_ARC1_ENDPOINT: 'https://arcweb.onl/internal/intake/arc1/adapter',
  ARC_INTAKE_ARC1_DOWNSTREAM_ENDPOINT: 'https://hooks.zapier.com/hooks/catch/123456/abcde_12345/',
  ARC_INTAKE_ARC1_RUN_SECRET: 'runner-run-secret-unique-0123456789-abcdefgh',
  ARC_INTAKE_ARC1_DISPATCH_SECRET: 'runner-dispatch-secret-unique-0123456789-ab',
  ARC_INTAKE_ARC1_DESTINATION_BEARER: 'runner-destination-bearer-unique-0123456789',
  ARC_INTAKE_ARC1_EVIDENCE_SECRET: 'runner-evidence-secret-unique-0123456789-ab',
  ARC_INTAKE_ARC1_ACK_SECRET: 'runner-ack-secret-unique-0123456789-abcdef',
  ARC_INTAKE_ARC1_STATE_SECRET: 'runner-state-secret-unique-0123456789-abcd',
  ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET: 'runner-proof-secret-unique-0123456789-abcd',
  ARC_INTAKE_ASSET_RETRIEVAL_SECRET: 'runner-asset-secret-unique-0123456789-abcde',
  ARC1_ASSET_RECEIPT_SECRET: 'runner-receipt-secret-unique-0123456789-abc',
  ARC_INTAKE_ARC1_DOWNSTREAM_BEARER: 'runner-downstream-bearer-unique-0123456789',
  ARC_INTAKE_ARC1_PACKET_SECRET: 'runner-packet-secret-unique-0123456789-abc',
  ARC_INTAKE_ARC1_CONSUMER_BEARER: 'runner-consumer-bearer-unique-0123456789',
  ARC_INTAKE_ARC1_CONSUMER_RECEIPT_SECRET: 'runner-consumer-receipt-secret-unique-012345',
  SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  SITE_NAME: 'arcsites',
  URL: 'https://arcweb.onl',
};

const adapter = new FakeStore();
const source = new FakeStore();
const seenCursors = [];
let recoveryCalls = 0;
const recover = async (_request, _env, stores, options) => {
  assert.equal(stores.adapter, adapter);
  assert.equal(stores.source, source);
  seenCursors.push(options.cursor);
  recoveryCalls += 1;
  return recoveryCalls === 1 ? {
    state: 'RECOVERY_PARTIAL', scanned: 100, attempted: 2, reviewed: 0, migration_required: 0, invalid: 0,
    next_cursor: 'signed-cursor-one',
  } : {
    state: 'RECOVERY_COMPLETE', scanned: 4, attempted: 1, reviewed: 1, migration_required: 0, invalid: 0,
    next_cursor: null,
  };
};

const first = await runArc1AdapterRecoveryCycle(env, { source, adapter }, {
  clock: () => now, uuid: () => '11111111-1111-4111-8111-111111111111', recover,
});
assert.deepEqual(first, { state: 'RECOVERY_PARTIAL', cursor: 'signed-cursor-one', idempotentReplay: false });
let state = validateArc1RecoveryRunnerState(adapter.values.get(INTAKE_ARC1_RECOVERY_RUNNER_KEY).data);
assert.equal(state.status, 'IDLE');
assert.equal(state.cursor, 'signed-cursor-one');
assert.equal(state.run_count, 1);
assert.equal(state.last_result.scanned, 100);

const second = await runArc1AdapterRecoveryCycle(env, { source, adapter }, {
  clock: () => new Date(now.getTime() + 10_000), uuid: () => '22222222-2222-4222-8222-222222222222', recover,
});
assert.deepEqual(second, { state: 'RECOVERY_COMPLETE', cursor: null, idempotentReplay: false });
assert.deepEqual(seenCursors, [null, 'signed-cursor-one'], 'Every bounded cycle resumes from the durable signed cursor.');
state = validateArc1RecoveryRunnerState(adapter.values.get(INTAKE_ARC1_RECOVERY_RUNNER_KEY).data);
assert.equal(state.run_count, 2);
assert.equal(state.cursor, null);

let releaseRecovery;
let recoveryEntered;
const entered = new Promise((resolve) => { recoveryEntered = resolve; });
const gate = new Promise((resolve) => { releaseRecovery = resolve; });
const running = runArc1AdapterRecoveryCycle(env, { source, adapter }, {
  clock: () => new Date(now.getTime() + 20_000),
  uuid: () => '33333333-3333-4333-8333-333333333333',
  recover: async () => { recoveryEntered(); return gate; },
});
await entered;
const concurrent = await runArc1AdapterRecoveryCycle(env, { source, adapter }, {
  clock: () => new Date(now.getTime() + 21_000),
  uuid: () => '44444444-4444-4444-8444-444444444444',
  recover: async () => { throw new Error('Concurrent runner must not recover.'); },
});
assert.equal(concurrent.state, 'RECOVERY_IN_PROGRESS');
assert.equal(concurrent.idempotentReplay, true);
releaseRecovery({
  state: 'RECOVERY_COMPLETE', scanned: 0, attempted: 0, reviewed: 0, migration_required: 0, invalid: 0,
  next_cursor: null,
});
await running;

const crashAdapter = new FakeStore();
await assert.rejects(runArc1AdapterRecoveryCycle(env, { source, adapter: crashAdapter }, {
  clock: () => now,
  uuid: () => '55555555-5555-4555-8555-555555555555',
  recover: async () => { throw new Error('synthetic runner crash'); },
}), /synthetic runner crash/);
assert.equal(validateArc1RecoveryRunnerState(crashAdapter.values.get(INTAKE_ARC1_RECOVERY_RUNNER_KEY).data).status, 'RUNNING');
assert.equal((await runArc1AdapterRecoveryCycle(env, { source, adapter: crashAdapter }, {
  clock: () => new Date(now.getTime() + 1_000),
  uuid: () => '66666666-6666-4666-8666-666666666666',
  recover: async () => { throw new Error('Live crash lease must block.'); },
})).state, 'RECOVERY_IN_PROGRESS');
const resumed = await runArc1AdapterRecoveryCycle(env, { source, adapter: crashAdapter }, {
  clock: () => new Date(now.getTime() + 2 * 60_000 + 1),
  uuid: () => '77777777-7777-4777-8777-777777777777',
  recover: async (_request, _env, _stores, options) => {
    assert.equal(options.cursor, null, 'A crash resumes from the last committed cursor, never an uncommitted skip.');
    return { state: 'RECOVERY_COMPLETE', scanned: 0, attempted: 0, reviewed: 0, migration_required: 0, invalid: 0, next_cursor: null };
  },
});
assert.equal(resumed.state, 'RECOVERY_COMPLETE');

let runnerSideEffects = 0;
const savedEnvironment = { ...process.env };
try {
  Object.assign(process.env, env);
  process.env.ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED = 'false';
  const disabled = await runnerHandler(new Request('https://arcweb.onl/.netlify/functions/intake-arc1-adapter-recovery-runner'),
    new Proxy({}, { get() { runnerSideEffects += 1; throw new Error('Disabled runner touched dependency.'); } }));
  assert.equal(disabled.status, 204);
  assert.equal(runnerSideEffects, 0);
} finally {
  for (const key of Object.keys(process.env)) if (!(key in savedEnvironment)) delete process.env[key];
  Object.assign(process.env, savedEnvironment);
}

assert.equal(runnerConfig.schedule, '*/5 * * * *');
assert.equal(Object.hasOwn(runnerConfig, 'path'), false);
console.log('ARC automatic durable-cursor intake recovery runner contract passed.');
