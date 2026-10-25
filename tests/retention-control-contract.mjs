import assert from 'node:assert/strict';
import {
  canonicalJson,
  hmacHex,
  sha256Hex,
} from '../netlify/lib/arc2-handoff-core.mjs';
import {
  RETENTION_ADULT_APPROVAL_PREFIX,
  RETENTION_MANIFEST_PREFIX,
  RETENTION_MANIFEST_SCHEMA,
  RETENTION_MANIFEST_SCOPE,
  RETENTION_POLICY_VERSION,
  retentionConfiguration,
  retentionKeys,
  runRetentionManifest,
} from '../netlify/lib/retention-control-core.mjs';
import {
  RETENTION_GENERATION_FENCE_STATE_KEY,
  retentionGenerationFenceKeys,
  validateRetentionGenerationFenceState,
  validateRetentionFinalizeReceipt,
  validateRetentionMissingSourceAnomaly,
  validateRetentionFreezeIntent,
} from '../netlify/lib/retention-generation-fence-core.mjs';
import retentionHandler, { config as retentionConfig } from '../netlify/functions/retention-cleanup.mjs';

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; this.mutateBeforeCas = null; }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    let current = this.values.get(key);
    if (options.onlyIfMatch && this.mutateBeforeCas?.key === key && current) {
      const mutated = structuredClone(current.data);
      this.mutateBeforeCas.mutate(mutated);
      const etag = `e-${++this.sequence}`;
      this.values.set(key, { data: mutated, etag });
      this.mutateBeforeCas = null;
      current = this.values.get(key);
    }
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `e-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
  async delete(key) {
    this.values.delete(key);
  }
  list({ prefix, paginate }) {
    assert.equal(paginate, true);
    const keys = [...this.values.keys()].filter((key) => key.startsWith(prefix)).sort();
    return {
      async *[Symbol.asyncIterator]() {
        yield { blobs: keys.map((key) => ({ key })), directories: [] };
      },
    };
  }
}

const now = new Date('2026-08-13T12:00:00.000Z');
const env = {
  ARC_RETENTION_CLEANUP_ENABLED: 'true',
  ARC_RETENTION_EXECUTION_MODE: 'dry-run',
  ARC_RETENTION_CLEANUP_SECRET: 'retention-endpoint-secret-unique-0123456789abcdef',
  ARC_RETENTION_MANIFEST_SECRET: 'retention-manifest-secret-unique-0123456789abcdef',
  ARC_RETENTION_RECORD_HMAC_SECRET: 'retention-record-hmac-secret-unique-0123456789abcdef',
  ARC_RETENTION_ADULT_APPROVAL_SECRET: 'retention-adult-approval-secret-unique-0123456789abcdef',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET: 'legacy-retention-global-fence-secret-0123456789abcdef',
};
assert.equal(retentionConfiguration(env).enabled, true);
assert.equal(retentionConfiguration({}).enabled, false);
assert.equal(retentionConfiguration({ ...env,
  ARC_HANDOFF_TRIGGER_SECRET: env.ARC_RETENTION_CLEANUP_SECRET,
}).enabled, false, 'Retention credentials must not reuse an existing handoff authorization secret.');
for (const credentialName of [
  'ARC_RETENTION_CLEANUP_SECRET',
  'ARC_RETENTION_MANIFEST_SECRET',
  'ARC_RETENTION_RECORD_HMAC_SECRET',
  'ARC_RETENTION_ADULT_APPROVAL_SECRET',
]) {
  assert.equal(retentionConfiguration({
    ...env,
    ARC_ROTATED_CREDENTIAL_V2: env[credentialName],
  }).enabled, false, `An arbitrary alias must not reuse ${credentialName}.`);
}

function intakeRecord(id, receivedAt = '2024-07-01T00:00:00.000Z') {
  return {
    schema: 'arc-intake-function-submission-v1',
    submission_id: id,
    received_at: receivedAt,
    source: 'first-party-netlify-function',
    form_name: 'arc-preview-function-v1',
    submission_data_sha256: 'a'.repeat(64),
    data: {},
    asset_manifest: [],
    assets: [],
    arc1_consumer_compatible: false,
    arc1_delivery: {
      schema: 'arc-intake-arc1-delivery-state-v1', status: 'PENDING', attempt_count: 0, next_attempt_at: receivedAt,
      lease_hmac_sha256: null, lease_expires_at: null, last_attempt_at: null, evidence_sha256: null,
      evidence_issued_at: null, evidence_expires_at: null, acknowledgement_sha256: null,
      consumer_claim_key_hmac_sha256: null, acknowledged_at: null, dead_lettered_at: null,
      alert_status: 'NONE', alert_code: null, alert_updated_at: null,
    },
    arc1_dispatch: {
      schema: 'arc-intake-arc1-dispatch-state-v1', status: 'PENDING', attempt_count: 0, last_attempt_at: null,
      accepted_at: null, alert_status: 'NONE', alert_code: null, alert_updated_at: null,
    },
  };
}

function manifestFor(runId, id, record, mode = 'dry-run', overrides = {}) {
  return {
    adult_approval_hmac_sha256: null,
    dry_run_id: null,
    dry_run_manifest_sha256: null,
    version: RETENTION_MANIFEST_SCHEMA,
    scope: RETENTION_MANIFEST_SCOPE,
    issued_at: now.toISOString(),
    mode,
    policy_version: RETENTION_POLICY_VERSION,
    run_id: runId,
    targets: [{
      key: `submissions/${id}`,
      last_interaction_at: '2024-07-01T00:00:00.000Z',
      record_sha256: sha256Hex(canonicalJson(record)),
      retention_class: 'unpaid-preview',
      store: 'arc-intake-submissions',
      ...overrides,
    }],
  };
}

function authorizeApply(value, dryRunValue, dryRunRaw, environment = applyEnv) {
  value.dry_run_id = dryRunValue.run_id;
  value.dry_run_manifest_sha256 = sha256Hex(dryRunRaw);
  value.adult_approval_hmac_sha256 = hmacHex(environment.ARC_RETENTION_ADULT_APPROVAL_SECRET,
    `${RETENTION_ADULT_APPROVAL_PREFIX}${canonicalJson({
      apply_run_id: value.run_id,
      dry_run_id: value.dry_run_id,
      dry_run_manifest_sha256: value.dry_run_manifest_sha256,
      policy_version: value.policy_version,
      target_set_sha256: sha256Hex(canonicalJson(value.targets)),
    })}`);
  return value;
}

async function completeDryRun(runId, id, sourceRecord, intake, control, environment = env, targetOverrides = {}) {
  const value = manifestFor(runId, id, sourceRecord, 'dry-run', targetOverrides);
  const raw = canonicalJson(value);
  const result = await runRetentionManifest(raw, sign(raw, environment), environment, { intake, control }, {
    clock: () => new Date(now),
  });
  assert.equal(result.eligible, 1);
  return { raw, value };
}

const sign = (raw, environment = env) => hmacHex(environment.ARC_RETENTION_MANIFEST_SECRET, `${RETENTION_MANIFEST_PREFIX}${raw}`);
const submissionId = '11111111-1111-4111-8111-111111111111';
const record = intakeRecord(submissionId);
const dryIntake = new FakeStore();
const dryControl = new FakeStore();
await dryIntake.setJSON(`submissions/${submissionId}`, record);
const dryValue = manifestFor('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', submissionId, record);
const dryManifest = canonicalJson(dryValue);
const dryResult = await runRetentionManifest(dryManifest, sign(dryManifest), env, { intake: dryIntake, control: dryControl }, {
  clock: () => new Date(now),
});
assert.equal(dryResult.eligible, 1);
assert.equal(dryResult.deleted, 0);
assert.ok(await dryIntake.getWithMetadata(`submissions/${submissionId}`), 'Dry-run must never delete data.');
assert.equal([...dryControl.values.keys()].some((key) => key.startsWith('delete-intents/')), false, 'Dry-run must not create deletion intent.');

const applyEnv = {
  ...env,
  ARC_RETENTION_EXECUTION_MODE: 'apply',
  ARC_RETENTION_ADULT_OPERATOR_VERIFIED: 'true',
  ARC_RETENTION_LEGAL_HOLD_CHECK_VERIFIED: 'true',
  ARC_RETENTION_DELETION_VERIFIED: 'true',
};
const applyIntake = new FakeStore();
const applyControl = new FakeStore();
await applyIntake.setJSON(`submissions/${submissionId}`, record);
const applyDry = await completeDryRun('abababab-abab-4bab-8bab-abababababab', submissionId, record, applyIntake, applyControl);
const applyValue = authorizeApply(manifestFor('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', submissionId, record, 'apply'), applyDry.value, applyDry.raw);
const applyManifest = canonicalJson(applyValue);
const applied = await runRetentionManifest(applyManifest, sign(applyManifest, applyEnv), applyEnv, {
  intake: applyIntake, control: applyControl,
}, { clock: () => new Date(now) });
assert.equal(applied.deleted, 1);
assert.equal((await applyIntake.getWithMetadata(`submissions/${submissionId}`)).data.schema,
  'arc-retention-record-tombstone-v1');
assert.equal([...applyControl.values.keys()].filter((key) => key.startsWith('delete-intents/')).length, 1);
assert.equal([...applyControl.values.keys()].filter((key) => key.startsWith('delete-receipts/')).length, 1);
const appliedReplay = await runRetentionManifest(applyManifest, sign(applyManifest, applyEnv), applyEnv, {
  intake: applyIntake, control: applyControl,
}, { clock: () => new Date(now.getTime() + 24 * 60 * 60_000) });
assert.equal(appliedReplay.idempotent_replay, true);

const crashId = '22222222-2222-4222-8222-222222222222';
const crashRecord = intakeRecord(crashId);
const crashIntake = new FakeStore();
const crashControl = new FakeStore();
await crashIntake.setJSON(`submissions/${crashId}`, crashRecord);
const crashDry = await completeDryRun('cacacaca-caca-4aca-8aca-cacacacacaca', crashId, crashRecord, crashIntake, crashControl);
const crashValue = authorizeApply(manifestFor('cccccccc-cccc-4ccc-8ccc-cccccccccccc', crashId, crashRecord, 'apply'), crashDry.value, crashDry.raw);
const crashManifest = canonicalJson(crashValue);
let crashAfterDelete = true;
await assert.rejects(runRetentionManifest(crashManifest, sign(crashManifest, applyEnv), applyEnv, {
  intake: crashIntake, control: crashControl,
}, { clock: () => new Date(now), afterDelete: () => {
  if (crashAfterDelete) {
    crashAfterDelete = false;
    throw new Error('simulated_crash_after_delete');
  }
} }), /simulated_crash/);
assert.equal((await crashIntake.getWithMetadata(`submissions/${crashId}`)).data.schema,
  'arc-retention-record-tombstone-v1');
assert.equal([...crashControl.values.keys()].filter((key) => key.startsWith('delete-intents/')).length, 1);
assert.equal([...crashControl.values.keys()].filter((key) => key.startsWith('delete-receipts/')).length, 0);
const resumed = await runRetentionManifest(crashManifest, sign(crashManifest, applyEnv), applyEnv, {
  intake: crashIntake, control: crashControl,
}, { clock: () => new Date(now.getTime() + 60 * 60_000) });
assert.equal(resumed.deleted, 1);
assert.equal(resumed.resumed, 1);
assert.equal([...crashControl.values.keys()].filter((key) => key.startsWith('delete-receipts/')).length, 1);

const holdId = '33333333-3333-4333-8333-333333333333';
const holdRecord = intakeRecord(holdId);
const holdIntake = new FakeStore();
const holdControl = new FakeStore();
await holdIntake.setJSON(`submissions/${holdId}`, holdRecord);
const holdDry = await completeDryRun('dadadada-dada-4ada-8ada-dadadadadada', holdId, holdRecord, holdIntake, holdControl);
const holdValue = authorizeApply(manifestFor('dddddddd-dddd-4ddd-8ddd-dddddddddddd', holdId, holdRecord, 'apply'), holdDry.value, holdDry.raw);
const holdManifest = canonicalJson(holdValue);
const holdTarget = holdValue.targets[0];
await holdControl.setJSON(retentionKeys.legalHoldKey(holdTarget, applyEnv), { schema: 'arc-retention-legal-hold-v1', active: true });
const held = await runRetentionManifest(holdManifest, sign(holdManifest, applyEnv), applyEnv, {
  intake: holdIntake, control: holdControl,
}, { clock: () => new Date(now) });
assert.equal(held.legal_hold, 1);
assert.ok(await holdIntake.getWithMetadata(`submissions/${holdId}`));

const freshId = '44444444-4444-4444-8444-444444444444';
const freshRecord = intakeRecord(freshId, '2026-08-01T00:00:00.000Z');
const freshIntake = new FakeStore();
const freshControl = new FakeStore();
await freshIntake.setJSON(`submissions/${freshId}`, freshRecord);
const freshValue = manifestFor('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', freshId, freshRecord, 'dry-run', {
  last_interaction_at: '2026-08-01T00:00:00.000Z',
});
const freshManifest = canonicalJson(freshValue);
const fresh = await runRetentionManifest(freshManifest, sign(freshManifest), env, {
  intake: freshIntake, control: freshControl,
}, { clock: () => new Date(now) });
assert.equal(fresh.not_expired, 1);

const deliveredId = '55555555-5555-4555-8555-555555555555';
const deliveredRecord = intakeRecord(deliveredId);
deliveredRecord.arc1_delivery.status = 'ACKED';
deliveredRecord.arc1_delivery.attempt_count = 1;
deliveredRecord.arc1_delivery.acknowledged_at = '2024-07-01T00:05:00.000Z';
deliveredRecord.arc1_delivery.acknowledgement_sha256 = 'b'.repeat(64);
deliveredRecord.arc1_delivery.consumer_claim_key_hmac_sha256 = 'c'.repeat(64);
const deliveredIntake = new FakeStore();
await deliveredIntake.setJSON(`submissions/${deliveredId}`, deliveredRecord);
const deliveredValue = manifestFor('99999999-9999-4999-8999-999999999999', deliveredId, deliveredRecord, 'dry-run');
const deliveredManifest = canonicalJson(deliveredValue);
await assert.rejects(runRetentionManifest(deliveredManifest, sign(deliveredManifest, env), env, {
  intake: deliveredIntake, control: new FakeStore(),
}, { clock: () => new Date(now) }), /DELIVERY_HISTORY/, 'Records with any ARC1 delivery history must be preserved.');
assert.ok(await deliveredIntake.getWithMetadata(`submissions/${deliveredId}`));

const racedId = '66666666-6666-4666-8666-666666666666';
const racedRecord = intakeRecord(racedId);
const racedIntake = new FakeStore();
const racedControl = new FakeStore();
await racedIntake.setJSON(`submissions/${racedId}`, racedRecord);
const racedDry = await completeDryRun('67676767-6767-4767-8767-676767676767', racedId, racedRecord, racedIntake, racedControl);
const racedValue = authorizeApply(manifestFor('68686868-6868-4868-8868-686868686868', racedId, racedRecord, 'apply'), racedDry.value, racedDry.raw);
const racedManifest = canonicalJson(racedValue);
racedIntake.mutateBeforeCas = { key: `submissions/${racedId}`, mutate: (value) => { value.concurrent_note = 'preserve-me'; } };
await assert.rejects(runRetentionManifest(racedManifest, sign(racedManifest, applyEnv), applyEnv, {
  intake: racedIntake, control: racedControl,
}, { clock: () => new Date(now) }), /TARGET_CHANGED/, 'A concurrent target update must win over cleanup and remain present.');
assert.equal((await racedIntake.getWithMetadata(`submissions/${racedId}`)).data.concurrent_note, 'preserve-me');
assert.equal([...racedControl.values.keys()].some((key) => key.startsWith('delete-receipts/')), false);
assert.equal([...racedControl.values.keys()].some((key) => key.startsWith('tombstone-claims/')), false);

const noDryControl = new FakeStore();
const noDryIntake = new FakeStore();
await noDryIntake.setJSON(`submissions/${submissionId}`, record);
await assert.rejects(runRetentionManifest(applyManifest, sign(applyManifest, applyEnv), applyEnv, {
  intake: noDryIntake, control: noDryControl,
}, { clock: () => new Date(now) }), /PRIOR_DRY_RUN_REQUIRED/, 'Apply must be bound to an exact successful dry run.');

const invalidValue = manifestFor('ffffffff-ffff-4fff-8fff-ffffffffffff', submissionId, record, 'dry-run', { store: 'arc2-handoffs' });
const invalidManifest = canonicalJson(invalidValue);
await assert.rejects(runRetentionManifest(invalidManifest, sign(invalidManifest), env, {
  intake: new FakeStore(), control: new FakeStore(),
}, { clock: () => new Date(now) }), /not allowlisted/);
const applyWithoutAttestation = { ...env, ARC_RETENTION_EXECUTION_MODE: 'apply' };
await assert.rejects(runRetentionManifest(applyManifest, sign(applyManifest, applyWithoutAttestation), applyWithoutAttestation, {
  intake: new FakeStore(), control: new FakeStore(),
}, { clock: () => new Date(now) }), /APPLY_DISABLED/);

assert.equal(retentionConfig.path, '/internal/retention/cleanup');
const bodyLimitSnapshot = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
Object.assign(process.env, env);
try {
  const multiFirstId = '70707070-7070-4070-8070-707070707070';
  const multiSecondId = '71717171-7171-4171-8171-717171717171';
  const multiFirst = intakeRecord(multiFirstId);
  const multiSecond = intakeRecord(multiSecondId);
  const multiValue = manifestFor('72727272-7272-4272-8272-727272727272', multiFirstId, multiFirst);
  multiValue.targets.push({
    key: `submissions/${multiSecondId}`,
    last_interaction_at: '2024-07-01T00:00:00.000Z',
    record_sha256: sha256Hex(canonicalJson(multiSecond)),
    retention_class: 'unpaid-preview',
    store: 'arc-intake-submissions',
  });
  const multiManifest = canonicalJson(multiValue);
  const multiControl = new FakeStore();
  const multiResponse = await retentionHandler(new Request(
    'https://arcweb.onl/internal/retention/cleanup', {
      method: 'POST',
      headers: { authorization: `Bearer ${env.ARC_RETENTION_CLEANUP_SECRET}`,
        'content-type': 'application/json' },
      body: JSON.stringify({ manifest: multiManifest,
        manifest_hmac_sha256: sign(multiManifest) }),
    }), { retentionStore: multiControl, intakeStore: new FakeStore(), clock: () => new Date(now) });
  assert.equal(multiResponse.status, 400);
  assert.equal((await multiResponse.json()).error, 'single_subject_retention_manifest_required');
  assert.equal(await multiControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY), null,
    'A multi-subject legacy request must fail before taking FROZEN.');

  const routeId = '77777777-7777-4777-8777-777777777777';
  const routeRecord = intakeRecord(routeId);
  const routeValue = manifestFor('78787878-7878-4878-8878-787878787878', routeId, routeRecord);
  const routeManifest = canonicalJson(routeValue);
  const routeRequest = () => new Request('https://arcweb.onl/internal/retention/cleanup', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.ARC_RETENTION_CLEANUP_SECRET}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      manifest: routeManifest,
      manifest_hmac_sha256: sign(routeManifest),
    }),
  });
  const routeControl = new FakeStore();
  const routeIntake = new FakeStore();
  await routeIntake.setJSON(`submissions/${routeId}`, routeRecord);
  const routeContext = {
    retentionStore: routeControl,
    intakeStore: routeIntake,
    clock: () => new Date(now),
  };
  const routed = await retentionHandler(routeRequest(), routeContext);
  assert.equal(routed.status, 200, 'Legacy cleanup must complete only through the global retention freeze.');
  const routedResult = await routed.json();
  assert.equal(routedResult.eligible, 1);
  assert.equal(routedResult.mode, 'dry-run');
  assert.equal(routedResult.deleted, 0, 'A dry-run gate completion must not claim a destructive result.');
  const openedFence = validateRetentionGenerationFenceState(
    (await routeControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, env,
  );
  assert.equal(openedFence.status, 'OPEN');
  assert.equal(openedFence.generation, 1, 'A signed finalize receipt must reopen the next generation.');
  assert.equal([...routeControl.values.keys()].filter((key) =>
    key.startsWith('first-party-retention/generation-fence/finalize-receipts/')).length, 1);
  const completedFreezeIntentKey = [...routeControl.values.keys()].find((key) =>
    key.startsWith('first-party-retention/generation-fence/freeze-intents/'));
  const completedFreezeIntent = validateRetentionFreezeIntent(
    (await routeControl.getWithMetadata(completedFreezeIntentKey)).data, env,
  );
  const dryRunFenceReceipt = validateRetentionFinalizeReceipt(
    (await routeControl.getWithMetadata(retentionGenerationFenceKeys.finalizeReceipt(
      completedFreezeIntent.operation_hmac_sha256))).data,
    completedFreezeIntent,
    env,
  );
  assert.equal(dryRunFenceReceipt.primary_tombstone_sha256,
    dryRunFenceReceipt.tombstone_set_sha256,
    'Dry-run fence evidence must use one explicit non-destructive sentinel, not tombstone output claims.');
  const routedReplay = await retentionHandler(routeRequest(), routeContext);
  assert.equal(routedReplay.status, 200);
  assert.equal((await routedReplay.json()).idempotent_replay, true);
  assert.equal(validateRetentionGenerationFenceState(
    (await routeControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, env,
  ).generation, 1, 'An exact completed retry must be a read-only replay, not a new freeze generation.');

  const missingId = '88888888-8888-4888-8888-888888888888';
  const missingRecord = intakeRecord(missingId);
  const missingValue = manifestFor('89898989-8989-4989-8989-898989898989', missingId, missingRecord);
  const missingManifest = canonicalJson(missingValue);
  const missingRequest = () => new Request('https://arcweb.onl/internal/retention/cleanup', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.ARC_RETENTION_CLEANUP_SECRET}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ manifest: missingManifest,
      manifest_hmac_sha256: sign(missingManifest) }),
  });
  const missingControl = new FakeStore();
  const missingContext = {
    retentionStore: missingControl,
    intakeStore: new FakeStore(),
    clock: () => new Date(now),
  };
  const missingResponse = await retentionHandler(missingRequest(), missingContext);
  assert.equal(missingResponse.status, 409);
  assert.equal((await missingResponse.json()).error, 'retention_missing_source');
  const frozenFence = validateRetentionGenerationFenceState(
    (await missingControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, env,
  );
  assert.equal(frozenFence.status, 'FROZEN', 'A partial missing-source run must never release FROZEN.');
  assert.equal(await missingControl.getWithMetadata(retentionKeys.completionKey(missingValue.run_id)), null,
    'A missing target must never produce a legacy completion.');
  const freezeIntent = validateRetentionFreezeIntent((await missingControl.getWithMetadata(
    retentionGenerationFenceKeys.freezeIntent(frozenFence.operation_hmac_sha256))).data, env);
  const anomalyKeys = [...missingControl.values.keys()].filter((key) =>
    key.startsWith(retentionGenerationFenceKeys.missingSourcePrefix(frozenFence.operation_hmac_sha256)));
  assert.equal(anomalyKeys.length, 1, 'A listed missing manifest target must persist one signed anomaly.');
  validateRetentionMissingSourceAnomaly(
    (await missingControl.getWithMetadata(anomalyKeys[0])).data, freezeIntent, env,
  );
  const contention = await retentionHandler(missingRequest(), missingContext);
  assert.equal(contention.status, 409, 'Fresh exact contention must retry without releasing FROZEN.');
  assert.equal([...missingControl.values.keys()].filter((key) =>
    key.startsWith('first-party-retention/generation-fence/critical-alerts/')).length, 0,
  'Normal lock contention must not create a permanent alert.');

  let canceled = false;
  let storeReads = 0;
  const request = new Request('https://arcweb.onl/internal/retention/cleanup', {
    method: 'POST', duplex: 'half',
    headers: { authorization: `Bearer ${env.ARC_RETENTION_CLEANUP_SECRET}`, 'content-type': 'application/json' },
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(200_000));
        controller.enqueue(new Uint8Array(100_000));
      },
      cancel() { canceled = true; },
    }),
  });
  const context = {};
  Object.defineProperties(context, {
    retentionStore: { get() { storeReads += 1; throw new Error('store must remain untouched'); } },
    intakeStore: { get() { storeReads += 1; throw new Error('store must remain untouched'); } },
  });
  assert.equal((await retentionHandler(request, context)).status, 413,
    'Retention must reject a headerless oversized manifest before parsing or storage.');
  assert.equal(canceled, true, 'Retention must cancel the oversized request stream.');
  assert.equal(storeReads, 0, 'Retention must not resolve durable storage for an oversized body.');
} finally {
  for (const [key, value] of Object.entries(bodyLimitSnapshot)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
}
const saved = process.env.ARC_RETENTION_CLEANUP_ENABLED;
delete process.env.ARC_RETENTION_CLEANUP_ENABLED;
try {
  assert.equal((await retentionHandler(new Request('https://arcweb.onl/internal/retention/cleanup', { method: 'POST' }))).status, 503);
} finally {
  if (saved === undefined) delete process.env.ARC_RETENTION_CLEANUP_ENABLED;
  else process.env.ARC_RETENTION_CLEANUP_ENABLED = saved;
}

console.log('ARC retention control contract passed.');
