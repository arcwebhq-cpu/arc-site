import { createHmac, randomUUID } from 'node:crypto';

import { assertPublicIntakeAuthority } from './activation-manifest-core.mjs';
import {
  arc1AdapterProtocolEnabled,
  recoverPendingArc1AdapterDispatches,
  resolveArc1AdapterEnvironment,
} from './intake-arc1-adapter-core.mjs';

export const INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED_ENV = 'ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED';
export const INTAKE_ARC1_RECOVERY_RUNNER_SCHEMA = 'arc-intake-arc1-adapter-recovery-runner-v1';
export const INTAKE_ARC1_RECOVERY_RUNNER_KEY = 'control/adapter-recovery-runner-v1';
export const INTAKE_ARC1_RECOVERY_RUNNER_LEASE_MS = 2 * 60_000;

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const FIELDS = Object.freeze([
  'completed_at', 'cursor', 'last_result', 'lease_expires_at', 'lease_hmac_sha256', 'run_count',
  'schema', 'started_at', 'status',
]);
const RESULT_FIELDS = Object.freeze(['attempted', 'invalid', 'migration_required', 'reviewed', 'scanned', 'state']);
const exactKeys = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
const iso = (value, label) => {
  const milliseconds = typeof value === 'string' ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return value;
};
const nullableIso = (value, label) => value === null ? null : iso(value, label);

export function arc1RecoveryAutomationEnabled(env = process.env) {
  return env[INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED_ENV] === 'true' && arc1AdapterProtocolEnabled(env);
}

export function validateArc1RecoveryRunnerState(value) {
  if (!exactKeys(value, FIELDS) || value.schema !== INTAKE_ARC1_RECOVERY_RUNNER_SCHEMA ||
      !['IDLE', 'RUNNING'].includes(value.status) || !Number.isSafeInteger(value.run_count) || value.run_count < 0 ||
      !(value.cursor === null || typeof value.cursor === 'string' && value.cursor.length > 0 && value.cursor.length <= 512) ||
      !(value.last_result === null || exactKeys(value.last_result, RESULT_FIELDS) &&
        ['RECOVERY_COMPLETE', 'RECOVERY_PARTIAL'].includes(value.last_result.state) &&
        ['scanned', 'attempted', 'reviewed', 'migration_required', 'invalid'].every((field) =>
          Number.isSafeInteger(value.last_result[field]) && value.last_result[field] >= 0))) {
    throw new TypeError('ARC1 adapter recovery runner state is invalid.');
  }
  nullableIso(value.started_at, 'ARC1 recovery runner started_at');
  nullableIso(value.lease_expires_at, 'ARC1 recovery runner lease_expires_at');
  nullableIso(value.completed_at, 'ARC1 recovery runner completed_at');
  if (value.lease_hmac_sha256 !== null && !SHA256_PATTERN.test(value.lease_hmac_sha256)) {
    throw new TypeError('ARC1 recovery runner lease is invalid.');
  }
  if (value.status === 'IDLE' && (value.lease_hmac_sha256 !== null || value.lease_expires_at !== null)) {
    throw new TypeError('Idle ARC1 recovery runner has a lease.');
  }
  if (value.status === 'RUNNING' && (!value.lease_hmac_sha256 || !value.lease_expires_at || !value.started_at)) {
    throw new TypeError('Running ARC1 recovery runner is incomplete.');
  }
  return value;
}

async function readState(store) {
  const entry = await store.getWithMetadata(INTAKE_ARC1_RECOVERY_RUNNER_KEY, { type: 'json', consistency: 'strong' });
  return entry ? { value: validateArc1RecoveryRunnerState(entry.data), etag: entry.etag } : null;
}

async function replaceState(store, entry, value) {
  validateArc1RecoveryRunnerState(value);
  const result = await store.setJSON(INTAKE_ARC1_RECOVERY_RUNNER_KEY, value, { onlyIfMatch: entry.etag });
  if (!result?.modified || typeof result.etag !== 'string' || result.etag.length === 0) {
    throw new Error('ARC1_RECOVERY_RUNNER_STATE_CONTENTION');
  }
  return { value, etag: result.etag };
}

async function createInitialLease(store, value) {
  try { await store.setJSON(INTAKE_ARC1_RECOVERY_RUNNER_KEY, value, { onlyIfNew: true }); } catch {}
  const entry = await readState(store);
  if (!entry) throw new Error('ARC1_RECOVERY_RUNNER_STATE_UNAVAILABLE');
  return entry;
}

export async function runArc1AdapterRecoveryCycle(env, stores, adapters = {}) {
  assertPublicIntakeAuthority(env);
  if (!arc1RecoveryAutomationEnabled(env)) {
    return { state: 'RECOVERY_AUTOMATION_DISABLED', cursor: null, idempotentReplay: true };
  }
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('ARC1 recovery runner clock is invalid.');
  const resolved = resolveArc1AdapterEnvironment(env);
  const leaseHmac = createHmac('sha256', resolved.ARC_INTAKE_ARC1_STATE_SECRET).update(
    `arc-intake-arc1-recovery-runner-lease-v1\n${now.toISOString()}\n${(adapters.uuid || randomUUID)()}`,
  ).digest('hex');
  const running = (previous) => ({
    schema: INTAKE_ARC1_RECOVERY_RUNNER_SCHEMA,
    status: 'RUNNING',
    cursor: previous?.cursor || null,
    run_count: (previous?.run_count || 0) + 1,
    lease_hmac_sha256: leaseHmac,
    lease_expires_at: new Date(now.getTime() + INTAKE_ARC1_RECOVERY_RUNNER_LEASE_MS).toISOString(),
    started_at: now.toISOString(),
    completed_at: previous?.completed_at || null,
    last_result: previous?.last_result || null,
  });
  let entry = await readState(stores.adapter);
  if (!entry) {
    entry = await createInitialLease(stores.adapter, running(null));
    if (entry.value.status === 'RUNNING' && entry.value.lease_hmac_sha256 !== leaseHmac &&
        Date.parse(entry.value.lease_expires_at) > now.getTime()) {
      return { state: 'RECOVERY_IN_PROGRESS', cursor: entry.value.cursor, idempotentReplay: true };
    }
  }
  if (entry.value.lease_hmac_sha256 !== leaseHmac) {
    if (entry.value.status === 'RUNNING' && Date.parse(entry.value.lease_expires_at) > now.getTime()) {
      return { state: 'RECOVERY_IN_PROGRESS', cursor: entry.value.cursor, idempotentReplay: true };
    }
    entry = await replaceState(stores.adapter, entry, running(entry.value));
  }
  const recover = adapters.recover || recoverPendingArc1AdapterDispatches;
  const result = await recover(new Request(`${resolved.origin}/internal/intake/arc1/adapter/recover`, { method: 'POST' }), env,
    stores, { ...adapters, cursor: entry.value.cursor });
  if (!['RECOVERY_COMPLETE', 'RECOVERY_PARTIAL'].includes(result?.state) ||
      !(result.next_cursor === null || typeof result.next_cursor === 'string')) {
    throw new Error('ARC1_RECOVERY_RUNNER_RESULT_INVALID');
  }
  const completedAt = new Date((adapters.clock || (() => new Date()))()).toISOString();
  const current = await readState(stores.adapter);
  if (!current || current.value.status !== 'RUNNING' || current.value.lease_hmac_sha256 !== leaseHmac) {
    throw new Error('ARC1_RECOVERY_RUNNER_STATE_CONTENTION');
  }
  const idle = {
    ...current.value,
    status: 'IDLE',
    cursor: result.next_cursor,
    lease_hmac_sha256: null,
    lease_expires_at: null,
    completed_at: completedAt,
    last_result: {
      state: result.state,
      scanned: result.scanned,
      attempted: result.attempted,
      reviewed: result.reviewed,
      migration_required: result.migration_required,
      invalid: result.invalid,
    },
  };
  await replaceState(stores.adapter, current, idle);
  return { state: result.state, cursor: result.next_cursor, idempotentReplay: false };
}
