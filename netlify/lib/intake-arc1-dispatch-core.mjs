import { createHmac, timingSafeEqual } from 'node:crypto';
import { normalizeStoredIntakeSubmissionForBridge, validateIntakeSubmissionForBridge } from './intake-arc1-bridge-core.mjs';

export const INTAKE_ARC1_DISPATCH_ENABLED_ENV = 'ARC_INTAKE_ARC1_DISPATCH_ENABLED';
export const INTAKE_ARC1_DISPATCH_TIMEOUT_MS = 5_000;
export const INTAKE_ARC1_RECOVERY_MAX_ATTEMPTS = 20;
export const INTAKE_ARC1_RECOVERY_MAX_RECORD_READS = 100;
export const INTAKE_ARC1_RECOVERY_MAX_LIST_PAGES = 20;
export const INTAKE_ARC1_RECOVERY_BUDGET_MS = 8_000;
export const INTAKE_ARC1_DISPATCH_LEASE_MS = 30_000;

const RECOVERY_CURSOR_VERSION = 2;
// Two UUID hex digits give 256 deterministic provider prefixes. With Netlify's
// 1,000-key pages and the 20 post-cursor page limit, one invocation design can
// cover more than five million queued submissions before any shard reaches its
// page ceiling; terminal queue records are expected to be pruned separately.
const RECOVERY_SHARD_COUNT = 256;
const RECOVERY_SHARD_WIDTH = 2;

const safeEqual = (left, right) => {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
};
const secret = (value, label) => {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 32 || Buffer.byteLength(value, 'utf8') > 256) {
    throw new TypeError(`${label} must be 32-256 UTF-8 bytes.`);
  }
  return value;
};

function wallNow(adapters) {
  const value = (adapters.wallClock || Date.now)();
  if (!Number.isFinite(value)) throw new TypeError('Dispatch recovery wall clock is invalid.');
  return value;
}

function recoveryCursorSecret(env) {
  return secret(env.ARC_INTAKE_ARC1_RUN_SECRET, 'ARC_INTAKE_ARC1_RUN_SECRET');
}

function encodeRecoveryCursor(value, env) {
  if (!Number.isSafeInteger(value.position) || value.position < 0 ||
      !(value.sequence_hmac_sha256 === null ? value.position === 0 :
        value.position > 0 && /^[a-f0-9]{64}$/.test(value.sequence_hmac_sha256))) {
    throw new TypeError('Dispatch recovery sequence checkpoint is invalid.');
  }
  const raw = Buffer.from(JSON.stringify({
    v: RECOVERY_CURSOR_VERSION,
    shard: value.shard,
    position: value.position,
    sequence_hmac_sha256: value.sequence_hmac_sha256,
  }), 'utf8').toString('base64url');
  const signature = createHmac('sha256', recoveryCursorSecret(env)).update(`arc-intake-dispatch-recovery-cursor-v2\n${raw}`).digest('base64url');
  return `${raw}.${signature}`;
}

function decodeRecoveryCursor(token, env) {
  if (token === null || token === undefined || token === '') return { shard: 0, position: 0, sequence_hmac_sha256: null };
  if (typeof token !== 'string' || token.length > 512 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
    throw new TypeError('Dispatch recovery cursor is invalid.');
  }
  const [raw, supplied] = token.split('.');
  const expected = createHmac('sha256', recoveryCursorSecret(env)).update(`arc-intake-dispatch-recovery-cursor-v2\n${raw}`).digest('base64url');
  if (!safeEqual(supplied, expected)) throw new TypeError('Dispatch recovery cursor signature mismatch.');
  let value;
  try { value = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')); } catch { throw new TypeError('Dispatch recovery cursor is invalid.'); }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['position', 'sequence_hmac_sha256', 'shard', 'v']) ||
      value.v !== RECOVERY_CURSOR_VERSION || !Number.isInteger(value.shard) || value.shard < 0 || value.shard >= RECOVERY_SHARD_COUNT ||
      !Number.isSafeInteger(value.position) || value.position < 0 ||
      !(value.sequence_hmac_sha256 === null ? value.position === 0 :
        value.position > 0 && /^[a-f0-9]{64}$/.test(value.sequence_hmac_sha256))) {
    throw new TypeError('Dispatch recovery cursor fields are invalid.');
  }
  return { shard: value.shard, position: value.position, sequence_hmac_sha256: value.sequence_hmac_sha256 };
}

function recoverySequenceInitial(env, shard, prefix) {
  return createHmac('sha256', recoveryCursorSecret(env)).update(
    `arc-intake-dispatch-provider-sequence-v1\n${shard}\n${Buffer.byteLength(prefix, 'utf8')}\n${prefix}`,
  ).digest('hex');
}

function recoverySequenceNext(env, previous, key) {
  const bytes = Buffer.from(key, 'utf8');
  return createHmac('sha256', recoveryCursorSecret(env)).update(Buffer.concat([
    Buffer.from(`arc-intake-dispatch-provider-sequence-step-v1\n${previous}\n${bytes.length}\n`, 'utf8'),
    bytes,
  ])).digest('hex');
}

function requestRecoveryCursor(request, adapters) {
  if (Object.hasOwn(adapters, 'cursor')) return adapters.cursor;
  let url;
  try { url = new URL(request.url); } catch { throw new TypeError('Dispatch recovery request URL is invalid.'); }
  const values = url.searchParams.getAll('cursor');
  if (values.length > 1) throw new TypeError('Dispatch recovery cursor is ambiguous.');
  return values[0] || null;
}

export function resolveSameDeployDispatcher(request, env) {
  const dispatchSecret = secret(env.ARC_INTAKE_ARC1_DISPATCH_SECRET, 'ARC_INTAKE_ARC1_DISPATCH_SECRET');
  const runSecret = secret(env.ARC_INTAKE_ARC1_RUN_SECRET, 'ARC_INTAKE_ARC1_RUN_SECRET');
  if (safeEqual(dispatchSecret, runSecret)) throw new TypeError('Dispatch and run secrets must be distinct.');
  const publicOrigin = String(env.URL || '').replace(/\/+$/, '');
  let configured;
  let requestUrl;
  try {
    configured = new URL(publicOrigin);
    requestUrl = new URL(request.url);
  } catch { throw new TypeError('Same-deploy dispatcher origin is invalid.'); }
  if (configured.protocol !== 'https:' || configured.username || configured.password || configured.port || configured.pathname !== '/' ||
      configured.search || configured.hash || !['arcweb.onl', 'arcsites.netlify.app'].includes(configured.hostname) ||
      requestUrl.protocol !== 'https:' || !['arcweb.onl', 'arcsites.netlify.app'].includes(requestUrl.hostname)) {
    throw new TypeError('Same-deploy dispatcher origin mismatch.');
  }
  return { endpoint: `${configured.origin}/.netlify/functions/intake-arc1-background`, dispatchSecret, runSecret };
}

async function replaceRecord(store, key, entry, record) {
  validateIntakeSubmissionForBridge(record);
  const result = await store.setJSON(key, record, { onlyIfMatch: entry.etag });
  if (!result?.modified || !result.etag) throw new Error('ARC1_DISPATCH_STATE_CONTENTION');
  return { record, etag: result.etag };
}

async function readRecord(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  return entry ? { record: normalizeStoredIntakeSubmissionForBridge(entry.data), etag: entry.etag } : null;
}

async function convergeDispatchState(store, key, desired) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const current = await readRecord(store, key);
    if (!current) throw new Error('ARC1_DISPATCH_SOURCE_MISSING');
    if (desired.status === 'ACCEPTED' && current.record.arc1_dispatch.status === 'ACCEPTED') return current;
    try {
      return await replaceRecord(store, key, current, {
        ...current.record,
        arc1_dispatch: { ...current.record.arc1_dispatch, ...desired },
      });
    } catch (error) {
      if (error?.message !== 'ARC1_DISPATCH_STATE_CONTENTION' || attempt === 3) throw error;
    }
  }
  throw new Error('ARC1_DISPATCH_STATE_CONTENTION');
}

export async function dispatchIntakeToArc1Background(submissionId, request, env, adapters = {}) {
  if (env[INTAKE_ARC1_DISPATCH_ENABLED_ENV] !== 'true') return { state: 'DISPATCH_DISABLED' };
  const resolved = resolveSameDeployDispatcher(request, env);
  const store = adapters.store;
  const clock = adapters.clock || (() => new Date());
  const fetchImpl = adapters.fetch || fetch;
  const key = `submissions/${submissionId}`;
  let entry = await readRecord(store, key);
  if (!entry) throw new Error('ARC1_DISPATCH_SOURCE_MISSING');
  const force = adapters.force === true;
  if (entry.record.arc1_dispatch.status === 'DEAD_LETTER') return { state: 'DEAD_LETTER', idempotentReplay: true };
  if (entry.record.arc1_dispatch.status === 'ACCEPTED' && !force) return { state: 'ACCEPTED', idempotentReplay: true };
  const now = new Date(clock());
  const leaseExpiresAt = entry.record.arc1_dispatch.attempt_lease_expires_at ?
    Date.parse(entry.record.arc1_dispatch.attempt_lease_expires_at) : null;
  if (Number.isFinite(leaseExpiresAt)) {
    if (leaseExpiresAt > now.getTime()) return { state: 'ATTEMPT_IN_FLIGHT', idempotentReplay: true };
    // A process exit cannot prove whether fetch entry occurred. The downstream
    // request is identity-bound and idempotent, so clear the stale lease and
    // retry without burning a failure count; surface the ambiguity durably.
    entry = await replaceRecord(store, key, entry, {
      ...entry.record,
      arc1_dispatch: {
        ...entry.record.arc1_dispatch,
        status: 'PENDING',
        attempt_lease_hmac_sha256: null,
        attempt_lease_expires_at: null,
        accepted_at: null,
        alert_status: 'PENDING',
        alert_code: 'DISPATCH_UNAVAILABLE',
        alert_updated_at: now.toISOString(),
      },
    });
  }
  if (entry.record.arc1_dispatch.attempt_count >= 5) {
    const deadAt = new Date(clock()).toISOString();
    const dead = {
      ...entry.record.arc1_dispatch, status: 'DEAD_LETTER', accepted_at: null,
      attempt_lease_hmac_sha256: null, attempt_lease_expires_at: null, alert_status: 'PENDING',
      alert_code: 'DISPATCH_MAX_ATTEMPTS', alert_updated_at: deadAt,
    };
    await convergeDispatchState(store, key, dead);
    return { state: 'DEAD_LETTER', code: 'DISPATCH_MAX_ATTEMPTS' };
  }
  const wallClock = adapters.wallClock || Date.now;
  const remainingMs = Number.isFinite(adapters.deadlineMs) ? Math.floor(adapters.deadlineMs - wallClock()) : INTAKE_ARC1_DISPATCH_TIMEOUT_MS;
  if (!Number.isFinite(remainingMs) || remainingMs <= 0) return { state: 'DISPATCH_DEFERRED', code: 'DISPATCH_UNAVAILABLE' };
  const leaseId = `${submissionId}\n${now.toISOString()}\n${entry.etag}`;
  const leaseHmac = createHmac('sha256', resolved.runSecret).update(`arc-intake-dispatch-attempt-lease-v1\n${leaseId}`).digest('hex');
  const attempted = {
    ...entry.record.arc1_dispatch,
    status: 'PENDING',
    accepted_at: null,
    attempt_lease_hmac_sha256: leaseHmac,
    attempt_lease_expires_at: new Date(now.getTime() + INTAKE_ARC1_DISPATCH_LEASE_MS).toISOString(),
    last_attempt_at: now.toISOString(),
  };
  entry = await replaceRecord(store, key, entry, { ...entry.record, arc1_dispatch: attempted });
  let result;
  let networkEntered = false;
  try {
    const body = JSON.stringify({ schema: 'arc-intake-arc1-delivery-request-v1', submission_id: submissionId });
    const responsePromise = fetchImpl(resolved.endpoint, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(Math.min(INTAKE_ARC1_DISPATCH_TIMEOUT_MS, remainingMs)),
      headers: { Authorization: `Bearer ${resolved.dispatchSecret}`, 'Content-Type': 'application/json; charset=utf-8' },
      body,
    });
    networkEntered = true;
    const response = await responsePromise;
    if (response.status !== 202 || response.url && response.url !== resolved.endpoint) throw new Error('ARC1_DISPATCH_REJECTED');
    result = { status: 'ACCEPTED', code: null };
  } catch (error) {
    result = { status: 'PENDING', code: error?.message === 'ARC1_DISPATCH_REJECTED' ? 'DISPATCH_REJECTED' : 'DISPATCH_UNAVAILABLE' };
  }
  const completedAt = new Date(clock()).toISOString();
  if (!networkEntered) {
    await convergeDispatchState(store, key, {
      ...entry.record.arc1_dispatch, attempt_lease_hmac_sha256: null, attempt_lease_expires_at: null,
    });
    return { state: 'DISPATCH_DEFERRED', code: result.code };
  }
  const countedAttempts = entry.record.arc1_dispatch.attempt_count + 1;
  const exhausted = result.status !== 'ACCEPTED' && countedAttempts >= 5;
  const next = result.status === 'ACCEPTED' ? {
    ...entry.record.arc1_dispatch, status: 'ACCEPTED', attempt_count: countedAttempts, accepted_at: completedAt,
    attempt_lease_hmac_sha256: null, attempt_lease_expires_at: null,
    alert_status: entry.record.arc1_dispatch.alert_status === 'PENDING' ? 'RESOLVED' : 'NONE',
    alert_code: null, alert_updated_at: entry.record.arc1_dispatch.alert_status === 'PENDING' ? completedAt : null,
  } : exhausted ? {
    ...entry.record.arc1_dispatch, status: 'DEAD_LETTER', attempt_count: countedAttempts, accepted_at: null,
    attempt_lease_hmac_sha256: null, attempt_lease_expires_at: null, alert_status: 'PENDING',
    alert_code: 'DISPATCH_MAX_ATTEMPTS', alert_updated_at: completedAt,
  } : {
    ...entry.record.arc1_dispatch, status: 'PENDING', attempt_count: countedAttempts, accepted_at: null,
    attempt_lease_hmac_sha256: null, attempt_lease_expires_at: null,
    alert_status: 'PENDING', alert_code: result.code, alert_updated_at: completedAt,
  };
  // Netlify can run and ACK the background delivery before returning 202 to
  // this caller. Re-read and merge only dispatch fields so concurrent delivery
  // state is never reverted; retry bounded CAS contention.
  await convergeDispatchState(store, key, next);
  return { state: next.status, code: next.alert_code };
}

export async function recoverPendingArc1Dispatches(request, env, adapters = {}) {
  if (env[INTAKE_ARC1_DISPATCH_ENABLED_ENV] !== 'true') {
    return { state: 'DISPATCH_DISABLED', scanned: 0, attempted: 0, invalid: 0, next_cursor: null };
  }
  const store = adapters.store;
  if (!store || typeof store.list !== 'function') throw new TypeError('Dispatch recovery store is unavailable.');
  const startedAt = wallNow(adapters);
  const deadlineMs = startedAt + INTAKE_ARC1_RECOVERY_BUDGET_MS;
  const resumeCursor = decodeRecoveryCursor(requestRecoveryCursor(request, adapters), env);
  let cursor = { ...resumeCursor };
  let scanned = 0;
  let attempted = 0;
  let invalid = 0;
  let processedPages = 0;
  const nowMs = new Date((adapters.clock || (() => new Date()))()).getTime();
  const initialCursor = (shard) => ({ shard, position: 0, sequence_hmac_sha256: null });
  const partial = () => ({
    state: 'RECOVERY_PARTIAL', scanned, attempted, invalid,
    next_cursor: encodeRecoveryCursor(cursor, env),
  });
  let emptyShards = 0;
  for (let shard = resumeCursor.shard; shard < RECOVERY_SHARD_COUNT; shard += 1) {
    const prefix = `submissions/${shard.toString(16).padStart(RECOVERY_SHARD_WIDTH, '0')}`;
    const checkpoint = shard === resumeCursor.shard ? resumeCursor : initialCursor(shard);
    cursor = { ...checkpoint };
    const iterable = store.list({ prefix, paginate: true });
    if (!iterable || typeof iterable[Symbol.asyncIterator] !== 'function') throw new Error('ARC1_DISPATCH_RECOVERY_PAGINATION_REQUIRED');
    let position = 0;
    let sequenceSha256 = recoverySequenceInitial(env, shard, prefix);
    let checkpointVerified = checkpoint.position === 0;
    let shardBlobCount = 0;
    for await (const result of iterable) {
      if (!result || !Array.isArray(result.blobs)) throw new Error('ARC1_DISPATCH_RECOVERY_PAGINATION_REQUIRED');
      if (wallNow(adapters) >= deadlineMs) return partial();
      const batch = result.blobs;
      shardBlobCount += batch.length;
      let pageCounted = false;
      for (const blob of batch) {
        if (typeof blob?.key !== 'string' || blob.key.length === 0) {
          throw new Error('ARC1_DISPATCH_RECOVERY_PAGINATION_REQUIRED');
        }
        const key = blob.key;
        const nextSequenceSha256 = recoverySequenceNext(env, sequenceSha256, key);
        position += 1;
        if (!checkpointVerified) {
          sequenceSha256 = nextSequenceSha256;
          if (position < checkpoint.position) continue;
          if (position === checkpoint.position && sequenceSha256 === checkpoint.sequence_hmac_sha256) {
            checkpointVerified = true;
            continue;
          }
          // Store.list does not promise key ordering and hides its opaque
          // provider cursor. A changed prefix sequence invalidates only this
          // authenticated checkpoint; it can never authorize a skip.
          cursor = initialCursor(shard);
          return partial();
        }
        if (!pageCounted) {
          processedPages += 1;
          pageCounted = true;
          if (processedPages > INTAKE_ARC1_RECOVERY_MAX_LIST_PAGES) return partial();
        }
        if (wallNow(adapters) >= deadlineMs) return partial();
        const advance = () => {
          sequenceSha256 = nextSequenceSha256;
          cursor = { shard, position, sequence_hmac_sha256: sequenceSha256 };
        };
        const submissionId = key.match(/^submissions\/([0-9a-f-]{36})$/)?.[1];
        if (!submissionId) {
          advance();
          continue;
        }
        if (scanned >= INTAKE_ARC1_RECOVERY_MAX_RECORD_READS || attempted >= INTAKE_ARC1_RECOVERY_MAX_ATTEMPTS ||
            wallNow(adapters) >= deadlineMs) return partial();
        scanned += 1;
        let entry;
        try { entry = await readRecord(store, key); } catch {
          invalid += 1;
          const detectedAt = new Date((adapters.clock || (() => new Date()))()).toISOString();
          const sourceKeyHmac = createHmac('sha256', recoveryCursorSecret(env))
            .update(`arc-intake-dispatch-quarantine-v1\n${key}`).digest('hex');
          await store.setJSON(`arc1-dispatch-quarantine/${sourceKeyHmac}`, {
            schema: 'arc-intake-dispatch-quarantine-v1', source_key_hmac_sha256: sourceKeyHmac,
            code: 'INVALID_SUBMISSION_RECORD', detected_at: detectedAt,
          }, { onlyIfNew: true });
          advance();
          continue;
        }
        if (!entry || ['ACKED', 'DEAD_LETTER'].includes(entry.record.arc1_delivery.status) ||
            entry.record.arc1_dispatch.status === 'DEAD_LETTER') { advance(); continue; }
        if (!['PENDING', 'ACCEPTED'].includes(entry.record.arc1_dispatch.status)) { advance(); continue; }
        if (entry.record.arc1_delivery.status === 'PENDING' && Date.parse(entry.record.arc1_delivery.next_attempt_at) > nowMs) {
          advance(); continue;
        }
        if (entry.record.arc1_delivery.status === 'CLAIMED' && Date.parse(entry.record.arc1_delivery.lease_expires_at) > nowMs) {
          advance(); continue;
        }
        attempted += 1;
        const dispatchResult = await dispatchIntakeToArc1Background(submissionId, request, env, {
          ...adapters, force: true, deadlineMs,
        });
        // A deadline reached before fetch entry made no durable delivery
        // attempt. Preserve the current sequence checkpoint so the exact item
        // is retried first rather than skipped until a future full audit cycle.
        if (dispatchResult.state === 'DISPATCH_DEFERRED') return partial();
        advance();
        if (wallNow(adapters) >= deadlineMs) return partial();
      }
    }
    if (!checkpointVerified) {
      cursor = initialCursor(shard);
      return partial();
    }
    emptyShards = shardBlobCount === 0 ? emptyShards + 1 : 0;
    if (shard + 1 < RECOVERY_SHARD_COUNT) cursor = initialCursor(shard + 1);
    // UUID v4 submission IDs are uniformly random. A bounded empty-shard gap
    // prevents one invocation from listing all 256 prefixes while retaining
    // the signed continuation for the next call.
    if (shard + 1 < RECOVERY_SHARD_COUNT && emptyShards >= 64) return partial();
    if (shard + 1 < RECOVERY_SHARD_COUNT && wallNow(adapters) >= deadlineMs) {
      return partial();
    }
  }
  return { state: 'RECOVERY_COMPLETE', scanned, attempted, invalid, next_cursor: null };
}

export function authorizeBackgroundDispatch(request, env) {
  try {
    const supplied = request.headers.get('authorization');
    return supplied?.startsWith('Bearer ') === true && safeEqual(supplied.slice(7), secret(env.ARC_INTAKE_ARC1_DISPATCH_SECRET, 'dispatch secret'));
  } catch { return false; }
}
