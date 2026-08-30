import { createHmac, timingSafeEqual } from 'node:crypto';
import { getStore } from '@netlify/blobs';
import {
  canonicalJson,
  hmacHex,
  safeEqual,
  sha256Hex,
} from '../lib/arc2-handoff-core.mjs';
import {
  ANALYTICS_SCHEMA,
  ANALYTICS_STORE,
  eventKey,
  expirationTimestamp,
  expirationTimestampFromMetadata,
  normalizeAnalyticsEvent,
} from '../lib/analytics-core.mjs';
import { RETENTION_CONTROL_STORE } from '../lib/retention-control-core.mjs';
import {
  assertRetentionGenerationFenceAuthority,
  beginRetentionFreeze,
  completeRetentionFreeze,
  ensureRetentionGenerationFence,
  raiseRetentionGenerationFenceCriticalAlert,
  readRetentionGenerationFence,
  recordRetentionMissingSourceAnomaly,
  renewRetentionGenerationFenceAuthority,
  retentionFreezeOperationHmac,
  retentionGenerationFenceConfiguration,
} from '../lib/retention-generation-fence-core.mjs';
import { enqueueRetentionGenerationFenceCriticalAlert } from
  '../lib/retention-generation-fence-alert-queue-core.mjs';
import { sensitiveCredentialsAreIsolated } from '../lib/sensitive-credential-isolation.mjs';

export const ANALYTICS_PRUNE_SECRET_ENV = 'ARC_ANALYTICS_PRUNE_SECRET';
export const ANALYTICS_PRUNE_RESULT_SCHEMA = 'arc-analytics-prune-result-v1';
export const ANALYTICS_RETENTION_TOMBSTONE_SCHEMA = 'arc-analytics-retention-tombstone-v1';
export const ANALYTICS_RETENTION_MANIFEST_SCHEMA = 'arc-analytics-retention-manifest-v1';
const CURSOR_SCHEMA = 'arc-analytics-prune-cursor-v1';
const CURSOR_SIGNATURE_PREFIX = 'arc-analytics-prune-cursor-signature-v1\n';
const TOMBSTONE_SIGNATURE_PREFIX = 'arc-analytics-retention-tombstone-signature-v1\n';
const MANIFEST_SIGNATURE_PREFIX = 'arc-analytics-retention-manifest-signature-v1\n';
const MANIFEST_PREFIX = 'analytics-retention/manifests/';
const FENCE_SECRET_ENV = 'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET';
const TOMBSTONE_FIELDS = Object.freeze([
  'customer_data_stored', 'event_key_hmac_sha256', 'record_hmac_sha256', 'schema',
  'source_record_sha256', 'tombstoned_at', 'version',
]);
const MANIFEST_FIELDS = Object.freeze([
  'action', 'built_at', 'customer_data_stored', 'generation', 'input_cursor_sha256',
  'invalid_records', 'metadata_fallbacks', 'next_cursor', 'output_record',
  'output_record_sha256', 'pages_scanned', 'record_hmac_sha256', 'retained', 'scanned',
  'schema', 'shards_scanned', 'source_etag', 'source_key', 'source_record_sha256',
  'subject_hmac_sha256', 'version',
]);
const EVENT_KEY_PATTERN = /^events\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHARD_COUNT = 256;
const SHARD_WIDTH = 2;
const DEFAULT_LIMITS = Object.freeze({ maxRecords: 100, maxPages: 32, maxShards: 32 });

function response(status, value) {
  return new Response(JSON.stringify(value), { status, headers: {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
  } });
}

function pruneSecret(env) {
  const secret = env?.[ANALYTICS_PRUNE_SECRET_ENV];
  if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 32 || Buffer.byteLength(secret, 'utf8') > 256) {
    return null;
  }
  return sensitiveCredentialsAreIsolated(env, [ANALYTICS_PRUNE_SECRET_ENV]) ? secret : null;
}

function authenticated(request, secret) {
  const header = request.headers.get('authorization') || '';
  if (!header.startsWith('Bearer ') || header.length > 512) return false;
  const supplied = Buffer.from(header.slice(7));
  const expected = Buffer.from(secret);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function exactLimits(input = {}) {
  const limits = { ...DEFAULT_LIMITS, ...input };
  for (const [name, maximum] of Object.entries(DEFAULT_LIMITS)) {
    if (!Number.isSafeInteger(limits[name]) || limits[name] < 1 || limits[name] > maximum) {
      throw new TypeError(`Analytics prune ${name} is invalid.`);
    }
  }
  return limits;
}

const shardPrefix = (shard) => `events/${shard.toString(16).padStart(SHARD_WIDTH, '0')}`;

function cursorSignature(encoded, secret) {
  return createHmac('sha256', secret).update(`${CURSOR_SIGNATURE_PREFIX}${encoded}`).digest('hex');
}

function encodeCursor(cursor, secret) {
  const raw = JSON.stringify({ schema: CURSOR_SCHEMA, shard: cursor.shard, after_key: cursor.afterKey });
  const encoded = Buffer.from(raw).toString('base64url');
  return `${encoded}.${cursorSignature(encoded, secret)}`;
}

function decodeCursor(request, secret) {
  const url = new URL(request.url);
  if ([...url.searchParams.keys()].some((name) => name !== 'cursor') || url.searchParams.getAll('cursor').length > 1) {
    throw new TypeError('Analytics prune cursor query is invalid.');
  }
  const token = url.searchParams.get('cursor');
  if (token === null) return { shard: 0, afterKey: null };
  const match = token.match(/^([A-Za-z0-9_-]{16,1024})\.([a-f0-9]{64})$/);
  if (!match) throw new TypeError('Analytics prune cursor is invalid.');
  const expected = Buffer.from(cursorSignature(match[1], secret));
  const supplied = Buffer.from(match[2]);
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new TypeError('Analytics prune cursor signature is invalid.');
  }
  let value;
  try { value = JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8')); } catch {
    throw new TypeError('Analytics prune cursor is invalid.');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['after_key', 'schema', 'shard']) ||
      value.schema !== CURSOR_SCHEMA || !Number.isSafeInteger(value.shard) || value.shard < 0 || value.shard >= SHARD_COUNT ||
      (value.after_key !== null && (typeof value.after_key !== 'string' || !EVENT_KEY_PATTERN.test(value.after_key) ||
        !value.after_key.startsWith(shardPrefix(value.shard))))) {
    throw new TypeError('Analytics prune cursor state is invalid.');
  }
  return { shard: value.shard, afterKey: value.after_key };
}

async function collectBoundedKeys(store, start, limits) {
  const entries = [];
  let shard = start.shard;
  let afterKey = start.afterKey;
  let pages = 0;
  let shards = 0;

  while (shard < SHARD_COUNT && pages < limits.maxPages && shards < limits.maxShards && entries.length < limits.maxRecords) {
    const prefix = shardPrefix(shard);
    const iterable = store.list({ prefix, paginate: true });
    if (!iterable || typeof iterable[Symbol.asyncIterator] !== 'function') throw new Error('Analytics prune list is unavailable.');
    const iterator = iterable[Symbol.asyncIterator]();
    let shardComplete = false;
    let previousKey = null;
    shards += 1;

    while (pages < limits.maxPages && entries.length < limits.maxRecords) {
      const page = await iterator.next();
      if (page.done) {
        shardComplete = true;
        break;
      }
      pages += 1;
      if (!page.value || !Array.isArray(page.value.blobs)) throw new Error('Analytics prune list page is invalid.');
      for (const item of page.value.blobs) {
        const key = item?.key;
        if (typeof key !== 'string' || !EVENT_KEY_PATTERN.test(key) || !key.startsWith(prefix) ||
            typeof item.etag !== 'string' || item.etag.length < 1 || item.etag.length > 512 ||
            (previousKey !== null && key <= previousKey)) {
          throw new Error('Analytics prune event index is invalid or unordered.');
        }
        previousKey = key;
        if (afterKey !== null && key <= afterKey) continue;
        entries.push(Object.freeze({ key, listed_etag: item.etag }));
        afterKey = key;
        if (entries.length >= limits.maxRecords) break;
      }
    }

    if (!shardComplete) return { entries, pages, shards, complete: false, cursor: { shard, afterKey } };
    shard += 1;
    afterKey = null;
  }

  return {
    entries,
    pages,
    shards,
    complete: shard >= SHARD_COUNT,
    cursor: shard < SHARD_COUNT ? { shard, afterKey } : null,
  };
}

function storedEventExpiration(event, key) {
  if (!event || typeof event !== 'object' || Array.isArray(event) || event.schema !== ANALYTICS_SCHEMA ||
      typeof event.event_id !== 'string' || eventKey(event) !== key) return null;
  try {
    const { schema, received_at: receivedAt, ...input } = event;
    const normalized = normalizeAnalyticsEvent(input, new Date(receivedAt));
    const normalizedKeys = Object.keys(normalized).sort();
    if (schema !== ANALYTICS_SCHEMA || JSON.stringify(Object.keys(event).sort()) !== JSON.stringify(normalizedKeys) ||
        normalizedKeys.some((field) => normalized[field] !== event[field])) return null;
    return expirationTimestamp(receivedAt);
  } catch { return null; }
}

function analyticsTombstone(key, source, now, secret) {
  const unsigned = {
    schema: ANALYTICS_RETENTION_TOMBSTONE_SCHEMA,
    version: 1,
    event_key_hmac_sha256: hmacHex(secret, `arc-analytics-retention-event-key-v1\n${key}`),
    source_record_sha256: sha256Hex(canonicalJson(source)),
    tombstoned_at: now.toISOString(),
    customer_data_stored: false,
  };
  return {
    ...unsigned,
    record_hmac_sha256: hmacHex(secret, `${TOMBSTONE_SIGNATURE_PREFIX}${canonicalJson(unsigned)}`),
  };
}

function validateAnalyticsTombstone(value, key, secret) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...TOMBSTONE_FIELDS].sort()) ||
      value.schema !== ANALYTICS_RETENTION_TOMBSTONE_SCHEMA || value.version !== 1 ||
      value.customer_data_stored !== false || !/^[a-f0-9]{64}$/.test(value.event_key_hmac_sha256) ||
      !/^[a-f0-9]{64}$/.test(value.source_record_sha256) ||
      !/^[a-f0-9]{64}$/.test(value.record_hmac_sha256) ||
      !Number.isFinite(Date.parse(value.tombstoned_at)) ||
      new Date(value.tombstoned_at).toISOString() !== value.tombstoned_at ||
      value.event_key_hmac_sha256 !== hmacHex(secret, `arc-analytics-retention-event-key-v1\n${key}`)) {
    throw new Error('ARC_ANALYTICS_RETENTION_TOMBSTONE_INVALID');
  }
  const { record_hmac_sha256: signature, ...unsigned } = value;
  const expected = hmacHex(secret, `${TOMBSTONE_SIGNATURE_PREFIX}${canonicalJson(unsigned)}`);
  if (!safeEqual(signature, expected)) throw new Error('ARC_ANALYTICS_RETENTION_TOMBSTONE_INVALID');
  return value;
}

function exactRecord(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}

function manifestSignature(unsigned, env) {
  return hmacHex(env[FENCE_SECRET_ENV],
    `${MANIFEST_SIGNATURE_PREFIX}${canonicalJson(unsigned)}`);
}

function signManifest(unsigned, env) {
  return Object.freeze({ ...unsigned, record_hmac_sha256: manifestSignature(unsigned, env) });
}

function validateAnalyticsRetentionManifest(value, env, secret) {
  if (!exactRecord(value, MANIFEST_FIELDS) ||
      value.schema !== ANALYTICS_RETENTION_MANIFEST_SCHEMA || value.version !== 1 ||
      !['MISSING', 'TOMBSTONE'].includes(value.action) ||
      !Number.isSafeInteger(value.generation) || value.generation < 0 ||
      typeof value.source_key !== 'string' || !EVENT_KEY_PATTERN.test(value.source_key) ||
      typeof value.source_etag !== 'string' || value.source_etag.length < 1 || value.source_etag.length > 512 ||
      !/^[a-f0-9]{64}$/.test(value.source_record_sha256) ||
      !/^[a-f0-9]{64}$/.test(value.output_record_sha256) ||
      !/^[a-f0-9]{64}$/.test(value.subject_hmac_sha256) ||
      !/^[a-f0-9]{64}$/.test(value.input_cursor_sha256) ||
      !/^[a-f0-9]{64}$/.test(value.record_hmac_sha256) ||
      value.customer_data_stored !== false ||
      !Number.isFinite(Date.parse(value.built_at)) ||
      new Date(value.built_at).toISOString() !== value.built_at ||
      (value.next_cursor !== null && (typeof value.next_cursor !== 'string' || value.next_cursor.length > 2048))) {
    throw new Error('ARC_ANALYTICS_RETENTION_MANIFEST_INVALID');
  }
  for (const field of ['invalid_records', 'metadata_fallbacks', 'pages_scanned', 'retained',
    'scanned', 'shards_scanned']) {
    if (!Number.isSafeInteger(value[field]) || value[field] < 0) {
      throw new Error('ARC_ANALYTICS_RETENTION_MANIFEST_INVALID');
    }
  }
  const { record_hmac_sha256: signature, ...unsigned } = value;
  if (!safeEqual(signature, manifestSignature(unsigned, env)) ||
      value.subject_hmac_sha256 !== hmacHex(env[FENCE_SECRET_ENV],
        `arc-analytics-retention-subject-v1\n${value.source_key}`)) {
    throw new Error('ARC_ANALYTICS_RETENTION_MANIFEST_INVALID');
  }
  if (value.action === 'TOMBSTONE') {
    validateAnalyticsTombstone(value.output_record, value.source_key, secret);
    if (value.output_record.source_record_sha256 !== value.source_record_sha256 ||
        sha256Hex(canonicalJson(value.output_record)) !== value.output_record_sha256 ||
        value.retained !== value.scanned - 1) {
      throw new Error('ARC_ANALYTICS_RETENTION_MANIFEST_INVALID');
    }
  } else if (value.output_record !== null ||
      value.output_record_sha256 !== sha256Hex(canonicalJson(null)) ||
      value.retained !== value.scanned - 1) {
    throw new Error('ARC_ANALYTICS_RETENTION_MANIFEST_INVALID');
  }
  return value;
}

function manifestDescriptor(manifest) {
  return Object.freeze({
    generation: manifest.generation,
    manifest_entry_count: 1,
    manifest_sha256: sha256Hex(canonicalJson(manifest)),
    subject_hmac_sha256: manifest.subject_hmac_sha256,
  });
}

async function persistAnalyticsRetentionManifest(store, manifest, env, secret) {
  validateAnalyticsRetentionManifest(manifest, env, secret);
  const descriptor = manifestDescriptor(manifest);
  const operation = retentionFreezeOperationHmac(descriptor, env);
  const key = `${MANIFEST_PREFIX}${operation}`;
  try { await store.setJSON(key, manifest, { onlyIfNew: true }); } catch {}
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!entry || canonicalJson(entry.data) !== canonicalJson(manifest)) {
    throw new Error('ARC_ANALYTICS_RETENTION_MANIFEST_CONFLICT');
  }
  validateAnalyticsRetentionManifest(entry.data, env, secret);
  return Object.freeze({ descriptor, manifest: entry.data, operation_hmac_sha256: operation });
}

async function readAnalyticsRetentionManifest(store, operation, env, secret) {
  if (typeof operation !== 'string' || !/^[a-f0-9]{64}$/.test(operation)) return null;
  const entry = await store.getWithMetadata(`${MANIFEST_PREFIX}${operation}`,
    { type: 'json', consistency: 'strong' });
  if (!entry) return null;
  const manifest = validateAnalyticsRetentionManifest(entry.data, env, secret);
  const descriptor = manifestDescriptor(manifest);
  if (retentionFreezeOperationHmac(descriptor, env) !== operation) {
    throw new Error('ARC_ANALYTICS_RETENTION_MANIFEST_BINDING_INVALID');
  }
  return Object.freeze({ descriptor, manifest, operation_hmac_sha256: operation });
}

const keyCursor = (key) => ({ shard: Number.parseInt(key.slice('events/'.length, 'events/'.length + 2), 16),
  afterKey: key });

async function buildAnalyticsRetentionPlan(store, collected, cursorToken, now, secret) {
  let candidate = null;
  let candidateIndex = -1;
  let invalidRecords = 0;
  let metadataFallbacks = 0;
  let scanned = 0;
  for (const listed of collected.entries) {
    scanned += 1;
    const entry = await store.getWithMetadata(listed.key, { consistency: 'strong', type: 'json' });
    if (!entry || typeof entry.etag !== 'string' || entry.etag.length < 1) {
      return Object.freeze({
        action: 'MISSING', collected, inputCursorSha256: sha256Hex(cursorToken),
        invalidRecords, metadataFallbacks, nextCursor: encodeCursor(keyCursor(listed.key), secret),
        retained: scanned - 1, scanned,
        source: Object.freeze({
          etag: listed.listed_etag,
          key: listed.key,
          recordSha256: sha256Hex(canonicalJson({
            listed_etag: listed.listed_etag, source_key: listed.key,
          })),
          value: null,
        }),
      });
    }
    if (entry.data?.schema === ANALYTICS_RETENTION_TOMBSTONE_SCHEMA) {
      validateAnalyticsTombstone(entry.data, listed.key, secret);
      continue;
    }
    const sourceExpiry = storedEventExpiration(entry.data, listed.key);
    const metadataExpiry = expirationTimestampFromMetadata(entry.metadata);
    if (sourceExpiry === null) {
      invalidRecords += 1;
      continue;
    }
    if (metadataExpiry === null) metadataFallbacks += 1;
    else if (metadataExpiry !== sourceExpiry) {
      invalidRecords += 1;
      continue;
    }
    if (candidate === null && sourceExpiry <= now.getTime()) {
      candidate = Object.freeze({ etag: entry.etag, key: listed.key,
        recordSha256: sha256Hex(canonicalJson(entry.data)), value: entry.data });
      candidateIndex = scanned - 1;
    }
  }
  if (candidate) {
    const complete = collected.complete && candidateIndex === collected.entries.length - 1;
    return Object.freeze({
      action: 'TOMBSTONE', collected, inputCursorSha256: sha256Hex(cursorToken),
      invalidRecords, metadataFallbacks,
      nextCursor: complete ? null : encodeCursor(keyCursor(candidate.key), secret),
      retained: scanned - 1, scanned, source: candidate,
    });
  }
  return Object.freeze({
    action: null, collected, inputCursorSha256: sha256Hex(cursorToken),
    invalidRecords, metadataFallbacks,
    nextCursor: collected.complete ? null : encodeCursor(collected.cursor, secret),
    retained: scanned, scanned, source: null,
  });
}

function buildAnalyticsRetentionManifest(plan, generation, now, env, secret) {
  if (!plan.action || !plan.source) return null;
  const output = plan.action === 'TOMBSTONE'
    ? analyticsTombstone(plan.source.key, plan.source.value, now, secret) : null;
  return signManifest({
    schema: ANALYTICS_RETENTION_MANIFEST_SCHEMA,
    version: 1,
    action: plan.action,
    generation,
    subject_hmac_sha256: hmacHex(env[FENCE_SECRET_ENV],
      `arc-analytics-retention-subject-v1\n${plan.source.key}`),
    source_key: plan.source.key,
    source_etag: plan.source.etag,
    source_record_sha256: plan.source.recordSha256,
    output_record: output,
    output_record_sha256: sha256Hex(canonicalJson(output)),
    input_cursor_sha256: plan.inputCursorSha256,
    next_cursor: plan.nextCursor,
    scanned: plan.scanned,
    retained: plan.retained,
    metadata_fallbacks: plan.metadataFallbacks,
    invalid_records: plan.invalidRecords,
    pages_scanned: plan.collected.pages,
    shards_scanned: plan.collected.shards,
    built_at: now.toISOString(),
    customer_data_stored: false,
  }, env);
}

function resultValue(value, idempotentReplay = false) {
  return {
    schema: ANALYTICS_PRUNE_RESULT_SCHEMA,
    state: value.next_cursor === null ? 'PRUNE_COMPLETE' : 'PRUNE_PARTIAL',
    observed_at: value.built_at,
    scanned: value.scanned,
    deleted: value.action === 'TOMBSTONE' ? 1 : 0,
    retained: value.retained,
    metadata_fallbacks: value.metadata_fallbacks,
    invalid_records: value.invalid_records,
    pages_scanned: value.pages_scanned,
    shards_scanned: value.shards_scanned,
    next_cursor: value.next_cursor,
    idempotent_replay: idempotentReplay,
  };
}

function noMutationResult(plan, now) {
  return resultValue({
    action: null, built_at: now.toISOString(), next_cursor: plan.nextCursor,
    scanned: plan.scanned, retained: plan.retained,
    metadata_fallbacks: plan.metadataFallbacks, invalid_records: plan.invalidRecords,
    pages_scanned: plan.collected.pages, shards_scanned: plan.collected.shards,
  });
}

function frozenAuthority(begun) {
  return Object.freeze({
    status: 'FROZEN', generation: begun.generation,
    operation_hmac_sha256: begun.operation_hmac_sha256,
    intent_sha256: begun.intent_sha256, authority_etag: begun.authority_etag,
  });
}

async function blockMissingAnalyticsSource(controlStore, pending, authority, env, adapters) {
  await assertRetentionGenerationFenceAuthority(controlStore, authority, env);
  await recordRetentionMissingSourceAnomaly(controlStore, pending.descriptor, {
    family: 'analytics',
    source_key_hmac_sha256: pending.manifest.subject_hmac_sha256,
    expected_source_record_sha256: pending.manifest.source_record_sha256,
  }, env, { authorityEtag: authority.authority_etag, clock: adapters.clock });
  await raiseRetentionGenerationFenceCriticalAlert(
    controlStore,
    authority,
    'RETENTION_MISSING_SOURCE_BLOCKED',
    env,
    { emitCriticalAlert: adapters.emitCriticalAlert },
  );
  throw new Error('ARC_ANALYTICS_RETENTION_MISSING_SOURCE_BLOCKED');
}

async function readFrozenAnalyticsOutput(store, manifest, secret) {
  const entry = await store.getWithMetadata(manifest.source_key,
    { type: 'json', consistency: 'strong' });
  if (!entry) return null;
  if (sha256Hex(canonicalJson(entry.data)) !== manifest.output_record_sha256) {
    throw new Error('ARC_ANALYTICS_RETENTION_OUTPUT_READBACK_INVALID');
  }
  validateAnalyticsTombstone(entry.data, manifest.source_key, secret);
  return sha256Hex(canonicalJson({
    output_record_sha256: manifest.output_record_sha256,
    subject_hmac_sha256: manifest.subject_hmac_sha256,
  }));
}

async function runFrozenAnalyticsManifest(stores, pending, env, secret, adapters) {
  const begun = await beginRetentionFreeze(stores.control, pending.descriptor, env, {
    clock: adapters.clock, staleAfterMs: adapters.staleAfterMs,
    emitCriticalAlert: adapters.emitCriticalAlert,
  });
  if (begun.retryable) return Object.freeze({ retryable: true });
  if (begun.state === 'COMPLETE') {
    return Object.freeze({ complete: true, idempotentReplay: true });
  }
  const authorityRef = { current: frozenAuthority(begun) };
  const heartbeat = async () => {
    authorityRef.current = await renewRetentionGenerationFenceAuthority(
      stores.control, authorityRef.current, env,
      { clock: adapters.clock, staleAfterMs: adapters.staleAfterMs },
    );
    return authorityRef.current;
  };
  if (adapters.afterFreeze) await adapters.afterFreeze(pending.manifest);
  await heartbeat();
  if (pending.manifest.action === 'MISSING') {
    await blockMissingAnalyticsSource(
      stores.control, pending, authorityRef.current, env, adapters,
    );
  }
  let current = await stores.analytics.getWithMetadata(pending.manifest.source_key,
    { type: 'json', consistency: 'strong' });
  if (!current) {
    await blockMissingAnalyticsSource(
      stores.control, pending, authorityRef.current, env, adapters,
    );
  }
  const currentDigest = sha256Hex(canonicalJson(current.data));
  let writeResult = null;
  if (currentDigest === pending.manifest.output_record_sha256) {
    validateAnalyticsTombstone(current.data, pending.manifest.source_key, secret);
  } else {
    if (currentDigest !== pending.manifest.source_record_sha256 ||
        current.etag !== pending.manifest.source_etag) {
      throw new Error('ARC_ANALYTICS_RETENTION_FROZEN_MANIFEST_DRIFT');
    }
    await heartbeat();
    await assertRetentionGenerationFenceAuthority(stores.control, authorityRef.current, env);
    writeResult = await stores.analytics.setJSON(
      pending.manifest.source_key,
      pending.manifest.output_record,
      { onlyIfMatch: pending.manifest.source_etag },
    );
    await assertRetentionGenerationFenceAuthority(stores.control, authorityRef.current, env);
    current = await stores.analytics.getWithMetadata(pending.manifest.source_key,
      { type: 'json', consistency: 'strong' });
    if (!current) {
      await blockMissingAnalyticsSource(
        stores.control, pending, authorityRef.current, env, adapters,
      );
    }
    if (sha256Hex(canonicalJson(current.data)) !== pending.manifest.output_record_sha256 ||
        writeResult?.modified !== true || typeof writeResult.etag !== 'string' ||
        current.etag !== writeResult.etag) {
      throw new Error('ARC_ANALYTICS_RETENTION_FROZEN_WRITE_CONTENTION');
    }
    validateAnalyticsTombstone(current.data, pending.manifest.source_key, secret);
    if (adapters.afterMutation) await adapters.afterMutation(pending.manifest);
  }
  await heartbeat();
  const outputReadback = await readFrozenAnalyticsOutput(
    stores.analytics, pending.manifest, secret,
  );
  if (!outputReadback) {
    await blockMissingAnalyticsSource(
      stores.control, pending, authorityRef.current, env, adapters,
    );
  }
  const evidence = {
    legal_hold_recheck_sha256: sha256Hex(canonicalJson({
      family: 'analytics', legal_hold_applicable: false,
      subject_hmac_sha256: pending.manifest.subject_hmac_sha256,
    })),
    output_readback_sha256: outputReadback,
    primary_tombstone_sha256: pending.manifest.output_record_sha256,
    tombstone_set_sha256: sha256Hex(canonicalJson([pending.manifest.output_record_sha256])),
  };
  const completed = await completeRetentionFreeze(
    stores.control, pending.descriptor, evidence, env, {
      authorityEtag: authorityRef.current.authority_etag,
      clock: adapters.clock,
      afterCompletionReceipt: adapters.afterCompletionReceipt,
      readback: async ({ authority }) => {
        if (authority) {
          authorityRef.current = authority;
          await heartbeat();
        } else {
          await assertRetentionGenerationFenceAuthority(
            stores.control, authorityRef.current, env,
          );
        }
        const digest = await readFrozenAnalyticsOutput(
          stores.analytics, pending.manifest, secret,
        );
        if (!digest) {
          await blockMissingAnalyticsSource(
            stores.control, pending, authorityRef.current, env, adapters,
          );
        }
        return authority
          ? { output_readback_sha256: digest,
            authority_etag: authorityRef.current.authority_etag }
          : digest;
      },
    },
  );
  if (completed.retryable) return Object.freeze({ retryable: true });
  return Object.freeze({ complete: true,
    idempotentReplay: completed.idempotent_replay === true });
}

export function createAnalyticsPruneHandler(options = {}) {
  const env = options.env || process.env;
  const limits = exactLimits(options.limits);
  const defaultClock = options.clock || (() => new Date());
  return async (request, context = {}) => {
    if (env.ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED !== 'true') {
      return response(503, { error: 'analytics_prune_disabled' });
    }
    if (request.method !== 'POST') return response(405, { error: 'method_not_allowed' });
    const secret = pruneSecret(env);
    if (!secret) return response(503, { error: 'analytics_prune_not_configured' });
    if (!authenticated(request, secret)) return response(401, { error: 'unauthorized' });

    let cursor;
    try { cursor = decodeCursor(request, secret); } catch (error) {
      if (error instanceof TypeError) return response(400, { error: 'invalid_cursor' });
      return response(503, { error: 'analytics_prune_unavailable' });
    }
    if (!retentionGenerationFenceConfiguration(env).ready) {
      return response(503, { error: 'analytics_prune_not_configured' });
    }

    try {
      const clock = context.clock || defaultClock;
      const now = new Date(clock());
      if (!Number.isFinite(now.getTime())) throw new TypeError('Analytics prune clock is invalid.');
      const stores = {
        analytics: options.store || context.analyticsStore ||
          getStore({ name: ANALYTICS_STORE, consistency: 'strong' }),
        control: options.controlStore || context.retentionStore ||
          getStore({ name: RETENTION_CONTROL_STORE, consistency: 'strong' }),
      };
      let alertStore;
      const emitCriticalAlert = options.emitCriticalAlert || context.emitCriticalAlert || ((alert) => {
        alertStore ||= options.alertStore || context.retentionFenceAlertStore || context.operationsAlertStore;
        return enqueueRetentionGenerationFenceCriticalAlert(alert, env,
          { clock, ...(alertStore ? { store: alertStore } : {}) });
      });
      const adapters = {
        clock,
        staleAfterMs: options.staleAfterMs ?? context.staleAfterMs,
        emitCriticalAlert,
        afterCompletionReceipt: options.afterCompletionReceipt || context.afterCompletionReceipt,
        afterFreeze: options.afterFreeze || context.afterFreeze,
        afterManifest: options.afterManifest || context.afterManifest,
        afterMutation: options.afterMutation || context.afterMutation,
      };
      const observed = await ensureRetentionGenerationFence(stores.control, env, { clock });
      if (observed.record.status === 'FROZEN') {
        const pending = await readAnalyticsRetentionManifest(
          stores.control, observed.record.operation_hmac_sha256, env, secret,
        );
        if (!pending) return response(409, { error: 'analytics_prune_contention' });
        if (pending.manifest.action === 'MISSING') {
          await blockMissingAnalyticsSource(stores.control, pending, {
            status: 'FROZEN', generation: observed.record.generation,
            operation_hmac_sha256: observed.record.operation_hmac_sha256,
            intent_sha256: observed.record.intent_sha256, authority_etag: observed.etag,
          }, env, adapters);
        }
        const resumed = await runFrozenAnalyticsManifest(stores, pending, env, secret, adapters);
        if (resumed.retryable) return response(409, { error: 'analytics_prune_contention' });
        return response(200, resultValue(pending.manifest, true));
      }
      if (observed.record.status !== 'OPEN') {
        return response(409, { error: 'analytics_prune_contention' });
      }
      const collected = await collectBoundedKeys(stores.analytics, cursor, limits);
      const cursorToken = new URL(request.url).searchParams.get('cursor') || '';
      const plan = await buildAnalyticsRetentionPlan(
        stores.analytics, collected, cursorToken, now, secret,
      );
      if (!plan.action) return response(200, noMutationResult(plan, now));
      const manifest = buildAnalyticsRetentionManifest(
        plan, observed.record.generation, now, env, secret,
      );
      const pending = await persistAnalyticsRetentionManifest(
        stores.control, manifest, env, secret,
      );
      if (adapters.afterManifest) await adapters.afterManifest(pending.manifest);
      const drift = await readRetentionGenerationFence(stores.control, env);
      if (!drift || drift.record.status !== 'OPEN' ||
          drift.record.generation !== observed.record.generation || drift.etag !== observed.etag) {
        return response(409, { error: 'analytics_prune_contention' });
      }
      const completed = await runFrozenAnalyticsManifest(stores, pending, env, secret, adapters);
      if (completed.retryable) return response(409, { error: 'analytics_prune_contention' });
      return response(200, resultValue(pending.manifest, completed.idempotentReplay));
    } catch (error) {
      const message = error?.message || '';
      if (/MISSING_SOURCE/.test(message)) {
        return response(503, { error: 'analytics_prune_missing_source' });
      }
      if (/CONTENTION|DRIFT|AUTHORITY_LOST|SOURCE_CHANGED/.test(message)) {
        return response(409, { error: 'analytics_prune_contention' });
      }
      return response(503, { error: 'analytics_prune_unavailable' });
    }
  };
}

export default createAnalyticsPruneHandler();

export const config = {
  path: '/internal/analytics/prune',
  method: 'POST',
  rateLimit: { windowLimit: 12, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
