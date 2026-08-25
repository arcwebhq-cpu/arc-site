import { createHmac, timingSafeEqual } from 'node:crypto';
import { getStore } from '@netlify/blobs';
import {
  ANALYTICS_SCHEMA,
  ANALYTICS_STORE,
  eventKey,
  expirationTimestamp,
  expirationTimestampFromMetadata,
  isExpiredMetadata,
  normalizeAnalyticsEvent,
} from '../lib/analytics-core.mjs';

export const ANALYTICS_PRUNE_SECRET_ENV = 'ARC_ANALYTICS_PRUNE_SECRET';
export const ANALYTICS_PRUNE_RESULT_SCHEMA = 'arc-analytics-prune-result-v1';
const CURSOR_SCHEMA = 'arc-analytics-prune-cursor-v1';
const CURSOR_SIGNATURE_PREFIX = 'arc-analytics-prune-cursor-signature-v1\n';
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
  const duplicated = Object.entries(env).some(([name, value]) => name !== ANALYTICS_PRUNE_SECRET_ENV &&
    /(?:SECRET|TOKEN|PAT|PASSWORD)$/.test(name) && typeof value === 'string' && value.length > 0 && value === secret);
  return duplicated ? null : secret;
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
  const keys = [];
  let shard = start.shard;
  let afterKey = start.afterKey;
  let pages = 0;
  let shards = 0;

  while (shard < SHARD_COUNT && pages < limits.maxPages && shards < limits.maxShards && keys.length < limits.maxRecords) {
    const prefix = shardPrefix(shard);
    const iterable = store.list({ prefix, paginate: true });
    if (!iterable || typeof iterable[Symbol.asyncIterator] !== 'function') throw new Error('Analytics prune list is unavailable.');
    const iterator = iterable[Symbol.asyncIterator]();
    let shardComplete = false;
    let previousKey = null;
    shards += 1;

    while (pages < limits.maxPages && keys.length < limits.maxRecords) {
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
            (previousKey !== null && key <= previousKey)) {
          throw new Error('Analytics prune event index is invalid or unordered.');
        }
        previousKey = key;
        if (afterKey !== null && key <= afterKey) continue;
        keys.push(key);
        afterKey = key;
        if (keys.length >= limits.maxRecords) break;
      }
    }

    if (!shardComplete) return { keys, pages, shards, complete: false, cursor: { shard, afterKey } };
    shard += 1;
    afterKey = null;
  }

  return {
    keys,
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

async function decideDeletions(store, keys, now) {
  const decisions = [];
  let metadataFallbacks = 0;
  let invalidRecords = 0;
  for (const key of keys) {
    const metadataResult = await store.getMetadata(key, { consistency: 'strong' });
    const metadata = metadataResult?.metadata;
    let expiry = expirationTimestampFromMetadata(metadata);
    let shouldDelete = expiry !== null && isExpiredMetadata(metadata, now);
    if (expiry === null) {
      metadataFallbacks += 1;
      const event = await store.get(key, { consistency: 'strong', type: 'json' });
      expiry = storedEventExpiration(event, key);
      if (expiry === null) invalidRecords += 1;
      shouldDelete = expiry !== null && expiry <= now.getTime();
    }
    decisions.push({ key, shouldDelete });
  }
  return { decisions, metadataFallbacks, invalidRecords };
}

export function createAnalyticsPruneHandler(options = {}) {
  const env = options.env || process.env;
  const limits = exactLimits(options.limits);
  const clock = options.clock || (() => new Date());
  return async (request) => {
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

    try {
      const now = new Date(clock());
      if (!Number.isFinite(now.getTime())) throw new TypeError('Analytics prune clock is invalid.');
      const store = options.store || getStore({ name: ANALYTICS_STORE, consistency: 'strong' });
      const collected = await collectBoundedKeys(store, cursor, limits);
      const evaluated = await decideDeletions(store, collected.keys, now);
      let deleted = 0;
      for (const decision of evaluated.decisions) {
        if (!decision.shouldDelete) continue;
        await store.delete(decision.key);
        deleted += 1;
      }
      const nextCursor = collected.complete ? null : encodeCursor(collected.cursor, secret);
      return response(200, {
        schema: ANALYTICS_PRUNE_RESULT_SCHEMA,
        state: collected.complete ? 'PRUNE_COMPLETE' : 'PRUNE_PARTIAL',
        observed_at: now.toISOString(),
        scanned: collected.keys.length,
        deleted,
        retained: collected.keys.length - deleted,
        metadata_fallbacks: evaluated.metadataFallbacks,
        invalid_records: evaluated.invalidRecords,
        pages_scanned: collected.pages,
        shards_scanned: collected.shards,
        next_cursor: nextCursor,
      });
    } catch {
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
