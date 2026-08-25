import assert from 'node:assert/strict';
import {
  aggregateAnalytics,
  eventKey,
  expirationTimestamp,
  expirationTimestampFromMetadata,
  isExpiredMetadata,
  normalizeAnalyticsEvent,
  RETENTION_DAYS,
} from '../netlify/lib/analytics-core.mjs';
import analyticsEventHandler, { config as eventConfig } from '../netlify/functions/analytics-event.mjs';
import analyticsDashboardHandler, { config as dashboardConfig } from '../netlify/functions/analytics-dashboard.mjs';
import {
  ANALYTICS_PRUNE_RESULT_SCHEMA,
  createAnalyticsPruneHandler,
  config as pruneConfig,
} from '../netlify/functions/analytics-prune.mjs';

const now = new Date('2026-08-11T20:00:00.000Z');
const base = {
  event: 'arc_page_view',
  event_id: '11111111-1111-4111-8111-111111111111',
  session_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  path: '/',
};
const normalized = normalizeAnalyticsEvent(base, now);
assert.equal(normalized.received_at, now.toISOString());
assert.equal(eventKey(normalized), `events/${base.event_id}`);
assert.equal(expirationTimestamp(normalized.received_at), now.getTime() + RETENTION_DAYS * 86400000);
assert.equal(expirationTimestampFromMetadata({ expires_at: now.getTime() }), now.getTime());
assert.equal(isExpiredMetadata({ expires_at: now.getTime() }, now), true);
assert.equal(isExpiredMetadata({ expires_at: now.getTime() + 1 }, now), false);
for (const metadata of [null, {}, { expires_at: null }, { expires_at: '' }, { expires_at: '123' },
  { expires_at: Number.NaN }, { expires_at: 0 }, { expires_at: -1 }, { expires_at: Number.MAX_SAFE_INTEGER + 1 }]) {
  assert.equal(expirationTimestampFromMetadata(metadata), null, 'Malformed expiry metadata must not coerce to the epoch.');
  assert.equal(isExpiredMetadata(metadata, now), false, 'Malformed expiry metadata must not authorize deletion.');
}

assert.throws(() => normalizeAnalyticsEvent({ ...base, email: 'person@example.com' }, now), /Unexpected analytics field/);
assert.throws(() => normalizeAnalyticsEvent({ ...base, event: 'anything_else' }, now), /Unknown analytics event/);
assert.throws(() => normalizeAnalyticsEvent({ ...base, event_id: 'not-a-uuid' }, now), /event_id must be a UUID/);
assert.throws(() => normalizeAnalyticsEvent({ ...base, event: 'arc_cta_click', cta: '<script>alert(1)</script>' }, now), /allowlisted label/);
assert.throws(() => normalizeAnalyticsEvent({ ...base, event: 'arc_form_step', step: 2, step_name: 'John Smith' }, now), /exact allowlisted step label/);
assert.throws(() => normalizeAnalyticsEvent({ ...base, event: 'arc_preview_request' }, now), /allowlisted page/);

const events = [
  normalized,
  normalizeAnalyticsEvent({ ...base, event: 'arc_cta_click', event_id: '22222222-2222-4222-8222-222222222222', cta: 'Get Free Preview' }, now),
  normalizeAnalyticsEvent({ ...base, event: 'arc_form_step', event_id: '33333333-3333-4333-8333-333333333333', step: 2, step_name: 'Offer' }, now),
  normalizeAnalyticsEvent({ ...base, event: 'arc_form_step', event_id: '44444444-4444-4444-8444-444444444444', step: 2, step_name: 'Offer' }, now),
  normalizeAnalyticsEvent({ ...base, event: 'arc_preview_request', event_id: '55555555-5555-4555-8555-555555555555', path: '/thank-you/' }, now),
  normalizeAnalyticsEvent({ ...base, event: 'arc_preview_request', event_id: '66666666-6666-4666-8666-666666666666', session_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', path: '/thank-you/' }, now),
];
const aggregate = aggregateAnalytics(events, now);
assert.equal(aggregate[7].counts.arc_page_view, 1);
assert.equal(aggregate[7].counts.arc_form_step, 1, 'Repeated steps from one session count once.');
assert.equal(aggregate[7].counts.arc_preview_request, 2);
assert.equal(aggregate[7].conversion_rate, 100, 'Request-only sessions must not inflate the viewed-session funnel.');

assert.equal(eventConfig.path, '/api/analytics/event');
assert.deepEqual(eventConfig.rateLimit.aggregateBy, ['ip', 'domain']);
assert.equal(dashboardConfig.path, '/internal/analytics');
const savedCollectionEnabled = process.env.ARC_ANALYTICS_COLLECTION_ENABLED;
delete process.env.ARC_ANALYTICS_COLLECTION_ENABLED;
assert.equal((await analyticsEventHandler(new Request('https://arcweb.onl/api/analytics/event', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(base),
}))).status, 503, 'Analytics collection must be an exact default-off no-op.');
process.env.ARC_ANALYTICS_COLLECTION_ENABLED = 'true';
const wrongHost = await analyticsEventHandler(new Request('https://example.com/api/analytics/event', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(base),
}));
assert.equal(wrongHost.status, 403);
const wrongType = await analyticsEventHandler(new Request('https://arcweb.onl/api/analytics/event', {
  method: 'POST', headers: { 'content-type': 'text/plain' }, body: JSON.stringify(base),
}));
assert.equal(wrongType.status, 415);
const badPayload = await analyticsEventHandler(new Request('https://arcweb.onl/api/analytics/event', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...base, email: 'person@example.com' }),
}));
assert.equal(badPayload.status, 400);
let oversizedCancelled = false;
const oversizedStream = new ReadableStream({
  start(controller) {
    controller.enqueue(new Uint8Array(2048));
    controller.enqueue(new Uint8Array(1));
  },
  cancel() { oversizedCancelled = true; },
});
const oversizedChunked = await analyticsEventHandler(new Request('https://arcweb.onl/api/analytics/event', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: oversizedStream, duplex: 'half',
}));
assert.equal(oversizedChunked.status, 413, 'A headerless/chunked body must be capped while streaming.');
assert.equal(oversizedCancelled, true, 'The oversized analytics stream must be cancelled immediately.');
if (savedCollectionEnabled === undefined) delete process.env.ARC_ANALYTICS_COLLECTION_ENABLED;
else process.env.ARC_ANALYTICS_COLLECTION_ENABLED = savedCollectionEnabled;

const savedUser = process.env.ARC_ANALYTICS_DASHBOARD_USER;
const savedPassword = process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD;
delete process.env.ARC_ANALYTICS_DASHBOARD_USER;
delete process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD;
try {
  const unconfiguredDashboard = await analyticsDashboardHandler(new Request('https://arcweb.onl/internal/analytics'));
  assert.equal(unconfiguredDashboard.status, 503);
} finally {
  if (savedUser === undefined) delete process.env.ARC_ANALYTICS_DASHBOARD_USER;
  else process.env.ARC_ANALYTICS_DASHBOARD_USER = savedUser;
  if (savedPassword === undefined) delete process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD;
  else process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD = savedPassword;
}

class FakeAnalyticsPruneStore {
  constructor(entries = [], pageSize = 1) {
    this.entries = new Map(entries.map(({ event, metadata }) => [eventKey(event), {
      event: structuredClone(event), metadata: structuredClone(metadata),
    }]));
    this.pageSize = pageSize;
    this.listCalls = 0;
    this.deleteCalls = [];
  }
  list({ prefix, paginate }) {
    assert.equal(paginate, true);
    this.listCalls += 1;
    const keys = [...this.entries.keys()].filter((key) => key.startsWith(prefix)).sort();
    const pageSize = this.pageSize;
    return {
      async *[Symbol.asyncIterator]() {
        for (let index = 0; index < keys.length; index += pageSize) {
          yield { blobs: keys.slice(index, index + pageSize).map((key) => ({ key, etag: `etag-${key}` })), directories: [] };
        }
      },
    };
  }
  async getMetadata(key) {
    const entry = this.entries.get(key);
    return entry ? { metadata: structuredClone(entry.metadata) } : null;
  }
  async get(key) {
    return structuredClone(this.entries.get(key)?.event || null);
  }
  async delete(key) {
    this.deleteCalls.push(key);
    this.entries.delete(key);
  }
}

const pruneSecret = 'analytics-prune-secret-0123456789-unique';
const pruneEnv = {
  ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED: 'true',
  ARC_ANALYTICS_PRUNE_SECRET: pruneSecret,
};
const pruneRequest = (url = 'https://arcweb.onl/internal/analytics/prune', method = 'POST', authorized = true) =>
  new Request(url, { method, headers: authorized ? { Authorization: `Bearer ${pruneSecret}` } : {} });
const untouchedStore = new FakeAnalyticsPruneStore();
const disabledPrune = createAnalyticsPruneHandler({ env: {}, store: untouchedStore, clock: () => now });
assert.equal((await disabledPrune(pruneRequest())).status, 503, 'Analytics pruning must remain exact default-off.');
assert.equal(untouchedStore.listCalls, 0, 'A disabled prune request must not touch provider state.');
assert.deepEqual(untouchedStore.deleteCalls, []);

const missingConfigPrune = createAnalyticsPruneHandler({
  env: { ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED: 'true' }, store: untouchedStore, clock: () => now,
});
assert.equal((await missingConfigPrune(pruneRequest())).status, 503, 'Enabled pruning without a dedicated secret must fail closed.');
const guardedPrune = createAnalyticsPruneHandler({ env: pruneEnv, store: untouchedStore, clock: () => now });
assert.equal((await guardedPrune(pruneRequest(undefined, 'GET'))).status, 405);
assert.equal((await guardedPrune(pruneRequest(undefined, 'POST', false))).status, 401);
assert.equal(untouchedStore.listCalls, 0, 'Rejected prune requests must not list provider state.');
assert.deepEqual(untouchedStore.deleteCalls, []);

const oldTime = new Date('2026-01-01T00:00:00.000Z');
const recentTime = new Date('2026-08-11T19:00:00.000Z');
const fallbackExpiredOne = normalizeAnalyticsEvent({
  ...base, event_id: '00111111-1111-4111-8111-111111111111',
}, oldTime);
const fallbackRetained = normalizeAnalyticsEvent({
  ...base, event_id: '00222222-2222-4222-8222-222222222222',
}, recentTime);
const fallbackExpiredTwo = normalizeAnalyticsEvent({
  ...base, event_id: '00333333-3333-4333-8333-333333333333',
}, oldTime);
const pruneStore = new FakeAnalyticsPruneStore([
  { event: fallbackExpiredOne, metadata: { expires_at: null } },
  { event: fallbackRetained, metadata: { expires_at: '' } },
  { event: fallbackExpiredTwo, metadata: { expires_at: 'not-a-number' } },
], 1);
const boundedPrune = createAnalyticsPruneHandler({
  env: pruneEnv,
  store: pruneStore,
  clock: () => now,
  limits: { maxRecords: 2, maxPages: 2, maxShards: 2 },
});
const firstPruneResponse = await boundedPrune(pruneRequest());
assert.equal(firstPruneResponse.status, 200);
assert.equal(firstPruneResponse.headers.get('cache-control'), 'no-store');
const firstPrune = await firstPruneResponse.json();
assert.deepEqual({
  schema: firstPrune.schema,
  state: firstPrune.state,
  scanned: firstPrune.scanned,
  deleted: firstPrune.deleted,
  retained: firstPrune.retained,
  metadata_fallbacks: firstPrune.metadata_fallbacks,
  invalid_records: firstPrune.invalid_records,
  pages_scanned: firstPrune.pages_scanned,
}, {
  schema: ANALYTICS_PRUNE_RESULT_SCHEMA,
  state: 'PRUNE_PARTIAL',
  scanned: 2,
  deleted: 1,
  retained: 1,
  metadata_fallbacks: 2,
  invalid_records: 0,
  pages_scanned: 2,
});
assert.equal(typeof firstPrune.next_cursor, 'string');
assert.ok(firstPrune.next_cursor.length > 64);
assert.equal(pruneStore.entries.has(eventKey(fallbackExpiredOne)), false,
  'Null expiry metadata must fall back to the expired record timestamp.');
assert.equal(pruneStore.entries.has(eventKey(fallbackRetained)), true,
  'Blank expiry metadata must fall back to and retain a fresh record.');

const resumedUrl = `https://arcweb.onl/internal/analytics/prune?cursor=${encodeURIComponent(firstPrune.next_cursor)}`;
const resumedResponse = await boundedPrune(pruneRequest(resumedUrl));
assert.equal(resumedResponse.status, 200);
const resumed = await resumedResponse.json();
assert.equal(resumed.state, 'PRUNE_PARTIAL');
assert.equal(resumed.scanned, 1);
assert.equal(resumed.deleted, 1);
assert.equal(resumed.metadata_fallbacks, 1);
assert.equal(pruneStore.entries.has(eventKey(fallbackExpiredTwo)), false,
  'A signed partial cursor must resume after the prior key without skipping the next expired record.');
assert.equal(pruneStore.entries.has(eventKey(fallbackRetained)), true);
assert.ok(resumed.pages_scanned <= 2 && resumed.scanned <= 2, 'Each resumed prune call must stay within its configured bounds.');

const corruptStoredEvent = { ...fallbackExpiredOne, event_id: '00444444-4444-4444-8444-444444444444', path: '/wrong/' };
const corruptStore = new FakeAnalyticsPruneStore([{ event: corruptStoredEvent, metadata: { expires_at: null } }], 1);
const corruptPrune = createAnalyticsPruneHandler({
  env: pruneEnv, store: corruptStore, clock: () => now,
  limits: { maxRecords: 1, maxPages: 1, maxShards: 1 },
});
const corruptResponse = await corruptPrune(pruneRequest());
assert.equal(corruptResponse.status, 200);
const corruptReceipt = await corruptResponse.json();
assert.equal(corruptReceipt.invalid_records, 1);
assert.equal(corruptReceipt.deleted, 0, 'Malformed fallback records must be retained for review, never deleted.');
assert.equal(corruptStore.entries.has(eventKey(corruptStoredEvent)), true);

const tamperedCursor = `${firstPrune.next_cursor.slice(0, -1)}${firstPrune.next_cursor.endsWith('a') ? 'b' : 'a'}`;
const tamperedResponse = await boundedPrune(pruneRequest(
  `https://arcweb.onl/internal/analytics/prune?cursor=${encodeURIComponent(tamperedCursor)}`,
));
assert.equal(tamperedResponse.status, 400, 'A changed prune cursor must fail authentication before provider access.');
assert.equal(pruneConfig.path, '/internal/analytics/prune');
assert.equal(pruneConfig.method, 'POST');
assert.deepEqual(pruneConfig.rateLimit.aggregateBy, ['ip', 'domain']);
assert.equal(Object.hasOwn(pruneConfig, 'schedule'), false, 'Analytics pruning must remain unscheduled while automation is off.');

console.log('ARC analytics contract passed.');
