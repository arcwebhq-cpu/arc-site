import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  ACTIVATION_EVIDENCE_BY_STAGE,
  ACTIVATION_MANIFEST_SCHEMA,
  ACTIVATION_MANIFEST_VERSION,
  signActivationManifest,
} from '../netlify/lib/activation-manifest-core.mjs';
import {
  aggregateAnalytics,
  ANALYTICS_SCHEMA,
  analyticsCollectionReady,
  eventKey,
  expirationTimestamp,
  expirationTimestampFromMetadata,
  isExpiredMetadata,
  normalizeAnalyticsEvent,
  RETENTION_DAYS,
} from '../netlify/lib/analytics-core.mjs';
import analyticsEventRoute, {
  config as eventConfig,
  createAnalyticsEventHandler,
} from '../netlify/functions/analytics-event.mjs';
import analyticsDashboardHandler, { config as dashboardConfig } from '../netlify/functions/analytics-dashboard.mjs';
import {
  ANALYTICS_PRUNE_RESULT_SCHEMA,
  ANALYTICS_RETENTION_MANIFEST_SCHEMA,
  ANALYTICS_RETENTION_TOMBSTONE_SCHEMA,
  createAnalyticsPruneHandler,
  config as pruneConfig,
} from '../netlify/functions/analytics-prune.mjs';
import {
  RETENTION_GENERATION_FENCE_STATE_KEY,
  beginRetentionFreeze,
  retentionGenerationFenceKeys,
  runRetentionProducerOperation,
  validateRetentionGenerationFenceAlert,
  validateRetentionGenerationFenceState,
  validateRetentionFinalizeReceipt,
  validateRetentionMissingSourceAnomaly,
  validateRetentionFreezeIntent,
} from '../netlify/lib/retention-generation-fence-core.mjs';

const now = new Date('2026-08-11T20:00:00.000Z');
const analyticsEventHandler = createAnalyticsEventHandler();
const activationNow = new Date();
const activationSecret = 'analytics-activation-manifest-secret-0123456789abcdef';
const activationDeploymentSha = '9'.repeat(40);
const activationManifest = (stage, overrides = {}) => signActivationManifest({
  schema: ACTIVATION_MANIFEST_SCHEMA,
  version: ACTIVATION_MANIFEST_VERSION,
  stage,
  authority_mode: 'ROLLOUT',
  issued_at: new Date(activationNow.getTime() - 60_000).toISOString(),
  expires_at: new Date(activationNow.getTime() + 60 * 60_000).toISOString(),
  deployment_sha: activationDeploymentSha,
  evidence: ACTIVATION_EVIDENCE_BY_STAGE[stage].map((kind) => ({
    kind,
    receipt_ref: `audit:${createHash('sha256').update(`receipt:${kind}`).digest('hex').slice(0, 24)}`,
    sha256: createHash('sha256').update(`evidence:${kind}`).digest('hex'),
  })),
  ...overrides,
}, activationSecret);
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
const analyticsAuthorityNames = [
  'ARC_ANALYTICS_COLLECTION_ENABLED',
  'ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED',
  'ARC_ACTIVATION_MANIFEST_HMAC_SECRET',
  'ARC_ACTIVATION_MANIFEST',
  'COMMIT_REF',
];
const savedAnalyticsAuthority = Object.fromEntries(analyticsAuthorityNames.map((name) => [name, process.env[name]]));
delete process.env.ARC_ANALYTICS_COLLECTION_ENABLED;
delete process.env.ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED;
delete process.env.ARC_ACTIVATION_MANIFEST_HMAC_SECRET;
delete process.env.ARC_ACTIVATION_MANIFEST;
delete process.env.COMMIT_REF;
assert.equal((await analyticsEventRoute(new Request('https://arcweb.onl/api/analytics/event', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(base),
}))).status, 503, 'Analytics collection must be an exact default-off no-op.');
process.env.ARC_ANALYTICS_COLLECTION_ENABLED = 'true';
assert.equal(analyticsCollectionReady(process.env, activationNow), false,
  'Collection cannot start before exact prune automation is enabled.');
assert.equal((await analyticsEventRoute(new Request('https://arcweb.onl/api/analytics/event', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(base),
}))).status, 503);
process.env.ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED = 'true';
assert.equal(analyticsCollectionReady(process.env, activationNow), false,
  'Mutable analytics flags cannot bypass a missing activation authority.');
process.env.ARC_ACTIVATION_MANIFEST_HMAC_SECRET = activationSecret;
process.env.COMMIT_REF = activationDeploymentSha;
process.env.ARC_ACTIVATION_MANIFEST = activationManifest('LIVE_CHECKOUT');
assert.equal(analyticsCollectionReady(process.env, activationNow), false,
  'Analytics cannot precede the PUBLIC_INTAKE stage.');
process.env.ARC_ACTIVATION_MANIFEST = activationManifest('PUBLIC_INTAKE');
assert.equal(analyticsCollectionReady(process.env, activationNow), true);
const wrongHost = await analyticsEventRoute(new Request('https://example.com/api/analytics/event', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(base),
}));
assert.equal(wrongHost.status, 403);
const wrongType = await analyticsEventRoute(new Request('https://arcweb.onl/api/analytics/event', {
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
for (const [name, value] of Object.entries(savedAnalyticsAuthority)) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

const savedUser = process.env.ARC_ANALYTICS_DASHBOARD_USER;
const savedPassword = process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD;
const savedRotatedCredential = process.env.ARC_ROTATED_CREDENTIAL_V2;
delete process.env.ARC_ANALYTICS_DASHBOARD_USER;
delete process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD;
delete process.env.ARC_ROTATED_CREDENTIAL_V2;
try {
  const unconfiguredDashboard = await analyticsDashboardHandler(new Request('https://arcweb.onl/internal/analytics'));
  assert.equal(unconfiguredDashboard.status, 503);
  process.env.ARC_ANALYTICS_DASHBOARD_USER = 'arc-analytics-operator';
  process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD = 'analytics-dashboard-password-unique-0123456789';
  for (const credentialName of [
    'ARC_ANALYTICS_DASHBOARD_USER',
    'ARC_ANALYTICS_DASHBOARD_PASSWORD',
  ]) {
    process.env.ARC_ROTATED_CREDENTIAL_V2 = process.env[credentialName];
    const aliasedDashboard = await analyticsDashboardHandler(new Request('https://arcweb.onl/internal/analytics', {
      headers: {
        authorization: `Basic ${Buffer.from(`${process.env.ARC_ANALYTICS_DASHBOARD_USER}:${
          process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD}`).toString('base64')}`,
      },
    }));
    assert.equal(aliasedDashboard.status, 503,
      `${credentialName} must reject an arbitrary configured alias before storage access.`);
  }
} finally {
  if (savedUser === undefined) delete process.env.ARC_ANALYTICS_DASHBOARD_USER;
  else process.env.ARC_ANALYTICS_DASHBOARD_USER = savedUser;
  if (savedPassword === undefined) delete process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD;
  else process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD = savedPassword;
  if (savedRotatedCredential === undefined) delete process.env.ARC_ROTATED_CREDENTIAL_V2;
  else process.env.ARC_ROTATED_CREDENTIAL_V2 = savedRotatedCredential;
}

class FakeAnalyticsPruneStore {
  constructor(entries = [], pageSize = 1) {
    this.sequence = 0;
    this.entries = new Map(entries.map(({ event, metadata }) => [eventKey(event), {
      event: structuredClone(event), metadata: structuredClone(metadata), etag: `e-${++this.sequence}`,
    }]));
    this.pageSize = pageSize;
    this.listCalls = 0;
    this.deleteCalls = [];
    this.mutateBeforeCas = null;
    this.corruptReadbackKey = null;
    this.missingAfterList = new Set();
    this.conditionalWrites = 0;
  }
  list({ prefix, paginate }) {
    assert.equal(paginate, true);
    this.listCalls += 1;
    const items = [...this.entries.entries()].filter(([key]) => key.startsWith(prefix))
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => ({ key, etag: entry.etag }));
    const pageSize = this.pageSize;
    return {
      async *[Symbol.asyncIterator]() {
        for (let index = 0; index < items.length; index += pageSize) {
          yield { blobs: items.slice(index, index + pageSize), directories: [] };
        }
      },
    };
  }
  async getWithMetadata(key) {
    if (this.missingAfterList.delete(key)) {
      this.entries.delete(key);
      return null;
    }
    const entry = this.entries.get(key);
    if (!entry) return null;
    return {
      data: structuredClone(entry.event),
      metadata: structuredClone(entry.metadata),
      etag: entry.etag,
    };
  }
  async setJSON(key, value, options = {}) {
    if (options.onlyIfMatch) this.conditionalWrites += 1;
    let current = this.entries.get(key);
    if (options.onlyIfMatch && this.mutateBeforeCas?.key === key && current) {
      current = { ...current, event: structuredClone(this.mutateBeforeCas.value), etag: `e-${++this.sequence}` };
      this.entries.set(key, current);
      this.mutateBeforeCas = null;
    }
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `e-${++this.sequence}`;
    const stored = structuredClone(value);
    if (this.corruptReadbackKey === key) {
      stored.record_hmac_sha256 = '0'.repeat(64);
      this.corruptReadbackKey = null;
    }
    this.entries.set(key, { event: stored, metadata: structuredClone(current?.metadata || {}), etag });
    return { modified: true, etag };
  }
  async delete(key) {
    this.deleteCalls.push(key);
    this.entries.delete(key);
  }
}

class FakeRetentionControlStore {
  constructor() { this.values = new Map(); this.sequence = 0; }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    if (options.onlyIfMatch && !current) return { modified: false };
    const etag = `c-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
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

const pruneSecret = 'analytics-prune-secret-0123456789-unique';
const pruneEnv = {
  ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED: 'true',
  ARC_ANALYTICS_PRUNE_SECRET: pruneSecret,
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'analytics-retention-fence-secret-unique-0123456789abcdef',
};
const testDigest = (value) => createHash('sha256').update(value).digest('hex');
const controlRecords = (store, prefix) => [...store.values.entries()]
  .filter(([key]) => key.startsWith(prefix));
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
const duplicatedConfigPrune = createAnalyticsPruneHandler({
  env: { ...pruneEnv, ARC_ANALYTICS_PRUNE_SECRET_V2: pruneSecret },
  store: untouchedStore,
  clock: () => now,
});
assert.equal((await duplicatedConfigPrune(pruneRequest())).status, 503,
  'A renamed analytics prune credential copy must fail closed.');
const guardedPrune = createAnalyticsPruneHandler({ env: pruneEnv, store: untouchedStore, clock: () => now });
assert.equal((await guardedPrune(pruneRequest(undefined, 'GET'))).status, 405);
assert.equal((await guardedPrune(pruneRequest(undefined, 'POST', false))).status, 401);
assert.equal(untouchedStore.listCalls, 0, 'Rejected prune requests must not list provider state.');
assert.deepEqual(untouchedStore.deleteCalls, []);

let rejectedProviderAccesses = 0;
const rejectedOptions = { env: pruneEnv, clock: () => now };
Object.defineProperties(rejectedOptions, {
  store: { get() { rejectedProviderAccesses += 1; return untouchedStore; } },
  controlStore: { get() { rejectedProviderAccesses += 1; return new FakeRetentionControlStore(); } },
});
const preflightOnlyPrune = createAnalyticsPruneHandler(rejectedOptions);
assert.equal((await preflightOnlyPrune(pruneRequest(undefined, 'GET'))).status, 405);
assert.equal((await preflightOnlyPrune(pruneRequest(undefined, 'POST', false))).status, 401);
assert.equal((await preflightOnlyPrune(pruneRequest(
  'https://arcweb.onl/internal/analytics/prune?cursor=invalid',
))).status, 400);
assert.equal(rejectedProviderAccesses, 0,
  'Method, authorization, and cursor validation must precede all gate/store access.');

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
const pruneControl = new FakeRetentionControlStore();
const boundedPrune = createAnalyticsPruneHandler({
  env: pruneEnv,
  store: pruneStore,
  controlStore: pruneControl,
  clock: () => now,
  limits: { maxRecords: 2, maxPages: 3, maxShards: 2 },
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
assert.equal(pruneStore.entries.get(eventKey(fallbackExpiredOne)).event.schema,
  ANALYTICS_RETENTION_TOMBSTONE_SCHEMA,
  'Null expiry metadata must fall back to an exact terminal tombstone.');
assert.equal(pruneStore.entries.get(eventKey(fallbackExpiredOne)).event.customer_data_stored, false);
assert.deepEqual(pruneStore.deleteCalls, [], 'Analytics pruning must never issue an unconditional delete.');
assert.equal(pruneStore.entries.has(eventKey(fallbackRetained)), true,
  'Blank expiry metadata must fall back to and retain a fresh record.');
const firstFence = validateRetentionGenerationFenceState(
  (await pruneControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, pruneEnv,
);
assert.equal(firstFence.status, 'OPEN');
assert.equal(firstFence.generation, 1);
const firstManifest = [...pruneControl.values.entries()].find(([key]) =>
  key.startsWith('analytics-retention/manifests/'))?.[1].data;
assert.equal(firstManifest.schema, ANALYTICS_RETENTION_MANIFEST_SCHEMA);
assert.equal(firstManifest.action, 'TOMBSTONE');
assert.equal(firstManifest.source_key, eventKey(fallbackExpiredOne));
const firstFreezeIntentEntry = [...pruneControl.values.entries()].find(([key]) =>
  key.startsWith('first-party-retention/generation-fence/freeze-intents/'))?.[1];
const firstFreezeIntent = validateRetentionFreezeIntent(firstFreezeIntentEntry.data, pruneEnv);
assert.equal(firstFreezeIntent.manifest_entry_count, 1,
  'Every analytics FROZEN manifest must bind exactly one event subject.');

const resumedUrl = `https://arcweb.onl/internal/analytics/prune?cursor=${encodeURIComponent(firstPrune.next_cursor)}`;
const resumedResponse = await boundedPrune(pruneRequest(resumedUrl));
assert.equal(resumedResponse.status, 200);
const resumed = await resumedResponse.json();
assert.equal(resumed.state, 'PRUNE_PARTIAL');
assert.equal(resumed.scanned, 2);
assert.equal(resumed.deleted, 1);
assert.equal(resumed.retained, 1);
assert.equal(resumed.metadata_fallbacks, 2);
assert.equal(pruneStore.entries.get(eventKey(fallbackExpiredTwo)).event.schema,
  ANALYTICS_RETENTION_TOMBSTONE_SCHEMA,
  'A signed partial cursor must resume after the prior key and write a terminal tombstone.');
assert.equal(pruneStore.entries.has(eventKey(fallbackRetained)), true);
assert.ok(resumed.pages_scanned <= 3 && resumed.scanned <= 2, 'Each resumed prune call must stay within its configured bounds.');
assert.equal(validateRetentionGenerationFenceState(
  (await pruneControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, pruneEnv,
).generation, 2, 'Each independently frozen event must consume exactly one generation.');

const paginatedFreshOne = normalizeAnalyticsEvent({
  ...base, event_id: '00777777-7777-4777-8777-777777777777',
}, recentTime);
const paginatedFreshTwo = normalizeAnalyticsEvent({
  ...base, event_id: '00888888-8888-4888-8888-888888888888',
}, recentTime);
const paginatedExpired = normalizeAnalyticsEvent({
  ...base, event_id: '00999999-9999-4999-8999-999999999999',
}, oldTime);
const paginatedStore = new FakeAnalyticsPruneStore([
  { event: paginatedFreshOne, metadata: { expires_at: expirationTimestamp(recentTime) } },
  { event: paginatedFreshTwo, metadata: { expires_at: expirationTimestamp(recentTime) } },
  { event: paginatedExpired, metadata: { expires_at: expirationTimestamp(oldTime) } },
], 1);
const paginatedControl = new FakeRetentionControlStore();
const paginatedPrune = createAnalyticsPruneHandler({
  env: pruneEnv, store: paginatedStore, controlStore: paginatedControl, clock: () => now,
  limits: { maxRecords: 3, maxPages: 3, maxShards: 1 },
});
const paginatedResponse = await paginatedPrune(pruneRequest());
assert.equal(paginatedResponse.status, 200);
const paginatedResult = await paginatedResponse.json();
assert.equal(paginatedResult.pages_scanned, 3,
  'The bounded manifest scan must consume every allowed page before freezing.');
assert.equal(paginatedResult.scanned, 3);
assert.equal(paginatedResult.retained, 2);
assert.equal(paginatedResult.deleted, 1);
assert.equal(paginatedStore.entries.get(eventKey(paginatedExpired)).event.schema,
  ANALYTICS_RETENTION_TOMBSTONE_SCHEMA);
assert.equal(controlRecords(paginatedControl, 'analytics-retention/manifests/').length, 1);
assert.equal(validateRetentionGenerationFenceState(
  (await paginatedControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, pruneEnv,
).generation, 1, 'A multi-page scan must still freeze exactly one event subject.');

const driftEvent = normalizeAnalyticsEvent({
  ...base, event_id: '00aaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
}, oldTime);
const driftStore = new FakeAnalyticsPruneStore([
  { event: driftEvent, metadata: { expires_at: expirationTimestamp(oldTime) } },
]);
const driftControl = new FakeRetentionControlStore();
let producerOutput = testDigest('analytics-drift-output-absent');
const expectedProducerOutput = testDigest('analytics-drift-output-present');
const driftProducer = {
  route: 'tests/analytics-generation-drift',
  subject_hmac_sha256: testDigest('analytics-drift-producer-subject'),
  idempotency_key_sha256: testDigest('analytics-drift-producer-idempotency'),
  source_record_sha256: testDigest('analytics-drift-producer-source'),
  mutation_sha256: testDigest('analytics-drift-producer-mutation'),
  output_record_sha256: expectedProducerOutput,
};
const driftAlerts = [];
const driftPrune = createAnalyticsPruneHandler({
  env: pruneEnv, store: driftStore, controlStore: driftControl, clock: () => now,
  limits: { maxRecords: 1, maxPages: 1, maxShards: 1 },
  emitCriticalAlert: async (alert) => { driftAlerts.push(alert); },
  afterManifest: async () => {
    const result = await runRetentionProducerOperation(driftControl, driftProducer, pruneEnv, {
      clock: () => now,
      readSource: async () => ({ source_record_sha256: driftProducer.source_record_sha256 }),
      readOutput: async () => ({ output_record_sha256: producerOutput }),
      mutate: async () => { producerOutput = expectedProducerOutput; },
    });
    assert.equal(result.retryable, false);
  },
});
assert.equal((await driftPrune(pruneRequest())).status, 409,
  'A producer generation change after manifest construction must restart retention.');
assert.equal(driftStore.entries.get(eventKey(driftEvent)).event.schema, ANALYTICS_SCHEMA);
assert.equal(validateRetentionGenerationFenceState(
  (await driftControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, pruneEnv,
).generation, 1);
assert.equal(driftAlerts.length, 0, 'Normal OPEN generation drift must not create a critical alert.');
assert.equal((await driftPrune(pruneRequest())).status, 200,
  'The exact retry must rebuild against the new OPEN generation.');
assert.equal(driftStore.entries.get(eventKey(driftEvent)).event.schema,
  ANALYTICS_RETENTION_TOMBSTONE_SCHEMA);
assert.equal(validateRetentionGenerationFenceState(
  (await driftControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, pruneEnv,
).generation, 2);

const contentionEvent = normalizeAnalyticsEvent({
  ...base, event_id: '00bbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
}, oldTime);
const contentionStore = new FakeAnalyticsPruneStore([
  { event: contentionEvent, metadata: { expires_at: expirationTimestamp(oldTime) } },
]);
const contentionControl = new FakeRetentionControlStore();
const unrelatedFreeze = await beginRetentionFreeze(contentionControl, {
  generation: 0,
  manifest_entry_count: 1,
  manifest_sha256: testDigest('unrelated-retention-manifest'),
  subject_hmac_sha256: testDigest('unrelated-retention-subject'),
}, pruneEnv, { clock: () => now });
assert.equal(unrelatedFreeze.state, 'FROZEN');
let contentionAlertCalls = 0;
const contentionPrune = createAnalyticsPruneHandler({
  env: pruneEnv, store: contentionStore, controlStore: contentionControl, clock: () => now,
  limits: { maxRecords: 1, maxPages: 1, maxShards: 1 },
  emitCriticalAlert: async () => { contentionAlertCalls += 1; },
});
assert.equal((await contentionPrune(pruneRequest())).status, 409,
  'An unrelated live FROZEN operation is ordinary retryable contention.');
assert.equal(contentionStore.listCalls, 0);
assert.equal(contentionAlertCalls, 0);
assert.equal(controlRecords(contentionControl,
  'first-party-retention/generation-fence/critical-alerts/').length, 0,
  'Normal lock contention must never create a permanent alert.');

const missingEvent = normalizeAnalyticsEvent({
  ...base, event_id: '00cccccc-cccc-4ccc-8ccc-cccccccccccc',
}, oldTime);
const missingStore = new FakeAnalyticsPruneStore([
  { event: missingEvent, metadata: { expires_at: expirationTimestamp(oldTime) } },
]);
missingStore.missingAfterList.add(eventKey(missingEvent));
const missingControl = new FakeRetentionControlStore();
const missingAlerts = [];
const missingPrune = createAnalyticsPruneHandler({
  env: pruneEnv, store: missingStore, controlStore: missingControl, clock: () => now,
  limits: { maxRecords: 1, maxPages: 1, maxShards: 1 },
  emitCriticalAlert: async (alert) => { missingAlerts.push(alert); },
});
const missingResponse = await missingPrune(pruneRequest());
assert.equal(missingResponse.status, 503);
assert.deepEqual(await missingResponse.json(), { error: 'analytics_prune_missing_source' });
const missingStateEntry = await missingControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY);
const missingState = validateRetentionGenerationFenceState(missingStateEntry.data, pruneEnv);
assert.equal(missingState.status, 'FROZEN', 'A missing listed source must never reopen FROZEN.');
const missingManifestEntry = controlRecords(missingControl, 'analytics-retention/manifests/')[0]?.[1];
assert.equal(missingManifestEntry.data.action, 'MISSING');
const missingIntentEntry = await missingControl.getWithMetadata(
  retentionGenerationFenceKeys.freezeIntent(missingState.operation_hmac_sha256),
);
const missingIntent = validateRetentionFreezeIntent(missingIntentEntry.data, pruneEnv);
const missingAnomalies = controlRecords(missingControl,
  retentionGenerationFenceKeys.missingSourcePrefix(missingState.operation_hmac_sha256));
assert.equal(missingAnomalies.length, 1);
validateRetentionMissingSourceAnomaly(missingAnomalies[0][1].data, missingIntent, pruneEnv);
const durableMissingAlerts = controlRecords(missingControl,
  'first-party-retention/generation-fence/critical-alerts/');
assert.equal(durableMissingAlerts.length, 1);
assert.equal(validateRetentionGenerationFenceAlert(durableMissingAlerts[0][1].data, pruneEnv).reason_code,
  'RETENTION_MISSING_SOURCE_BLOCKED');
assert.equal(missingAlerts.length, 1);
assert.equal((await missingPrune(pruneRequest())).status, 503,
  'An exact missing-source retry must remain blocked.');
assert.equal(missingAlerts.length, 2,
  'The critical alert queue adapter must run on every exact retry.');
assert.equal(controlRecords(missingControl,
  retentionGenerationFenceKeys.missingSourcePrefix(missingState.operation_hmac_sha256)).length, 1);
assert.equal(controlRecords(missingControl,
  'first-party-retention/generation-fence/critical-alerts/').length, 1,
  'Missing-source anomaly and alert records must remain immutable and deduplicated.');
assert.equal(validateRetentionGenerationFenceState(
  (await missingControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, pruneEnv,
).status, 'FROZEN');

const mutationCrashEvent = normalizeAnalyticsEvent({
  ...base, event_id: '00dddddd-dddd-4ddd-8ddd-dddddddddddd',
}, oldTime);
const mutationCrashStore = new FakeAnalyticsPruneStore([
  { event: mutationCrashEvent, metadata: { expires_at: expirationTimestamp(oldTime) } },
]);
const mutationCrashControl = new FakeRetentionControlStore();
let mutationCrashNow = new Date(now);
let crashAfterMutation = true;
const mutationCrashAlerts = [];
const mutationCrashPrune = createAnalyticsPruneHandler({
  env: pruneEnv, store: mutationCrashStore, controlStore: mutationCrashControl,
  clock: () => mutationCrashNow, staleAfterMs: 1_000,
  limits: { maxRecords: 1, maxPages: 1, maxShards: 1 },
  emitCriticalAlert: async (alert) => { mutationCrashAlerts.push(alert); },
  afterMutation: async () => {
    if (crashAfterMutation) {
      crashAfterMutation = false;
      throw new Error('SIMULATED_ANALYTICS_MUTATION_CRASH');
    }
  },
});
assert.equal((await mutationCrashPrune(pruneRequest())).status, 503);
const mutationCrashState = validateRetentionGenerationFenceState(
  (await mutationCrashControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, pruneEnv,
);
assert.equal(mutationCrashState.status, 'FROZEN');
assert.equal(mutationCrashStore.entries.get(eventKey(mutationCrashEvent)).event.schema,
  ANALYTICS_RETENTION_TOMBSTONE_SCHEMA);
assert.equal(mutationCrashStore.conditionalWrites, 1);
assert.equal((await mutationCrashControl.getWithMetadata(
  retentionGenerationFenceKeys.finalizeReceipt(mutationCrashState.operation_hmac_sha256),
)), null);
mutationCrashNow = new Date(mutationCrashNow.getTime() + 1_001);
const mutationCrashRetry = await mutationCrashPrune(pruneRequest());
assert.equal(mutationCrashRetry.status, 200,
  'A stale exact retry must validate the prior tombstone and finish the same operation.');
assert.equal(mutationCrashStore.conditionalWrites, 1,
  'Crash recovery must not repeat an already completed exact-etag mutation.');
assert.equal(validateRetentionGenerationFenceState(
  (await mutationCrashControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, pruneEnv,
).status, 'OPEN');
assert.equal(mutationCrashAlerts.length, 1);
assert.equal(validateRetentionGenerationFenceAlert(mutationCrashAlerts[0], pruneEnv).reason_code,
  'FENCE_STALE_EXACT_RETRY_RESUMED');

const receiptCrashEvent = normalizeAnalyticsEvent({
  ...base, event_id: '00eeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
}, oldTime);
const receiptCrashStore = new FakeAnalyticsPruneStore([
  { event: receiptCrashEvent, metadata: { expires_at: expirationTimestamp(oldTime) } },
]);
const receiptCrashControl = new FakeRetentionControlStore();
let crashAfterReceipt = true;
const receiptCrashAlerts = [];
const receiptCrashPrune = createAnalyticsPruneHandler({
  env: pruneEnv, store: receiptCrashStore, controlStore: receiptCrashControl, clock: () => now,
  limits: { maxRecords: 1, maxPages: 1, maxShards: 1 },
  emitCriticalAlert: async (alert) => { receiptCrashAlerts.push(alert); },
  afterCompletionReceipt: async () => {
    if (crashAfterReceipt) {
      crashAfterReceipt = false;
      throw new Error('SIMULATED_ANALYTICS_RECEIPT_CRASH');
    }
  },
});
assert.equal((await receiptCrashPrune(pruneRequest())).status, 503);
const receiptCrashState = validateRetentionGenerationFenceState(
  (await receiptCrashControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, pruneEnv,
);
assert.equal(receiptCrashState.status, 'FROZEN');
const receiptCrashIntent = validateRetentionFreezeIntent((await receiptCrashControl.getWithMetadata(
  retentionGenerationFenceKeys.freezeIntent(receiptCrashState.operation_hmac_sha256),
)).data, pruneEnv);
const receiptCrashReceipt = await receiptCrashControl.getWithMetadata(
  retentionGenerationFenceKeys.finalizeReceipt(receiptCrashState.operation_hmac_sha256),
);
validateRetentionFinalizeReceipt(receiptCrashReceipt.data, receiptCrashIntent, pruneEnv);
assert.equal((await receiptCrashPrune(pruneRequest())).status, 200,
  'A signed-finalize crash must reopen on the immediate exact retry.');
assert.equal(receiptCrashStore.conditionalWrites, 1);
assert.equal(validateRetentionGenerationFenceState(
  (await receiptCrashControl.getWithMetadata(RETENTION_GENERATION_FENCE_STATE_KEY)).data, pruneEnv,
).status, 'OPEN');
assert.equal(receiptCrashAlerts.length, 0,
  'A valid signed finalize receipt must recover without a stale critical alert.');

const corruptStoredEvent = { ...fallbackExpiredOne, event_id: '00444444-4444-4444-8444-444444444444', path: '/wrong/' };
const corruptStore = new FakeAnalyticsPruneStore([{ event: corruptStoredEvent, metadata: { expires_at: null } }], 1);
const corruptPrune = createAnalyticsPruneHandler({
  env: pruneEnv, store: corruptStore, controlStore: new FakeRetentionControlStore(), clock: () => now,
  limits: { maxRecords: 1, maxPages: 1, maxShards: 1 },
});
const corruptResponse = await corruptPrune(pruneRequest());
assert.equal(corruptResponse.status, 200);
const corruptReceipt = await corruptResponse.json();
assert.equal(corruptReceipt.invalid_records, 1);
assert.equal(corruptReceipt.deleted, 0, 'Malformed fallback records must be retained for review, never deleted.');
assert.equal(corruptStore.entries.has(eventKey(corruptStoredEvent)), true);

const mismatchedMetadataEvent = normalizeAnalyticsEvent({
  ...base, event_id: '00444444-4444-4444-9444-444444444444',
}, recentTime);
const mismatchedMetadataStore = new FakeAnalyticsPruneStore([
  { event: mismatchedMetadataEvent, metadata: { expires_at: expirationTimestamp(oldTime) } },
]);
const mismatchedMetadataPrune = createAnalyticsPruneHandler({
  env: pruneEnv, store: mismatchedMetadataStore,
  controlStore: new FakeRetentionControlStore(), clock: () => now,
  limits: { maxRecords: 1, maxPages: 1, maxShards: 1 },
});
const mismatchedMetadataResponse = await mismatchedMetadataPrune(pruneRequest());
assert.equal(mismatchedMetadataResponse.status, 200);
const mismatchedMetadataResult = await mismatchedMetadataResponse.json();
assert.equal(mismatchedMetadataResult.invalid_records, 1);
assert.equal(mismatchedMetadataResult.deleted, 0,
  'Expired metadata must not override a strongly reread fresh source record.');
assert.equal(mismatchedMetadataStore.entries.get(eventKey(mismatchedMetadataEvent)).event.schema,
  ANALYTICS_SCHEMA);

const racedAnalyticsEvent = normalizeAnalyticsEvent({
  ...base, event_id: '00555555-5555-4555-8555-555555555555',
}, oldTime);
const racedAnalyticsStore = new FakeAnalyticsPruneStore([
  { event: racedAnalyticsEvent, metadata: { expires_at: expirationTimestamp(oldTime) } },
]);
const concurrentlyUpdated = { ...racedAnalyticsEvent, path: '/thank-you/' };
racedAnalyticsStore.mutateBeforeCas = {
  key: eventKey(racedAnalyticsEvent), value: concurrentlyUpdated,
};
const racedAnalyticsPrune = createAnalyticsPruneHandler({
  env: pruneEnv, store: racedAnalyticsStore,
  controlStore: new FakeRetentionControlStore(), clock: () => now,
  limits: { maxRecords: 1, maxPages: 1, maxShards: 1 },
});
assert.equal((await racedAnalyticsPrune(pruneRequest())).status, 409,
  'A concurrent analytics update must win the exact-etag race.');
assert.deepEqual(racedAnalyticsStore.entries.get(eventKey(racedAnalyticsEvent)).event, concurrentlyUpdated);
assert.deepEqual(racedAnalyticsStore.deleteCalls, []);

const readbackEvent = normalizeAnalyticsEvent({
  ...base, event_id: '00666666-6666-4666-8666-666666666666',
}, oldTime);
const readbackStore = new FakeAnalyticsPruneStore([
  { event: readbackEvent, metadata: { expires_at: expirationTimestamp(oldTime) } },
]);
readbackStore.corruptReadbackKey = eventKey(readbackEvent);
const readbackPrune = createAnalyticsPruneHandler({
  env: pruneEnv, store: readbackStore,
  controlStore: new FakeRetentionControlStore(), clock: () => now,
  limits: { maxRecords: 1, maxPages: 1, maxShards: 1 },
});
assert.equal((await readbackPrune(pruneRequest())).status, 409,
  'A corrupted terminal tombstone readback must fail the prune run.');
assert.deepEqual(readbackStore.deleteCalls, []);
assert.equal((await readbackPrune(pruneRequest())).status, 409,
  'A tampered terminal tombstone must remain blocked and must never be accepted as a replay.');

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
