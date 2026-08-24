import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import adapterHandler, { config as adapterConfig } from '../netlify/functions/intake-arc1-adapter.mjs';
import backgroundHandler, { config as backgroundConfig } from '../netlify/functions/intake-arc1-adapter-background.mjs';
import recoveryHandler, { config as recoveryConfig } from '../netlify/functions/intake-arc1-adapter-recovery.mjs';
import {
  INTAKE_ARC1_ADAPTER_BACKGROUND_SCHEMA,
  INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS,
  acceptArc1AdapterEnvelope,
  dispatchArc1AdapterRecord,
  markArc1AdapterQueueUnavailable,
  recoverPendingArc1AdapterDispatches,
  validateArc1AdapterRecord,
} from '../netlify/lib/intake-arc1-adapter-core.mjs';
import {
  INTAKE_ARC1_CONSUMER_SCHEMA,
  INTAKE_ARC1_CONTRACT_SHA256,
  canonicalJson,
  createAdapterAttestation,
  createBridgeEnvelope,
  deliverIntakeToArc1,
  resolveArc1BridgeEnvironment,
} from '../netlify/lib/intake-arc1-bridge-core.mjs';
import { retrievePrivateAsset } from '../netlify/lib/intake-private-asset-core.mjs';
import { BUDGET_CONFIRMATION, TERMS_CONFIRMATION, normalizeIntakeForm } from '../netlify/lib/intake-submission-core.mjs';

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; this.writes = []; }
  async getWithMetadata(key) {
    const current = this.values.get(key);
    return current ? { data: structuredClone(current.data), etag: current.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    this.writes.push({ key, onlyIfNew: options.onlyIfNew === true, onlyIfMatch: options.onlyIfMatch || null });
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    if (options.onlyIfMatch && !current) return { modified: false };
    const etag = `etag-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
  async delete(key) { this.values.delete(key); }
  list({ prefix, paginate }) {
    assert.equal(paginate, true);
    const keys = [...this.values.keys()].filter((key) => key.startsWith(prefix)).sort();
    return { async *[Symbol.asyncIterator]() { yield { blobs: keys.map((key) => ({ key })) }; } };
  }
}

const now = new Date(Date.now() - 2_000);
const submissionId = '11111111-1111-4111-8111-111111111111';
const form = new FormData();
for (const [field, value] of Object.entries({
  intake_version: 'arc-intake-v7', name: 'Private Adapter Owner', email: 'adapter-owner@example.test',
  business: 'Private Adapter Roofing', industry: 'Roofing', city: 'Everett, WA', main_services: 'Roof replacement',
  main_call_to_action: 'Request Estimate', budget_confirmed: BUDGET_CONFIRMATION, terms_accepted: TERMS_CONFIRMATION,
  asset_permission: 'Confirmed', 'bot-field': '',
})) form.append(field, value);
form.append('goals', 'More qualified calls');
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
form.append('logo_file', new Blob([png], { type: 'image/png' }), 'logo.png');
const normalized = await normalizeIntakeForm(form, now, () => submissionId);

const env = {
  ARC_INTAKE_ARC1_ADAPTER_ENABLED: 'true',
  ARC_INTAKE_ARC1_BRIDGE_ENABLED: 'true',
  ARC_INTAKE_ARC1_DOWNSTREAM_ENABLED: 'true',
  ARC_INTAKE_ASSET_RETRIEVAL_ENABLED: 'true',
  ARC_INTAKE_ARC1_ENDPOINT: 'https://arcweb.onl/internal/intake/arc1/adapter',
  ARC_INTAKE_ARC1_DOWNSTREAM_ENDPOINT: 'https://hooks.zapier.com/hooks/catch/123456/abcde_12345/',
  ARC_INTAKE_ARC1_RUN_SECRET: 'run-secret-unique-0123456789-abcdefgh',
  ARC_INTAKE_ARC1_DESTINATION_BEARER: 'destination-bearer-unique-0123456789',
  ARC_INTAKE_ARC1_EVIDENCE_SECRET: 'evidence-secret-unique-0123456789-abcdef',
  ARC_INTAKE_ARC1_ACK_SECRET: 'ack-secret-unique-0123456789-abcdefghij',
  ARC_INTAKE_ARC1_STATE_SECRET: 'state-secret-unique-0123456789-abcdefgh',
  ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET: 'proof-secret-unique-0123456789-abcdefgh',
  ARC_INTAKE_ASSET_RETRIEVAL_SECRET: 'asset-retrieval-secret-unique-0123456789',
  ARC1_ASSET_RECEIPT_SECRET: 'asset-receipt-secret-unique-0123456789-ab',
  ARC1_INTAKE_EVIDENCE_SECRET: 'intake-evidence-secret-unique-0123456789',
  ARC_INTAKE_ARC1_DOWNSTREAM_BEARER: 'downstream-bearer-unique-0123456789-ab',
  ARC_INTAKE_ARC1_DISPATCH_SECRET: 'adapter-dispatch-secret-unique-0123456789',
  SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  SITE_NAME: 'arcsites', URL: 'https://arcweb.onl',
};
const assetEndpoint = 'https://arcweb.onl/internal/intake/arc1/assets/retrieve';
env.ARC_INTAKE_ARC1_ADAPTER_ATTESTATION = createAdapterAttestation({
  schema: 'arc-intake-arc1-adapter-attestation-v1', version: 1,
  source_schema: 'arc-intake-function-submission-v1', bridge_schema: 'arc-intake-arc1-bridge-evidence-v1',
  consumer_schema: INTAKE_ARC1_CONSUMER_SCHEMA, bridge_contract_sha256: INTAKE_ARC1_CONTRACT_SHA256,
  endpoint_sha256: createHash('sha256').update(env.ARC_INTAKE_ARC1_ENDPOINT).digest('hex'),
  asset_retrieval_endpoint_sha256: createHash('sha256').update(assetEndpoint).digest('hex'),
  site_id_sha256: createHash('sha256').update(env.SITE_ID).digest('hex'),
  asset_producer_consumer_tests_sha256: 'd'.repeat(64), asset_pipeline_verified: true,
  tests_passed: true, default_off_verified: true, verified_at: now.toISOString(),
  expires_at: new Date(now.getTime() + 24 * 60 * 60_000).toISOString(),
}, env.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET);

const sourceStore = new FakeStore();
const ingressStore = new FakeStore();
await sourceStore.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
let adapterRequestBody;
let adapterRequestHeaders;
let queued = 0;
const savedEnvironment = { ...process.env };
Object.assign(process.env, env);
try {
  const delivered = await deliverIntakeToArc1(submissionId, env, {
    store: sourceStore, clock: () => new Date(now), uuid: () => '22222222-2222-4222-8222-222222222222',
    fetch: async (url, options) => {
      adapterRequestBody = options.body;
      adapterRequestHeaders = options.headers;
      return adapterHandler(new Request(url, options), {
        intakeStore: sourceStore, adapterStore: ingressStore, clock: () => new Date(now),
        fetch: async (backgroundUrl, backgroundOptions) => {
          queued += 1;
          assert.equal(backgroundUrl, 'https://arcweb.onl/.netlify/functions/intake-arc1-adapter-background');
          assert.equal(backgroundOptions.headers.Authorization, `Bearer ${env.ARC_INTAKE_ARC1_DISPATCH_SECRET}`);
          assert.deepEqual(JSON.parse(backgroundOptions.body), {
            schema: INTAKE_ARC1_ADAPTER_BACKGROUND_SCHEMA,
            delivery_id: JSON.parse(adapterRequestBody).evidence.delivery_id,
          });
          return { status: 202, url: backgroundUrl };
        },
      });
    },
  });
  assert.deepEqual(delivered, {
    state: 'ACKED', idempotentReplay: false, deliveryId: JSON.parse(adapterRequestBody).evidence.delivery_id,
  });
  assert.equal(queued, 1);
  assert.equal(sourceStore.values.get(normalized.key).data.arc1_delivery.status, 'ACKED');

  const ingressKey = [...ingressStore.values.keys()].find((key) => key.startsWith('ingress/'));
  const pendingKey = [...ingressStore.values.keys()].find((key) => key.startsWith('pending/'));
  assert.ok(ingressKey && pendingKey, 'The acknowledgement requires both a create-only ingress record and recovery index.');
  const ingress = validateArc1AdapterRecord(ingressStore.values.get(ingressKey).data);
  const acknowledgementJson = ingress.acknowledgement_json;
  assert.equal(ingress.dispatch.status, 'PENDING');
  assert.equal(ingress.contains_direct_customer_content, false);
  for (const [key, value] of ingressStore.values) {
    assert.doesNotMatch(`${key}\n${JSON.stringify(value.data)}`, /Private Adapter|adapter-owner|Everett|content_base64/,
      'Adapter Blob keys and records must remain free of customer data and asset bytes.');
  }

  const replayResponse = await adapterHandler(new Request(env.ARC_INTAKE_ARC1_ENDPOINT, {
    method: 'POST', headers: adapterRequestHeaders, body: adapterRequestBody,
  }), {
    intakeStore: sourceStore, adapterStore: ingressStore, clock: () => new Date(now.getTime() + 5_000),
    fetch: async (url) => ({ status: 202, url }),
  });
  assert.equal(replayResponse.status, 200);
  assert.equal(await replayResponse.text(), acknowledgementJson);
  assert.equal(ingressStore.writes.filter((item) => item.key === ingressKey && item.onlyIfNew).length, 1,
    'A sequential exact replay must not create a second durable ingress record.');

  // Two simultaneous first deliveries use different request clocks but still
  // converge because claim_created_at is bound to immutable producer evidence.
  const raceStore = new FakeStore();
  const makeIngressRequest = () => new Request(env.ARC_INTAKE_ARC1_ENDPOINT, {
    method: 'POST', headers: adapterRequestHeaders, body: adapterRequestBody,
  });
  const raced = await Promise.all([
    acceptArc1AdapterEnvelope(adapterRequestBody, makeIngressRequest(), env, { source: sourceStore, adapter: raceStore }, {
      clock: () => new Date(now.getTime() + 10_000),
    }),
    acceptArc1AdapterEnvelope(adapterRequestBody, makeIngressRequest(), env, { source: sourceStore, adapter: raceStore }, {
      clock: () => new Date(now.getTime() + 20_000),
    }),
  ]);
  assert.equal(raced.filter((item) => item.created).length, 1);
  assert.equal(raced[0].acknowledgementJson, raced[1].acknowledgementJson);

  // The adapter verifies the authoritative content-addressed indexes and
  // actual stored bytes before it can sign a VERIFIED asset receipt.
  const missingIndexSource = new FakeStore();
  await missingIndexSource.setJSON(normalized.key, sourceStore.values.get(normalized.key).data, { onlyIfNew: true });
  const missingIndexIngress = new FakeStore();
  await assert.rejects(acceptArc1AdapterEnvelope(adapterRequestBody, makeIngressRequest(), env,
    { source: missingIndexSource, adapter: missingIndexIngress }, { clock: () => new Date(now.getTime() + 25_000) }),
  /ASSET_NOT_FOUND/);
  assert.equal([...missingIndexIngress.values.keys()].some((key) => key.startsWith('ingress/')), false);
  const tamperedSource = new FakeStore();
  for (const [key, item] of sourceStore.values) await tamperedSource.setJSON(key, item.data, { onlyIfNew: true });
  const tamperedRecord = tamperedSource.values.get(normalized.key);
  tamperedRecord.data.assets[0].content_base64 = Buffer.from([1, 2, 3]).toString('base64');
  const tamperedIngress = new FakeStore();
  await assert.rejects(acceptArc1AdapterEnvelope(adapterRequestBody, makeIngressRequest(), env,
    { source: tamperedSource, adapter: tamperedIngress }, { clock: () => new Date(now.getTime() + 25_000) }),
  /asset bytes|Image asset/i);
  assert.equal([...tamperedIngress.values.keys()].some((key) => key.startsWith('ingress/')), false);

  // Exact verifier time rules are enforced before the create-only claim.
  const resolvedBridge = resolveArc1BridgeEnvironment(env);
  const staleCases = [
    {
      received_at: new Date(now.getTime() - 25 * 60 * 60_000).toISOString(),
      evidence_issued_at: new Date(now.getTime() - 25 * 60 * 60_000).toISOString(),
      evidence_expires_at: new Date(now.getTime() - 60 * 60_000).toISOString(),
    },
    {
      received_at: now.toISOString(), evidence_issued_at: new Date(now.getTime() + 6 * 60_000).toISOString(),
      evidence_expires_at: new Date(now.getTime() + 60 * 60_000).toISOString(),
    },
    {
      received_at: now.toISOString(), evidence_issued_at: new Date(now.getTime() - 60 * 60_000).toISOString(),
      evidence_expires_at: new Date(now.getTime() - 1).toISOString(),
    },
  ];
  for (const timing of staleCases) {
    const current = structuredClone(sourceStore.values.get(normalized.key).data);
    current.received_at = timing.received_at;
    current.arc1_delivery = {
      ...current.arc1_delivery, evidence_issued_at: timing.evidence_issued_at,
      evidence_expires_at: timing.evidence_expires_at,
    };
    const envelope = createBridgeEnvelope(current, current.arc1_delivery, resolvedBridge);
    const staleSource = new FakeStore();
    await staleSource.setJSON(normalized.key, current, { onlyIfNew: true });
    const staleIngress = new FakeStore();
    const staleRequest = new Request(env.ARC_INTAKE_ARC1_ENDPOINT, { method: 'POST', headers: {
      authorization: `Bearer ${env.ARC_INTAKE_ARC1_DESTINATION_BEARER}`, 'content-type': 'application/json',
      'idempotency-key': envelope.deliveryId, 'x-arc-bridge-contract': INTAKE_ARC1_CONTRACT_SHA256,
    }, body: envelope.raw });
    await assert.rejects(acceptArc1AdapterEnvelope(envelope.raw, staleRequest, env,
      { source: staleSource, adapter: staleIngress }, { clock: () => new Date(now.getTime() + 30_000) }), /EVIDENCE_STALE/);
    assert.equal([...staleIngress.values.keys()].some((key) => key.startsWith('ingress/')), false);
  }

  // A durable exact replay is authenticated by the stored envelope digest and
  // bridge HMAC; it does not depend on the source record or a fresh proof.
  const replayOnlyStore = new FakeStore();
  const replayOnly = await acceptArc1AdapterEnvelope(adapterRequestBody, makeIngressRequest(), env,
    { source: sourceStore, adapter: replayOnlyStore }, { clock: () => new Date(now.getTime() + 31_000) });
  const replayWithoutSource = await acceptArc1AdapterEnvelope(adapterRequestBody, makeIngressRequest(), {
    ...env, ARC_INTAKE_ARC1_ADAPTER_ATTESTATION: 'expired-or-revoked-proof',
  }, {
    get source() { throw new Error('Exact durable replay must not read the source record.'); },
    adapter: replayOnlyStore,
  }, { clock: () => new Date(now.getTime() + 32_000) });
  assert.equal(replayWithoutSource.acknowledgementJson, replayOnly.acknowledgementJson);

  await assert.rejects(acceptArc1AdapterEnvelope(adapterRequestBody, makeIngressRequest(), {
    ...env, ARC_INTAKE_ASSET_RETRIEVAL_ENABLED: 'false',
  }, {
    get source() { throw new Error('Disabled retrieval must not read source state.'); },
    get adapter() { throw new Error('Disabled retrieval must not read adapter state.'); },
  }), /ADAPTER_DISABLED/);

  const tampered = JSON.parse(adapterRequestBody);
  tampered.evidence.data.business = 'Changed body without a valid HMAC';
  const conflict = await adapterHandler(new Request(env.ARC_INTAKE_ARC1_ENDPOINT, {
    method: 'POST', headers: adapterRequestHeaders, body: canonicalJson(tampered),
  }), { intakeStore: sourceStore, adapterStore: ingressStore, fetch: async () => { throw new Error('must not queue'); } });
  assert.equal(conflict.status, 409);

  let downstreamCalls = 0;
  let downstreamBody;
  let downstreamHeaders;
  const backgroundRequest = () => new Request('https://arcweb.onl/.netlify/functions/intake-arc1-adapter-background', {
    method: 'POST', headers: {
      authorization: `Bearer ${env.ARC_INTAKE_ARC1_DISPATCH_SECRET}`, 'content-type': 'application/json',
    }, body: canonicalJson({ schema: INTAKE_ARC1_ADAPTER_BACKGROUND_SCHEMA, delivery_id: delivered.deliveryId }),
  });
  const dispatched = await backgroundHandler(backgroundRequest(), {
    intakeStore: sourceStore, adapterStore: ingressStore, clock: () => new Date(now.getTime() + 30_000),
    fetch: async (url, options) => {
      downstreamCalls += 1; downstreamBody = options.body; downstreamHeaders = options.headers;
      assert.equal(url, env.ARC_INTAKE_ARC1_DOWNSTREAM_ENDPOINT);
      return { status: 200, url };
    },
  });
  assert.equal(dispatched.status, 204);
  assert.equal(downstreamCalls, 1);
  const packet = JSON.parse(downstreamBody);
  assert.equal(packet.schema, 'arc-intake-arc1-downstream-dispatch-v1');
  assert.equal(packet.bridge_envelope_json, adapterRequestBody);
  assert.doesNotMatch(downstreamBody, /content_base64/);
  assert.match(downstreamBody, /adapter-owner@example\.test/, 'Customer data is confined to the signed HTTPS body.');
  assert.doesNotMatch(canonicalJson(downstreamHeaders), /adapter-owner|Private Adapter|Everett/);
  assert.equal(downstreamHeaders.Authorization, `Bearer ${env.ARC_INTAKE_ARC1_DOWNSTREAM_BEARER}`);
  assert.equal(downstreamHeaders['Idempotency-Key'], delivered.deliveryId);
  assert.equal(ingressStore.values.get(ingressKey).data.dispatch.status, 'HOOK_ACCEPTED');
  assert.equal([...ingressStore.values.keys()].some((key) => key.startsWith('pending/')), false);
  const replayedDispatch = await backgroundHandler(backgroundRequest(), {
    intakeStore: sourceStore, adapterStore: ingressStore,
    fetch: async () => { downstreamCalls += 1; throw new Error('terminal replay must not send'); },
  });
  assert.equal(replayedDispatch.status, 204);
  assert.equal(downstreamCalls, 1);

  // Prove byte-for-byte compatibility with the committed downstream verifier,
  // private asset consumer, and acknowledgement producer in the paired repo.
  const previewRoot = new URL(`${process.env.ARC_PREVIEWS_DIR || '../arc-previews-launch'}/`, new URL(`file://${process.cwd()}/`));
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const runCodeStep = async (file, inputData, fetchImpl = globalThis.fetch) => {
    const source = await readFile(new URL(`zapier/${file}`, previewRoot), 'utf8');
    return new AsyncFunction('inputData', 'fetch', source)(inputData, fetchImpl);
  };
  const verified = await runCodeStep('arc1_verify_function_intake.js', {
    bridge_destination_bearer: downstreamHeaders.Authorization.slice(7),
    expected_bridge_destination_bearer: env.ARC_INTAKE_ARC1_DOWNSTREAM_BEARER,
    bridge_evidence_secret: env.ARC_INTAKE_ARC1_EVIDENCE_SECRET,
    intake_evidence_secret: env.ARC1_INTAKE_EVIDENCE_SECRET,
    expected_netlify_site_id: env.SITE_ID,
    bridge_envelope_json: packet.bridge_envelope_json,
  });
  assert.equal(verified.ingress_state_key, packet.ingress_state_key);
  assert.equal(verified.ingress_state_digest_sha256, packet.ingress_state_digest_sha256);
  const retrieved = await runCodeStep('arc1_retrieve_function_assets.js', {
    asset_retrieval_bearer: env.ARC_INTAKE_ASSET_RETRIEVAL_SECRET,
    asset_receipt_secret: env.ARC1_ASSET_RECEIPT_SECRET,
    asset_retrieval_endpoint: verified.asset_retrieval_endpoint,
    bridge_contract_sha256: verified.bridge_contract_sha256,
    bridge_delivery_id: verified.bridge_delivery_id,
    bridge_evidence_sha256: verified.bridge_evidence_sha256,
    private_asset_grants_json: verified.private_asset_grants_json,
    private_asset_grants_sha256: verified.private_asset_grants_sha256,
  }, async (url, options) => {
    assert.equal(url, assetEndpoint);
    assert.equal(options.headers.Authorization, `Bearer ${env.ARC_INTAKE_ASSET_RETRIEVAL_SECRET}`);
    const result = await retrievePrivateAsset(JSON.parse(options.body), env, { store: sourceStore, now });
    const response = new Response(result.bytes, { status: 200, headers: {
      'Content-Length': String(result.bytes.length), 'Content-Type': result.grant.content_type,
      'X-ARC-Asset-Id': result.grant.asset_id, 'X-ARC-Asset-Kind': result.grant.kind,
      'X-ARC-Asset-Role': result.grant.role, 'X-ARC-Asset-SHA256': result.grant.sha256,
    } });
    Object.defineProperty(response, 'url', { value: url });
    return response;
  });
  assert.equal(retrieved.asset_receipt_private, packet.asset_receipt_private);
  assert.equal(retrieved.asset_receipt_sha256, packet.asset_receipt_sha256);
  assert.equal(retrieved.asset_receipt_hmac_sha256, packet.asset_receipt_hmac_sha256);
  const acked = await runCodeStep('arc1_ack_function_intake.js', {
    ...packet, arc1_ack_secret: env.ARC_INTAKE_ARC1_ACK_SECRET, asset_receipt_secret: env.ARC1_ASSET_RECEIPT_SECRET,
  });
  assert.equal(acked.acknowledgement_json, acknowledgementJson);

  // Queue loss remains recoverable from its create-only pending index and
  // resolves the durable alert after exact downstream acceptance.
  await markArc1AdapterQueueUnavailable(raced[0].deliveryId, env, raceStore, { clock: () => new Date(now.getTime() + 40_000) });
  const raceIngressKey = [...raceStore.values.keys()].find((key) => key.startsWith('ingress/'));
  assert.equal(raceStore.values.get(raceIngressKey).data.dispatch.alert_code, 'QUEUE_UNAVAILABLE');
  let recoveryCursor = null;
  let recoveryAttempts = 0;
  do {
    const recovery = await recoverPendingArc1AdapterDispatches(new Request(
      `https://arcweb.onl/internal/intake/arc1/adapter/recover${recoveryCursor ? `?cursor=${encodeURIComponent(recoveryCursor)}` : ''}`,
      { method: 'POST' },
    ), env, { source: sourceStore, adapter: raceStore }, {
      clock: () => new Date(now.getTime() + 40_001), fetch: async (url) => ({ status: 200, url }),
    });
    recoveryAttempts += recovery.attempted;
    recoveryCursor = recovery.next_cursor;
  } while (recoveryCursor);
  assert.equal(recoveryAttempts, 1);
  assert.equal(raceStore.values.get(raceIngressKey).data.dispatch.status, 'HOOK_ACCEPTED');
  assert.equal(raceStore.values.get(raceIngressKey).data.dispatch.alert_status, 'RESOLVED');

  // An ambiguous queue timeout cannot clear a live downstream lease.
  const claimedStore = new FakeStore();
  const claimedAccepted = await acceptArc1AdapterEnvelope(adapterRequestBody, makeIngressRequest(), env,
    { source: sourceStore, adapter: claimedStore }, { clock: () => new Date(now.getTime() + 41_000) });
  let releaseHook;
  let hookEntered;
  const entered = new Promise((resolve) => { hookEntered = resolve; });
  const hookGate = new Promise((resolve) => { releaseHook = resolve; });
  const runningDispatch = dispatchArc1AdapterRecord(claimedAccepted.deliveryId, env,
    { source: sourceStore, adapter: claimedStore }, {
      clock: () => new Date(now.getTime() + 42_000),
      fetch: async () => { hookEntered(); return hookGate; },
    });
  await entered;
  const claimedIngressKey = [...claimedStore.values.keys()].find((key) => key.startsWith('ingress/'));
  const activeLease = structuredClone(claimedStore.values.get(claimedIngressKey).data.dispatch);
  assert.equal(activeLease.status, 'CLAIMED');
  await markArc1AdapterQueueUnavailable(claimedAccepted.deliveryId, env, claimedStore, {
    clock: () => new Date(now.getTime() + 43_000),
  });
  assert.deepEqual(claimedStore.values.get(claimedIngressKey).data.dispatch, activeLease);
  releaseHook({ status: 200, url: env.ARC_INTAKE_ARC1_DOWNSTREAM_ENDPOINT });
  assert.equal((await runningDispatch).state, 'HOOK_ACCEPTED');

  // Five bounded ambiguous failures dead-letter durably; a sixth invocation
  // is a network-free terminal replay.
  const deadStore = new FakeStore();
  const deadAccepted = await acceptArc1AdapterEnvelope(adapterRequestBody, makeIngressRequest(), env,
    { source: sourceStore, adapter: deadStore }, { clock: () => new Date(now) });
  let deadNow = new Date(now.getTime() + 50_000);
  let failedFetches = 0;
  for (let attempt = 1; attempt <= INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS; attempt += 1) {
    const result = await dispatchArc1AdapterRecord(deadAccepted.deliveryId, env, { source: sourceStore, adapter: deadStore }, {
      clock: () => new Date(deadNow), fetch: async () => { failedFetches += 1; throw new Error('unavailable'); },
    });
    if (attempt < INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS) {
      assert.equal(result.state, 'PENDING');
      const key = [...deadStore.values.keys()].find((item) => item.startsWith('ingress/'));
      if (attempt === 1) {
        const failedDispatch = structuredClone(deadStore.values.get(key).data.dispatch);
        await markArc1AdapterQueueUnavailable(deadAccepted.deliveryId, env, deadStore, {
          clock: () => new Date(deadNow.getTime() + 1),
        });
        assert.deepEqual(deadStore.values.get(key).data.dispatch, failedDispatch,
          'A duplicate queue failure must preserve an existing downstream alert and retry backoff.');
      }
      deadNow = new Date(Date.parse(deadStore.values.get(key).data.dispatch.next_attempt_at) + 1);
    } else assert.equal(result.state, 'DEAD_LETTER');
  }
  assert.equal(failedFetches, INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS);
  assert.equal((await dispatchArc1AdapterRecord(deadAccepted.deliveryId, env, { source: sourceStore, adapter: deadStore }, {
    fetch: async () => { failedFetches += 1; throw new Error('must not send'); },
  })).state, 'DEAD_LETTER');
  assert.equal(failedFetches, INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS);

  const missingSourceStore = new FakeStore();
  let missingSourceNow = new Date(now.getTime() + 60_000);
  let missingSourceFetches = 0;
  for (let attempt = 1; attempt <= INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS; attempt += 1) {
    const result = await dispatchArc1AdapterRecord(replayOnly.deliveryId, env,
      { source: missingSourceStore, adapter: replayOnlyStore }, {
        clock: () => new Date(missingSourceNow),
        fetch: async () => { missingSourceFetches += 1; throw new Error('source failure must precede hook fetch'); },
      });
    if (attempt < INTAKE_ARC1_ADAPTER_MAX_ATTEMPTS) {
      assert.equal(result.code, 'DOWNSTREAM_SOURCE_UNAVAILABLE');
      const key = [...replayOnlyStore.values.keys()].find((item) => item.startsWith('ingress/'));
      missingSourceNow = new Date(Date.parse(replayOnlyStore.values.get(key).data.dispatch.next_attempt_at) + 1);
    } else assert.equal(result.state, 'DEAD_LETTER');
  }
  assert.equal(missingSourceFetches, 0);

  // Signed cursor/shard continuation cannot starve a due record behind more
  // than one invocation's 100-record read bound; corrupt indexes quarantine.
  const starvationStore = new FakeStore();
  const stateHmac = (value) => createHmac('sha256', env.ARC_INTAKE_ARC1_STATE_SECRET).update(value).digest('hex');
  const digest = (value) => createHash('sha256').update(value).digest('hex');
  const keysForDelivery = (deliveryId) => ({
    ingress: `ingress/${stateHmac(`arc-intake-arc1-adapter-record-v1\n${deliveryId}`)}`,
    pending: `pending/${stateHmac(`arc-intake-arc1-adapter-pending-v1\n${deliveryId}`)}`,
  });
  let dueDelivery;
  let dueKeys;
  for (let candidate = 0; candidate < 10_000; candidate += 1) {
    const deliveryId = digest(`starvation-due-${candidate}`);
    const keys = keysForDelivery(deliveryId);
    if (keys.pending.startsWith('pending/ff')) { dueDelivery = deliveryId; dueKeys = keys; break; }
  }
  assert.ok(dueDelivery && dueKeys);
  const pendingTemplate = structuredClone(ingress);
  pendingTemplate.delivery_id = dueDelivery;
  pendingTemplate.dispatch = { ...pendingTemplate.dispatch, next_attempt_at: now.toISOString() };
  await starvationStore.setJSON(dueKeys.ingress, pendingTemplate, { onlyIfNew: true });
  await starvationStore.setJSON(dueKeys.pending, {
    schema: 'arc-intake-arc1-adapter-pending-index-v1', delivery_id_sha256: digest(dueDelivery), ingress_key: dueKeys.ingress,
  }, { onlyIfNew: true });
  let futureCount = 0;
  for (let candidate = 0; futureCount < 100; candidate += 1) {
    const deliveryId = digest(`starvation-future-${candidate}`);
    const keys = keysForDelivery(deliveryId);
    if (keys.pending >= dueKeys.pending) continue;
    const record = structuredClone(ingress);
    record.delivery_id = deliveryId;
    record.dispatch = { ...record.dispatch, next_attempt_at: new Date(now.getTime() + 24 * 60 * 60_000).toISOString() };
    await starvationStore.setJSON(keys.ingress, record, { onlyIfNew: true });
    await starvationStore.setJSON(keys.pending, {
      schema: 'arc-intake-arc1-adapter-pending-index-v1', delivery_id_sha256: digest(deliveryId), ingress_key: keys.ingress,
    }, { onlyIfNew: true });
    futureCount += 1;
  }
  await starvationStore.setJSON(`pending/${'0'.repeat(64)}`, { malformed: true }, { onlyIfNew: true });
  let starvationCursor = null;
  let firstCursor = null;
  let scannedBeforeDue = 0;
  let starvationAttempts = 0;
  let starvationInvalid = 0;
  let starvationCalls = 0;
  do {
    const result = await recoverPendingArc1AdapterDispatches(new Request(
      `https://arcweb.onl/internal/intake/arc1/adapter/recover${starvationCursor ? `?cursor=${encodeURIComponent(starvationCursor)}` : ''}`,
      { method: 'POST' },
    ), env, { source: sourceStore, adapter: starvationStore }, {
      clock: () => new Date(now.getTime() + 90_000),
      fetch: async () => { throw new Error('Synthetic due reconstruction must fail before network.'); },
    });
    starvationCalls += 1;
    assert.ok(starvationCalls < 100);
    if (starvationAttempts === 0 && result.attempted === 0) scannedBeforeDue += result.scanned;
    if (!firstCursor && result.next_cursor) firstCursor = result.next_cursor;
    starvationAttempts += result.attempted;
    starvationInvalid += result.invalid;
    starvationCursor = result.next_cursor;
  } while (starvationCursor);
  assert.equal(futureCount, 100);
  assert.ok(scannedBeforeDue > 0, 'Recovery must advance through earlier future work before reaching the due record.');
  assert.equal(starvationAttempts, 1);
  assert.equal(starvationInvalid, 1);
  assert.equal(starvationStore.values.has(`pending/${'0'.repeat(64)}`), false);
  assert.equal([...starvationStore.values.keys()].some((key) => key.startsWith('quarantine/')), true);
  const corruptedCursor = `${firstCursor.slice(0, -1)}${firstCursor.endsWith('0') ? '1' : '0'}`;
  await assert.rejects(recoverPendingArc1AdapterDispatches(new Request(
    `https://arcweb.onl/internal/intake/arc1/adapter/recover?cursor=${encodeURIComponent(corruptedCursor)}`,
    { method: 'POST' },
  ), env, { source: sourceStore, adapter: starvationStore }), /cursor signature/i);

  // All endpoints honor revocation before parsing or touching Blob/network.
  process.env.ARC_INTAKE_ARC1_ADAPTER_ENABLED = 'false';
  const disabled = await adapterHandler(new Request(env.ARC_INTAKE_ARC1_ENDPOINT, {
    method: 'POST', headers: adapterRequestHeaders, body: adapterRequestBody,
  }), {
    get intakeStore() { throw new Error('disabled adapter must not touch source state'); },
    get adapterStore() { throw new Error('disabled adapter must not touch ingress state'); },
    fetch: async () => { throw new Error('disabled adapter must not use network'); },
  });
  assert.equal(disabled.status, 503);
  const revokedBackground = await backgroundHandler(backgroundRequest(), {
    get intakeStore() { throw new Error('disabled background must not touch source state'); },
    get adapterStore() { throw new Error('disabled background must not touch ingress state'); },
    fetch: async () => { throw new Error('disabled background must not use network'); },
  });
  assert.equal(revokedBackground.status, 503);
  const recoveryRequest = new Request('https://arcweb.onl/internal/intake/arc1/adapter/recover', {
    method: 'POST', headers: { authorization: `Bearer ${env.ARC_INTAKE_ARC1_DISPATCH_SECRET}` },
  });
  const revokedRecovery = await recoveryHandler(recoveryRequest, {
    get intakeStore() { throw new Error('disabled recovery must not touch source state'); },
    get adapterStore() { throw new Error('disabled recovery must not touch ingress state'); },
  });
  assert.equal(revokedRecovery.status, 503);
} finally {
  for (const key of Object.keys(process.env)) if (!(key in savedEnvironment)) delete process.env[key];
  Object.assign(process.env, savedEnvironment);
}

assert.equal(adapterConfig.path, '/internal/intake/arc1/adapter');
assert.equal(adapterConfig.method, 'POST');
assert.equal(backgroundConfig.background, true);
assert.equal(Object.hasOwn(backgroundConfig, 'schedule'), false);
assert.equal(recoveryConfig.path, '/internal/intake/arc1/adapter/recover');
assert.equal(recoveryConfig.method, 'POST');
assert.equal(Object.hasOwn(recoveryConfig, 'schedule'), false);
console.log('ARC first-party durable synchronous adapter and retryable downstream dispatch contract passed.');
