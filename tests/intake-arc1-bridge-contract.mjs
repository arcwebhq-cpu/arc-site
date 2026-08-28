import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { config as bridgeConfig, createIntakeArc1BridgeHandler } from '../netlify/functions/intake-arc1-bridge.mjs';
import {
  INTAKE_ARC1_ACK_SCHEMA,
  INTAKE_ARC1_CONSUMER_SCHEMA,
  INTAKE_ARC1_CONTRACT_SHA256,
  INTAKE_ARC1_REQUEST_SCHEMA,
  canonicalJson,
  createAdapterAttestation,
  deliverIntakeToArc1,
  resolveArc1BridgeEnvironment,
  validateIntakeSubmissionForBridge,
} from '../netlify/lib/intake-arc1-bridge-core.mjs';
import { BUDGET_CONFIRMATION, TERMS_CONFIRMATION, normalizeIntakeForm } from '../netlify/lib/intake-submission-core.mjs';
import { consumeIntakeEmailVerificationToken, reserveIntakeEmailVerification } from '../netlify/lib/intake-email-verification-core.mjs';
import { testActivationAuthority } from './helpers/activation-authority.mjs';

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; this.writeCalls = 0; this.writeTrace = []; }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    this.writeCalls += 1;
    this.writeTrace.push({ key, status: data?.arc1_delivery?.status || null });
    const existing = this.values.get(key);
    if (options.onlyIfNew && existing) return { modified: false };
    if (options.onlyIfMatch && existing?.etag !== options.onlyIfMatch) return { modified: false };
    if (options.onlyIfMatch && !existing) return { modified: false };
    const etag = `etag-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    if (!existing && key.startsWith('submissions/') && data?.schema === 'arc-intake-function-submission-v1') {
      const verification = await reserveIntakeEmailVerification(data, env, this, { clock: () => receivedAt });
      await consumeIntakeEmailVerificationToken(new URL(verification.verification_url).hash.slice(1), env, this, {
        clock: () => receivedAt,
      });
    }
    return { modified: true, etag };
  }
}

const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const form = new FormData();
for (const [field, value] of Object.entries({
  intake_version: 'arc-intake-v8', offer_contract_id: 'arc-fixed-five-page-offer-v1', name: 'Private Test Owner', email: 'private-owner@example.test', business: 'Private Test Roofing',
  industry: 'Roofing', city: 'Everett, WA', main_services: 'Roof replacement', main_call_to_action: 'Request Estimate',
  lead_form_needed: 'Yes', lead_notification_email: 'private-owner@example.test', primary_style: 'Modern',
  budget_confirmed: BUDGET_CONFIRMATION, terms_accepted: TERMS_CONFIRMATION, asset_permission: 'Confirmed rights and no visible watermark v1', 'bot-field': '',
})) form.append(field, value);
form.append('goals', 'More calls');
form.append('lead_form_fields', 'Email');
form.append('sections', 'Contact or quote form');
form.append('assets', 'Logo');
const png = new Uint8Array(Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64'));
form.append('logo_file', new Blob([png], { type: 'image/png' }), 'logo.png');
const submissionId = '11111111-1111-4111-8111-111111111111';
const receivedAt = new Date('2026-08-13T18:00:00.000Z');
const normalized = await normalizeIntakeForm(form, receivedAt, () => submissionId);
validateIntakeSubmissionForBridge(normalized.record);

const env = {
  ...testActivationAuthority(new Date()),
  ARC_INTAKE_ARC1_BRIDGE_ENABLED: 'true',
  ARC_INTAKE_ARC1_ENDPOINT: 'https://hooks.example.test/arc1/intake',
  ARC_INTAKE_ARC1_RUN_SECRET: 'run-secret-unique-0123456789-abcdefgh',
  ARC_INTAKE_ARC1_DESTINATION_BEARER: 'destination-bearer-unique-0123456789',
  ARC_INTAKE_ARC1_EVIDENCE_SECRET: 'evidence-secret-unique-0123456789-abcdef',
  ARC_INTAKE_ARC1_ACK_SECRET: 'ack-secret-unique-0123456789-abcdefghij',
  ARC_INTAKE_ARC1_STATE_SECRET: 'state-secret-unique-0123456789-abcdefgh',
  ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET: 'proof-secret-unique-0123456789-abcdefgh',
  ARC_INTAKE_ASSET_RETRIEVAL_SECRET: 'asset-retrieval-secret-unique-0123456789',
  ARC_INTAKE_ASSET_RETRIEVAL_ENABLED: 'true',
  ARC_INTAKE_EMAIL_VERIFICATION_ENABLED: 'true',
  ARC_INTAKE_EMAIL_VERIFICATION_STATE_SECRET: 'verification-state-secret-unique-0123456789',
  ARC_INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET: 'verification-token-secret-unique-0123456789',
  ARC_INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET: 'verification-recipient-secret-unique-012345',
  ARC_INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET: 'verification-release-secret-unique-01234567',
  SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  SITE_NAME: 'arcsites',
  URL: 'https://arcweb.onl',
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
  tests_passed: true, default_off_verified: true, verified_at: receivedAt.toISOString(),
  expires_at: new Date(receivedAt.getTime() + 24 * 60 * 60_000).toISOString(),
}, env.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET);
resolveArc1BridgeEnvironment(env);
assert.throws(() => resolveArc1BridgeEnvironment({ ...env, ARC_INTAKE_ARC1_ACK_SECRET: env.ARC_INTAKE_ARC1_EVIDENCE_SECRET }), /distinct/);
assert.throws(() => resolveArc1BridgeEnvironment({ ...env, ARC_INTAKE_ARC1_ENDPOINT: 'http://example.test/arc1' }), /HTTPS/);

const makeAcknowledgement = (requestBody, received = receivedAt) => {
  const envelope = JSON.parse(requestBody);
  const evidenceRaw = canonicalJson(envelope.evidence);
  const acknowledgement = {
    schema: INTAKE_ARC1_ACK_SCHEMA, version: 1, status: 'ACCEPTED', consumer_schema: INTAKE_ARC1_CONSUMER_SCHEMA,
    bridge_contract_sha256: INTAKE_ARC1_CONTRACT_SHA256, delivery_id: envelope.evidence.delivery_id,
    evidence_sha256: createHash('sha256').update(evidenceRaw).digest('hex'), consumer_claim_key_hmac_sha256: 'c'.repeat(64),
    asset_receipt_sha256: 'd'.repeat(64),
    ack_id: `ack_${envelope.evidence.delivery_id.slice(0, 32)}`, received_at: received.toISOString(),
  };
  const canonical = canonicalJson(acknowledgement);
  return canonicalJson({ acknowledgement, hmac_sha256: hmac(env.ARC_INTAKE_ARC1_ACK_SECRET, `arc-intake-arc1-consumer-ack-v1\n${canonical}`) });
};

const response = (body, status = 200) => new Response(body, {
  status, headers: { 'content-length': String(Buffer.byteLength(body)) },
});

const disabledStore = new FakeStore();
await disabledStore.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
await assert.rejects(deliverIntakeToArc1(submissionId, { ...env, ARC_INTAKE_ARC1_BRIDGE_ENABLED: 'false' }, {
  get store() { throw new Error('Disabled bridge must not touch storage.'); },
}), /BRIDGE_DISABLED/);

const store = new FakeStore();
await store.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
let fetchCalls = 0;
let outbound;
const success = await deliverIntakeToArc1(submissionId, env, {
  store, clock: () => new Date(receivedAt), uuid: () => '22222222-2222-4222-8222-222222222222',
  fetch: async (url, options) => {
    fetchCalls += 1;
    outbound = { url, options };
    assert.equal(url, env.ARC_INTAKE_ARC1_ENDPOINT);
    assert.equal(options.method, 'POST');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.Authorization, `Bearer ${env.ARC_INTAKE_ARC1_DESTINATION_BEARER}`);
    assert.match(options.headers['Idempotency-Key'], /^[a-f0-9]{64}$/);
    assert.equal(options.headers['X-ARC-Bridge-Contract'], INTAKE_ARC1_CONTRACT_SHA256);
    assert.doesNotMatch(`${url}\n${canonicalJson(options.headers)}`, /Private Test|private-owner|Roofing|Everett/,
      'PII must not enter the destination URL or request headers.');
    const envelope = JSON.parse(options.body);
    assert.equal(envelope.evidence.data.email, 'private-owner@example.test', 'Private intake data is allowed only inside the authenticated HTTPS body.');
    assert.equal(Object.hasOwn(envelope.evidence, 'assets'), false, 'Raw asset bytes must never be embedded in bridge evidence.');
    assert.equal(envelope.evidence.asset_manifest[0].kind, 'UPLOAD');
    assert.equal(envelope.evidence.asset_manifest[0].sha256, createHash('sha256').update(png).digest('hex'));
    assert.equal(envelope.evidence.asset_retrieval_endpoint, assetEndpoint);
    return response(makeAcknowledgement(options.body));
  },
});
assert.equal(success.state, 'ACKED');
assert.equal(success.idempotentReplay, false);
const firstClaimWrite = store.writeTrace.findIndex(item => item.key === normalized.key && item.status === 'CLAIMED');
const firstAssetIndexWrite = store.writeTrace.findIndex(item => item.key.startsWith('arc1-asset-index/'));
assert.ok(firstClaimWrite >= 0 && firstAssetIndexWrite > firstClaimWrite,
  'Private asset indexes must not exist until the delivery attempt is CLAIMED and retention-ineligible.');
assert.equal(fetchCalls, 1);
const stored = store.values.get(normalized.key).data;
assert.equal(stored.arc1_delivery.status, 'ACKED');
assert.equal(stored.arc1_delivery.attempt_count, 1);
assert.match(stored.arc1_delivery.acknowledgement_sha256, /^[a-f0-9]{64}$/);
assert.equal(stored.arc1_delivery.consumer_claim_key_hmac_sha256, 'c'.repeat(64));
assert.equal(JSON.stringify(stored.arc1_delivery).includes('ack_'), false, 'Raw provider acknowledgement ids must not be durable state.');
for (const [key, entry] of store.values) {
  if (key.startsWith('arc1-')) assert.doesNotMatch(JSON.stringify(entry.data), /private-owner|Private Test|Everett/);
}
const replay = await deliverIntakeToArc1(submissionId, env, { store, clock: () => new Date(receivedAt), fetch: async () => { throw new Error('ACKED replay must not send.'); } });
assert.equal(replay.state, 'ACKED');
assert.equal(replay.idempotentReplay, true);

// A chunked ACK with no Content-Length is cancelled as soon as it crosses the
// exact 32 KiB cap; it never buffers the unbounded response.
const oversizedAckStore = new FakeStore(); await oversizedAckStore.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
let ackCancelled = false;
const oversizedAck = await deliverIntakeToArc1(submissionId, env, {
  store: oversizedAckStore, clock: () => new Date(receivedAt), uuid: () => '66666666-6666-4666-8666-666666666666',
  fetch: async () => {
    const stream = new ReadableStream({
      start(controller) { controller.enqueue(new Uint8Array(32 * 1024)); controller.enqueue(new Uint8Array([1])); },
      cancel() { ackCancelled = true; },
    });
    const result = new Response(stream, { status: 200 });
    Object.defineProperty(result, 'url', { value: env.ARC_INTAKE_ARC1_ENDPOINT });
    return result;
  },
});
assert.equal(oversizedAck.code, 'INVALID_ACK');
assert.equal(ackCancelled, true);

// A lost/unavailable response retains one immutable evidence body and idempotency key for retry.
const retryStore = new FakeStore();
await retryStore.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
let retryNow = new Date(receivedAt);
let failedBody;
const firstFailure = await deliverIntakeToArc1(submissionId, env, {
  store: retryStore, clock: () => new Date(retryNow), uuid: () => '33333333-3333-4333-8333-333333333333',
  fetch: async (_url, options) => { failedBody = options.body; throw new Error('ambiguous network failure'); },
});
assert.equal(firstFailure.state, 'PENDING');
assert.equal(firstFailure.code, 'DELIVERY_UNAVAILABLE');
assert.equal(retryStore.values.get(normalized.key).data.arc1_delivery.alert_status, 'PENDING');
retryNow = new Date(retryNow.getTime() + 60_001);
const retried = await deliverIntakeToArc1(submissionId, env, {
  store: retryStore, clock: () => new Date(retryNow), uuid: () => '44444444-4444-4444-8444-444444444444',
  fetch: async (_url, options) => {
    assert.equal(options.body, failedBody, 'A crash retry must resend byte-identical signed evidence.');
    assert.equal(JSON.parse(options.body).evidence.evidence_issued_at, receivedAt.toISOString());
    return response(makeAcknowledgement(options.body, retryNow));
  },
});
assert.equal(retried.state, 'ACKED');
assert.equal(retryStore.values.get(normalized.key).data.arc1_delivery.alert_status, 'RESOLVED');

// Exhaustion becomes a durable dead-letter with alert state and no sixth send.
const deadStore = new FakeStore();
await deadStore.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
let deadNow = new Date(receivedAt);
let deadFetches = 0;
for (let attempt = 1; attempt <= 5; attempt += 1) {
  const result = await deliverIntakeToArc1(submissionId, env, {
    store: deadStore, clock: () => new Date(deadNow), uuid: () => `${String(attempt).repeat(8)}-${String(attempt).repeat(4)}-4${String(attempt).repeat(3)}-8${String(attempt).repeat(3)}-${String(attempt).repeat(12)}`,
    fetch: async () => { deadFetches += 1; return response('', 503); },
  });
  if (attempt < 5) {
    assert.equal(result.state, 'PENDING');
    deadNow = new Date(Date.parse(result.retryAt) + 1);
  } else assert.equal(result.state, 'DEAD_LETTER');
}
assert.equal(deadFetches, 5);
const deadRecord = deadStore.values.get(normalized.key).data;
assert.equal(deadRecord.arc1_delivery.status, 'DEAD_LETTER');
assert.equal(deadRecord.arc1_delivery.alert_status, 'PENDING');
assert.equal(deadRecord.arc1_delivery.alert_code, 'MAX_ATTEMPTS');
const noSixth = await deliverIntakeToArc1(submissionId, env, { store: deadStore, clock: () => new Date(deadNow), fetch: async () => { deadFetches += 1; } });
assert.equal(noSixth.state, 'DEAD_LETTER');
assert.equal(deadFetches, 5);

// Internal delivery endpoint is authenticated, body-bounded, and still disabled by default.
const handler = createIntakeArc1BridgeHandler();
const savedEnv = { ...process.env };
try {
  Object.assign(process.env, env);
  delete process.env.ARC_INTAKE_ARC1_BRIDGE_ENABLED;
  const requestBody = canonicalJson({ schema: INTAKE_ARC1_REQUEST_SCHEMA, submission_id: submissionId });
  const makeRequest = (authorization = `Bearer ${env.ARC_INTAKE_ARC1_RUN_SECRET}`) => new Request('https://arcweb.onl/internal/intake/arc1/deliver', {
    method: 'POST', headers: { authorization, 'content-type': 'application/json' }, body: requestBody,
  });
  assert.equal((await handler(makeRequest('Bearer wrong'), { clock: () => receivedAt })).status, 401);
  const disabled = await handler(makeRequest(), {
    clock: () => receivedAt,
    get intakeStore() { throw new Error('Disabled endpoint must not touch storage.'); },
  });
  assert.equal(disabled.status, 503);
  assert.deepEqual(await disabled.json(), { error: 'bridge_disabled' });
  assert.equal((await handler(new Request('https://arcweb.onl/internal/intake/arc1/deliver'))).status, 405);
  assert.equal(bridgeConfig.path, '/internal/intake/arc1/deliver');
  assert.equal(bridgeConfig.method, 'POST');
} finally {
  for (const key of Object.keys(process.env)) if (!(key in savedEnv)) delete process.env[key];
  Object.assign(process.env, savedEnv);
}

assert.equal(outbound.url.includes('private-owner'), false);
console.log('ARC intake to ARC1 authenticated resumable bridge contract passed.');
