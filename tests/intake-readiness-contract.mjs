import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import handler, { config, createIntakeReadinessHandler } from '../netlify/functions/intake-readiness.mjs';
import submitHandler, { config as submitConfig, createIntakeSubmitHandler } from '../netlify/functions/intake-submit.mjs';
import {
  INTAKE_ARC1_ADAPTER_PROOF_ENV,
  INTAKE_ARC1_ADAPTER_PROOF_SCHEMA,
  INTAKE_ARC1_BRIDGE_EVIDENCE_SCHEMA,
  INTAKE_ARC1_CONSUMER_SCHEMA,
  INTAKE_ARC1_CONTRACT_SHA256,
  createAdapterAttestation,
  intakeArc1AdapterAttested,
} from '../netlify/lib/intake-arc1-bridge-core.mjs';
import {
  INTAKE_BUILD_MARKER_SCHEMA,
  INTAKE_BUILD_MARKER_VERSION,
  INTAKE_READINESS_BOOLEAN_FIELDS,
  INTAKE_READINESS_ENV,
  INTAKE_READINESS_SCHEMA,
  INTAKE_READINESS_VERSION,
  intakeEnabledFromAttestation,
  intakeEnabledFromBuildMarker,
  intakeArc1RuntimeReady,
} from '../netlify/lib/intake-readiness-core.mjs';
import {
  BUDGET_CONFIRMATION,
  INTAKE_ALLOWED_FIELDS,
  INTAKE_FILE_FIELDS,
  INTAKE_MAX_FILE_BYTES,
  INTAKE_MAX_REQUEST_BYTES,
  INTAKE_MAX_TOTAL_FILE_BYTES,
  INTAKE_SUBMISSION_SCHEMA,
  INTAKE_IDEMPOTENCY_SECRET_ENV,
  TERMS_CONFIRMATION,
  intakeIdempotencyConfigured,
  normalizeIntakeForm,
} from '../netlify/lib/intake-submission-core.mjs';

class FakeStore {
  constructor() { this.values = new Map(); this.calls = 0; }
  async setJSON(key, value, options = {}) {
    this.calls += 1;
    if (options.onlyIfNew !== true || this.values.has(key)) return { modified: false };
    this.values.set(key, structuredClone(value));
    return { modified: true, etag: `etag-${this.calls}` };
  }
  async getWithMetadata(key) {
    const value = this.values.get(key);
    return value ? { data: structuredClone(value), etag: `etag-${this.calls}` } : null;
  }
}

class AmbiguousWriteStore extends FakeStore {
  constructor() { super(); this.failAfterFirstWrite = true; }
  async setJSON(key, value, options = {}) {
    const result = await super.setJSON(key, value, options);
    if (result.modified && this.failAfterFirstWrite) {
      this.failAfterFirstWrite = false;
      throw new Error('simulated_ambiguous_intake_write');
    }
    return result;
  }
}

const validForm = () => {
  const form = new FormData();
  for (const [field, value] of Object.entries({
    intake_version: 'arc-intake-v8', offer_contract_id: 'arc-fixed-five-page-offer-v1',
    submission_request_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    name: 'Test Owner',
    email: 'owner@example.test',
    business: 'Test Roofing',
    industry: 'Roofing',
    city: 'Everett, WA',
    main_services: 'Roof replacement',
    main_call_to_action: 'Request Estimate',
    lead_form_needed: 'Yes',
    lead_notification_email: 'owner@example.test',
    primary_style: 'Modern',
    budget_confirmed: BUDGET_CONFIRMATION,
    terms_accepted: TERMS_CONFIRMATION,
    'bot-field': '',
  })) form.append(field, value);
  form.append('goals', 'More calls');
  form.append('goals', 'Estimate requests');
  form.append('lead_form_fields', 'Email');
  form.append('sections', 'Contact or quote form');
  return form;
};

const home = await readFile(new URL('../index.html', import.meta.url), 'utf8');
const projectFormMarkup = home.match(/<form\b[^>]*\bid="projectForm"[^>]*>[\s\S]*?<\/form>/)?.[0];
assert.ok(projectFormMarkup, 'The public project form must remain discoverable to its server-contract test.');
const actualNamedControlFields = [...new Set(
  [...projectFormMarkup.matchAll(/<(?:input|select|textarea)\b[^>]*\bname="([^"]+)"/g)].map((match) => match[1]),
)].sort();
assert.deepEqual(actualNamedControlFields, [...INTAKE_ALLOWED_FIELDS].sort(),
  'Every distinct named public form control must have an exact server allowlist entry, with no server-only drift.');

const validPng = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
const pngCrcTable = Array.from({ length: 256 }, (_, value) => {
  let current = value;
  for (let bit = 0; bit < 8; bit += 1) current = current & 1 ? 0xedb88320 ^ (current >>> 1) : current >>> 1;
  return current >>> 0;
});
const pngCrc32 = (bytes) => {
  let value = 0xffffffff;
  for (const byte of bytes) value = pngCrcTable[(value ^ byte) & 255] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
};
const pngBlob = (size) => {
  if (size === undefined) return new Blob([validPng], { type: 'image/png' });
  if (size >= 57 && size <= INTAKE_MAX_FILE_BYTES) {
    const data = Buffer.alloc(size - 57);
    const idat = Buffer.alloc(12 + data.length);
    idat.writeUInt32BE(data.length, 0); idat.write('IDAT', 4, 4, 'ascii'); data.copy(idat, 8);
    idat.writeUInt32BE(pngCrc32(idat.subarray(4, 8 + data.length)), 8 + data.length);
    return new Blob([validPng.subarray(0, 33), idat, validPng.subarray(-12)], { type: 'image/png' });
  }
  const bytes = new Uint8Array(size);
  bytes.set([137, 80, 78, 71, 13, 10, 26, 10]);
  return new Blob([bytes], { type: 'image/png' });
};
const pngWithChunk = (type, data = Buffer.from('metadata')) => {
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  chunk.write(type, 4, 4, 'ascii');
  data.copy(chunk, 8);
  return Buffer.concat([validPng.subarray(0, -12), chunk, validPng.subarray(-12)]);
};

const allNamedControlForm = () => {
  const form = new FormData();
  const exactValues = {
    'bot-field': '',
    asset_permission: 'Confirmed',
    budget_confirmed: BUDGET_CONFIRMATION,
    business: 'Test Roofing',
    city: 'Everett, WA',
    email: 'owner@example.test',
    goals: 'More calls',
    industry: 'Roofing',
    intake_version: 'arc-intake-v8', offer_contract_id: 'arc-fixed-five-page-offer-v1',
    main_call_to_action: 'Request Estimate',
    main_services: 'Roof replacement',
    name: 'Test Owner',
    lead_form_needed: 'Yes',
    lead_form_fields: 'Email',
    lead_notification_email: 'owner@example.test',
    primary_style: 'Modern',
    public_email: 'public@example.test',
    sections: 'Contact or quote form',
    submission_request_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    website: 'https://example.test',
    brand_tone: 'Professional',
    domain_status: 'I own a domain',
    assets: 'Logo',
    proof: 'Customer reviews',
    proof_details: 'Verified review supplied by the customer.',
    terms_accepted: TERMS_CONFIRMATION,
  };
  for (const field of actualNamedControlFields) {
    if (INTAKE_FILE_FIELDS.includes(field)) form.append(field, pngBlob(), `${field}.png`);
    else form.append(field, exactValues[field] ?? 'Contract test value');
  }
  form.append('assets', 'Photos');
  return form;
};

const enabledBuildMarker = Object.freeze({
  schema: INTAKE_BUILD_MARKER_SCHEMA,
  version: INTAKE_BUILD_MARKER_VERSION,
  intake_enabled: true,
});
let simulatedFutureRuntimeReady = false;
const enabledReadinessHandler = createIntakeReadinessHandler(enabledBuildMarker, () => simulatedFutureRuntimeReady);
const enabledSubmitHandler = createIntakeSubmitHandler(enabledBuildMarker, () => simulatedFutureRuntimeReady);
assert.equal(intakeEnabledFromBuildMarker(enabledBuildMarker), true);
for (const invalidMarker of [
  null,
  {},
  { ...enabledBuildMarker, intake_enabled: false },
  { ...enabledBuildMarker, intake_enabled: 'true' },
  { ...enabledBuildMarker, version: 2 },
  { ...enabledBuildMarker, unexpected: true },
]) assert.equal(intakeEnabledFromBuildMarker(invalidMarker), false);

const normalizedRealForm = await normalizeIntakeForm(
  allNamedControlForm(),
  new Date('2026-08-13T07:59:00.000Z'),
  () => '00000000-0000-4000-8000-000000000000',
);
assert.equal(normalizedRealForm.record.data.primary_style, 'Modern');
assert.deepEqual(
  Object.keys(normalizedRealForm.record.data).sort(),
  actualNamedControlFields.filter((field) => !['bot-field', 'submission_request_id'].includes(field) && !INTAKE_FILE_FIELDS.includes(field)).sort(),
  'A form assembled from every actual named control must survive normalization without dropping fields.',
);
assert.deepEqual(normalizedRealForm.record.asset_manifest.map(({ role }) => role).sort(), [...INTAKE_FILE_FIELDS].sort());

const invalidCtaForm = validForm();
invalidCtaForm.set('main_call_to_action', 'Invent a CTA');
await assert.rejects(normalizeIntakeForm(invalidCtaForm), /main_call_to_action is invalid/i);
const missingLeadRouteForm = validForm();
missingLeadRouteForm.delete('lead_notification_email');
await assert.rejects(normalizeIntakeForm(missingLeadRouteForm), /lead routing details are required/i);
const invalidWebsiteForm = validForm();
invalidWebsiteForm.set('website', 'javascript:alert(1)');
await assert.rejects(normalizeIntakeForm(invalidWebsiteForm), /website is invalid/i);
const duplicateGoalForm = validForm();
duplicateGoalForm.append('goals', 'More calls');
await assert.rejects(normalizeIntakeForm(duplicateGoalForm), /goals contains duplicate values/i);
const unsupportedGoalForm = validForm();
unsupportedGoalForm.set('goals', 'Guaranteed revenue');
await assert.rejects(normalizeIntakeForm(unsupportedGoalForm), /goals is invalid/i);
const unsupportedProofForm = validForm();
unsupportedProofForm.append('proof', 'Customer reviews');
await assert.rejects(normalizeIntakeForm(unsupportedProofForm), /proof details are required/i);
const invalidRequestIdentityForm = validForm();
invalidRequestIdentityForm.set('submission_request_id', 'caller-controlled-id');
await assert.rejects(normalizeIntakeForm(invalidRequestIdentityForm), /request identity is invalid/i);

const tooLargeFileForm = validForm();
tooLargeFileForm.append('asset_permission', 'Confirmed');
tooLargeFileForm.append('assets', 'Logo');
tooLargeFileForm.append('logo_file', pngBlob(INTAKE_MAX_FILE_BYTES + 1), 'logo.png');
await assert.rejects(normalizeIntakeForm(tooLargeFileForm), /file size is invalid/i);
const tooLargeTotalForm = validForm();
tooLargeTotalForm.append('asset_permission', 'Confirmed');
tooLargeTotalForm.append('assets', 'Logo');
tooLargeTotalForm.append('assets', 'Photos');
for (const field of INTAKE_FILE_FIELDS) {
  const size = field === INTAKE_FILE_FIELDS.at(-1) ? 1_000_001 : 1_000_000;
  tooLargeTotalForm.append(field, pngBlob(size), `${field}.png`);
}
assert.equal([...tooLargeTotalForm.values()].filter((value) => typeof value !== 'string').reduce((sum, file) => sum + file.size, 0), INTAKE_MAX_TOTAL_FILE_BYTES + 1);
await assert.rejects(normalizeIntakeForm(tooLargeTotalForm), /files are too large/i);

const submitRequest = (form = validForm(), origin = 'https://arcweb.onl') => new Request(`${origin}/api/intake/submit`, {
  method: 'POST', headers: { origin }, body: form,
});

const completeAttestation = Object.freeze({
  schema: INTAKE_READINESS_SCHEMA,
  version: INTAKE_READINESS_VERSION,
  ...Object.fromEntries(INTAKE_READINESS_BOOLEAN_FIELDS.map((field) => [field, true])),
});
const encodedCompleteAttestation = JSON.stringify(completeAttestation);
const adapterProofSecret = 'arc-intake-adapter-proof-secret-unique-0123456789';
const adapterProofNow = new Date();
const adapterEndpoint = 'https://arcweb.onl/internal/intake/arc1/adapter';
const adapterAssetEndpoint = 'https://arcweb.onl/internal/intake/arc1/assets/retrieve';
const adapterSiteId = '8f9d462c-952f-42fc-a3a0-50a2529e8f5d';
const adapterProofValue = Object.freeze({
  schema: INTAKE_ARC1_ADAPTER_PROOF_SCHEMA,
  version: 1,
  source_schema: INTAKE_SUBMISSION_SCHEMA,
  bridge_schema: INTAKE_ARC1_BRIDGE_EVIDENCE_SCHEMA,
  consumer_schema: INTAKE_ARC1_CONSUMER_SCHEMA,
  bridge_contract_sha256: INTAKE_ARC1_CONTRACT_SHA256,
  endpoint_sha256: createHash('sha256').update(adapterEndpoint).digest('hex'),
  asset_retrieval_endpoint_sha256: createHash('sha256').update(adapterAssetEndpoint).digest('hex'),
  site_id_sha256: createHash('sha256').update(adapterSiteId).digest('hex'),
  asset_producer_consumer_tests_sha256: 'a'.repeat(64),
  asset_pipeline_verified: true,
  tests_passed: true,
  default_off_verified: true,
  verified_at: new Date(adapterProofNow.getTime() - 1_000).toISOString(),
  expires_at: new Date(adapterProofNow.getTime() + 60 * 60_000).toISOString(),
});
const encodedAdapterProof = createAdapterAttestation(adapterProofValue, adapterProofSecret);
assert.equal(intakeArc1AdapterAttested(encodedAdapterProof, adapterProofSecret, adapterProofNow,
  adapterEndpoint, adapterAssetEndpoint, adapterSiteId), true);
assert.equal(intakeArc1AdapterAttested(encodedAdapterProof, adapterProofSecret, adapterProofNow,
  'https://attacker.example/arc1/intake', adapterAssetEndpoint, adapterSiteId), false,
  'The signed proof must bind the exact reviewed PII destination.');
const saved = {
  attestation: process.env[INTAKE_READINESS_ENV],
  buildIntake: process.env.ARC_BUILD_INTAKE_ENABLED,
  legacyIntake: process.env.ARC_INTAKE_ENABLED,
  legacyRoute: process.env.ARC_LEAD_ROUTE_VERIFIED,
  adapterProof: process.env[INTAKE_ARC1_ADAPTER_PROOF_ENV],
  adapterProofSecret: process.env.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET,
};
const bridgeRuntimeEnv = {
  ARC_INTAKE_ARC1_ADAPTER_ENABLED: 'true',
  ARC_INTAKE_ARC1_BRIDGE_ENABLED: 'true',
  ARC_INTAKE_ARC1_DISPATCH_ENABLED: 'true',
  ARC_INTAKE_ARC1_DOWNSTREAM_ENABLED: 'true',
  ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED: 'true',
  ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED: 'true',
  ARC_INTAKE_ARC1_ENDPOINT: adapterEndpoint,
  ARC_INTAKE_ARC1_DOWNSTREAM_ENDPOINT: 'https://hooks.zapier.com/hooks/catch/123456/abcde_12345/',
  ARC_INTAKE_ARC1_RUN_SECRET: 'run-secret-unique-0123456789-abcdefgh',
  ARC_INTAKE_ARC1_DISPATCH_SECRET: 'dispatch-secret-unique-0123456789-abcdef',
  ARC_INTAKE_ARC1_DESTINATION_BEARER: 'destination-bearer-unique-0123456789',
  ARC_INTAKE_ARC1_EVIDENCE_SECRET: 'evidence-secret-unique-0123456789-abcdef',
  ARC_INTAKE_ARC1_ACK_SECRET: 'ack-secret-unique-0123456789-abcdefghij',
  ARC_INTAKE_ARC1_STATE_SECRET: 'state-secret-unique-0123456789-abcdefgh',
  ARC_INTAKE_ASSET_RETRIEVAL_SECRET: 'asset-retrieval-secret-unique-0123456789',
  ARC1_ASSET_RECEIPT_SECRET: 'asset-receipt-secret-unique-0123456789-ab',
  ARC_INTAKE_ARC1_DOWNSTREAM_BEARER: 'downstream-bearer-unique-0123456789-ab',
  ARC_INTAKE_ARC1_PACKET_SECRET: 'packet-secret-unique-0123456789-abcdefgh',
  ARC_INTAKE_ARC1_CONSUMER_BEARER: 'consumer-bearer-unique-0123456789-abcdef',
  ARC_INTAKE_ARC1_CONSUMER_RECEIPT_SECRET: 'consumer-receipt-secret-unique-0123456789',
  ARC_INTAKE_ASSET_RETRIEVAL_ENABLED: 'true',
  ARC_INTAKE_IDEMPOTENCY_SECRET: 'intake-idempotency-secret-unique-0123456789',
  SITE_ID: adapterSiteId,
  ARC_EXPECTED_NETLIFY_SITE_ID: adapterSiteId,
  SITE_NAME: 'arcsites',
  URL: 'https://arcweb.onl',
};
const bridgeRuntimeSaved = Object.fromEntries(Object.keys(bridgeRuntimeEnv).map((key) => [key, process.env[key]]));

const request = (selectedHandler = enabledReadinessHandler) => selectedHandler(new Request('https://arcweb.onl/api/intake/readiness'));
const responseBody = async (selectedHandler = enabledReadinessHandler) => {
  const response = await request(selectedHandler);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  return response.json();
};

try {
  delete process.env[INTAKE_READINESS_ENV];
  delete process.env.ARC_BUILD_INTAKE_ENABLED;
  process.env.ARC_INTAKE_ENABLED = 'true';
  process.env.ARC_LEAD_ROUTE_VERIFIED = 'true';
  assert.deepEqual(await responseBody(), { schema: 'arc-intake-readiness-v1', intake_enabled: false });

  process.env[INTAKE_READINESS_ENV] = encodedCompleteAttestation;
  process.env.ARC_BUILD_INTAKE_ENABLED = 'true';
  delete process.env[INTAKE_ARC1_ADAPTER_PROOF_ENV];
  delete process.env.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET;
  assert.equal((await responseBody(handler)).intake_enabled, false,
    'A complete runtime attestation and mutable runtime flag cannot override the same-deploy build marker.');
  const compiledClosed = await submitHandler(submitRequest(), {
    get intakeStore() { throw new Error('A compiled-closed intake must not touch storage.'); },
  });
  assert.equal(compiledClosed.status, 503);
  assert.deepEqual(await compiledClosed.json(), { error: 'intake_disabled' });

  delete process.env.ARC_BUILD_INTAKE_ENABLED;
  const runtimeClosed = await enabledSubmitHandler(submitRequest(), {
    get intakeStore() { throw new Error('A runtime-closed intake must not touch storage.'); },
  });
  assert.equal(runtimeClosed.status, 503);
  process.env.ARC_BUILD_INTAKE_ENABLED = 'true';
  assert.deepEqual(await responseBody(), { schema: 'arc-intake-readiness-v1', intake_enabled: false },
    'A boolean self-attestation cannot replace an exact signed ARC1 adapter proof.');
  const unproved = await enabledSubmitHandler(submitRequest(), {
    get intakeStore() { throw new Error('Unproved ARC1 compatibility must block before storage.'); },
  });
  assert.equal(unproved.status, 503);
  process.env[INTAKE_ARC1_ADAPTER_PROOF_ENV] = encodedAdapterProof;
  process.env.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET = adapterProofSecret;
  Object.assign(process.env, bridgeRuntimeEnv);
  const readinessRequest = new Request('https://arcweb.onl/api/intake/readiness');
  assert.equal(intakeArc1RuntimeReady(readinessRequest, process.env), false,
    'Private retrieval alone cannot open readiness before bound preview publication wiring is proven.');
  simulatedFutureRuntimeReady = true;
  for (const field of ['ARC_INTAKE_ARC1_ADAPTER_ENABLED', 'ARC_INTAKE_ARC1_BRIDGE_ENABLED',
    'ARC_INTAKE_ARC1_DISPATCH_ENABLED', 'ARC_INTAKE_ARC1_DOWNSTREAM_ENABLED',
    'ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED', 'ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED']) {
    const previous = process.env[field];
    delete process.env[field];
    assert.equal(intakeArc1RuntimeReady(readinessRequest, process.env), false, `${field} must block readiness.`);
    process.env[field] = previous;
  }
  for (const field of ['ARC_INTAKE_ARC1_PACKET_SECRET', 'ARC_INTAKE_ARC1_CONSUMER_BEARER',
    'ARC_INTAKE_ARC1_CONSUMER_RECEIPT_SECRET']) {
    const previous = process.env[field];
    delete process.env[field];
    assert.equal(intakeArc1RuntimeReady(readinessRequest, process.env), false,
      `${field} must block readiness before any v2 packet can be emitted.`);
    process.env[field] = previous;
  }
  const savedAckSecret = process.env.ARC_INTAKE_ARC1_ACK_SECRET;
  process.env.ARC_INTAKE_ARC1_ACK_SECRET = process.env.ARC_INTAKE_ARC1_EVIDENCE_SECRET;
  assert.equal(intakeArc1RuntimeReady(readinessRequest, process.env), false, 'Duplicate bridge secrets must block readiness.');
  process.env.ARC_INTAKE_ARC1_ACK_SECRET = savedAckSecret;
  assert.equal(intakeIdempotencyConfigured(process.env), true);
  const savedIdempotencySecret = process.env[INTAKE_IDEMPOTENCY_SECRET_ENV];
  delete process.env[INTAKE_IDEMPOTENCY_SECRET_ENV];
  assert.equal(intakeArc1RuntimeReady(readinessRequest, process.env), false,
    'Public intake readiness must require a private lost-response idempotency secret.');
  process.env[INTAKE_IDEMPOTENCY_SECRET_ENV] = process.env.ARC_INTAKE_ARC1_ACK_SECRET;
  assert.equal(intakeIdempotencyConfigured(process.env), false, 'The intake idempotency secret must be distinct.');
  process.env[INTAKE_IDEMPOTENCY_SECRET_ENV] = savedIdempotencySecret;

  for (const invalidProof of [
    '',
    encodedAdapterProof.replace(INTAKE_ARC1_CONTRACT_SHA256, '0'.repeat(64)),
    createAdapterAttestation({ ...adapterProofValue, tests_passed: false }, adapterProofSecret),
    createAdapterAttestation({ ...adapterProofValue, expires_at: new Date(adapterProofNow.getTime() - 1).toISOString() }, adapterProofSecret),
  ]) assert.equal(intakeArc1AdapterAttested(invalidProof, adapterProofSecret, adapterProofNow,
    adapterEndpoint, adapterAssetEndpoint, adapterSiteId), false);

  const malformedOrIncomplete = [
    '',
    ' ',
    '{',
    'null',
    '[]',
    JSON.stringify({ ...completeAttestation, schema: 'arc-intake-readiness-attestation-v2' }),
    JSON.stringify({ ...completeAttestation, version: 2 }),
    JSON.stringify({ ...completeAttestation, route_verified: 'true' }),
    JSON.stringify({ ...completeAttestation, unexpected_gate: true }),
    JSON.stringify(Object.fromEntries(Object.entries(completeAttestation).filter(([key]) => key !== 'recipient_verified'))),
    JSON.stringify({ ...completeAttestation, __proto_gate: true }),
    JSON.stringify({ ...completeAttestation, payment_readiness_verified: false }),
    'x'.repeat(2049),
  ];
  for (const raw of malformedOrIncomplete) {
    assert.equal(intakeEnabledFromAttestation(raw), false, `Attestation must fail closed: ${raw.slice(0, 100)}`);
    process.env[INTAKE_READINESS_ENV] = raw;
    assert.equal((await responseBody()).intake_enabled, false);
  }

  for (const field of INTAKE_READINESS_BOOLEAN_FIELDS) {
    const value = { ...completeAttestation, [field]: false };
    assert.equal(intakeEnabledFromAttestation(JSON.stringify(value)), false, `${field} must be true`);
  }

  assert.equal(intakeEnabledFromAttestation(null), false);
  assert.equal(intakeEnabledFromAttestation(completeAttestation), false);
  assert.equal(intakeEnabledFromAttestation(encodedCompleteAttestation), true);
  assert.equal(intakeEnabledFromAttestation(JSON.stringify({
    payment_readiness_verified: true,
    tax_readiness_verified: true,
    legal_readiness_verified: true,
    adult_operator_verified: true,
    transactional_sender_verified: true,
    arc1_consumer_adapter_verified: true,
    native_netlify_forms_disabled_verified: true,
    retention_verified: true,
    asset_pipeline_verified: true,
    failure_alert_verified: true,
    dedupe_verified: true,
    recipient_verified: true,
    route_verified: true,
    intake_enabled: true,
    version: INTAKE_READINESS_VERSION,
    schema: INTAKE_READINESS_SCHEMA,
  }, null, 2)), true, 'Key order and insignificant whitespace must not affect a valid attestation.');

  process.env[INTAKE_READINESS_ENV] = encodedCompleteAttestation;
  assert.deepEqual(await responseBody(), { schema: 'arc-intake-readiness-v1', intake_enabled: true },
    'Injected future-compatible runtime proof keeps lower-level intake tests reachable.');
  assert.deepEqual(await responseBody(handler), { schema: 'arc-intake-readiness-v1', intake_enabled: false },
    'The compiled production marker remains OFF even when a simulated exact runtime proof is present.');

  assert.equal((await handler(new Request('https://arcsites.netlify.app/api/intake/readiness'))).status, 200);
  assert.equal((await handler(new Request('https://example.com/api/intake/readiness'))).status, 403);
  assert.equal((await handler(new Request('https://arcweb.onl/api/intake/readiness', { method: 'POST' }))).status, 405);
  assert.equal(config.path, '/api/intake/readiness');
  assert.equal(config.method, 'GET');

  const store = new FakeStore();
  delete process.env[INTAKE_READINESS_ENV];
  const disabled = await enabledSubmitHandler(submitRequest(), {
    get intakeStore() { throw new Error('Revoked intake must not touch storage.'); },
  });
  assert.equal(disabled.status, 503);
  assert.deepEqual(await disabled.json(), { error: 'intake_disabled' });

  process.env[INTAKE_READINESS_ENV] = JSON.stringify({ ...completeAttestation, arc1_consumer_adapter_verified: false });
  const incompatible = await enabledSubmitHandler(submitRequest(), {
    get intakeStore() { throw new Error('Unadapted ARC1 intake must not touch storage.'); },
  });
  assert.equal(incompatible.status, 503, 'The current Netlify-Forms ARC1 consumer must remain unusable.');

  for (const field of ['retention_verified', 'asset_pipeline_verified']) {
    process.env[INTAKE_READINESS_ENV] = JSON.stringify({ ...completeAttestation, [field]: false });
    const gated = await enabledSubmitHandler(submitRequest(), {
      get intakeStore() { throw new Error(`${field}=false must block before storage.`); },
    });
    assert.equal(gated.status, 503, `${field} must independently keep intake closed.`);
  }

  process.env[INTAKE_READINESS_ENV] = encodedCompleteAttestation;
  const metadataFile = validForm();
  metadataFile.append('asset_permission', 'Confirmed');
  metadataFile.append('logo_file', new Blob([pngWithChunk('tEXt')], { type: 'image/png' }), 'metadata.png');
  const metadataResponse = await enabledSubmitHandler(submitRequest(metadataFile), {
    get intakeStore() { throw new Error('Metadata-bearing uploads must be rejected before storage.'); },
  });
  assert.equal(metadataResponse.status, 400);
  assert.deepEqual(await metadataResponse.json(), { error: 'invalid_intake' });

  const unpermittedFile = validForm();
  unpermittedFile.append('logo_file', pngBlob(), 'logo.png');
  const unpermittedFileResponse = await enabledSubmitHandler(submitRequest(unpermittedFile), {
    get intakeStore() { throw new Error('Unpermitted files must be rejected before storage.'); },
  });
  assert.equal(unpermittedFileResponse.status, 400);
  const unpermittedFolder = validForm();
  unpermittedFolder.append('asset_folder_link', 'https://files.example.test/assets');
  const unpermittedFolderResponse = await enabledSubmitHandler(submitRequest(unpermittedFolder), {
    get intakeStore() { throw new Error('Disabled legacy folder links must be rejected before storage.'); },
  });
  assert.equal(unpermittedFolderResponse.status, 400);
  assert.deepEqual(await unpermittedFolderResponse.json(), { error: 'invalid_intake' });
  await assert.rejects(normalizeIntakeForm(unpermittedFolder), /unexpected intake field/i);

  process.env.ARC_INTAKE_ARC1_DISPATCH_ENABLED = 'false';
  delete process.env[INTAKE_IDEMPOTENCY_SECRET_ENV];
  const missingIdempotencyControl = await enabledSubmitHandler(submitRequest(), {
    get intakeStore() { throw new Error('Missing idempotency control must block before storage.'); },
  });
  assert.equal(missingIdempotencyControl.status, 503);
  process.env[INTAKE_IDEMPOTENCY_SECRET_ENV] = savedIdempotencySecret;
  const accepted = await enabledSubmitHandler(submitRequest(allNamedControlForm()), {
    intakeStore: store,
    clock: () => new Date('2026-08-13T08:00:00.000Z'),
    uuid: () => '11111111-1111-4111-8111-111111111111',
  });
  assert.equal(accepted.status, 201);
  const acceptedBody = await accepted.json();
  assert.equal(acceptedBody.schema, 'arc-intake-submission-accepted-v1');
  assert.equal(acceptedBody.accepted, true);
  assert.match(acceptedBody.submission_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(acceptedBody.submission_id, '11111111-1111-4111-8111-111111111111',
    'Public submission identity must derive from the private idempotency key, not caller-supplied randomness.');
  const stored = store.values.get(`submissions/${acceptedBody.submission_id}`);
  assert.equal(stored.schema, INTAKE_SUBMISSION_SCHEMA);
  assert.equal(stored.source, 'first-party-netlify-function');
  assert.equal(stored.form_name, 'arc-preview-function-v1');
  assert.equal(stored.arc1_consumer_compatible, false, 'Storage must not impersonate a native Netlify Forms submission.');
  assert.equal(stored.arc1_delivery.status, 'PENDING');
  assert.equal(stored.arc1_delivery.attempt_count, 0);
  assert.equal(stored.arc1_dispatch.status, 'PENDING');
  assert.equal(stored.arc1_dispatch.attempt_count, 0, 'Default-OFF dispatch must not invoke a background function.');
  assert.equal(stored.data.primary_style, 'Modern');
  assert.match(stored.submission_data_sha256, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(stored).includes('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'), false,
    'The raw browser idempotency nonce must never enter durable customer records.');
  assert.equal(store.calls, 1);

  const exactRetry = await enabledSubmitHandler(submitRequest(allNamedControlForm()), {
    intakeStore: store,
    clock: () => new Date('2026-08-13T08:05:00.000Z'),
    uuid: () => '22222222-2222-4222-8222-222222222222',
  });
  assert.equal(exactRetry.status, 200, 'A lost-response retry must recover the original durable acceptance.');
  assert.deepEqual(await exactRetry.json(), acceptedBody);
  assert.equal(store.values.size, 1, 'An exact retry must not create a duplicate lead.');

  const changedRetryForm = allNamedControlForm();
  changedRetryForm.set('business', 'Changed after ambiguous response');
  const changedRetry = await enabledSubmitHandler(submitRequest(changedRetryForm), { intakeStore: store });
  assert.equal(changedRetry.status, 409);
  assert.deepEqual(await changedRetry.json(), { error: 'intake_conflict' });
  assert.equal(store.values.size, 1, 'A reused nonce with changed answers must fail closed.');
  assert.equal(store.calls, 3);

  const ambiguousForm = allNamedControlForm();
  ambiguousForm.set('submission_request_id', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
  const ambiguousStore = new AmbiguousWriteStore();
  const ambiguousAccepted = await enabledSubmitHandler(submitRequest(ambiguousForm), {
    intakeStore: ambiguousStore,
    clock: () => new Date('2026-08-13T08:10:00.000Z'),
  });
  assert.equal(ambiguousAccepted.status, 200,
    'A strong read after an ambiguous create response must recover the durable acceptance.');
  assert.equal(ambiguousStore.values.size, 1);

  process.env[INTAKE_READINESS_ENV] = JSON.stringify({ ...completeAttestation, route_verified: false });
  const revoked = await enabledSubmitHandler(submitRequest(), { intakeStore: store });
  assert.equal(revoked.status, 503);
  assert.equal(store.calls, 3, 'Revocation must block before any further storage write.');

  process.env[INTAKE_READINESS_ENV] = encodedCompleteAttestation;
  assert.equal((await enabledSubmitHandler(submitRequest(validForm(), 'https://example.com'), { intakeStore: store })).status, 403);
  assert.equal((await enabledSubmitHandler(new Request('https://arcweb.onl/api/intake/submit', { method: 'GET' }), { intakeStore: store })).status, 405);
  const oversized = await enabledSubmitHandler({
    method: 'POST',
    url: 'https://arcweb.onl/api/intake/submit',
    headers: new Headers({
      origin: 'https://arcweb.onl',
      'content-type': 'multipart/form-data; boundary=arc-test-boundary',
      'content-length': String(INTAKE_MAX_REQUEST_BYTES + 1),
    }),
    formData() { throw new Error('Oversized intake must be rejected before body parsing.'); },
  }, {
    get intakeStore() { throw new Error('Oversized intake must be rejected before storage.'); },
  });
  assert.equal(oversized.status, 413);
  assert.deepEqual(await oversized.json(), { error: 'intake_too_large' });
  const chunkedOversized = new Request('https://arcweb.onl/api/intake/submit', {
    method: 'POST',
    headers: { origin: 'https://arcweb.onl', 'content-type': 'multipart/form-data; boundary=arc-chunked-boundary' },
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(2_000_000));
        controller.enqueue(new Uint8Array(2_000_001));
        controller.close();
      },
    }),
    duplex: 'half',
  });
  assert.equal(chunkedOversized.headers.get('content-length'), null);
  const boundedChunked = await enabledSubmitHandler(chunkedOversized, {
    get intakeStore() { throw new Error('Chunked oversized intake must be rejected before storage.'); },
  });
  assert.equal(boundedChunked.status, 413);
  assert.deepEqual(await boundedChunked.json(), { error: 'intake_too_large' });
  assert.equal((await enabledSubmitHandler(new Request('https://arcweb.onl/api/intake/submit', {
    method: 'POST', headers: { origin: 'https://arcweb.onl', 'content-type': 'application/x-www-form-urlencoded' }, body: 'name=test',
  }), { intakeStore: store })).status, 415);
  const unknown = validForm();
  unknown.append('client_claims_ready', 'true');
  assert.equal((await enabledSubmitHandler(submitRequest(unknown), { intakeStore: store })).status, 400);
  assert.equal(store.calls, 3);
  assert.equal(submitConfig.path, '/api/intake/submit');
  assert.equal(submitConfig.method, 'POST');
  assert.equal(submitConfig.rateLimit.windowLimit, 5);
} finally {
  if (saved.attestation === undefined) delete process.env[INTAKE_READINESS_ENV];
  else process.env[INTAKE_READINESS_ENV] = saved.attestation;
  if (saved.buildIntake === undefined) delete process.env.ARC_BUILD_INTAKE_ENABLED;
  else process.env.ARC_BUILD_INTAKE_ENABLED = saved.buildIntake;
  if (saved.legacyIntake === undefined) delete process.env.ARC_INTAKE_ENABLED;
  else process.env.ARC_INTAKE_ENABLED = saved.legacyIntake;
  if (saved.legacyRoute === undefined) delete process.env.ARC_LEAD_ROUTE_VERIFIED;
  else process.env.ARC_LEAD_ROUTE_VERIFIED = saved.legacyRoute;
  if (saved.adapterProof === undefined) delete process.env[INTAKE_ARC1_ADAPTER_PROOF_ENV];
  else process.env[INTAKE_ARC1_ADAPTER_PROOF_ENV] = saved.adapterProof;
  if (saved.adapterProofSecret === undefined) delete process.env.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET;
  else process.env.ARC_INTAKE_ARC1_ADAPTER_PROOF_SECRET = saved.adapterProofSecret;
  for (const [key, value] of Object.entries(bridgeRuntimeSaved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

console.log('ARC intake readiness attestation contract passed.');
