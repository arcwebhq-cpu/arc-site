import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import handler, { config, createIntakeReadinessHandler } from '../netlify/functions/intake-readiness.mjs';
import submitHandler, { config as submitConfig, createIntakeSubmitHandler } from '../netlify/functions/intake-submit.mjs';
import {
  INTAKE_BUILD_MARKER_SCHEMA,
  INTAKE_BUILD_MARKER_VERSION,
  INTAKE_READINESS_BOOLEAN_FIELDS,
  INTAKE_READINESS_ENV,
  INTAKE_READINESS_SCHEMA,
  INTAKE_READINESS_VERSION,
  intakeEnabledFromAttestation,
  intakeEnabledFromBuildMarker,
} from '../netlify/lib/intake-readiness-core.mjs';
import {
  BUDGET_CONFIRMATION,
  INTAKE_ALLOWED_FIELDS,
  INTAKE_FILE_FIELDS,
  INTAKE_MAX_FILE_BYTES,
  INTAKE_MAX_REQUEST_BYTES,
  INTAKE_MAX_TOTAL_FILE_BYTES,
  INTAKE_SUBMISSION_SCHEMA,
  TERMS_CONFIRMATION,
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
}

const validForm = () => {
  const form = new FormData();
  for (const [field, value] of Object.entries({
    intake_version: 'arc-intake-v7',
    name: 'Test Owner',
    email: 'owner@example.test',
    business: 'Test Roofing',
    industry: 'Roofing',
    city: 'Everett, WA',
    main_services: 'Roof replacement',
    main_call_to_action: 'Request Estimate',
    primary_style: 'Modern',
    budget_confirmed: BUDGET_CONFIRMATION,
    terms_accepted: TERMS_CONFIRMATION,
    'bot-field': '',
  })) form.append(field, value);
  form.append('goals', 'More calls');
  form.append('goals', 'Estimate requests');
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

const pngBlob = (size = 8) => {
  const bytes = new Uint8Array(size);
  bytes.set([137, 80, 78, 71, 13, 10, 26, 10]);
  return new Blob([bytes], { type: 'image/png' });
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
    intake_version: 'arc-intake-v7',
    main_call_to_action: 'Request Estimate',
    main_services: 'Roof replacement',
    name: 'Test Owner',
    primary_style: 'Modern',
    terms_accepted: TERMS_CONFIRMATION,
  };
  for (const field of actualNamedControlFields) {
    if (INTAKE_FILE_FIELDS.includes(field)) form.append(field, pngBlob(), `${field}.png`);
    else form.append(field, exactValues[field] ?? 'Contract test value');
  }
  return form;
};

const enabledBuildMarker = Object.freeze({
  schema: INTAKE_BUILD_MARKER_SCHEMA,
  version: INTAKE_BUILD_MARKER_VERSION,
  intake_enabled: true,
});
const enabledReadinessHandler = createIntakeReadinessHandler(enabledBuildMarker);
const enabledSubmitHandler = createIntakeSubmitHandler(enabledBuildMarker);
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
  actualNamedControlFields.filter((field) => field !== 'bot-field' && !INTAKE_FILE_FIELDS.includes(field)).sort(),
  'A form assembled from every actual named control must survive normalization without dropping fields.',
);
assert.deepEqual(normalizedRealForm.record.asset_manifest.map(({ field }) => field).sort(), [...INTAKE_FILE_FIELDS].sort());

const tooLargeFileForm = validForm();
tooLargeFileForm.append('asset_permission', 'Confirmed');
tooLargeFileForm.append('logo_file', pngBlob(INTAKE_MAX_FILE_BYTES + 1), 'logo.png');
await assert.rejects(normalizeIntakeForm(tooLargeFileForm), /file size is invalid/i);
const tooLargeTotalForm = validForm();
tooLargeTotalForm.append('asset_permission', 'Confirmed');
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
const saved = {
  attestation: process.env[INTAKE_READINESS_ENV],
  buildIntake: process.env.ARC_BUILD_INTAKE_ENABLED,
  legacyIntake: process.env.ARC_INTAKE_ENABLED,
  legacyRoute: process.env.ARC_LEAD_ROUTE_VERIFIED,
};

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
  assert.deepEqual(await responseBody(), { schema: 'arc-intake-readiness-v1', intake_enabled: true });

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
  const unpermittedFile = validForm();
  unpermittedFile.append('logo_file', pngBlob(), 'logo.png');
  const unpermittedFileResponse = await enabledSubmitHandler(submitRequest(unpermittedFile), {
    get intakeStore() { throw new Error('Unpermitted files must be rejected before storage.'); },
  });
  assert.equal(unpermittedFileResponse.status, 400);
  const unpermittedFolder = validForm();
  unpermittedFolder.append('asset_folder_link', 'https://files.example.test/assets');
  const unpermittedFolderResponse = await enabledSubmitHandler(submitRequest(unpermittedFolder), {
    get intakeStore() { throw new Error('Unpermitted folder links must be rejected before storage.'); },
  });
  assert.equal(unpermittedFolderResponse.status, 400);

  const accepted = await enabledSubmitHandler(submitRequest(allNamedControlForm()), {
    intakeStore: store,
    clock: () => new Date('2026-08-13T08:00:00.000Z'),
    uuid: () => '11111111-1111-4111-8111-111111111111',
  });
  assert.equal(accepted.status, 201);
  assert.deepEqual(await accepted.json(), {
    schema: 'arc-intake-submission-accepted-v1', accepted: true, submission_id: '11111111-1111-4111-8111-111111111111',
  });
  const stored = store.values.get('submissions/11111111-1111-4111-8111-111111111111');
  assert.equal(stored.schema, INTAKE_SUBMISSION_SCHEMA);
  assert.equal(stored.source, 'first-party-netlify-function');
  assert.equal(stored.form_name, 'arc-preview-function-v1');
  assert.equal(stored.arc1_consumer_compatible, false, 'Storage must not impersonate a native Netlify Forms submission.');
  assert.equal(stored.data.primary_style, 'Modern');
  assert.match(stored.submission_data_sha256, /^[a-f0-9]{64}$/);
  assert.equal(store.calls, 1);

  process.env[INTAKE_READINESS_ENV] = JSON.stringify({ ...completeAttestation, route_verified: false });
  const revoked = await enabledSubmitHandler(submitRequest(), { intakeStore: store });
  assert.equal(revoked.status, 503);
  assert.equal(store.calls, 1, 'Revocation must block before any second storage write.');

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
  assert.equal(store.calls, 1);
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
}

console.log('ARC intake readiness attestation contract passed.');
