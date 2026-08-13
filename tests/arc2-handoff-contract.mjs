import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  ARTIFACT_SIGNATURE_PREFIX,
  canonicalJson,
  CLAIM_STATE_EVIDENCE_SCOPE,
  CLAIM_STATE_SIGNATURE_PREFIX,
  configuredEnvironment,
  createClaimStateEvidence,
  createStoredZip,
  handoffKeyFromId,
  hmacHex,
  LEAD_RECIPIENT_PREFIX,
  normalizeStartPayload,
  PAYMENT_SIGNATURE_PREFIX,
  netlifyClaimUrl,
  resolveHandoffEnvironment,
  sha256Hex,
  transitionRecord,
  validateExpectedBindings,
} from '../netlify/lib/arc2-handoff-core.mjs';
import { createEntry, createIndex, readEntry, replaceEntry } from '../netlify/lib/arc2-handoff-store.mjs';
import {
  getHandoffStatus,
  markClaimInvitationReady,
  processClaimWebhook,
  startHandoff,
} from '../netlify/lib/arc2-handoff-service.mjs';
import claimHandler, { config as claimConfig } from '../netlify/functions/arc2-claim.mjs';
import webhookHandler, { config as webhookConfig } from '../netlify/functions/arc2-claim-webhook.mjs';
import invitationHandler, { config as invitationConfig } from '../netlify/functions/arc2-claim-invitation-ready.mjs';
import startHandler, { config as startConfig } from '../netlify/functions/arc2-handoff-start.mjs';
import statusHandler, { config as statusConfig } from '../netlify/functions/arc2-handoff-status.mjs';

const now = new Date('2026-08-12T18:00:00.000Z');
const secrets = Object.fromEntries([
  'ARC_CHECKOUT_BINDING_SECRET',
  'ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET',
  'ARC_LEAD_ROUTE_EVIDENCE_SECRET',
  'ARC_HANDOFF_STATE_SECRET',
  'ARC_HANDOFF_TRIGGER_SECRET',
  'ARC_CLAIM_TOKEN_SECRET',
  'ARC_CLAIM_STATE_EVIDENCE_SECRET',
  'ARC_EMAIL_CLAIM_BINDING_SECRET',
  'ARC_FINAL_DELIVERY_RECEIPT_SECRET',
  'ARC_FINAL_DELIVERY_ACK_SECRET',
  'NETLIFY_ADMIN_PAT',
  'NETLIFY_OAUTH_CLIENT_SECRET',
].map((name, index) => [name, `${name.toLowerCase()}-${String(index).padStart(2, '0')}-unique-test-secret-0123456789`]));
const env = {
  ...secrets,
  ARC_HANDOFF_ENABLED: 'true',
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_EXPECTED_PAYMENT_LINK_ID: 'plink_1ArcHandoffTest',
  ARC_EXPECTED_PRICE_ID: 'price_1ArcHandoffTest',
  ARC_EXPECTED_PRODUCT_TAX_CODE: 'txcd_10000000',
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256: sha256Hex('acct_arc_test'),
  ARC_ADULT_OPERATOR_VERIFIED: 'true',
  ARC_BUSINESS_LICENSE_VERIFIED: 'true',
  ARC_TAX_REGISTRATION_VERIFIED: 'true',
  ARC_TRANSACTIONAL_EMAIL_VERIFIED: 'true',
  ARC_RETENTION_CONTROL_VERIFIED: 'true',
  ARC_POSTCLAIM_READBACK_VERIFIED: 'true',
  ARC_DEVICE_QA_VERIFIED: 'true',
  ARC_LEAD_ROUTE_VERIFIED: 'true',
  ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
  ARC_PUBLIC_ORIGIN: 'https://arcweb.onl/',
  SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  SITE_NAME: 'arcsites',
  URL: 'https://arcweb.onl/',
  DEPLOY_PRIME_URL: 'https://main--arcsites.netlify.app/',
  NETLIFY_TEAM_SLUG: 'arc-team',
  NETLIFY_TEAM_ACCOUNT_ID: 'account-source-123',
  NETLIFY_OAUTH_CLIENT_ID: 'oauth-client-123',
};
assert.deepEqual(configuredEnvironment(env), { enabled: true, missing: [], invalid: [] });
const tokenAliasEnv = { ...env, NETLIFY_ACCESS_TOKEN: env.NETLIFY_ADMIN_PAT };
delete tokenAliasEnv.NETLIFY_ADMIN_PAT;
assert.equal(configuredEnvironment(tokenAliasEnv).enabled, true, 'Workflow-facing Netlify token alias must satisfy runtime readiness.');
assert.equal(resolveHandoffEnvironment(tokenAliasEnv).environment.NETLIFY_ADMIN_PAT, env.NETLIFY_ADMIN_PAT);
const taxCodeAliasEnv = { ...env, ARC_EXPECTED_STRIPE_PRODUCT_TAX_CODE: env.ARC_EXPECTED_PRODUCT_TAX_CODE };
delete taxCodeAliasEnv.ARC_EXPECTED_PRODUCT_TAX_CODE;
assert.equal(configuredEnvironment(taxCodeAliasEnv).enabled, true, 'Workflow-facing Stripe tax-code alias must satisfy runtime readiness.');
assert.equal(resolveHandoffEnvironment(taxCodeAliasEnv).environment.ARC_EXPECTED_PRODUCT_TAX_CODE, env.ARC_EXPECTED_PRODUCT_TAX_CODE);
assert.equal(configuredEnvironment({
  ...env,
  NETLIFY_ACCESS_TOKEN: env.NETLIFY_ADMIN_PAT,
  ARC_EXPECTED_STRIPE_PRODUCT_TAX_CODE: env.ARC_EXPECTED_PRODUCT_TAX_CODE,
}).enabled, true, 'Matching canonical and alias values must be accepted.');
const conflictingAliases = configuredEnvironment({
  ...env,
  NETLIFY_ACCESS_TOKEN: `${env.NETLIFY_ADMIN_PAT}-different`,
  ARC_EXPECTED_STRIPE_PRODUCT_TAX_CODE: 'txcd_99999999',
});
assert.equal(conflictingAliases.enabled, false, 'Conflicting canonical and alias values must fail closed.');
assert.ok(conflictingAliases.invalid.includes('NETLIFY_ADMIN_PAT_NETLIFY_ACCESS_TOKEN_CONFLICT'));
assert.ok(conflictingAliases.invalid.includes('ARC_EXPECTED_PRODUCT_TAX_CODE_ARC_EXPECTED_STRIPE_PRODUCT_TAX_CODE_CONFLICT'));
assert.equal(configuredEnvironment({ ...env, ARC_CLAIM_TOKEN_SECRET: env.ARC_HANDOFF_STATE_SECRET }).enabled, false, 'Secrets must be distinct.');
assert.equal(configuredEnvironment({ ...env, ARC_TAX_REGISTRATION_VERIFIED: 'false' }).enabled, false, 'Manual attestations must be exact and fail closed.');
assert.equal(configuredEnvironment({ ...env, ARC_STRIPE_LIVE_MODE_ENABLED: 'yes' }).enabled, false, 'Stripe mode must be an explicit boolean string.');
assert.equal(configuredEnvironment({}).enabled, false, 'Missing configuration must fail closed.');
assert.equal(configuredEnvironment({ ...env, SITE_ID: '00000000-0000-4000-8000-000000000000' }).enabled, false, 'Wrong Netlify site must fail closed.');
assert.equal(configuredEnvironment({ ...env, SITE_NAME: 'attacker-site' }).enabled, false, 'Wrong Netlify site name must fail closed.');
assert.equal(configuredEnvironment({ ...env, DEPLOY_PRIME_URL: 'https://deploy-preview-7--arcsites.netlify.app/' }).enabled, true, 'Per-deploy URL must not be mistaken for the canonical production identity.');
assert.equal(configuredEnvironment({ ...env, URL: 'https://attacker.example/' }).enabled, false, 'Wrong canonical production origin must fail closed.');

const headersFile = '/*\n  X-Robots-Tag: noindex, nofollow, noarchive\n';
const html = '<!doctype html><form name="sample-lead" method="POST" data-netlify="true"><input name="email"></form>\n';
const artifactsWithBytes = [
  { path: '_headers', bytes: Buffer.from(headersFile) },
  { path: 'index.html', bytes: Buffer.from(html) },
];
const artifacts = artifactsWithBytes.map(({ path, bytes }) => ({ path, sha256: sha256Hex(bytes), size: bytes.length }));
const artifactEvidenceObject = {
  version: 'arc2-handoff-artifact-evidence-v1',
  scope: 'netlify-claimable-deploy-artifacts',
  preview_folder: 'sample-roofing-a1b2c3d4',
  production_content_sha256: sha256Hex(html),
  artifact_manifest_sha256: sha256Hex(canonicalJson(artifacts)),
  bundle_fingerprint: sha256Hex(`_headers\0${headersFile}\0index.html\0${html}\0`),
  artifacts,
  issued_at: new Date(now.getTime() - 60_000).toISOString(),
};
const artifactEvidence = canonicalJson(artifactEvidenceObject);
const customerEmail = 'buyer@example.test';
const leadEmail = 'leads@example.test';
const paymentEvidenceObject = {
  version: 'arc2-payment-evidence-v2',
  scope: 'authoritative-stripe-checkout-session',
  checkout_session_id: 'cs_test_arc2_handoff_contract',
  client_reference_id_sha256: sha256Hex('sample-reference'),
  preview_folder: artifactEvidenceObject.preview_folder,
  production_content_sha256: artifactEvidenceObject.production_content_sha256,
  artifact_manifest_sha256: artifactEvidenceObject.artifact_manifest_sha256,
  handoff_artifact_evidence_sha256: sha256Hex(artifactEvidence),
  bundle_fingerprint: artifactEvidenceObject.bundle_fingerprint,
  customer_email_sha256: sha256Hex(customerEmail),
  livemode: false,
  mode: 'payment',
  status: 'complete',
  payment_status: 'paid',
  currency: 'usd',
  subtotal_amount_minor_units: 500000,
  tax_amount_minor_units: 50000,
  amount_total_minor_units: 550000,
  automatic_tax_enabled: true,
  automatic_tax_status: 'complete',
  price_tax_behavior: 'exclusive',
  product_tax_code: 'txcd_10000000',
  tax_contract_version: 'arc-tax-v1',
  tax_registrations_sha256: sha256Hex('wa-tax-registration-evidence'),
  customer_address_sha256: sha256Hex('buyer-destination-address'),
  customer_address_country: 'US',
  customer_address_state: 'WA',
  customer_address_status: 'verified',
  tax_registration_status: 'verified',
  stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
  payment_link_id: env.ARC_EXPECTED_PAYMENT_LINK_ID,
  price_id: env.ARC_EXPECTED_PRICE_ID,
  quantity: 1,
  terms_of_service_consent: 'accepted',
  terms_version: '2026-08-12',
  adult_purchaser_acknowledgement: 'accepted',
};
const paymentEvidence = canonicalJson(paymentEvidenceObject);
const input = {
  artifact_evidence: artifactEvidence,
  artifact_evidence_hmac_sha256: hmacHex(env.ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET, `${ARTIFACT_SIGNATURE_PREFIX}${artifactEvidence}`),
  deploy_artifacts: canonicalJson(artifactsWithBytes.map(({ path, bytes }) => ({ path, content_base64: bytes.toString('base64') }))),
  lead_notification_email: leadEmail,
  lead_route_recipient_hmac_sha256: hmacHex(env.ARC_LEAD_ROUTE_EVIDENCE_SECRET, `${LEAD_RECIPIENT_PREFIX}${leadEmail}`),
  payment_evidence: paymentEvidence,
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}${paymentEvidence}`),
};

const normalized = normalizeStartPayload(input, env, now);
assert.equal(normalized.formName, 'sample-lead');
assert.equal(normalized.leadEmail, leadEmail);
assert.equal(normalized.leadRouteRecipientHmacSha256, input.lead_route_recipient_hmac_sha256);
assert.doesNotThrow(() => normalizeStartPayload(input, taxCodeAliasEnv, now), 'Tax-code alias must be used by payment binding, not readiness alone.');
assert.throws(() => normalizeStartPayload(input, {
  ...env,
  ARC_EXPECTED_STRIPE_PRODUCT_TAX_CODE: 'txcd_99999999',
}, now), /environment aliases conflict/i);
assert.throws(() => normalizeStartPayload({ ...input, lead_notification_email: 'attacker@example.test' }, env, now), /unbound/);
const wrongPriceObject = { ...paymentEvidenceObject, price_id: 'price_1Wrong' };
const wrongPrice = canonicalJson(wrongPriceObject);
assert.throws(() => normalizeStartPayload({
  ...input,
  payment_evidence: wrongPrice,
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}${wrongPrice}`),
}, env, now), /Payment evidence bindings/);
for (const mutation of [
  { amount_total_minor_units: 500000 },
  { tax_amount_minor_units: 0 },
  { automatic_tax_enabled: false },
  { automatic_tax_status: 'requires_location_inputs' },
  { price_tax_behavior: 'inclusive' },
  { product_tax_code: 'not-a-tax-code' },
  { tax_contract_version: 'arc-tax-v0' },
  { customer_address_sha256: 'not-a-hash' },
  { customer_address_country: 'usa' },
  { customer_address_state: '' },
  { customer_address_status: 'unverified' },
  { tax_registration_status: 'unverified' },
  { stripe_account_id_sha256: sha256Hex('acct_wrong') },
  { livemode: true },
  { checkout_session_id: 'cs_live_wrong_mode' },
]) {
  const tamperedObject = { ...paymentEvidenceObject, ...mutation };
  const tampered = canonicalJson(tamperedObject);
  assert.throws(() => normalizeStartPayload({
    ...input,
    payment_evidence: tampered,
    payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}${tampered}`),
  }, env, now), /invalid|Payment evidence bindings/i);
}
const livePaymentObject = { ...paymentEvidenceObject, livemode: true, checkout_session_id: 'cs_live_arc2_handoff_contract' };
const livePayment = canonicalJson(livePaymentObject);
assert.doesNotThrow(() => normalizeStartPayload({
  ...input,
  payment_evidence: livePayment,
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}${livePayment}`),
}, { ...env, ARC_STRIPE_LIVE_MODE_ENABLED: 'true' }, now));
const nonUsPaymentObject = { ...paymentEvidenceObject, customer_address_country: 'CA', customer_address_state: '' };
const nonUsPayment = canonicalJson(nonUsPaymentObject);
assert.doesNotThrow(() => normalizeStartPayload({
  ...input,
  payment_evidence: nonUsPayment,
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}${nonUsPayment}`),
}, env, now));
assert.throws(() => transitionRecord({ state: 'SITE_INTENT' }, 'DELIVERED'), /Invalid handoff transition/);

const zip = createStoredZip(artifactsWithBytes);
assert.equal(zip.readUInt32LE(0), 0x04034b50);
assert.equal(zip.readUInt32LE(zip.length - 22), 0x06054b50);
assert.equal(zip.includes(Buffer.from(headersFile)), true);
assert.equal(zip.includes(Buffer.from(html)), true);

class FakeStore {
  constructor() {
    this.values = new Map();
    this.counter = 0;
  }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag, metadata: {} } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && (!current || current.etag !== options.onlyIfMatch)) return { modified: false };
    const etag = `etag-${++this.counter}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
}

const storeContract = new FakeStore();
const firstEntry = await createEntry(storeContract, 'handoffs/test', { schema: 'bad-on-read' });
assert.equal(firstEntry.etag, 'etag-1');
assert.equal(await createEntry(storeContract, 'handoffs/test', {}), null);
await assert.rejects(replaceEntry(storeContract, 'handoffs/test', { etag: 'wrong' }, {}), /STATE_CONTENTION/);
const racedIndexes = await Promise.allSettled([
  createIndex(storeContract, 'checkout-session-index/concurrent', { handoff_id: 'a'.repeat(64) }),
  createIndex(storeContract, 'checkout-session-index/concurrent', { handoff_id: 'b'.repeat(64) }),
]);
assert.equal(racedIndexes.filter(({ status }) => status === 'fulfilled').length, 1, 'A checkout-session index race must have one winner.');
assert.equal(racedIndexes.filter((result) => result.status === 'rejected' && /INDEX_CONFLICT/.test(String(result.reason))).length, 1);

const siteId = 'site-arc123';
const deployId = 'deploy-arc123';
const formId = 'form-arc123';
const hookId = 'hook-arc123';
const fetchCalls = [];
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
const fakeFetch = async (url, options = {}) => {
  fetchCalls.push({ url: String(url), method: options.method || 'GET', authorization: options.headers?.Authorization });
  const parsed = new URL(url);
  const path = `${parsed.pathname}${parsed.search}`;
  if (String(url) === `https://arc-lead-route-${hmacHex(env.ARC_HANDOFF_STATE_SECRET, `site-name-v1\n${paymentEvidenceObject.checkout_session_id}\n${paymentEvidenceObject.bundle_fingerprint}`).slice(0, 24)}.netlify.app/`) return new Response(html, { headers: { 'x-robots-tag': 'noindex, nofollow' } });
  if (path.startsWith('/api/v1/sites?name=') && path.endsWith('&filter=owner')) return json([]);
  if (path === '/api/v1/sites' && options.method === 'POST') return json({
    id: siteId,
    name: 'arc-lead-route-' + hmacHex(env.ARC_HANDOFF_STATE_SECRET, `site-name-v1\n${paymentEvidenceObject.checkout_session_id}\n${paymentEvidenceObject.bundle_fingerprint}`).slice(0, 24),
    session_id: '11111111-1111-4111-8111-111111111111',
    account_id: env.NETLIFY_TEAM_ACCOUNT_ID,
    account_slug: env.NETLIFY_TEAM_SLUG,
  }, 201);
  if (path.startsWith(`/api/v1/sites/${siteId}/deploys?`) && options.method === 'POST') return json({ id: deployId, site_id: siteId });
  if (path === `/api/v1/sites/${siteId}/deploys?per_page=100` && options.method !== 'POST') return json([]);
  if (path === `/api/v1/deploys/${deployId}`) return json({ id: deployId, site_id: siteId, state: 'ready' });
  if (path === `/api/v1/sites/${siteId}/forms`) return json([{ id: formId, site_id: siteId, name: 'sample-lead' }]);
  if (path === `/api/v1/hooks?site_id=${siteId}` && options.method === 'GET') {
    const hookCreated = fetchCalls.some((call) => call.url.endsWith(`/hooks?site_id=${siteId}`) && call.method === 'POST');
    return json(hookCreated ? [{ id: hookId, site_id: siteId, form_id: formId, type: 'email', event: 'submission_created', data: { email: leadEmail } }] : []);
  }
  if (path === `/api/v1/hooks?site_id=${siteId}` && options.method === 'POST') return json({
    id: hookId, site_id: siteId, form_id: formId, type: 'email', event: 'submission_created', data: { email: leadEmail },
  }, 201);
  if (path === `/api/v1/sites/${siteId}`) return json({
    id: siteId,
    name: 'arc-lead-route-' + hmacHex(env.ARC_HANDOFF_STATE_SECRET, `site-name-v1\n${paymentEvidenceObject.checkout_session_id}\n${paymentEvidenceObject.bundle_fingerprint}`).slice(0, 24),
    session_id: '11111111-1111-4111-8111-111111111111',
    account_id: env.NETLIFY_TEAM_ACCOUNT_ID,
    account_slug: env.NETLIFY_TEAM_SLUG,
    published_deploy: { id: deployId },
    ssl_url: 'https://attacker.example/',
    url: 'https://169.254.169.254/',
  });
  if (path === `/api/v1/accounts/${env.NETLIFY_TEAM_ACCOUNT_ID}`) return json({ id: env.NETLIFY_TEAM_ACCOUNT_ID });
  if (path === `/api/v1/sites/${siteId}/deploys/${deployId}`) return json({ id: deployId, site_id: siteId, state: 'ready' });
  if (path === `/api/v1/sites/${siteId}/files`) return json(artifacts.map((artifact) => ({ path: `/${artifact.path}`, size: artifact.size })));
  if (path === `/api/v1/sites/${siteId}/files/_headers`) return options.headers?.['Content-Type'] === 'application/vnd.bitballoon.v1.raw'
    ? new Response(headersFile) : json({ error: 'raw-media-type-required' });
  if (path === `/api/v1/sites/${siteId}/files/index.html`) return options.headers?.['Content-Type'] === 'application/vnd.bitballoon.v1.raw'
    ? new Response(html) : json({ error: 'raw-media-type-required' });
  throw new Error(`Unexpected fake request: ${options.method || 'GET'} ${url}`);
};

const store = new FakeStore();
const adapters = {
  store,
  fetch: fakeFetch,
  clock: () => new Date(now),
  uuid: () => '11111111-1111-4111-8111-111111111111',
  wait: () => Promise.resolve(),
};
const started = await startHandoff(input, tokenAliasEnv, adapters);
assert.equal(started.record.state, 'PRECLAIM_DEPLOY_READY');
assert.equal(started.record.claim_token_expires_at, null, 'Claim TTL must not begin before durable invitation acknowledgement.');
assert.equal(started.record.lead_notification_email_sha256, sha256Hex(leadEmail));
assert.equal(started.record.lead_route_recipient_hmac_sha256, input.lead_route_recipient_hmac_sha256);
assert.ok(fetchCalls.some((call) => call.authorization === `Bearer ${env.NETLIFY_ADMIN_PAT}`), 'Netlify token alias must reach authenticated runtime requests.');
assert.equal(JSON.stringify([...store.values.values()]).includes(leadEmail), false, 'Raw lead email must not enter handoff storage.');
assert.equal(fetchCalls.some((call) => /attacker\.example|169\.254\.169\.254/.test(call.url)), false, 'Destination-controlled site URLs must never be fetched.');

const legacyStartStore = new FakeStore();
const legacyStartRecord = {
  ...started.record,
  schema: 'arc2-netlify-handoff-v1',
  netlify_site_name: `arc-${'b'.repeat(24)}`,
};
delete legacyStartRecord.lead_route_recipient_hmac_sha256;
for (const field of [
  'final_delivery_receipt_sha256',
  'final_delivery_provider',
  'final_delivery_provider_account_hmac_sha256',
  'final_delivery_provider_event_id_hmac_sha256',
  'final_delivery_provider_message_id_hmac_sha256',
  'final_delivery_event_type',
  'final_delivery_status',
  'final_delivery_receipt_issued_at',
]) delete legacyStartRecord[field];
await createEntry(legacyStartStore, handoffKeyFromId(started.handoffId), legacyStartRecord);
const legacyStartSnapshot = JSON.stringify([...legacyStartStore.values.entries()]);
const legacyStartFetchCount = fetchCalls.length;
await assert.rejects(startHandoff(input, env, { ...adapters, store: legacyStartStore }),
  /ARC2_LEGACY_SITE_NAMESPACE_QUARANTINED/,
  'An exact authenticated start replay must quarantine an old-namespace pre-invitation record.');
assert.equal(JSON.stringify([...legacyStartStore.values.entries()]), legacyStartSnapshot,
  'Legacy namespace quarantine must happen before index creation or record repair.');
assert.equal(fetchCalls.length, legacyStartFetchCount,
  'Legacy namespace quarantine must happen before Netlify recovery or verification.');

const callCount = fetchCalls.length;
const replay = await startHandoff(input, env, adapters);
assert.equal(replay.idempotentReplay, true);
assert.equal('claimToken' in replay, false, 'Start must never issue or return a claim bearer.');
assert.ok(fetchCalls.length > callCount, 'Idempotent replay must reverify persisted preclaim state before returning.');
const staleReplay = await startHandoff(input, env, { ...adapters, clock: () => new Date(now.getTime() + 25 * 60 * 60_000) });
assert.equal(staleReplay.idempotentReplay, true, 'Exact immutable state must remain resumable after evidence freshness expires.');
const freshStore = new FakeStore();
await assert.rejects(startHandoff(input, env, { ...adapters, store: freshStore, clock: () => new Date(now.getTime() + 25 * 60 * 60_000) }), /stale/);

const alternateHtml = '<!doctype html><form name="sample-lead" method="POST" data-netlify="true"><input name="email"></form><p>alternate</p>\n';
const alternateArtifactsWithBytes = [
  { path: '_headers', bytes: Buffer.from(headersFile) },
  { path: 'index.html', bytes: Buffer.from(alternateHtml) },
];
const alternateArtifacts = alternateArtifactsWithBytes.map(({ path, bytes }) => ({ path, sha256: sha256Hex(bytes), size: bytes.length }));
const alternateArtifactObject = {
  ...artifactEvidenceObject,
  production_content_sha256: sha256Hex(alternateHtml),
  artifact_manifest_sha256: sha256Hex(canonicalJson(alternateArtifacts)),
  bundle_fingerprint: sha256Hex(`_headers\0${headersFile}\0index.html\0${alternateHtml}\0`),
  artifacts: alternateArtifacts,
};
const alternateArtifactEvidence = canonicalJson(alternateArtifactObject);
const alternatePaymentObject = {
  ...paymentEvidenceObject,
  production_content_sha256: alternateArtifactObject.production_content_sha256,
  artifact_manifest_sha256: alternateArtifactObject.artifact_manifest_sha256,
  handoff_artifact_evidence_sha256: sha256Hex(alternateArtifactEvidence),
  bundle_fingerprint: alternateArtifactObject.bundle_fingerprint,
};
const alternatePaymentEvidence = canonicalJson(alternatePaymentObject);
const alternateInput = {
  ...input,
  artifact_evidence: alternateArtifactEvidence,
  artifact_evidence_hmac_sha256: hmacHex(env.ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET, `${ARTIFACT_SIGNATURE_PREFIX}${alternateArtifactEvidence}`),
  deploy_artifacts: canonicalJson(alternateArtifactsWithBytes.map(({ path, bytes }) => ({ path, content_base64: bytes.toString('base64') }))),
  payment_evidence: alternatePaymentEvidence,
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}${alternatePaymentEvidence}`),
};
const beforeCheckoutConflict = fetchCalls.length;
await assert.rejects(startHandoff(alternateInput, env, adapters), /INDEX_CONFLICT/);
assert.equal(fetchCalls.length, beforeCheckoutConflict, 'Checkout-session bundle conflict must fail before any external write or read.');

const invitationAt = new Date(now.getTime() + 5 * 60_000);
const invitationAdapters = { ...adapters, clock: () => new Date(invitationAt) };
await assert.rejects(markClaimInvitationReady(started.handoffId, '{}', '0'.repeat(64), env, invitationAdapters), /evidence fields|signature/i);

// A future state model must distinguish durable invitation issuance from claim
// wrapper consumption. No current helper performs either transition; this
// synthetic record only contracts the official JWT and unsigned-callback gate.
const claimAt = new Date(invitationAt.getTime() + 60_000);
const claimAdapters = { ...adapters, clock: () => new Date(claimAt) };
let unreachable = await readEntry(store, handoffKeyFromId(started.handoffId));
unreachable = await replaceEntry(store, handoffKeyFromId(started.handoffId), unreachable, {
  ...unreachable.record,
  state: 'CLAIM_WRAPPER_CONSUMED',
  revision: unreachable.record.revision + 1,
  claim_invitation_ready_at: invitationAt.toISOString(),
  lead_route_provider_message_id_sha256: sha256Hex('provider-message-123'),
  lead_route_receipt_sha256: sha256Hex('lead-route-receipt'),
  claim_token_consumed_hmac_sha256: sha256Hex('consumed-claim-bearer'),
  claim_token_expires_at: new Date(invitationAt.getTime() + 30 * 60_000).toISOString(),
  claim_token_used_at: claimAt.toISOString(),
  claim_wrapper_consumed_at: claimAt.toISOString(),
  claim_jwt_issued_at: Math.floor(claimAt.getTime() / 1000),
  updated_at: invitationAt.toISOString(),
});
const randomClaimToken = 'random-opaque-claim-token-0123456789ABCDEFGHIJK';
assert.throws(() => validateExpectedBindings({ ...unreachable.record, claim_token_expires_at: 'not-a-date' }), /invalid|ISO timestamp/);
assert.throws(() => validateExpectedBindings({ ...unreachable.record, claim_token_expires_at: invitationAt.toISOString() }), /expiry ordering/);
const claimUrl = netlifyClaimUrl(unreachable.record, env);
assert.match(claimUrl, /^https:\/\/app\.netlify\.com\/claim#[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
const payload = JSON.parse(Buffer.from(claimUrl.split('#')[1].split('.')[1], 'base64url').toString());
assert.deepEqual(Object.keys(payload).sort(), ['claim_webhook', 'client_id', 'exp', 'iat', 'session_id']);
assert.equal(payload.claim_webhook, 'https://arcweb.onl/api/arc2/claim-webhook');
assert.equal(payload.iat, Math.floor(claimAt.getTime() / 1000));
assert.equal(payload.exp, Math.floor(new Date(invitationAt.getTime() + 30 * 60_000).getTime() / 1000));

const postClaimFetchCount = fetchCalls.length;
await assert.rejects(processClaimWebhook({
  claimed: true,
  site_id: siteId,
  destination_acc_id: 'account-customer-123',
}, env, claimAdapters), /SITE_NOT_CLAIMED/);
assert.ok(fetchCalls.length > postClaimFetchCount, 'Unsigned callback must be treated only as a hint and checked with source-creator readback.');
const callbackStatus = await getHandoffStatus(started.handoffId, env, claimAdapters);
assert.equal(callbackStatus.status, 'CLAIM_WRAPPER_CONSUMED');
assert.equal(callbackStatus.claim_available, false, 'Exchanged wrapper tokens must not be reported as unconsumed invitations.');
assert.equal(callbackStatus.claim_verified, false);
assert.equal('claim_state_evidence_private' in callbackStatus, false, 'Blocked post-claim state cannot authorize final email.');

const stored = await readEntry(store, handoffKeyFromId(started.handoffId));
const finalRecord = {
  ...stored.record,
  state: 'FINAL_DEPLOY_READY',
  destination_account_id: 'account-customer-123',
  final_deploy_id: 'deploy-final-123',
  production_url: `https://arc-lead-route-${hmacHex(env.ARC_HANDOFF_STATE_SECRET, `site-name-v1\n${paymentEvidenceObject.checkout_session_id}\n${paymentEvidenceObject.bundle_fingerprint}`).slice(0, 24)}.netlify.app/`,
  claim_callback_received_at: new Date(claimAt.getTime() + 30_000).toISOString(),
  claimed_verified_at: new Date(claimAt.getTime() + 60_000).toISOString(),
  final_deploy_ready_at: new Date(claimAt.getTime() + 120_000).toISOString(),
  outbox_claim_status: 'CLAIMED',
  outbox_claim_key_hmac_sha256: 'a'.repeat(64),
};
const evidenceAt = new Date(claimAt.getTime() + 180_000);
const evidence = createClaimStateEvidence(finalRecord, env, evidenceAt);
const evidenceValue = JSON.parse(evidence.claim_state_evidence_private);
assert.equal(evidenceValue.scope, CLAIM_STATE_EVIDENCE_SCOPE);
assert.equal(Object.keys(evidenceValue).length, 20);
assert.equal(evidenceValue.issued_at, finalRecord.final_deploy_ready_at, 'Reading status must not refresh a stale verification timestamp.');
assert.equal(evidence.claim_state_evidence_hmac_sha256, createHmac('sha256', env.ARC_CLAIM_STATE_EVIDENCE_SECRET)
  .update(`${CLAIM_STATE_SIGNATURE_PREFIX}${evidence.claim_state_evidence_private}`).digest('hex'));

assert.equal(startConfig.path, '/api/arc2/handoff/start');
assert.equal(claimConfig.path, '/api/arc2/claim');
assert.equal(webhookConfig.path, '/api/arc2/claim-webhook');
assert.equal(invitationConfig.path, '/internal/arc2/claim-invitation-ready');
assert.equal(statusConfig.path, '/internal/arc2/handoff-status');
for (const config of [startConfig, claimConfig, webhookConfig, invitationConfig, statusConfig]) assert.equal(typeof config.rateLimit.windowLimit, 'number');

const configuredSnapshot = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
Object.assign(process.env, env);
try {
  const originalFetch = globalThis.fetch;
  let externalCalls = 0;
  globalThis.fetch = async () => {
    externalCalls += 1;
    throw new Error('External call must be unreachable.');
  };
  try {
    const blockedStart = await startHandler(new Request('https://arcweb.onl/api/arc2/handoff/start', {
      method: 'POST',
      headers: { authorization: `Bearer ${env.ARC_HANDOFF_TRIGGER_SECRET}`, 'content-type': 'application/json' },
      body: '{}',
    }));
    assert.equal(blockedStart.status, 503);
    assert.deepEqual(await blockedStart.json(), { error: 'handoff_unavailable' });
    const blockedInvitation = await invitationHandler(new Request('https://arcweb.onl/internal/arc2/claim-invitation-ready', {
      method: 'POST',
      headers: { authorization: `Bearer ${env.ARC_HANDOFF_TRIGGER_SECRET}`, 'content-type': 'application/json' },
      body: '{}',
    }));
    assert.equal(blockedInvitation.status, 400);
    assert.deepEqual(await blockedInvitation.json(), { error: 'invalid_receipt' });
    const blockedClaim = await claimHandler(new Request('https://arcweb.onl/api/arc2/claim', {
      method: 'POST',
      headers: { authorization: `Bearer ${randomClaimToken}`, 'x-arc-handoff-id': started.handoffId },
    }));
    assert.equal(blockedClaim.status, 401);
    assert.deepEqual(await blockedClaim.json(), { error: 'claim_bearer_invalid_or_expired' });
    const blockedWebhook = await webhookHandler(new Request('https://arcweb.onl/api/arc2/claim-webhook', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    }));
    assert.equal(blockedWebhook.status, 503);
    assert.deepEqual(await blockedWebhook.json(), { error: 'claim_reverification_unavailable' });
    const blockedStatus = await statusHandler(new Request('https://arcweb.onl/internal/arc2/handoff-status'));
    assert.equal(blockedStatus.status, 401);
    assert.deepEqual(await blockedStatus.json(), { error: 'unauthorized' });
    assert.equal(externalCalls, 0, 'Blocked endpoints must not perform network calls even when fully configured.');
  } finally {
    globalThis.fetch = originalFetch;
  }
} finally {
  for (const [key, value] of Object.entries(configuredSnapshot)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

const saved = { ...process.env };
for (const key of Object.keys(process.env)) if (key.startsWith('ARC_') || key.startsWith('NETLIFY_')) delete process.env[key];
try {
  for (const [handler, request] of [
    [startHandler, new Request('https://arcweb.onl/api/arc2/handoff/start', { method: 'POST' })],
    [claimHandler, new Request('https://arcweb.onl/api/arc2/claim', { method: 'POST' })],
    [webhookHandler, new Request('https://arcweb.onl/api/arc2/claim-webhook', { method: 'POST' })],
    [invitationHandler, new Request('https://arcweb.onl/internal/arc2/claim-invitation-ready', { method: 'POST' })],
    [statusHandler, new Request('https://arcweb.onl/internal/arc2/handoff-status')],
  ]) {
    const response = await handler(request);
    assert.equal(response.status, 503, 'Every unconfigured ARC2 endpoint must fail closed before touching Blobs.');
    assert.equal(response.headers.get('x-robots-tag'), 'noindex, nofollow, noarchive');
    assert.equal(response.headers.get('access-control-allow-origin'), null);
  }
} finally {
  for (const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env, saved);
}

console.log('ARC2 Netlify handoff contract passed.');
