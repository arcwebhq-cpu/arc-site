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
  sha256Hex,
  transitionRecord,
  validateExpectedBindings,
} from '../netlify/lib/arc2-handoff-core.mjs';
import { createEntry, readEntry, replaceEntry } from '../netlify/lib/arc2-handoff-store.mjs';
import {
  getHandoffStatus,
  markClaimInvitationSent,
  processClaimWebhook,
  startHandoff,
} from '../netlify/lib/arc2-handoff-service.mjs';
import claimHandler, { config as claimConfig } from '../netlify/functions/arc2-claim.mjs';
import webhookHandler, { config as webhookConfig } from '../netlify/functions/arc2-claim-webhook.mjs';
import invitationHandler, { config as invitationConfig } from '../netlify/functions/arc2-claim-invitation-sent.mjs';
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
  'NETLIFY_ADMIN_PAT',
  'NETLIFY_OAUTH_CLIENT_SECRET',
].map((name, index) => [name, `${name.toLowerCase()}-${String(index).padStart(2, '0')}-unique-test-secret-0123456789`]));
const env = {
  ...secrets,
  ARC_EXPECTED_PAYMENT_LINK_ID: 'plink_1ArcHandoffTest',
  ARC_EXPECTED_PRICE_ID: 'price_1ArcHandoffTest',
  ARC_PUBLIC_ORIGIN: 'https://arcweb.onl/',
  NETLIFY_TEAM_SLUG: 'arc-team',
  NETLIFY_TEAM_ACCOUNT_ID: 'account-source-123',
  NETLIFY_OAUTH_CLIENT_ID: 'oauth-client-123',
};
assert.deepEqual(configuredEnvironment(env), { enabled: true, missing: [], invalid: [] });
assert.equal(configuredEnvironment({ ...env, ARC_CLAIM_TOKEN_SECRET: env.ARC_HANDOFF_STATE_SECRET }).enabled, false, 'Secrets must be distinct.');
assert.equal(configuredEnvironment({}).enabled, false, 'Missing configuration must fail closed.');

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
  version: 'arc2-payment-evidence-v1',
  scope: 'authoritative-stripe-test-checkout-session',
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
  amount_total_minor_units: 500000,
  amount_subtotal_minor_units: 500000,
  payment_link_id: env.ARC_EXPECTED_PAYMENT_LINK_ID,
  price_id: env.ARC_EXPECTED_PRICE_ID,
  quantity: 1,
  terms_of_service_consent: 'accepted',
  terms_version: '2026-08-11',
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
assert.throws(() => normalizeStartPayload({ ...input, lead_notification_email: 'attacker@example.test' }, env, now), /unbound/);
const wrongPriceObject = { ...paymentEvidenceObject, price_id: 'price_1Wrong' };
const wrongPrice = canonicalJson(wrongPriceObject);
assert.throws(() => normalizeStartPayload({
  ...input,
  payment_evidence: wrongPrice,
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}${wrongPrice}`),
}, env, now), /Payment evidence bindings/);
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

const siteId = 'site-arc123';
const deployId = 'deploy-arc123';
const formId = 'form-arc123';
const hookId = 'hook-arc123';
const fetchCalls = [];
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
const fakeFetch = async (url, options = {}) => {
  fetchCalls.push({ url: String(url), method: options.method || 'GET' });
  const parsed = new URL(url);
  const path = `${parsed.pathname}${parsed.search}`;
  if (String(url) === 'https://sample.netlify.app/') return new Response(html, { headers: { 'x-robots-tag': 'noindex, nofollow' } });
  if (path === '/api/v1/sites' && options.method === 'POST') return json({
    id: siteId,
    name: 'arc-' + hmacHex(env.ARC_HANDOFF_STATE_SECRET, `site-name-v1\n${paymentEvidenceObject.checkout_session_id}\n${paymentEvidenceObject.bundle_fingerprint}`).slice(0, 24),
    session_id: '11111111-1111-4111-8111-111111111111',
    account_id: env.NETLIFY_TEAM_ACCOUNT_ID,
    account_slug: env.NETLIFY_TEAM_SLUG,
  }, 201);
  if (path.startsWith(`/api/v1/sites/${siteId}/deploys?`) && options.method === 'POST') return json({ id: deployId, site_id: siteId });
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
    session_id: '11111111-1111-4111-8111-111111111111',
    account_id: env.NETLIFY_TEAM_ACCOUNT_ID,
    published_deploy: { id: deployId },
    ssl_url: 'https://sample.netlify.app/',
  });
  if (path === `/api/v1/accounts/${env.NETLIFY_TEAM_ACCOUNT_ID}`) return json({ id: env.NETLIFY_TEAM_ACCOUNT_ID });
  if (path === `/api/v1/sites/${siteId}/deploys/${deployId}`) return json({ id: deployId, site_id: siteId, state: 'ready' });
  if (path === `/api/v1/sites/${siteId}/files`) return json(artifacts.map((artifact) => ({ path: `/${artifact.path}`, size: artifact.size })));
  if (path === `/api/v1/sites/${siteId}/files/_headers`) return new Response(headersFile);
  if (path === `/api/v1/sites/${siteId}/files/index.html`) return new Response(html);
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
const started = await startHandoff(input, env, adapters);
assert.equal(started.record.state, 'PRECLAIM_DEPLOY_READY');
assert.equal(started.record.claim_token_expires_at, null, 'Claim TTL must not begin before durable invitation acknowledgement.');
assert.equal(started.record.lead_notification_email_sha256, sha256Hex(leadEmail));
assert.equal(JSON.stringify([...store.values.values()]).includes(leadEmail), false, 'Raw lead email must not enter handoff storage.');
const callCount = fetchCalls.length;
const replay = await startHandoff(input, env, adapters);
assert.equal(replay.idempotentReplay, true);
assert.equal('claimToken' in replay, false, 'Start must never issue or return a claim bearer.');
assert.equal(fetchCalls.length, callCount, 'Idempotent replay must not repeat external calls.');

const invitationAt = new Date(now.getTime() + 5 * 60_000);
const invitationAdapters = { ...adapters, clock: () => new Date(invitationAt) };
await assert.rejects(markClaimInvitationSent(started.handoffId, sha256Hex('provider-message-123'), env, invitationAdapters), /LEAD_ROUTE_EVIDENCE_ENDPOINT_NOT_IMPLEMENTED/);

// A future state model must distinguish durable invitation issuance from claim
// wrapper consumption. No current helper performs either transition; this
// synthetic record only contracts the official JWT and unsigned-callback gate.
const claimAt = new Date(invitationAt.getTime() + 60_000);
const claimAdapters = { ...adapters, clock: () => new Date(claimAt) };
let unreachable = await readEntry(store, handoffKeyFromId(started.handoffId));
unreachable = await replaceEntry(store, handoffKeyFromId(started.handoffId), unreachable, {
  ...unreachable.record,
  state: 'CLAIM_INVITED',
  revision: unreachable.record.revision + 1,
  claim_invitation_sent_at: invitationAt.toISOString(),
  claim_invitation_provider_message_id_sha256: sha256Hex('provider-message-123'),
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
assert.deepEqual(Object.keys(payload).sort(), ['claim_webhook', 'client_id', 'session_id']);
assert.equal(payload.claim_webhook, 'https://arcweb.onl/api/arc2/claim-webhook');

const postClaimFetchCount = fetchCalls.length;
await assert.rejects(processClaimWebhook({
  claimed: true,
  site_id: siteId,
  destination_acc_id: 'account-customer-123',
}, env, claimAdapters), /POSTCLAIM_REVERIFY_NOT_CONFIGURED/);
assert.equal(fetchCalls.length, postClaimFetchCount, 'Unsigned callback must never trigger source-PAT post-claim reads.');
const callbackStatus = await getHandoffStatus(started.handoffId, env, claimAdapters);
assert.equal(callbackStatus.status, 'CLAIM_INVITED');
assert.equal(callbackStatus.claim_available, false, 'Consumed one-time wrapper tokens must not be reported available.');
assert.equal(callbackStatus.claim_verified, false);
assert.equal('claim_state_evidence_private' in callbackStatus, false, 'Blocked post-claim state cannot authorize final email.');

const stored = await readEntry(store, handoffKeyFromId(started.handoffId));
const finalRecord = {
  ...stored.record,
  state: 'FINAL_DEPLOY_READY',
  destination_account_id: 'account-customer-123',
  final_deploy_id: 'deploy-final-123',
  production_url: 'https://sample.netlify.app/',
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
assert.equal(evidence.claim_state_evidence_hmac_sha256, createHmac('sha256', env.ARC_CLAIM_STATE_EVIDENCE_SECRET)
  .update(`${CLAIM_STATE_SIGNATURE_PREFIX}${evidence.claim_state_evidence_private}`).digest('hex'));

assert.equal(startConfig.path, '/api/arc2/handoff/start');
assert.equal(claimConfig.path, '/api/arc2/claim');
assert.equal(webhookConfig.path, '/api/arc2/claim-webhook');
assert.equal(invitationConfig.path, '/internal/arc2/claim-invitation-sent');
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
    assert.deepEqual(await blockedStart.json(), { error: 'resumable_recovery_not_implemented' });
    const blockedInvitation = await invitationHandler(new Request('https://arcweb.onl/internal/arc2/claim-invitation-sent', {
      method: 'POST',
      headers: { authorization: `Bearer ${env.ARC_HANDOFF_TRIGGER_SECRET}`, 'content-type': 'application/json' },
      body: '{}',
    }));
    assert.equal(blockedInvitation.status, 503);
    assert.deepEqual(await blockedInvitation.json(), { error: 'lead_route_evidence_endpoint_not_implemented' });
    const blockedClaim = await claimHandler(new Request('https://arcweb.onl/api/arc2/claim', {
      method: 'POST',
      headers: { authorization: `Bearer ${randomClaimToken}`, 'x-arc-handoff-id': started.handoffId },
    }));
    assert.equal(blockedClaim.status, 503);
    assert.deepEqual(await blockedClaim.json(), { error: 'resumable_claim_exchange_not_implemented' });
    const blockedWebhook = await webhookHandler(new Request('https://arcweb.onl/api/arc2/claim-webhook', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    }));
    assert.equal(blockedWebhook.status, 503);
    assert.deepEqual(await blockedWebhook.json(), { error: 'postclaim_reverification_not_implemented' });
    const blockedStatus = await statusHandler(new Request('https://arcweb.onl/internal/arc2/handoff-status'));
    assert.equal(blockedStatus.status, 503);
    assert.deepEqual(await blockedStatus.json(), { error: 'handoff_status_not_implemented' });
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
    [invitationHandler, new Request('https://arcweb.onl/internal/arc2/claim-invitation-sent', { method: 'POST' })],
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
