import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  ARC2_CONTENT_SECURITY_POLICY,
  ARC2_PRECLAIM_HEADERS_FILE,
  ARC2_PRODUCTION_HEADERS_FILE,
  ARTIFACT_SIGNATURE_PREFIX,
  canonicalJson,
  CLAIM_JWT_TTL_SECONDS,
  CLAIM_STATE_EVIDENCE_SCOPE,
  CLAIM_STATE_SIGNATURE_PREFIX,
  configuredEnvironment,
  createClaimStateEvidence,
  createStoredZip,
  ensureEmailHook,
  handoffKeyFromId,
  hmacHex,
  LEAD_RECIPIENT_PREFIX,
  netlifyRequest,
  readNetlifyJsonBounded,
  pollDeployReady,
  normalizeStartPayload,
  PAYMENT_SIGNATURE_PREFIX,
  netlifyClaimUrl,
  resolveHandoffEnvironment,
  sha256Hex,
  transitionRecord,
  validateExpectedBindings,
  verifyNetlifyHandoff,
} from '../netlify/lib/arc2-handoff-core.mjs';
import { createEntry, createIndex, readEntry, replaceEntry } from '../netlify/lib/arc2-handoff-store.mjs';
import {
  duplicatePaymentReviewKey,
  duplicatePaymentReviewValue,
  exchangeClaimBearer,
  getHandoffStatus,
  markClaimInvitationReady,
  processClaimWebhook,
  renewClaimInvitation,
  startHandoff,
} from '../netlify/lib/arc2-handoff-service.mjs';
import {
  registerStripeReversalBinding,
  registerStripeReversalRecheck,
  STRIPE_REVERSAL_BINDING_PREFIX,
  STRIPE_REVERSAL_BINDING_SCHEMA,
  STRIPE_REVERSAL_BINDING_SCOPE,
  STRIPE_PENDING_PAYMENT_SCHEMA,
  STRIPE_REVERSAL_SCHEMA,
  STRIPE_REVERSAL_RECHECK_PREFIX,
  STRIPE_REVERSAL_RECHECK_SCHEMA,
  STRIPE_REVERSAL_RECHECK_SCOPE,
  STRIPE_WEBHOOK_API_VERSION,
  stripeReversalKeys,
} from '../netlify/lib/stripe-reversal-core.mjs';
import {
  STRIPE_CHECKOUT_HANDOFF_BINDING_SCHEMA,
  STRIPE_CHECKOUT_SESSION_SCHEMA,
  stripeCheckoutKeys,
} from '../netlify/lib/stripe-checkout-core.mjs';
import claimHandler, { config as claimConfig } from '../netlify/functions/arc2-claim.mjs';
import webhookHandler, { config as webhookConfig } from '../netlify/functions/arc2-claim-webhook.mjs';
import invitationHandler, { config as invitationConfig } from '../netlify/functions/arc2-claim-invitation-ready.mjs';
import startHandler, { config as startConfig } from '../netlify/functions/arc2-handoff-start.mjs';
import statusHandler, { config as statusConfig } from '../netlify/functions/arc2-handoff-status.mjs';

const now = new Date('2026-08-12T18:00:00.000Z');
const stripeAccountId = 'acct_ArcHandoffContract123';
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
  'ARC_STRIPE_WEBHOOK_SIGNING_SECRET',
  'ARC_STRIPE_REVERSAL_HMAC_SECRET',
  'ARC_STRIPE_REVERSAL_BINDING_SECRET',
  'ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET',
  'ARC_STRIPE_REVERSAL_RECHECK_SECRET',
  'ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET',
  'NETLIFY_ADMIN_PAT',
  'NETLIFY_OAUTH_CLIENT_SECRET',
].map((name, index) => [name, `${name.toLowerCase()}-${String(index).padStart(2, '0')}-unique-test-secret-0123456789`]));
const env = {
  ...secrets,
  ARC_HANDOFF_ENABLED: 'false',
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: 'rk_' + 'test_arcHandoffRestrictedAccountRead0123456789',
  ARC_CHECKOUT_BINDING_KEY_ID: '01',
  ARC_RETIRED_CHECKOUT_BINDING_KEYS_JSON: '{}',
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_EXPECTED_PAYMENT_LINK_ID: 'plink_1ArcHandoffTest',
  ARC_EXPECTED_PRICE_ID: 'price_1ArcHandoffTest',
  ARC_EXPECTED_PRODUCT_TAX_CODE: 'txcd_10000000',
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256: sha256Hex(stripeAccountId),
  ARC_ADULT_OPERATOR_VERIFIED: 'true',
  ARC_BUSINESS_LICENSE_VERIFIED: 'true',
  ARC_TAX_REGISTRATION_VERIFIED: 'true',
  ARC_TRANSACTIONAL_EMAIL_VERIFIED: 'true',
  ARC_RETENTION_CONTROL_VERIFIED: 'true',
  ARC_POSTCLAIM_READBACK_VERIFIED: 'true',
  ARC_DEVICE_QA_VERIFIED: 'true',
  ARC_LEAD_ROUTE_VERIFIED: 'true',
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'true',
  ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_BINDING_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_RECHECK_ENABLED: 'true',
  ARC_STRIPE_CHECKOUT_LEDGER_ENABLED: 'true',
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'false',
  ARC_STRIPE_WEBHOOK_API_VERSION: STRIPE_WEBHOOK_API_VERSION,
  ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
  ARC_ALLOW_TEST_MODE_EVENTS: 'true',
  ARC_RUNTIME_ENVIRONMENT: 'sandbox',
  ARC_PUBLIC_ORIGIN: 'https://arcweb.onl/',
  SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  SITE_NAME: 'arc2-sandbox',
  URL: 'https://arcweb.onl/',
  DEPLOY_PRIME_URL: 'https://main--arcsites.netlify.app/',
  NETLIFY_TEAM_SLUG: 'arc-team',
  NETLIFY_TEAM_ACCOUNT_ID: 'account-source-123',
  NETLIFY_OAUTH_CLIENT_ID: 'oauth-client-123',
};
assert.equal(configuredEnvironment({ ...env, ARC_HANDOFF_ENABLED: 'true' }).enabled, false,
  'Test-mode events require a disabled handoff on an explicit nonproduction sandbox.');
const sandboxEnv = { ...env };
assert.deepEqual(configuredEnvironment(sandboxEnv), { enabled: true, missing: [], invalid: [] });
const productionEnv = {
  ...env,
  ARC_STRIPE_LIVE_MODE_ENABLED: 'true',
  ARC_ALLOW_TEST_MODE_EVENTS: 'false',
  ARC_RUNTIME_ENVIRONMENT: 'production',
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'true',
  ARC_HANDOFF_ENABLED: 'true',
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: 'rk_' + 'live_arcHandoffRestrictedAccountRead0123456789',
  SITE_NAME: 'arcsites',
};
assert.deepEqual(configuredEnvironment(productionEnv), { enabled: true, missing: [], invalid: [] });
const tokenAliasEnv = { ...productionEnv, NETLIFY_ACCESS_TOKEN: productionEnv.NETLIFY_ADMIN_PAT };
delete tokenAliasEnv.NETLIFY_ADMIN_PAT;
assert.equal(configuredEnvironment(tokenAliasEnv).enabled, true, 'Workflow-facing Netlify token alias must satisfy runtime readiness.');
assert.equal(resolveHandoffEnvironment(tokenAliasEnv).environment.NETLIFY_ADMIN_PAT, productionEnv.NETLIFY_ADMIN_PAT);
const tokenAliasTestEnv = { ...sandboxEnv, NETLIFY_ACCESS_TOKEN: sandboxEnv.NETLIFY_ADMIN_PAT };
delete tokenAliasTestEnv.NETLIFY_ADMIN_PAT;
assert.equal(configuredEnvironment({
  ...productionEnv,
  NETLIFY_ACCESS_TOKEN: productionEnv.NETLIFY_ADMIN_PAT,
}).enabled, true, 'Matching canonical and alias values must be accepted.');
const conflictingAliases = configuredEnvironment({
  ...productionEnv,
  NETLIFY_ACCESS_TOKEN: `${productionEnv.NETLIFY_ADMIN_PAT}-different`,
});
assert.equal(conflictingAliases.enabled, false, 'Conflicting canonical and alias values must fail closed.');
assert.ok(conflictingAliases.invalid.includes('NETLIFY_ADMIN_PAT_NETLIFY_ACCESS_TOKEN_CONFLICT'));
assert.equal(configuredEnvironment({ ...productionEnv, ARC_CLAIM_TOKEN_SECRET: productionEnv.ARC_HANDOFF_STATE_SECRET }).enabled, false, 'Secrets must be distinct.');
assert.equal(configuredEnvironment({ ...productionEnv, ARC_TAX_REGISTRATION_VERIFIED: 'false' }).enabled, false, 'Manual attestations must be exact and fail closed.');
assert.equal(configuredEnvironment({ ...productionEnv, ARC_STRIPE_LIVE_MODE_ENABLED: 'yes' }).enabled, false, 'Stripe mode must be exact live in production.');
assert.equal(configuredEnvironment({ ...productionEnv, ARC_CHECKOUT_BINDING_KEY_ID: '' }).enabled, false, 'Checkout key id must be explicit.');
assert.equal(configuredEnvironment({ ...productionEnv, ARC_RETIRED_CHECKOUT_BINDING_KEYS_JSON: '{ }' }).enabled, false, 'Retired key registry must be canonical.');
assert.equal(configuredEnvironment({ ...productionEnv, ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'false' }).enabled, false,
  'Production handoff cannot bypass the authenticated Checkout event ledger.');
assert.equal(configuredEnvironment({}).enabled, false, 'Missing configuration must fail closed.');
assert.equal(configuredEnvironment({ ...productionEnv, SITE_ID: '00000000-0000-4000-8000-000000000000' }).enabled, false, 'Wrong Netlify site must fail closed.');
assert.equal(configuredEnvironment({ ...productionEnv, SITE_NAME: 'attacker-site' }).enabled, false, 'Wrong Netlify site name must fail closed.');
assert.equal(configuredEnvironment({ ...productionEnv, DEPLOY_PRIME_URL: 'https://deploy-preview-7--arcsites.netlify.app/' }).enabled, true, 'Per-deploy URL must not be mistaken for the canonical production identity.');
assert.equal(configuredEnvironment({ ...productionEnv, URL: 'https://attacker.example/' }).enabled, false, 'Wrong canonical production origin must fail closed.');

let observedNetlifySignal;
const boundedResponse = await netlifyRequest('/sites', { method: 'GET' }, env, async (_url, options) => {
  observedNetlifySignal = options.signal;
  return new Response(JSON.stringify([{ id: 'site-timeout-test' }]), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}, 100);
assert.ok(observedNetlifySignal instanceof AbortSignal, 'Every Netlify request must carry a bounded abort signal.');
assert.deepEqual(await boundedResponse.json(), [{ id: 'site-timeout-test' }]);
await assert.rejects(netlifyRequest('/sites', { method: 'GET' }, env, async (_url, options) => new Promise((_resolve, reject) => {
  options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true });
}), 5), /bounded timeout/, 'A stalled Netlify request must abort before the Function can hang indefinitely.');
await assert.rejects(netlifyRequest('/sites', { method: 'GET' }, env, async () => new Response('{}'), 10_001), /timeout is invalid/,
  'Callers must not weaken the fixed Netlify timeout ceiling.');
await assert.rejects(netlifyRequest('/sites', { method: 'GET' }, env, async () => new Response('{}', {
  headers: { 'content-type': 'application/json', 'content-length': '256001' },
})).then(response => readNetlifyJsonBounded(response, 256_000, 'Netlify test JSON')),
/bounded response size/i, 'Netlify API JSON must reject an oversized declared body before parsing.');
const expiredDeadlineFetches = [];
await assert.rejects(
  // An already-expired total polling budget must stop before even one request;
  // wall time is authoritative, so a frozen business clock cannot bypass it.
  pollDeployReady(
    'site-deadline-test',
    'deploy-deadline-test',
    env,
    async (...args) => { expiredDeadlineFetches.push(args); return new Response('{}'); },
    { deadlineMs: Date.now() - 1, clock: () => new Date(0) },
  ),
  /operation deadline/,
);
assert.equal(expiredDeadlineFetches.length, 0);
let hookCreateCalls = 0;
await assert.rejects(ensureEmailHook(
  'site-hook-deadline',
  'form-hook-deadline',
  'lead@example.test',
  env,
  async (_url, options) => {
    if ((options.method || 'GET') === 'GET') return new Response('[]', { status: 200 });
    hookCreateCalls += 1;
    return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(
      Object.assign(new Error('aborted'), { name: 'AbortError' }),
    ), { once: true }));
  },
  { deadlineMs: Date.now() + 20 },
), /bounded timeout|deadline/i, 'A hanging email-hook creation must obey the shared provider-stage deadline.');
assert.equal(hookCreateCalls, 1);

const headersFile = ARC2_PRODUCTION_HEADERS_FILE;
const html = '<!doctype html><form name="sample-lead" method="POST" data-netlify="true" netlify-honeypot="bot-field"><input name="email"></form>\n';
const processedHtml = html.replace(' data-netlify="true"', '').replace(' netlify-honeypot="bot-field"', '');
const artifactsWithBytes = [
  { path: '_headers', bytes: Buffer.from(headersFile) },
  { path: 'index.html', bytes: Buffer.from(html) },
];
const artifacts = artifactsWithBytes.map(({ path, bytes }) => ({ path, sha256: sha256Hex(bytes), size: bytes.length }));
const checkoutTaxRegistrations = [{ country: 'US', id: 'taxreg_ArcWashingtonTest', state: 'WA', type: 'state_sales_tax' }];
const approvalContentSha256 = sha256Hex('approved-preview-before-toolbar');
const sourceCommitSha = 'a'.repeat(40);
const sourceTreeSha = 'b'.repeat(40);
const customerEmail = 'buyer@example.test';
const leadEmail = 'leads@example.test';
const stableCheckoutConfiguration = {
  adult_acknowledgement_key: 'adultpurchaserack', amount_subtotal_minor_units: 500000, automatic_tax_enabled: true,
  checkout_binding_key_id: '01', checkout_redirect_url: 'https://arcweb.onl/payment-success/?session_id={CHECKOUT_SESSION_ID}',
  claim_recipient_email_sha256: sha256Hex(customerEmail), completed_sessions_limit: 1, currency: 'usd',
  customer_address_source: 'stripe_checkout_customer_details.address', name_collection_required: true,
  price_id: 'price_1ArcHandoffTest', price_tax_behavior: 'exclusive', product_id: 'prod_ArcHandoffTest', product_tax_code: 'txcd_10000000', quantity: 1,
  stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256, stripe_api_version: '2026-06-24.dahlia', stripe_mode: 'test',
  tax_contract_version: 'arc-tax-v1', tax_registrations: checkoutTaxRegistrations,
  tax_registrations_sha256: sha256Hex(canonicalJson(checkoutTaxRegistrations)), terms_document_sha256: sha256Hex('terms-document-v1'), terms_version: '2026-08-12',
};
const checkoutConfigSnapshot = canonicalJson({
  version: 'arc-private-checkout-policy-v1', scope: 'one-approved-preview-one-private-payment-link',
  ...stableCheckoutConfiguration,
  preview_folder: 'sample-roofing-a1b2c3d4', preview_path: 'sample-roofing-a1b2c3d4/index.html', preview_source_repository: 'arcwebhq-cpu/arc-previews',
  approval_content_sha256: approvalContentSha256, content_sha256: sha256Hex('preview-content'), published_html_sha256: sha256Hex(html),
  source_commit_sha: sourceCommitSha, source_tree_sha: sourceTreeSha, asset_publication_receipt_sha256: sha256Hex('arc1-no-publication-receipt-v1'),
  lead_route_recipient_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, 'arc-checkout-lead-recipient-v1\ntest\nleads@example.test'),
  readiness_core_sha256: sha256Hex('readiness-core'), offer_snapshot_sha256: sha256Hex('offer-snapshot'), recipient_reservation_sha256: sha256Hex('recipient-reservation'),
});
const checkoutConfigSnapshotSha256 = sha256Hex(checkoutConfigSnapshot);
const checkoutReferencePayload = Buffer.concat([
  Buffer.from('01', 'hex'), Buffer.from('a1b2c3d4', 'hex'), Buffer.from(approvalContentSha256, 'hex'), Buffer.from(checkoutConfigSnapshotSha256, 'hex'),
]);
const checkoutReferenceMac = createHmac('sha256', env.ARC_CHECKOUT_BINDING_SECRET)
  .update('arc-checkout-reference-v3\narcwebhq-cpu/arc-previews\narc-production\nstripe-test\n').update(checkoutReferencePayload).digest();
const checkoutReference = `v3_${Buffer.concat([checkoutReferencePayload, checkoutReferenceMac]).toString('base64url')}`;
const checkoutReferenceSha256 = sha256Hex(checkoutReference);
const sourceTagSha256 = sha256Hex(`refs/tags/arc-checkout-ready-v3/${checkoutReferenceSha256}`);
const assetPublicationReceiptSha256 = sha256Hex('arc1-no-publication-receipt-v1');
const artifactEvidenceObject = {
  version: 'arc2-handoff-artifact-evidence-v3',
  scope: 'netlify-claimable-deploy-artifacts',
  approval_content_sha256: approvalContentSha256,
  asset_publication_receipt_sha256: assetPublicationReceiptSha256,
  checkout_binding_key_id: '01',
  checkout_config_snapshot_sha256: checkoutConfigSnapshotSha256,
  checkout_reference_sha256: checkoutReferenceSha256,
  preview_folder: 'sample-roofing-a1b2c3d4',
  preview_source_commit_sha: sourceCommitSha,
  preview_source_repository: 'arcwebhq-cpu/arc-previews',
  preview_source_tag_sha256: sourceTagSha256,
  lead_route_mode: 'netlify_form',
  lead_route_form_name: 'sample-lead',
  lead_route_recipient_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, 'arc-checkout-lead-recipient-v1\ntest\nleads@example.test'),
  production_content_sha256: sha256Hex(html),
  artifact_manifest_sha256: sha256Hex(canonicalJson(artifacts)),
  bundle_fingerprint: sha256Hex(`_headers\0${headersFile}\0index.html\0${html}\0`),
  artifacts,
  issued_at: new Date(now.getTime() - 60_000).toISOString(),
};
const artifactEvidence = canonicalJson(artifactEvidenceObject);
const paymentEvidenceObject = {
  version: 'arc2-payment-evidence-v3',
  scope: 'authoritative-stripe-checkout-session',
  checkout_session_id: 'cs_test_arc2_handoff_contract',
  client_reference_id: checkoutReference,
  client_reference_id_observation: 'ABSENT',
  client_reference_id_sha256: checkoutReferenceSha256,
  client_reference_mismatch_review_required: false,
  client_reference_mismatch_review_record_key_hmac_sha256: '',
  client_reference_mismatch_review_state: '',
  client_reference_mismatch_review_sha256: '',
  client_reference_mismatch_review_hmac_sha256: '',
  approval_content_sha256: approvalContentSha256,
  asset_publication_receipt_sha256: assetPublicationReceiptSha256,
  checkout_config_snapshot: checkoutConfigSnapshot,
  checkout_config_snapshot_sha256: checkoutConfigSnapshotSha256,
  preview_folder: artifactEvidenceObject.preview_folder,
  preview_source_commit_sha: sourceCommitSha,
  preview_source_repository: 'arcwebhq-cpu/arc-previews',
  preview_source_tag_sha256: sourceTagSha256,
  production_content_sha256: artifactEvidenceObject.production_content_sha256,
  artifact_manifest_sha256: artifactEvidenceObject.artifact_manifest_sha256,
  handoff_artifact_evidence_sha256: sha256Hex(artifactEvidence),
  bundle_fingerprint: artifactEvidenceObject.bundle_fingerprint,
  claim_recipient_email_sha256: sha256Hex(customerEmail),
  payer_email_sha256: sha256Hex('adult-payer@example.test'),
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
  product_id: 'prod_ArcHandoffTest',
  tax_contract_version: 'arc-tax-v1',
  tax_registrations_sha256: stableCheckoutConfiguration.tax_registrations_sha256,
  customer_address_sha256: sha256Hex('buyer-destination-address'),
  customer_address_country: 'US',
  customer_address_state: 'WA',
  customer_address_status: 'verified',
  tax_registration_status: 'historical_precheckout_snapshot',
  stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
  payment_link_id: 'plink_1ArcHandoffTest',
  payment_intent_id: 'pi_1ArcHandoffTest',
  charge_id: 'ch_1ArcHandoffTest',
  price_id: stableCheckoutConfiguration.price_id,
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
  lead_route_recipient_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `arc-checkout-lead-recipient-v1\ntest\n${leadEmail}`),
  payment_evidence: paymentEvidence,
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}test\n${paymentEvidence}`),
};

const normalized = normalizeStartPayload(input, env, now);
assert.equal(normalized.formName, 'sample-lead');
assert.equal(normalized.leadEmail, leadEmail);
assert.equal(normalized.leadRouteRecipientHmacSha256, input.lead_route_recipient_hmac_sha256);
const duplicateWinnerFixture = {
  winning_checkout_session_id: 'cs_test_ArcWinningSession',
  winning_payment_link_id_hmac_sha256: '1'.repeat(64),
  handoff_id: 'arc2_winning_handoff',
  payment_evidence_sha256: '2'.repeat(64),
  artifact_evidence_sha256: '3'.repeat(64),
};
const duplicateReviewFixture = duplicatePaymentReviewValue(duplicateWinnerFixture, normalized, env);
const expectedDuplicateReviewKeyDigest = hmacHex(env.ARC_HANDOFF_STATE_SECRET,
  `duplicate-payment-review-key-v1\n${duplicateReviewFixture.checkout_reference_sha256}\n${duplicateReviewFixture.duplicate_checkout_session_id_hmac_sha256}`);
assert.equal(duplicatePaymentReviewKey(normalized, env), `duplicate-payment-review/${expectedDuplicateReviewKeyDigest}`,
  'Duplicate review key must be recomputable from authenticated fields stored in the signed review record.');
assert.equal(duplicateReviewFixture.review_hmac_sha256, hmacHex(env.ARC_HANDOFF_STATE_SECRET,
  `arc2-duplicate-payment-review-signature-v1\n${canonicalJson(Object.fromEntries(Object.entries(duplicateReviewFixture).filter(([key]) => key !== 'review_hmac_sha256')))}`));
assert.doesNotThrow(() => normalizeStartPayload(input, { ...env, ARC_EXPECTED_PRICE_ID: 'price_current_rotated', ARC_EXPECTED_PRODUCT_TAX_CODE: 'txcd_99999999' }, now),
  'V3 fulfillment must ignore mutable current Price/tax-code singleton drift.');
assert.throws(() => normalizeStartPayload({ ...input, lead_notification_email: 'attacker@example.test' }, env, now), /unbound/);
const wrongPriceObject = { ...paymentEvidenceObject, price_id: 'price_1Wrong' };
const wrongPrice = canonicalJson(wrongPriceObject);
assert.throws(() => normalizeStartPayload({
  ...input,
  payment_evidence: wrongPrice,
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}test\n${wrongPrice}`),
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
    payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}test\n${tampered}`),
  }, env, now), /invalid|Payment evidence bindings/i);
}
const livePaymentObject = { ...paymentEvidenceObject, livemode: true, checkout_session_id: 'cs_live_arc2_handoff_contract' };
const livePayment = canonicalJson(livePaymentObject);
assert.throws(() => normalizeStartPayload({
  ...input,
  payment_evidence: livePayment,
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}test\n${livePayment}`),
}, { ...env, ARC_STRIPE_LIVE_MODE_ENABLED: 'true' }, now), /Payment evidence signature|mode|livemode/i,
'Runtime mode rotation must not reinterpret a snapshot-bound test Session as live.');
const nonUsPaymentObject = { ...paymentEvidenceObject, customer_address_country: 'CA', customer_address_state: '' };
const nonUsPayment = canonicalJson(nonUsPaymentObject);
assert.doesNotThrow(() => normalizeStartPayload({
  ...input,
  payment_evidence: nonUsPayment,
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}test\n${nonUsPayment}`),
}, env, now));
assert.throws(() => transitionRecord({ state: 'SITE_INTENT' }, 'DELIVERED'), /Invalid handoff transition/);

const zip = createStoredZip(artifactsWithBytes);
assert.equal(zip.readUInt32LE(0), 0x04034b50);
assert.equal(zip.readUInt32LE(zip.length - 22), 0x06054b50);
assert.equal(zip.includes(Buffer.from(headersFile)), true);
assert.equal(zip.includes(Buffer.from(html)), true);

// A paid upload bundle must be self-contained: exact content-addressed assets
// travel with the HTML and are validated before any store/provider access.
const pngBytes = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
const pngDigest = sha256Hex(pngBytes);
const assetPath = `assets/${pngDigest}.png`;
const assetHtml = html.replace('</form>', `</form><img src="${assetPath}" alt="Customer logo">`);
const assetArtifactsWithBytes = [
  { path: '_headers', bytes: Buffer.from(headersFile) },
  { path: assetPath, bytes: pngBytes },
  { path: 'index.html', bytes: Buffer.from(assetHtml) },
];
const assetArtifacts = assetArtifactsWithBytes.map(({ path, bytes }) => ({ path, sha256: sha256Hex(bytes), size: bytes.length }));
const bundleDigest = (entries) => {
  let encoded = Buffer.alloc(0);
  for (const entry of entries) encoded = Buffer.concat([encoded, Buffer.from(`${entry.path}\0`), entry.bytes, Buffer.from('\0')]);
  return sha256Hex(encoded);
};
const assetEvidenceObject = {
  ...artifactEvidenceObject,
  production_content_sha256: sha256Hex(assetHtml),
  artifact_manifest_sha256: sha256Hex(canonicalJson(assetArtifacts)),
  bundle_fingerprint: bundleDigest(assetArtifactsWithBytes),
  artifacts: assetArtifacts,
};
const assetEvidence = canonicalJson(assetEvidenceObject);
const assetPaymentObject = {
  ...paymentEvidenceObject,
  production_content_sha256: assetEvidenceObject.production_content_sha256,
  artifact_manifest_sha256: assetEvidenceObject.artifact_manifest_sha256,
  handoff_artifact_evidence_sha256: sha256Hex(assetEvidence),
  bundle_fingerprint: assetEvidenceObject.bundle_fingerprint,
};
const assetPayment = canonicalJson(assetPaymentObject);
const assetInput = {
  ...input,
  artifact_evidence: assetEvidence,
  artifact_evidence_hmac_sha256: hmacHex(env.ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET, `${ARTIFACT_SIGNATURE_PREFIX}${assetEvidence}`),
  deploy_artifacts: canonicalJson(assetArtifactsWithBytes.map(({ path, bytes }) => ({ path, content_base64: bytes.toString('base64') }))),
  payment_evidence: assetPayment,
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}test\n${assetPayment}`),
};
const normalizedAsset = normalizeStartPayload(assetInput, env, now);
assert.deepEqual(normalizedAsset.deployArtifacts.map(({ path }) => path), ['_headers', assetPath, 'index.html']);
const assetZip = createStoredZip(normalizedAsset.deployArtifacts);
assert.equal(assetZip.includes(pngBytes), true, 'The exact uploaded bytes must be present in the stored deploy ZIP.');

function signedBundleInput({
  productionHtml,
  assetBytes = [],
  leadRouteMode = 'netlify_form',
  checkoutSessionId = `cs_test_bundle_${sha256Hex(productionHtml).slice(0, 12)}`,
} = {}) {
  const routeHmac = leadRouteMode === 'netlify_form'
    ? hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `arc-checkout-lead-recipient-v1\ntest\n${leadEmail}`) : '';
  const bundleSnapshotObject = { ...JSON.parse(checkoutConfigSnapshot), lead_route_recipient_hmac_sha256: routeHmac };
  const bundleSnapshot = canonicalJson(bundleSnapshotObject);
  const bundleSnapshotSha = sha256Hex(bundleSnapshot);
  const bundleReferencePayload = Buffer.concat([
    Buffer.from('01', 'hex'), Buffer.from('a1b2c3d4', 'hex'), Buffer.from(approvalContentSha256, 'hex'), Buffer.from(bundleSnapshotSha, 'hex'),
  ]);
  const bundleReferenceMac = createHmac('sha256', env.ARC_CHECKOUT_BINDING_SECRET)
    .update('arc-checkout-reference-v3\narcwebhq-cpu/arc-previews\narc-production\nstripe-test\n').update(bundleReferencePayload).digest();
  const bundleReference = `v3_${Buffer.concat([bundleReferencePayload, bundleReferenceMac]).toString('base64url')}`;
  const bundleReferenceSha = sha256Hex(bundleReference);
  const bundleTagSha = sha256Hex(`refs/tags/arc-checkout-v3/${bundleReferenceSha}`);
  const assetEntries = assetBytes.map((bytes) => {
    const digest = sha256Hex(bytes);
    return { path: `assets/${digest}.jpg`, bytes };
  }).sort((left, right) => left.path.localeCompare(right.path));
  const bundleBytes = [
    { path: '_headers', bytes: Buffer.from(headersFile) },
    ...assetEntries,
    { path: 'index.html', bytes: Buffer.from(productionHtml) },
  ];
  const signedArtifacts = bundleBytes.map(({ path, bytes }) => ({ path, sha256: sha256Hex(bytes), size: bytes.length }));
  const signedArtifactValue = {
    ...artifactEvidenceObject,
    checkout_config_snapshot_sha256: bundleSnapshotSha,
    checkout_reference_sha256: bundleReferenceSha,
    preview_source_tag_sha256: bundleTagSha,
    lead_route_mode: leadRouteMode,
    lead_route_form_name: leadRouteMode === 'netlify_form' ? 'sample-lead' : '',
    lead_route_recipient_hmac_sha256: routeHmac,
    production_content_sha256: sha256Hex(productionHtml),
    artifact_manifest_sha256: sha256Hex(canonicalJson(signedArtifacts)),
    bundle_fingerprint: bundleDigest(bundleBytes),
    artifacts: signedArtifacts,
  };
  const signedArtifactEvidence = canonicalJson(signedArtifactValue);
  const signedPaymentValue = {
    ...paymentEvidenceObject,
    client_reference_id: bundleReference,
    client_reference_id_sha256: bundleReferenceSha,
    checkout_config_snapshot: bundleSnapshot,
    checkout_config_snapshot_sha256: bundleSnapshotSha,
    preview_source_tag_sha256: bundleTagSha,
    checkout_session_id: checkoutSessionId,
    production_content_sha256: signedArtifactValue.production_content_sha256,
    artifact_manifest_sha256: signedArtifactValue.artifact_manifest_sha256,
    handoff_artifact_evidence_sha256: sha256Hex(signedArtifactEvidence),
    bundle_fingerprint: signedArtifactValue.bundle_fingerprint,
  };
  const signedPaymentEvidence = canonicalJson(signedPaymentValue);
  return {
    input: {
      ...input,
      artifact_evidence: signedArtifactEvidence,
      artifact_evidence_hmac_sha256: hmacHex(
        env.ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET,
        `${ARTIFACT_SIGNATURE_PREFIX}${signedArtifactEvidence}`,
      ),
      deploy_artifacts: canonicalJson(bundleBytes.map(({ path, bytes }) => ({ path, content_base64: bytes.toString('base64') }))),
      lead_notification_email: leadRouteMode === 'netlify_form' ? leadEmail : '',
      lead_route_recipient_hmac_sha256: leadRouteMode === 'netlify_form'
        ? signedArtifactValue.lead_route_recipient_hmac_sha256
        : '',
      payment_evidence: signedPaymentEvidence,
      payment_evidence_hmac_sha256: hmacHex(
        env.ARC_CHECKOUT_BINDING_SECRET,
        `${PAYMENT_SIGNATURE_PREFIX}test\n${signedPaymentEvidence}`,
      ),
    },
    artifactValue: signedArtifactValue,
    artifacts: signedArtifacts,
    bundleBytes,
    paymentValue: signedPaymentValue,
  };
}

const noFormHtml = '<!doctype html><main><a href="tel:+12065550100">Call to order</a></main>\n';
const noFormBundle = signedBundleInput({
  productionHtml: noFormHtml,
  leadRouteMode: 'not_required',
  checkoutSessionId: 'cs_test_arc2_no_form_contract',
});
const normalizedNoForm = normalizeStartPayload(noFormBundle.input, env, now);
assert.equal(normalizedNoForm.artifact.value.lead_route_mode, 'not_required');
assert.equal(normalizedNoForm.leadEmail, '');
assert.equal(normalizedNoForm.leadRouteRecipientHmacSha256, '');
assert.equal(normalizedNoForm.formName, '');
assert.throws(() => normalizeStartPayload({
  ...noFormBundle.input,
  lead_notification_email: leadEmail,
}, env, now), /No-form|not contain/i, 'No-form evidence cannot acquire an unsigned notification route.');

const baseElementBundle = signedBundleInput({
  productionHtml: '<!doctype html><base href="https://attacker.example/"><main>Signed page</main>\n',
  leadRouteMode: 'not_required',
  checkoutSessionId: 'cs_test_arc2_base_element_rejected',
});
assert.throws(() => normalizeStartPayload(baseElementBundle.input, env, now), /base elements are forbidden/i,
  'A fully re-signed base element must fail before any store or provider call.');

function boundedJpeg(size, fill) {
  const prefix = Buffer.from([
    0xff, 0xd8,
    0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
    0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00,
  ]);
  assert.ok(size > prefix.length + 2);
  return Buffer.concat([prefix, Buffer.alloc(size - prefix.length - 2, fill), Buffer.from([0xff, 0xd9])], size);
}
const maximumAssets = [boundedJpeg(1_000_000, 0x11), boundedJpeg(1_000_000, 0x22), boundedJpeg(1_000_000, 0x33)];
const maximumAssetRefs = maximumAssets.map((bytes) => `<img src="assets/${sha256Hex(bytes)}.jpg" alt="Bound asset">`).join('');
const maximumBundle = signedBundleInput({
  productionHtml: `<!doctype html><main>${maximumAssetRefs}</main>\n`,
  assetBytes: maximumAssets,
  leadRouteMode: 'not_required',
  checkoutSessionId: 'cs_test_arc2_maximum_asset_bundle',
});
assert.ok(Buffer.byteLength(JSON.stringify(maximumBundle.input), 'utf8') < 5_000_000,
  'The canonical maximum public intake bundle must fit the streamed start endpoint envelope.');
assert.equal(normalizeStartPayload(maximumBundle.input, env, now).deployArtifacts.length, 5,
  'The exact 3 MB public-intake asset maximum must remain handoff-eligible.');
const overMaximumAssets = [boundedJpeg(1_000_001, 0x44), boundedJpeg(1_000_000, 0x55), boundedJpeg(1_000_000, 0x66)];
const overMaximumRefs = overMaximumAssets.map((bytes) => `<img src="assets/${sha256Hex(bytes)}.jpg" alt="Over limit">`).join('');
const overMaximumBundle = signedBundleInput({
  productionHtml: `<!doctype html><main>${overMaximumRefs}</main>\n`,
  assetBytes: overMaximumAssets,
  leadRouteMode: 'not_required',
  checkoutSessionId: 'cs_test_arc2_over_maximum_asset_bundle',
});
assert.throws(() => normalizeStartPayload(overMaximumBundle.input, env, now), /aggregate size/i,
  'Even correctly signed assets exceeding the intake maximum by one byte must fail closed.');

const orphanHtml = assetHtml.replace(`<img src="${assetPath}" alt="Customer logo">`, '');
assert.throws(() => normalizeStartPayload({ ...assetInput, deploy_artifacts: canonicalJson(assetArtifactsWithBytes.map(({ path, bytes }) => ({
  path, content_base64: (path === 'index.html' ? Buffer.from(orphanHtml) : bytes).toString('base64'),
}))) }, env, now), /signed evidence|asset references|bytes/i);
const previewHostHtml = assetHtml.replace(assetPath, `https://arcwebhq-cpu.github.io/arc-previews/${artifactEvidenceObject.preview_folder}/${assetPath}`);
assert.throws(() => normalizeStartPayload({ ...assetInput, deploy_artifacts: canonicalJson(assetArtifactsWithBytes.map(({ path, bytes }) => ({
  path, content_base64: (path === 'index.html' ? Buffer.from(previewHostHtml) : bytes).toString('base64'),
}))) }, env, now), /signed evidence|preview host|bytes/i);
const assetSiteName = 'arc-lead-route-' + 'a'.repeat(24);
const assetSiteId = 'site-asset-123';
const assetDeployId = 'deploy-asset-123';
const assetFormId = 'form-asset-123';
const assetHookId = 'hook-asset-123';
const assetAccountId = 'account-asset-123';
const assetProductionUrl = `https://${assetSiteName}.netlify.app/`;
const assetRecord = {
  netlify_site_id: assetSiteId,
  netlify_site_name: assetSiteName,
  netlify_session_id: '11111111-1111-4111-8111-111111111111',
  lead_route_mode: 'netlify_form',
};
const assetReadbackFetch = async (url) => {
  const parsed = new URL(url);
  const apiPath = `${parsed.pathname}${parsed.search}`;
  if (apiPath === `/api/v1/sites/${assetSiteId}`) return new Response(JSON.stringify({
    id: assetSiteId, name: assetSiteName, session_id: assetRecord.netlify_session_id,
    account_id: assetAccountId, published_deploy: { id: assetDeployId },
  }), { headers: { 'content-type': 'application/json' } });
  if (apiPath === `/api/v1/accounts/${assetAccountId}`) return new Response(JSON.stringify({ id: assetAccountId }), { headers: { 'content-type': 'application/json' } });
  if (apiPath === `/api/v1/sites/${assetSiteId}/deploys/${assetDeployId}`) return new Response(JSON.stringify({ id: assetDeployId, site_id: assetSiteId, state: 'ready' }), { headers: { 'content-type': 'application/json' } });
  if (apiPath === `/api/v1/sites/${assetSiteId}/files`) return new Response(JSON.stringify(assetArtifacts.map(item => ({ path: `/${item.path}`, size: item.size }))), { headers: { 'content-type': 'application/json' } });
  if (apiPath.startsWith(`/api/v1/sites/${assetSiteId}/files/`)) {
    const relative = decodeURIComponent(apiPath.slice(`/api/v1/sites/${assetSiteId}/files/`.length));
    const entry = assetArtifactsWithBytes.find(item => item.path === relative);
    return entry ? new Response(entry.bytes) : new Response('', { status: 404 });
  }
  if (apiPath === `/api/v1/sites/${assetSiteId}/forms`) return new Response(JSON.stringify([{ id: assetFormId, site_id: assetSiteId, name: 'sample-lead' }]), { headers: { 'content-type': 'application/json' } });
  if (apiPath === `/api/v1/hooks?site_id=${assetSiteId}`) return new Response(JSON.stringify([{
    id: assetHookId, site_id: assetSiteId, form_id: assetFormId, type: 'email', event: 'submission_created', disabled: false,
    data: { email: leadEmail },
  }]), { headers: { 'content-type': 'application/json' } });
  if (url === assetProductionUrl) return new Response(assetHtml.replace(' data-netlify="true"', '').replace(' netlify-honeypot="bot-field"', ''), { headers: {
    'content-type': 'text/html', 'content-security-policy': ARC2_CONTENT_SECURITY_POLICY,
  } });
  if (url === new URL(assetPath, assetProductionUrl).toString()) return new Response(pngBytes, { headers: { 'content-type': 'image/png' } });
  return new Response('', { status: 404 });
};
const assetReadback = await verifyNetlifyHandoff(assetRecord, {
  accountId: assetAccountId, artifacts: assetArtifacts, phase: 'final', deployId: assetDeployId,
  formId: assetFormId, formName: 'sample-lead', hookId: assetHookId, leadEmailSha256: sha256Hex(leadEmail),
}, env, assetReadbackFetch, { deadlineMs: Date.now() + 10_000 });
assert.equal(assetReadback.productionUrl, assetProductionUrl);
await assert.rejects(verifyNetlifyHandoff(assetRecord, {
  accountId: assetAccountId, artifacts: assetArtifacts, phase: 'final', deployId: assetDeployId,
  formId: assetFormId, formName: 'sample-lead', hookId: assetHookId, leadEmailSha256: sha256Hex(leadEmail),
}, env, async (url, options) => url === new URL(assetPath, assetProductionUrl).toString()
  ? new Response(Buffer.concat([pngBytes, Buffer.from('tamper')]), { headers: { 'content-type': 'image/png' } })
  : assetReadbackFetch(url, options), { deadlineMs: Date.now() + 10_000 }), /asset|response body/i);

class FakeStore {
  constructor() {
    this.values = new Map();
    this.counter = 0;
    this.failPrefixOnce = null;
    this.failStateOnce = null;
  }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag, metadata: {} } : null;
  }
  async setJSON(key, data, options = {}) {
    if (this.failPrefixOnce && key.startsWith(this.failPrefixOnce)) {
      this.failPrefixOnce = null;
      throw new Error('simulated_post_state_outbox_failure');
    }
    if (this.failStateOnce && data?.state === this.failStateOnce) {
      this.failStateOnce = null;
      throw new Error('simulated_state_transition_failure');
    }
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && (!current || current.etag !== options.onlyIfMatch)) return { modified: false };
    const etag = `etag-${++this.counter}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
}

const checkoutGateStore = new FakeStore();
await assert.rejects(startHandoff(input, {
  ...tokenAliasTestEnv,
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'true',
}, {
  store: checkoutGateStore,
  clock: () => new Date(now),
  fetch: async () => { throw new Error('Checkout gating must precede provider access.'); },
  stripeAccountFetch: async () => new Response(JSON.stringify({ id: stripeAccountId, object: 'account' }), {
    status: 200, headers: { 'content-type': 'application/json' },
  }),
}), /ARC_STRIPE_CHECKOUT_EVENT_REQUIRED/,
'Required Checkout event confirmation must stop before the first handoff reservation or provider request.');
assert.equal(checkoutGateStore.values.size, 0, 'A missing Checkout receipt must not create handoff state.');

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
  if (String(url) === `https://arc-lead-route-${hmacHex(env.ARC_HANDOFF_STATE_SECRET, `site-name-v1\n${paymentEvidenceObject.checkout_session_id}\n${paymentEvidenceObject.bundle_fingerprint}`).slice(0, 24)}.netlify.app/`) return new Response(processedHtml, { headers: {
    'x-robots-tag': 'noindex, nofollow, noarchive', 'content-security-policy': ARC2_CONTENT_SECURITY_POLICY,
  } });
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
  if (path === `/api/v1/sites/${siteId}/files`) return json(artifacts.map((artifact, index) => ({
    path: `/${artifact.path}`,
    size: index === 0 ? Buffer.byteLength(ARC2_PRECLAIM_HEADERS_FILE) : artifact.size,
  })));
  if (path === `/api/v1/sites/${siteId}/files/_headers`) return options.headers?.['Content-Type'] === 'application/vnd.bitballoon.v1.raw'
    ? new Response(ARC2_PRECLAIM_HEADERS_FILE) : json({ error: 'raw-media-type-required' });
  if (path === `/api/v1/sites/${siteId}/files/index.html`) return options.headers?.['Content-Type'] === 'application/vnd.bitballoon.v1.raw'
    ? new Response(html) : json({ error: 'raw-media-type-required' });
  throw new Error(`Unexpected fake request: ${options.method || 'GET'} ${url}`);
};

// A signed external booking/phone site must complete the same immutable
// deploy/readback/claim path without inventing a Netlify form or email hook.
const noFormStore = new FakeStore();
const noFormSiteName = `arc-lead-route-${hmacHex(
  env.ARC_HANDOFF_STATE_SECRET,
  `site-name-v1\n${noFormBundle.paymentValue.checkout_session_id}\n${noFormBundle.paymentValue.bundle_fingerprint}`,
).slice(0, 24)}`;
const noFormSiteId = 'site-no-form-123';
const noFormDeployId = 'deploy-no-form-123';
const noFormPaymentIntentId = 'pi_arc2NoFormContract';
const noFormProviderCalls = [];
const noFormFetch = async (url, options = {}) => {
  const parsed = new URL(url);
  const path = `${parsed.pathname}${parsed.search}`;
  const method = options.method || 'GET';
  noFormProviderCalls.push({ method, url: String(url) });
  if (/\/(?:forms|hooks)(?:\?|$)/.test(path)) throw new Error('No-form handoff must not access form or hook APIs.');
  if (String(url) === `https://${noFormSiteName}.netlify.app/`) {
    return new Response(noFormHtml, { headers: {
      'content-type': 'text/html', 'x-robots-tag': 'noindex, nofollow, noarchive', 'content-security-policy': ARC2_CONTENT_SECURITY_POLICY,
    } });
  }
  if (path.startsWith('/api/v1/sites?name=') && path.endsWith('&filter=owner')) return json([]);
  if (path === '/api/v1/sites' && method === 'POST') return json({
    id: noFormSiteId,
    name: noFormSiteName,
    session_id: '22222222-2222-4222-8222-222222222222',
    account_id: env.NETLIFY_TEAM_ACCOUNT_ID,
    account_slug: env.NETLIFY_TEAM_SLUG,
  }, 201);
  if (path.startsWith(`/api/v1/sites/${noFormSiteId}/deploys?`) && method === 'POST') {
    return json({ id: noFormDeployId, site_id: noFormSiteId }, 201);
  }
  if (path === `/api/v1/sites/${noFormSiteId}/deploys?per_page=100` && method === 'GET') return json([]);
  if (path === `/api/v1/deploys/${noFormDeployId}`) return json({ id: noFormDeployId, site_id: noFormSiteId, state: 'ready' });
  if (path === `/api/v1/sites/${noFormSiteId}`) return json({
    id: noFormSiteId,
    name: noFormSiteName,
    session_id: '22222222-2222-4222-8222-222222222222',
    account_id: env.NETLIFY_TEAM_ACCOUNT_ID,
    account_slug: env.NETLIFY_TEAM_SLUG,
    published_deploy: { id: noFormDeployId },
  });
  if (path === `/api/v1/accounts/${env.NETLIFY_TEAM_ACCOUNT_ID}`) return json({ id: env.NETLIFY_TEAM_ACCOUNT_ID });
  if (path === `/api/v1/sites/${noFormSiteId}/deploys/${noFormDeployId}`) {
    return json({ id: noFormDeployId, site_id: noFormSiteId, state: 'ready' });
  }
  if (path === `/api/v1/sites/${noFormSiteId}/files`) {
    return json(noFormBundle.artifacts.map((artifact, index) => ({
      path: `/${artifact.path}`,
      size: index === 0 ? Buffer.byteLength(ARC2_PRECLAIM_HEADERS_FILE) : artifact.size,
    })));
  }
  if (path.startsWith(`/api/v1/sites/${noFormSiteId}/files/`)) {
    const relative = decodeURIComponent(path.slice(`/api/v1/sites/${noFormSiteId}/files/`.length));
    const artifact = noFormBundle.bundleBytes.find((item) => item.path === relative);
    if (relative === '_headers') return new Response(ARC2_PRECLAIM_HEADERS_FILE);
    return artifact ? new Response(artifact.bytes) : new Response('', { status: 404 });
  }
  throw new Error(`Unexpected no-form fake request: ${method} ${url}`);
};
const noFormAdapters = {
  store: noFormStore,
  fetch: noFormFetch,
  clock: () => new Date(now),
  uuid: () => '22222222-2222-4222-8222-222222222222',
  wait: () => Promise.resolve(),
};
const noFormBootstrap = await startHandoff(noFormBundle.input, env, noFormAdapters);
assert.equal(noFormBootstrap.record.state, 'PAYMENT_VERIFIED');
assert.equal(noFormProviderCalls.length, 0, 'No-form bootstrap must reserve state before any provider request.');
const noFormBindingValue = {
  version: STRIPE_REVERSAL_BINDING_SCHEMA,
  scope: STRIPE_REVERSAL_BINDING_SCOPE,
  issued_at: now.toISOString(),
  checkout_session_id: noFormBundle.paymentValue.checkout_session_id,
  payment_intent_id: noFormPaymentIntentId,
  handoff_id: noFormBootstrap.handoffId,
  stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
  livemode: false,
};
const noFormBindingEvidence = canonicalJson(noFormBindingValue);
await registerStripeReversalBinding(noFormBindingEvidence, hmacHex(
  env.ARC_STRIPE_REVERSAL_BINDING_SECRET,
  `${STRIPE_REVERSAL_BINDING_PREFIX}${noFormBindingEvidence}`,
), env, noFormAdapters);
const noFormRecheckValue = {
  version: STRIPE_REVERSAL_RECHECK_SCHEMA,
  scope: STRIPE_REVERSAL_RECHECK_SCOPE,
  handoff_id: noFormBootstrap.handoffId,
  checkout_session_id: noFormBundle.paymentValue.checkout_session_id,
  payment_intent_id: noFormPaymentIntentId,
  stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
  livemode: false,
  payment_intent_status: 'succeeded',
  refunded_amount_minor_units: 0,
  dispute_status: 'none',
  issued_at: now.toISOString(),
};
const noFormRecheckEvidence = canonicalJson(noFormRecheckValue);
await registerStripeReversalRecheck(noFormRecheckEvidence, hmacHex(
  env.ARC_STRIPE_REVERSAL_RECHECK_SECRET,
  `${STRIPE_REVERSAL_RECHECK_PREFIX}${noFormRecheckEvidence}`,
), env, noFormAdapters);
assert.equal((await startHandoff(noFormBundle.input, env, noFormAdapters)).record.state, 'SITE_CREATED');
assert.equal((await startHandoff(noFormBundle.input, env, noFormAdapters)).record.state, 'PRECLAIM_DEPLOY_READY');
noFormStore.failPrefixOnce = 'invitation-ready-outbox/';
await assert.rejects(startHandoff(noFormBundle.input, env, noFormAdapters), /simulated_post_state_outbox_failure/,
  'A failure after the INVITATION_READY CAS must surface instead of losing the claim authority.');
const noFormCrashed = await readEntry(noFormStore, handoffKeyFromId(noFormBootstrap.handoffId));
assert.equal(noFormCrashed.record.state, 'INVITATION_READY');
const noFormRecovered = await startHandoff(noFormBundle.input, env, noFormAdapters);
assert.match(noFormRecovered.claimBearer, /^[A-Za-z0-9_-]{43}$/);
assert.equal(noFormRecovered.record.lead_route_mode, 'not_required');
assert.equal(noFormRecovered.record.form_id, null);
assert.equal(noFormRecovered.record.hook_id, null);
assert.equal(noFormProviderCalls.some(({ url }) => /\/(?:forms|hooks)(?:\?|$)/.test(new URL(url).pathname)), false);
assert.ok([...noFormStore.values.keys()].some((key) => key.startsWith('invitation-ready-outbox/')),
  'Exact replay must recover the immutable invitation outbox after a post-CAS failure.');
const noFormReplay = await startHandoff(noFormBundle.input, env, noFormAdapters);
assert.equal(noFormReplay.claimBearer, noFormRecovered.claimBearer, 'No-form lost-response replay must return the deterministic bearer.');
const checkoutReviewStore = new FakeStore();
checkoutReviewStore.values = new Map([...noFormStore.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
checkoutReviewStore.counter = noFormStore.counter;
const checkoutSessionHmac = hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
  `stripe-checkout-session-id-v1\n${noFormBundle.paymentValue.checkout_session_id}`);
const checkoutPaymentIntentHmac = hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
  `stripe-checkout-payment-intent-id-v1\n${noFormPaymentIntentId}`);
const checkoutPaymentLinkHmac = hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
  `stripe-checkout-payment-link-id-v1\n${noFormBundle.paymentValue.payment_link_id}`);
await createIndex(checkoutReviewStore, stripeCheckoutKeys.handoffBindingKey(noFormBootstrap.handoffId), {
  schema: STRIPE_CHECKOUT_HANDOFF_BINDING_SCHEMA,
  handoff_id: noFormBootstrap.handoffId,
  checkout_session_id_hmac_sha256: checkoutSessionHmac,
  payment_intent_id_hmac_sha256: checkoutPaymentIntentHmac,
  payment_link_id_hmac_sha256: checkoutPaymentLinkHmac,
  payment_evidence_sha256: noFormRecovered.record.payment_evidence_sha256,
  stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
  livemode: false,
});
await createIndex(checkoutReviewStore, stripeCheckoutKeys.sessionStateKey(
  noFormBundle.paymentValue.checkout_session_id, env,
), {
  schema: STRIPE_CHECKOUT_SESSION_SCHEMA,
  state: 'REVIEW_REQUIRED',
  fulfillment_allowed: false,
  manual_review_required: true,
});
await assert.rejects(exchangeClaimBearer(
  noFormBootstrap.handoffId,
  noFormRecovered.claimBearer,
  { ...env, ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'true' },
  {
    store: checkoutReviewStore,
    clock: () => new Date(now),
    stripeAccountFetch: async () => new Response(JSON.stringify({ id: stripeAccountId, object: 'account' }), {
      status: 200, headers: { 'content-type': 'application/json' },
    }),
  },
), /ARC_STRIPE_CHECKOUT_LEDGER_HALT/,
'A Checkout conflict discovered after invitation creation must block claim exchange before consuming the bearer.');
assert.equal((await readEntry(checkoutReviewStore, handoffKeyFromId(noFormBootstrap.handoffId))).record.state, 'INVITATION_READY');
const noFormExpiredStore = new FakeStore();
noFormExpiredStore.values = new Map([...noFormStore.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
noFormExpiredStore.counter = noFormStore.counter;
const noFormRenewed = await startHandoff(noFormBundle.input, { ...env, ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'false' }, {
  ...noFormAdapters,
  store: noFormExpiredStore,
  clock: () => new Date(Date.parse(noFormRecovered.record.claim_token_expires_at) + 1),
});
assert.notEqual(noFormRenewed.claimBearer, noFormRecovered.claimBearer,
  'Expired no-form invitations must rotate through the authenticated start authority.');
assert.equal(noFormRenewed.record.claim_invitation_generation, noFormRecovered.record.claim_invitation_generation + 1);
await assert.rejects(exchangeClaimBearer(noFormBootstrap.handoffId, noFormRecovered.claimBearer,
  { ...env, ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'false' }, {
    store: noFormExpiredStore,
    clock: () => new Date(Date.parse(noFormRecovered.record.claim_token_expires_at) + 2),
  }), /ARC2_CLAIM_BEARER_INVALID/);
const noFormRenewalReplay = await startHandoff(noFormBundle.input,
  { ...env, ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'false' }, {
    ...noFormAdapters,
    store: noFormExpiredStore,
    clock: () => new Date(Date.parse(noFormRecovered.record.claim_token_expires_at) + 2),
  });
assert.equal(noFormRenewalReplay.claimBearer, noFormRenewed.claimBearer,
  'Lost no-form renewal response must recover the current bearer.');

const noFormReversalStore = new FakeStore();
noFormReversalStore.values = new Map([...noFormStore.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
noFormReversalStore.counter = noFormStore.counter;
const noFormCheckoutHmac = hmacHex(
  env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
  `checkout-session-v1\n${noFormBundle.paymentValue.checkout_session_id}`,
);
const noFormPaymentIntentHmac = hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `payment-intent-v1\n${noFormPaymentIntentId}`);
await createIndex(noFormReversalStore, stripeReversalKeys.reversalHandoffKey(noFormBootstrap.handoffId), {
  schema: STRIPE_REVERSAL_SCHEMA,
  handoff_id: noFormBootstrap.handoffId,
  checkout_session_id_hmac_sha256: noFormCheckoutHmac,
  payment_intent_id_hmac_sha256: noFormPaymentIntentHmac,
  delivery_halted: true,
  automatic_refund_requested: false,
});
await assert.rejects(exchangeClaimBearer(noFormBootstrap.handoffId, noFormRecovered.claimBearer, env, {
  store: noFormReversalStore,
  clock: () => new Date(now),
}), /ARC_STRIPE_REVERSAL_HALT/, 'A reversal must halt no-form ownership claim before token consumption.');
await assert.rejects(renewClaimInvitation(noFormBootstrap.handoffId, env, {
  store: noFormReversalStore,
  clock: () => new Date(Date.parse(noFormRecovered.record.claim_token_expires_at) + 1),
}), /ARC_STRIPE_REVERSAL_HALT/, 'A reversal must halt invitation renewal before generation or outbox mutation.');

const store = new FakeStore();
const adapters = {
  store,
  fetch: fakeFetch,
  clock: () => new Date(now),
  uuid: () => '11111111-1111-4111-8111-111111111111',
  wait: () => Promise.resolve(),
};
const orphanReservationStore = new FakeStore();
orphanReservationStore.failPrefixOnce = 'handoffs/';
await assert.rejects(startHandoff(input, tokenAliasTestEnv, {
  ...adapters,
  store: orphanReservationStore,
}), /simulated_post_state_outbox_failure/,
'A simulated crash may occur after the immutable checkout reservation but before the handoff row.');
assert.equal([...orphanReservationStore.values.keys()].filter(key => key.startsWith('checkout-session-index/')).length, 1);
assert.equal([...orphanReservationStore.values.keys()].filter(key => key.startsWith('handoffs/')).length, 0);
const recoveredOrphan = await startHandoff(input, tokenAliasTestEnv, {
  ...adapters,
  store: orphanReservationStore,
  clock: () => new Date(now.getTime() + 25 * 60 * 60_000),
});
assert.equal(recoveredOrphan.record.state, 'PAYMENT_VERIFIED',
  'An exact stale retry must recover an orphaned signed checkout reservation without provider access.');
const providerCallsBeforeBootstrap = fetchCalls.length;
const bootstrap = await startHandoff(input, tokenAliasTestEnv, adapters);
assert.equal(bootstrap.record.state, 'PAYMENT_VERIFIED');
assert.equal(bootstrap.reversalControlReady, false);
assert.equal(fetchCalls.length, providerCallsBeforeBootstrap,
  'The bootstrap call must return the durable handoff id before any Netlify provider write.');
const paymentIntentId = 'pi_arc2HandoffContract';
const bindingValue = {
  version: STRIPE_REVERSAL_BINDING_SCHEMA,
  scope: STRIPE_REVERSAL_BINDING_SCOPE,
  issued_at: now.toISOString(),
  checkout_session_id: paymentEvidenceObject.checkout_session_id,
  payment_intent_id: paymentIntentId,
  handoff_id: bootstrap.handoffId,
  stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
  livemode: false,
};
const bindingEvidence = canonicalJson(bindingValue);
await registerStripeReversalBinding(bindingEvidence, hmacHex(
  env.ARC_STRIPE_REVERSAL_BINDING_SECRET,
  `${STRIPE_REVERSAL_BINDING_PREFIX}${bindingEvidence}`,
), env, adapters);
const waitingForRecheck = await startHandoff(input, tokenAliasTestEnv, adapters);
assert.equal(waitingForRecheck.record.state, 'PAYMENT_VERIFIED');
assert.equal(waitingForRecheck.reversalControlReady, false);
assert.equal(fetchCalls.length, providerCallsBeforeBootstrap,
  'A durable binding alone must not permit a Netlify provider write without a fresh recheck.');
async function registerNoReversalRecheck(targetStore, issuedAt) {
  const recheckEvidence = canonicalJson({
    version: STRIPE_REVERSAL_RECHECK_SCHEMA,
    scope: STRIPE_REVERSAL_RECHECK_SCOPE,
    handoff_id: bootstrap.handoffId,
    checkout_session_id: paymentEvidenceObject.checkout_session_id,
    payment_intent_id: paymentIntentId,
    stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    livemode: false,
    payment_intent_status: 'succeeded',
    refunded_amount_minor_units: 0,
    dispute_status: 'none',
    issued_at: issuedAt.toISOString(),
  });
  return registerStripeReversalRecheck(recheckEvidence, hmacHex(
    env.ARC_STRIPE_REVERSAL_RECHECK_SECRET,
    `${STRIPE_REVERSAL_RECHECK_PREFIX}${recheckEvidence}`,
  ), env, { store: targetStore, clock: () => new Date(issuedAt) });
}
await registerNoReversalRecheck(store, now);
const haltBeforeSiteStore = new FakeStore();
haltBeforeSiteStore.values = new Map([...store.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
haltBeforeSiteStore.counter = store.counter;
const providerWritesBeforeInjectedHalt = fetchCalls.filter(({ method }) => method !== 'GET').length;
let injectedSiteHalt = false;
await assert.rejects(startHandoff(input, tokenAliasTestEnv, {
  ...adapters,
  store: haltBeforeSiteStore,
  beforeProviderMutation: async (operation) => {
    if (operation !== 'create-site' || injectedSiteHalt) return;
    injectedSiteHalt = true;
    await createIndex(haltBeforeSiteStore, stripeReversalKeys.reversalHandoffKey(bootstrap.handoffId), {
      schema: STRIPE_REVERSAL_SCHEMA,
      handoff_id: bootstrap.handoffId,
      checkout_session_id_hmac_sha256: hmacHex(
        env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
        `checkout-session-v1\n${paymentEvidenceObject.checkout_session_id}`,
      ),
      payment_intent_id_hmac_sha256: hmacHex(
        env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
        `payment-intent-v1\n${paymentIntentId}`,
      ),
      delivery_halted: true,
      automatic_refund_requested: false,
    });
  },
}), /ARC_STRIPE_REVERSAL_HALT/,
'A reversal arriving after site recovery but before creation must cancel the provider mutation.');
assert.equal(injectedSiteHalt, true);
assert.equal(fetchCalls.filter(({ method }) => method !== 'GET').length, providerWritesBeforeInjectedHalt,
  'A mid-flight reversal halt must prevent the recovered site-create POST.');
const siteStage = await startHandoff(input, tokenAliasTestEnv, adapters);
assert.equal(siteStage.record.state, 'SITE_CREATED', 'One invocation performs at most one bounded provider stage.');
const deployStage = await startHandoff(input, tokenAliasTestEnv, adapters);
assert.equal(deployStage.record.state, 'PRECLAIM_DEPLOY_READY');
const started = await startHandoff(input, tokenAliasTestEnv, adapters);
assert.equal(started.reversalControlReady, true);
assert.equal(started.record.state, 'PRECLAIM_DEPLOY_READY');
assert.equal(started.record.claim_token_expires_at, null, 'Claim TTL must not begin before durable invitation acknowledgement.');
assert.equal(started.record.lead_notification_email_sha256, sha256Hex(leadEmail));
assert.equal(started.record.lead_route_recipient_hmac_sha256, input.lead_route_recipient_hmac_sha256);
assert.ok(fetchCalls.some((call) => call.authorization === `Bearer ${env.NETLIFY_ADMIN_PAT}`), 'Netlify token alias must reach authenticated runtime requests.');
assert.equal(JSON.stringify([...store.values.values()]).includes(leadEmail), false, 'Raw lead email must not enter handoff storage.');
assert.equal(fetchCalls.some((call) => /attacker\.example|169\.254\.169\.254/.test(call.url)), false, 'Destination-controlled site URLs must never be fetched.');

const retryableDeployStore = new FakeStore();
retryableDeployStore.values = new Map([...store.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
retryableDeployStore.counter = store.counter;
const retryableKey = handoffKeyFromId(started.handoffId);
const retryableEntry = await readEntry(retryableDeployStore, retryableKey);
const retryableRecord = {
  ...retryableEntry.record,
  state: 'SITE_CREATED',
  revision: retryableEntry.record.revision + 1,
  preclaim_deploy_attempted_at: null,
  preclaim_deploy_candidate_id: null,
  preclaim_deploy_id: null,
  form_id: null,
  hook_id: null,
  email_hook_attempted_at: null,
};
retryableDeployStore.values.set(retryableKey, {
  data: retryableRecord,
  etag: `etag-${++retryableDeployStore.counter}`,
});
const recheckPath = stripeReversalKeys.recheckKey(started.handoffId);
assert.ok(retryableDeployStore.values.get(recheckPath));
const deployPostsBeforeRetryableGuard = fetchCalls.filter(({ method, url }) => method === 'POST' && /\/deploys\?/.test(url)).length;
let blockedAfterDeployIntent = false;
await assert.rejects(startHandoff(input, env, {
  ...adapters,
  store: retryableDeployStore,
  beforeProviderMutation: async (operation) => {
    if (operation === 'create-preclaim-deploy' && !blockedAfterDeployIntent) {
      blockedAfterDeployIntent = true;
      throw new Error('simulated_transient_guard_read_failure');
    }
  },
}), /simulated_transient_guard_read_failure/,
'Any guard failure after durable deploy intent must stop before the provider POST.');
assert.equal(blockedAfterDeployIntent, true);
assert.equal((await readEntry(retryableDeployStore, retryableKey)).record.preclaim_deploy_attempted_at, null,
  'A guard failure before the provider call must clear only its exact retryable intent marker.');
assert.equal(fetchCalls.filter(({ method, url }) => method === 'POST' && /\/deploys\?/.test(url)).length, deployPostsBeforeRetryableGuard);
const retryableDeploy = await startHandoff(input, env, { ...adapters, store: retryableDeployStore });
assert.equal(retryableDeploy.record.state, 'PRECLAIM_DEPLOY_READY');
assert.equal(fetchCalls.filter(({ method, url }) => method === 'POST' && /\/deploys\?/.test(url)).length,
  deployPostsBeforeRetryableGuard + 1, 'A restored fresh recheck must retry the provider mutation exactly once.');

const expiredDeployStore = new FakeStore();
expiredDeployStore.values = new Map([...store.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
expiredDeployStore.counter = store.counter;
expiredDeployStore.values.set(retryableKey, {
  data: retryableRecord,
  etag: `etag-${++expiredDeployStore.counter}`,
});
const realDateNow = Date.now;
const expiredDeployDeadline = realDateNow() + 1_000;
let expireDeployAfterGuard = false;
try {
  await assert.rejects(startHandoff(input, env, {
    ...adapters,
    store: expiredDeployStore,
    providerStageDeadlineMs: expiredDeployDeadline,
    beforeProviderMutation: async (operation) => {
      if (operation === 'create-preclaim-deploy') {
        expireDeployAfterGuard = true;
        Date.now = () => expiredDeployDeadline + 1;
      }
    },
  }), /PROVIDER_STAGE_DEADLINE/,
  'A stage deadline expiring after the second guard but before fetch entry must remain retryable.');
} finally {
  Date.now = realDateNow;
}
assert.equal(expireDeployAfterGuard, true);
assert.equal((await readEntry(expiredDeployStore, retryableKey)).record.preclaim_deploy_attempted_at, null,
  'Deadline expiry before deploy fetch entry must clear the exact provider intent.');
assert.equal(fetchCalls.filter(({ method, url }) => method === 'POST' && /\/deploys\?/.test(url)).length,
  deployPostsBeforeRetryableGuard + 1, 'No deploy POST may begin after the shared deadline expires.');
const retriedExpiredDeploy = await startHandoff(input, env, { ...adapters, store: expiredDeployStore });
assert.equal(retriedExpiredDeploy.record.state, 'PRECLAIM_DEPLOY_READY');
assert.equal(fetchCalls.filter(({ method, url }) => method === 'POST' && /\/deploys\?/.test(url)).length,
  deployPostsBeforeRetryableGuard + 2, 'A pre-fetch deadline failure must retry the provider mutation exactly once.');

const expiredHookStore = new FakeStore();
expiredHookStore.values = new Map([...expiredDeployStore.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
expiredHookStore.counter = expiredDeployStore.counter;
const hookReadyEntry = await readEntry(expiredHookStore, retryableKey);
expiredHookStore.values.set(retryableKey, {
  data: {
    ...hookReadyEntry.record,
    revision: hookReadyEntry.record.revision + 1,
    form_id: null,
    hook_id: null,
    email_hook_attempted_at: null,
  },
  etag: `etag-${++expiredHookStore.counter}`,
});
const expiredHookDeadline = realDateNow() + 1_000;
const hookPostsBeforeDeadline = fetchCalls.filter(({ method, url }) => method === 'POST' && /\/hooks\?/.test(url)).length;
let expireHookAfterGuard = false;
let isolatedHookCreated = false;
const isolatedHookFetch = async (url, options = {}) => {
  const parsed = new URL(url);
  const path = `${parsed.pathname}${parsed.search}`;
  if (path === `/api/v1/hooks?site_id=${siteId}`) {
    fetchCalls.push({ url: String(url), method: options.method || 'GET', authorization: options.headers?.Authorization });
    if ((options.method || 'GET') === 'GET') return json(isolatedHookCreated ? [{
      id: hookId, site_id: siteId, form_id: formId, type: 'email', event: 'submission_created', data: { email: leadEmail },
    }] : []);
    isolatedHookCreated = true;
    return json({
      id: hookId, site_id: siteId, form_id: formId, type: 'email', event: 'submission_created', data: { email: leadEmail },
    }, 201);
  }
  return fakeFetch(url, options);
};
try {
  await assert.rejects(startHandoff(input, env, {
    ...adapters,
    fetch: isolatedHookFetch,
    store: expiredHookStore,
    providerStageDeadlineMs: expiredHookDeadline,
    beforeProviderMutation: async (operation) => {
      if (operation === 'create-email-hook') {
        expireHookAfterGuard = true;
        Date.now = () => expiredHookDeadline + 1;
      }
    },
  }), /operation deadline|PROVIDER_STAGE_DEADLINE/i,
  'A hook deadline expiring after the second guard but before fetch entry must remain retryable.');
} finally {
  Date.now = realDateNow;
}
assert.equal(expireHookAfterGuard, true);
assert.equal((await readEntry(expiredHookStore, retryableKey)).record.email_hook_attempted_at, null,
  'Deadline expiry before hook fetch entry must clear the exact provider intent.');
assert.equal(fetchCalls.filter(({ method, url }) => method === 'POST' && /\/hooks\?/.test(url)).length, hookPostsBeforeDeadline,
  'No hook POST may begin after the shared deadline expires.');
const retriedExpiredHook = await startHandoff(input, env, { ...adapters, store: expiredHookStore, fetch: isolatedHookFetch });
assert.equal(retriedExpiredHook.record.hook_id, hookId);
assert.equal(fetchCalls.filter(({ method, url }) => method === 'POST' && /\/hooks\?/.test(url)).length, hookPostsBeforeDeadline + 1,
  'A pre-fetch hook deadline failure must retry the provider mutation exactly once.');

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
const staleReplayAt = new Date(now.getTime() + 25 * 60 * 60_000);
const staleReplayStore = new FakeStore();
staleReplayStore.values = new Map([...store.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
staleReplayStore.counter = store.counter;
await registerNoReversalRecheck(staleReplayStore, staleReplayAt);
const staleReplay = await startHandoff(input, env, { ...adapters, store: staleReplayStore, clock: () => new Date(staleReplayAt) });
assert.equal(staleReplay.idempotentReplay, true, 'Exact immutable state must remain resumable after evidence freshness expires.');
const freshStore = new FakeStore();
const delayedV3Bootstrap = await startHandoff(input, env, { ...adapters, store: freshStore, clock: () => new Date(now.getTime() + 25 * 60 * 60_000) });
assert.equal(delayedV3Bootstrap.record.state, 'PAYMENT_VERIFIED',
  'A currently reverified paid v3 Session must not be stranded solely because checkout creation was over 24 hours ago.');

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
  payment_evidence_hmac_sha256: hmacHex(env.ARC_CHECKOUT_BINDING_SECRET, `${PAYMENT_SIGNATURE_PREFIX}test\n${alternatePaymentEvidence}`),
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
await registerNoReversalRecheck(store, claimAt);
const randomClaimToken = 'r'.repeat(43);
let unreachable = await readEntry(store, handoffKeyFromId(started.handoffId));
unreachable = await replaceEntry(store, handoffKeyFromId(started.handoffId), unreachable, {
  ...unreachable.record,
  state: 'CLAIM_WRAPPER_CONSUMED',
  revision: unreachable.record.revision + 1,
  claim_invitation_ready_at: invitationAt.toISOString(),
  lead_route_provider_message_id_sha256: sha256Hex('provider-message-123'),
  lead_route_receipt_sha256: sha256Hex('lead-route-receipt'),
  claim_token_consumed_hmac_sha256: hmacHex(env.ARC_CLAIM_TOKEN_SECRET, `arc2-claim-bearer-at-rest-v1\n${randomClaimToken}`),
  claim_token_expires_at: new Date(invitationAt.getTime() + 30 * 60_000).toISOString(),
  claim_token_used_at: claimAt.toISOString(),
  claim_wrapper_consumed_at: claimAt.toISOString(),
  claim_jwt_issued_at: Math.floor(claimAt.getTime() / 1000),
  updated_at: invitationAt.toISOString(),
});
assert.throws(() => validateExpectedBindings({ ...unreachable.record, claim_token_expires_at: 'not-a-date' }), /invalid|ISO timestamp/);
assert.throws(() => validateExpectedBindings({ ...unreachable.record, claim_token_expires_at: invitationAt.toISOString() }), /expiry ordering/);
const claimUrl = netlifyClaimUrl(unreachable.record, env);
assert.match(claimUrl, /^https:\/\/app\.netlify\.com\/claim#[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
const payload = JSON.parse(Buffer.from(claimUrl.split('#')[1].split('.')[1], 'base64url').toString());
assert.deepEqual(Object.keys(payload).sort(), ['claim_webhook', 'client_id', 'exp', 'iat', 'session_id']);
assert.equal(payload.claim_webhook, 'https://arcweb.onl/api/arc2/claim-webhook');
assert.equal(payload.iat, Math.floor(claimAt.getTime() / 1000));
assert.equal(payload.exp, payload.iat + CLAIM_JWT_TTL_SECONDS,
  'The irreversible external claim JWT must expire quickly even while the invitation wrapper has a longer lifetime.');

const refreshedAt = new Date(claimAt.getTime() + (CLAIM_JWT_TTL_SECONDS + 1) * 1000);
const refreshStore = new FakeStore();
refreshStore.values = new Map([...store.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
refreshStore.counter = store.counter;
await registerNoReversalRecheck(refreshStore, refreshedAt);
const refreshed = await exchangeClaimBearer(started.handoffId, randomClaimToken, env, {
  ...adapters, store: refreshStore, clock: () => new Date(refreshedAt),
});
const refreshedPayload = JSON.parse(Buffer.from(refreshed.claimUrl.split('#')[1].split('.')[1], 'base64url').toString());
assert.equal(refreshedPayload.iat, Math.floor(refreshedAt.getTime() / 1000));
assert.equal(refreshedPayload.exp, refreshedPayload.iat + CLAIM_JWT_TTL_SECONDS,
  'An exact consumed-bearer replay after expiry must issue a fresh short-lived provider JWT.');
assert.notEqual(refreshed.claimUrl, claimUrl);

const reversalDuringRefreshStore = new FakeStore();
reversalDuringRefreshStore.values = new Map([...refreshStore.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
reversalDuringRefreshStore.counter = refreshStore.counter;
const paymentIntentHmac = hmacHex(env.ARC_STRIPE_REVERSAL_HMAC_SECRET, `payment-intent-v1\n${paymentIntentId}`);
await createIndex(reversalDuringRefreshStore, stripeReversalKeys.pendingPaymentKeyFromHmac(paymentIntentHmac), {
  schema: STRIPE_PENDING_PAYMENT_SCHEMA,
  payment_intent_id_hmac_sha256: paymentIntentHmac,
  stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
  livemode: false,
  delivery_halted: true,
});
const haltedRefreshAt = new Date(refreshedAt.getTime() + (CLAIM_JWT_TTL_SECONDS + 1) * 1000);
await assert.rejects(exchangeClaimBearer(started.handoffId, randomClaimToken, env, {
  ...adapters, store: reversalDuringRefreshStore, clock: () => new Date(haltedRefreshAt),
}), /ARC_STRIPE_REVERSAL_HALT/,
'A reversal halt must prevent refreshing an expired provider claim JWT.');
assert.equal((await readEntry(reversalDuringRefreshStore, handoffKeyFromId(started.handoffId))).record.claim_jwt_issued_at,
  refreshedPayload.iat, 'A blocked refresh must not advance durable JWT issuance state.');

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

const consumedSnapshotForClaim = new Map([...store.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
const destinationAccountId = 'account-customer-123';
const finalDeployId = 'deploy-final-123';
const claimedFetchFactory = () => {
  let finalPublished = false;
  return async (url, options = {}) => {
    const parsed = new URL(url);
    const path = `${parsed.pathname}${parsed.search}`;
    const method = options.method || 'GET';
    if (path === `/api/v1/sites/${siteId}`) return json({
      id: siteId,
      name: started.record.netlify_site_name,
      session_id: started.record.netlify_session_id,
      account_id: destinationAccountId,
      account_slug: 'customer-team',
      published_deploy: { id: finalPublished ? finalDeployId : deployId },
    });
    if (path === `/api/v1/accounts/${destinationAccountId}`) return json({ id: destinationAccountId });
    if (path === `/api/v1/sites/${siteId}/deploys?per_page=100` && method === 'GET') return json([]);
    if (path.startsWith(`/api/v1/sites/${siteId}/deploys?`) && method === 'POST') {
      finalPublished = true;
      return json({ id: finalDeployId, site_id: siteId }, 201);
    }
    if (path === `/api/v1/sites/${siteId}/deploys/${deployId}`) return json({ id: deployId, site_id: siteId, state: 'ready' });
    if (path === `/api/v1/sites/${siteId}/deploys/${finalDeployId}` || path === `/api/v1/deploys/${finalDeployId}`) {
      return json({ id: finalDeployId, site_id: siteId, state: 'ready' });
    }
    if (path === `/api/v1/sites/${siteId}/files`) return json(artifacts.map((artifact, index) => ({
      path: `/${artifact.path}`,
      size: index === 0 && !finalPublished ? Buffer.byteLength(ARC2_PRECLAIM_HEADERS_FILE) : artifact.size,
    })));
    if (path === `/api/v1/sites/${siteId}/files/_headers`) return new Response(
      finalPublished ? ARC2_PRODUCTION_HEADERS_FILE : ARC2_PRECLAIM_HEADERS_FILE,
    );
    if (path === `/api/v1/sites/${siteId}/files/index.html`) return new Response(html);
    if (path === `/api/v1/sites/${siteId}/forms`) return json([{ id: formId, site_id: siteId, name: 'sample-lead' }]);
    if (path === `/api/v1/hooks?site_id=${siteId}`) return json([{
      id: hookId, site_id: siteId, form_id: formId, type: 'email', event: 'submission_created', data: { email: leadEmail },
    }]);
    if (String(url) === `https://${started.record.netlify_site_name}.netlify.app/`) return new Response(processedHtml, { headers: {
      'content-security-policy': ARC2_CONTENT_SECURITY_POLICY,
      'content-type': 'text/html',
      ...(finalPublished ? {} : { 'x-robots-tag': 'noindex, nofollow, noarchive' }),
    } });
    throw new Error(`Unexpected claimed-flow request: ${method} ${url}`);
  };
};

const successfulClaimStore = new FakeStore();
successfulClaimStore.values = new Map([...consumedSnapshotForClaim.entries()].map(([key, value]) => [key, structuredClone(value)]));
successfulClaimStore.counter = store.counter;
const successfulClaimFetch = claimedFetchFactory();
const successfulClaim = await processClaimWebhook({ claimed: true, site_id: siteId, destination_acc_id: destinationAccountId }, env, {
  ...claimAdapters, store: successfulClaimStore, fetch: successfulClaimFetch,
});
assert.equal(successfulClaim.record.state, 'FINAL_DEPLOY_READY',
  'One authenticated claim callback must converge every bounded post-claim stage.');
const delayedAuthorizationAt = new Date(claimAt.getTime() + 31 * 60_000);
await registerNoReversalRecheck(successfulClaimStore, delayedAuthorizationAt);
const delayedPrivateStatus = await getHandoffStatus(started.handoffId, env, {
  ...claimAdapters,
  store: successfulClaimStore,
  fetch: successfulClaimFetch,
  clock: () => new Date(delayedAuthorizationAt),
}, { includePrivate: true });
const delayedAuthorization = JSON.parse(delayedPrivateStatus.claim_state_evidence_private);
assert.equal(delayedAuthorization.issued_at, delayedAuthorizationAt.toISOString(),
  'A worker outage beyond the original 30-minute window must receive freshly reverified send authority.');
const delayedPrivateReplay = await getHandoffStatus(started.handoffId, env, {
  ...claimAdapters,
  store: successfulClaimStore,
  fetch: successfulClaimFetch,
  clock: () => new Date(delayedAuthorizationAt),
}, { includePrivate: true });
assert.equal(delayedPrivateReplay.claim_state_evidence_private, delayedPrivateStatus.claim_state_evidence_private,
  'A lost send-authority response at the same observation instant must replay exact evidence.');

const staleSendAuthorizationAt = new Date(delayedAuthorizationAt.getTime() + 60_001);
await assert.rejects(getHandoffStatus(started.handoffId, env, {
  ...claimAdapters,
  store: successfulClaimStore,
  fetch: successfulClaimFetch,
  clock: () => new Date(staleSendAuthorizationAt),
}, { includePrivate: true }), /ARC_STRIPE_REVERSAL_RECHECK_REQUIRED/,
'Final-email authority must fail closed once its Stripe observation is more than one minute old.');
await registerNoReversalRecheck(successfulClaimStore, staleSendAuthorizationAt);
const refreshedPrivateStatus = await getHandoffStatus(started.handoffId, env, {
  ...claimAdapters,
  store: successfulClaimStore,
  fetch: successfulClaimFetch,
  clock: () => new Date(staleSendAuthorizationAt),
}, { includePrivate: true });
assert.equal(JSON.parse(refreshedPrivateStatus.claim_state_evidence_private).issued_at,
  staleSendAuthorizationAt.toISOString(), 'A new authoritative Stripe observation must restore bounded send authority.');

const sendReadbackRaceStore = new FakeStore();
sendReadbackRaceStore.values = new Map([...successfulClaimStore.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
sendReadbackRaceStore.counter = successfulClaimStore.counter;
let reversalInjectedDuringSendReadback = false;
const sendReadbackRaceFetch = async (...args) => {
  const response = await successfulClaimFetch(...args);
  if (!reversalInjectedDuringSendReadback) {
    reversalInjectedDuringSendReadback = true;
    await createIndex(sendReadbackRaceStore, stripeReversalKeys.pendingPaymentKeyFromHmac(paymentIntentHmac), {
      schema: STRIPE_PENDING_PAYMENT_SCHEMA,
      payment_intent_id_hmac_sha256: paymentIntentHmac,
      stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
      livemode: false,
      delivery_halted: true,
    });
  }
  return response;
};
await assert.rejects(getHandoffStatus(started.handoffId, env, {
  ...claimAdapters,
  store: sendReadbackRaceStore,
  fetch: sendReadbackRaceFetch,
  clock: () => new Date(staleSendAuthorizationAt),
}, { includePrivate: true }), /ARC_STRIPE_REVERSAL_HALT/,
'A reversal observed during final Netlify readback must be caught before send authority is emitted.');
assert.equal(reversalInjectedDuringSendReadback, true);

const crashedClaimStore = new FakeStore();
crashedClaimStore.values = new Map([...consumedSnapshotForClaim.entries()].map(([key, value]) => [key, structuredClone(value)]));
crashedClaimStore.counter = store.counter;
crashedClaimStore.failStateOnce = 'CLAIMED_VERIFIED';
const crashFetch = claimedFetchFactory();
await assert.rejects(processClaimWebhook({ claimed: true, site_id: siteId, destination_acc_id: destinationAccountId }, env, {
  ...claimAdapters, store: crashedClaimStore, fetch: crashFetch,
}), /simulated_state_transition_failure/);
assert.equal((await readEntry(crashedClaimStore, handoffKeyFromId(started.handoffId))).record.state, 'CLAIM_CALLBACK_RECEIVED');
const resumedClaim = await processClaimWebhook({ claimed: true, site_id: siteId, destination_acc_id: destinationAccountId }, env, {
  ...claimAdapters, store: crashedClaimStore, fetch: crashFetch,
});
assert.equal(resumedClaim.record.state, 'FINAL_DEPLOY_READY',
  'A callback replay must resume from the last durable post-claim transition after a crash.');

const expiredClaimStore = new FakeStore();
expiredClaimStore.values = new Map([...consumedSnapshotForClaim.entries()].map(([key, value]) => [key, structuredClone(value)]));
expiredClaimStore.counter = store.counter;
await assert.rejects(processClaimWebhook({ claimed: true, site_id: siteId, destination_acc_id: destinationAccountId }, env, {
  ...claimAdapters,
  store: expiredClaimStore,
  fetch: claimedFetchFactory(),
  providerStageDeadlineMs: Date.now() - 1,
}), /DEADLINE/);
assert.equal((await readEntry(expiredClaimStore, handoffKeyFromId(started.handoffId))).record.state, 'CLAIM_WRAPPER_CONSUMED',
  'An exhausted shared provider deadline must stop before the first post-claim state mutation.');

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
assert.equal(Object.keys(evidenceValue).length, 22);
assert.equal(evidenceValue.provider_observed_at, evidenceAt.toISOString());
assert.equal(evidenceValue.issued_at, evidenceAt.toISOString(),
  'Final email authority must carry the exact fresh provider-observation time.');
assert.match(evidenceValue.authorization_nonce_sha256, /^[a-f0-9]{64}$/);
assert.equal(evidence.claim_state_evidence_hmac_sha256, createHmac('sha256', env.ARC_CLAIM_STATE_EVIDENCE_SECRET)
  .update(`${CLAIM_STATE_SIGNATURE_PREFIX}${evidence.claim_state_evidence_private}`).digest('hex'));

assert.equal(startConfig.path, '/api/arc2/handoff/start');
assert.equal(claimConfig.path, '/api/arc2/claim');
assert.equal(webhookConfig.path, '/api/arc2/claim-webhook');
assert.equal(invitationConfig.path, '/internal/arc2/claim-invitation-ready');
assert.equal(statusConfig.path, '/internal/arc2/handoff-status');
for (const config of [startConfig, claimConfig, webhookConfig, invitationConfig, statusConfig]) assert.equal(typeof config.rateLimit.windowLimit, 'number');

const configuredSnapshot = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
Object.assign(process.env, sandboxEnv);
try {
  const originalFetch = globalThis.fetch;
  let externalCalls = 0;
  globalThis.fetch = async () => {
    externalCalls += 1;
    throw new Error('External call must be unreachable.');
  };
  try {
    const oversizedRequest = (url, byteCount, headers = {}) => new Request(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(byteCount)); controller.close(); } }),
      duplex: 'half',
    });
    for (const [handler, request, expectedError] of [
      [startHandler, oversizedRequest('https://arcweb.onl/api/arc2/handoff/start', 5_000_001,
        { authorization: `Bearer ${env.ARC_HANDOFF_TRIGGER_SECRET}` }), 'handoff_request_too_large'],
      [invitationHandler, oversizedRequest('https://arcweb.onl/internal/arc2/claim-invitation-ready', 30_001,
        { authorization: `Bearer ${env.ARC_HANDOFF_TRIGGER_SECRET}` }), 'receipt_too_large'],
      [webhookHandler, oversizedRequest('https://arcweb.onl/api/arc2/claim-webhook', 4097), 'claim_hint_too_large'],
    ]) {
      const response = await handler(request, { get arc2Store() { throw new Error('Oversized bodies must not touch storage.'); } });
      assert.equal(response.status, 413);
      assert.deepEqual(await response.json(), { error: expectedError });
    }
    assert.equal(externalCalls, 0, 'Headerless oversized bodies must be rejected before storage or provider access.');

    const endpointBootstrapStore = new FakeStore();
    const endpointBootstrap = await startHandler(new Request('https://arcweb.onl/api/arc2/handoff/start', {
      method: 'POST',
      headers: { authorization: `Bearer ${env.ARC_HANDOFF_TRIGGER_SECRET}`, 'content-type': 'application/json' },
      body: JSON.stringify(input),
    }), { arc2Store: endpointBootstrapStore, clock: () => new Date(now) });
    assert.equal(endpointBootstrap.status, 202);
    assert.deepEqual(await endpointBootstrap.json(), {
      handoff_id: bootstrap.handoffId,
      reversal_control_ready: false,
      status: 'PAYMENT_VERIFIED',
      site_ready: false,
      claim_available: false,
      claim_verified: false,
      delivery_ready: false,
      delivered: false,
      updated_at: now.toISOString(),
    }, 'The public start endpoint must expose the reserved handoff id while reversal binding and recheck remain pending.');
    assert.equal(externalCalls, 0, 'The start bootstrap response must precede every provider call.');
    const noFormEndpointResponse = await startHandler(new Request('https://arcweb.onl/api/arc2/handoff/start', {
      method: 'POST',
      headers: { authorization: `Bearer ${env.ARC_HANDOFF_TRIGGER_SECRET}`, 'content-type': 'application/json' },
      body: JSON.stringify(noFormBundle.input),
    }), { arc2Store: noFormStore, clock: () => new Date(now) });
    assert.equal(noFormEndpointResponse.status, 202);
    const noFormEndpointBody = await noFormEndpointResponse.json();
    assert.equal(noFormEndpointBody.status, 'INVITATION_READY');
    assert.equal(noFormEndpointBody.claim_invitation_expires_at, noFormRecovered.record.claim_token_expires_at);
    assert.equal(noFormEndpointBody.claim_invitation_url,
      `https://arcweb.onl/claim/#arc2.${noFormBootstrap.handoffId}.${noFormRecovered.claimBearer}`,
      'The authenticated start sender must recover the exact no-form claim invitation without storing its bearer.');
    const noFormClaimed = await exchangeClaimBearer(noFormBootstrap.handoffId, noFormRecovered.claimBearer, env, {
      store: noFormStore,
      clock: () => new Date(now),
    });
    assert.equal(noFormClaimed.record.state, 'CLAIM_WRAPPER_CONSUMED');
    assert.match(noFormClaimed.claimUrl, /^https:\/\/app\.netlify\.com\/claim#[A-Za-z0-9_.-]+$/);
    const noFormClaimReplay = await exchangeClaimBearer(noFormBootstrap.handoffId, noFormRecovered.claimBearer, env, {
      store: noFormStore,
      clock: () => new Date(now),
    });
    assert.equal(noFormClaimReplay.claimUrl, noFormClaimed.claimUrl, 'No-form claim exchange must be replay-safe after a lost response.');
    assert.equal(externalCalls, 0, 'No-form invitation recovery and claim exchange must not make an unbound provider call.');
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
