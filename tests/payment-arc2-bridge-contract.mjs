import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import {
  PAYMENT_ARC2_COMPLETION_SCHEMA,
  PAYMENT_ARC2_LEASE_SECONDS,
  PAYMENT_ARC2_OUTBOX_SCHEMA,
  PAYMENT_ARC2_PENDING_INDEX_SCHEMA,
  PAYMENT_ARC2_REVIEW_SESSION_BINDING_SCHEMA,
  claimNextPaymentArc2StartOutbox,
  claimPaymentArc2StartOutbox,
  completePaymentArc2StartOutbox,
  createPaymentArc2ReviewEvidence,
  createPaymentArc2StartOutbox,
  paymentArc2BridgeConfiguration,
  releasePaymentArc2StartOutbox,
} from '../netlify/lib/payment-arc2-bridge-core.mjs';
import {
  ARC2_PRODUCTION_HEADERS_FILE,
  ARTIFACT_SIGNATURE_PREFIX,
  hmacHex,
} from '../netlify/lib/arc2-handoff-core.mjs';
import { startHandoff, startReviewHandoff } from '../netlify/lib/arc2-handoff-service.mjs';
import { stripeCheckoutKeys } from '../netlify/lib/stripe-checkout-core.mjs';
import {
  ensureReviewEmailRecipientControl,
  suppressReviewEmailRecipientControl,
} from '../netlify/lib/review-email-recipient-control-core.mjs';
import {
  bindReviewCheckoutSession,
  requestReviewCheckoutRevocation,
  reserveReviewCheckoutBinding,
} from '../netlify/lib/review-checkout-revocation-core.mjs';

const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
};
const hash = value => createHash('sha256').update(value).digest('hex');
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');

class FakeStore {
  constructor() {
    this.values = new Map();
    this.sequence = 0;
    this.calls = 0;
    this.writeKeys = [];
    this.failAfterCommitPrefixOnce = null;
    this.forceContentionOnce = false;
  }

  async getWithMetadata(key) {
    this.calls += 1;
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }

  async setJSON(key, data, options = {}) {
    this.calls += 1;
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    if (options.onlyIfMatch && this.forceContentionOnce) {
      this.forceContentionOnce = false;
      return { modified: false };
    }
    const etag = `e-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    this.writeKeys.push(key);
    if (this.failAfterCommitPrefixOnce && key.startsWith(this.failAfterCommitPrefixOnce)) {
      this.failAfterCommitPrefixOnce = null;
      throw new Error('simulated_post_commit_crash');
    }
    return { modified: true, etag };
  }

  async overwrite(key, data) {
    return this.setJSON(key, data);
  }

  async delete(key) {
    this.values.delete(key);
  }

  list({ prefix, paginate }) {
    assert.equal(paginate, true);
    const keys = [...this.values.keys()].filter((key) => key.startsWith(prefix)).sort();
    return {
      async *[Symbol.asyncIterator]() {
        yield { blobs: keys.map((key) => ({ key })) };
      },
    };
  }
}

const now = new Date('2026-08-27T12:00:00.000Z');
const rawEmail = 'private.owner@example.test';
const rawPayerEmail = 'billing.agent@example.test';
const rawAccountId = 'acct_arcSandboxAuthority';
const rawSessionId = 'cs_test_arcPaidAuthoritySession';
const rawPaymentIntentId = 'pi_arcPaidAuthorityIntent';
const inviteHmac = hash('authoritative-review-invite');
const accountSha256 = hash(rawAccountId);

const env = {
  ARC_PAYMENT_ARC2_BRIDGE_ENABLED: 'true',
  ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET: 'bridge-hmac-secret-unique-0123456789-abcdefghijkl',
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256: accountSha256,
  ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
  ARC_STRIPE_CHECKOUT_LEDGER_ENABLED: 'true',
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'true',
  ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER: 'arc_review_checkout_asdfghjk',
  ARC_RUNTIME_ENVIRONMENT: 'sandbox',
  ARC_ALLOW_TEST_MODE_EVENTS: 'true',
  ARC_HANDOFF_ENABLED: 'false',
  ARC_STRIPE_WEBHOOK_SIGNING_SECRET: 'whsec_unique_checkout_webhook_0123456789_abcdefgh',
  ARC_STRIPE_REVERSAL_HMAC_SECRET: 'reversal-hmac-secret-unique-0123456789-abcdefgh',
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: ['rk', 'test', 'arcAuthorityVerificationKey0123456789'].join('_'),
  ARC_STRIPE_WEBHOOK_API_VERSION: '2026-07-29.dahlia',
  ARC_REVIEW_PORTAL_ENABLED: 'true',
  ARC_REVIEW_CHECKOUT_ENABLED: 'true',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://previews.arcweb.onl',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
  ARC_REVIEW_INVITE_HMAC_SECRET: 'review-invite-secret-unique-0123456789-abcdefgh',
  ARC_REVIEW_SESSION_HMAC_SECRET: 'review-session-secret-unique-0123456789-abcdefgh',
  ARC_REVIEW_RECORD_HMAC_SECRET: 'review-record-secret-unique-0123456789-abcdefgh',
  ARC_REVIEW_DECISION_HMAC_SECRET: 'review-decision-secret-unique-0123456789-abcdefgh',
  ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
  ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET: 'review-email-outbox-secret-unique-0123456789-abcdef',
  ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET: 'review-email-receipt-secret-unique-0123456789-abcdef',
  ARC_STRIPE_REVIEW_REVOCATION_ENABLED: 'true',
  ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET: 'review-checkout-revocation-secret-0123456789-abcdef',
  ARC_CHECKOUT_BINDING_SECRET: 'checkout-binding-secret-unique-0123456789-abcdefgh',
  ARC_CHECKOUT_BINDING_KEY_ID: '01',
  ARC_RETIRED_CHECKOUT_BINDING_KEYS_JSON: '{}',
  ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET: 'artifact-evidence-secret-unique-0123456789-abcdefgh',
  ARC_HANDOFF_STATE_SECRET: 'handoff-state-secret-unique-0123456789-abcdefgh',
  ARC_CLAIM_TOKEN_SECRET: 'claim-token-secret-unique-0123456789-abcdefgh',
  ARC_EMAIL_CLAIM_BINDING_SECRET: 'claim-email-binding-secret-unique-0123456789-abcdefgh',
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'true',
  ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_BINDING_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_RECHECK_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_BINDING_SECRET: 'reversal-binding-secret-unique-0123456789-abcdefgh',
  ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET: 'reversal-binding-endpoint-secret-0123456789-abcdef',
  ARC_STRIPE_REVERSAL_RECHECK_SECRET: 'reversal-recheck-secret-unique-0123456789-abcdefgh',
  ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET: 'reversal-recheck-endpoint-secret-0123456789-abcdef',
  NETLIFY_TEAM_ACCOUNT_ID: 'arc-team-account',
};

const artifactBytes = [
  { path: '_headers', bytes: Buffer.from(ARC2_PRODUCTION_HEADERS_FILE) },
  { path: 'about/index.html', bytes: Buffer.from('<!doctype html><main>About</main>\n') },
  { path: 'contact/index.html', bytes: Buffer.from('<!doctype html><main>Contact</main>\n') },
  { path: 'process/index.html', bytes: Buffer.from('<!doctype html><main>Process</main>\n') },
  { path: 'services/index.html', bytes: Buffer.from('<!doctype html><main>Services</main>\n') },
  { path: 'index.html', bytes: Buffer.from('<!doctype html><main>Home</main>\n') },
];
const artifactManifest = artifactBytes.map(({ path, bytes }) => ({
  path,
  sha256: hash(bytes),
  size: bytes.length,
}));
const framedDigest = entries => {
  const digest = createHash('sha256');
  for (const entry of entries) digest.update(entry.path).update('\0').update(entry.bytes).update('\0');
  return digest.digest('hex');
};
const reviewArtifactManifestSha256 = hash(canonicalJson(artifactManifest));
const reviewProductionContentSha256 = framedDigest(artifactBytes.slice(1));
const reviewBundleFingerprint = framedDigest(artifactBytes);

const pageBindings = [
  'about/index.html',
  'contact/index.html',
  'index.html',
  'process/index.html',
  'services/index.html',
].map(path => ({ path, sha256: hash(`page:${path}`) }));

function signedApprovedReview(overrides = {}) {
  const actionPayloadSha256 = hash(canonicalJson({ action: 'APPROVE_AND_PAY', revision_notes_sha256: null }));
  const decisionBase = {
    schema: 'arc-preview-review-decision-v1',
    action: 'APPROVE_AND_PAY',
    action_payload_sha256: actionPayloadSha256,
    idempotency_hmac_sha256: hash('review-decision-idempotency'),
    decided_at: '2026-08-27T11:58:00.316Z',
    revision_notes: null,
    revision_notes_sha256: null,
    approval_receipt_sha256: null,
    approval_receipt_hmac_sha256: null,
    checkout_idempotency_key_sha256: hash(hmac(env.ARC_REVIEW_DECISION_HMAC_SECRET,
      `arc-preview-checkout-idempotency-v1\n${inviteHmac}`)),
  };
  const base = {
    schema: 'arc-preview-review-invite-v1',
    version: 1,
    record_revision: 4,
    state: 'APPROVED',
    invite_hmac_sha256: inviteHmac,
    created_at: '2026-08-27T11:30:00.000Z',
    expires_at: '2026-08-28T12:00:00.000Z',
    recipient_email_sha256: hash(rawEmail),
    email_delivery_receipt_sha256: hash('authoritative-email-delivery'),
    email_delivery_binding_mode: 'signed-outbox',
    email_delivery_outbox_hmac_sha256: hash('authoritative-email-outbox'),
    email_suppression_receipt_sha256: null,
    email_suppression_outbox_hmac_sha256: null,
    email_suppression_source_outbox_hmac_sha256: null,
    email_suppression_status: null,
    email_suppressed_at: null,
    preview_url: 'https://previews.arcweb.onl/private-preview/',
    preview_source_repository: 'arcwebhq-cpu/arc-previews',
    preview_source_commit_sha: 'a'.repeat(40),
    preview_manifest_sha256: reviewArtifactManifestSha256,
    preview_content_sha256: reviewProductionContentSha256,
    brief_sha256: hash('customer-brief'),
    scope_version: 'arc-fixed-five-page-offer-v1',
    page_bindings: pageBindings,
    revision_round: 0,
    prior_invite_hmac_sha256: null,
    prior_preview_manifest_sha256: null,
    session_nonce_hmac_sha256: hash('review-session-nonce'),
    exchanged_at: '2026-08-27T11:45:00.000Z',
    decision: decisionBase,
    successor_invite_hmac_sha256: null,
  };
  Object.assign(base, overrides);
  const approvalReceipt = {
    schema: 'arc-preview-customer-approval-v1',
    invite_hmac_sha256: base.invite_hmac_sha256,
    recipient_email_sha256: base.recipient_email_sha256,
    email_delivery_receipt_sha256: base.email_delivery_receipt_sha256,
    email_delivery_binding_mode: base.email_delivery_binding_mode,
    email_delivery_outbox_hmac_sha256: base.email_delivery_outbox_hmac_sha256,
    preview_url: base.preview_url,
    preview_source_repository: base.preview_source_repository,
    preview_source_commit_sha: base.preview_source_commit_sha,
    preview_manifest_sha256: base.preview_manifest_sha256,
    preview_content_sha256: base.preview_content_sha256,
    brief_sha256: base.brief_sha256,
    scope_version: base.scope_version,
    page_bindings: base.page_bindings,
    revision_round: base.revision_round,
    session_nonce_hmac_sha256: base.session_nonce_hmac_sha256,
    action_payload_sha256: actionPayloadSha256,
    decided_at: decisionBase.decided_at,
  };
  const canonicalApproval = canonicalJson(approvalReceipt);
  base.decision.approval_receipt_sha256 = hash(canonicalApproval);
  base.decision.approval_receipt_hmac_sha256 = hmac(env.ARC_REVIEW_DECISION_HMAC_SECRET,
    `arc-preview-customer-approval-signature-v1\n${canonicalApproval}`);
  const unsigned = { ...base };
  unsigned.record_hmac_sha256 = hmac(env.ARC_REVIEW_RECORD_HMAC_SECRET,
    `arc-preview-review-record-signature-v1\n${canonicalJson(unsigned)}`);
  return unsigned;
}

const reviewRecord = signedApprovedReview();
const reviewArtifactObject = {
  version: 'arc2-handoff-artifact-evidence-v4',
  scope: 'netlify-claimable-deploy-artifacts',
  approval_content_sha256: hash('review-approved-content'),
  artifact_manifest_sha256: reviewRecord.preview_manifest_sha256,
  artifacts: artifactManifest,
  asset_publication_receipt_sha256: hash('review-asset-publication'),
  bundle_fingerprint: reviewBundleFingerprint,
  checkout_binding_key_id: '01',
  checkout_config_snapshot_sha256: hash('review-checkout-configuration'),
  checkout_reference_sha256: hash(reviewRecord.decision.approval_receipt_sha256),
  issued_at: '2026-08-27T11:57:00.000Z',
  lead_route_form_name: '',
  lead_route_mode: 'not_required',
  lead_route_recipient_hmac_sha256: '',
  preview_folder: 'private-preview-a1b2c3d4',
  preview_source_commit_sha: reviewRecord.preview_source_commit_sha,
  preview_source_repository: reviewRecord.preview_source_repository,
  preview_source_tag_sha256: hash('review-preview-source-tag'),
  production_content_sha256: reviewRecord.preview_content_sha256,
};
const reviewArtifactEvidence = canonicalJson(reviewArtifactObject);
const reviewDeployArtifacts = canonicalJson(artifactBytes.map(({ path, bytes }) => ({
  path,
  content_base64: bytes.toString('base64'),
})));
const metadata = {
  approval_receipt_hmac_sha256: reviewRecord.decision.approval_receipt_hmac_sha256,
  approval_receipt_sha256: reviewRecord.decision.approval_receipt_sha256,
  invite_hmac_sha256: inviteHmac,
  offer_contract_id: 'arc-fixed-five-page-offer-v1',
  preview_manifest_sha256: reviewRecord.preview_manifest_sha256,
  recipient_email_sha256: reviewRecord.recipient_email_sha256,
  schema: 'arc-review-checkout-session-v1',
  scope_version: 'arc-fixed-five-page-offer-v1',
  terms_version: '2026-08-25',
};

const identityHmac = (kind, value) => hmac(env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
  `stripe-checkout-${kind}-v1\n${value}`);
const sessionHmac = identityHmac('session-id', rawSessionId);
const paymentIntentHmac = identityHmac('payment-intent-id', rawPaymentIntentId);
const stateEventIdHmac = identityHmac('event-id', 'evt_arcPaidAuthorityEvent');
const stateEventSha256 = hash('signed-paid-webhook-bytes');

function providerAuthority(overrides = {}) {
  const paymentIntent = {
    object: 'payment_intent',
    id: rawPaymentIntentId,
    status: 'succeeded',
    livemode: false,
    currency: 'usd',
    amount: 545_000,
    amount_received: 545_000,
    metadata: { ...metadata },
  };
  const session = {
    object: 'checkout.session',
    id: rawSessionId,
    mode: 'payment',
    ui_mode: 'hosted_page',
    integration_identifier: env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER,
    status: 'complete',
    payment_status: 'paid',
    livemode: false,
    payment_link: null,
    created: Math.floor(Date.parse('2026-08-27T11:59:00.000Z') / 1000),
    currency: 'usd',
    client_reference_id: reviewRecord.decision.approval_receipt_sha256,
    automatic_tax: { enabled: true, status: 'complete' },
    consent: { terms_of_service: 'accepted' },
    custom_fields: [{ key: 'adultpurchaserack', type: 'dropdown', dropdown: { value: 'accepted' } }],
    metadata: { ...metadata },
    payment_intent: paymentIntent,
    amount_subtotal: 500_000,
    amount_total: 545_000,
    total_details: { amount_discount: 0, amount_shipping: 0, amount_tax: 45_000 },
    customer_details: { email: rawPayerEmail, address: { country: 'US', state: 'WA' } },
  };
  return { account: { object: 'account', id: rawAccountId }, session: { ...session, ...overrides } };
}

function ledgerSummary(overrides = {}) {
  return {
    schema: 'arc-stripe-checkout-session-state-v1',
    checkout_session_id_hmac_sha256: sessionHmac,
    payment_intent_id_hmac_sha256: paymentIntentHmac,
    payment_link_id_hmac_sha256: null,
    client_reference_id_sha256: hash(reviewRecord.decision.approval_receipt_sha256),
    payer_email_sha256: hash(rawPayerEmail),
    customer_address_country: 'US',
    customer_address_state: 'WA',
    stripe_account_id_sha256: accountSha256,
    livemode: false,
    currency: 'usd',
    subtotal_amount_minor_units: 500_000,
    tax_amount_minor_units: 45_000,
    amount_total_minor_units: 545_000,
    automatic_tax_enabled: true,
    automatic_tax_status: 'complete',
    terms_of_service_consent: true,
    adult_purchaser_acknowledgement: true,
    review_checkout_binding: { ...metadata },
    state: 'PAID',
    fulfillment_allowed: true,
    manual_review_required: false,
    first_event_created_at: '2026-08-27T11:59:00.000Z',
    latest_event_created_at: '2026-08-27T11:59:00.000Z',
    latest_event_type: 'checkout.session.completed',
    latest_event_id_hmac_sha256: stateEventIdHmac,
    latest_event_sha256: stateEventSha256,
    state_event_id_hmac_sha256: stateEventIdHmac,
    state_event_sha256: stateEventSha256,
    processed_event_hmacs_sha256: [stateEventIdHmac],
    event_count: 1,
    ...overrides,
  };
}

const ledgerReceipt = (overrides = {}) => ({
  schema: 'arc-stripe-checkout-processing-receipt-v1',
  event_id_hmac_sha256: stateEventIdHmac,
  event_sha256: stateEventSha256,
  checkout_session_id_hmac_sha256: sessionHmac,
  stripe_account_id_sha256: accountSha256,
  accepted: true,
  resulting_state: 'PAID',
  review_alert_required: false,
  ...overrides,
});

async function seededStores() {
  const review = new FakeStore();
  const ledger = new FakeStore();
  const bridge = new FakeStore();
  await review.setJSON(`review-invites/${inviteHmac}`, reviewRecord, { onlyIfNew: true });
  await ensureReviewEmailRecipientControl(review, reviewRecord.recipient_email_sha256, env, now);
  await reserveReviewCheckoutBinding(review, {
    approval_receipt_hmac_sha256: reviewRecord.decision.approval_receipt_hmac_sha256,
    approval_receipt_sha256: reviewRecord.decision.approval_receipt_sha256,
    checkout_expires_at: Math.floor(now.getTime() / 1000) + 23 * 60 * 60,
    invite_hmac_sha256: reviewRecord.invite_hmac_sha256,
    preview_manifest_sha256: reviewRecord.preview_manifest_sha256,
    recipient_email_sha256: reviewRecord.recipient_email_sha256,
    scope_version: reviewRecord.scope_version,
  }, env, now);
  await bindReviewCheckoutSession(review, reviewRecord.decision.approval_receipt_sha256, {
    id: rawSessionId,
    integration_identifier: env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER,
    livemode: false,
    url: `https://checkout.stripe.com/c/pay/${rawSessionId}`,
  }, env, now);
  await ledger.setJSON(stripeCheckoutKeys.sessionStateKey(rawSessionId, env), ledgerSummary(), { onlyIfNew: true });
  await ledger.setJSON(`stripe-checkout-receipt/${stateEventIdHmac}`, ledgerReceipt(), { onlyIfNew: true });
  bridge.writeKeys.length = 0;
  return { review, ledger, bridge };
}

const clock = (date = now) => ({ clock: () => new Date(date) });
const input = { invite_hmac_sha256: inviteHmac, checkout_session_id: rawSessionId };
const claimOne = 'claim_token_worker_one_0123456789_abcdefgh';
const claimTwo = 'claim_token_worker_two_0123456789_abcdefgh';

assert.equal(paymentArc2BridgeConfiguration(env).enabled, true);
const untouched = await seededStores();
const callsBeforeDisabled = untouched.bridge.calls;
await assert.rejects(createPaymentArc2StartOutbox(untouched, input, {
  ...env, ARC_PAYMENT_ARC2_BRIDGE_ENABLED: 'false',
}, { ...clock(), retrieveCheckoutSessionAuthority: async () => providerAuthority() }), /BRIDGE_DISABLED/);
assert.equal(untouched.bridge.calls, callsBeforeDisabled, 'Default-off must not touch bridge state.');

const stores = await seededStores();
let providerReads = 0;
const adapters = {
  ...clock(),
  retrieveCheckoutSessionAuthority: async (id, options) => {
    providerReads += 1;
    assert.equal(id, rawSessionId);
    assert.deepEqual(options, { expand: ['payment_intent'] });
    return providerAuthority();
  },
};
const created = await createPaymentArc2StartOutbox(stores, input, env, adapters);
assert.equal(created.state, 'PENDING');
assert.equal(created.review_session_binding_created, true);
assert.equal(providerReads, 1);
assert.match(stores.bridge.writeKeys[0], /^payment-review-session-binding\/[a-f0-9]{64}$/,
  'The durable review→Session binding must be committed before the ARC2 outbox.');
assert.match(stores.bridge.writeKeys[1], /^payment-arc2-start-outbox\/[a-f0-9]{64}$/);
assert.match(stores.bridge.writeKeys[2], /^payment-arc2-pending\/[a-f0-9]{64}$/);
assert.equal(stores.bridge.values.get(created.outbox_key).data.schema, PAYMENT_ARC2_OUTBOX_SCHEMA);
assert.equal([...stores.bridge.values.values()].some(entry => entry.data.schema === PAYMENT_ARC2_REVIEW_SESSION_BINDING_SCHEMA), true);
assert.doesNotMatch(stores.bridge.writeKeys.join('\n'), /cs_test_|private\.owner|@/);
assert.doesNotMatch(JSON.stringify([...stores.bridge.values.values()]), /cs_test_|private\.owner@example|billing\.agent@example/,
  'Bridge records contain authenticated hashes, never raw provider ids or customer email.');

const replay = await createPaymentArc2StartOutbox(stores, input, env, adapters);
assert.equal(replay.outbox_key, created.outbox_key);
assert.equal(replay.idempotent_replay, true);
assert.equal(replay.review_session_binding_created, false);
assert.equal(stores.bridge.values.size, 3);

await assert.rejects(createPaymentArc2StartOutbox(stores, {
  ...input, ledger_summary: ledgerSummary(),
}, env, adapters), /fields/i, 'Caller-supplied ledger state is never accepted.');
await assert.rejects(createPaymentArc2StartOutbox(await seededStores(), input, env, clock()),
  /PROVIDER_AUTHORITY_REQUIRED/);

const forgedReviewStores = await seededStores();
const forgedReviewEntry = forgedReviewStores.review.values.get(`review-invites/${inviteHmac}`);
forgedReviewEntry.data.preview_manifest_sha256 = hash('forged-preview');
await assert.rejects(createPaymentArc2StartOutbox(forgedReviewStores, input, env, adapters),
  /SIGNATURE_INVALID/, 'Unsigned caller/store mutations cannot authorize paid work.');
assert.equal(forgedReviewStores.bridge.values.size, 0);

const legacyEmailStores = await seededStores();
await legacyEmailStores.review.overwrite(`review-invites/${inviteHmac}`, signedApprovedReview({
  email_delivery_binding_mode: 'legacy-prebound',
  email_delivery_outbox_hmac_sha256: null,
}));
await assert.rejects(createPaymentArc2StartOutbox(legacyEmailStores, input, {
  ...env,
  ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
}, adapters), /EMAIL_DELIVERY_REQUIRED/,
'An enabled signed email outbox must not accept a legacy-prebound delivery receipt.');
assert.equal(legacyEmailStores.bridge.values.size, 0);

const badProviderStores = await seededStores();
await assert.rejects(createPaymentArc2StartOutbox(badProviderStores, input, env, {
  ...clock(), retrieveCheckoutSessionAuthority: async () => providerAuthority({
    metadata: { ...metadata, preview_manifest_sha256: hash('wrong-provider-preview') },
  }),
}), /PROVIDER_METADATA_MISMATCH/);
assert.equal(badProviderStores.bridge.values.size, 0);

for (const invalidProvenance of [
  { ui_mode: 'embedded' },
  { integration_identifier: 'arc_review_checkout_zxcvbnmq' },
]) {
  const provenanceStores = await seededStores();
  await assert.rejects(createPaymentArc2StartOutbox(provenanceStores, input, env, {
    ...clock(),
    retrieveCheckoutSessionAuthority: async () => providerAuthority(invalidProvenance),
  }), /PROVIDER_SESSION_MISMATCH/);
  assert.equal(provenanceStores.bridge.values.size, 0,
    'Paid provider authority must preserve hosted Checkout producer provenance.');
}

const badReceiptStores = await seededStores();
await badReceiptStores.ledger.overwrite(`stripe-checkout-receipt/${stateEventIdHmac}`,
  ledgerReceipt({ event_sha256: hash('wrong-receipt-event') }));
await assert.rejects(createPaymentArc2StartOutbox(badReceiptStores, input, env, adapters),
  /LEDGER_BINDING_MISMATCH/);
assert.equal(badReceiptStores.bridge.values.size, 0);

const reviewRequiredStores = await seededStores();
await reviewRequiredStores.ledger.overwrite(stripeCheckoutKeys.sessionStateKey(rawSessionId, env), ledgerSummary({
  state: 'REVIEW_REQUIRED', fulfillment_allowed: false, manual_review_required: true,
}));
await assert.rejects(createPaymentArc2StartOutbox(reviewRequiredStores, input, env, adapters), /REVIEW_REQUIRED/);
assert.equal(reviewRequiredStores.bridge.values.size, 0);

const revocationRaceStores = await seededStores();
const revocationRaceOutbox = await createPaymentArc2StartOutbox(
  revocationRaceStores, input, env, adapters,
);
const revocationBinding = [...revocationRaceStores.review.values.values()]
  .map(entry => entry.data)
  .find(value => value?.schema === 'arc-review-checkout-revocable-binding-v1');
await requestReviewCheckoutRevocation(revocationRaceStores.review,
  revocationBinding.binding_hmac_sha256, {
    recipient_email_sha256: reviewRecord.recipient_email_sha256,
    source_invite_hmac_sha256: reviewRecord.invite_hmac_sha256,
    source_outbox_hmac_sha256: reviewRecord.email_delivery_outbox_hmac_sha256,
    suppressed_at: now.toISOString(),
    suppression_receipt_sha256: hash('durable-recipient-complaint'),
    suppression_status: 'complained',
  }, env, now);
await assert.rejects(claimPaymentArc2StartOutbox(
  revocationRaceStores, revocationRaceOutbox.outbox_key, claimOne, env, clock(),
), /REVIEW_REQUIRED/,
'A durable recipient revocation racing after PAID outbox creation must halt claim/resume.');

const claimReadsBefore = providerReads;
const ledgerKey = stripeCheckoutKeys.sessionStateKey(rawSessionId, env);
await stores.ledger.overwrite(ledgerKey, ledgerSummary({
  state: 'REVIEW_REQUIRED', fulfillment_allowed: false, manual_review_required: true,
}));
await assert.rejects(claimPaymentArc2StartOutbox(stores, created.outbox_key, claimOne, env, clock()),
  /REVIEW_REQUIRED/, 'Claim must re-read authoritative paid state, not trust a stale outbox snapshot.');
await stores.ledger.overwrite(ledgerKey, ledgerSummary());
const claimed = await claimPaymentArc2StartOutbox(stores, created.outbox_key, claimOne, env, clock());
assert.equal(claimed.state, 'CLAIMED');
assert.equal(claimed.claim_attempt_count, 1);
assert.equal(claimed.lease_expires_at, new Date(now.getTime() + PAYMENT_ARC2_LEASE_SECONDS * 1000).toISOString());
assert.equal(providerReads, claimReadsBefore, 'Paid resumability uses durable signed review+ledger authorities without a provider mutation/read.');
assert.equal((await claimPaymentArc2StartOutbox(stores, created.outbox_key, claimOne, env, clock())).idempotent_replay, true);
await assert.rejects(claimPaymentArc2StartOutbox(stores, created.outbox_key, claimTwo, env, clock()), /OUTBOX_LEASED/);

// A response-marker crash after claim-next must converge the same worker onto
// its still-live first lease. It must not advance to another pending subject.
const firstPendingKey = `payment-arc2-pending/${created.outbox_key.slice('payment-arc2-start-outbox/'.length)}`;
const secondPendingSuffix = 'f'.repeat(64);
assert.notEqual(firstPendingKey, `payment-arc2-pending/${secondPendingSuffix}`);
const secondOutboxKey = `payment-arc2-start-outbox/${secondPendingSuffix}`;
const secondPendingKey = `payment-arc2-pending/${secondPendingSuffix}`;
await stores.bridge.setJSON(secondPendingKey, {
  schema: PAYMENT_ARC2_PENDING_INDEX_SCHEMA,
  outbox_key: secondOutboxKey,
  immutable_binding_sha256: hash('second-pending-immutable'),
  created_at: now.toISOString(),
}, { onlyIfNew: true });
const claimNextReplay = await claimNextPaymentArc2StartOutbox(
  stores, claimOne, env, clock(),
);
assert.equal(claimNextReplay.outbox_key, created.outbox_key);
assert.equal(claimNextReplay.idempotent_replay, true);
assert.equal(stores.bridge.values.has(secondPendingKey), true,
  'Same-worker claim-next replay must not inspect or claim the next pending subject.');

const artifactBinding = {
  artifact_evidence_sha256: hash(reviewArtifactEvidence),
  artifact_manifest_sha256: reviewRecord.preview_manifest_sha256,
  bundle_fingerprint: reviewBundleFingerprint,
  checkout_reference_sha256: hash(reviewRecord.decision.approval_receipt_sha256),
  preview_folder: reviewArtifactObject.preview_folder,
  preview_source_commit_sha: reviewRecord.preview_source_commit_sha,
  preview_source_repository: reviewRecord.preview_source_repository,
  production_content_sha256: reviewRecord.preview_content_sha256,
};
const reviewEvidence = await createPaymentArc2ReviewEvidence(stores, {
  artifact_binding: artifactBinding,
  checkout_session_id: rawSessionId,
  claim_token: claimOne,
  outbox_key: created.outbox_key,
}, env, adapters);
assert.equal(reviewEvidence.value.payment_link_id, null);
assert.equal(reviewEvidence.value.claim_recipient_email_sha256, reviewRecord.recipient_email_sha256);
assert.equal(reviewEvidence.value.payer_email_sha256, hash(rawPayerEmail));
assert.notEqual(reviewEvidence.value.payer_email_sha256, reviewEvidence.value.claim_recipient_email_sha256,
  'Billing payer identity is audit-only; signed review recipient remains fulfillment authority.');
assert.equal(reviewEvidence.value.handoff_artifact_evidence_sha256, artifactBinding.artifact_evidence_sha256);
assert.match(reviewEvidence.signature, /^[a-f0-9]{64}$/);
await assert.rejects(createPaymentArc2ReviewEvidence(stores, {
  artifact_binding: { ...artifactBinding, production_content_sha256: hash('wrong-content') },
  checkout_session_id: rawSessionId,
  claim_token: claimOne,
  outbox_key: created.outbox_key,
}, env, adapters), /ARTIFACT_BINDING_MISMATCH/,
'A claimed paid outbox must not authorize artifacts outside the exact signed review.');

const reviewStartInput = {
  artifact_evidence: reviewArtifactEvidence,
  artifact_evidence_hmac_sha256: hmacHex(env.ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET,
    `${ARTIFACT_SIGNATURE_PREFIX}${reviewArtifactEvidence}`),
  deploy_artifacts: reviewDeployArtifacts,
  lead_notification_email: '',
  lead_route_recipient_hmac_sha256: '',
  payment_evidence: reviewEvidence.canonical,
  payment_evidence_hmac_sha256: reviewEvidence.signature,
};
const originalReviewPaymentEvidence = reviewStartInput.payment_evidence;
let mutatedReviewInputDuringAwait = false;
const reviewStart = await startReviewHandoff(reviewStartInput, env, {
  store: stores.ledger,
  reviewStore: stores.review,
  clock: () => new Date(now),
  uuid: () => '22222222-2222-4222-8222-222222222222',
  fetch: async () => { throw new Error('Reversal gating must precede Netlify mutation.'); },
  stripeAccountFetch: async () => {
    if (!mutatedReviewInputDuringAwait) {
      mutatedReviewInputDuringAwait = true;
      reviewStartInput.payment_evidence = canonicalJson({
        ...reviewEvidence.value,
        payer_email_sha256: '0'.repeat(64),
      });
    }
    return new Response(JSON.stringify({ id: rawAccountId, object: 'account' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  },
});
reviewStartInput.payment_evidence = originalReviewPaymentEvidence;
assert.equal(reviewStart.record.state, 'PAYMENT_VERIFIED');
assert.equal(reviewStart.reversalControlReady, false);
assert.equal(reviewStart.record.customer_email_sha256, reviewRecord.recipient_email_sha256);
assert.notEqual(reviewStart.record.customer_email_sha256, hash(rawPayerEmail));
assert.equal(reviewStart.startReceipt.value.payer_email_sha256, hash(rawPayerEmail));
assert.equal(mutatedReviewInputDuringAwait, true);
assert.match(reviewStart.startReceipt.signature, /^[a-f0-9]{64}$/);
assert.doesNotMatch(JSON.stringify([...stores.ledger.values.values()]), /private\.owner@example|billing\.agent@example/,
  'The durable review handoff stores fulfillment and payer digests without PII.');
await assert.rejects(startHandoff(reviewStartInput, env, {
  store: stores.ledger,
  clock: () => new Date(now),
}), /fields|Payment evidence|Checkout reference/i,
'The legacy v4 Payment Link entrypoint must not reinterpret review-session evidence.');
const forgedLinkEvidence = canonicalJson({ ...reviewEvidence.value, payment_link_id: 'plink_forbiddenReviewPath' });
await assert.rejects(startReviewHandoff({
  ...reviewStartInput,
  payment_evidence: forgedLinkEvidence,
  payment_evidence_hmac_sha256: hmac(env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET,
    `arc2-review-session-payment-evidence-signature-v1\ntest\n${forgedLinkEvidence}`),
}, env, {
  store: stores.ledger,
  reviewStore: stores.review,
  clock: () => new Date(now),
}), /provider semantics|payment/i,
'Only the explicit review-session schema may carry a null Payment Link; it cannot be shape-overloaded.');

const completion = {
  schema: PAYMENT_ARC2_COMPLETION_SCHEMA,
  accepted: true,
  immutable_binding_sha256: created.immutable_binding_sha256,
  arc2_start_receipt: reviewStart.startReceipt.canonical,
  arc2_start_receipt_hmac_sha256: reviewStart.startReceipt.signature,
};
await assert.rejects(completePaymentArc2StartOutbox(stores, created.outbox_key, claimTwo, completion, env, clock()),
  /CLAIM_MISMATCH/);
await assert.rejects(completePaymentArc2StartOutbox(stores, created.outbox_key, claimOne, {
  ...completion,
  arc2_start_receipt_hmac_sha256: '0'.repeat(64),
}, env, clock()), /START_RECEIPT_INVALID/,
'A worker bearer cannot complete paid work with an arbitrary digest or forged start receipt.');
await assert.rejects(completePaymentArc2StartOutbox(
  stores, created.outbox_key, claimOne, completion, env, clock(),
), /START_RECEIPT_INVALID/,
'A PAYMENT_VERIFIED receipt cannot remove paid work before reversal-ready continuation ownership exists.');
const released = await releasePaymentArc2StartOutbox(
  stores, created.outbox_key, claimOne, env, clock(),
);
assert.equal(released.state, 'PENDING');
assert.equal(released.claim_attempt_count, 1);
assert.equal([...stores.bridge.values.keys()].some(key => key.startsWith('payment-arc2-pending/')), true,
  'A nonterminal ARC2 phase remains durably discoverable for the next worker run.');

await suppressReviewEmailRecipientControl(stores.review, {
  recipient_email_sha256: reviewRecord.recipient_email_sha256,
  suppression_receipt_sha256: hash('late-handoff-complaint'),
  suppression_status: 'complained',
  suppressed_at: now.toISOString(),
  source_invite_hmac_sha256: reviewRecord.invite_hmac_sha256,
  source_outbox_hmac_sha256: reviewRecord.email_delivery_outbox_hmac_sha256,
}, env, now);
await assert.rejects(startReviewHandoff(reviewStartInput, env, {
  store: stores.ledger,
  reviewStore: stores.review,
  clock: () => new Date(now),
  fetch: async () => { throw new Error('Late suppression must halt before Netlify mutation.'); },
  stripeAccountFetch: async () => new Response(JSON.stringify({ id: rawAccountId, object: 'account' }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  }),
}), /REVIEW_REQUIRED/,
'A complaint after handoff creation must halt the next ARC2 continuation phase.');

const delayedSettlementTime = new Date('2026-08-30T12:00:00.000Z');
const delayedSettlementStores = await seededStores();
assert.equal((await createPaymentArc2StartOutbox(delayedSettlementStores, input, env, {
  ...clock(delayedSettlementTime),
  retrieveCheckoutSessionAuthority: async () => providerAuthority(),
})).state, 'PENDING',
'A Session created inside the approved window may settle through an authenticated asynchronous payment after expiry.');

assert.equal((await createPaymentArc2StartOutbox(await seededStores(), input, env, {
  ...clock(),
  retrieveCheckoutSessionAuthority: async () => providerAuthority({
    created: Math.floor(Date.parse('2026-08-27T11:58:00.000Z') / 1000),
  }),
})).state, 'PENDING',
'Second-precision Session.created may share the approval second when decided_at has milliseconds.');

await assert.rejects(createPaymentArc2StartOutbox(await seededStores(), input, env, {
  ...clock(),
  retrieveCheckoutSessionAuthority: async () => providerAuthority({
    created: Math.floor(Date.parse('2026-08-27T11:57:00.000Z') / 1000),
  }),
}), /AUTHORIZATION_WINDOW_INVALID/,
'A provider Session created before the approval decision cannot consume that approval.');
await assert.rejects(createPaymentArc2StartOutbox(await seededStores(), input, env, {
  ...clock(new Date('2026-08-29T12:00:00.000Z')),
  retrieveCheckoutSessionAuthority: async () => providerAuthority({
    created: Math.floor(Date.parse('2026-08-28T12:01:00.000Z') / 1000),
  }),
}), /AUTHORIZATION_WINDOW_INVALID/,
'A provider Session created after authorization expiry cannot consume that approval.');

const longAfterAuthorization = new Date('2026-10-10T12:00:00.000Z');
await assert.rejects(createPaymentArc2StartOutbox(await seededStores(), input, env, {
  ...clock(longAfterAuthorization),
  retrieveCheckoutSessionAuthority: async () => providerAuthority(),
}), /SETTLEMENT_STALE/,
'A Session created in-window cannot authorize an unbounded late settlement.');

const lateResumeStores = await seededStores();
const lateResumeOutbox = await createPaymentArc2StartOutbox(lateResumeStores, input, env, {
  ...clock(), retrieveCheckoutSessionAuthority: async () => providerAuthority(),
});
const lateClaim = await claimPaymentArc2StartOutbox(
  lateResumeStores, lateResumeOutbox.outbox_key, claimOne, env, clock(longAfterAuthorization),
);
assert.equal(lateClaim.state, 'CLAIMED',
  'A verified PAID outbox must remain claimable after the original authorization expires.');
const lateEvidence = await createPaymentArc2ReviewEvidence(lateResumeStores, {
  artifact_binding: artifactBinding,
  checkout_session_id: rawSessionId,
  claim_token: claimOne,
  outbox_key: lateResumeOutbox.outbox_key,
}, env, {
  ...clock(longAfterAuthorization),
  retrieveCheckoutSessionAuthority: async () => providerAuthority(),
});
const lateStart = await startReviewHandoff({
  ...reviewStartInput,
  payment_evidence: lateEvidence.canonical,
  payment_evidence_hmac_sha256: lateEvidence.signature,
}, env, {
  store: lateResumeStores.ledger,
  reviewStore: lateResumeStores.review,
  clock: () => new Date(longAfterAuthorization),
  uuid: () => '33333333-3333-4333-8333-333333333333',
  fetch: async () => { throw new Error('Reversal gating must precede Netlify mutation.'); },
  stripeAccountFetch: async () => new Response(JSON.stringify({ id: rawAccountId, object: 'account' }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  }),
});
const lateCompletion = {
  schema: PAYMENT_ARC2_COMPLETION_SCHEMA,
  accepted: true,
  immutable_binding_sha256: lateResumeOutbox.immutable_binding_sha256,
  arc2_start_receipt: lateStart.startReceipt.canonical,
  arc2_start_receipt_hmac_sha256: lateStart.startReceipt.signature,
};
await assert.rejects(completePaymentArc2StartOutbox(
  lateResumeStores,
  lateResumeOutbox.outbox_key,
  claimOne,
  lateCompletion,
  env,
  clock(new Date(longAfterAuthorization.getTime() + 60_000)),
), /START_RECEIPT_INVALID/,
  'Expired approval time cannot make a nonterminal start receipt completion-authoritative.');
assert.equal((await releasePaymentArc2StartOutbox(
  lateResumeStores,
  lateResumeOutbox.outbox_key,
  claimOne,
  env,
  clock(new Date(longAfterAuthorization.getTime() + 60_000)),
)).state, 'PENDING',
  'A verified PAID claim remains resumable after the original authorization expires.');

const crashStores = await seededStores();
crashStores.bridge.failAfterCommitPrefixOnce = 'payment-review-session-binding/';
const crashCreated = await createPaymentArc2StartOutbox(crashStores, input, env, adapters);
assert.equal(crashCreated.state, 'PENDING');
assert.equal(crashCreated.review_session_binding_created, false,
  'A post-commit binding crash must converge before creating one outbox.');
assert.equal(crashStores.bridge.values.size, 3);

const contentionStores = await seededStores();
const contentionCreated = await createPaymentArc2StartOutbox(contentionStores, input, env, adapters);
contentionStores.bridge.forceContentionOnce = true;
assert.equal((await claimPaymentArc2StartOutbox(
  contentionStores, contentionCreated.outbox_key, claimOne, env, clock(),
)).state, 'CLAIMED');

const tamperStores = await seededStores();
const tamperCreated = await createPaymentArc2StartOutbox(tamperStores, input, env, adapters);
const tamperedOutbox = tamperStores.bridge.values.get(tamperCreated.outbox_key);
tamperedOutbox.data.immutable.preview_manifest_sha256 = hash('tampered-outbox-preview');
await assert.rejects(claimPaymentArc2StartOutbox(
  tamperStores, tamperCreated.outbox_key, claimOne, env, clock(),
), /IMMUTABLE_MISMATCH/);

console.log('payment ARC2 authoritative bridge contract passed');
