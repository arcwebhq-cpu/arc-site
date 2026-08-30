import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import {
  PAYMENT_ARC2_COMPLETION_SCHEMA,
  PAYMENT_ARC2_PENDING_INDEX_SCHEMA,
} from '../netlify/lib/payment-arc2-bridge-core.mjs';
import {
  ACTIVATION_EVIDENCE_BY_STAGE,
  ACTIVATION_MANIFEST_SCHEMA,
  ACTIVATION_MANIFEST_VERSION,
  signActivationManifest,
} from '../netlify/lib/activation-manifest-core.mjs';
import {
  ARC2_PRECLAIM_HEADERS_FILE,
  ARC2_PRODUCTION_HEADERS_FILE,
  ARTIFACT_SIGNATURE_PREFIX,
  expectedNetlifyLiveHtml,
} from '../netlify/lib/arc2-handoff-core.mjs';
import {
  STRIPE_REVERSAL_BINDING_PREFIX,
  STRIPE_REVERSAL_BINDING_SCHEMA,
  STRIPE_REVERSAL_BINDING_SCOPE,
  STRIPE_REVERSAL_RECHECK_PREFIX,
  STRIPE_REVERSAL_RECHECK_SCHEMA,
  STRIPE_REVERSAL_RECHECK_SCOPE,
  STRIPE_PENDING_PAYMENT_SCHEMA,
  registerStripeReversalBinding,
  registerStripeReversalRecheck,
  stripeReversalKeys,
} from '../netlify/lib/stripe-reversal-core.mjs';
import {
  acknowledgeReviewEmailReceipt,
  prepareReviewInviteEmail,
  reserveReviewEmailSend,
  reviewEmailReceiptContract,
} from '../netlify/lib/review-email-outbox-core.mjs';
import { sealPreviewReviewEmailCapsule } from '../netlify/lib/review-email-resend-core.mjs';
import {
  emailRecipientVaultConfiguration,
  openEmailRecipientCapsule,
} from '../netlify/lib/email-recipient-vault-core.mjs';
import { arc2TransactionalEmailConfiguration } from '../netlify/lib/arc2-transactional-email-core.mjs';
import {
  createApprovedCheckout,
  decideReview,
  exchangeReviewInvite,
  readReviewInviteForEmail,
  readReviewStatus,
} from '../netlify/lib/review-flow-core.mjs';
import {
  STRIPE_REVIEW_CHECKOUT_API_VERSION,
  createStripeReviewCheckoutAdapter,
} from '../netlify/lib/stripe-review-checkout-adapter.mjs';
import paymentArc2WorkerHandler, {
  config as paymentArc2WorkerConfig,
  paymentArc2WorkerConfiguration,
} from '../netlify/functions/payment-arc2-worker.mjs';
import stripeWebhookHandler from '../netlify/functions/stripe-reversal-webhook.mjs';
import { claimSandboxBootstrapConfiguration } from '../netlify/lib/claim-sandbox-bootstrap-core.mjs';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const canonicalJson = value => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
};

class FakeStore {
  constructor() {
    this.values = new Map();
    this.sequence = 0;
    this.writeKeys = [];
  }

  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }

  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `integration-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    this.writeKeys.push(key);
    return { modified: true, etag };
  }

  list({ prefix = '', paginate = false } = {}) {
    assert.equal(paginate, true);
    const blobs = [...this.values.keys()].filter(key => key.startsWith(prefix)).sort().map(key => ({ key }));
    return (async function* () { yield { blobs }; }());
  }

  async delete(key) {
    this.values.delete(key);
  }
}

const cloneStore = source => {
  const copy = new FakeStore();
  copy.sequence = source.sequence;
  copy.values = new Map([...source.values].map(([key, entry]) => [key, structuredClone(entry)]));
  copy.writeKeys = [...source.writeKeys];
  return copy;
};

const now = new Date('2026-08-27T20:00:00.000Z');
const sessionCreatedTimestamp = Math.floor((now.getTime() + 3_000) / 1000);
const settlementNow = new Date(now.getTime() + 2 * 86_400_000);
const webhookTimestamp = Math.floor(settlementNow.getTime() / 1000);
const recipientEmail = 'preview.owner@example.test';
const payerEmail = 'billing.agent@example.test';
const accountId = 'acct_ArcPaymentIntegration';
const priceId = 'price_ArcPaymentIntegration';
const productId = 'prod_ArcPaymentIntegration';
const taxCodeId = 'txcd_10000000';
const checkoutSessionId = 'cs_test_ArcPaymentIntegration';
const paymentIntentId = 'pi_ArcPaymentIntegration';
const eventId = 'evt_ArcPaymentIntegration';
const activationSecret = 'payment-integration-activation-secret-0123456789abcdef';
const activationManifest = signActivationManifest({
  schema: ACTIVATION_MANIFEST_SCHEMA,
  version: ACTIVATION_MANIFEST_VERSION,
  stage: 'CLAIM_SANDBOX',
  authority_mode: 'TEST_BOOTSTRAP',
  issued_at: new Date(settlementNow.getTime() - 60_000).toISOString(),
  expires_at: new Date(settlementNow.getTime() + 10 * 60_000).toISOString(),
  deployment_sha: '9'.repeat(40),
  evidence: ACTIVATION_EVIDENCE_BY_STAGE.EMAIL_SANDBOX.map((kind) => ({
    kind,
    receipt_ref: `audit:${sha256(`payment-integration:${kind}`).slice(0, 24)}`,
    sha256: sha256(`payment-integration-evidence:${kind}`),
  })),
}, activationSecret);

const env = {
  ARC_ACTIVATION_MANIFEST: activationManifest,
  ARC_ACTIVATION_MANIFEST_HMAC_SECRET: activationSecret,
  ARC_ALLOW_TEST_MODE_EVENTS: 'true',
  ARC_EXPECTED_PRICE_ID: priceId,
  ARC_EXPECTED_PRODUCT_ID: productId,
  ARC_EXPECTED_PRODUCT_NAME: 'ARC Fixed Five-Page Website',
  ARC_EXPECTED_PRODUCT_TAX_CODE: taxCodeId,
  ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256: sha256(accountId),
  ARC_HANDOFF_ENABLED: 'false',
  ARC_EXPECTED_NETLIFY_SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  ARC_PUBLIC_ORIGIN: 'https://arcweb.onl/',
  ARC_CHECKOUT_BINDING_SECRET: 'checkout-binding-integration-secret-0123456789abcdef',
  ARC_CHECKOUT_BINDING_KEY_ID: '01',
  ARC_RETIRED_CHECKOUT_BINDING_KEYS_JSON: '{}',
  ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET: 'artifact-evidence-integration-secret-0123456789abcdef',
  ARC_HANDOFF_STATE_SECRET: 'handoff-state-integration-secret-0123456789abcdef',
  ARC_CLAIM_TOKEN_SECRET: 'claim-token-integration-secret-0123456789abcdef',
  ARC_EMAIL_CLAIM_BINDING_SECRET: 'email-claim-binding-integration-secret-0123456789abcdef',
  ARC_FINAL_DELIVERY_RECEIPT_SECRET: 'final-delivery-receipt-integration-secret-0123456789abcdef',
  ARC_TRANSACTIONAL_EMAIL_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET: 'payment-email-attempt-integration-secret-0123456789',
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY: Buffer.alloc(32, 47).toString('base64url'),
  ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET: 'payment-email-vault-integration-secret-0123456789ab',
  ARC_REVIEW_EMAIL_RESEND_CAPSULE_ENABLED: 'true',
  ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET: 'payment-resend-binding-integration-secret-0123456789',
  ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED: 'true',
  ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED: 'true',
  ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET: 'payment-negative-email-state-secret-0123456789abcd',
  ARC_PAYMENT_ARC2_BRIDGE_ENABLED: 'true',
  ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET: 'payment-bridge-integration-secret-0123456789abcdef',
  ARC_PAYMENT_ARC2_WORKER_ENABLED: 'true',
  ARC_PAYMENT_ARC2_WORKER_SECRET: 'payment-worker-integration-secret-0123456789abcdef',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'payment-retention-fence-integration-secret-0123456789abcdef',
  ARC_OPERATIONS_AUDIT_ENABLED: 'true',
  ARC_OPERATIONS_AUDIT_SECRET: 'payment-operations-audit-integration-secret-0123456789abcdef',
  ARC_OPERATIONS_ALERT_HMAC_SECRET: 'payment-operations-alert-integration-secret-0123456789abcdef',
  ARC_REVIEW_CHECKOUT_ENABLED: 'true',
  ARC_REVIEW_CHECKOUT_ORIGIN: 'https://checkout.stripe.com',
  ARC_REVIEW_DECISION_HMAC_SECRET: 'review-decision-integration-secret-0123456789abcdef',
  ARC_REVIEW_EMAIL_OUTBOX_ENABLED: 'true',
  ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET: 'review-email-outbox-integration-secret-0123456789abcdef',
  ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET: 'review-email-receipt-integration-secret-0123456789abcdef',
  ARC_REVIEW_INVITE_HMAC_SECRET: 'review-invite-integration-secret-0123456789abcdef',
  ARC_REVIEW_PORTAL_ENABLED: 'true',
  ARC_REVIEW_PREVIEW_ORIGIN: 'https://arcwebhq-cpu.github.io',
  ARC_REVIEW_PUBLIC_ORIGIN: 'https://arcweb.onl',
  ARC_REVIEW_RECORD_HMAC_SECRET: 'review-record-integration-secret-0123456789abcdef',
  ARC_REVIEW_SESSION_HMAC_SECRET: 'review-session-integration-secret-0123456789abcdef',
  ARC_RUNTIME_ENVIRONMENT: 'sandbox',
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: ['rk', 'test', 'arcIntegrationAccountRead0123456789'].join('_'),
  ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER: 'arc_review_checkout_qwertyui',
  ARC_STRIPE_CHECKOUT_LEDGER_ENABLED: 'true',
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'true',
  ARC_STRIPE_CHECKOUT_OFFER_ID: 'arc-fixed-five-page-offer-v1',
  ARC_STRIPE_CHECKOUT_SUCCESS_URL: 'https://arcweb.onl/payment-success/?session_id={CHECKOUT_SESSION_ID}',
  ARC_STRIPE_CHECKOUT_CANCEL_URL: 'https://arcweb.onl/review/?checkout=cancelled',
  ARC_STRIPE_CHECKOUT_TERMS_VERSION: '2026-08-25',
  ARC_STRIPE_LIVE_MODE_ENABLED: 'false',
  ARC_STRIPE_REVIEW_CHECKOUT_ENABLED: 'true',
  ARC_STRIPE_REVIEW_REVOCATION_ENABLED: 'true',
  ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET: 'stripe-review-revocation-integration-secret-0123456789abcdef',
  ARC_STRIPE_REVIEW_SECRET_KEY: ['rk', 'test', 'arcIntegrationCheckout0123456789abcdef'].join('_'),
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'true',
  ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_BINDING_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_RECHECK_ENABLED: 'true',
  ARC_STRIPE_REVERSAL_BINDING_SECRET: 'reversal-binding-integration-secret-0123456789abcdef',
  ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET: 'reversal-binding-endpoint-integration-0123456789abcdef',
  ARC_STRIPE_REVERSAL_RECHECK_SECRET: 'reversal-recheck-integration-secret-0123456789abcdef',
  ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET: 'reversal-recheck-endpoint-integration-0123456789abcdef',
  ARC_STRIPE_REVERSAL_HMAC_SECRET: 'stripe-reversal-integration-secret-0123456789abcdef',
  ARC_STRIPE_WEBHOOK_API_VERSION: STRIPE_REVIEW_CHECKOUT_API_VERSION,
  ARC_STRIPE_WEBHOOK_SIGNING_SECRET: 'whsec_arc_integration_0123456789abcdef',
  NETLIFY_ADMIN_PAT: 'netlify-admin-integration-secret-0123456789abcdef',
  NETLIFY_TEAM_ACCOUNT_ID: 'arc-integration-team',
  NETLIFY_TEAM_SLUG: 'arc-integration-team-slug',
  SITE_ID: '8f9d462c-952f-42fc-a3a0-50a2529e8f5d',
  SITE_NAME: 'arc2-sandbox',
  URL: 'https://arcweb.onl/',
};

const review = new FakeStore();
const ledger = new FakeStore();
const bridge = new FakeStore();
const vault = new FakeStore();
const retentionFence = new FakeStore();
const retentionAlerts = new FakeStore();
let fenceNow = new Date(settlementNow);
const inviteToken = 'I'.repeat(43);
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
  sha256: sha256(bytes),
  size: bytes.length,
}));
const framedDigest = entries => {
  const digest = createHash('sha256');
  for (const entry of entries) digest.update(entry.path).update('\0').update(entry.bytes).update('\0');
  return digest.digest('hex');
};
const previewManifestSha256 = sha256(canonicalJson(artifactManifest));
const previewContentSha256 = framedDigest(artifactBytes.slice(1));
const bundleFingerprint = framedDigest(artifactBytes);
const pageBindings = [
  'about/index.html',
  'contact/index.html',
  'index.html',
  'process/index.html',
  'services/index.html',
].map(path => ({ path, sha256: sha256(`integration:${path}`) }));

const prepared = await prepareReviewInviteEmail(review, {
  brief_sha256: sha256('integration-brief'),
  expires_at: new Date(now.getTime() + 86_400_000).toISOString(),
  invite_token: inviteToken,
  page_bindings: pageBindings,
  preview_content_sha256: previewContentSha256,
  preview_manifest_sha256: previewManifestSha256,
  preview_source_commit_sha: 'a'.repeat(40),
  preview_source_repository: 'arcwebhq-cpu/arc-previews',
  preview_url: 'https://arcwebhq-cpu.github.io/arc-previews/integration-preview/',
  recipient_email_sha256: sha256(recipientEmail),
  scope_version: 'arc-fixed-five-page-offer-v1',
}, env, { clock: () => new Date(now) });
await sealPreviewReviewEmailCapsule(vault, {
  invite_token: inviteToken,
  prepared,
  recipient_email: recipientEmail,
}, env, { clock: () => new Date(now), randomBytes: () => Buffer.alloc(12, 49) });
await reserveReviewEmailSend(review, {
  invite_token: inviteToken,
  recipient_email: recipientEmail,
}, env, { clock: () => new Date(now) });
const delivery = {
  schema: reviewEmailReceiptContract.schema,
  version: reviewEmailReceiptContract.version,
  outbox_hmac_sha256: prepared.outbox.outbox_hmac_sha256,
  invite_hmac_sha256: prepared.invite.invite_hmac_sha256,
  recipient_email_sha256: prepared.invite.recipient_email_sha256,
  preview_manifest_sha256: prepared.invite.preview_manifest_sha256,
  provider: 'provider-integration',
  provider_account_hmac_sha256: sha256('integration-provider-account'),
  provider_event_id: 'integration-email-delivered-event',
  provider_message_id: 'integration-email-delivered-message',
  event_type: 'message.delivered',
  delivery_status: 'delivered',
  event_at: new Date(now.getTime() + 1_000).toISOString(),
  issued_at: new Date(now.getTime() + 2_000).toISOString(),
};
const deliveryEvidence = canonicalJson(delivery);
const deliverySignature = createHmac('sha256', env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET)
  .update(reviewEmailReceiptContract.signaturePrefix + deliveryEvidence).digest('hex');
await acknowledgeReviewEmailReceipt(review, deliveryEvidence, deliverySignature, env, {
  clock: () => new Date(now.getTime() + 2_000),
});
const issued = await readReviewInviteForEmail(review, prepared.invite.invite_hmac_sha256, env);
const exchanged = await exchangeReviewInvite(review, inviteToken, env, {
  clock: () => new Date(now.getTime() + 3_000),
  randomBytes: () => Buffer.alloc(32, 23),
});
const status = await readReviewStatus(review, exchanged.session_token, env, new Date(now.getTime() + 3_000));
await decideReview(review, exchanged.session_token, {
  action: 'APPROVE_AND_PAY',
  expected_revision: status.record_revision,
  idempotency_key: '99999999-9999-4999-8999-999999999999',
}, env, { clock: () => new Date(now.getTime() + 3_000) });

let createdParameters;
const stripeClient = {
  accounts: {
    retrieve: async () => ({ id: accountId, object: 'account' }),
  },
  prices: {
    retrieve: async () => ({
      active: true,
      currency: 'usd',
      id: priceId,
      livemode: false,
      object: 'price',
      product: {
        active: true,
        default_price: priceId,
        id: productId,
        livemode: false,
        name: 'ARC Fixed Five-Page Website',
        object: 'product',
        shippable: false,
        tax_code: taxCodeId,
      },
      recurring: null,
      tax_behavior: 'exclusive',
      type: 'one_time',
      unit_amount: 500_000,
    }),
  },
  checkout: {
    sessions: {
      create: async parameters => {
        createdParameters = structuredClone(parameters);
        return {
          amount_subtotal: 500_000,
          automatic_tax: { enabled: true, status: null },
          client_reference_id: parameters.client_reference_id,
          currency: 'usd',
          expires_at: parameters.expires_at,
          id: checkoutSessionId,
          integration_identifier: parameters.integration_identifier,
          livemode: false,
          metadata: structuredClone(parameters.metadata),
          mode: 'payment',
          object: 'checkout.session',
          payment_link: null,
          payment_status: 'unpaid',
          status: 'open',
          ui_mode: 'hosted_page',
          url: `https://checkout.stripe.com/c/pay/${checkoutSessionId}`,
        };
      },
      retrieve: async (id, options) => {
        assert.equal(id, checkoutSessionId);
        assert.deepEqual(options, { expand: ['payment_intent'] });
        return structuredClone(providerSession);
      },
      expire: async () => {
        throw new Error('Integration fixture must not expire an unsuppressed Session.');
      },
    },
  },
};

const checkoutProducerEnv = {
  ...env,
  ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED: 'false',
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'false',
};
const checkout = await createApprovedCheckout(review, exchanged.session_token, env, {
  clock: () => new Date(now.getTime() + 3_000),
  createCheckout: createStripeReviewCheckoutAdapter(checkoutProducerEnv, {
    store: review,
    clock: () => new Date(now.getTime() + 3_000),
    stripeClient,
  }),
});
assert.equal(checkout.checkout_url, `https://checkout.stripe.com/c/pay/${checkoutSessionId}`);
const approved = (await readReviewInviteForEmail(review, issued.record.invite_hmac_sha256, env)).record;
assert.equal(createdParameters.client_reference_id, approved.decision.approval_receipt_sha256);
assert.equal(createdParameters.expires_at,
  Math.floor(Date.parse(approved.decision.decided_at) / 1000) + 23 * 60 * 60,
  'The private Checkout Session must expire 23 hours after the approval decision.');
assert.equal('billing_address_collection' in createdParameters, false,
  'Checkout must collect only the address fields automatic tax requires.');
assert.equal(createdParameters.metadata.approval_receipt_hmac_sha256,
  approved.decision.approval_receipt_hmac_sha256);
assert.equal(createdParameters.metadata.preview_manifest_sha256, approved.preview_manifest_sha256);
const artifactObject = {
  version: 'arc2-handoff-artifact-evidence-v4',
  scope: 'netlify-claimable-deploy-artifacts',
  approval_content_sha256: sha256('integration-approved-content'),
  artifact_manifest_sha256: previewManifestSha256,
  artifacts: artifactManifest,
  asset_publication_receipt_sha256: sha256('integration-asset-publication'),
  bundle_fingerprint: bundleFingerprint,
  checkout_binding_key_id: '01',
  checkout_config_snapshot_sha256: sha256('integration-review-checkout-config'),
  checkout_reference_sha256: sha256(approved.decision.approval_receipt_sha256),
  issued_at: new Date(now.getTime() + 3_000).toISOString(),
  lead_route_form_name: '',
  lead_route_mode: 'not_required',
  lead_route_recipient_hmac_sha256: '',
  preview_folder: 'integration-preview-a1b2c3d4',
  preview_source_commit_sha: approved.preview_source_commit_sha,
  preview_source_repository: approved.preview_source_repository,
  preview_source_tag_sha256: sha256('integration-review-source-tag'),
  production_content_sha256: previewContentSha256,
};
const artifactEvidence = canonicalJson(artifactObject);
const artifactSignature = createHmac('sha256', env.ARC_HANDOFF_ARTIFACT_EVIDENCE_SECRET)
  .update(`${ARTIFACT_SIGNATURE_PREFIX}${artifactEvidence}`).digest('hex');
const deployArtifacts = canonicalJson(artifactBytes.map(({ path, bytes }) => ({
  path,
  content_base64: bytes.toString('base64'),
})));

const paidSession = {
  amount_subtotal: 500_000,
  amount_total: 545_000,
  automatic_tax: { enabled: true, status: 'complete' },
  client_reference_id: createdParameters.client_reference_id,
  consent: { terms_of_service: 'accepted' },
  created: sessionCreatedTimestamp,
  currency: 'usd',
  custom_fields: [{
    dropdown: { value: 'accepted' },
    key: 'adultpurchaserack',
    type: 'dropdown',
  }],
  customer_details: { email: payerEmail, address: { country: 'US', state: 'WA' } },
  id: checkoutSessionId,
  integration_identifier: createdParameters.integration_identifier,
  livemode: false,
  metadata: structuredClone(createdParameters.metadata),
  mode: 'payment',
  object: 'checkout.session',
  payment_intent: paymentIntentId,
  payment_link: null,
  payment_status: 'paid',
  status: 'complete',
  total_details: { amount_discount: 0, amount_shipping: 0, amount_tax: 45_000 },
  ui_mode: 'hosted_page',
};
const webhookEvent = {
  api_version: STRIPE_REVIEW_CHECKOUT_API_VERSION,
  created: webhookTimestamp,
  data: { object: paidSession },
  id: eventId,
  livemode: false,
  object: 'event',
  type: 'checkout.session.async_payment_succeeded',
};
const rawWebhook = JSON.stringify(webhookEvent);
const stripeSignature = `t=${webhookTimestamp},v1=${createHmac('sha256', env.ARC_STRIPE_WEBHOOK_SIGNING_SECRET)
  .update(`${webhookTimestamp}.${rawWebhook}`).digest('hex')}`;
const accountFetch = async url => {
  const target = String(url);
  if (target === 'https://api.stripe.com/v1/account') {
    return new Response(JSON.stringify({ id: accountId, object: 'account' }), {
      status: 200, headers: { 'content-type': 'application/json' },
    });
  }
  if (target === `https://api.stripe.com/v1/events/${eventId}`) {
    return new Response(rawWebhook, { status: 200, headers: { 'content-type': 'application/json' } });
  }
  return new Response(JSON.stringify({ error: { type: 'invalid_request_error' } }), {
    status: 404, headers: { 'content-type': 'application/json' },
  });
};
const paymentIntent = {
  amount: 545_000,
  amount_received: 545_000,
  currency: 'usd',
  id: paymentIntentId,
  livemode: false,
  metadata: structuredClone(createdParameters.payment_intent_data.metadata),
  object: 'payment_intent',
  status: 'succeeded',
};
const providerSession = { ...paidSession, payment_intent: paymentIntent };

const netlifySiteId = 'site_ArcPaymentIntegration';
const netlifyDeployId = 'deploy_ArcPaymentIntegration';
let netlifySite = null;
let netlifyDeployTitle = null;
const preclaimArtifacts = artifactBytes.map((artifact, index) => index === 0
  ? { path: artifact.path, bytes: Buffer.from(ARC2_PRECLAIM_HEADERS_FILE) }
  : artifact);
const csp = ARC2_PRODUCTION_HEADERS_FILE.match(/^\s*Content-Security-Policy:\s*(.+?)\s*$/mi)?.[1];
assert.ok(csp);
const netlifyCalls = [];
const netlifyFetch = async (url, options = {}) => {
  const target = new URL(String(url));
  const method = options.method || 'GET';
  netlifyCalls.push({ method, url: target.toString() });
  if (target.origin === 'https://api.netlify.com') {
    const path = target.pathname.slice('/api/v1'.length);
    if (method === 'GET' && path === '/sites' && target.searchParams.get('filter') === 'owner') {
      return new Response(JSON.stringify(netlifySite ? [netlifySite] : []), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    }
    if (method === 'POST' && path === '/sites') {
      const intent = JSON.parse(options.body);
      netlifySite = {
        account_id: env.NETLIFY_TEAM_ACCOUNT_ID,
        account_slug: env.NETLIFY_TEAM_SLUG,
        id: netlifySiteId,
        name: intent.name,
        published_deploy: null,
        session_id: intent.session_id,
      };
      return new Response(JSON.stringify(netlifySite), {
        status: 201, headers: { 'content-type': 'application/json' },
      });
    }
    if (method === 'GET' && path === `/sites/${netlifySiteId}/deploys` && target.searchParams.get('per_page') === '100') {
      return new Response(JSON.stringify(netlifyDeployTitle ? [{
        id: netlifyDeployId, site_id: netlifySiteId, state: 'ready', title: netlifyDeployTitle,
      }] : []), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (method === 'POST' && path === `/sites/${netlifySiteId}/deploys`) {
      netlifyDeployTitle = target.searchParams.get('title');
      netlifySite = { ...netlifySite, published_deploy: { id: netlifyDeployId } };
      return new Response(JSON.stringify({ id: netlifyDeployId, site_id: netlifySiteId, state: 'ready' }), {
        status: 201, headers: { 'content-type': 'application/json' },
      });
    }
    if (method === 'GET' && path === `/deploys/${netlifyDeployId}`) {
      return new Response(JSON.stringify({ id: netlifyDeployId, site_id: netlifySiteId, state: 'ready' }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    }
    if (method === 'GET' && path === `/sites/${netlifySiteId}`) {
      return new Response(JSON.stringify(netlifySite), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    }
    if (method === 'GET' && path === `/accounts/${env.NETLIFY_TEAM_ACCOUNT_ID}`) {
      return new Response(JSON.stringify({ id: env.NETLIFY_TEAM_ACCOUNT_ID }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    }
    if (method === 'GET' && path === `/sites/${netlifySiteId}/deploys/${netlifyDeployId}`) {
      return new Response(JSON.stringify({ id: netlifyDeployId, site_id: netlifySiteId, state: 'ready' }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    }
    if (method === 'GET' && path === `/sites/${netlifySiteId}/files`) {
      return new Response(JSON.stringify(preclaimArtifacts.map(artifact => ({
        path: `/${artifact.path}`, size: artifact.bytes.length,
      }))), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const rawPrefix = `/sites/${netlifySiteId}/files/`;
    if (method === 'GET' && path.startsWith(rawPrefix)) {
      const artifactPath = decodeURIComponent(path.slice(rawPrefix.length));
      const artifact = preclaimArtifacts.find(item => item.path === artifactPath);
      return artifact ? new Response(artifact.bytes, { status: 200 }) : new Response('', { status: 404 });
    }
    throw new Error(`Unexpected Netlify integration request: ${method} ${target}`);
  }
  if (netlifySite && target.origin === `https://${netlifySite.name}.netlify.app`) {
    const artifactPath = target.pathname === '/' ? 'index.html' : `${target.pathname.slice(1)}index.html`;
    const artifact = artifactBytes.find(item => item.path === artifactPath);
    if (!artifact) return new Response('', { status: 404 });
    return new Response(expectedNetlifyLiveHtml(artifact.bytes, 'not_required', artifact.path), {
      status: 200,
      headers: {
        'content-security-policy': csp,
        'content-type': 'text/html; charset=utf-8',
        'x-robots-tag': 'noindex, nofollow, noarchive',
      },
    });
  }
  throw new Error(`Unexpected integration fetch: ${method} ${target}`);
};

assert.deepEqual(paymentArc2WorkerConfig.path,
  ['/internal/payment-arc2/claim', '/internal/payment-arc2/start', '/internal/payment-arc2/complete']);
assert.equal(claimSandboxBootstrapConfiguration(env, settlementNow).bootstrap_active, true);
assert.equal(paymentArc2WorkerConfiguration(env).enabled, true);
assert.equal(paymentArc2WorkerConfiguration({ ...env, ARC_PAYMENT_ARC2_WORKER_ENABLED: 'false' }).enabled, false);
assert.equal(paymentArc2WorkerConfiguration({
  ...env,
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'false',
}).enabled, true, 'The documented sandbox worker profile may run with reversal control not required.');
for (const unsafeSandboxMutation of [
  { ARC_STRIPE_LIVE_MODE_ENABLED: 'true' },
  { ARC_ALLOW_TEST_MODE_EVENTS: 'false' },
  { ARC_HANDOFF_ENABLED: 'true' },
  {
    ARC_STRIPE_LIVE_MODE_ENABLED: 'true',
    ARC_ALLOW_TEST_MODE_EVENTS: 'false',
    ARC_HANDOFF_ENABLED: 'true',
  },
]) {
  const unsafeSandboxWorker = paymentArc2WorkerConfiguration({
    ...env,
    ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'false',
    ...unsafeSandboxMutation,
  });
  assert.equal(unsafeSandboxWorker.reversalPolicyValid, false,
    'A sandbox label alone cannot exempt the worker from reversal control.');
  assert.equal(unsafeSandboxWorker.enabled, false,
    'A live, test-disabled, or handoff-enabled sandbox-labelled worker must fail closed.');
}
const productionWorkerEnv = {
  ...env,
  ARC_ALLOW_TEST_MODE_EVENTS: 'false',
  ARC_HANDOFF_ENABLED: 'true',
  ARC_RUNTIME_ENVIRONMENT: 'production',
  ARC_STRIPE_ACCOUNT_VERIFICATION_KEY: ['rk', 'live', 'arcIntegrationAccountRead0123456789'].join('_'),
  ARC_STRIPE_LIVE_MODE_ENABLED: 'true',
  ARC_STRIPE_REVIEW_SECRET_KEY: ['rk', 'live', 'arcIntegrationCheckout0123456789abcdef'].join('_'),
};
assert.equal(paymentArc2WorkerConfiguration({
  ...productionWorkerEnv,
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'false',
}).enabled, false, 'A production worker can never run when reversal control is not required.');
assert.equal(paymentArc2WorkerConfiguration({
  ...productionWorkerEnv,
  ARC_STRIPE_REVERSAL_CONTROL_REQUIRED: 'true',
}).enabled, true, 'An otherwise valid production worker remains available with reversal control required.');
assert.equal(paymentArc2WorkerConfiguration({
  ...env,
  ARC_RUNTIME_ENVIRONMENT: 'unknown',
}).enabled, false, 'An unknown runtime environment must fail closed.');
assert.equal(paymentArc2WorkerConfiguration({
  ...env,
  ARC_PAYMENT_ARC2_WORKER_SECRET: env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET,
}).enabled, false, 'The worker bearer secret must remain independent of durable identity HMACs.');
assert.equal(paymentArc2WorkerConfiguration({
  ...env,
  ARC_ROTATED_CREDENTIAL_V2: env.ARC_PAYMENT_ARC2_WORKER_SECRET,
}).enabled, false, 'A misleadingly named rotated alias cannot reuse the worker credential.');

const savedEnvironment = { ...process.env };
try {
  for (const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env, env);
  assert.equal(emailRecipientVaultConfiguration(process.env).enabled, true,
    JSON.stringify(Object.fromEntries(Object.entries(process.env).filter(([key]) => key.includes('VAULT')))));
  assert.deepEqual(arc2TransactionalEmailConfiguration(process.env), {
    flags_valid: true,
    requested: true,
    capsule_producer_enabled: true,
    claim_invitation_enabled: true,
    final_delivery_enabled: true,
  });
  const webhookRequest = () => new Request('https://arcweb.onl/internal/stripe/reversal-webhook', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'stripe-signature': stripeSignature,
    },
    body: rawWebhook,
  });
  const webhookContext = {
    alertStore: new FakeStore(),
    arc2Store: ledger,
    clock: () => new Date(fenceNow),
    paymentArc2BridgeStore: bridge,
    retentionFenceAlertStore: retentionAlerts,
    retentionFenceStaleAfterMs: 1_000,
    retentionFenceStore: retentionFence,
    reviewStore: review,
    stripeAccountFetch: accountFetch,
    stripeCheckoutAuthorityClient: stripeClient,
  };
  process.env.ARC_PAYMENT_ARC2_BRIDGE_ENABLED = 'false';
  const disabledBridgeResponse = await stripeWebhookHandler(webhookRequest(), webhookContext);
  assert.equal(disabledBridgeResponse.status, 503,
    'A paid review Checkout must request Stripe redelivery when the default-off bridge is unavailable.');
  assert.equal(bridge.values.size, 0);
  assert.equal([...ledger.values.values()].some(entry => entry.data?.state === 'PAID'), true,
    'The authenticated paid ledger must survive before the retriable bridge failure.');
  fenceNow = new Date(fenceNow.getTime() + 1_001);
  process.env.ARC_PAYMENT_ARC2_BRIDGE_ENABLED = 'true';
  const webhookResponse = await stripeWebhookHandler(webhookRequest(), webhookContext);
  assert.equal(webhookResponse.status, 200);
  const webhookBody = await webhookResponse.json();
  assert.equal(webhookEvent.type, 'checkout.session.async_payment_succeeded');
  assert.ok(settlementNow.getTime() > Date.parse(issued.record.expires_at),
    'The integration fixture must prove a Session created in-window can settle after invite expiry.');
  assert.equal(webhookBody.checkout_state, 'PAID');
  assert.equal(webhookBody.fulfillment_halted, false);
  assert.equal(webhookBody.payment_arc2_outbox_state, 'PENDING');
  assert.equal(webhookBody.payment_arc2_outbox_idempotent_replay, false);
  assert.match(bridge.writeKeys[0], /^payment-review-session-binding\/[a-f0-9]{64}$/);
  assert.match(bridge.writeKeys[1], /^payment-arc2-start-outbox\/[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify([...bridge.values.values()]), /cs_test_|preview\.owner@example/,
    'The paid webhook must persist only authenticated hashes, never raw Stripe ids or customer email.');

  const replayResponse = await stripeWebhookHandler(webhookRequest(), webhookContext);
  assert.equal(replayResponse.status, 200);
  const replayBody = await replayResponse.json();
  assert.equal(replayBody.idempotent_replay, true);
  assert.equal(replayBody.payment_arc2_outbox_idempotent_replay, true,
    'A Stripe retry must converge both the signed ledger receipt and the durable ARC2 outbox.');
  assert.equal(bridge.values.size, 3);

  const claimToken = 'payment_arc2_integration_claim_token_0123456789';
  const workerRequest = (path, body, secret = env.ARC_PAYMENT_ARC2_WORKER_SECRET) => new Request(
    `https://arcweb.onl${path}`,
    {
      method: 'POST',
      headers: { authorization: `Bearer ${secret}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
  const workerContext = {
    activationClock: () => new Date(settlementNow),
    arc2Store: ledger,
    clock: () => new Date(fenceNow),
    emailRecipientVaultStore: vault,
    paymentArc2BridgeStore: bridge,
    retentionFenceAlertStore: retentionAlerts,
    retentionFenceStaleAfterMs: 1_000,
    retentionFenceStore: retentionFence,
    reviewStore: review,
    stripeAccountFetch: accountFetch,
    stripeCheckoutAuthorityClient: stripeClient,
    uuid: () => '44444444-4444-4444-8444-444444444444',
    netlifyFetch,
  };
  assert.equal((await paymentArc2WorkerHandler(workerRequest('/internal/payment-arc2/claim', {
    claim_token: claimToken,
  }, 'wrong-worker-secret-value-0123456789abcdef'), workerContext)).status, 401);
  const claimResponse = await paymentArc2WorkerHandler(workerRequest('/internal/payment-arc2/claim', {
    claim_token: claimToken,
  }), workerContext);
  assert.equal(claimResponse.status, 200, await claimResponse.clone().text());
  const claimed = await claimResponse.json();
  assert.equal(claimed.state, 'CLAIMED');
  assert.equal(claimed.accepted, true);
  assert.equal(claimed.payload.invite_hmac_sha256, issued.record.invite_hmac_sha256);
  assert.match(claimed.outbox_key, /^payment-arc2-start-outbox\/[a-f0-9]{64}$/,
    'The authenticated claim-next route must discover durable paid work without the bridge HMAC secret.');

  const forgedCompletionResponse = await paymentArc2WorkerHandler(workerRequest('/internal/payment-arc2/complete', {
    claim_token: claimToken,
    completion: {
      schema: PAYMENT_ARC2_COMPLETION_SCHEMA,
      accepted: true,
      immutable_binding_sha256: claimed.immutable_binding_sha256,
      arc2_start_receipt: canonicalJson({ forged: true }),
      arc2_start_receipt_hmac_sha256: '0'.repeat(64),
    },
    outbox_key: claimed.outbox_key,
  }), workerContext);
  assert.equal(forgedCompletionResponse.status, 400,
    'A worker bearer cannot complete paid work with a forged receipt.');
  const startBody = {
    artifact_evidence: artifactEvidence,
    artifact_evidence_hmac_sha256: artifactSignature,
    checkout_session_id: checkoutSessionId,
    claim_token: claimToken,
    deploy_artifacts: deployArtifacts,
    lead_notification_email: '',
    lead_route_recipient_hmac_sha256: '',
    outbox_key: claimed.outbox_key,
  };
  const currentActivationManifest = process.env.ARC_ACTIVATION_MANIFEST;
  delete process.env.ARC_ACTIVATION_MANIFEST;
  const missingAuthorityResponse = await paymentArc2WorkerHandler(
    workerRequest('/internal/payment-arc2/start', startBody), workerContext,
  );
  assert.equal(missingAuthorityResponse.status, 503,
    'The payment worker must fail before ARC2 mutation when claim authority is absent.');
  assert.equal(ledger.writeKeys.some((key) => key.startsWith('claim-sandbox-bootstrap/')), false);
  process.env.ARC_ACTIVATION_MANIFEST = currentActivationManifest;
  fenceNow = new Date(fenceNow.getTime() + 1_001);
  const awaitingReversalResponse = await paymentArc2WorkerHandler(
    workerRequest('/internal/payment-arc2/start', startBody), workerContext,
  );
  assert.equal(awaitingReversalResponse.status, 202, await awaitingReversalResponse.clone().text());
  const awaitingReversal = await awaitingReversalResponse.json();
  assert.equal(awaitingReversal.state, 'PENDING');
  assert.equal(awaitingReversal.handoff_state, 'PAYMENT_VERIFIED');
  assert.equal(awaitingReversal.reversal_control_ready, false);
  assert.equal(awaitingReversal.retry_required, true);
  assert.equal(ledger.writeKeys.filter((key) => key.startsWith('claim-sandbox-bootstrap/')).length, 1,
    'The claim bootstrap must be atomically consumed once before the first ARC2 mutation.');
  assert.equal(netlifyCalls.length, 0,
    'Reversal-not-ready work must be requeued before any Netlify request.');

  const reversalBindingValue = {
    version: STRIPE_REVERSAL_BINDING_SCHEMA,
    scope: STRIPE_REVERSAL_BINDING_SCOPE,
    issued_at: settlementNow.toISOString(),
    checkout_session_id: checkoutSessionId,
    payment_intent_id: paymentIntentId,
    handoff_id: awaitingReversal.handoff_id,
    stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    livemode: false,
  };
  const reversalBindingEvidence = canonicalJson(reversalBindingValue);
  await registerStripeReversalBinding(reversalBindingEvidence, hmac(
    env.ARC_STRIPE_REVERSAL_BINDING_SECRET,
    `${STRIPE_REVERSAL_BINDING_PREFIX}${reversalBindingEvidence}`,
  ), env, { store: ledger, clock: () => new Date(settlementNow) });

  // A reversal that races after the handoff is prepared is terminal, not a
  // perpetually claimed/retried queue item. Exercise the real worker path on
  // an isolated copy so the clean-recheck happy path below remains intact.
  const haltedLedger = cloneStore(ledger);
  const haltedBridge = cloneStore(bridge);
  const haltedReview = cloneStore(review);
  const haltedVault = cloneStore(vault);
  const paymentIntentHmac = hmac(env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
    `payment-intent-v1\n${paymentIntentId}`);
  await haltedLedger.setJSON(stripeReversalKeys.pendingPaymentKeyFromHmac(paymentIntentHmac), {
    schema: STRIPE_PENDING_PAYMENT_SCHEMA,
    payment_intent_id_hmac_sha256: paymentIntentHmac,
    stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    livemode: false,
    delivery_halted: true,
  }, { onlyIfNew: true });
  let haltedProviderReads = 0;
  const haltedContext = {
    ...workerContext,
    arc2Store: haltedLedger,
    emailRecipientVaultStore: haltedVault,
    paymentArc2BridgeStore: haltedBridge,
    paymentArc2ProviderAuthority: async () => {
      haltedProviderReads += 1;
      return {
        account: { id: accountId, object: 'account' },
        session: structuredClone(providerSession),
      };
    },
    reviewStore: haltedReview,
  };
  const haltedResponse = await paymentArc2WorkerHandler(
    workerRequest('/internal/payment-arc2/start', startBody), haltedContext,
  );
  assert.equal(haltedResponse.status, 409, await haltedResponse.clone().text());
  const haltedBody = await haltedResponse.json();
  assert.equal(haltedBody.error, 'payment_arc2_authority_halted');
  assert.equal(haltedBody.state, 'REVIEW_REQUIRED');
  assert.equal(haltedBody.manual_review_required, true);
  assert.equal(haltedBody.retry_required, false);
  const haltedOutbox = haltedBridge.values.get(claimed.outbox_key).data;
  assert.equal(haltedOutbox.status, 'REVIEW_REQUIRED');
  assert.equal(haltedOutbox.manual_review_code, 'ARC_STRIPE_REVERSAL_HALT');
  assert.match(haltedOutbox.manual_review_evidence_sha256, /^[a-f0-9]{64}$/);
  assert.equal([...haltedBridge.values.keys()].some(key => key.startsWith('payment-arc2-pending/')), false);
  assert.equal([...haltedBridge.values.keys()].some(key => key.startsWith('payment-arc2-manual-review/')), true);
  // Simulate process death after the REVIEW_REQUIRED CAS but before its
  // manual-review index write. A Checkout webhook replay must reconstruct the
  // terminal index before deleting the stale pending entry.
  const haltedSuffix = claimed.outbox_key.slice('payment-arc2-start-outbox/'.length);
  for (const key of [...haltedBridge.values.keys()]) {
    if (key.startsWith('payment-arc2-manual-review/')) await haltedBridge.delete(key);
  }
  await haltedBridge.setJSON(`payment-arc2-pending/${haltedSuffix}`, {
    schema: PAYMENT_ARC2_PENDING_INDEX_SCHEMA,
    outbox_key: claimed.outbox_key,
    immutable_binding_sha256: haltedOutbox.immutable_sha256,
    created_at: haltedOutbox.created_at,
  }, { onlyIfNew: true });
  const haltedWebhookReplay = await stripeWebhookHandler(webhookRequest(), {
    ...webhookContext,
    arc2Store: haltedLedger,
    paymentArc2BridgeStore: haltedBridge,
    reviewStore: haltedReview,
  });
  assert.equal(haltedWebhookReplay.status, 200, await haltedWebhookReplay.clone().text());
  assert.equal([...haltedBridge.values.keys()].some(key => key.startsWith('payment-arc2-pending/')), false);
  assert.equal([...haltedBridge.values.keys()].some(key => key.startsWith('payment-arc2-manual-review/')), true,
    'Webhook replay must recover terminal manual-review discoverability before pending cleanup.');
  const attemptsAtHalt = haltedOutbox.claim_attempt_count;
  const providerReadsAtHalt = haltedProviderReads;
  const haltedReplay = await paymentArc2WorkerHandler(
    workerRequest('/internal/payment-arc2/start', startBody), haltedContext,
  );
  assert.equal(haltedReplay.status, 409, await haltedReplay.clone().text());
  const haltedReplayBody = await haltedReplay.json();
  assert.equal(haltedReplayBody.error, 'payment_arc2_authority_halted');
  assert.equal(haltedReplayBody.state, 'REVIEW_REQUIRED');
  assert.equal(haltedReplayBody.manual_review_required, true);
  assert.equal(haltedReplayBody.retry_required, false);
  assert.equal(haltedReplayBody.manual_review_evidence_sha256,
    haltedBody.manual_review_evidence_sha256);
  assert.equal(haltedBridge.values.get(claimed.outbox_key).data.claim_attempt_count, attemptsAtHalt,
    'A permanent reversal halt must never increment retries or reopen the claimed outbox.');
  assert.equal(haltedProviderReads, providerReadsAtHalt,
    'A terminal replay must return before any Stripe provider read.');

  const reversalRecheckValue = {
    version: STRIPE_REVERSAL_RECHECK_SCHEMA,
    scope: STRIPE_REVERSAL_RECHECK_SCOPE,
    handoff_id: awaitingReversal.handoff_id,
    checkout_session_id: checkoutSessionId,
    payment_intent_id: paymentIntentId,
    stripe_account_id_sha256: env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256,
    livemode: false,
    payment_intent_status: 'succeeded',
    refunded_amount_minor_units: 0,
    dispute_status: 'none',
    issued_at: settlementNow.toISOString(),
  };
  const reversalRecheckEvidence = canonicalJson(reversalRecheckValue);
  await registerStripeReversalRecheck(reversalRecheckEvidence, hmac(
    env.ARC_STRIPE_REVERSAL_RECHECK_SECRET,
    `${STRIPE_REVERSAL_RECHECK_PREFIX}${reversalRecheckEvidence}`,
  ), env, { store: ledger, clock: () => new Date(settlementNow) });

  const siteCreatedResponse = await paymentArc2WorkerHandler(
    workerRequest('/internal/payment-arc2/start', startBody), workerContext,
  );
  assert.equal(siteCreatedResponse.status, 202);
  assert.equal((await siteCreatedResponse.json()).handoff_state, 'SITE_CREATED');
  const deployReadyResponse = await paymentArc2WorkerHandler(
    workerRequest('/internal/payment-arc2/start', startBody), workerContext,
  );
  assert.equal(deployReadyResponse.status, 202);
  assert.equal((await deployReadyResponse.json()).handoff_state, 'PRECLAIM_DEPLOY_READY');
  const startResponse = await paymentArc2WorkerHandler(
    workerRequest('/internal/payment-arc2/start', startBody), workerContext,
  );
  assert.equal(startResponse.status, 200);
  const started = await startResponse.json();
  assert.equal(started.state, 'COMPLETED');
  assert.equal(started.handoff_state, 'INVITATION_READY');
  assert.equal(started.reversal_control_ready, true);
  assert.match(started.start_receipt_hmac_sha256, /^[a-f0-9]{64}$/);
  assert.equal(JSON.parse(started.start_receipt).continuation_ready, true);
  assert.equal(JSON.parse(started.start_receipt).recipient_email_sha256, sha256(recipientEmail));
  assert.equal(JSON.parse(started.start_receipt).payer_email_sha256, sha256(payerEmail));
  assert.notEqual(JSON.parse(started.start_receipt).recipient_email_sha256,
    JSON.parse(started.start_receipt).payer_email_sha256);
  assert.equal([...bridge.values.keys()].some(key => key.startsWith('payment-arc2-pending/')), false,
    'The start worker removes discoverability only after signed durable handoff receipt verification.');
  await assert.rejects(openEmailRecipientCapsule(vault, {
    job_kind: 'preview_review', job_key: prepared.outbox.outbox_hmac_sha256,
  }, env, { clock: () => new Date(settlementNow) }), /VAULT_NOT_FOUND/,
  'The source preview recipient capsule must be erased only after durable ARC2 completion.');
  for (const kind of ['claim_invitation', 'final_delivery']) {
    assert.equal((await openEmailRecipientCapsule(vault, {
      job_kind: kind, job_key: awaitingReversal.handoff_id,
    }, env, { clock: () => new Date(settlementNow) })).recipient_email, recipientEmail,
    'Both downstream ownership-email capsules must survive source cleanup.');
  }
  const completedReplay = await paymentArc2WorkerHandler(
    workerRequest('/internal/payment-arc2/start', startBody), workerContext,
  );
  assert.equal(completedReplay.status, 200);
  assert.equal((await completedReplay.json()).state, 'COMPLETED',
    'A completed paid worker replay must converge after idempotent source cleanup.');

  process.env.ARC_STRIPE_REVERSAL_CONTROL_REQUIRED = 'true';
  assert.equal(paymentArc2WorkerConfiguration(process.env).enabled, true);
  assert.equal((await paymentArc2WorkerHandler(workerRequest('/internal/payment-arc2/claim', {
    claim_token: claimToken,
  }), workerContext)).status, 200,
  'The reversal-aware worker must remain available when production reversal control is required.');
} finally {
  for (const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env, savedEnvironment);
}

const [webhookSource, workerSource] = await Promise.all([
  readFile(new URL('../netlify/functions/stripe-reversal-webhook.mjs', import.meta.url), 'utf8'),
  readFile(new URL('../netlify/functions/payment-arc2-worker.mjs', import.meta.url), 'utf8'),
]);
assert.ok(webhookSource.indexOf('processStripeCheckoutEvent(') <
  webhookSource.indexOf('createPaymentArc2StartOutbox('),
'The webhook source must commit the signed Checkout ledger before creating the payment ARC2 outbox.');
assert.match(workerSource, /authenticateBearer\(request, process\.env\.ARC_PAYMENT_ARC2_WORKER_SECRET\)/);
assert.match(workerSource, /configuration\.reversalControlRequired/);

console.log('Stripe review payment integration contract passed.');
