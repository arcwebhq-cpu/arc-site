import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import {
  canonicalJson,
  sha256Hex,
  validateExpectedBindings,
} from '../netlify/lib/arc2-handoff-core.mjs';
import { ACTIVATION_BUILD_IDENTITY } from '../netlify/lib/activation-build-identity.mjs';
import {
  FIRST_PARTY_RETENTION_RECEIPT_ENV,
  FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA,
  buildFirstPartyLegalHoldRecord,
  buildPaidHandoffRetentionRelease,
  firstPartyLegalHoldKey,
  firstPartyRetentionConfiguration,
  firstPartyRetentionContract,
  firstPartyRetentionReceiptFromEnvironment,
  paidHandoffRetentionReleaseKey,
  runFirstPartyRetentionSweepCycle,
  validateFirstPartyRetentionReceipt,
} from '../netlify/lib/first-party-retention-core.mjs';
import {
  assertRetentionGenerationFenceAuthority,
  beginRetentionProducerOperation,
  runRetentionProducerOperation,
} from '../netlify/lib/retention-generation-fence-core.mjs';

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; this.conditionalRaces = new Map(); this.deleteCalls = 0; }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    if (options.onlyIfMatch && this.conditionalRaces.has(key)) {
      const replacement = this.conditionalRaces.get(key);
      this.conditionalRaces.delete(key);
      this.values.set(key, { data: structuredClone(replacement), etag: `retention-etag-${++this.sequence}` });
    }
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `retention-etag-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
  raceNextOnlyIfMatch(key, replacement) { this.conditionalRaces.set(key, structuredClone(replacement)); }
  async delete() { this.deleteCalls += 1; throw new Error('Unconditional delete is forbidden.'); }
  list({ prefix, paginate }) {
    assert.equal(paginate, true, 'Every retention family must consume provider pages explicitly.');
    const blobs = [...this.values.keys()].filter((key) => key.startsWith(prefix)).sort().map((key) => ({ key }));
    return (async function *pages() {
      for (let index = 0; index < blobs.length; index += 2) yield { blobs: blobs.slice(index, index + 2) };
      if (blobs.length === 0) yield { blobs: [] };
    })();
  }
}

const now = new Date('2035-08-28T12:00:00.000Z');
const old = (minutes) => new Date(Date.parse('2026-01-01T00:00:00.000Z') + minutes * 60_000).toISOString();
const secretNames = [
  'ARC_FIRST_PARTY_RETENTION_HMAC_SECRET',
  'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET',
  'ARC_INTAKE_ABUSE_HMAC_SECRET',
  'ARC_REVIEW_RECORD_HMAC_SECRET',
  'ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET',
  'ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET',
  'ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET',
  'ARC_HANDOFF_STATE_SECRET',
  'ARC_EMAIL_CLAIM_BINDING_SECRET',
  'ARC_STRIPE_REVERSAL_HMAC_SECRET',
  'ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET',
];
const env = {
  ...Object.fromEntries(secretNames.map((name, index) => [name,
    `${name.toLowerCase()}-${index}-unique-contract-secret-0123456789abcdef`])),
  ARC_FIRST_PARTY_RETENTION_ENABLED: 'true',
  ARC_FIRST_PARTY_RETENTION_UNPAID_DAYS: '730',
  ARC_FIRST_PARTY_RETENTION_PAID_DAYS: '2555',
};
assert.equal(firstPartyRetentionConfiguration({}).enabled, false);
assert.equal(firstPartyRetentionConfiguration(env).enabled, true);
assert.equal(firstPartyRetentionContract.phases.some((phase) =>
  phase.store === 'payment' && phase.kind === 'payment-child' &&
  phase.prefix === 'payment-arc2-manual-review/'), true,
'Retention inventory must explicitly account for durable payment manual-review indexes.');
assert.equal(firstPartyRetentionConfiguration({ ...env,
  ARC_FIRST_PARTY_RETENTION_HMAC_SECRET: env.ARC_HANDOFF_STATE_SECRET }).enabled, false,
'Retention evidence must use a key that is distinct from every source-state key.');
for (const credentialName of secretNames) {
  assert.equal(firstPartyRetentionConfiguration({
    ...env,
    ARC_ROTATED_CREDENTIAL_V2: env[credentialName],
  }).enabled, false, `An arbitrary alias must not reuse ${credentialName}.`);
}

const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const signSource = (value, secret, domain) => ({
  ...value,
  record_hmac_sha256: hmac(secret, `${domain}\n${canonicalJson(value)}`),
});
const reviewOutboxHmac = (invite) => hmac(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
  `arc-preview-review-email-outbox-id-v1\n${invite}`);
function reviewRenewal(replacedInvite, replacementInvite, state = 'READY', overrides = {}, signingSecret = null) {
  const unsigned = {
    schema: 'arc-preview-review-email-renewal-v1', version: 1,
    record_revision: state === 'READY' ? 2 : 1, state,
    renewal_hmac_sha256: hmac(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
      `arc-preview-review-email-renewal-id-v1\n${replacedInvite}`),
    replaced_invite_hmac_sha256: replacedInvite,
    replaced_outbox_hmac_sha256: reviewOutboxHmac(replacedInvite),
    replacement_invite_hmac_sha256: replacementInvite,
    replacement_outbox_hmac_sha256: reviewOutboxHmac(replacementInvite),
    recipient_email_sha256: '9'.repeat(64), preview_manifest_sha256: '8'.repeat(64),
    created_at: old(1), replacement_expires_at: old(60),
    ready_at: state === 'READY' ? old(2) : null,
    ...overrides,
  };
  return signSource(unsigned, signingSecret || env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    'arc-preview-review-email-renewal-record-signature-v1');
}
const tombstoneFields = [
  'customer_data_stored', 'family', 'record_hmac_sha256', 'schema', 'source_key_hmac_sha256',
  'source_record_sha256', 'sweep_hmac_sha256', 'tombstoned_at', 'version',
];
function assertTombstone(store, key, source, family, receipt) {
  const value = store.values.get(key)?.data;
  assert.ok(value, `Expected a retention tombstone at ${key}.`);
  assert.deepEqual(Object.keys(value).sort(), [...tombstoneFields].sort());
  assert.equal(value.schema, FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA);
  assert.equal(value.version, 1);
  assert.equal(value.family, family);
  assert.equal(value.sweep_hmac_sha256, receipt.sweep_hmac_sha256);
  assert.equal(value.source_key_hmac_sha256, hmac(env.ARC_FIRST_PARTY_RETENTION_HMAC_SECRET,
    `arc-first-party-retention-source-key-v1\n${key}`));
  assert.equal(value.source_record_sha256, sha256Hex(canonicalJson(source)));
  assert.equal(value.tombstoned_at, receipt.started_at);
  assert.equal(value.customer_data_stored, false);
  const { record_hmac_sha256: signature, ...unsigned } = value;
  assert.equal(signature, hmac(env.ARC_FIRST_PARTY_RETENTION_HMAC_SECRET,
    `arc-first-party-retention-tombstone-record-v1\n${canonicalJson(unsigned)}`));
  for (const sourceField of Object.keys(source)) {
    if (!tombstoneFields.includes(sourceField)) {
      assert.equal(Object.hasOwn(value, sourceField), false, `Tombstone leaked source field ${sourceField}.`);
    }
  }
  return value;
}
const stores = {
  control: new FakeStore(), abuse: new FakeStore(), review: new FakeStore(),
  revision: new FakeStore(), handoff: new FakeStore(), payment: new FakeStore(), alerts: new FakeStore(),
};

await stores.abuse.setJSON(`challenge-replay/${'1'.repeat(64)}`, {
  schema: 'arc-intake-turnstile-replay-v1', request_hmac_sha256: '2'.repeat(64),
  challenge_at: old(1), consumed_at: old(2), expires_at: old(7),
});
const legalSuppressionId = '3'.repeat(64);
const legalSuppression = signSource({
  schema: 'arc-intake-abuse-suppression-v1', scope: 'recipient',
  identity_hmac_sha256: legalSuppressionId, reason_code: 'LEGAL', issued_at: old(1), expires_at: old(8),
}, env.ARC_INTAKE_ABUSE_HMAC_SECRET, 'arc-intake-abuse-suppression-v1');
await stores.abuse.setJSON(`suppression/recipient/${legalSuppressionId}`, legalSuppression);
await stores.abuse.setJSON(`quota/global/${'4'.repeat(64)}/${old(0)}/00000`, {
  schema: 'corrupt-unsigned-quota', expires_at: old(3),
});

const inviteId = '5'.repeat(64);
const recipient = '6'.repeat(64);
const review = signSource({
  schema: 'arc-preview-review-invite-v1', version: 1, state: 'OPEN',
  invite_hmac_sha256: inviteId, recipient_email_sha256: recipient,
  created_at: old(1), expires_at: old(60), decision: null,
  prior_invite_hmac_sha256: null, successor_invite_hmac_sha256: null,
}, env.ARC_REVIEW_RECORD_HMAC_SECRET, 'arc-preview-review-record-signature-v1');
await stores.review.setJSON(`review-invites/${inviteId}`, review);
const outboxId = hmac(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
  `arc-preview-review-email-outbox-id-v1\n${inviteId}`);
const reviewProviderEventId = '7'.repeat(64);
const reviewProviderMessageId = '8'.repeat(64);
const reviewDeliveryReceipt = '1'.repeat(64);
const reviewProviderAccount = '2'.repeat(64);
const outbox = signSource({
  schema: 'arc-preview-review-email-outbox-v1', version: 1, record_revision: 2, state: 'DELIVERED',
  outbox_hmac_sha256: outboxId, invite_hmac_sha256: inviteId,
  recipient_email_sha256: recipient, preview_manifest_sha256: '3'.repeat(64),
  template_version: 'arc-review-preview-v1', created_at: old(1), expires_at: old(60),
  send_reserved_at: old(20), provider_idempotency_key_sha256: '4'.repeat(64),
  delivery_receipt_sha256: reviewDeliveryReceipt, provider: 'resend',
  provider_account_hmac_sha256: reviewProviderAccount,
  provider_event_id_hmac_sha256: reviewProviderEventId,
  provider_message_id_hmac_sha256: reviewProviderMessageId,
  event_type: 'message.delivered', delivery_status: 'delivered', event_at: old(61),
  receipt_issued_at: old(62), delivered_receipt_sha256: reviewDeliveryReceipt,
  suppression_receipt_sha256: null, suppression_status: null, suppressed_at: null,
  terminal_at: old(61),
}, env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET, 'arc-preview-review-email-outbox-record-signature-v1');
await stores.review.setJSON(`review-email-outbox/${outboxId}`, outbox);
const reviewProviderEvent = {
  schema: 'arc-preview-review-email-provider-identity-v1', kind: 'provider-event',
  outbox_hmac_sha256: outboxId, provider: 'resend',
  provider_account_hmac_sha256: reviewProviderAccount,
  identity_hmac_sha256: reviewProviderEventId, delivery_receipt_sha256: reviewDeliveryReceipt,
};
await stores.review.setJSON(`review-email-provider-event/${reviewProviderEventId}`, reviewProviderEvent);
const reviewProviderMessage = {
  schema: 'arc-preview-review-email-provider-identity-v1', kind: 'provider-message',
  outbox_hmac_sha256: outboxId, provider: 'resend',
  provider_account_hmac_sha256: reviewProviderAccount,
  identity_hmac_sha256: reviewProviderMessageId,
};
await stores.review.setJSON(`review-email-provider-message/${reviewProviderMessageId}`, reviewProviderMessage);
const recipientControlId = hmac(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
  `arc-preview-review-email-recipient-control-id-v1\n${recipient}`);
const recipientControl = signSource({
  schema: 'arc-preview-review-email-recipient-control-v1', version: 1, record_revision: 1, state: 'ACTIVE',
  recipient_control_hmac_sha256: recipientControlId, recipient_email_sha256: recipient,
  authority_operation_hmac_sha256: null, authority_expires_at: null,
  suppression_receipt_sha256: null, suppression_status: null, suppressed_at: null,
  source_invite_hmac_sha256: null, source_outbox_hmac_sha256: null,
}, env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
'arc-preview-review-email-recipient-control-signature-v1');
await stores.review.setJSON(`review-email-recipient-control/${recipientControlId}`, recipientControl);
const pending = signSource({
  schema: 'arc-preview-review-email-pending-v1', version: 1, record_revision: 1,
  entries: [{ invite_hmac_sha256: inviteId, outbox_hmac_sha256: outboxId }], updated_at: old(30),
}, env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET, 'arc-preview-review-email-pending-record-signature-v1');
await stores.review.setJSON('review-email-pending/index-v1', pending);

const approval = 'b'.repeat(64);
const checkoutId = hmac(env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET,
  `arc-review-checkout-revocable-binding-id-v1\n${approval}`);
const checkout = signSource({
  schema: 'arc-review-checkout-revocable-binding-v1', version: 1, record_revision: 3,
  state: 'EXPIRED', binding_hmac_sha256: checkoutId, approval_receipt_sha256: approval,
  recipient_email_sha256: recipient, created_at: old(1), expired_at: old(62), suppressed_at: old(60),
  fulfillment_halted: true, provider_payment_status: 'unpaid',
}, env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET,
'arc-review-checkout-revocable-binding-signature-v1');
await stores.review.setJSON(`review-checkout-binding/${checkoutId}`, checkout);
const approvedInviteId = 'a'.repeat(64);
const approvedReview = signSource({
  schema: 'arc-preview-review-invite-v1', version: 1, state: 'APPROVED',
  invite_hmac_sha256: approvedInviteId, recipient_email_sha256: recipient,
  created_at: old(1), expires_at: old(60),
  decision: { action: 'APPROVE_AND_PAY', approval_receipt_sha256: approval },
  prior_invite_hmac_sha256: null, successor_invite_hmac_sha256: null,
}, env.ARC_REVIEW_RECORD_HMAC_SECRET, 'arc-preview-review-record-signature-v1');
await stores.review.setJSON(`review-invites/${approvedInviteId}`, approvedReview);
const checkoutIndexId = hmac(env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET,
  `arc-review-checkout-recipient-index-id-v1\n${recipient}`);
const checkoutIndex = signSource({
  schema: 'arc-review-checkout-recipient-index-v1', version: 1, record_revision: 1,
  recipient_index_hmac_sha256: checkoutIndexId, recipient_email_sha256: recipient,
  bindings: [{ approval_receipt_sha256: approval, binding_hmac_sha256: checkoutId }], updated_at: old(63),
}, env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET,
'arc-review-checkout-recipient-index-signature-v1');
await stores.review.setJSON(`review-checkout-recipient-index/${checkoutIndexId}`, checkoutIndex);

function deliveredHandoff() {
  const id = 'd'.repeat(64);
  return {
    schema: 'arc2-netlify-handoff-v2', handoff_id: id, state: 'DELIVERED', revision: 15,
    created_at: old(0), updated_at: old(40),
    payment_evidence_sha256: '1'.repeat(64), artifact_evidence_sha256: '2'.repeat(64),
    artifact_manifest_sha256: '3'.repeat(64), bundle_fingerprint: '4'.repeat(64),
    production_content_sha256: '5'.repeat(64), customer_email_sha256: '6'.repeat(64),
    lead_notification_email_sha256: sha256Hex(''), lead_route_recipient_hmac_sha256: '',
    lead_route_mode: 'not_required', preview_folder: 'sample-roofing-a1b2c3d4',
    artifacts: [
      { path: '_headers', sha256: '9'.repeat(64), size: 10 },
      { path: 'about/index.html', sha256: 'a'.repeat(64), size: 20 },
      { path: 'contact/index.html', sha256: 'b'.repeat(64), size: 20 },
      { path: 'process/index.html', sha256: 'c'.repeat(64), size: 20 },
      { path: 'services/index.html', sha256: 'd'.repeat(64), size: 20 },
      { path: 'index.html', sha256: 'e'.repeat(64), size: 20 },
    ],
    form_name: '', netlify_session_id: '11111111-1111-4111-8111-111111111111',
    netlify_site_name: `arc-lead-route-${'a'.repeat(24)}`, netlify_source_account_id: 'source-account',
    netlify_site_id: 'site-identifier', site_created_at: old(5),
    preclaim_deploy_attempted_at: old(6), preclaim_deploy_candidate_id: 'f'.repeat(24),
    preclaim_deploy_id: 'f'.repeat(24), final_deploy_attempted_at: old(32),
    final_deploy_candidate_id: 'e'.repeat(24), final_deploy_id: 'e'.repeat(24),
    email_hook_attempted_at: null, form_id: null, hook_id: null,
    destination_account_id: 'customer-account', lead_route_receipt_sha256: '7'.repeat(64),
    claim_token_hmac_sha256: null, claim_invitation_generation: 1,
    claim_token_consumed_hmac_sha256: '8'.repeat(64), claim_token_expires_at: old(40),
    claim_token_used_at: old(20), claim_wrapper_consumed_at: old(20),
    claim_jwt_issued_at: Math.floor(Date.parse(old(20)) / 1000), claim_invitation_ready_at: old(10),
    lead_route_provider_message_id_sha256: '9'.repeat(64), claim_callback_received_at: old(30),
    claimed_verified_at: old(31), final_deploy_ready_at: old(33),
    production_url: `https://arc-lead-route-${'a'.repeat(24)}.netlify.app/`,
    outbox_claim_status: 'CLAIMED', outbox_claim_key_hmac_sha256: 'a'.repeat(64),
    final_delivery_receipt_sha256: 'b'.repeat(64), final_delivery_provider: 'resend',
    final_delivery_provider_account_hmac_sha256: 'c'.repeat(64),
    final_delivery_provider_event_id_hmac_sha256: 'd'.repeat(64),
    final_delivery_provider_message_id_hmac_sha256: 'e'.repeat(64),
    final_delivery_event_type: 'message.delivered', final_delivery_status: 'delivered',
    final_delivery_receipt_issued_at: old(35), delivered_at: old(34),
  };
}
const handoff = deliveredHandoff();
assert.doesNotThrow(() => validateExpectedBindings(handoff));
await stores.handoff.setJSON(`handoffs/${handoff.handoff_id}`, handoff);
const siteIndex = (record) => ({
  key: `site-index/${sha256Hex(record.netlify_site_id)}`,
  value: {
    schema: 'arc2-site-index-v1', handoff_id: record.handoff_id,
    netlify_site_id: record.netlify_site_id, netlify_session_id: record.netlify_session_id,
  },
});
const primarySiteIndex = siteIndex(handoff);
await stores.handoff.setJSON(primarySiteIndex.key, primarySiteIndex.value);
const release = buildPaidHandoffRetentionRelease({
  handoff_id: handoff.handoff_id,
  source_record_sha256: sha256Hex(canonicalJson(handoff)),
  provider_evidence_sha256: '1'.repeat(64), adult_approval_hmac_sha256: '2'.repeat(64),
  legal_hold: false, netlify_transfer_verified: true, payment_retention_complete: true,
  tax_retention_complete: true, dispute_refund_retention_complete: true,
  issued_at: new Date(now.getTime() - 60_000).toISOString(),
  expires_at: new Date(now.getTime() + 60 * 60_000).toISOString(),
}, env);
await stores.control.setJSON(paidHandoffRetentionReleaseKey(handoff.handoff_id), release);

const heldReviewId = 'e'.repeat(64);
const heldReview = signSource({
  schema: 'arc-preview-review-invite-v1', version: 1, state: 'OPEN',
  invite_hmac_sha256: heldReviewId, recipient_email_sha256: 'f'.repeat(64),
  created_at: old(1), expires_at: old(60), decision: null,
  prior_invite_hmac_sha256: null, successor_invite_hmac_sha256: null,
}, env.ARC_REVIEW_RECORD_HMAC_SECRET, 'arc-preview-review-record-signature-v1');
await stores.review.setJSON(`review-invites/${heldReviewId}`, heldReview);
const hold = buildFirstPartyLegalHoldRecord({
  family: 'review', subject_hmac_sha256: heldReviewId, reason_code: 'LEGAL',
  issued_at: new Date(now.getTime() - 60_000).toISOString(), expires_at: null,
}, env);
await stores.control.setJSON(firstPartyLegalHoldKey('review', heldReviewId), hold);

let result;
for (let cycle = 0; cycle < firstPartyRetentionContract.phases.length * 8; cycle += 1) {
  result = await runFirstPartyRetentionSweepCycle(env, stores, {
    clock: () => new Date(now), limit: 1, uuid: () => '11111111-1111-4111-8111-111111111111',
  });
  if (result.state === 'COMPLETE') break;
}
assert.equal(result?.state, 'COMPLETE', 'Every bounded phase must eventually finish with a durable receipt.');
assert.ok(result.receipt);
assertTombstone(stores.abuse, `challenge-replay/${'1'.repeat(64)}`, {
  schema: 'arc-intake-turnstile-replay-v1', request_hmac_sha256: '2'.repeat(64),
  challenge_at: old(1), consumed_at: old(2), expires_at: old(7),
}, 'intake_abuse', result.receipt);
assert.equal(stores.abuse.values.has(`suppression/recipient/${legalSuppressionId}`), true,
  'A LEGAL suppression is an exact legal hold, even after expires_at.');
assert.equal([...stores.control.values.keys()].some((key) => key.startsWith('first-party-retention/quarantine/intake_abuse/')), true);
assertTombstone(stores.review, `review-invites/${inviteId}`, review, 'review', result.receipt);
assertTombstone(stores.review, `review-email-outbox/${outboxId}`, outbox, 'review', result.receipt);
assertTombstone(stores.review, `review-email-provider-event/${'7'.repeat(64)}`,
  reviewProviderEvent, 'review', result.receipt);
assertTombstone(stores.review, `review-email-provider-message/${'8'.repeat(64)}`,
  reviewProviderMessage, 'review', result.receipt);
assert.deepEqual((await stores.review.getWithMetadata(
  `review-email-recipient-control/${recipientControlId}`)).data, recipientControl,
'ACTIVE recipient controls remain reusable after every bound review is retained.');
assertTombstone(stores.review, `review-checkout-binding/${checkoutId}`, checkout, 'checkout', result.receipt);
assertTombstone(stores.review, `review-invites/${approvedInviteId}`,
  approvedReview, 'review', result.receipt);
const reusableCheckoutIndex = (await stores.review.getWithMetadata(
  `review-checkout-recipient-index/${checkoutIndexId}`)).data;
assert.equal(reusableCheckoutIndex.schema, 'arc-review-checkout-recipient-index-v1');
assert.equal(reusableCheckoutIndex.recipient_index_hmac_sha256, checkoutIndexId);
assert.equal(reusableCheckoutIndex.recipient_email_sha256, recipient);
assert.deepEqual(reusableCheckoutIndex.bindings, [],
  'A shared Checkout recipient index must become a signed empty reusable record.');
assert.equal(reusableCheckoutIndex.record_revision, checkoutIndex.record_revision + 1);
assert.equal(stores.review.values.has(`review-invites/${heldReviewId}`), true,
  'A signed active legal hold must preserve the complete review cascade.');
assertTombstone(stores.handoff, `handoffs/${handoff.handoff_id}`, handoff, 'handoff', result.receipt);
assertTombstone(stores.handoff, primarySiteIndex.key, primarySiteIndex.value, 'handoff', result.receipt);

const subjectManifests = [...stores.control.values.values()].map((entry) => entry.data)
  .filter((value) => value?.schema === 'arc-first-party-retention-subject-manifest-v1');
const atomicReviewManifest = subjectManifests.find((manifest) => manifest.family === 'review' &&
  manifest.entries.some((item) => item.role === 'PRIMARY' &&
    item.source_key === `review-invites/${inviteId}`));
assert.ok(atomicReviewManifest, 'The review primary must have one signed subject manifest.');
for (const key of [`review-email-outbox/${outboxId}`,
  `review-email-provider-event/${reviewProviderEventId}`,
  `review-email-provider-message/${reviewProviderMessageId}`, 'review-email-pending/index-v1',
  `review-invites/${inviteId}`]) {
  assert.equal(atomicReviewManifest.entries.some((item) => item.source_key === key), true,
    'Every bound review child and the primary must share one FROZEN manifest.');
}
assert.equal(atomicReviewManifest.entries.filter((item) => item.role === 'PRIMARY').length, 1);
const atomicCheckoutManifest = subjectManifests.find((manifest) => manifest.family === 'checkout' &&
  manifest.entries.some((item) => item.role === 'PRIMARY' &&
    item.source_key === `review-checkout-binding/${checkoutId}`));
assert.ok(atomicCheckoutManifest, 'The Checkout primary must have one signed subject manifest.');
assert.equal(atomicCheckoutManifest.entries.some((item) =>
  item.source_key === `review-checkout-recipient-index/${checkoutIndexId}` && item.role === 'CHILD'), true,
'The shared Checkout index rewrite and primary must share one FROZEN manifest.');

const receipt = validateFirstPartyRetentionReceipt(result.receipt, env, { current: true, now });
assert.equal(receipt.customer_data_stored, false);
assert.deepEqual(receipt.families, ['intake_abuse', 'review', 'checkout', 'handoff']);
const receiptEnv = { ...env, [FIRST_PARTY_RETENTION_RECEIPT_ENV]: JSON.stringify(receipt) };
assert.deepEqual(firstPartyRetentionReceiptFromEnvironment(receiptEnv, now), receipt);
assert.equal(receipt.deployment_sha, ACTIVATION_BUILD_IDENTITY.deployment_sha);
assert.equal(firstPartyRetentionReceiptFromEnvironment({ ...receiptEnv,
  [FIRST_PARTY_RETENTION_RECEIPT_ENV]: JSON.stringify({ ...receipt, deployment_sha: 'b'.repeat(40) }),
}, now), null, 'A completion receipt cannot be replayed onto another deploy.');
assert.equal((await runFirstPartyRetentionSweepCycle(env, stores, {
  clock: () => new Date(now), limit: 1, uuid: () => '22222222-2222-4222-8222-222222222222',
})).idempotent_replay, true);

const freshStores = () => ({
  control: new FakeStore(), abuse: new FakeStore(), review: new FakeStore(),
  revision: new FakeStore(), handoff: new FakeStore(), payment: new FakeStore(), alerts: new FakeStore(),
});
const runThroughPhase = async (scenarioStores, kind) => {
  const phaseIndex = firstPartyRetentionContract.phases.findIndex((phase) => phase.kind === kind);
  assert.notEqual(phaseIndex, -1);
  for (let index = 0; index <= phaseIndex; index += 1) {
    await runFirstPartyRetentionSweepCycle(env, scenarioStores, {
      clock: () => new Date(now), limit: 500, uuid: () => '33333333-3333-4333-8333-333333333333',
    });
  }
};
const finishSweep = async (scenarioStores) => {
  let completion;
  for (let cycle = 0; cycle < firstPartyRetentionContract.phases.length * 2; cycle += 1) {
    completion = await runFirstPartyRetentionSweepCycle(env, scenarioStores, {
      clock: () => new Date(now), limit: 500, uuid: () => '44444444-4444-4444-8444-444444444444',
    });
    if (completion.state === 'COMPLETE') return completion;
  }
  assert.fail('Retention race scenario did not complete.');
};

const producerDescriptor = (label) => ({
  route: `test/${label}`,
  idempotency_key_sha256: sha256Hex(`idempotency:${label}`),
  mutation_sha256: sha256Hex(`mutation:${label}`),
  output_record_sha256: sha256Hex(`output:${label}`),
  source_record_sha256: sha256Hex(`source:${label}`),
  subject_hmac_sha256: sha256Hex(`subject:${label}`),
});

// A manifest built at OPEN(N) cannot freeze after a producer advances N. The
// same subject is retried from a new manifest at OPEN(N+1).
const driftStores = freshStores();
const driftKey = `challenge-replay/${'d'.repeat(64)}`;
const driftReplay = {
  schema: 'arc-intake-turnstile-replay-v1', request_hmac_sha256: 'e'.repeat(64),
  challenge_at: old(1), consumed_at: old(2), expires_at: old(3),
};
await driftStores.abuse.setJSON(driftKey, driftReplay);
let driftInjected = false;
const driftResult = await runFirstPartyRetentionSweepCycle(env, driftStores, {
  clock: () => new Date(now), limit: 500, uuid: () => '12121212-1212-4212-8212-121212121212',
  afterSubjectManifest: async () => {
    if (driftInjected) return;
    driftInjected = true;
    const descriptor = producerDescriptor('manifest-drift');
    const completed = await runRetentionProducerOperation(driftStores.control, descriptor, env, {
      clock: () => new Date(now),
      readSource: async () => descriptor.source_record_sha256,
      readOutput: async () => descriptor.output_record_sha256,
      mutate: async () => {},
    });
    assert.equal(completed.state, 'COMPLETE');
  },
});
assert.equal(driftResult.state, 'PARTIAL');
assert.deepEqual((await driftStores.abuse.getWithMetadata(driftKey)).data, driftReplay);
await runFirstPartyRetentionSweepCycle(env, driftStores, {
  clock: () => new Date(now), limit: 500, uuid: () => '12121212-1212-4212-8212-121212121212',
});
assert.equal((await driftStores.abuse.getWithMetadata(driftKey)).data.schema,
  FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA);

// Once the subject is FROZEN, a producer can create its signed intent but
// cannot enter WRITING or mutate until retention finalizes and reopens.
const frozenStores = freshStores();
const frozenKey = `challenge-replay/${'a'.repeat(64)}`;
await frozenStores.abuse.setJSON(frozenKey, {
  schema: 'arc-intake-turnstile-replay-v1', request_hmac_sha256: 'b'.repeat(64),
  challenge_at: old(1), consumed_at: old(2), expires_at: old(3),
});
let blockedProducer = null;
await runFirstPartyRetentionSweepCycle(env, frozenStores, {
  clock: () => new Date(now), limit: 500, uuid: () => '13131313-1313-4313-8313-131313131313',
  afterSubjectFreeze: async () => {
    blockedProducer = await beginRetentionProducerOperation(frozenStores.control,
      producerDescriptor('producer-vs-freeze'), env, { clock: () => new Date(now) });
  },
});
assert.equal(blockedProducer.retryable, true);
assert.equal((await frozenStores.abuse.getWithMetadata(frozenKey)).data.schema,
  FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA);

// A long FROZEN subject renews its signed authority with the live clock before
// every domain operation. Each renewal advances stale_at and invalidates the
// prior ETag so a slow pre-renewal worker cannot continue.
const heartbeatStores = freshStores();
const heartbeatKey = `challenge-replay/${'c'.repeat(64)}`;
await heartbeatStores.abuse.setJSON(heartbeatKey, {
  schema: 'arc-intake-turnstile-replay-v1', request_hmac_sha256: 'd'.repeat(64),
  challenge_at: old(1), consumed_at: old(2), expires_at: old(3),
});
let heartbeatTick = -1;
const heartbeatClock = () => new Date(now.getTime() + (++heartbeatTick * 90_000));
let oldFrozenAuthority = null;
let oldStaleAt = null;
let heartbeatAdvanced = false;
await runFirstPartyRetentionSweepCycle(env, heartbeatStores, {
  clock: heartbeatClock, limit: 500, uuid: () => '16161616-1616-4616-8616-161616161616',
  afterSubjectFreeze: async () => {
    const state = await heartbeatStores.control.getWithMetadata(
      'first-party-retention/generation-fence/state-v1');
    oldStaleAt = state.data.stale_at;
    oldFrozenAuthority = {
      status: state.data.status,
      generation: state.data.generation,
      operation_hmac_sha256: state.data.operation_hmac_sha256,
      intent_sha256: state.data.intent_sha256,
      authority_etag: state.etag,
    };
  },
  afterSubjectMutation: async () => {
    const state = await heartbeatStores.control.getWithMetadata(
      'first-party-retention/generation-fence/state-v1');
    assert.equal(state.data.status, 'FROZEN');
    assert.ok(Date.parse(state.data.stale_at) > Date.parse(oldStaleAt));
    await assert.rejects(assertRetentionGenerationFenceAuthority(
      heartbeatStores.control, oldFrozenAuthority, env,
    ), /FENCE_AUTHORITY_LOST/);
    heartbeatAdvanced = true;
  },
});
assert.equal(heartbeatAdvanced, true);
assert.ok(heartbeatTick * 90_000 > 2 * 60_000,
  'The adversarial subject must span beyond the original two-minute stale interval.');
assert.equal((await heartbeatStores.abuse.getWithMetadata(heartbeatKey)).data.schema,
  FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA);

// The destructive fence is the provider's exact-etag CAS. A source refreshed
// between the strong read and mutation must survive byte-for-byte.
const tombstoneRaceStores = freshStores();
const raceKey = `challenge-replay/${'0'.repeat(64)}`;
const expiredReplay = {
  schema: 'arc-intake-turnstile-replay-v1', request_hmac_sha256: '1'.repeat(64),
  challenge_at: old(1), consumed_at: old(2), expires_at: old(3),
};
const refreshedReplay = {
  ...expiredReplay, expires_at: new Date(now.getTime() + 60 * 60_000).toISOString(),
};
await tombstoneRaceStores.abuse.setJSON(raceKey, expiredReplay);
tombstoneRaceStores.abuse.raceNextOnlyIfMatch(raceKey, refreshedReplay);
const tombstoneRaceResult = await runFirstPartyRetentionSweepCycle(env, tombstoneRaceStores, {
  clock: () => new Date(now), limit: 500, uuid: () => '14141414-1414-4414-8414-141414141414',
});
assert.notEqual(tombstoneRaceResult.state, 'COMPLETE');
assert.deepEqual((await tombstoneRaceStores.abuse.getWithMetadata(raceKey)).data, refreshedReplay,
  'A concurrent refresh must win the exact-etag tombstone fence.');
assert.ok([...tombstoneRaceStores.control.values.keys()].some((key) =>
  key.startsWith('first-party-retention/quarantine/intake_abuse/')),
'A lost tombstone CAS must preserve signed PII-free quarantine evidence.');
assert.equal((await tombstoneRaceStores.control.getWithMetadata(
  'first-party-retention/generation-fence/state-v1')).data.status, 'FROZEN',
'An impossible ungated source drift must not reopen the retention generation.');
assert.equal(tombstoneRaceStores.abuse.deleteCalls, 0);

// A terminal unpaid Checkout candidate cannot authorize deletion after the
// exact source record is refreshed to an open/paid state between phases.
const reopenedCheckoutStores = freshStores();
await reopenedCheckoutStores.review.setJSON(`review-checkout-binding/${checkoutId}`, checkout);
await runThroughPhase(reopenedCheckoutStores, 'checkout-candidate');
const { record_hmac_sha256: ignoredCheckoutSignature, ...checkoutUnsigned } = checkout;
const reopenedPaidCheckout = signSource({
  ...checkoutUnsigned, record_revision: checkout.record_revision + 1, state: 'OPEN',
  fulfillment_halted: false, provider_payment_status: 'paid', expired_at: null, suppressed_at: null,
}, env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET,
'arc-review-checkout-revocable-binding-signature-v1');
await reopenedCheckoutStores.review.setJSON(`review-checkout-binding/${checkoutId}`, reopenedPaidCheckout);
await finishSweep(reopenedCheckoutStores);
assert.deepEqual((await reopenedCheckoutStores.review.getWithMetadata(
  `review-checkout-binding/${checkoutId}`)).data, reopenedPaidCheckout,
'A refreshed paid Checkout record must survive a stale candidate marker.');
assert.ok([...reopenedCheckoutStores.control.values.keys()].some((key) =>
  key.startsWith('first-party-retention/quarantine/checkout/')),
'The stale Checkout candidate must leave signed quarantine evidence.');

// A Checkout subject manifest exhausts every provider page before freezing;
// more than one API page of bound alerts cannot be orphaned behind its primary.
const paginatedCheckoutStores = freshStores();
await paginatedCheckoutStores.review.setJSON(`review-checkout-binding/${checkoutId}`, checkout);
const paginatedCheckoutAlertKeys = [];
for (let index = 0; index < 501; index += 1) {
  const identity = index.toString(16).padStart(64, '0');
  const key = `review-checkout-revocation-alert/${identity}`;
  const alert = signSource({
    schema: 'arc-review-checkout-revocation-alert-v1',
    alert_hmac_sha256: identity, binding_hmac_sha256: checkoutId, detected_at: old(70),
  }, env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET,
  'arc-review-checkout-revocation-alert-signature-v1');
  await paginatedCheckoutStores.review.setJSON(key, alert);
  paginatedCheckoutAlertKeys.push(key);
}
const paginatedCheckoutCompletion = await finishSweep(paginatedCheckoutStores);
assert.equal((await paginatedCheckoutStores.review.getWithMetadata(
  paginatedCheckoutAlertKeys[0])).data.schema, FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA);
assert.equal((await paginatedCheckoutStores.review.getWithMetadata(
  paginatedCheckoutAlertKeys.at(-1))).data.schema, FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA);
assertTombstone(paginatedCheckoutStores.review, `review-checkout-binding/${checkoutId}`,
  checkout, 'checkout', paginatedCheckoutCompletion.receipt);
const paginatedCheckoutManifest = [...paginatedCheckoutStores.control.values.values()]
  .map((entry) => entry.data).find((value) =>
    value?.schema === 'arc-first-party-retention-subject-manifest-v1' &&
    value.family === 'checkout' && value.entries.some((item) => item.role === 'PRIMARY'));
assert.equal(paginatedCheckoutManifest.entries.length, 502,
  'All 501 paginated children and the primary must be frozen as one subject.');

// A legal hold added after review candidate marking must stop outbox,
// recipient-control, and primary deletion using the authoritative current hold.
const lateReviewHoldStores = freshStores();
await lateReviewHoldStores.review.setJSON(`review-invites/${inviteId}`, review);
await lateReviewHoldStores.review.setJSON(`review-email-outbox/${outboxId}`, outbox);
await lateReviewHoldStores.review.setJSON(`review-email-recipient-control/${recipientControlId}`, recipientControl);
await runThroughPhase(lateReviewHoldStores, 'review-candidate');
const lateReviewHold = buildFirstPartyLegalHoldRecord({
  family: 'review', subject_hmac_sha256: inviteId, reason_code: 'LEGAL',
  issued_at: new Date(now.getTime() - 30_000).toISOString(), expires_at: null,
}, env);
await lateReviewHoldStores.control.setJSON(firstPartyLegalHoldKey('review', inviteId), lateReviewHold);
await finishSweep(lateReviewHoldStores);
for (const key of [`review-invites/${inviteId}`, `review-email-outbox/${outboxId}`,
  `review-email-recipient-control/${recipientControlId}`]) {
  assert.equal(lateReviewHoldStores.review.values.has(key), true,
    'A newly held review must preserve every remaining cascade record.');
}

// A source that vanishes after candidate marking is not equivalent to a
// successful tombstone. It creates durable signed anomaly evidence and the
// sweep cannot issue a completion receipt.
const missingSourceStores = freshStores();
await missingSourceStores.review.setJSON(`review-invites/${inviteId}`, review);
await missingSourceStores.review.setJSON(`review-email-outbox/${outboxId}`, outbox);
await runThroughPhase(missingSourceStores, 'review-candidate');
missingSourceStores.review.values.delete(`review-invites/${inviteId}`);
let missingSourceResult = null;
for (let cycle = 0; cycle < firstPartyRetentionContract.phases.length * 3; cycle += 1) {
  missingSourceResult = await runFirstPartyRetentionSweepCycle(env, missingSourceStores, {
    clock: () => new Date(now), limit: 500, uuid: () => '55555555-5555-4555-8555-555555555555',
  });
}
assert.notEqual(missingSourceResult?.state, 'COMPLETE',
  'A marked source missing without an exact tombstone must block completion.');
assert.ok([...missingSourceStores.control.values.keys()].some((key) =>
  key.startsWith('first-party-retention/missing-source/')),
'A missing marked source must persist signed anomaly evidence.');
assert.ok([...missingSourceStores.control.values.keys()].some((key) =>
  key.startsWith('first-party-retention/generation-fence/missing-source/')),
'A missing marked source must also persist signed global-gate anomaly evidence.');
assert.deepEqual((await missingSourceStores.review.getWithMetadata(
  `review-email-outbox/${outboxId}`)).data, outbox,
'A child must survive when its marked primary disappears without a tombstone.');

// Complaint/bounce suppressions are durable safety controls. Even a fresh
// suppression tied only to an otherwise eligible old review is preserved.
const suppressionStores = freshStores();
const suppressionRecipient = '0'.repeat(64);
const suppressionInviteId = '1'.repeat(64);
const suppressionInvite = signSource({
  schema: 'arc-preview-review-invite-v1', version: 1, state: 'OPEN',
  invite_hmac_sha256: suppressionInviteId, recipient_email_sha256: suppressionRecipient,
  created_at: old(1), expires_at: old(60), decision: null,
  prior_invite_hmac_sha256: null, successor_invite_hmac_sha256: null,
}, env.ARC_REVIEW_RECORD_HMAC_SECRET, 'arc-preview-review-record-signature-v1');
await suppressionStores.review.setJSON(`review-invites/${suppressionInviteId}`, suppressionInvite);
const suppressedAt = new Date(now.getTime() - 60_000).toISOString();
const suppressionControlId = hmac(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
  `arc-preview-review-email-recipient-control-id-v1\n${suppressionRecipient}`);
const suppressionControl = signSource({
  schema: 'arc-preview-review-email-recipient-control-v1', version: 1, record_revision: 2,
  state: 'SUPPRESSED', recipient_control_hmac_sha256: suppressionControlId,
  recipient_email_sha256: suppressionRecipient, authority_operation_hmac_sha256: null,
  authority_expires_at: null, suppression_receipt_sha256: '2'.repeat(64),
  suppression_status: 'complained', suppressed_at: suppressedAt,
  source_invite_hmac_sha256: suppressionInviteId, source_outbox_hmac_sha256: '3'.repeat(64),
}, env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
'arc-preview-review-email-recipient-control-signature-v1');
await suppressionStores.review.setJSON(
  `review-email-recipient-control/${suppressionControlId}`, suppressionControl);
const recipientSuppressionId = hmac(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
  `arc-preview-review-email-recipient-suppression-id-v1\n${suppressionRecipient}`);
const recipientSuppression = signSource({
  schema: 'arc-preview-review-email-recipient-suppression-v1', version: 1, record_revision: 1,
  recipient_suppression_hmac_sha256: recipientSuppressionId,
  recipient_email_sha256: suppressionRecipient, suppression_receipt_sha256: '2'.repeat(64),
  suppression_status: 'complained', suppressed_at: suppressedAt,
  source_invite_hmac_sha256: suppressionInviteId, source_outbox_hmac_sha256: '3'.repeat(64),
}, env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
'arc-preview-review-email-recipient-suppression-signature-v1');
await suppressionStores.review.setJSON(
  `review-email-recipient-suppression/${recipientSuppressionId}`, recipientSuppression);
await finishSweep(suppressionStores);
assert.deepEqual((await suppressionStores.review.getWithMetadata(
  `review-email-recipient-control/${suppressionControlId}`)).data, suppressionControl);
assert.deepEqual((await suppressionStores.review.getWithMetadata(
  `review-email-recipient-suppression/${recipientSuppressionId}`)).data, recipientSuppression,
'Fresh suppressions must be preserved indefinitely so retention cannot reopen email.');

// Renewal retention must delegate to the production validator. Only an exact
// READY row at its derived key may cascade; every other signed lookalike is
// retained with signed quarantine evidence.
const renewalStores = freshStores();
const renewalCases = [
  { name: 'ready', replaced: '1'.repeat(64), replacement: '2'.repeat(64) },
  { name: 'planned', replaced: '3'.repeat(64), replacement: '4'.repeat(64) },
  { name: 'wrong-key', replaced: '5'.repeat(64), replacement: '6'.repeat(64) },
  { name: 'extra-field', replaced: '7'.repeat(64), replacement: '8'.repeat(64) },
  { name: 'misbound', replaced: '9'.repeat(64), replacement: 'a'.repeat(64) },
  { name: 'wrong-secret', replaced: 'b'.repeat(64), replacement: 'c'.repeat(64) },
];
for (const item of renewalCases) {
  for (const inviteId of [item.replaced, item.replacement]) {
    const invite = signSource({
      schema: 'arc-preview-review-invite-v1', version: 1, state: 'OPEN',
      invite_hmac_sha256: inviteId, recipient_email_sha256: '9'.repeat(64),
      created_at: old(1), expires_at: old(60), decision: null,
      prior_invite_hmac_sha256: null, successor_invite_hmac_sha256: null,
    }, env.ARC_REVIEW_RECORD_HMAC_SECRET, 'arc-preview-review-record-signature-v1');
    await renewalStores.review.setJSON(`review-invites/${inviteId}`, invite);
  }
  let record;
  if (item.name === 'planned') record = reviewRenewal(item.replaced, item.replacement, 'PLANNED');
  else if (item.name === 'extra-field') record = reviewRenewal(
    item.replaced, item.replacement, 'READY', { unexpected_field: true });
  else if (item.name === 'misbound') record = reviewRenewal(
    item.replaced, item.replacement, 'READY', { replacement_outbox_hmac_sha256: 'd'.repeat(64) });
  else if (item.name === 'wrong-secret') record = reviewRenewal(
    item.replaced, item.replacement, 'READY', {}, 'wrong-renewal-secret-unique-0123456789abcdef');
  else record = reviewRenewal(item.replaced, item.replacement, 'READY');
  const derivedKey = `review-email-renewal/${record.renewal_hmac_sha256}`;
  item.key = item.name === 'wrong-key' ? `review-email-renewal/${'f'.repeat(64)}` : derivedKey;
  item.record = record;
  await renewalStores.review.setJSON(item.key, record);
}
const renewalCompletion = await finishSweep(renewalStores);
assert.equal(renewalCompletion.state, 'COMPLETE');
const exactRenewal = renewalCases.find((item) => item.name === 'ready');
assertTombstone(renewalStores.review, exactRenewal.key, exactRenewal.record,
  'review', renewalCompletion.receipt);
for (const item of renewalCases.filter((candidate) => candidate.name !== 'ready')) {
  assert.deepEqual((await renewalStores.review.getWithMetadata(item.key)).data, item.record,
    `${item.name} renewal must survive retention.`);
}
assert.ok([...renewalStores.control.values.keys()].filter((key) =>
  key.startsWith('first-party-retention/quarantine/review/')).length >= 5,
'Every non-authoritative renewal form must create signed quarantine evidence.');

// A paid release that expires after handoff candidate marking cannot be reused
// by child or primary deletion.
const expiredReleaseStores = freshStores();
await expiredReleaseStores.handoff.setJSON(`handoffs/${handoff.handoff_id}`, handoff);
await expiredReleaseStores.handoff.setJSON(primarySiteIndex.key, primarySiteIndex.value);
await expiredReleaseStores.control.setJSON(paidHandoffRetentionReleaseKey(handoff.handoff_id), release);
await runThroughPhase(expiredReleaseStores, 'handoff-candidate');
const expiredRelease = buildPaidHandoffRetentionRelease({
  handoff_id: handoff.handoff_id, source_record_sha256: sha256Hex(canonicalJson(handoff)),
  provider_evidence_sha256: '1'.repeat(64), adult_approval_hmac_sha256: '2'.repeat(64),
  legal_hold: false, netlify_transfer_verified: true, payment_retention_complete: true,
  tax_retention_complete: true, dispute_refund_retention_complete: true,
  issued_at: new Date(now.getTime() - 2 * 60 * 60_000).toISOString(),
  expires_at: new Date(now.getTime() - 60 * 60_000).toISOString(),
}, env);
await expiredReleaseStores.control.setJSON(paidHandoffRetentionReleaseKey(handoff.handoff_id), expiredRelease);
await finishSweep(expiredReleaseStores);
assert.equal(expiredReleaseStores.handoff.values.has(`handoffs/${handoff.handoff_id}`), true);
assert.equal(expiredReleaseStores.handoff.values.has(primarySiteIndex.key), true,
  'A child must survive when the exact paid release is no longer current.');

// A live child owned by another handoff must not globally block an otherwise
// complete subject cascade.
const scopedHandoffStores = freshStores();
await scopedHandoffStores.handoff.setJSON(`handoffs/${handoff.handoff_id}`, handoff);
await scopedHandoffStores.handoff.setJSON(primarySiteIndex.key, primarySiteIndex.value);
await scopedHandoffStores.control.setJSON(paidHandoffRetentionReleaseKey(handoff.handoff_id), release);
const otherHandoffId = 'f'.repeat(64);
const otherSiteKey = `site-index/${sha256Hex('other-live-netlify-site')}`;
const otherSiteIndex = {
  schema: 'arc2-site-index-v1', handoff_id: otherHandoffId,
  netlify_site_id: 'other-live-netlify-site',
  netlify_session_id: '22222222-2222-4222-8222-222222222222',
};
await scopedHandoffStores.handoff.setJSON(otherSiteKey, otherSiteIndex);
for (let index = 0; index < 501; index += 1) {
  const indexedHandoffId = sha256Hex(`other-live-handoff-${index}`);
  const indexedSiteId = `other-live-netlify-site-${index}`;
  await scopedHandoffStores.handoff.setJSON(`site-index/${sha256Hex(indexedSiteId)}`, {
    schema: 'arc2-site-index-v1', handoff_id: indexedHandoffId,
    netlify_site_id: indexedSiteId,
    netlify_session_id: `33333333-3333-4333-8333-${String(index).padStart(12, '0')}`,
  });
}
const scopedCompletion = await finishSweep(scopedHandoffStores);
assertTombstone(scopedHandoffStores.handoff, `handoffs/${handoff.handoff_id}`,
  handoff, 'handoff', scopedCompletion.receipt);
assert.deepEqual((await scopedHandoffStores.handoff.getWithMetadata(otherSiteKey)).data, otherSiteIndex,
'Another handoff\'s live child must survive without blocking the eligible handoff.');

// A checkout-review alert with no direct handoff_id is owned through its
// event/receipt Session binding. It blocks only that handoff, not every paid
// delivery sharing the global alert store.
const alertScopedStores = freshStores();
const alertUnrelatedHandoff = {
  ...deliveredHandoff(), handoff_id: 'c'.repeat(64),
  netlify_site_id: 'alert-unrelated-site',
  netlify_session_id: '44444444-4444-4444-8444-444444444444',
};
const alertUnrelatedSiteIndex = siteIndex(alertUnrelatedHandoff);
for (const [record, index] of [[handoff, primarySiteIndex],
  [alertUnrelatedHandoff, alertUnrelatedSiteIndex]]) {
  await alertScopedStores.handoff.setJSON(`handoffs/${record.handoff_id}`, record);
  await alertScopedStores.handoff.setJSON(index.key, index.value);
  await alertScopedStores.control.setJSON(paidHandoffRetentionReleaseKey(record.handoff_id),
    buildPaidHandoffRetentionRelease({
      handoff_id: record.handoff_id, source_record_sha256: sha256Hex(canonicalJson(record)),
      provider_evidence_sha256: '1'.repeat(64), adult_approval_hmac_sha256: '2'.repeat(64),
      legal_hold: false, netlify_transfer_verified: true, payment_retention_complete: true,
      tax_retention_complete: true, dispute_refund_retention_complete: true,
      issued_at: new Date(now.getTime() - 60_000).toISOString(),
      expires_at: new Date(now.getTime() + 60 * 60_000).toISOString(),
    }, env));
}
const checkoutAlertEventId = 'a'.repeat(64);
const checkoutAlertSessionId = '7'.repeat(64);
await alertScopedStores.handoff.setJSON(`stripe-checkout-event/${checkoutAlertEventId}`, {
  checkout_session_id_hmac_sha256: checkoutAlertSessionId,
});
await alertScopedStores.handoff.setJSON(`stripe-checkout-receipt/${checkoutAlertEventId}`, {
  checkout_session_id_hmac_sha256: checkoutAlertSessionId,
});
await alertScopedStores.handoff.setJSON(`stripe-checkout-handoff/${'b'.repeat(64)}`, {
  handoff_id: handoff.handoff_id,
  checkout_session_id_hmac_sha256: checkoutAlertSessionId,
});
await alertScopedStores.alerts.setJSON(`alerts/stripe-checkout-review/${checkoutAlertEventId}`, {
  schema: 'arc-operational-alert-v1', status: 'OPEN', category: 'stripe-checkout-review',
  severity: 'critical', handoff_id: null, subject_hmac_sha256: checkoutAlertEventId,
  detected_at: old(41), delivery_status: 'PENDING', contains_customer_data: false,
});
const alertScopedCompletion = await finishSweep(alertScopedStores);
assert.deepEqual((await alertScopedStores.handoff.getWithMetadata(
  `handoffs/${handoff.handoff_id}`)).data, handoff,
'The indirectly bound checkout alert must preserve its exact handoff.');
assertTombstone(alertScopedStores.handoff,
  `handoffs/${alertUnrelatedHandoff.handoff_id}`, alertUnrelatedHandoff,
  'handoff', alertScopedCompletion.receipt);
assertTombstone(alertScopedStores.handoff, alertUnrelatedSiteIndex.key,
  alertUnrelatedSiteIndex.value, 'handoff', alertScopedCompletion.receipt);

// Two eligible handoffs are independently frozen, planned, and finalized. A
// completed subject cannot authorize the other subject's children or primary.
const independentHandoffStores = freshStores();
const secondHandoff = {
  ...deliveredHandoff(), handoff_id: 'c'.repeat(64),
  netlify_site_id: 'second-site-identifier',
  netlify_session_id: '22222222-2222-4222-8222-222222222222',
};
assert.doesNotThrow(() => validateExpectedBindings(secondHandoff));
const secondSiteIndex = siteIndex(secondHandoff);
for (const [record, index] of [[handoff, primarySiteIndex], [secondHandoff, secondSiteIndex]]) {
  await independentHandoffStores.handoff.setJSON(`handoffs/${record.handoff_id}`, record);
  await independentHandoffStores.handoff.setJSON(index.key, index.value);
  await independentHandoffStores.control.setJSON(paidHandoffRetentionReleaseKey(record.handoff_id),
    buildPaidHandoffRetentionRelease({
      handoff_id: record.handoff_id, source_record_sha256: sha256Hex(canonicalJson(record)),
      provider_evidence_sha256: '1'.repeat(64), adult_approval_hmac_sha256: '2'.repeat(64),
      legal_hold: false, netlify_transfer_verified: true, payment_retention_complete: true,
      tax_retention_complete: true, dispute_refund_retention_complete: true,
      issued_at: new Date(now.getTime() - 60_000).toISOString(),
      expires_at: new Date(now.getTime() + 60 * 60_000).toISOString(),
    }, env));
}
const independentCompletion = await finishSweep(independentHandoffStores);
for (const [record, index] of [[handoff, primarySiteIndex], [secondHandoff, secondSiteIndex]]) {
  assertTombstone(independentHandoffStores.handoff, `handoffs/${record.handoff_id}`,
    record, 'handoff', independentCompletion.receipt);
  assertTombstone(independentHandoffStores.handoff, index.key,
    index.value, 'handoff', independentCompletion.receipt);
}
assert.equal([...independentHandoffStores.control.values.keys()].filter((key) =>
  key.includes('/generation-fence/finalize-receipts/')).length >= 2, true);

// A crash after a planned child tombstone resumes the exact signed manifest;
// it validates persisted child plans, applies the primary last, and reopens.
const crashResumeStores = freshStores();
await crashResumeStores.handoff.setJSON(`handoffs/${handoff.handoff_id}`, handoff);
await crashResumeStores.handoff.setJSON(primarySiteIndex.key, primarySiteIndex.value);
await crashResumeStores.control.setJSON(paidHandoffRetentionReleaseKey(handoff.handoff_id), release);
let reachedHandoffPrimary = false;
for (let cycle = 0; cycle < firstPartyRetentionContract.phases.length * 2; cycle += 1) {
  const progress = await runFirstPartyRetentionSweepCycle(env, crashResumeStores, {
    clock: () => new Date(now), limit: 500, uuid: () => '15151515-1515-4515-8515-151515151515',
  });
  if (progress.phase === 'handoff-primary') { reachedHandoffPrimary = true; break; }
}
assert.equal(reachedHandoffPrimary, true);
let crashed = false;
await assert.rejects(runFirstPartyRetentionSweepCycle(env, crashResumeStores, {
  clock: () => new Date(now), limit: 500, uuid: () => '15151515-1515-4515-8515-151515151515',
  afterSubjectMutation: async ({ key, role }) => {
    if (!crashed && role === 'CHILD' && key === primarySiteIndex.key) {
      crashed = true;
      throw new Error('simulated mid-FROZEN crash');
    }
  },
}), /simulated mid-FROZEN crash/);
assert.equal(crashed, true);
assert.equal((await crashResumeStores.handoff.getWithMetadata(primarySiteIndex.key)).data.schema,
  FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA);
assert.deepEqual((await crashResumeStores.handoff.getWithMetadata(
  `handoffs/${handoff.handoff_id}`)).data, handoff);
const resumeNow = new Date(now.getTime() + 3 * 60_000);
const recoveryAlerts = [];
let crashResumeCompletion;
for (let cycle = 0; cycle < firstPartyRetentionContract.phases.length * 2; cycle += 1) {
  crashResumeCompletion = await runFirstPartyRetentionSweepCycle(env, crashResumeStores, {
    clock: () => new Date(resumeNow), limit: 500,
    uuid: () => '15151515-1515-4515-8515-151515151515',
    emitCriticalAlert: async (alert) => recoveryAlerts.push(alert),
  });
  if (crashResumeCompletion.state === 'COMPLETE') break;
}
assert.equal(crashResumeCompletion.state, 'COMPLETE');
assert.equal(recoveryAlerts.length, 1,
  'A genuinely stale exact manifest resume must emit one persisted critical alert.');
assertTombstone(crashResumeStores.handoff, `handoffs/${handoff.handoff_id}`,
  handoff, 'handoff', crashResumeCompletion.receipt);
assert.equal(crashResumeCompletion.receipt.counts.handoff.deleted, 2,
  'Resumed child and primary mutations must be merged into the durable sweep counts.');

// Review children and primary share one manifest and one FROZEN interval. A
// crash after the first child resumes that exact set, then counts every
// finalized mutation once when the primary cursor is replayed.
const reviewCrashStores = freshStores();
for (const [key, value] of [
  [`review-invites/${inviteId}`, review],
  [`review-email-outbox/${outboxId}`, outbox],
  [`review-email-provider-event/${reviewProviderEventId}`, reviewProviderEvent],
  [`review-email-provider-message/${reviewProviderMessageId}`, reviewProviderMessage],
  ['review-email-pending/index-v1', pending],
]) await reviewCrashStores.review.setJSON(key, value);
let reachedReviewPrimary = false;
for (let cycle = 0; cycle < firstPartyRetentionContract.phases.length * 2; cycle += 1) {
  const progress = await runFirstPartyRetentionSweepCycle(env, reviewCrashStores, {
    clock: () => new Date(now), limit: 500,
    uuid: () => '17171717-1717-4717-8717-171717171717',
  });
  if (progress.phase === 'review-primary') { reachedReviewPrimary = true; break; }
}
assert.equal(reachedReviewPrimary, true);
let reviewCrashed = false;
await assert.rejects(runFirstPartyRetentionSweepCycle(env, reviewCrashStores, {
  clock: () => new Date(now), limit: 500,
  uuid: () => '17171717-1717-4717-8717-171717171717',
  afterSubjectMutation: async ({ key, role }) => {
    if (!reviewCrashed && role === 'CHILD' && key === `review-email-outbox/${outboxId}`) {
      reviewCrashed = true;
      throw new Error('simulated atomic review crash');
    }
  },
}), /simulated atomic review crash/);
assert.equal(reviewCrashed, true);
assert.equal((await reviewCrashStores.review.getWithMetadata(
  `review-email-outbox/${outboxId}`)).data.schema, FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA);
assert.deepEqual((await reviewCrashStores.review.getWithMetadata(
  `review-invites/${inviteId}`)).data, review);
const reviewRecoveryAlerts = [];
let reviewCrashCompletion;
for (let cycle = 0; cycle < firstPartyRetentionContract.phases.length * 2; cycle += 1) {
  reviewCrashCompletion = await runFirstPartyRetentionSweepCycle(env, reviewCrashStores, {
    clock: () => new Date(resumeNow), limit: 500,
    uuid: () => '17171717-1717-4717-8717-171717171717',
    emitCriticalAlert: async (alert) => reviewRecoveryAlerts.push(alert),
  });
  if (reviewCrashCompletion.state === 'COMPLETE') break;
}
assert.equal(reviewCrashCompletion.state, 'COMPLETE');
assert.equal(reviewRecoveryAlerts.length, 1);
assert.equal(reviewCrashCompletion.receipt.counts.review.deleted, 5,
  'The resumed atomic review manifest must contribute all four children and its primary once.');
assertTombstone(reviewCrashStores.review, `review-invites/${inviteId}`,
  review, 'review', reviewCrashCompletion.receipt);

// A stale FROZEN operation whose persisted manifest source disappeared stays
// fail-closed and emits the durable critical recovery alert through the
// production adapter instead of returning a silent permanent BLOCKED state.
const missingFrozenStores = freshStores();
const missingFrozenKey = `challenge-replay/${'9'.repeat(64)}`;
await missingFrozenStores.abuse.setJSON(missingFrozenKey, {
  schema: 'arc-intake-turnstile-replay-v1', request_hmac_sha256: 'a'.repeat(64),
  challenge_at: old(1), consumed_at: old(2), expires_at: old(3),
});
await runFirstPartyRetentionSweepCycle(env, missingFrozenStores, {
  clock: () => new Date(now), limit: 500,
  uuid: () => '18181818-1818-4818-8818-181818181818',
  afterSubjectFreeze: async () => { throw new Error('simulated pre-mutation crash'); },
});
assert.equal((await missingFrozenStores.control.getWithMetadata(
  'first-party-retention/generation-fence/state-v1')).data.status, 'FROZEN');
missingFrozenStores.abuse.values.delete(missingFrozenKey);
const missingFrozenAlerts = [];
const missingFrozenResult = await runFirstPartyRetentionSweepCycle(env, missingFrozenStores, {
  clock: () => new Date(resumeNow), limit: 500,
  uuid: () => '18181818-1818-4818-8818-181818181818',
  emitCriticalAlert: async (alert) => missingFrozenAlerts.push(alert),
});
assert.equal(missingFrozenResult.state, 'BLOCKED');
assert.equal(missingFrozenResult.critical_alert, true);
assert.equal(missingFrozenAlerts.length, 1,
  'The stale missing-source freeze must synchronously surface its persisted critical alert.');
assert.equal([...missingFrozenStores.control.values.keys()].some((key) =>
  key.includes('/generation-fence/critical-alerts/')), true);

// Production duplicate-paid records use winning_handoff_id. An unresolved
// duplicate inserted after candidate marking must block both the child cascade
// and handoff primary instead of becoming a dangling record.
const duplicatePaidStores = freshStores();
await duplicatePaidStores.handoff.setJSON(`handoffs/${handoff.handoff_id}`, handoff);
await duplicatePaidStores.handoff.setJSON(primarySiteIndex.key, primarySiteIndex.value);
await duplicatePaidStores.control.setJSON(paidHandoffRetentionReleaseKey(handoff.handoff_id), release);
await runThroughPhase(duplicatePaidStores, 'handoff-candidate');
const duplicateReviewUnsigned = {
  schema: 'arc2-duplicate-payment-review-v1',
  status: 'CRITICAL_DUPLICATE_PAID_SESSION_REVIEW_REQUIRED', automatic_refund_requested: false,
  checkout_reference_sha256: '3'.repeat(64), winning_checkout_session_id_hmac_sha256: '4'.repeat(64),
  duplicate_checkout_session_id_hmac_sha256: '5'.repeat(64),
  winning_payment_link_id_hmac_sha256: '6'.repeat(64), duplicate_payment_link_id_hmac_sha256: '7'.repeat(64),
  winning_handoff_id: handoff.handoff_id, winning_payment_evidence_sha256: handoff.payment_evidence_sha256,
  winning_artifact_evidence_sha256: handoff.artifact_evidence_sha256,
  duplicate_payment_evidence_sha256: '8'.repeat(64),
};
const duplicateReview = {
  ...duplicateReviewUnsigned,
  review_hmac_sha256: hmac(env.ARC_HANDOFF_STATE_SECRET,
    `arc2-duplicate-payment-review-signature-v1\n${canonicalJson(duplicateReviewUnsigned)}`),
};
const duplicateReviewKey = `duplicate-payment-review/${hmac(env.ARC_HANDOFF_STATE_SECRET,
  `duplicate-payment-review-key-v1\n${duplicateReview.checkout_reference_sha256}\n${duplicateReview.duplicate_checkout_session_id_hmac_sha256}`)}`;
await duplicatePaidStores.handoff.setJSON(duplicateReviewKey, duplicateReview);
await finishSweep(duplicatePaidStores);
assert.equal(duplicatePaidStores.handoff.values.has(duplicateReviewKey), true);
assert.equal(duplicatePaidStores.handoff.values.has(`handoffs/${handoff.handoff_id}`), true);
assert.equal(duplicatePaidStores.handoff.values.has(primarySiteIndex.key), true,
  'An unresolved duplicate-paid review must preserve the winning handoff cascade.');
assert.ok([...duplicatePaidStores.control.values.keys()].some((key) =>
  key.startsWith('first-party-retention/quarantine/handoff/')),
'The winning_handoff_id duplicate must produce signed PII-free quarantine evidence.');

for (const scenario of [stores, reopenedCheckoutStores, lateReviewHoldStores, missingSourceStores,
  paginatedCheckoutStores, suppressionStores, renewalStores, heartbeatStores,
  expiredReleaseStores, scopedHandoffStores, alertScopedStores,
  independentHandoffStores, crashResumeStores, reviewCrashStores, missingFrozenStores,
  duplicatePaidStores]) {
  for (const store of Object.values(scenario)) assert.equal(store.deleteCalls, 0,
    'Retention must never call a provider\'s unconditional delete primitive.');
}

console.log('ARC first-party abuse, review, Checkout, and paid-handoff retention cascade contract passed.');
