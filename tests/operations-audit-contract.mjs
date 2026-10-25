import assert from 'node:assert/strict';
import {
  canonicalJson,
  createInitialRecord,
  hmacHex,
  sha256Hex,
  validateExpectedBindings,
} from '../netlify/lib/arc2-handoff-core.mjs';
import { BUDGET_CONFIRMATION, TERMS_CONFIRMATION, normalizeIntakeForm } from '../netlify/lib/intake-submission-core.mjs';
import {
  operationsAuditConfiguration,
  runOperationsAudit,
} from '../netlify/lib/operations-audit-core.mjs';
import { RETENTION_INTENT_SCHEMA, RETENTION_POLICY_VERSION } from '../netlify/lib/retention-control-core.mjs';
import {
  STRIPE_PAYMENT_INTENT_INDEX_SCHEMA,
  STRIPE_PENDING_PAYMENT_SCHEMA,
  STRIPE_REVERSAL_BINDING_SCHEMA,
  STRIPE_REVERSAL_EVENT_SCHEMA,
  STRIPE_REVERSAL_SCHEMA,
} from '../netlify/lib/stripe-reversal-core.mjs';
import auditHandler, { config as auditConfig } from '../netlify/functions/operations-audit.mjs';

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `e-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
  list({ prefix = '', paginate = false } = {}) {
    assert.equal(paginate, true, 'Operations audit must manually paginate every prefix.');
    const blobs = [...this.values.keys()].filter((key) => key.startsWith(prefix)).sort().map((key) => ({ key }));
    return (async function* () {
      yield { blobs: blobs.slice(0, 1) };
      yield { blobs: blobs.slice(1) };
    }());
  }
}

class OverflowStore extends FakeStore {
  list() {
    return (async function* () {
      yield { blobs: Array.from({ length: 5_001 }, (_, index) => ({ key: `handoffs/${String(index).padStart(64, '0')}` })) };
    }());
  }
}

class IncrementalBacklogStore extends FakeStore {
  constructor(values) { super(); this.backlog = values; }
  list({ prefix = '', paginate = false } = {}) {
    assert.equal(paginate, true);
    const blobs = this.backlog.filter((key) => key.startsWith(prefix)).sort().map((key) => ({ key }));
    return (async function* () {
      for (let offset = 0; offset < blobs.length; offset += 25) yield { blobs: blobs.slice(offset, offset + 25) };
      if (blobs.length === 0) yield { blobs: [] };
    }());
  }
}

class ProviderSequenceStore extends FakeStore {
  constructor(layouts) {
    super();
    this.layouts = layouts;
    this.catchAllCalls = 0;
  }
  list({ prefix = '', paginate = false } = {}) {
    assert.equal(paginate, true);
    if (prefix !== 'submissions/') {
      return (async function* () { yield { blobs: [] }; }());
    }
    const layout = this.layouts[Math.min(this.catchAllCalls, this.layouts.length - 1)];
    this.catchAllCalls += 1;
    return (async function* () {
      for (const page of layout) yield { blobs: page.map((key) => ({ key })) };
    }());
  }
}

const now = new Date('2026-08-13T12:00:00.000Z');
const old = new Date(now.getTime() - 2 * 60 * 60_000);
const handoffId = 'a'.repeat(64);
const env = {
  ARC_OPERATIONS_AUDIT_ENABLED: 'true',
  ARC_OPERATIONS_AUDIT_SECRET: 'operations-audit-secret-unique-0123456789abcdef',
  ARC_OPERATIONS_ALERT_HMAC_SECRET: 'operations-alert-hmac-secret-unique-0123456789abcdef',
  ARC_EMAIL_CLAIM_BINDING_SECRET: 'email-claim-binding-secret-unique-0123456789abcdef',
  ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET:
    'first-party-retention-fence-secret-unique-0123456789abcdef',
  ARC_HANDOFF_STATE_SECRET: 'handoff-state-secret-unique-0123456789abcdef',
  NETLIFY_TEAM_ACCOUNT_ID: 'team-account-123',
};
assert.equal(operationsAuditConfiguration(env).enabled, true);
assert.equal(operationsAuditConfiguration({}).enabled, false);
assert.equal(operationsAuditConfiguration({ ...env, ARC_HANDOFF_STATE_SECRET: '' }).enabled, false,
  'Duplicate-payment review validation requires the handoff-state HMAC secret.');
assert.equal(operationsAuditConfiguration({ ...env, ARC_HANDOFF_TRIGGER_SECRET: env.ARC_OPERATIONS_AUDIT_SECRET }).enabled, false,
  'Audit authorization must not reuse an existing handoff secret.');
for (const credentialName of [
  'ARC_OPERATIONS_AUDIT_SECRET',
  'ARC_OPERATIONS_ALERT_HMAC_SECRET',
  'ARC_EMAIL_CLAIM_BINDING_SECRET',
  'ARC_HANDOFF_STATE_SECRET',
]) {
  assert.equal(operationsAuditConfiguration({
    ...env,
    ARC_ROTATED_CREDENTIAL_V2: env[credentialName],
  }).enabled, false, `An arbitrary alias must not reuse ${credentialName}.`);
}

const fixture = {
  payment: { digest: '1'.repeat(64), value: {
    checkout_session_id: 'cs_test_operationsAudit', claim_recipient_email_sha256: '2'.repeat(64), bundle_fingerprint: '3'.repeat(64),
  } },
  artifact: { digest: '4'.repeat(64), artifacts: [
    { path: '_headers', sha256: '5'.repeat(64), size: 10 },
    { path: 'about/index.html', sha256: '6'.repeat(64), size: 20 },
    { path: 'contact/index.html', sha256: '7'.repeat(64), size: 20 },
    { path: 'process/index.html', sha256: '8'.repeat(64), size: 20 },
    { path: 'services/index.html', sha256: '9'.repeat(64), size: 20 },
    { path: 'index.html', sha256: 'a'.repeat(64), size: 20 },
  ], value: {
    artifact_manifest_sha256: '7'.repeat(64), bundle_fingerprint: '3'.repeat(64),
    lead_route_mode: 'netlify_form',
    preview_folder: 'sample-roofing-a1b2c3d4', production_content_sha256: '8'.repeat(64),
  } },
  leadEmail: 'lead@example.test', leadEmailHash: sha256Hex('lead@example.test'),
  leadRouteRecipientHmacSha256: '9'.repeat(64), formName: 'sample-lead',
};
const record = createInitialRecord(fixture, env, `handoffs/${handoffId}`, old, {
  uuid: () => '11111111-1111-4111-8111-111111111111',
}).record;
const handoff = new FakeStore();
const retention = new FakeStore();
const alerts = new FakeStore();
const intake = new FakeStore();
await handoff.setJSON(`handoffs/${handoffId}`, record);
const checkoutHmac = 'd'.repeat(64);
const paymentIntentHmac = 'e'.repeat(64);
const stripeAccountHash = 'f'.repeat(64);
const reversalBinding = {
  schema: STRIPE_REVERSAL_BINDING_SCHEMA,
  handoff_id: handoffId,
  checkout_session_id_hmac_sha256: checkoutHmac,
  payment_intent_id_hmac_sha256: paymentIntentHmac,
  stripe_account_id_sha256: stripeAccountHash,
  livemode: false,
  payment_evidence_sha256: record.payment_evidence_sha256,
  binding_evidence_sha256: '0'.repeat(64),
};
await handoff.setJSON(`stripe-reversal-binding/handoff/${handoffId}`, reversalBinding);
await handoff.setJSON(`stripe-payment-intent/${paymentIntentHmac}`, {
  ...reversalBinding, schema: STRIPE_PAYMENT_INTENT_INDEX_SCHEMA,
});
const reversalEvent = {
  schema: STRIPE_REVERSAL_EVENT_SCHEMA,
  handoff_id: null,
  checkout_session_id_hmac_sha256: null,
  payment_intent_id_hmac_sha256: paymentIntentHmac,
  event_id_hmac_sha256: '1'.repeat(64),
  object_id_hmac_sha256: '3'.repeat(64),
  event_sha256: '2'.repeat(64),
  event_type: 'refund.created',
  event_status: 'pending',
  kind: 'refund',
  event_created_at: old.toISOString(),
  amount_minor_units: 500,
  currency: 'usd',
  livemode: false,
  stripe_account_id_sha256: stripeAccountHash,
};
await handoff.setJSON(`stripe-reversal-event/${reversalEvent.event_id_hmac_sha256}`, reversalEvent);
await handoff.setJSON(`stripe-reversal-pending/${paymentIntentHmac}/${reversalEvent.event_id_hmac_sha256}`, reversalEvent);
await handoff.setJSON(`stripe-reversal-pending-payment/${paymentIntentHmac}`, {
  schema: STRIPE_PENDING_PAYMENT_SCHEMA,
  payment_intent_id_hmac_sha256: paymentIntentHmac,
  stripe_account_id_sha256: stripeAccountHash,
  livemode: false,
  delivery_halted: true,
});
await handoff.setJSON(`stripe-reversal/handoff/${handoffId}`, {
  schema: STRIPE_REVERSAL_SCHEMA,
  handoff_id: handoffId,
  checkout_session_id_hmac_sha256: checkoutHmac,
  payment_intent_id_hmac_sha256: paymentIntentHmac,
  stripe_account_id_sha256: stripeAccountHash,
  livemode: false,
  delivery_halted: true,
  automatic_refund_requested: false,
  manual_review_required: true,
  severity: 'FUNDS_AT_RISK',
  refund_state: 'ATTEMPT_RECORDED',
  dispute_state: 'NONE',
  refund_observed: true,
  dispute_observed: false,
  first_event_created_at: old.toISOString(),
  latest_event_created_at: old.toISOString(),
  latest_event_type: 'refund.created',
  latest_event_status: 'pending',
  latest_event_id_hmac_sha256: '1'.repeat(64),
  latest_event_sha256: '2'.repeat(64),
  latest_object_id_hmac_sha256: '3'.repeat(64),
  latest_amount_minor_units: 500,
  currency: 'usd',
});
const targetHmac = 'b'.repeat(64);
const manifestHash = 'c'.repeat(64);
const intentPath = `delete-intents/${targetHmac}/${manifestHash}`;
const intent = {
  schema: RETENTION_INTENT_SCHEMA,
  run_id: '22222222-2222-4222-8222-222222222222',
  mode: 'apply',
  policy_version: RETENTION_POLICY_VERSION,
  manifest_sha256: manifestHash,
  target_set_sha256: '4'.repeat(64),
  dry_run_id: '33333333-3333-4333-8333-333333333333',
  dry_run_manifest_sha256: '5'.repeat(64),
  adult_approval_hmac_sha256: '6'.repeat(64),
  target_store: 'arc-intake-submissions',
  target_hmac_sha256: targetHmac,
  record_sha256: '7'.repeat(64),
  retention_class: 'unpaid-preview',
  last_interaction_at: '2024-07-01T00:00:00.000Z',
  delete_not_before: '2026-07-01T00:00:00.000Z',
  authorized_at: old.toISOString(),
};
await retention.setJSON(intentPath, intent);

const first = await runOperationsAudit(env, { handoff, retention, alerts, intake }, { clock: () => new Date(now) });
assert.equal(first.alert_conditions, 3);
assert.equal(first.alerts_created, 3);
assert.equal(first.alert_delivery_implemented, false);
assert.equal(first.categories['handoff-stuck'], 1);
assert.equal(first.categories['stripe-reversal-review'], 1);
assert.equal(first.categories['retention-delete-stuck'], 1);
assert.equal([...alerts.values.keys()].length, 3);
assert.equal(JSON.stringify([...alerts.values.values()]).includes('lead@example.test'), false);
const replay = await runOperationsAudit(env, { handoff, retention, alerts, intake }, { clock: () => new Date(now) });
assert.equal(replay.alerts_created, 0);
assert.equal(replay.alerts_replayed, 3);
assert.equal([...alerts.values.keys()].length, 3, 'Create-only alert conditions must deduplicate exact replays.');

await handoff.setJSON('handoffs/not-valid', { anything: true });
const integrity = await runOperationsAudit(env, { handoff, retention, alerts, intake }, { clock: () => new Date(now) });
assert.equal(integrity.categories['handoff-integrity'], 1);

await retention.setJSON(intentPath.replace('delete-intents/', 'delete-receipts/'), {
  schema: 'arc-retention-delete-receipt-v1', customer_data_stored: false,
});
const invalidReceipt = await runOperationsAudit(env, { handoff, retention, alerts, intake }, { clock: () => new Date(now) });
assert.equal(invalidReceipt.categories['retention-integrity'], 1, 'Malformed receipts must create a critical integrity condition.');
assert.equal(invalidReceipt.categories['retention-delete-stuck'], 1, 'Malformed receipts must not suppress a stuck delete intent.');

await handoff.setJSON(`invitation-ready-outbox/${'8'.repeat(64)}`, {
  schema: 'arc2-claim-invitation-ready-outbox-v1',
  status: 'READY',
  handoff_id: handoffId,
  recipient_email_sha256: record.customer_email_sha256,
  claim_token_hmac_sha256: '9'.repeat(64),
  expires_at: new Date(now.getTime() + 60 * 60_000).toISOString(),
});
const wrongStateInvitation = await runOperationsAudit(env, { handoff, retention, alerts, intake }, { clock: () => new Date(now) });
assert.equal(wrongStateInvitation.categories['claim-outbox-integrity'], 1,
  'A valid-looking invitation outbox in the wrong handoff state must fail closed.');

const invitationId = '6'.repeat(64);
const invitationBase = createInitialRecord(fixture, env, `handoffs/${invitationId}`, new Date('2026-08-13T09:00:00.000Z'), {
  uuid: () => '66666666-6666-4666-8666-666666666666',
}).record;
const invitationReadyAt = '2026-08-13T10:00:00.000Z';
const invitationExpiresAt = '2026-08-13T10:30:00.000Z';
const currentInvitationToken = '4'.repeat(64);
const invitationRecord = {
  ...invitationBase,
  state: 'INVITATION_READY', revision: 6, updated_at: invitationReadyAt,
  netlify_site_id: 'site-invitation-123', site_created_at: '2026-08-13T09:10:00.000Z',
  preclaim_deploy_attempted_at: '2026-08-13T09:20:00.000Z', preclaim_deploy_candidate_id: 'deploy-invitation-123',
  preclaim_deploy_id: 'deploy-invitation-123', email_hook_attempted_at: '2026-08-13T09:30:00.000Z',
  form_id: 'form-invitation-123', hook_id: 'hook-invitation-123', lead_route_receipt_sha256: '3'.repeat(64),
  claim_token_hmac_sha256: currentInvitationToken, claim_invitation_generation: 2,
  claim_token_expires_at: invitationExpiresAt, claim_invitation_ready_at: invitationReadyAt,
  lead_route_provider_message_id_sha256: '5'.repeat(64),
};
validateExpectedBindings(invitationRecord);
const invitationStore = new FakeStore();
await invitationStore.setJSON(`handoffs/${invitationId}`, invitationRecord);
const currentOutboxBinding = {
  version: 'arc2-claim-invitation-ready-outbox-v2', handoff_id: invitationId,
  recipient_email_sha256: invitationRecord.customer_email_sha256, claim_invitation_generation: 2,
  claim_token_hmac_sha256: currentInvitationToken, expires_at: invitationExpiresAt,
};
const currentOutboxDigest = hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET, canonicalJson(currentOutboxBinding));
const currentOutboxKey = `invitation-ready-outbox/${currentOutboxDigest}`;
await invitationStore.setJSON(currentOutboxKey, {
  schema: currentOutboxBinding.version, status: 'READY', handoff_id: invitationId,
  claim_invitation_generation: 2, recipient_email_sha256: invitationRecord.customer_email_sha256,
  claim_token_hmac_sha256: currentInvitationToken, expires_at: invitationExpiresAt,
});
const currentPointerBinding = {
  schema: 'arc2-claim-invitation-current-v1', handoff_id: invitationId, claim_invitation_generation: 2,
  claim_token_hmac_sha256: currentInvitationToken, expires_at: invitationExpiresAt,
  outbox_key_sha256: sha256Hex(currentOutboxKey),
};
await invitationStore.setJSON(`invitation-ready-current/${invitationId}`, {
  ...currentPointerBinding,
  binding_hmac_sha256: hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET,
    `arc2-claim-invitation-current-v1\n${canonicalJson(currentPointerBinding)}`),
});
const legacyBinding = {
  version: 'arc2-claim-invitation-ready-outbox-v1', handoff_id: invitationId,
  recipient_email_sha256: invitationRecord.customer_email_sha256,
  claim_token_hmac_sha256: '6'.repeat(64), expires_at: '2026-08-13T09:30:00.000Z',
};
const legacyKey = `invitation-ready-outbox/${hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET, canonicalJson(legacyBinding))}`;
await invitationStore.setJSON(legacyKey, {
  schema: legacyBinding.version, status: 'READY', handoff_id: invitationId,
  recipient_email_sha256: legacyBinding.recipient_email_sha256,
  claim_token_hmac_sha256: legacyBinding.claim_token_hmac_sha256, expires_at: legacyBinding.expires_at,
});
const validInvitationAudit = await runOperationsAudit(env, {
  handoff: invitationStore, retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date('2026-08-13T10:10:00.000Z') });
assert.equal(validInvitationAudit.categories['claim-outbox-integrity'], undefined,
  'A valid v2 current authority and immutable superseded v1 outbox must not raise integrity alerts.');
assert.equal(validInvitationAudit.categories['claim-invitation-migration'], undefined,
  'A fully migrated historical v1 outbox must be classified as non-sendable superseded history.');

const missingPointerStore = new FakeStore();
missingPointerStore.values = new Map([...invitationStore.values.entries()].filter(([key]) => !key.startsWith('invitation-ready-current/')));
const missingPointerAudit = await runOperationsAudit(env, {
  handoff: missingPointerStore, retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date('2026-08-13T10:10:00.000Z') });
assert.ok((missingPointerAudit.categories['claim-invitation-migration'] || 0) >= 1,
  'A valid-looking invitation outbox without current authority must require repair instead of authorizing send.');

const tamperedPointerStore = new FakeStore();
tamperedPointerStore.values = new Map([...invitationStore.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
const pointerKey = `invitation-ready-current/${invitationId}`;
const tamperedPointer = structuredClone(tamperedPointerStore.values.get(pointerKey).data);
tamperedPointer.claim_invitation_generation = 1;
await tamperedPointerStore.setJSON(pointerKey, tamperedPointer);
const tamperedPointerAudit = await runOperationsAudit(env, {
  handoff: tamperedPointerStore, retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date('2026-08-13T10:10:00.000Z') });
assert.ok((tamperedPointerAudit.categories['claim-outbox-integrity'] || 0) >= 1,
  'A generation or HMAC mismatch in the current pointer must be critical.');

const duplicateReferenceSha256 = 'c'.repeat(64);
const winningPaymentLinkHmacSha256 = 'd'.repeat(64);
const duplicateSessionHmacSha256 = hmacHex(env.ARC_HANDOFF_STATE_SECRET,
  'duplicate-payment-session-id-v1\ncs_test_operationsAuditDuplicate');
const duplicateReviewUnsigned = {
  schema: 'arc2-duplicate-payment-review-v1',
  status: 'CRITICAL_DUPLICATE_PAID_SESSION_REVIEW_REQUIRED',
  automatic_refund_requested: false,
  checkout_reference_sha256: duplicateReferenceSha256,
  winning_checkout_session_id_hmac_sha256: hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `duplicate-payment-session-id-v1\n${fixture.payment.value.checkout_session_id}`),
  duplicate_checkout_session_id_hmac_sha256: duplicateSessionHmacSha256,
  winning_payment_link_id_hmac_sha256: winningPaymentLinkHmacSha256,
  duplicate_payment_link_id_hmac_sha256: 'e'.repeat(64),
  winning_handoff_id: handoffId,
  winning_payment_evidence_sha256: record.payment_evidence_sha256,
  winning_artifact_evidence_sha256: record.artifact_evidence_sha256,
  duplicate_payment_evidence_sha256: 'f'.repeat(64),
};
const duplicateReview = {
  ...duplicateReviewUnsigned,
  review_hmac_sha256: hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `arc2-duplicate-payment-review-signature-v1\n${canonicalJson(duplicateReviewUnsigned)}`),
};
const duplicateReviewKey = `duplicate-payment-review/${hmacHex(env.ARC_HANDOFF_STATE_SECRET,
  `duplicate-payment-review-key-v1\n${duplicateReferenceSha256}\n${duplicateSessionHmacSha256}`)}`;
const duplicateReferenceKey = `checkout-reference-index/${hmacHex(env.ARC_HANDOFF_STATE_SECRET,
  `checkout-reference-index-v1\n${duplicateReferenceSha256}`)}`;
const winningSessionKey = `checkout-session-index/${hmacHex(env.ARC_HANDOFF_STATE_SECRET,
  `checkout-session-index-v1\n${fixture.payment.value.checkout_session_id}`)}`;
const duplicateReviewStore = new FakeStore();
await duplicateReviewStore.setJSON(`handoffs/${handoffId}`, record);
await duplicateReviewStore.setJSON(duplicateReferenceKey, {
  schema: 'arc2-checkout-reference-index-v1', client_reference_id_sha256: duplicateReferenceSha256,
  winning_checkout_session_id: fixture.payment.value.checkout_session_id,
  winning_payment_link_id_hmac_sha256: winningPaymentLinkHmacSha256, handoff_id: handoffId,
  preview_source_commit_sha: 'a'.repeat(40), payment_evidence_sha256: record.payment_evidence_sha256,
  artifact_evidence_sha256: record.artifact_evidence_sha256,
});
await duplicateReviewStore.setJSON(winningSessionKey, {
  schema: 'arc2-checkout-session-index-v1', handoff_id: handoffId,
  payment_evidence_sha256: record.payment_evidence_sha256, artifact_evidence_sha256: record.artifact_evidence_sha256,
  bundle_fingerprint: record.bundle_fingerprint,
});
await duplicateReviewStore.setJSON(duplicateReviewKey, duplicateReview);
const duplicateReviewAlerts = new FakeStore();
const validDuplicateReviewAudit = await runOperationsAudit(env, {
  handoff: duplicateReviewStore, retention: new FakeStore(), alerts: duplicateReviewAlerts, intake: new FakeStore(),
}, { clock: () => new Date(now) });
assert.equal(validDuplicateReviewAudit.categories['duplicate-payment-review'], 1,
  'An exact duplicate paid-session review must persist a critical operator-review alert.');
assert.equal(validDuplicateReviewAudit.categories['duplicate-payment-integrity'], undefined);
assert.equal(JSON.stringify([...duplicateReviewAlerts.values.values()]).includes(fixture.payment.value.checkout_session_id), false,
  'Duplicate-payment alerts must contain only HMACs and digests, never raw Checkout Session IDs.');

const invalidDuplicateReviewStore = new FakeStore();
invalidDuplicateReviewStore.values = new Map([...duplicateReviewStore.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
const invalidDuplicateReview = structuredClone(invalidDuplicateReviewStore.values.get(duplicateReviewKey).data);
invalidDuplicateReview.review_hmac_sha256 = '0'.repeat(64);
await invalidDuplicateReviewStore.setJSON(duplicateReviewKey, invalidDuplicateReview);
const invalidDuplicateReviewAudit = await runOperationsAudit(env, {
  handoff: invalidDuplicateReviewStore, retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date(now) });
assert.equal(invalidDuplicateReviewAudit.categories['duplicate-payment-integrity'], 1,
  'A review-HMAC mismatch must create a critical integrity alert.');

const orphanDuplicateReviewStore = new FakeStore();
orphanDuplicateReviewStore.values = new Map([...duplicateReviewStore.values.entries()]
  .filter(([key]) => key !== `handoffs/${handoffId}`).map(([key, value]) => [key, structuredClone(value)]));
const orphanDuplicateReviewAudit = await runOperationsAudit(env, {
  handoff: orphanDuplicateReviewStore, retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date(now) });
assert.equal(orphanDuplicateReviewAudit.categories['duplicate-payment-integrity'], 1,
  'A duplicate review without its winning handoff must remain a critical orphan condition.');

const conflictingDuplicateReviewStore = new FakeStore();
conflictingDuplicateReviewStore.values = new Map([...duplicateReviewStore.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
await conflictingDuplicateReviewStore.setJSON(duplicateReferenceKey, {
  ...conflictingDuplicateReviewStore.values.get(duplicateReferenceKey).data,
  payment_evidence_sha256: '0'.repeat(64),
});
const conflictingDuplicateReviewAudit = await runOperationsAudit(env, {
  handoff: conflictingDuplicateReviewStore, retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date(now) });
assert.equal(conflictingDuplicateReviewAudit.categories['duplicate-payment-integrity'], 1,
  'A conflicting winner/reference/evidence chain must remain a critical integrity condition.');

const duplicateShard = Number.parseInt(duplicateReviewKey.split('/')[1].slice(0, 2), 16);
const duplicateCursorValue = { v: 3, phase: 12, shard: duplicateShard, position: 0, sequence_hmac_sha256: null };
const duplicateCursorRaw = Buffer.from(JSON.stringify(duplicateCursorValue), 'utf8').toString('base64url');
const duplicateCursor = `${duplicateCursorRaw}.${hmacHex(env.ARC_OPERATIONS_AUDIT_SECRET,
  `arc-operations-audit-cursor-v3\n${duplicateCursorRaw}`)}`;
const incrementalDuplicateAlerts = new FakeStore();
const incrementalDuplicateAudit = await runOperationsAudit(env, {
  handoff: duplicateReviewStore, retention: new FakeStore(), alerts: incrementalDuplicateAlerts, intake: new FakeStore(),
}, { clock: () => new Date(now), incremental: true, cursor: duplicateCursor });
assert.equal(incrementalDuplicateAudit.categories['duplicate-payment-review'], 1,
  'The production incremental walker must scan and persist the duplicate-payment review alert.');
assert.equal(incrementalDuplicateAlerts.values.size, 1);

const intakeForm = new FormData();
for (const [field, value] of Object.entries({
  intake_version: 'arc-intake-v8', offer_contract_id: 'arc-fixed-five-page-offer-v1', name: 'Private Owner', email: 'private@example.test', business: 'Private Roofing',
  industry: 'Roofing', city: 'Everett, WA', main_services: 'Roofing', main_call_to_action: 'Contact',
  lead_form_needed: 'Yes', lead_notification_email: 'private@example.test', primary_style: 'Modern',
  budget_confirmed: BUDGET_CONFIRMATION, terms_accepted: TERMS_CONFIRMATION, 'bot-field': '',
})) intakeForm.append(field, value);
intakeForm.append('goals', 'More calls');
intakeForm.append('lead_form_fields', 'Email');
intakeForm.append('sections', 'Contact or quote form');
const intakeNormalized = await normalizeIntakeForm(intakeForm, old, () => '44444444-4444-4444-8444-444444444444');
await intake.setJSON(intakeNormalized.key, {
  ...intakeNormalized.record,
  arc1_dispatch: {
    ...intakeNormalized.record.arc1_dispatch,
    status: 'DEAD_LETTER', attempt_count: 5, last_attempt_at: old.toISOString(), accepted_at: null,
    alert_status: 'PENDING', alert_code: 'DISPATCH_MAX_ATTEMPTS', alert_updated_at: old.toISOString(),
  },
});
const deadLetter = await runOperationsAudit(env, { handoff, retention, alerts, intake }, { clock: () => new Date(now) });
assert.equal(deadLetter.categories['intake-arc1-dispatch'], 1, 'ARC1 dispatch dead letters must become critical audit conditions.');
assert.equal(JSON.stringify([...alerts.values.values()]).includes('private@example.test'), false, 'Audit alerts must never copy intake PII.');

const deliveredId = '8'.repeat(64);
const deliveredBase = createInitialRecord(fixture, env, `handoffs/${deliveredId}`, new Date('2026-08-13T08:00:00.000Z'), {
  uuid: () => '55555555-5555-4555-8555-555555555555',
}).record;
const at = (minutes) => new Date(Date.parse(deliveredBase.created_at) + minutes * 60_000).toISOString();
const outboxDigest = '7'.repeat(64);
const deliveredRecord = {
  ...deliveredBase,
  state: 'DELIVERED', revision: 9, updated_at: at(8),
  netlify_site_id: 'site-final-123', site_created_at: at(1),
  preclaim_deploy_attempted_at: at(1), preclaim_deploy_candidate_id: 'deploy-preclaim-123', preclaim_deploy_id: 'deploy-preclaim-123',
  email_hook_attempted_at: at(2), form_id: 'form-final-123', hook_id: 'hook-final-123',
  claim_invitation_ready_at: at(3), lead_route_provider_message_id_sha256: 'a'.repeat(64),
  lead_route_receipt_sha256: 'b'.repeat(64), claim_token_hmac_sha256: null,
  claim_token_consumed_hmac_sha256: 'c'.repeat(64), claim_token_expires_at: at(33),
  claim_token_used_at: at(4), claim_wrapper_consumed_at: at(4), claim_jwt_issued_at: Math.floor(Date.parse(at(4)) / 1000),
  destination_account_id: 'destination-account-123', claim_callback_received_at: at(5), claimed_verified_at: at(6),
  final_deploy_attempted_at: at(6), final_deploy_candidate_id: 'deploy-final-123', final_deploy_id: 'deploy-final-123',
  final_deploy_ready_at: at(7), production_url: `https://${deliveredBase.netlify_site_name}.netlify.app/`,
  outbox_claim_status: 'CLAIMED', outbox_claim_key_hmac_sha256: outboxDigest,
  delivered_at: at(8), final_delivery_receipt_sha256: 'd'.repeat(64), final_delivery_provider: 'mail.test',
  final_delivery_provider_account_hmac_sha256: 'e'.repeat(64), final_delivery_provider_event_id_hmac_sha256: 'f'.repeat(64),
  final_delivery_provider_message_id_hmac_sha256: '0'.repeat(64), final_delivery_event_type: 'message.delivered',
  final_delivery_status: 'delivered', final_delivery_receipt_issued_at: at(9),
};
validateExpectedBindings(deliveredRecord);
const deliveredStore = new FakeStore();
await deliveredStore.setJSON(`handoffs/${deliveredId}`, deliveredRecord);
await deliveredStore.setJSON(`outbox/${outboxDigest}`, { status: 'DELIVERED' });
const deliveredAudit = await runOperationsAudit(env, {
  handoff: deliveredStore, retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date(now) });
assert.equal(deliveredAudit.categories['final-delivery-integrity'], 1,
  'A terminal status alone must not satisfy exact final-delivery outbox bindings.');

const unboundReversalStore = new FakeStore();
await unboundReversalStore.setJSON(`stripe-reversal-event/${reversalEvent.event_id_hmac_sha256}`, reversalEvent);
await unboundReversalStore.setJSON(
  `stripe-reversal-pending/${paymentIntentHmac}/${reversalEvent.event_id_hmac_sha256}`,
  reversalEvent,
);
await unboundReversalStore.setJSON(`stripe-reversal-pending-payment/${paymentIntentHmac}`, {
  schema: STRIPE_PENDING_PAYMENT_SCHEMA,
  payment_intent_id_hmac_sha256: paymentIntentHmac,
  stripe_account_id_sha256: stripeAccountHash,
  livemode: false,
  delivery_halted: true,
});
const unboundReversalAudit = await runOperationsAudit(env, {
  handoff: unboundReversalStore, retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date(now) });
assert.equal(unboundReversalAudit.categories['stripe-reversal-unbound'], 1,
  'A verified reversal that arrives before binding must remain a visible critical audit condition.');
assert.equal(unboundReversalAudit.categories['stripe-reversal-integrity'], undefined,
  'An exact pre-binding halt is an unbound operational condition, not malformed storage.');

const orphanHaltStore = new FakeStore();
await orphanHaltStore.setJSON(`stripe-reversal-pending-payment/${paymentIntentHmac}`, {
  schema: STRIPE_PENDING_PAYMENT_SCHEMA,
  payment_intent_id_hmac_sha256: paymentIntentHmac,
  stripe_account_id_sha256: stripeAccountHash,
  livemode: false,
  delivery_halted: true,
});
const orphanHaltAudit = await runOperationsAudit(env, {
  handoff: orphanHaltStore, retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date(now) });
assert.equal(orphanHaltAudit.categories['stripe-reversal-integrity'], 1,
  'A pending-payment halt without a verified pending event must create a critical integrity condition.');

const incrementalOrphanStore = new FakeStore();
await incrementalOrphanStore.setJSON(`handoffs/${handoffId}`, record);
await incrementalOrphanStore.setJSON(`stripe-reversal-binding/handoff/${handoffId}`, reversalBinding);
await incrementalOrphanStore.setJSON(`stripe-payment-intent/${paymentIntentHmac}`, {
  ...reversalBinding, schema: STRIPE_PAYMENT_INTENT_INDEX_SCHEMA,
});
await incrementalOrphanStore.setJSON(`stripe-reversal-pending-payment/${paymentIntentHmac}`, {
  schema: STRIPE_PENDING_PAYMENT_SCHEMA, payment_intent_id_hmac_sha256: paymentIntentHmac,
  stripe_account_id_sha256: stripeAccountHash, livemode: false, delivery_halted: true,
});
const incrementalOrphanAudit = await runOperationsAudit(env, {
  handoff: incrementalOrphanStore, retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date(now), incremental: true, cursor: null });
assert.equal(incrementalOrphanAudit.categories['stripe-reversal-integrity'], 1,
  'The production incremental audit must detect a bound pending-payment halt with no exact pending event.');

const corruptPendingStore = new FakeStore();
await corruptPendingStore.setJSON(`stripe-reversal-pending-payment/${paymentIntentHmac}`, {
  schema: STRIPE_PENDING_PAYMENT_SCHEMA, payment_intent_id_hmac_sha256: paymentIntentHmac,
  stripe_account_id_sha256: stripeAccountHash, livemode: false, delivery_halted: true,
});
const originalCorruptList = corruptPendingStore.list.bind(corruptPendingStore);
corruptPendingStore.list = (options) => {
  if (options.prefix === `stripe-reversal-pending/${paymentIntentHmac}/`) return (async function* () {
    yield { blobs: Array.from({ length: 1_000 }, (_, index) => ({
      key: `stripe-reversal-pending/${paymentIntentHmac}/${index.toString(16).padStart(64, '0')}`,
    })) };
  }());
  return originalCorruptList(options);
};
let corruptStrongReads = 0;
const originalCorruptRead = corruptPendingStore.getWithMetadata.bind(corruptPendingStore);
corruptPendingStore.getWithMetadata = async (key, ...args) => {
  if (key.startsWith(`stripe-reversal-pending/${paymentIntentHmac}/`)) corruptStrongReads += 1;
  return originalCorruptRead(key, ...args);
};
const corruptAlerts = new FakeStore();
const corruptAudit = await runOperationsAudit(env, {
  handoff: corruptPendingStore, retention: new FakeStore(), alerts: corruptAlerts, intake: new FakeStore(),
}, { clock: () => new Date(now), incremental: true, cursor: null });
assert.equal(corruptAudit.categories['stripe-reversal-integrity'], 1);
assert.ok(corruptStrongReads <= 9,
  'One corrupt 1,000-item pending-event page must have a fixed small strong-read budget before persisting its critical alert.');
assert.equal(corruptAlerts.values.size, 1);

const orphanBindingStore = new FakeStore();
await orphanBindingStore.setJSON(`stripe-payment-intent/${paymentIntentHmac}`, {
  ...reversalBinding, schema: STRIPE_PAYMENT_INTENT_INDEX_SCHEMA,
});
const orphanBindingAudit = await runOperationsAudit(env, {
  handoff: orphanBindingStore, retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date(now) });
assert.equal(orphanBindingAudit.categories['stripe-reversal-integrity'], 1,
  'Each PaymentIntent binding must have the exact handoff-side binding and handoff record.');

await assert.rejects(runOperationsAudit(env, {
  handoff: new OverflowStore(), retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, { clock: () => new Date(now) }), /RECORD_LIMIT/, 'Cumulative pagination must fail closed above the audit cap.');

const incrementalIntake = new IncrementalBacklogStore([]);
const incrementalKeys = [];
for (let index = 0; index < 125; index += 1) {
  const id = `${index.toString(16).padStart(8, '0')}-0000-4000-8000-${index.toString(16).padStart(12, '0')}`;
  const key = `submissions/${id}`;
  incrementalKeys.push(key);
  incrementalIntake.backlog.push(key);
  await incrementalIntake.setJSON(key, {
    malformed: true,
  });
}
const incrementalAlerts = new FakeStore();
const incrementalStores = {
  handoff: new IncrementalBacklogStore([]), retention: new IncrementalBacklogStore([]),
  alerts: incrementalAlerts, intake: incrementalIntake,
};
let auditCursor = null;
let totalCreated = 0;
let calls = 0;
do {
  const result = await runOperationsAudit(env, incrementalStores, {
    clock: () => new Date(now), incremental: true, cursor: auditCursor,
  });
  calls += 1;
  totalCreated += result.alerts_created;
  auditCursor = result.next_cursor;
  assert.ok(result.scanned <= 100, 'Each audit invocation must have a strict record budget.');
  assert.ok(calls < 10, 'Signed continuation must eventually finish rather than rescan the head forever.');
} while (auditCursor);
assert.equal(totalCreated, 125);
assert.equal(incrementalAlerts.values.size, 125,
  'Critical alerts must be persisted incrementally before a later page or invocation can fail.');

const deadlineIntake = new IncrementalBacklogStore(incrementalKeys.slice(0, 2));
deadlineIntake.values = new Map([...incrementalIntake.values.entries()].slice(0, 2));
let auditWallMs = 0;
const deadlineAlerts = new FakeStore();
const deadlineAudit = await runOperationsAudit(env, {
  handoff: new IncrementalBacklogStore([]), retention: new IncrementalBacklogStore([]),
  alerts: deadlineAlerts, intake: deadlineIntake,
}, {
  clock: () => new Date(now), incremental: true, cursor: null,
  wallClock: () => { const current = auditWallMs; auditWallMs += 4_001; return current; },
});
assert.equal(deadlineAudit.state, 'AUDIT_PARTIAL');
assert.ok(deadlineAudit.next_cursor, 'Wall-clock exhaustion must return an authenticated continuation instead of losing progress.');
await assert.rejects(runOperationsAudit(env, incrementalStores, {
  clock: () => new Date(now), incremental: true, cursor: `${auditCursor || 'broken'}.bad`,
}), /cursor/i, 'Audit continuation must reject tampering before storage reads.');

const terminalCursorValue = { v: 3, phase: 12, shard: 256, position: 0, sequence_hmac_sha256: null };
const terminalCursorRaw = Buffer.from(JSON.stringify(terminalCursorValue), 'utf8').toString('base64url');
const terminalCursor = `${terminalCursorRaw}.${hmacHex(env.ARC_OPERATIONS_AUDIT_SECRET,
  `arc-operations-audit-cursor-v3\n${terminalCursorRaw}`)}`;
let terminalWallCall = 0;
const terminalAudit = await runOperationsAudit(env, {
  handoff: new FakeStore(), retention: new FakeStore(), alerts: new FakeStore(), intake: new FakeStore(),
}, {
  clock: () => new Date(now), incremental: true, cursor: terminalCursor,
  wallClock: () => [0, 0, 0, 8_001][terminalWallCall++] ?? 8_001,
});
assert.equal(terminalAudit.state, 'AUDIT_COMPLETE');
assert.equal(terminalAudit.next_cursor, null,
  'Completing the final catch-all shard must not emit an out-of-range continuation at the wall deadline.');

const longMalformedIntake = new IncrementalBacklogStore([]);
for (let index = 0; index < 101; index += 1) {
  const key = `submissions/${'z'.repeat(540)}${String(index).padStart(3, '0')}`;
  assert.ok(key.length > 512 && Buffer.byteLength(key, 'utf8') <= 600,
    'The continuation fixture must exceed the old cursor cap while remaining a valid provider key length.');
  longMalformedIntake.backlog.push(key);
  await longMalformedIntake.setJSON(key, { malformed: true });
}
const laterMalformedKey = 'submissions/zzzz-later-malformed-record';
longMalformedIntake.backlog.push(laterMalformedKey);
await longMalformedIntake.setJSON(laterMalformedKey, { malformed: true });
const longMalformedAlerts = new FakeStore();
let longCursor = null;
let longCalls = 0;
do {
  const result = await runOperationsAudit(env, {
    handoff: new IncrementalBacklogStore([]), retention: new IncrementalBacklogStore([]),
    alerts: longMalformedAlerts, intake: longMalformedIntake,
  }, { clock: () => new Date(now), incremental: true, cursor: longCursor });
  longCursor = result.next_cursor;
  longCalls += 1;
  assert.ok(longCalls < 8, 'Long provider keys must resume and converge rather than poison the signed cursor.');
  if (longCursor) assert.ok(Buffer.byteLength(longCursor, 'utf8') <= 2_048, 'Signed cursor must remain URL-bounded.');
} while (longCursor);
assert.equal(longMalformedAlerts.values.size, 102,
  'A >512-character malformed provider key must not starve later integrity alerts across continuations.');

const nonmonotonicHead = Array.from({ length: 100 }, (_, index) =>
  `submissions/z-provider-order-${String(index).padStart(3, '0')}`);
const nonmonotonicTail = [
  'submissions/!later-lower-key',
  'submissions/é-precomposed',
  'submissions/e\u0301-combining',
  'submissions/😀-astral',
];
const nonmonotonicSequence = [...nonmonotonicHead, ...nonmonotonicTail];
const nonmonotonicStore = new ProviderSequenceStore([
  [nonmonotonicHead, nonmonotonicTail],
  [
    nonmonotonicSequence.slice(0, 17), nonmonotonicSequence.slice(17, 51),
    nonmonotonicSequence.slice(51, 88), nonmonotonicSequence.slice(88),
  ],
]);
for (const key of nonmonotonicSequence) await nonmonotonicStore.setJSON(key, { malformed: true });
const nonmonotonicAlerts = new FakeStore();
let nonmonotonicCursor = null;
let nonmonotonicCalls = 0;
do {
  const result = await runOperationsAudit(env, {
    handoff: new FakeStore(), retention: new FakeStore(), alerts: nonmonotonicAlerts, intake: nonmonotonicStore,
  }, { clock: () => new Date(now), incremental: true, cursor: nonmonotonicCursor });
  nonmonotonicCursor = result.next_cursor;
  nonmonotonicCalls += 1;
  assert.ok(nonmonotonicCalls < 8);
  if (nonmonotonicCalls === 1) {
    const cursorValue = JSON.parse(Buffer.from(nonmonotonicCursor.split('.')[0], 'base64url').toString('utf8'));
    assert.deepEqual(Object.keys(cursorValue).sort(), ['phase', 'position', 'sequence_hmac_sha256', 'shard', 'v']);
    assert.doesNotMatch(JSON.stringify(cursorValue), /provider-order|later-lower|é|😀/,
      'A continuation must not expose provider keys or customer-controlled Unicode.');
  }
} while (nonmonotonicCursor);
assert.equal(nonmonotonicAlerts.values.size, nonmonotonicSequence.length,
  'Provider-nonmonotonic and Unicode keys must survive a continuation and changed page boundaries.');

const driftOriginal = Array.from({ length: 101 }, (_, index) =>
  `submissions/z-drift-${String(index).padStart(3, '0')}`);
const driftReplacement = 'submissions/y-drift-replacement';
const driftChanged = [driftReplacement, ...driftOriginal.slice(1)];
const driftStore = new ProviderSequenceStore([
  [driftOriginal.slice(0, 100), driftOriginal.slice(100)],
  [driftChanged.slice(0, 45), driftChanged.slice(45)],
  [driftChanged.slice(0, 63), driftChanged.slice(63)],
]);
for (const key of [...driftOriginal, driftReplacement]) await driftStore.setJSON(key, { malformed: true });
const driftAlerts = new FakeStore();
const firstDriftRun = await runOperationsAudit(env, {
  handoff: new FakeStore(), retention: new FakeStore(), alerts: driftAlerts, intake: driftStore,
}, { clock: () => new Date(now), incremental: true, cursor: null });
assert.equal(firstDriftRun.state, 'AUDIT_PARTIAL');
const resetDriftRun = await runOperationsAudit(env, {
  handoff: new FakeStore(), retention: new FakeStore(), alerts: driftAlerts, intake: driftStore,
}, { clock: () => new Date(now), incremental: true, cursor: firstDriftRun.next_cursor });
assert.equal(resetDriftRun.state, 'AUDIT_PARTIAL');
assert.equal(resetDriftRun.scanned, 0,
  'Sequence drift before the checkpoint must reset the current prefix without auditing or skipping records.');
let driftCursor = resetDriftRun.next_cursor;
let driftCalls = 0;
do {
  const result = await runOperationsAudit(env, {
    handoff: new FakeStore(), retention: new FakeStore(), alerts: driftAlerts, intake: driftStore,
  }, { clock: () => new Date(now), incremental: true, cursor: driftCursor });
  driftCursor = result.next_cursor;
  driftCalls += 1;
  assert.ok(driftCalls < 8);
} while (driftCursor);
assert.equal(driftAlerts.values.size, 102,
  'A stable retry after sequence drift must cover the replacement and the later record without losing prior alerts.');

assert.equal(auditConfig.path, '/internal/operations/audit');
const savedEnvironment = { ...process.env };
const restoreEnvironment = () => {
  for (const key of Object.keys(process.env)) if (!(key in savedEnvironment)) delete process.env[key];
  Object.assign(process.env, savedEnvironment);
};
delete process.env.ARC_OPERATIONS_AUDIT_ENABLED;
try {
  assert.equal((await auditHandler(new Request('https://arcweb.onl/internal/operations/audit', { method: 'POST' }))).status, 503);
} finally {
  restoreEnvironment();
}

const malformedHandoffStore = new FakeStore();
const malformedRetentionStore = new FakeStore();
const malformedIntakeStore = new FakeStore();
const malformedAlerts = new FakeStore();
await malformedHandoffStore.setJSON('handoffs/not-valid', { malformed: true });
await malformedHandoffStore.setJSON('invitation-ready-current/not-valid', { malformed: true });
await malformedHandoffStore.setJSON('duplicate-payment-review/not-valid', { malformed: true });
await malformedHandoffStore.setJSON('stripe-reversal/handoff/not-valid', { malformed: true });
await malformedRetentionStore.setJSON('delete-receipts/not-valid', { malformed: true });
await malformedIntakeStore.setJSON('submissions/not-valid', { malformed: true });
try {
  Object.assign(process.env, env);
  const response = await auditHandler(new Request('https://arcweb.onl/internal/operations/audit', {
    method: 'POST', headers: { authorization: `Bearer ${env.ARC_OPERATIONS_AUDIT_SECRET}` },
  }), {
    alertStore: malformedAlerts, arc2Store: malformedHandoffStore,
    retentionStore: malformedRetentionStore, intakeStore: malformedIntakeStore,
    retentionFenceStore: new FakeStore(),
    clock: () => new Date(now),
  });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.state, 'AUDIT_COMPLETE');
  assert.equal(result.categories['handoff-integrity'], 1);
  assert.equal(result.categories['claim-outbox-integrity'], 1);
  assert.equal(result.categories['duplicate-payment-integrity'], 1);
  assert.equal(result.categories['stripe-reversal-integrity'], 1);
  assert.equal(result.categories['retention-integrity'], 1);
  assert.equal(result.categories['intake-arc1-integrity'], 1);
  assert.equal(malformedAlerts.values.size, 6,
    'The production endpoint must persist alerts for malformed non-hex keys outside every normal shard.');
} finally {
  restoreEnvironment();
}

console.log('ARC operations audit contract passed.');
