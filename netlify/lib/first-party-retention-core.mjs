import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';

import {
  canonicalJson,
  sha256Hex,
  validateExpectedBindings,
} from './arc2-handoff-core.mjs';
import { ACTIVATION_BUILD_IDENTITY } from './activation-build-identity.mjs';
import {
  reviewEmailRenewalKey,
  validateReviewEmailRenewal,
} from './review-email-outbox-core.mjs';
import {
  HANDOFF_CHILD_RETENTION_ACTION,
  planHandoffChildSet,
} from './first-party-retention-handoff-child-core.mjs';
import {
  RETENTION_GENERATION_FENCE_SECRET_ENV,
  assertRetentionGenerationFenceAuthority,
  beginRetentionFreeze,
  completeRetentionFreeze,
  ensureRetentionGenerationFence,
  readRetentionGenerationFence,
  recordRetentionMissingSourceAnomaly,
  recoverStaleRetentionGenerationFence,
  renewRetentionGenerationFenceAuthority,
  retentionFreezeOperationHmac,
  retentionGenerationFenceConfiguration,
  retentionGenerationFenceKeys,
  validateRetentionFinalizeReceipt,
  validateRetentionFreezeIntent,
} from './retention-generation-fence-core.mjs';

export const FIRST_PARTY_RETENTION_ENABLED_ENV = 'ARC_FIRST_PARTY_RETENTION_ENABLED';
export const FIRST_PARTY_RETENTION_HMAC_SECRET_ENV = 'ARC_FIRST_PARTY_RETENTION_HMAC_SECRET';
export const FIRST_PARTY_RETENTION_UNPAID_DAYS_ENV = 'ARC_FIRST_PARTY_RETENTION_UNPAID_DAYS';
export const FIRST_PARTY_RETENTION_PAID_DAYS_ENV = 'ARC_FIRST_PARTY_RETENTION_PAID_DAYS';
export const FIRST_PARTY_RETENTION_RECEIPT_ENV = 'ARC_FIRST_PARTY_RETENTION_RECEIPT';
export const FIRST_PARTY_RETENTION_STATE_KEY = 'first-party-retention/state-v1';
export const FIRST_PARTY_RETENTION_SWEEP_SCHEMA = 'arc-first-party-retention-sweep-v1';
export const FIRST_PARTY_RETENTION_RECEIPT_SCHEMA = 'arc-first-party-retention-completion-v1';
export const FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA = 'arc-first-party-retention-tombstone-v1';
export const FIRST_PARTY_RETENTION_MISSING_SOURCE_SCHEMA =
  'arc-first-party-retention-sweep-missing-source-anomaly-v1';
export const FIRST_PARTY_RETENTION_INTERVAL_MS = 24 * 60 * 60_000;

const LEASE_MS = 2 * 60_000;
const HEX_40 = /^[a-f0-9]{40}$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const FAMILIES = Object.freeze(['intake_abuse', 'review', 'checkout', 'handoff']);
const COUNT_FIELDS = Object.freeze(['candidates', 'deleted', 'held', 'inspected', 'quarantined']);
const SOURCE_SECRETS = Object.freeze([
  'ARC_INTAKE_ABUSE_HMAC_SECRET',
  'ARC_REVIEW_RECORD_HMAC_SECRET',
  'ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET',
  'ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET',
  'ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET',
  'ARC_HANDOFF_STATE_SECRET',
  'ARC_EMAIL_CLAIM_BINDING_SECRET',
  'ARC_STRIPE_REVERSAL_HMAC_SECRET',
  'ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET',
]);

const RETENTION_SUBJECT_MANIFEST_SCHEMA =
  'arc-first-party-retention-subject-manifest-v1';
const RETENTION_SUBJECT_MANIFEST_FIELDS = Object.freeze([
  'built_at', 'customer_data_stored', 'entries', 'family', 'generation',
  'record_hmac_sha256', 'schema', 'subject_hmac_sha256', 'sweep_hmac_sha256',
  'version',
]);
const RETENTION_SUBJECT_MANIFEST_ENTRY_FIELDS = Object.freeze([
  'action', 'family', 'output_record_sha256', 'role', 'source_key',
  'source_record_sha256', 'store',
]);

const PHASES = Object.freeze([
  Object.freeze({ family: 'intake_abuse', store: 'abuse', prefix: 'challenge-replay/', kind: 'abuse' }),
  Object.freeze({ family: 'intake_abuse', store: 'abuse', prefix: 'quota/', kind: 'abuse' }),
  Object.freeze({ family: 'intake_abuse', store: 'abuse', prefix: 'suppression/', kind: 'abuse' }),
  Object.freeze({ family: 'intake_abuse', store: 'abuse', prefix: 'circuit-breaker/', kind: 'abuse' }),
  Object.freeze({ family: 'checkout', store: 'review', prefix: 'review-checkout-binding/', kind: 'checkout-candidate' }),
  Object.freeze({ family: 'review', store: 'review', prefix: 'review-invites/', kind: 'review-candidate' }),
  Object.freeze({ family: 'review', store: 'revision', prefix: 'review-revision-work/', kind: 'revision-work' }),
  Object.freeze({ family: 'review', store: 'revision', prefix: 'review-revision-pending/', kind: 'revision-pending' }),
  Object.freeze({ family: 'review', store: 'review', prefix: 'review-email-provider-event/', kind: 'review-provider-index' }),
  Object.freeze({ family: 'review', store: 'review', prefix: 'review-email-provider-message/', kind: 'review-provider-index' }),
  Object.freeze({ family: 'review', store: 'review', prefix: 'review-email-outbox/', kind: 'review-outbox' }),
  Object.freeze({ family: 'review', store: 'review', prefix: 'review-email-resend-attempt/', kind: 'review-resend-attempt' }),
  Object.freeze({ family: 'review', store: 'review', prefix: 'review-email-renewal/', kind: 'review-renewal' }),
  Object.freeze({ family: 'checkout', store: 'review', prefix: 'review-checkout-revocation-alert/', kind: 'checkout-alert' }),
  Object.freeze({ family: 'checkout', store: 'review', prefix: 'review-checkout-recipient-index/', kind: 'checkout-index' }),
  Object.freeze({ family: 'review', store: 'review', prefix: 'review-email-pending/', kind: 'review-pending' }),
  Object.freeze({ family: 'review', store: 'review', prefix: 'review-email-recipient-control/', kind: 'review-recipient' }),
  Object.freeze({ family: 'review', store: 'review', prefix: 'review-email-recipient-suppression/', kind: 'review-recipient' }),
  Object.freeze({ family: 'checkout', store: 'review', prefix: 'review-checkout-binding/', kind: 'checkout-primary' }),
  Object.freeze({ family: 'review', store: 'review', prefix: 'review-invites/', kind: 'review-primary' }),
  Object.freeze({ family: 'handoff', store: 'handoff', prefix: 'handoffs/', kind: 'handoff-candidate' }),
  Object.freeze({ family: 'handoff', store: 'payment', prefix: 'payment-arc2-pending/', kind: 'payment-child' }),
  Object.freeze({ family: 'handoff', store: 'payment', prefix: 'payment-arc2-start-outbox/', kind: 'payment-child' }),
  Object.freeze({ family: 'handoff', store: 'payment', prefix: 'payment-review-session-binding/', kind: 'payment-child' }),
  ...[
    'checkout-session-index/', 'checkout-reference-index/', 'duplicate-payment-review/',
    'invitation-ready-current/', 'invitation-ready-outbox/',
    'final-delivery-provider-event/', 'final-delivery-provider-message/', 'outbox/',
    'stripe-checkout-event/', 'stripe-checkout-receipt/', 'stripe-checkout-session/', 'stripe-checkout-handoff/',
    'stripe-reversal/handoff/', 'stripe-reversal-event/', 'stripe-reversal-pending-payment/', 'stripe-reversal-pending/',
    'stripe-reversal-recheck/handoff/', 'stripe-payment-intent/', 'stripe-reversal-binding/handoff/',
    'site-index/', 'arc2-email-negative-events/', 'arc2-email-negative-controls/',
    'arc2-email-local-alerts/',
  ].map((prefix) => Object.freeze({ family: 'handoff', store: 'handoff', prefix, kind: 'handoff-child' })),
  Object.freeze({ family: 'handoff', store: 'alerts', prefix: 'alerts/stripe-reversal/', kind: 'handoff-alert' }),
  Object.freeze({ family: 'handoff', store: 'alerts', prefix: 'alerts/stripe-reversal-unbound/', kind: 'handoff-alert' }),
  Object.freeze({ family: 'handoff', store: 'alerts', prefix: 'alerts/stripe-checkout-review/', kind: 'handoff-alert' }),
  Object.freeze({ family: 'handoff', store: 'handoff', prefix: 'handoffs/', kind: 'handoff-primary' }),
]);

const STATE_FIELDS = Object.freeze([
  'completed_at', 'counts', 'cursor', 'deployment_sha', 'lease_expires_at', 'lease_hmac_sha256',
  'next_sweep_at', 'phase_index', 'record_hmac_sha256', 'run_count', 'schema', 'started_at',
  'status', 'sweep_hmac_sha256', 'version',
]);
const RECEIPT_FIELDS = Object.freeze([
  'completed_at', 'counts', 'customer_data_stored', 'deployment_sha', 'families', 'next_sweep_at',
  'record_hmac_sha256', 'schema', 'started_at', 'sweep_hmac_sha256', 'version',
]);
const TOMBSTONE_FIELDS = Object.freeze([
  'customer_data_stored', 'family', 'record_hmac_sha256', 'schema', 'source_key_hmac_sha256',
  'source_record_sha256', 'sweep_hmac_sha256', 'tombstoned_at', 'version',
]);
const MISSING_SOURCE_FIELDS = Object.freeze([
  'customer_data_stored', 'detected_at', 'family', 'reason_code', 'record_hmac_sha256',
  'schema', 'source_key_hmac_sha256', 'source_record_sha256', 'source_store',
  'sweep_hmac_sha256', 'version',
]);
const HANDOFF_CHILD_PLAN_FIELDS = Object.freeze([
  'customer_data_stored', 'family', 'handoff_id', 'marked_at', 'plan_action',
  'reason_code', 'record_hmac_sha256', 'schema', 'source_key_hmac_sha256',
  'source_record_sha256', 'source_store', 'sweep_hmac_sha256', 'version',
]);
const REVIEW_CHECKOUT_INDEX_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'recipient_index_hmac_sha256',
  'recipient_email_sha256', 'bindings', 'updated_at', 'record_hmac_sha256',
]);
const REVIEW_RECIPIENT_CONTROL_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'state', 'recipient_control_hmac_sha256',
  'recipient_email_sha256', 'authority_operation_hmac_sha256', 'authority_expires_at',
  'suppression_receipt_sha256', 'suppression_status', 'suppressed_at',
  'source_invite_hmac_sha256', 'source_outbox_hmac_sha256', 'record_hmac_sha256',
]);
const REVIEW_RECIPIENT_SUPPRESSION_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'recipient_suppression_hmac_sha256',
  'recipient_email_sha256', 'suppression_receipt_sha256', 'suppression_status', 'suppressed_at',
  'source_invite_hmac_sha256', 'source_outbox_hmac_sha256', 'record_hmac_sha256',
]);
const REVIEW_PROVIDER_EVENT_FIELDS = Object.freeze([
  'delivery_receipt_sha256', 'identity_hmac_sha256', 'kind', 'outbox_hmac_sha256',
  'provider', 'provider_account_hmac_sha256', 'schema',
]);
const REVIEW_PROVIDER_MESSAGE_FIELDS = Object.freeze([
  'identity_hmac_sha256', 'kind', 'outbox_hmac_sha256', 'provider',
  'provider_account_hmac_sha256', 'schema',
]);
const REVIEW_OUTBOX_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'state', 'outbox_hmac_sha256', 'invite_hmac_sha256',
  'recipient_email_sha256', 'preview_manifest_sha256', 'template_version', 'created_at', 'expires_at',
  'send_reserved_at', 'provider_idempotency_key_sha256', 'delivery_receipt_sha256', 'provider',
  'provider_account_hmac_sha256', 'provider_event_id_hmac_sha256', 'provider_message_id_hmac_sha256',
  'event_type', 'delivery_status', 'event_at', 'receipt_issued_at', 'delivered_receipt_sha256',
  'suppression_receipt_sha256', 'suppression_status', 'suppressed_at', 'terminal_at', 'record_hmac_sha256',
]);
const REVIEW_RESEND_ATTEMPT_FIELDS = Object.freeze([
  'attempt_hmac_sha256', 'created_at', 'invite_hmac_sha256', 'outbox_hmac_sha256',
  'preview_manifest_sha256', 'provider_account_hmac_sha256', 'recipient_email_sha256',
  'record_hmac_sha256', 'schema', 'version',
]);
const SITE_INDEX_FIELDS = Object.freeze([
  'handoff_id', 'netlify_session_id', 'netlify_site_id', 'schema',
]);
const CHECKOUT_SESSION_INDEX_FIELDS = Object.freeze([
  'artifact_evidence_sha256', 'bundle_fingerprint', 'handoff_id', 'payment_evidence_sha256', 'schema',
]);
const CHECKOUT_REFERENCE_INDEX_FIELDS = Object.freeze([
  'artifact_evidence_sha256', 'client_reference_id_sha256', 'handoff_id', 'payment_evidence_sha256',
  'preview_source_commit_sha', 'schema', 'winning_checkout_session_id', 'winning_payment_link_id_hmac_sha256',
]);
const REVIEW_CHECKOUT_REFERENCE_INDEX_FIELDS = Object.freeze([
  'artifact_evidence_sha256', 'bridge_immutable_binding_sha256', 'checkout_session_id_hmac_sha256',
  'client_reference_id_sha256', 'handoff_id', 'payment_evidence_sha256', 'payment_intent_id_hmac_sha256',
  'payment_link_id_hmac_sha256', 'preview_source_commit_sha', 'review_session_binding_sha256', 'schema',
]);
const DUPLICATE_PAYMENT_REVIEW_FIELDS = Object.freeze([
  'automatic_refund_requested', 'checkout_reference_sha256', 'duplicate_checkout_session_id_hmac_sha256',
  'duplicate_payment_evidence_sha256', 'duplicate_payment_link_id_hmac_sha256', 'review_hmac_sha256', 'schema',
  'status', 'winning_artifact_evidence_sha256', 'winning_checkout_session_id_hmac_sha256', 'winning_handoff_id',
  'winning_payment_evidence_sha256', 'winning_payment_link_id_hmac_sha256',
]);
const INVITATION_OUTBOX_FIELDS = Object.freeze([
  'claim_invitation_generation', 'claim_token_hmac_sha256', 'expires_at', 'handoff_id',
  'recipient_email_sha256', 'schema', 'status',
]);
const INVITATION_CURRENT_FIELDS = Object.freeze([
  'binding_hmac_sha256', 'claim_invitation_generation', 'claim_token_hmac_sha256', 'expires_at',
  'handoff_id', 'outbox_key_sha256', 'schema',
]);
const FINAL_OUTBOX_FIELDS = Object.freeze([
  'delivered_at', 'delivery_receipt_sha256', 'delivery_status', 'event_type', 'handoff_id',
  'netlify_deploy_id_sha256', 'netlify_site_id_sha256', 'outbox_claim_key_hmac_sha256', 'provider',
  'provider_account_hmac_sha256', 'provider_event_id_hmac_sha256', 'provider_message_id_hmac_sha256',
  'receipt_issued_at', 'schema', 'status',
]);
const FINAL_PROVIDER_INDEX_FIELDS = Object.freeze([
  'delivery_receipt_sha256', 'handoff_id', 'identity_hmac_sha256', 'kind', 'provider',
  'provider_account_hmac_sha256', 'schema',
]);
const REVERSAL_BINDING_FIELDS = Object.freeze([
  'binding_evidence_sha256', 'checkout_session_id_hmac_sha256', 'handoff_id', 'livemode',
  'payment_evidence_sha256', 'payment_intent_id_hmac_sha256', 'schema', 'stripe_account_id_sha256',
]);
const REVERSAL_RECHECK_FIELDS = Object.freeze([
  'binding_evidence_sha256', 'checkout_session_id_hmac_sha256', 'dispute_status', 'evidence_sha256',
  'handoff_id', 'issued_at', 'livemode', 'payment_intent_id_hmac_sha256', 'payment_intent_status',
  'refunded_amount_minor_units', 'schema', 'stripe_account_id_sha256',
]);
const REVERSAL_EVENT_FIELDS = Object.freeze([
  'amount_minor_units', 'checkout_session_id_hmac_sha256', 'currency', 'event_created_at',
  'event_id_hmac_sha256', 'event_sha256', 'event_status', 'event_type', 'handoff_id', 'kind', 'livemode',
  'object_id_hmac_sha256', 'payment_intent_id_hmac_sha256', 'schema', 'stripe_account_id_sha256',
]);
const PENDING_PAYMENT_FIELDS = Object.freeze([
  'delivery_halted', 'livemode', 'payment_intent_id_hmac_sha256', 'schema', 'stripe_account_id_sha256',
]);
const REVERSAL_ALERT_FIELDS = Object.freeze([
  'category', 'contains_customer_data', 'delivery_status', 'detected_at', 'handoff_id', 'schema',
  'severity', 'status', 'subject_hmac_sha256',
]);
const PAYMENT_REVIEW_BINDING_FIELDS = Object.freeze([
  'created_at', 'immutable', 'immutable_sha256', 'schema',
]);
const PAYMENT_REVIEW_IMMUTABLE_FIELDS = Object.freeze([
  'approval_decided_at', 'approval_receipt_hmac_sha256', 'approval_receipt_sha256', 'authorization_expires_at',
  'brief_sha256', 'checkout_idempotency_key_sha256', 'checkout_session_created_at',
  'checkout_session_id_hmac_sha256', 'client_reference_id_sha256', 'currency', 'customer_address_country',
  'customer_address_state', 'invite_hmac_sha256', 'ledger_payment_binding_sha256', 'ledger_receipt_sha256',
  'ledger_session_storage_key', 'livemode', 'payer_email_sha256', 'payment_intent_id_hmac_sha256',
  'payment_state_event_sha256', 'preview_content_sha256', 'preview_manifest_sha256', 'provider_metadata_sha256',
  'provider_session_binding_sha256', 'recipient_email_sha256', 'review_record_hmac_sha256',
  'review_record_revision', 'review_record_sha256', 'revision_round', 'schema', 'scope_version',
  'stripe_account_id_sha256', 'subtotal_amount_minor_units', 'tax_amount_minor_units', 'amount_total_minor_units',
]);
const PAYMENT_START_OUTBOX_FIELDS = Object.freeze([
  'arc2_start_receipt_sha256', 'claim_attempt_count', 'completed_at', 'completion_claim_hmac_sha256',
  'completion_receipt_sha256', 'created_at', 'immutable', 'immutable_sha256', 'lease_claim_hmac_sha256',
  'lease_claimed_at', 'lease_expires_at', 'record_revision', 'schema', 'status', 'updated_at',
]);
const PAYMENT_START_IMMUTABLE_FIELDS = Object.freeze([
  'approval_receipt_hmac_sha256', 'approval_receipt_sha256', 'authorization_expires_at', 'brief_sha256',
  'checkout_session_id_hmac_sha256', 'invite_hmac_sha256', 'livemode', 'payer_email_sha256',
  'payment_binding_sha256', 'payment_intent_id_hmac_sha256', 'payment_receipt_sha256',
  'payment_state_event_sha256', 'preview_content_sha256', 'preview_manifest_sha256',
  'recipient_email_sha256', 'review_session_binding_sha256', 'schema', 'scope_version',
  'stripe_account_id_sha256',
]);
const PAYMENT_PENDING_FIELDS = Object.freeze([
  'created_at', 'immutable_binding_sha256', 'outbox_key', 'schema',
]);
const STRIPE_REVIEW_CHECKOUT_HANDOFF_FIELDS = Object.freeze([
  'approval_receipt_sha256', 'bridge_immutable_binding_sha256', 'checkout_session_id_hmac_sha256',
  'handoff_id', 'livemode', 'payer_email_sha256', 'payment_evidence_sha256',
  'payment_intent_id_hmac_sha256', 'payment_link_id_hmac_sha256', 'recipient_email_sha256',
  'review_checkout_binding_sha256', 'review_session_binding_sha256', 'schema', 'stripe_account_id_sha256',
]);

const exactKeys = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
const safeEqual = (left, right) => {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
};
const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
const unsigned = (value) => {
  const { record_hmac_sha256: ignored, ...record } = value;
  return record;
};
const sign = (value, domain, secret) => ({
  ...unsigned(value),
  record_hmac_sha256: hmac(secret, `${domain}\n${canonicalJson(unsigned(value))}`),
});
const verify = (value, domain, secret) => {
  if (!value || !HEX_64.test(value.record_hmac_sha256 || '') ||
      !safeEqual(value.record_hmac_sha256, hmac(secret, `${domain}\n${canonicalJson(unsigned(value))}`))) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_SIGNATURE_INVALID');
  }
  return value;
};
const iso = (value, label) => {
  const parsed = typeof value === 'string' ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new TypeError(`${label} is invalid.`);
  }
  return parsed;
};
const nullableIso = (value, label) => value === null ? null : iso(value, label);
const integerEnv = (value, minimum, maximum) => {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,4}$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : null;
};
const validSecret = (value) => typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= 32 &&
  Buffer.byteLength(value, 'utf8') <= 512;
const recordSha = (value) => sha256Hex(canonicalJson(value));

function emptyCounts() {
  return Object.fromEntries(FAMILIES.map((family) => [family,
    Object.fromEntries(COUNT_FIELDS.map((field) => [field, 0]))]));
}

function validCounts(value) {
  return exactKeys(value, FAMILIES) && FAMILIES.every((family) =>
    exactKeys(value[family], COUNT_FIELDS) && COUNT_FIELDS.every((field) =>
      Number.isSafeInteger(value[family][field]) && value[family][field] >= 0));
}

export function firstPartyRetentionConfiguration(env = process.env) {
  const flag = env[FIRST_PARTY_RETENTION_ENABLED_ENV];
  const requested = flag === 'true';
  const missing = [];
  const invalid = [];
  if (flag !== undefined && !['true', 'false'].includes(flag)) invalid.push(FIRST_PARTY_RETENTION_ENABLED_ENV);
  const secret = env[FIRST_PARTY_RETENTION_HMAC_SECRET_ENV];
  const unpaidDays = integerEnv(env[FIRST_PARTY_RETENTION_UNPAID_DAYS_ENV], 30, 3650);
  const paidDays = integerEnv(env[FIRST_PARTY_RETENTION_PAID_DAYS_ENV], 365, 3650);
  const deploymentSha = ACTIVATION_BUILD_IDENTITY?.schema === 'arc-activation-build-identity-v1' &&
    ACTIVATION_BUILD_IDENTITY?.version === 1
    ? String(ACTIVATION_BUILD_IDENTITY.deployment_sha || '') : '';
  if (requested) {
    for (const name of [FIRST_PARTY_RETENTION_HMAC_SECRET_ENV,
      RETENTION_GENERATION_FENCE_SECRET_ENV,
      FIRST_PARTY_RETENTION_UNPAID_DAYS_ENV, FIRST_PARTY_RETENTION_PAID_DAYS_ENV,
      ...SOURCE_SECRETS]) {
      if (typeof env[name] !== 'string' || env[name].length === 0) missing.push(name);
    }
    if (!missing.includes(FIRST_PARTY_RETENTION_HMAC_SECRET_ENV) && !validSecret(secret)) {
      invalid.push(FIRST_PARTY_RETENTION_HMAC_SECRET_ENV);
    }
    if (!missing.includes(FIRST_PARTY_RETENTION_UNPAID_DAYS_ENV) && unpaidDays === null) {
      invalid.push(FIRST_PARTY_RETENTION_UNPAID_DAYS_ENV);
    }
    if (!missing.includes(FIRST_PARTY_RETENTION_PAID_DAYS_ENV) && paidDays === null) {
      invalid.push(FIRST_PARTY_RETENTION_PAID_DAYS_ENV);
    }
    if (!HEX_40.test(deploymentSha)) invalid.push('ACTIVATION_BUILD_IDENTITY');
    for (const name of SOURCE_SECRETS) if (!missing.includes(name) && !validSecret(env[name])) invalid.push(name);
    const fenceConfiguration = retentionGenerationFenceConfiguration(env);
    for (const name of fenceConfiguration.missing) missing.push(name);
    for (const name of fenceConfiguration.invalid) invalid.push(name);
    const suppliedSecrets = [secret, env[RETENTION_GENERATION_FENCE_SECRET_ENV],
      ...SOURCE_SECRETS.map((name) => env[name])]
      .filter((value) => typeof value === 'string' && value.length > 0);
    if (new Set(suppliedSecrets).size !== suppliedSecrets.length) invalid.push('FIRST_PARTY_RETENTION_SECRET_SEPARATION');
  }
  return Object.freeze({
    requested,
    enabled: requested && missing.length === 0 && invalid.length === 0,
    missing: Object.freeze([...new Set(missing)].sort()),
    invalid: Object.freeze([...new Set(invalid)].sort()),
    unpaid_days: unpaidDays,
    paid_days: paidDays,
    deployment_sha: HEX_40.test(deploymentSha) ? deploymentSha : null,
  });
}

function requireConfiguration(env) {
  const configuration = firstPartyRetentionConfiguration(env);
  if (!configuration.enabled) throw new Error('ARC_FIRST_PARTY_RETENTION_DISABLED');
  return { ...configuration, secret: env[FIRST_PARTY_RETENTION_HMAC_SECRET_ENV] };
}

export function validateFirstPartyRetentionReceipt(value, env = process.env, options = {}) {
  const configuration = requireConfiguration(env);
  if (!exactKeys(value, RECEIPT_FIELDS) || value.schema !== FIRST_PARTY_RETENTION_RECEIPT_SCHEMA ||
      value.version !== 1 || !HEX_64.test(value.sweep_hmac_sha256 || '') ||
      value.deployment_sha !== configuration.deployment_sha || value.customer_data_stored !== false ||
      JSON.stringify(value.families) !== JSON.stringify(FAMILIES) || !validCounts(value.counts)) {
    throw new TypeError('First-party retention receipt is invalid.');
  }
  const started = iso(value.started_at, 'First-party retention receipt started_at');
  const completed = iso(value.completed_at, 'First-party retention receipt completed_at');
  const next = iso(value.next_sweep_at, 'First-party retention receipt next_sweep_at');
  if (completed < started || next - completed !== FIRST_PARTY_RETENTION_INTERVAL_MS) {
    throw new TypeError('First-party retention receipt timing is invalid.');
  }
  verify(value, 'arc-first-party-retention-completion-record-v1', configuration.secret);
  if (options.current === true) {
    const now = new Date(options.now || new Date()).getTime();
    if (!Number.isFinite(now) || completed > now + 60_000 || next <= now) {
      throw new Error('ARC_FIRST_PARTY_RETENTION_RECEIPT_STALE');
    }
  }
  return value;
}

export function firstPartyRetentionReceiptFromEnvironment(env = process.env, now = new Date()) {
  if (typeof env[FIRST_PARTY_RETENTION_RECEIPT_ENV] !== 'string' ||
      Buffer.byteLength(env[FIRST_PARTY_RETENTION_RECEIPT_ENV], 'utf8') > 32_768) return null;
  let value;
  try { value = JSON.parse(env[FIRST_PARTY_RETENTION_RECEIPT_ENV]); } catch { return null; }
  try { return validateFirstPartyRetentionReceipt(value, env, { current: true, now }); } catch { return null; }
}

export function firstPartyLegalHoldKey(family, subjectHmac) {
  if (!FAMILIES.includes(family) || !HEX_64.test(subjectHmac || '')) throw new TypeError('Retention legal hold identity is invalid.');
  return `first-party-retention/legal-holds/${family}/${subjectHmac}`;
}

export function buildFirstPartyLegalHoldRecord(input, env = process.env) {
  const configuration = requireConfiguration(env);
  if (!input || !FAMILIES.includes(input.family) || !HEX_64.test(input.subject_hmac_sha256 || '') ||
      !['DISPUTE', 'FRAUD', 'LEGAL', 'SECURITY', 'TAX'].includes(input.reason_code)) {
    throw new TypeError('Retention legal hold is invalid.');
  }
  const issuedAt = iso(input.issued_at, 'Retention legal hold issued_at');
  const expiresAt = input.expires_at === null ? null : iso(input.expires_at, 'Retention legal hold expires_at');
  if (expiresAt !== null && expiresAt <= issuedAt) throw new TypeError('Retention legal hold lifetime is invalid.');
  return sign({
    schema: 'arc-first-party-retention-legal-hold-v1', version: 1,
    family: input.family, subject_hmac_sha256: input.subject_hmac_sha256,
    reason_code: input.reason_code, issued_at: input.issued_at, expires_at: input.expires_at,
    customer_data_stored: false,
  }, 'arc-first-party-retention-legal-hold-record-v1', configuration.secret);
}

export function validateFirstPartyLegalHoldRecord(value, env = process.env, options = {}) {
  const secret = env[FIRST_PARTY_RETENTION_HMAC_SECRET_ENV];
  const fields = ['customer_data_stored', 'expires_at', 'family', 'issued_at',
    'reason_code', 'record_hmac_sha256', 'schema', 'subject_hmac_sha256', 'version'];
  if (!validSecret(secret) || !exactKeys(value, fields) ||
      value.schema !== 'arc-first-party-retention-legal-hold-v1' || value.version !== 1 ||
      !FAMILIES.includes(value.family) || !HEX_64.test(value.subject_hmac_sha256 || '') ||
      !['DISPUTE', 'FRAUD', 'LEGAL', 'SECURITY', 'TAX'].includes(value.reason_code) ||
      value.customer_data_stored !== false) {
    throw new TypeError('First-party retention legal hold record is invalid.');
  }
  const issuedAt = iso(value.issued_at, 'Retention legal hold issued_at');
  const expiresAt = value.expires_at === null
    ? null : iso(value.expires_at, 'Retention legal hold expires_at');
  if (expiresAt !== null && expiresAt <= issuedAt) {
    throw new TypeError('Retention legal hold lifetime is invalid.');
  }
  verify(value, 'arc-first-party-retention-legal-hold-record-v1', secret);
  const now = new Date(options.now === undefined ? new Date() : options.now);
  if (!Number.isFinite(now.getTime())) throw new TypeError('Retention legal hold validation clock is invalid.');
  return Object.freeze({ record: value, active: expiresAt === null || expiresAt > now.getTime() });
}

export function paidHandoffRetentionReleaseKey(handoffId) {
  if (!HEX_64.test(handoffId || '')) throw new TypeError('Paid handoff retention release identity is invalid.');
  return `first-party-retention/paid-handoff-releases/${handoffId}`;
}

export function buildPaidHandoffRetentionRelease(input, env = process.env) {
  const configuration = requireConfiguration(env);
  if (!input || !HEX_64.test(input.handoff_id || '') || !HEX_64.test(input.source_record_sha256 || '') ||
      !HEX_64.test(input.provider_evidence_sha256 || '') || !HEX_64.test(input.adult_approval_hmac_sha256 || '') ||
      input.legal_hold !== false || input.netlify_transfer_verified !== true ||
      input.payment_retention_complete !== true || input.tax_retention_complete !== true ||
      input.dispute_refund_retention_complete !== true) {
    throw new TypeError('Paid handoff retention release is invalid.');
  }
  const issuedAt = iso(input.issued_at, 'Paid handoff retention release issued_at');
  const expiresAt = iso(input.expires_at, 'Paid handoff retention release expires_at');
  if (expiresAt <= issuedAt || expiresAt - issuedAt > 24 * 60 * 60_000) {
    throw new TypeError('Paid handoff retention release lifetime is invalid.');
  }
  return sign({
    schema: 'arc-first-party-paid-handoff-retention-release-v1', version: 1,
    handoff_id: input.handoff_id, source_record_sha256: input.source_record_sha256,
    provider_evidence_sha256: input.provider_evidence_sha256,
    adult_approval_hmac_sha256: input.adult_approval_hmac_sha256,
    legal_hold: false, netlify_transfer_verified: true, payment_retention_complete: true,
    tax_retention_complete: true, dispute_refund_retention_complete: true,
    issued_at: input.issued_at, expires_at: input.expires_at, customer_data_stored: false,
  }, 'arc-first-party-paid-handoff-retention-release-record-v1', configuration.secret);
}

function validateState(value, secret) {
  if (!exactKeys(value, STATE_FIELDS) || value.schema !== FIRST_PARTY_RETENTION_SWEEP_SCHEMA ||
      value.version !== 1 || !['IDLE', 'RUNNING', 'COMPLETE'].includes(value.status) ||
      !HEX_64.test(value.sweep_hmac_sha256 || '') || !HEX_40.test(value.deployment_sha || '') ||
      !Number.isSafeInteger(value.phase_index) || value.phase_index < 0 || value.phase_index > PHASES.length ||
      !(value.cursor === null || typeof value.cursor === 'string' && value.cursor.length <= 1_024) ||
      !validCounts(value.counts) || !Number.isSafeInteger(value.run_count) || value.run_count < 0) {
    throw new TypeError('First-party retention sweep state is invalid.');
  }
  const completed = nullableIso(value.completed_at, 'First-party retention completed_at');
  const next = nullableIso(value.next_sweep_at, 'First-party retention next_sweep_at');
  const lease = nullableIso(value.lease_expires_at, 'First-party retention lease_expires_at');
  iso(value.started_at, 'First-party retention started_at');
  if (value.status === 'RUNNING' && (!HEX_64.test(value.lease_hmac_sha256 || '') || lease === null) ||
      value.status !== 'RUNNING' && (value.lease_hmac_sha256 !== null || lease !== null) ||
      value.status === 'COMPLETE' && (value.phase_index !== PHASES.length || value.cursor !== null ||
        completed === null || next === null) ||
      value.status !== 'COMPLETE' && (value.phase_index >= PHASES.length || completed !== null || next !== null)) {
    throw new TypeError('First-party retention sweep state is inconsistent.');
  }
  verify(value, 'arc-first-party-retention-sweep-record-v1', secret);
  return value;
}

async function getEntry(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  return entry ? { value: entry.data, etag: entry.etag } : null;
}

async function getEntryUnderFence(context, store, key) {
  if (context?.freezeAuthority) await heartbeatFrozenAuthority(context);
  const entry = await getEntry(store, key);
  if (context?.freezeAuthority) await assertFrozenAuthority(context);
  return entry;
}

async function listEntries(store, prefix, afterKey, limit, fenceContext = null) {
  const listing = store.list({ prefix, paginate: true });
  const pages = listing && typeof listing[Symbol.asyncIterator] === 'function'
    ? listing : (async function *single() { yield await listing; })();
  const output = [];
  let prior = null;
  const iterator = pages[Symbol.asyncIterator]();
  while (true) {
    if (fenceContext?.freezeAuthority) await heartbeatFrozenAuthority(fenceContext);
    const step = await iterator.next();
    if (fenceContext?.freezeAuthority) await assertFrozenAuthority(fenceContext);
    if (step.done) break;
    const page = step.value;
    if (!page || !Array.isArray(page.blobs)) throw new Error('ARC_FIRST_PARTY_RETENTION_LIST_UNAVAILABLE');
    for (const blob of page.blobs) {
      if (!blob || typeof blob.key !== 'string' || !blob.key.startsWith(prefix) ||
          prior !== null && blob.key <= prior) throw new Error('ARC_FIRST_PARTY_RETENTION_LIST_INVALID');
      prior = blob.key;
      if (afterKey !== null && blob.key <= afterKey) continue;
      if (output.length >= limit) return { entries: output, next_cursor: output.at(-1)?.key || afterKey };
      output.push({ key: blob.key });
    }
  }
  return { entries: output, next_cursor: null };
}

async function scanEntries(store, prefix, visitor, limit = 500, fenceContext = null) {
  let cursor = null;
  do {
    const listed = await listEntries(store, prefix, cursor, limit, fenceContext);
    for (const item of listed.entries) {
      if (fenceContext?.freezeAuthority) await heartbeatFrozenAuthority(fenceContext);
      const entry = await getEntry(store, item.key);
      if (fenceContext?.freezeAuthority) await assertFrozenAuthority(fenceContext);
      if (await visitor(item.key, entry)) return true;
    }
    cursor = listed.next_cursor;
  } while (cursor !== null);
  return false;
}

function tombstoneSourceKeyHmac(key, secret) {
  return hmac(secret, `arc-first-party-retention-source-key-v1\n${key}`);
}

function validateRetentionTombstone(value, context, family, key, expectedRecordSha256 = null) {
  if (!exactKeys(value, TOMBSTONE_FIELDS) || value.schema !== FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA ||
      value.version !== 1 || value.family !== family || !FAMILIES.includes(value.family) ||
      value.source_key_hmac_sha256 !== tombstoneSourceKeyHmac(key, context.configuration.secret) ||
      !HEX_64.test(value.source_record_sha256 || '') || !HEX_64.test(value.sweep_hmac_sha256 || '') ||
      value.customer_data_stored !== false ||
      expectedRecordSha256 !== null && value.source_record_sha256 !== expectedRecordSha256) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_TOMBSTONE_INVALID');
  }
  iso(value.tombstoned_at, 'Retention tombstone tombstoned_at');
  verify(value, 'arc-first-party-retention-tombstone-record-v1', context.configuration.secret);
  return value;
}

function isRetentionTombstone(value) {
  return value?.schema === FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA;
}

function buildRetentionTombstone(context, family, key, sourceRecordSha256) {
  return sign({
    schema: FIRST_PARTY_RETENTION_TOMBSTONE_SCHEMA,
    version: 1,
    sweep_hmac_sha256: context.sweep,
    family,
    source_key_hmac_sha256: tombstoneSourceKeyHmac(key, context.configuration.secret),
    source_record_sha256: sourceRecordSha256,
    tombstoned_at: context.startedAt,
    customer_data_stored: false,
  }, 'arc-first-party-retention-tombstone-record-v1', context.configuration.secret);
}

async function cascadeSourceUnderFreeze(context, family, store, key, expectedRecordSha256) {
  await heartbeatFrozenAuthority(context);
  const current = await getEntry(store, key);
  await assertFrozenAuthority(context);
  if (!current) {
    await persistMissingSourceAnomaly(
      context, family, store, key, expectedRecordSha256, 'MARKED_SOURCE_MISSING_BEFORE_TOMBSTONE',
    );
    return { deleted: 0, held: 1 };
  }
  if (isRetentionTombstone(current.value)) {
    try {
      validateRetentionTombstone(current.value, context, family, key, expectedRecordSha256);
      return { deleted: 0 };
    } catch {
      const quarantined = await quarantine(
        context, family, key, current.value, 'RETENTION_TOMBSTONE_INVALID', store,
      );
      return { deleted: 0, held: 1, ...quarantined };
    }
  }
  if (!HEX_64.test(expectedRecordSha256 || '') || recordSha(current.value) !== expectedRecordSha256) {
    const quarantined = await quarantine(
      context, family, key, current.value, 'SOURCE_CHANGED_BEFORE_RETENTION_TOMBSTONE', store,
    );
    return { deleted: 0, held: 1, ...quarantined };
  }
  const tombstone = buildRetentionTombstone(context, family, key, expectedRecordSha256);
  await heartbeatFrozenAuthority(context);
  const fenced = await store.setJSON(key, tombstone, { onlyIfMatch: current.etag });
  await assertFrozenAuthority(context);
  if (!fenced?.modified) {
    await heartbeatFrozenAuthority(context);
    const raced = await getEntry(store, key);
    await assertFrozenAuthority(context);
    if (raced && isRetentionTombstone(raced.value)) {
      try {
        validateRetentionTombstone(raced.value, context, family, key, expectedRecordSha256);
        return { deleted: 0 };
      } catch {}
    }
    if (!raced) {
      await persistMissingSourceAnomaly(
        context, family, store, key, expectedRecordSha256,
        'MARKED_SOURCE_MISSING_DURING_TOMBSTONE',
      );
      return { deleted: 0, held: 1 };
    }
    const quarantined = await quarantine(
      context, family, key, raced.value, 'SOURCE_CHANGED_DURING_RETENTION_TOMBSTONE', store,
    );
    return { deleted: 0, held: 1, ...quarantined };
  }
  await heartbeatFrozenAuthority(context);
  const stored = await getEntry(store, key);
  await assertFrozenAuthority(context);
  if (!stored) {
    await persistMissingSourceAnomaly(
      context, family, store, key, expectedRecordSha256,
      'TOMBSTONE_READBACK_MISSING',
    );
    return { deleted: 0, held: 1 };
  }
  if (canonicalJson(validateRetentionTombstone(
    stored.value, context, family, key, expectedRecordSha256,
  )) !== canonicalJson(tombstone)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_TOMBSTONE_UNAVAILABLE');
  }
  return { deleted: 1 };
}

function retentionSubjectHmac(context, family, subject) {
  return hmac(context.env[RETENTION_GENERATION_FENCE_SECRET_ENV],
    `arc-first-party-retention-subject-id-v1\n${family}\n${subject}`);
}

function retentionManifestKey(generation, subjectHmac, manifestSha256) {
  return `first-party-retention/generation-manifests/${generation}/${subjectHmac}/${manifestSha256}`;
}

function normalizedManifestMutations(context, mutations) {
  if (!Array.isArray(mutations) || mutations.length < 1 || mutations.length > 1_000_000) {
    throw new TypeError('First-party retention subject manifest is invalid.');
  }
  const seen = new Set();
  return mutations.map((mutation) => {
    const store = mutation.storeName || retentionStoreName(context, mutation.store);
    if (!['abuse', 'alerts', 'handoff', 'payment', 'review', 'revision'].includes(store) ||
        typeof mutation.key !== 'string' || mutation.key.length < 1 || mutation.key.length > 1_024 ||
        !['TOMBSTONE', 'REWRITE', 'PRESERVE'].includes(mutation.action) ||
        !['PRIMARY', 'CHILD'].includes(mutation.role) ||
        !HEX_64.test(mutation.sourceRecordSha256 || '') ||
        !HEX_64.test(mutation.outputRecordSha256 || '')) {
      throw new TypeError('First-party retention manifest entry is invalid.');
    }
    const identity = `${store}\n${mutation.key}`;
    if (seen.has(identity)) throw new TypeError('First-party retention manifest has a duplicate source.');
    seen.add(identity);
    return { ...mutation, storeName: store };
  }).sort((left, right) => left.storeName.localeCompare(right.storeName) || left.key.localeCompare(right.key));
}

async function persistSubjectManifest(context, generation, family, subject, mutations) {
  const subjectHmac = retentionSubjectHmac(context, family, subject);
  const entries = mutations.map((mutation) => ({
    action: mutation.action,
    family: mutation.family || family,
    output_record_sha256: mutation.outputRecordSha256,
    role: mutation.role,
    source_key: mutation.key,
    source_record_sha256: mutation.sourceRecordSha256,
    store: mutation.storeName,
  }));
  const value = sign({
    schema: RETENTION_SUBJECT_MANIFEST_SCHEMA,
    version: 1,
    generation,
    sweep_hmac_sha256: context.sweep,
    family,
    subject_hmac_sha256: subjectHmac,
    entries,
    built_at: context.startedAt,
    customer_data_stored: false,
  }, 'arc-first-party-retention-subject-manifest-record-v1',
  context.env[RETENTION_GENERATION_FENCE_SECRET_ENV]);
  if (!exactKeys(value, RETENTION_SUBJECT_MANIFEST_FIELDS) ||
      !value.entries.every((entry) => exactKeys(entry, RETENTION_SUBJECT_MANIFEST_ENTRY_FIELDS))) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_SUBJECT_MANIFEST_INVALID');
  }
  const digest = recordSha(value);
  await ensureImmutableSigned(context.stores.control,
    retentionManifestKey(generation, subjectHmac, digest), unsigned(value),
    'arc-first-party-retention-subject-manifest-record-v1',
    context.env[RETENTION_GENERATION_FENCE_SECRET_ENV]);
  const stored = await getEntry(context.stores.control,
    retentionManifestKey(generation, subjectHmac, digest));
  if (!stored || canonicalJson(stored.value) !== canonicalJson(value)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_SUBJECT_MANIFEST_READBACK_INVALID');
  }
  return { value, digest, subjectHmac };
}

function validateSubjectManifest(value, intent, env) {
  if (!exactKeys(value, RETENTION_SUBJECT_MANIFEST_FIELDS) ||
      value.schema !== RETENTION_SUBJECT_MANIFEST_SCHEMA || value.version !== 1 ||
      value.generation !== intent.generation ||
      value.subject_hmac_sha256 !== intent.subject_hmac_sha256 ||
      !HEX_64.test(value.sweep_hmac_sha256 || '') ||
      !['intake_abuse', 'review', 'checkout', 'handoff'].includes(value.family) ||
      !Array.isArray(value.entries) || value.entries.length !== intent.manifest_entry_count ||
      value.customer_data_stored !== false) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_SUBJECT_MANIFEST_INVALID');
  }
  iso(value.built_at, 'Retention subject manifest built_at');
  let prior = '';
  for (const entry of value.entries) {
    if (!exactKeys(entry, RETENTION_SUBJECT_MANIFEST_ENTRY_FIELDS) ||
        !['TOMBSTONE', 'REWRITE', 'PRESERVE'].includes(entry.action) ||
        !['PRIMARY', 'CHILD'].includes(entry.role) ||
        !FAMILIES.includes(entry.family) ||
        !['abuse', 'alerts', 'handoff', 'payment', 'review', 'revision'].includes(entry.store) ||
        typeof entry.source_key !== 'string' || entry.source_key.length < 1 ||
        !HEX_64.test(entry.source_record_sha256 || '') ||
        !HEX_64.test(entry.output_record_sha256 || '')) {
      throw new Error('ARC_FIRST_PARTY_RETENTION_SUBJECT_MANIFEST_ENTRY_INVALID');
    }
    const identity = `${entry.store}\n${entry.source_key}`;
    if (prior && prior.localeCompare(identity) >= 0) {
      throw new Error('ARC_FIRST_PARTY_RETENTION_SUBJECT_MANIFEST_ORDER_INVALID');
    }
    prior = identity;
  }
  verify(value, 'arc-first-party-retention-subject-manifest-record-v1',
    env[RETENTION_GENERATION_FENCE_SECRET_ENV]);
  if (recordSha(value) !== intent.manifest_sha256) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_SUBJECT_MANIFEST_DIGEST_INVALID');
  }
  return value;
}

async function assertFrozenAuthority(context) {
  if (!context.freezeDescriptor || !context.freezeAuthority) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_FROZEN_AUTHORITY_MISSING');
  }
  return assertRetentionGenerationFenceAuthority(
    context.stores.control, context.freezeAuthority, context.env,
  );
}

function liveFenceClock(context) {
  const supplied = context.adapters?.clock ? context.adapters.clock() : new Date();
  const value = supplied instanceof Date ? new Date(supplied.getTime()) : new Date(supplied);
  if (!Number.isFinite(value.getTime())) {
    throw new TypeError('First-party retention live fence clock is invalid.');
  }
  return value;
}

async function heartbeatFrozenAuthority(context) {
  await assertFrozenAuthority(context);
  const renewed = await renewRetentionGenerationFenceAuthority(
    context.stores.control, context.freezeAuthority, context.env,
    { clock: () => liveFenceClock(context) },
  );
  context.freezeAuthority = renewed;
  return renewed;
}

async function readManifestOutputs(context, mutations, allowed, renewAuthority = true) {
  const output = [];
  for (const mutation of mutations) {
    if (renewAuthority) await heartbeatFrozenAuthority(context);
    else await assertFrozenAuthority(context);
    const entry = await getEntry(mutation.store, mutation.key);
    await assertFrozenAuthority(context);
    if (!entry) {
      await persistMissingSourceAnomaly({ ...context, freezeDescriptor: context.freezeDescriptor },
        mutation.family, mutation.store, mutation.key, mutation.sourceRecordSha256,
        'FROZEN_OUTPUT_READBACK_MISSING');
      throw new Error('ARC_FIRST_PARTY_RETENTION_FROZEN_OUTPUT_MISSING');
    }
    const expected = allowed ? mutation.outputRecordSha256 : mutation.sourceRecordSha256;
    if (recordSha(entry.value) !== expected) {
      throw new Error('ARC_FIRST_PARTY_RETENTION_FROZEN_OUTPUT_CHANGED');
    }
    output.push({ key: mutation.key, record_sha256: expected, store: mutation.storeName });
  }
  return recordSha(output);
}

async function runFrozenSubjectMutation(context, input) {
  const mutations = normalizedManifestMutations(context, input.mutations);
  let descriptor;
  let manifest;
  if (input.resumeDescriptor) {
    descriptor = input.resumeDescriptor;
    manifest = { value: input.persistedManifest };
  } else {
    const open = input.open || await ensureRetentionGenerationFence(context.stores.control, context.env,
      { clock: () => liveFenceClock(context) });
    if (open.record.status !== 'OPEN') {
      return { deleted: 0, held: 1, retryable: true, fence_state: open.record.status };
    }
    manifest = await persistSubjectManifest(
      context, open.record.generation, input.family, input.subject, mutations,
    );
    descriptor = {
      generation: open.record.generation,
      manifest_entry_count: mutations.length,
      manifest_sha256: manifest.digest,
      subject_hmac_sha256: manifest.subjectHmac,
    };
    if (context.adapters?.afterSubjectManifest) {
      await context.adapters.afterSubjectManifest(Object.freeze({ descriptor, manifest: manifest.value }));
    }
    const driftCheck = await readRetentionGenerationFence(context.stores.control, context.env);
    if (!driftCheck || driftCheck.record.status !== 'OPEN' ||
        driftCheck.record.generation !== open.record.generation) {
      return { deleted: 0, held: 1, retryable: true,
        fence_state: driftCheck?.record.status || 'MISSING' };
    }
  }
  const begun = await beginRetentionFreeze(context.stores.control, descriptor, context.env,
    { clock: () => liveFenceClock(context), emitCriticalAlert: context.adapters?.emitCriticalAlert });
  if (begun.retryable) return { deleted: 0, held: 1, retryable: true, fence_state: begun.state };
  if (begun.state === 'COMPLETE') {
    return { deleted: 0, held: 0, idempotent_replay: true };
  }
  const freezeAuthority = {
    status: 'FROZEN', generation: begun.generation,
    operation_hmac_sha256: begun.operation_hmac_sha256,
    intent_sha256: begun.intent_sha256,
    authority_etag: begun.authority_etag,
  };
  if (!freezeAuthority.authority_etag || !freezeAuthority.intent_sha256) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_FROZEN_AUTHORITY_UNAVAILABLE');
  }
  const frozenContext = { ...context, freezeDescriptor: descriptor,
    freezeAuthority };
  if (context.adapters?.afterSubjectFreeze) {
    await context.adapters.afterSubjectFreeze(Object.freeze({ descriptor, manifest: manifest.value }));
  }
  for (const mutation of mutations) {
    await heartbeatFrozenAuthority(frozenContext);
    const current = await getEntry(mutation.store, mutation.key);
    await assertFrozenAuthority(frozenContext);
    if (!current) {
      await persistMissingSourceAnomaly(frozenContext, mutation.family, mutation.store, mutation.key,
        mutation.sourceRecordSha256, 'FROZEN_MANIFEST_SOURCE_MISSING');
      return { deleted: 0, held: 1, missing_source: true };
    }
    const digest = recordSha(current.value);
    if (digest !== mutation.sourceRecordSha256 && digest !== mutation.outputRecordSha256) {
      throw new Error('ARC_FIRST_PARTY_RETENTION_FROZEN_MANIFEST_DRIFT');
    }
  }
  await heartbeatFrozenAuthority(frozenContext);
  const recheck = input.recheck ? await input.recheck(frozenContext, mutations) : true;
  await heartbeatFrozenAuthority(frozenContext);
  let allowed = recheck === true || recheck?.allowed === true;
  let mutationAuthorization = null;
  if (allowed && input.beforeMutate) {
    await heartbeatFrozenAuthority(frozenContext);
    mutationAuthorization = await input.beforeMutate(frozenContext, mutations);
    await heartbeatFrozenAuthority(frozenContext);
    if (mutationAuthorization === false || mutationAuthorization?.allowed === false) allowed = false;
  }
  if (allowed && input.beforePrimary && input.primaryAfterChildren !== true) {
    await heartbeatFrozenAuthority(frozenContext);
    if (!await input.beforePrimary(frozenContext, mutations)) allowed = false;
    await heartbeatFrozenAuthority(frozenContext);
  }
  const legalHoldDigest = recordSha({
    mutation_authorization: mutationAuthorization,
    recheck: recheck === true ? { allowed: true } : recheck,
  });
  let deleted = 0;
  if (allowed) {
    for (const mutation of mutations.filter((value) => value.role !== 'PRIMARY')) {
      if (mutation.action === 'PRESERVE') continue;
      if (mutation.action === 'TOMBSTONE') {
        const result = await cascadeSourceUnderFreeze(frozenContext, mutation.family,
          mutation.store, mutation.key, mutation.sourceRecordSha256);
        deleted += result.deleted || 0;
        if (result.held) return { deleted, held: 1, missing_source: true };
      } else {
        await heartbeatFrozenAuthority(frozenContext);
        const current = await getEntry(mutation.store, mutation.key);
        await assertFrozenAuthority(frozenContext);
        if (!current) {
          await persistMissingSourceAnomaly(frozenContext, mutation.family, mutation.store,
            mutation.key, mutation.sourceRecordSha256, 'FROZEN_REWRITE_SOURCE_MISSING');
          return { deleted, held: 1, missing_source: true };
        }
        if (recordSha(current.value) !== mutation.outputRecordSha256) {
          if (recordSha(current.value) !== mutation.sourceRecordSha256) {
            throw new Error('ARC_FIRST_PARTY_RETENTION_FROZEN_REWRITE_DRIFT');
          }
          await heartbeatFrozenAuthority(frozenContext);
          const result = await mutation.store.setJSON(mutation.key, mutation.output,
            { onlyIfMatch: current.etag });
          await assertFrozenAuthority(frozenContext);
          await heartbeatFrozenAuthority(frozenContext);
          const reread = await getEntry(mutation.store, mutation.key);
          await assertFrozenAuthority(frozenContext);
          if (!result?.modified && recordSha(reread?.value) !== mutation.outputRecordSha256) {
            throw new Error('ARC_FIRST_PARTY_RETENTION_FROZEN_REWRITE_CONTENTION');
          }
          if (!reread) {
            await persistMissingSourceAnomaly(frozenContext, mutation.family, mutation.store,
              mutation.key, mutation.sourceRecordSha256, 'FROZEN_REWRITE_READBACK_MISSING');
            return { deleted, held: 1, missing_source: true };
          }
          deleted += 1;
        }
      }
      if (context.adapters?.afterSubjectMutation) {
        await context.adapters.afterSubjectMutation(Object.freeze({
          action: mutation.action, key: mutation.key, role: mutation.role,
          store: mutation.storeName,
        }));
      }
    }
    for (const mutation of mutations.filter((value) => value.role === 'PRIMARY')) {
      if (input.beforePrimary && input.primaryAfterChildren === true) {
        await heartbeatFrozenAuthority(frozenContext);
        if (!await input.beforePrimary(frozenContext, mutations)) {
          await heartbeatFrozenAuthority(frozenContext);
          throw new Error('ARC_FIRST_PARTY_RETENTION_PRIMARY_CHILD_RESCAN_FAILED');
        }
        await heartbeatFrozenAuthority(frozenContext);
      }
      if (mutation.action === 'TOMBSTONE') {
        const result = await cascadeSourceUnderFreeze(frozenContext, mutation.family,
          mutation.store, mutation.key, mutation.sourceRecordSha256);
        deleted += result.deleted || 0;
        if (result.held) return { deleted, held: 1, missing_source: true };
      } else if (mutation.action === 'REWRITE') {
        await heartbeatFrozenAuthority(frozenContext);
        const current = await getEntry(mutation.store, mutation.key);
        await assertFrozenAuthority(frozenContext);
        if (!current) {
          await persistMissingSourceAnomaly(frozenContext, mutation.family, mutation.store,
            mutation.key, mutation.sourceRecordSha256, 'FROZEN_REWRITE_SOURCE_MISSING');
          return { deleted, held: 1, missing_source: true };
        }
        if (recordSha(current.value) !== mutation.outputRecordSha256) {
          if (recordSha(current.value) !== mutation.sourceRecordSha256) {
            throw new Error('ARC_FIRST_PARTY_RETENTION_FROZEN_REWRITE_DRIFT');
          }
          await heartbeatFrozenAuthority(frozenContext);
          const result = await mutation.store.setJSON(mutation.key, mutation.output,
            { onlyIfMatch: current.etag });
          await assertFrozenAuthority(frozenContext);
          await heartbeatFrozenAuthority(frozenContext);
          const reread = await getEntry(mutation.store, mutation.key);
          await assertFrozenAuthority(frozenContext);
          if (!result?.modified && recordSha(reread?.value) !== mutation.outputRecordSha256) {
            throw new Error('ARC_FIRST_PARTY_RETENTION_FROZEN_REWRITE_CONTENTION');
          }
          if (!reread) {
            await persistMissingSourceAnomaly(frozenContext, mutation.family, mutation.store,
              mutation.key, mutation.sourceRecordSha256, 'FROZEN_REWRITE_READBACK_MISSING');
            return { deleted, held: 1, missing_source: true };
          }
          deleted += 1;
        }
      }
      if (context.adapters?.afterSubjectMutation) {
        await context.adapters.afterSubjectMutation(Object.freeze({
          action: mutation.action, key: mutation.key, role: mutation.role,
          store: mutation.storeName,
        }));
      }
    }
  }
  const outputReadback = await readManifestOutputs(frozenContext, mutations, allowed);
  const tombstones = mutations.filter((value) => allowed && value.action === 'TOMBSTONE')
    .map((value) => value.outputRecordSha256).sort();
  const primary = mutations.find((value) => value.role === 'PRIMARY');
  const evidence = {
    legal_hold_recheck_sha256: legalHoldDigest,
    output_readback_sha256: outputReadback,
    primary_tombstone_sha256: allowed && primary?.action === 'TOMBSTONE'
      ? primary.outputRecordSha256 : recordSha(null),
    tombstone_set_sha256: recordSha(tombstones),
  };
  await heartbeatFrozenAuthority(frozenContext);
  const completed = await completeRetentionFreeze(context.stores.control, descriptor, evidence,
    context.env, {
      clock: () => liveFenceClock(frozenContext),
      authorityEtag: frozenContext.freezeAuthority.authority_etag,
      readback: () => readManifestOutputs(frozenContext, mutations, allowed, false),
    });
  if (completed.retryable) return { deleted, held: 1, retryable: true, fence_state: completed.state };
  return { deleted, held: allowed ? 0 : 1, finalized: true };
}

async function cascadeSource(context, family, store, key, expectedRecordSha256, options = {}) {
  if (context.freezeDescriptor) {
    return cascadeSourceUnderFreeze(context, family, store, key, expectedRecordSha256);
  }
  const open = await ensureRetentionGenerationFence(context.stores.control, context.env,
    { clock: () => liveFenceClock(context) });
  if (open.record.status !== 'OPEN') return { deleted: 0, held: 1, retryable: true };
  const tombstone = buildRetentionTombstone(context, family, key, expectedRecordSha256);
  return runFrozenSubjectMutation(context, {
    family,
    subject: options.subject || tombstoneSourceKeyHmac(key, context.configuration.secret),
    open,
    mutations: [{
      action: 'TOMBSTONE', family, key, output: tombstone,
      outputRecordSha256: recordSha(tombstone), role: options.role || 'PRIMARY',
      sourceRecordSha256: expectedRecordSha256, store,
    }],
    recheck: options.recheck,
    beforePrimary: options.beforePrimary,
  });
}

async function rewriteSource(context, family, store, key, source, output, options = {}) {
  const open = await ensureRetentionGenerationFence(context.stores.control, context.env,
    { clock: () => liveFenceClock(context) });
  if (open.record.status !== 'OPEN') return { deleted: 0, held: 1, retryable: true };
  return runFrozenSubjectMutation(context, {
    family,
    subject: options.subject || tombstoneSourceKeyHmac(key, context.configuration.secret),
    open,
    mutations: [{
      action: 'REWRITE', family, key, output,
      outputRecordSha256: recordSha(output), role: 'PRIMARY',
      sourceRecordSha256: recordSha(source), store,
    }],
    recheck: options.recheck,
  });
}

async function recordMissingMarkedSource(context, family, subject, store, key,
  expectedRecordSha256, reasonCode) {
  if (context.freezeDescriptor) {
    await persistMissingSourceAnomaly(context, family, store, key, expectedRecordSha256, reasonCode);
    return;
  }
  const open = await ensureRetentionGenerationFence(context.stores.control, context.env,
    { clock: () => liveFenceClock(context) });
  if (open.record.status !== 'OPEN') {
    await persistMissingSourceAnomaly(context, family, store, key, expectedRecordSha256, reasonCode);
    return;
  }
  const tombstone = buildRetentionTombstone(context, family, key, expectedRecordSha256);
  await runFrozenSubjectMutation(context, {
    family, subject, open,
    mutations: [{
      action: 'TOMBSTONE', family, key, output: tombstone,
      outputRecordSha256: recordSha(tombstone), role: 'PRIMARY',
      sourceRecordSha256: expectedRecordSha256, store,
    }],
    recheck: async () => ({ allowed: true, missing_source_rechecked: true }),
  });
}

const candidateKey = (sweep, family, id) => `first-party-retention/candidates/${sweep}/${family}/${id}`;
const recipientMarkerKey = (sweep, kind, recipient, secret) =>
  `first-party-retention/review-recipients/${sweep}/${kind}/${hmac(secret,
    `arc-first-party-retention-review-recipient-v1\n${recipient}`)}`;
const outboxCandidateKey = (sweep, outbox) => `first-party-retention/outboxes/${sweep}/${outbox}`;
const paymentCandidateKey = (sweep, payment) => `first-party-retention/payments/${sweep}/${payment}`;
const missingSourcePrefix = (sweep) => `first-party-retention/missing-source/${sweep}/`;

async function ensureImmutableSigned(control, key, value, domain, secret, fenceContext = null) {
  const expected = sign(value, domain, secret);
  if (fenceContext?.freezeAuthority) await heartbeatFrozenAuthority(fenceContext);
  try { await control.setJSON(key, expected, { onlyIfNew: true }); } catch {}
  if (fenceContext?.freezeAuthority) await assertFrozenAuthority(fenceContext);
  const entry = await getEntryUnderFence(fenceContext, control, key);
  if (!entry || canonicalJson(entry.value) !== canonicalJson(expected)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_EVIDENCE_CONFLICT');
  }
  return expected;
}

function retentionStoreName(context, store) {
  return Object.entries(context.stores).find(([, candidate]) => candidate === store)?.[0] || 'unknown';
}

async function persistMissingSourceAnomaly(context, family, store, key,
  expectedRecordSha256 = null, reasonCode = 'MARKED_SOURCE_MISSING') {
  if (context.freezeAuthority) await heartbeatFrozenAuthority(context);
  const sourceStore = retentionStoreName(context, store);
  const expected = expectedRecordSha256 === null ? null : String(expectedRecordSha256);
  if (expected !== null && !HEX_64.test(expected)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_MISSING_SOURCE_EXPECTATION_INVALID');
  }
  const sourceKeyHmac = tombstoneSourceKeyHmac(key, context.configuration.secret);
  const identity = hmac(context.configuration.secret,
    `arc-first-party-retention-missing-source-id-v1\n${canonicalJson({
      sweep_hmac_sha256: context.sweep,
      family,
      source_store: sourceStore,
      source_key_hmac_sha256: sourceKeyHmac,
      source_record_sha256: expected,
      reason_code: reasonCode,
    })}`);
  const sweepAnomaly = await ensureImmutableSigned(context.stores.control,
    `${missingSourcePrefix(context.sweep)}${identity}`, {
    schema: FIRST_PARTY_RETENTION_MISSING_SOURCE_SCHEMA,
    version: 1,
    sweep_hmac_sha256: context.sweep,
    family,
    source_store: sourceStore,
    source_key_hmac_sha256: sourceKeyHmac,
    source_record_sha256: expected,
    reason_code: reasonCode,
    detected_at: context.startedAt,
    customer_data_stored: false,
    }, 'arc-first-party-retention-sweep-missing-source-anomaly-record-v1', context.configuration.secret,
  context);
  if (context.freezeDescriptor) {
    const authorityEtag = context.freezeAuthority?.authority_etag ||
      (await readRetentionGenerationFence(context.stores.control, context.env))?.etag;
    await recordRetentionMissingSourceAnomaly(context.stores.control, context.freezeDescriptor, {
      expected_source_record_sha256: expected || recordSha(null),
      family,
      source_key_hmac_sha256: hmac(context.env[RETENTION_GENERATION_FENCE_SECRET_ENV],
        `arc-first-party-retention-fence-source-key-v1\n${sourceStore}\n${key}`),
    }, context.env, { authorityEtag, clock: () => liveFenceClock(context) });
  }
  return sweepAnomaly;
}

function validateMissingSourceAnomaly(value, context) {
  if (!exactKeys(value, MISSING_SOURCE_FIELDS) ||
      value.schema !== FIRST_PARTY_RETENTION_MISSING_SOURCE_SCHEMA || value.version !== 1 ||
      value.sweep_hmac_sha256 !== context.sweep || !FAMILIES.includes(value.family) ||
      !['abuse', 'alerts', 'control', 'handoff', 'payment', 'review', 'revision', 'unknown']
        .includes(value.source_store) ||
      !HEX_64.test(value.source_key_hmac_sha256 || '') ||
      !(value.source_record_sha256 === null || HEX_64.test(value.source_record_sha256 || '')) ||
      typeof value.reason_code !== 'string' || !/^[A-Z0-9_]{3,96}$/.test(value.reason_code) ||
      value.customer_data_stored !== false) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_MISSING_SOURCE_ANOMALY_INVALID');
  }
  iso(value.detected_at, 'Retention missing-source detected_at');
  verify(value, 'arc-first-party-retention-sweep-missing-source-anomaly-record-v1',
    context.configuration.secret);
  return value;
}

async function hasBlockingMissingSourceAnomaly(context) {
  const listed = await listEntries(context.stores.control, missingSourcePrefix(context.sweep), null, 1);
  for (const item of listed.entries) {
    const entry = await getEntry(context.stores.control, item.key);
    if (!entry) throw new Error('ARC_FIRST_PARTY_RETENTION_MISSING_SOURCE_ANOMALY_UNAVAILABLE');
    validateMissingSourceAnomaly(entry.value, context);
    return true;
  }
  return false;
}

async function auditMarkedCandidateSources(context) {
  const prefix = `first-party-retention/candidates/${context.sweep}/`;
  let missing = false;
  await scanEntries(context.stores.control, prefix, async (key, entry) => {
    if (!entry) {
      await persistMissingSourceAnomaly(context, 'review', context.stores.control, key, null,
        'CANDIDATE_MARKER_LISTED_SOURCE_MISSING');
      missing = true;
      return false;
    }
    const match = key.match(/^first-party-retention\/candidates\/[a-f0-9]{64}\/(checkout|review|handoff)\/([a-f0-9]{64})$/);
    if (!match) {
      missing = true;
      return false;
    }
    const [, family, subject] = match;
    const source = candidateSource(context, family, subject);
    if (!source) {
      missing = true;
      return false;
    }
    const current = await getEntry(source.store, source.key);
    if (!current) {
      await recordMissingMarkedSource(context, family, subject, source.store, source.key,
        entry.value?.source_record_sha256 || null, 'MARKED_CANDIDATE_SOURCE_MISSING_AT_FINALIZE');
      missing = true;
    }
    return false;
  });
  return missing;
}

const handoffChildPlanKey = (context, handoffId, storeName, key) =>
  `first-party-retention/handoff-child-plans/${context.sweep}/${handoffId}/${
    tombstoneSourceKeyHmac(`${storeName}\n${key}`, context.configuration.secret)}`;

async function persistHandoffChildPlan(context, handoffId, storeName, key, value,
  planAction, reasonCode, family) {
  if (context.freezeAuthority) await heartbeatFrozenAuthority(context);
  return ensureImmutableSigned(context.stores.control,
    handoffChildPlanKey(context, handoffId, storeName, key), {
      schema: 'arc-first-party-retention-handoff-child-plan-v1',
      version: 1,
      sweep_hmac_sha256: context.sweep,
      handoff_id: handoffId,
      family,
      source_store: storeName,
      source_key_hmac_sha256: tombstoneSourceKeyHmac(
        `${storeName}\n${key}`, context.configuration.secret),
      source_record_sha256: recordSha(value),
      plan_action: planAction,
      reason_code: reasonCode,
      marked_at: context.startedAt,
      customer_data_stored: false,
    }, 'arc-first-party-retention-handoff-child-plan-record-v1', context.configuration.secret,
  context);
}

async function readHandoffChildPlan(context, handoffId, storeName, key, expectedRecordSha256) {
  const entry = await getEntryUnderFence(context, context.stores.control,
    handoffChildPlanKey(context, handoffId, storeName, key));
  if (!entry) return null;
  const value = entry.value;
  if (!exactKeys(value, HANDOFF_CHILD_PLAN_FIELDS) ||
      value.schema !== 'arc-first-party-retention-handoff-child-plan-v1' || value.version !== 1 ||
      value.sweep_hmac_sha256 !== context.sweep || value.handoff_id !== handoffId ||
      value.source_store !== storeName ||
      value.source_key_hmac_sha256 !== tombstoneSourceKeyHmac(
        `${storeName}\n${key}`, context.configuration.secret) ||
      value.source_record_sha256 !== expectedRecordSha256 ||
      !['CASCADE', 'PRESERVE'].includes(value.plan_action) ||
      !['alerts', 'handoff', 'payment'].includes(value.source_store) ||
      typeof value.family !== 'string' || value.family.length < 1 || value.family.length > 96 ||
      typeof value.reason_code !== 'string' || !/^[A-Z0-9_]{3,96}$/.test(value.reason_code) ||
      value.customer_data_stored !== false) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_HANDOFF_CHILD_PLAN_INVALID');
  }
  iso(value.marked_at, 'Retention handoff child plan marked_at');
  verify(value, 'arc-first-party-retention-handoff-child-plan-record-v1', context.configuration.secret);
  return value;
}

async function markCandidate(context, family, id, source) {
  if (!HEX_64.test(id || '')) throw new Error('ARC_FIRST_PARTY_RETENTION_CANDIDATE_INVALID');
  await ensureImmutableSigned(context.stores.control, candidateKey(context.sweep, family, id), {
    schema: 'arc-first-party-retention-candidate-v1', version: 1,
    sweep_hmac_sha256: context.sweep, family, subject_hmac_sha256: id,
    source_record_sha256: recordSha(source), marked_at: context.startedAt, customer_data_stored: false,
  }, 'arc-first-party-retention-candidate-record-v1', context.configuration.secret);
}

async function candidateEvidence(context, family, id) {
  if (!HEX_64.test(id || '')) return null;
  const entry = await getEntryUnderFence(context, context.stores.control,
    candidateKey(context.sweep, family, id));
  if (!entry) return null;
  verify(entry.value, 'arc-first-party-retention-candidate-record-v1', context.configuration.secret);
  return exactKeys(entry.value, ['customer_data_stored', 'family', 'marked_at', 'record_hmac_sha256', 'schema',
    'source_record_sha256', 'subject_hmac_sha256', 'sweep_hmac_sha256', 'version']) &&
    entry.value.schema === 'arc-first-party-retention-candidate-v1' && entry.value.version === 1 &&
    entry.value.sweep_hmac_sha256 === context.sweep && entry.value.family === family &&
    entry.value.subject_hmac_sha256 === id && entry.value.customer_data_stored === false &&
    HEX_64.test(entry.value.source_record_sha256 || '') &&
    Number.isFinite(iso(entry.value.marked_at, 'Retention candidate marked_at')) ? entry.value : null;
}

async function hasCandidate(context, family, id, source) {
  if (!source || typeof source !== 'object') return false;
  const evidence = await candidateEvidence(context, family, id);
  return Boolean(evidence && evidence.source_record_sha256 === recordSha(source));
}

async function markRecipient(context, kind, recipient) {
  if (!['active', 'candidate'].includes(kind) || !HEX_64.test(recipient || '')) return;
  const key = recipientMarkerKey(context.sweep, kind, recipient, context.configuration.secret);
  await ensureImmutableSigned(context.stores.control, key, {
    schema: 'arc-first-party-retention-review-recipient-marker-v1', version: 1,
    sweep_hmac_sha256: context.sweep, marker: kind, marked_at: context.startedAt,
    customer_data_stored: false,
  }, 'arc-first-party-retention-review-recipient-marker-record-v1', context.configuration.secret);
}

async function recipientMarked(context, kind, recipient) {
  const entry = await getEntry(context.stores.control,
    recipientMarkerKey(context.sweep, kind, recipient, context.configuration.secret));
  if (!entry) return false;
  verify(entry.value, 'arc-first-party-retention-review-recipient-marker-record-v1', context.configuration.secret);
  return entry.value.sweep_hmac_sha256 === context.sweep && entry.value.marker === kind;
}

async function quarantine(context, family, key, value, reason, sourceStore = context.phaseStore) {
  const strongSource = sourceStore ? await getEntryUnderFence(context, sourceStore, key) : null;
  if (sourceStore && !strongSource) {
    await persistMissingSourceAnomaly(
      context, family, sourceStore, key, recordSha(value), 'LISTED_SOURCE_MISSING_DURING_QUARANTINE',
    );
    return { quarantined: 1, held: 1 };
  }
  if (strongSource && recordSha(strongSource.value) !== recordSha(value)) {
    value = strongSource.value;
    reason = 'SOURCE_CHANGED_DURING_RETENTION_REVIEW';
  }
  const sourceKeyHmac = hmac(context.configuration.secret, `arc-first-party-retention-source-key-v1\n${key}`);
  const sourceRecordSha = recordSha(value);
  const quarantineKey = `first-party-retention/quarantine/${family}/${sourceKeyHmac}/${sourceRecordSha}`;
  const current = await getEntryUnderFence(context, context.stores.control, quarantineKey);
  if (current) {
    verify(current.value, 'arc-first-party-retention-quarantine-record-v1', context.configuration.secret);
    if (current.value.family !== family || current.value.source_key_hmac_sha256 !== sourceKeyHmac ||
        current.value.source_record_sha256 !== sourceRecordSha || current.value.reason_code !== reason) {
      throw new Error('ARC_FIRST_PARTY_RETENTION_QUARANTINE_CONFLICT');
    }
    return { quarantined: 1 };
  }
  await ensureImmutableSigned(context.stores.control, quarantineKey, {
    schema: 'arc-first-party-retention-quarantine-v1', version: 1, family,
    source_key_hmac_sha256: sourceKeyHmac, source_record_sha256: sourceRecordSha,
    reason_code: reason, detected_at: context.now.toISOString(), customer_data_stored: false,
  }, 'arc-first-party-retention-quarantine-record-v1', context.configuration.secret, context);
  return { quarantined: 1 };
}

async function activeLegalHold(context, family, subject) {
  const entry = await getEntryUnderFence(context, context.stores.control,
    firstPartyLegalHoldKey(family, subject));
  if (!entry) return false;
  const value = entry.value;
  if (value.schema !== 'arc-first-party-retention-legal-hold-v1' || value.family !== family ||
      value.subject_hmac_sha256 !== subject || value.customer_data_stored !== false) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_INVALID');
  }
  verify(value, 'arc-first-party-retention-legal-hold-record-v1', context.configuration.secret);
  iso(value.issued_at, 'Retention legal hold issued_at');
  return value.expires_at === null || iso(value.expires_at, 'Retention legal hold expires_at') > context.now.getTime();
}

function verifySource(value, secret, domain) {
  return verify(value, domain, secret);
}

function baseResult(extra = {}) {
  return { candidates: 0, deleted: 0, held: 0, inspected: 1, quarantined: 0, ...extra };
}

async function handleAbuse(entry, context) {
  const { key, value } = entry;
  try {
    let expiresAt;
    let subject;
    if (key.startsWith('challenge-replay/') && value.schema === 'arc-intake-turnstile-replay-v1') {
      if (!/^challenge-replay\/[a-f0-9]{64}$/.test(key) ||
          !exactKeys(value, ['challenge_at', 'consumed_at', 'expires_at', 'request_hmac_sha256', 'schema']) ||
          !HEX_64.test(value.request_hmac_sha256 || '')) throw new Error('replay-invalid');
      const challengeAt = iso(value.challenge_at, 'Abuse replay challenge_at');
      const consumedAt = iso(value.consumed_at, 'Abuse replay consumed_at');
      expiresAt = iso(value.expires_at, 'Abuse replay expires_at');
      subject = value.request_hmac_sha256;
      if (consumedAt < challengeAt || expiresAt <= challengeAt) throw new Error('replay-order-invalid');
    } else if (key.startsWith('quota/') && value.schema === 'arc-intake-abuse-quota-slot-v1') {
      verifySource(value, context.env.ARC_INTAKE_ABUSE_HMAC_SECRET, 'arc-intake-abuse-quota-slot-v1');
      const match = key.match(/^quota\/(recipient|domain|global)\/([a-f0-9]{64})\/([^/]+)\/([0-9]{5})$/);
      if (!match || value.scope !== match[1] || value.identity_hmac_sha256 !== match[2] ||
          value.bucket_started_at !== match[3] || Number(match[4]) !== value.slot) throw new Error('quota-binding-invalid');
      expiresAt = iso(value.bucket_expires_at, 'Abuse quota expires_at');
      subject = value.identity_hmac_sha256;
    } else if (key.startsWith('suppression/') && value.schema === 'arc-intake-abuse-suppression-v1') {
      verifySource(value, context.env.ARC_INTAKE_ABUSE_HMAC_SECRET, 'arc-intake-abuse-suppression-v1');
      const match = key.match(/^suppression\/(recipient|domain)\/([a-f0-9]{64})$/);
      if (!match || value.scope !== match[1] || value.identity_hmac_sha256 !== match[2]) {
        throw new Error('suppression-binding-invalid');
      }
      if (value.reason_code === 'LEGAL') return baseResult({ held: 1 });
      expiresAt = iso(value.expires_at, 'Abuse suppression expires_at');
      subject = value.identity_hmac_sha256;
    } else if (key === 'circuit-breaker/current-v1' && value.schema === 'arc-intake-abuse-circuit-v1') {
      verifySource(value, context.env.ARC_INTAKE_ABUSE_HMAC_SECRET, 'arc-intake-abuse-circuit-v1');
      expiresAt = iso(value.expires_at, 'Abuse circuit expires_at');
      subject = tombstoneSourceKeyHmac(key, context.configuration.secret);
    } else {
      return { ...baseResult(), ...await quarantine(context, 'intake_abuse', key, value, 'UNKNOWN_OR_INVALID_RECORD') };
    }
    if (expiresAt > context.now.getTime()) return baseResult({ held: 1 });
    if (await activeLegalHold(context, 'intake_abuse', subject)) return baseResult({ held: 1 });
    return baseResult(await cascadeSource(
      context, 'intake_abuse', context.phaseStore, key, recordSha(value), {
        subject,
        recheck: async (frozenContext) => ({
          allowed: !await activeLegalHold(frozenContext, 'intake_abuse', subject) &&
            expiresAt <= frozenContext.now.getTime(),
          legal_holds_rechecked: [subject],
        }),
      },
    ));
  } catch {
    return { ...baseResult(), ...await quarantine(context, 'intake_abuse', key, value, 'SIGNATURE_OR_EXPIRY_INVALID') };
  }
}

function checkoutBindingId(record, env) {
  return hmac(env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET,
    `arc-review-checkout-revocable-binding-id-v1\n${record.approval_receipt_sha256}`);
}

function checkoutCandidateStateValid(value, id, context) {
  verifySource(value, context.env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET,
    'arc-review-checkout-revocable-binding-signature-v1');
  if (value.schema !== 'arc-review-checkout-revocable-binding-v1' || value.binding_hmac_sha256 !== id ||
      checkoutBindingId(value, context.env) !== id) return false;
  const terminalAt = value.expired_at || value.suppressed_at || value.created_at;
  return iso(terminalAt, 'Checkout terminal time') <= context.unpaidCutoff &&
    ['EXPIRED', 'CANCELLED'].includes(value.state) && value.fulfillment_halted === true &&
    (value.provider_payment_status === null || value.provider_payment_status === 'unpaid');
}

async function reviewCandidateStateValid(value, id, context) {
  verifySource(value, context.env.ARC_REVIEW_RECORD_HMAC_SECRET,
    'arc-preview-review-record-signature-v1');
  if (value.schema !== 'arc-preview-review-invite-v1' || value.invite_hmac_sha256 !== id ||
      !HEX_64.test(value.recipient_email_sha256 || '') ||
      iso(value.expires_at, 'Review expires_at') > context.unpaidCutoff) return false;
  if (value.state === 'OPEN' && value.decision === null) return true;
  if (!['APPROVED', 'REVISION_SUPERSEDED', 'REVOKED'].includes(value.state)) return false;
  if (value.decision?.action !== 'APPROVE_AND_PAY') return true;
  const bindingId = checkoutBindingId(value.decision, context.env);
  return currentOrCascadedCandidate(context, 'checkout', bindingId);
}

async function unresolvedDuplicatePaymentReview(context, handoffId) {
  return scanEntries(context.stores.handoff, 'duplicate-payment-review/', async (key, entry) => {
    if (!entry) {
      await persistMissingSourceAnomaly(context, 'handoff', context.stores.handoff, key, null,
        'DUPLICATE_REVIEW_LISTED_SOURCE_MISSING');
      return true;
    }
    return !isRetentionTombstone(entry.value) && entry.value?.winning_handoff_id === handoffId;
  }, 500, context);
}

async function anyNonTombstoned(context, store, family, prefix) {
  const listed = await listEntries(store, prefix, null, 500);
  if (listed.next_cursor !== null) return true;
  for (const item of listed.entries) {
    const entry = await getEntry(store, item.key);
    if (!entry) continue;
    if (!isRetentionTombstone(entry.value)) return true;
    try { validateRetentionTombstone(entry.value, context, family, item.key); } catch { return true; }
  }
  return false;
}

async function handoffIdForRawChild(context, key, value) {
  for (const candidate of [value?.handoff_id, value?.winning_handoff_id]) {
    if (HEX_64.test(candidate || '')) return candidate;
  }
  const keyed = key.match(/^(?:invitation-ready-current|stripe-reversal(?:-binding|-recheck)?\/handoff)\/([a-f0-9]{64})$/)?.[1];
  if (keyed) return keyed;
  let paymentIntent = value?.payment_intent_id_hmac_sha256 || null;
  if (!paymentIntent && key.startsWith('stripe-reversal-pending-payment/')) paymentIntent = key.split('/').at(-1);
  if (!paymentIntent && key.startsWith('stripe-reversal-pending/')) paymentIntent = key.split('/')[1];
  if (HEX_64.test(paymentIntent || '')) {
    const payment = await getEntryUnderFence(context, context.stores.handoff,
      `stripe-payment-intent/${paymentIntent}`);
    if (HEX_64.test(payment?.value?.handoff_id || '')) return payment.value.handoff_id;
  }
  const checkoutSession = value?.checkout_session_id_hmac_sha256 || null;
  if (HEX_64.test(checkoutSession || '')) {
    let matched = null;
    const ambiguous = await scanEntries(context.stores.handoff, 'stripe-checkout-handoff/',
      async (bindingKey, bindingEntry) => {
        if (!bindingEntry) {
          await persistMissingSourceAnomaly(context, 'handoff', context.stores.handoff,
            bindingKey, null, 'CHECKOUT_HANDOFF_LISTED_SOURCE_MISSING');
          return true;
        }
        if (isRetentionTombstone(bindingEntry.value) ||
            bindingEntry.value?.checkout_session_id_hmac_sha256 !== checkoutSession ||
            !HEX_64.test(bindingEntry.value?.handoff_id || '')) return false;
        if (matched && matched !== bindingEntry.value.handoff_id) return true;
        matched = bindingEntry.value.handoff_id;
        return false;
      }, 500, context);
    if (!ambiguous) return matched;
  }
  return null;
}

async function checkoutAlertBelongsToHandoff(context, key, value, handoffId) {
  const eventId = key.match(/^alerts\/stripe-checkout-review\/([a-f0-9]{64})$/)?.[1];
  if (!eventId || value?.subject_hmac_sha256 !== eventId) return false;
  const related = [];
  for (const prefix of ['stripe-checkout-event/', 'stripe-checkout-receipt/']) {
    const sourceKey = `${prefix}${eventId}`;
    const entry = await getEntryUnderFence(context, context.stores.handoff, sourceKey);
    if (!entry) {
      await persistMissingSourceAnomaly(context, 'handoff', context.stores.handoff,
        sourceKey, null, 'CHECKOUT_ALERT_EVENT_SOURCE_MISSING');
      continue;
    }
    if (isRetentionTombstone(entry.value)) continue;
    const session = entry.value?.checkout_session_id_hmac_sha256;
    if (HEX_64.test(session || '')) related.push(session);
  }
  const sessions = [...new Set(related)];
  if (sessions.length === 0) return false;
  if (sessions.length > 1) {
    await persistMissingSourceAnomaly(context, 'handoff', context.stores.handoff,
      `stripe-checkout-event/${eventId}`, null, 'CHECKOUT_ALERT_EVENT_BINDING_AMBIGUOUS');
  }
  return scanEntries(context.stores.handoff, 'stripe-checkout-handoff/', async (bindingKey, entry) => {
    if (!entry) {
      await persistMissingSourceAnomaly(context, 'handoff', context.stores.handoff,
        bindingKey, null, 'CHECKOUT_ALERT_HANDOFF_BINDING_SOURCE_MISSING');
      return false;
    }
    if (isRetentionTombstone(entry.value)) return false;
    return entry.value?.handoff_id === handoffId &&
      sessions.includes(entry.value?.checkout_session_id_hmac_sha256);
  }, 500, context);
}

async function handoffAlertBelongsTo(context, key, value, handoffId) {
  if (HEX_64.test(value?.handoff_id || '')) return value.handoff_id === handoffId;
  if (key.startsWith('alerts/stripe-checkout-review/')) {
    return checkoutAlertBelongsToHandoff(context, key, value, handoffId);
  }
  if (key.startsWith('alerts/stripe-reversal-unbound/')) {
    const eventId = key.match(/^alerts\/stripe-reversal-unbound\/([a-f0-9]{64})$/)?.[1];
    if (!eventId || value?.subject_hmac_sha256 !== eventId) return false;
    const eventKey = `stripe-reversal-event/${eventId}`;
    const event = await getEntryUnderFence(context, context.stores.handoff, eventKey);
    if (!event) {
      await persistMissingSourceAnomaly(context, 'handoff', context.stores.handoff,
        eventKey, null, 'REVERSAL_ALERT_EVENT_SOURCE_MISSING');
      return false;
    }
    if (isRetentionTombstone(event.value)) return false;
    return await handoffIdForRawChild(context, eventKey, event.value) === handoffId;
  }
  return false;
}

async function handoffSafetyBlocked(context, handoffId) {
  if (await getEntryUnderFence(context, context.stores.handoff,
    `stripe-reversal/handoff/${handoffId}`)) return true;
  for (const prefix of ['stripe-reversal-pending-payment/', 'stripe-reversal-pending/']) {
    if (await scanEntries(context.stores.handoff, prefix, async (key, entry) =>
      {
        if (!entry) {
          await persistMissingSourceAnomaly(context, 'handoff', context.stores.handoff,
            key, null, 'HANDOFF_SAFETY_LISTED_SOURCE_MISSING');
          return true;
        }
        return !isRetentionTombstone(entry.value) &&
          await handoffIdForRawChild(context, key, entry.value) === handoffId;
      }, 500, context)) return true;
  }
  for (const prefix of ['alerts/stripe-reversal/', 'alerts/stripe-reversal-unbound/',
    'alerts/stripe-checkout-review/']) {
    if (await scanEntries(context.stores.alerts, prefix, async (key, entry) => {
      if (!entry) {
        await persistMissingSourceAnomaly(context, 'handoff', context.stores.alerts,
          key, null, 'HANDOFF_ALERT_LISTED_SOURCE_MISSING');
        return true;
      }
      return !isRetentionTombstone(entry.value) &&
        await handoffAlertBelongsTo(context, key, entry.value, handoffId);
    }, 500, context)) return true;
  }
  return false;
}

function validateDuplicatePaymentReview(value, context, key = null, handoff = null) {
  const domain = {
    'arc2-duplicate-payment-review-v1': 'arc2-duplicate-payment-review-signature-v1',
    'arc2-review-duplicate-payment-review-v1': 'arc2-review-duplicate-payment-review-signature-v1',
  }[value?.schema];
  if (!domain || !exactKeys(value, DUPLICATE_PAYMENT_REVIEW_FIELDS) ||
      value.status !== 'CRITICAL_DUPLICATE_PAID_SESSION_REVIEW_REQUIRED' ||
      value.automatic_refund_requested !== false || !HEX_64.test(value.winning_handoff_id || '') ||
      ![value.checkout_reference_sha256, value.winning_checkout_session_id_hmac_sha256,
        value.duplicate_checkout_session_id_hmac_sha256, value.winning_payment_evidence_sha256,
        value.winning_artifact_evidence_sha256, value.duplicate_payment_evidence_sha256,
        value.review_hmac_sha256].every((field) => HEX_64.test(field || '')) ||
      value.winning_checkout_session_id_hmac_sha256 === value.duplicate_checkout_session_id_hmac_sha256 ||
      value.winning_payment_evidence_sha256 === value.duplicate_payment_evidence_sha256) {
    throw new Error('duplicate-payment-review-invalid');
  }
  const paymentLinks = [value.winning_payment_link_id_hmac_sha256, value.duplicate_payment_link_id_hmac_sha256];
  if (value.schema === 'arc2-review-duplicate-payment-review-v1'
    ? paymentLinks.some((field) => field !== null)
    : paymentLinks.some((field) => !HEX_64.test(field || ''))) {
    throw new Error('duplicate-payment-review-payment-link-invalid');
  }
  if (key !== null) {
    const digest = hmac(context.env.ARC_HANDOFF_STATE_SECRET,
      `duplicate-payment-review-key-v1\n${value.checkout_reference_sha256}\n${value.duplicate_checkout_session_id_hmac_sha256}`);
    if (key !== `duplicate-payment-review/${digest}`) throw new Error('duplicate-payment-review-key-invalid');
  }
  const { review_hmac_sha256: signature, ...unsignedReview } = value;
  if (!safeEqual(signature, hmac(context.env.ARC_HANDOFF_STATE_SECRET,
    `${domain}\n${canonicalJson(unsignedReview)}`))) throw new Error('duplicate-payment-review-signature-invalid');
  if (handoff && (value.winning_handoff_id !== handoff.handoff_id ||
      value.winning_payment_evidence_sha256 !== handoff.payment_evidence_sha256 ||
      value.winning_artifact_evidence_sha256 !== handoff.artifact_evidence_sha256)) {
    throw new Error('duplicate-payment-review-handoff-invalid');
  }
  return value.winning_handoff_id;
}

async function handoffCandidateStateValid(value, id, context) {
  const record = validateExpectedBindings(value);
  if (record.handoff_id !== id || record.state !== 'DELIVERED' ||
      iso(record.delivered_at || record.updated_at, 'Handoff retention time') > context.paidCutoff ||
      await activeLegalHold(context, 'handoff', id) || await unresolvedDuplicatePaymentReview(context, id) ||
      await handoffSafetyBlocked(context, id)) return false;
  for (const kind of ['claim_invitation', 'final_delivery']) {
    if (await getEntryUnderFence(context, context.stores.handoff,
      `arc2-email-negative-controls/by-handoff/${id}/${kind}`)) return false;
  }
  return !await getEntryUnderFence(context, context.stores.handoff,
    `stripe-reversal/handoff/${id}`) && await validatePaidRelease(context, record);
}

function candidateSource(context, family, id) {
  return {
    checkout: { store: context.stores.review, key: `review-checkout-binding/${id}` },
    review: { store: context.stores.review, key: `review-invites/${id}` },
    handoff: { store: context.stores.handoff, key: `handoffs/${id}` },
  }[family] || null;
}

async function currentCandidate(context, family, id) {
  const source = candidateSource(context, family, id);
  if (!source || !HEX_64.test(id || '')) return null;
  const evidence = await candidateEvidence(context, family, id);
  const current = await getEntryUnderFence(context, source.store, source.key);
  if (!current) {
    if (evidence) await recordMissingMarkedSource(context, family, id,
      source.store, source.key, evidence.source_record_sha256,
      'MARKED_CANDIDATE_SOURCE_MISSING');
    return null;
  }
  if (isRetentionTombstone(current.value)) return null;
  if (!evidence || evidence.source_record_sha256 !== recordSha(current.value)) {
    await quarantine(context, family, source.key, current.value, 'STALE_CANDIDATE_SOURCE_CHANGED', source.store);
    return null;
  }
  if (await activeLegalHold(context, family, id)) return null;
  let eligible = false;
  try {
    if (family === 'checkout') eligible = checkoutCandidateStateValid(current.value, id, context);
    else if (family === 'review') eligible = await reviewCandidateStateValid(current.value, id, context);
    else eligible = await handoffCandidateStateValid(current.value, id, context);
  } catch {
    eligible = false;
  }
  if (!eligible) {
    await quarantine(context, family, source.key, current.value, 'STALE_CANDIDATE_STATE_OR_RELEASE_CHANGED', source.store);
    return null;
  }
  return current;
}

async function currentOrCascadedCandidate(context, family, id) {
  const source = candidateSource(context, family, id);
  if (!source || !HEX_64.test(id || '')) return false;
  const evidence = await candidateEvidence(context, family, id);
  const current = await getEntryUnderFence(context, source.store, source.key);
  if (!current) {
    if (evidence) await recordMissingMarkedSource(context, family, id,
      source.store, source.key, evidence.source_record_sha256,
      'MARKED_CANDIDATE_SOURCE_MISSING');
    return false;
  }
  if (isRetentionTombstone(current.value)) {
    try {
      validateRetentionTombstone(current.value, context, family, source.key,
        evidence?.source_record_sha256 || null);
      return Boolean(evidence);
    } catch {
      await quarantine(context, family, source.key, current.value, 'RETENTION_TOMBSTONE_INVALID', source.store);
      return false;
    }
  }
  return Boolean(await currentCandidate(context, family, id));
}

async function cascadeRecordRemains(context, family, store, key) {
  const entry = await getEntryUnderFence(context, store, key);
  if (!entry) return false;
  if (!isRetentionTombstone(entry.value)) return true;
  try {
    validateRetentionTombstone(entry.value, context, family, key);
    return false;
  } catch {
    await quarantine(context, family, key, entry.value, 'RETENTION_TOMBSTONE_INVALID', store);
    return true;
  }
}

async function cascadeRecordCompleted(context, family, store, key) {
  const entry = await getEntryUnderFence(context, store, key);
  if (!entry) {
    await persistMissingSourceAnomaly(
      context, family, store, key, null, 'EXPECTED_CASCADE_SOURCE_MISSING',
    );
    return false;
  }
  if (!isRetentionTombstone(entry.value)) return false;
  try {
    validateRetentionTombstone(entry.value, context, family, key);
    return true;
  } catch {
    await quarantine(context, family, key, entry.value, 'RETENTION_TOMBSTONE_INVALID', store);
    return false;
  }
}

async function handleCheckoutCandidate(entry, context) {
  const { key, value } = entry;
  try {
    const id = key.match(/^review-checkout-binding\/([a-f0-9]{64})$/)?.[1];
    if (!id) throw new Error('binding-invalid');
    if (await activeLegalHold(context, 'checkout', id)) return baseResult({ held: 1 });
    const eligible = checkoutCandidateStateValid(value, id, context);
    if (eligible) {
      await markCandidate(context, 'checkout', id, value);
      return baseResult({ candidates: 1 });
    }
    const terminalAt = value.expired_at || value.suppressed_at || value.created_at;
    const old = iso(terminalAt, 'Checkout terminal time') <= context.unpaidCutoff;
    if (old && ['CREATING', 'OPEN', 'EXPIRY_PENDING'].includes(value.state)) {
      return { ...baseResult(), ...await quarantine(context, 'checkout', key, value, 'STALE_NONTERMINAL_CHECKOUT') };
    }
    return baseResult({ held: 1 });
  } catch {
    return { ...baseResult(), ...await quarantine(context, 'checkout', key, value, 'CHECKOUT_RECORD_INVALID') };
  }
}

async function handleReviewCandidate(entry, context) {
  const { key, value } = entry;
  const id = key.match(/^review-invites\/([a-f0-9]{64})$/)?.[1];
  try {
    if (!id) throw new Error('review-invalid');
    if (await activeLegalHold(context, 'review', id)) {
      await markRecipient(context, 'active', value.recipient_email_sha256);
      return baseResult({ held: 1 });
    }
    const old = iso(value.expires_at, 'Review expires_at') <= context.unpaidCutoff;
    const eligible = await reviewCandidateStateValid(value, id, context);
    if (eligible) {
      await markCandidate(context, 'review', id, value);
      await markRecipient(context, 'candidate', value.recipient_email_sha256);
      return baseResult({ candidates: 1 });
    }
    await markRecipient(context, 'active', value.recipient_email_sha256);
    if (old && ['REVISION_REQUESTED'].includes(value.state)) {
      return { ...baseResult(), ...await quarantine(context, 'review', key, value, 'STALE_REVISION_WORK') };
    }
    return baseResult({ held: 1 });
  } catch {
    return { ...baseResult(), ...await quarantine(context, 'review', key, value, 'REVIEW_RECORD_INVALID') };
  }
}

async function cascadeCandidatesRemainAuthorized(context, family, subjects, extraRecheck = null) {
  const uniqueSubjects = [...new Set(subjects)].filter((subject) => HEX_64.test(subject || '')).sort();
  if (uniqueSubjects.length !== subjects.length) {
    return { allowed: false, legal_holds_rechecked: uniqueSubjects };
  }
  for (const subject of uniqueSubjects) {
    if (await activeLegalHold(context, family, subject)) {
      return { allowed: false, legal_holds_rechecked: uniqueSubjects };
    }
  }
  for (const subject of uniqueSubjects) {
    if (!await currentCandidate(context, family, subject)) {
      return { allowed: false, legal_holds_rechecked: uniqueSubjects };
    }
  }
  return {
    allowed: extraRecheck ? Boolean(await extraRecheck(context)) : true,
    legal_holds_rechecked: uniqueSubjects,
  };
}

async function handleRevisionWork(entry, context) {
  const { key, value } = entry;
  try {
    verifySource(value, context.env.ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET,
      'arc-preview-review-revision-work-record-v2');
    const id = key.match(/^review-revision-work\/([a-f0-9]{64})$/)?.[1];
    if (!id || value.schema !== 'arc-preview-review-revision-work-v2' || value.work_hmac_sha256 !== id ||
        !HEX_64.test(value.source_invite_hmac_sha256 || '')) throw new Error('revision-invalid');
    const old = iso(value.completed_at || value.reserved_at, 'Revision retention time') <= context.unpaidCutoff;
    if (value.state === 'COMPLETED' && old &&
        await currentCandidate(context, 'review', value.source_invite_hmac_sha256) &&
        await currentCandidate(context, 'review', value.successor_invite_hmac_sha256)) {
      const subjects = [value.source_invite_hmac_sha256, value.successor_invite_hmac_sha256];
      return baseResult(await cascadeSource(context, 'review', context.phaseStore, key, recordSha(value), {
        subject: value.source_invite_hmac_sha256,
        recheck: (frozenContext) =>
          cascadeCandidatesRemainAuthorized(frozenContext, 'review', subjects),
      }));
    }
    if (old && value.state !== 'COMPLETED') {
      return { ...baseResult(), ...await quarantine(context, 'review', key, value, 'STALE_NONTERMINAL_REVISION') };
    }
    return baseResult({ held: 1 });
  } catch {
    return { ...baseResult(), ...await quarantine(context, 'review', key, value, 'REVISION_RECORD_INVALID') };
  }
}

async function handleRevisionPending(entry, context) {
  const { key, value } = entry;
  try {
    verifySource(value, context.env.ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET,
      'arc-preview-review-revision-pending-signature-v1');
    const id = key.match(/^review-revision-pending\/([a-f0-9]{64})$/)?.[1];
    if (!id || value.schema !== 'arc-preview-review-revision-pending-v1' || value.work_hmac_sha256 !== id ||
        !await currentCandidate(context, 'review', value.source_invite_hmac_sha256)) return baseResult({ held: 1 });
    if (await cascadeRecordRemains(context, 'review', context.phaseStore,
      `review-revision-work/${id}`)) return baseResult({ held: 1 });
    return baseResult(await cascadeSource(context, 'review', context.phaseStore, key, recordSha(value), {
      subject: value.source_invite_hmac_sha256,
      recheck: (frozenContext) => cascadeCandidatesRemainAuthorized(
        frozenContext, 'review', [value.source_invite_hmac_sha256],
        async (authorizedContext) => !await cascadeRecordRemains(
          authorizedContext, 'review', authorizedContext.phaseStore, `review-revision-work/${id}`,
        ),
      ),
    }));
  } catch {
    return { ...baseResult(), ...await quarantine(context, 'review', key, value, 'REVISION_PENDING_INVALID') };
  }
}

async function handleReviewOutbox(entry, context) {
  const { key, value } = entry;
  try {
    verifySource(value, context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
      'arc-preview-review-email-outbox-record-signature-v1');
    const id = key.match(/^review-email-outbox\/([a-f0-9]{64})$/)?.[1];
    if (!id || !exactKeys(value, REVIEW_OUTBOX_FIELDS) ||
        value.schema !== 'arc-preview-review-email-outbox-v1' || value.outbox_hmac_sha256 !== id) {
      throw new Error('outbox-invalid');
    }
    if (!await currentCandidate(context, 'review', value.invite_hmac_sha256)) return baseResult({ held: 1 });
    const old = iso(value.terminal_at || value.expires_at, 'Review outbox retention time') <= context.unpaidCutoff;
    if (!old || !['DELIVERED', 'BOUNCED', 'COMPLAINED'].includes(value.state)) {
      if (old) return { ...baseResult(), ...await quarantine(context, 'review', key, value, 'STALE_NONTERMINAL_OUTBOX') };
      return baseResult({ held: 1 });
    }
    await ensureImmutableSigned(context.stores.control, outboxCandidateKey(context.sweep, id), {
      schema: 'arc-first-party-retention-outbox-candidate-v1', version: 1,
      sweep_hmac_sha256: context.sweep, outbox_hmac_sha256: id,
      invite_hmac_sha256: value.invite_hmac_sha256, source_record_sha256: recordSha(value),
      marked_at: context.startedAt, customer_data_stored: false,
    }, 'arc-first-party-retention-outbox-candidate-record-v1', context.configuration.secret);
    if (!await currentCandidate(context, 'review', value.invite_hmac_sha256)) return baseResult({ held: 1 });
    if (!await cascadeRecordCompleted(context, 'review', context.phaseStore,
      `review-email-provider-event/${value.provider_event_id_hmac_sha256}`) ||
        !await cascadeRecordCompleted(context, 'review', context.phaseStore,
          `review-email-provider-message/${value.provider_message_id_hmac_sha256}`)) {
      return { ...baseResult({ held: 1 }), ...await quarantine(
        context, 'review', key, value, 'REVIEW_PROVIDER_CASCADE_INCOMPLETE',
      ) };
    }
    return baseResult(await cascadeSource(context, 'review', context.phaseStore, key, recordSha(value), {
      subject: value.invite_hmac_sha256,
      recheck: (frozenContext) => cascadeCandidatesRemainAuthorized(
        frozenContext, 'review', [value.invite_hmac_sha256], async (authorizedContext) =>
          await cascadeRecordCompleted(authorizedContext, 'review', authorizedContext.phaseStore,
            `review-email-provider-event/${value.provider_event_id_hmac_sha256}`) &&
          await cascadeRecordCompleted(authorizedContext, 'review', authorizedContext.phaseStore,
            `review-email-provider-message/${value.provider_message_id_hmac_sha256}`),
      ),
    }));
  } catch {
    return { ...baseResult(), ...await quarantine(context, 'review', key, value, 'REVIEW_OUTBOX_INVALID') };
  }
}

async function hasOutboxCandidate(context, id) {
  if (!HEX_64.test(id || '')) return false;
  const entry = await getEntry(context.stores.control, outboxCandidateKey(context.sweep, id));
  if (!entry) return false;
  verify(entry.value, 'arc-first-party-retention-outbox-candidate-record-v1', context.configuration.secret);
  if (!exactKeys(entry.value, ['customer_data_stored', 'invite_hmac_sha256', 'marked_at', 'outbox_hmac_sha256',
    'record_hmac_sha256', 'schema', 'source_record_sha256', 'sweep_hmac_sha256', 'version']) ||
      entry.value.schema !== 'arc-first-party-retention-outbox-candidate-v1' || entry.value.version !== 1 ||
      entry.value.sweep_hmac_sha256 !== context.sweep || entry.value.outbox_hmac_sha256 !== id ||
      !HEX_64.test(entry.value.invite_hmac_sha256 || '') ||
      !HEX_64.test(entry.value.source_record_sha256 || '') || entry.value.customer_data_stored !== false ||
      !await currentCandidate(context, 'review', entry.value.invite_hmac_sha256)) return false;
  // Provider identity indexes follow the outbox primary. A same-key outbox
  // recreated after candidate marking must block their deletion.
  const source = await getEntry(context.stores.review, `review-email-outbox/${id}`);
  if (!source) {
    await recordMissingMarkedSource(context, 'review', entry.value.invite_hmac_sha256,
      context.stores.review, `review-email-outbox/${id}`,
      entry.value.source_record_sha256, 'MARKED_OUTBOX_SOURCE_MISSING');
    return false;
  }
  if (!isRetentionTombstone(source.value)) return false;
  try {
    validateRetentionTombstone(source.value, context, 'review', `review-email-outbox/${id}`,
      entry.value.source_record_sha256);
    return true;
  } catch {
    return false;
  }
}

async function handleReviewResendAttempt(entry, context) {
  const { key, value } = entry;
  try {
    const id = key.match(/^review-email-resend-attempt\/([a-f0-9]{64})$/)?.[1];
    if (!id || !exactKeys(value, REVIEW_RESEND_ATTEMPT_FIELDS) ||
        value.schema !== 'arc-preview-review-email-resend-attempt-binding-v1' || value.version !== 1 ||
        value.attempt_hmac_sha256 !== id ||
        ![value.invite_hmac_sha256, value.outbox_hmac_sha256, value.recipient_email_sha256,
          value.preview_manifest_sha256, value.provider_account_hmac_sha256]
          .every((field) => HEX_64.test(field || ''))) {
      throw new Error('review-resend-attempt-invalid');
    }
    iso(value.created_at, 'Review Resend attempt created_at');
    verifySource(value, context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
      'arc-preview-review-email-resend-attempt-binding-record-v1');
    if (!await currentCandidate(context, 'review', value.invite_hmac_sha256) ||
        !await hasOutboxCandidate(context, value.outbox_hmac_sha256)) return baseResult({ held: 1 });
    return baseResult(await cascadeSource(
      context, 'review', context.phaseStore, key, recordSha(value), {
        subject: value.invite_hmac_sha256,
        recheck: (frozenContext) => cascadeCandidatesRemainAuthorized(
          frozenContext, 'review', [value.invite_hmac_sha256],
          (authorizedContext) => hasOutboxCandidate(authorizedContext, value.outbox_hmac_sha256),
        ),
      },
    ));
  } catch {
    return { ...baseResult({ held: 1 }), ...await quarantine(
      context, 'review', key, value, 'REVIEW_RESEND_ATTEMPT_INVALID',
    ) };
  }
}

async function handleReviewProviderIndex(entry, context) {
  const { key, value } = entry;
  try {
    const event = key.startsWith('review-email-provider-event/');
    const fields = event ? REVIEW_PROVIDER_EVENT_FIELDS : REVIEW_PROVIDER_MESSAGE_FIELDS;
    const kind = event ? 'provider-event' : 'provider-message';
    const identity = key.match(/^review-email-provider-(?:event|message)\/([a-f0-9]{64})$/)?.[1];
    if (!identity || !exactKeys(value, fields) ||
        value.schema !== 'arc-preview-review-email-provider-identity-v1' || value.kind !== kind ||
        value.identity_hmac_sha256 !== identity || !HEX_64.test(value.outbox_hmac_sha256 || '') ||
        !HEX_64.test(value.provider_account_hmac_sha256 || '') ||
        typeof value.provider !== 'string' || !/^[a-z0-9][a-z0-9_.-]{1,63}$/.test(value.provider) ||
        event && !HEX_64.test(value.delivery_receipt_sha256 || '')) throw new Error('provider-index-invalid');
    const outboxEntry = await getEntry(context.stores.review, `review-email-outbox/${value.outbox_hmac_sha256}`);
    const outbox = outboxEntry?.value;
    if (!outbox || isRetentionTombstone(outbox) || !exactKeys(outbox, REVIEW_OUTBOX_FIELDS)) {
      throw new Error('provider-outbox-missing');
    }
    verifySource(outbox, context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
      'arc-preview-review-email-outbox-record-signature-v1');
    if (!['DELIVERED', 'BOUNCED', 'COMPLAINED'].includes(outbox.state) ||
        outbox.provider !== value.provider || outbox.provider_account_hmac_sha256 !== value.provider_account_hmac_sha256 ||
        (event ? outbox.provider_event_id_hmac_sha256 : outbox.provider_message_id_hmac_sha256) !== identity ||
        event && outbox.delivery_receipt_sha256 !== value.delivery_receipt_sha256) {
      throw new Error('provider-binding-invalid');
    }
    const counterpartKey = event
      ? `review-email-provider-message/${outbox.provider_message_id_hmac_sha256}`
      : `review-email-provider-event/${outbox.provider_event_id_hmac_sha256}`;
    const counterpart = await getEntry(context.stores.review, counterpartKey);
    if (!counterpart) throw new Error('provider-pair-incomplete');
    if (isRetentionTombstone(counterpart.value)) {
      validateRetentionTombstone(counterpart.value, context, 'review', counterpartKey);
    } else {
      const counterpartFields = event ? REVIEW_PROVIDER_MESSAGE_FIELDS : REVIEW_PROVIDER_EVENT_FIELDS;
      if (!exactKeys(counterpart.value, counterpartFields) || counterpart.value.outbox_hmac_sha256 !== value.outbox_hmac_sha256 ||
          counterpart.value.provider !== value.provider ||
          counterpart.value.provider_account_hmac_sha256 !== value.provider_account_hmac_sha256) {
        throw new Error('provider-pair-invalid');
      }
    }
    if (!await currentCandidate(context, 'review', outbox.invite_hmac_sha256)) return baseResult({ held: 1 });
    return baseResult(await cascadeSource(context, 'review', context.phaseStore, key, recordSha(value), {
      subject: outbox.invite_hmac_sha256,
      recheck: (frozenContext) => cascadeCandidatesRemainAuthorized(
        frozenContext, 'review', [outbox.invite_hmac_sha256],
      ),
    }));
  } catch {
    return { ...baseResult({ held: 1 }), ...await quarantine(
      context, 'review', key, value, 'REVIEW_PROVIDER_IDENTITY_INVALID',
    ) };
  }
}

async function handleReviewRenewal(entry, context) {
  const { key, value } = entry;
  try {
    const renewal = validateReviewEmailRenewal(value, context.env);
    if (key !== reviewEmailRenewalKey(renewal.renewal_hmac_sha256)) {
      throw new Error('review-renewal-key-invalid');
    }
    if (renewal.state !== 'READY') {
      throw new Error('review-renewal-not-ready');
    }
    if (!await currentCandidate(context, 'review', renewal.replaced_invite_hmac_sha256) ||
        !await currentCandidate(context, 'review', renewal.replacement_invite_hmac_sha256) ||
        iso(renewal.replacement_expires_at, 'Review renewal expires_at') > context.unpaidCutoff) {
      return baseResult({ held: 1 });
    }
    const subjects = [renewal.replaced_invite_hmac_sha256, renewal.replacement_invite_hmac_sha256];
    return baseResult(await cascadeSource(context, 'review', context.phaseStore, key, recordSha(renewal), {
      subject: renewal.replaced_invite_hmac_sha256,
      recheck: (frozenContext) => cascadeCandidatesRemainAuthorized(
        frozenContext, 'review', subjects,
        (authorizedContext) => iso(renewal.replacement_expires_at,
          'Review renewal expires_at') <= authorizedContext.unpaidCutoff,
      ),
    }));
  } catch {
    return { ...baseResult({ held: 1 }), ...await quarantine(
      context, 'review', key, value, 'REVIEW_RENEWAL_INVALID_OR_NOT_READY',
    ) };
  }
}

async function handleCheckoutAlert(entry, context) {
  const { key, value } = entry;
  try {
    verifySource(value, context.env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET,
      'arc-review-checkout-revocation-alert-signature-v1');
    if (!await currentCandidate(context, 'checkout', value.binding_hmac_sha256)) return baseResult({ held: 1 });
    return baseResult(await cascadeSource(context, 'checkout', context.phaseStore, key, recordSha(value), {
      subject: value.binding_hmac_sha256,
      recheck: (frozenContext) => cascadeCandidatesRemainAuthorized(
        frozenContext, 'checkout', [value.binding_hmac_sha256],
      ),
    }));
  } catch {
    return { ...baseResult(), ...await quarantine(context, 'checkout', key, value, 'CHECKOUT_ALERT_INVALID') };
  }
}

function validateReviewCheckoutIndex(value, key, context) {
  const secret = context.env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET;
  if (!exactKeys(value, REVIEW_CHECKOUT_INDEX_FIELDS) ||
      value.schema !== 'arc-review-checkout-recipient-index-v1' || value.version !== 1 ||
      !Number.isSafeInteger(value.record_revision) || value.record_revision < 1 ||
      !HEX_64.test(value.recipient_email_sha256 || '') ||
      value.recipient_index_hmac_sha256 !== hmac(secret,
        `arc-review-checkout-recipient-index-id-v1\n${value.recipient_email_sha256}`) ||
      key !== `review-checkout-recipient-index/${value.recipient_index_hmac_sha256}` ||
      !Array.isArray(value.bindings) || value.bindings.length > 128) {
    throw new Error('review-checkout-index-invalid');
  }
  let prior = '';
  for (const binding of value.bindings) {
    if (!exactKeys(binding, ['approval_receipt_sha256', 'binding_hmac_sha256']) ||
        !HEX_64.test(binding.approval_receipt_sha256 || '') ||
        binding.binding_hmac_sha256 !== hmac(secret,
          `arc-review-checkout-revocable-binding-id-v1\n${binding.approval_receipt_sha256}`) ||
        binding.approval_receipt_sha256 <= prior) {
      throw new Error('review-checkout-index-binding-invalid');
    }
    prior = binding.approval_receipt_sha256;
  }
  iso(value.updated_at, 'Review Checkout recipient index updated_at');
  verifySource(value, secret, 'arc-review-checkout-recipient-index-signature-v1');
  return value;
}

async function handleCheckoutIndex(entry, context) {
  const { key } = entry;
  let current = entry;
  try {
    const value = validateReviewCheckoutIndex(current.value, key, context);
    const retained = [];
    for (const binding of value.bindings) {
      if (!await currentCandidate(context, 'checkout', binding.binding_hmac_sha256)) retained.push(binding);
    }
    if (retained.length === value.bindings.length) return baseResult({ held: 1 });
    const removed = value.bindings.filter((candidate) =>
      !retained.some((kept) => kept.binding_hmac_sha256 === candidate.binding_hmac_sha256));
    const updated = sign({ ...unsigned(value), record_revision: value.record_revision + 1,
      bindings: retained, updated_at: context.startedAt },
    'arc-review-checkout-recipient-index-signature-v1', context.env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET);
    const result = await rewriteSource(context, 'checkout', context.phaseStore, key, value, updated, {
      recheck: async (frozenContext) => ({
        allowed: (await Promise.all(removed.map((binding) =>
          currentCandidate(frozenContext, 'checkout', binding.binding_hmac_sha256))))
          .every(Boolean),
        legal_holds_rechecked: removed.map((binding) => binding.binding_hmac_sha256).sort(),
      }),
    });
    return baseResult(result);
  } catch {
    return { ...baseResult(), ...await quarantine(
      context, 'checkout', key, current.value, 'CHECKOUT_INDEX_INVALID',
    ) };
  }
}

async function handleReviewPending(entry, context) {
  const { key, value } = entry;
  try {
    verifySource(value, context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
      'arc-preview-review-email-pending-record-signature-v1');
    const retained = [];
    for (const item of value.entries || []) {
      if (!await currentCandidate(context, 'review', item.invite_hmac_sha256)) retained.push(item);
    }
    if (retained.length === (value.entries || []).length) return baseResult({ held: 1 });
    const updated = sign({ ...unsigned(value), record_revision: value.record_revision + 1,
      entries: retained, updated_at: context.startedAt },
    'arc-preview-review-email-pending-record-signature-v1', context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET);
    for (const item of value.entries.filter((candidate) =>
      !retained.some((kept) => canonicalJson(kept) === canonicalJson(candidate)))) {
      if (!await currentCandidate(context, 'review', item.invite_hmac_sha256)) return baseResult({ held: 1 });
    }
    const removed = value.entries.filter((candidate) =>
      !retained.some((kept) => canonicalJson(kept) === canonicalJson(candidate)));
    const result = await rewriteSource(context, 'review', context.phaseStore, key, value, updated, {
      recheck: async (frozenContext) => ({
        allowed: (await Promise.all(removed.map((item) =>
          currentCandidate(frozenContext, 'review', item.invite_hmac_sha256)))).every(Boolean),
        legal_holds_rechecked: [...new Set(removed.map((item) => item.invite_hmac_sha256))].sort(),
      }),
    });
    return baseResult({ ...result,
      deleted: result.deleted ? value.entries.length - retained.length : 0 });
  } catch {
    return { ...baseResult(), ...await quarantine(context, 'review', key, value, 'REVIEW_PENDING_INVALID') };
  }
}

async function reviewRecipientCascadeValid(context, recipient) {
  const listed = await listEntries(context.stores.review, 'review-invites/', null, 500);
  if (listed.next_cursor !== null) return false;
  let foundCandidate = false;
  for (const item of listed.entries) {
    const current = await getEntry(context.stores.review, item.key);
    if (!current || current.value?.recipient_email_sha256 !== recipient) continue;
    const inviteId = item.key.match(/^review-invites\/([a-f0-9]{64})$/)?.[1];
    if (!inviteId || !await currentCandidate(context, 'review', inviteId)) return false;
    foundCandidate = true;
  }
  return foundCandidate;
}

function validateReviewRecipientControl(value, key, context) {
  const secret = context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET;
  if (!exactKeys(value, REVIEW_RECIPIENT_CONTROL_FIELDS) ||
      value.schema !== 'arc-preview-review-email-recipient-control-v1' || value.version !== 1 ||
      !Number.isSafeInteger(value.record_revision) || value.record_revision < 1 ||
      !['ACTIVE', 'AUTHORIZING', 'SUPPRESSED'].includes(value.state) ||
      !HEX_64.test(value.recipient_email_sha256 || '') ||
      !HEX_64.test(value.recipient_control_hmac_sha256 || '') ||
      value.recipient_control_hmac_sha256 !== hmac(secret,
        `arc-preview-review-email-recipient-control-id-v1\n${value.recipient_email_sha256}`) ||
      key !== `review-email-recipient-control/${value.recipient_control_hmac_sha256}`) {
    throw new Error('review-recipient-control-invalid');
  }
  if (value.state === 'ACTIVE') {
    if ([value.authority_operation_hmac_sha256, value.authority_expires_at,
      value.suppression_receipt_sha256, value.suppression_status, value.suppressed_at,
      value.source_invite_hmac_sha256, value.source_outbox_hmac_sha256].some((field) => field !== null)) {
      throw new Error('review-recipient-control-active-invalid');
    }
  } else if (value.state === 'AUTHORIZING') {
    if (!HEX_64.test(value.authority_operation_hmac_sha256 || '')) {
      throw new Error('review-recipient-control-authority-invalid');
    }
    iso(value.authority_expires_at, 'Review recipient authority_expires_at');
    const suppression = [value.suppression_receipt_sha256, value.suppression_status, value.suppressed_at,
      value.source_invite_hmac_sha256, value.source_outbox_hmac_sha256];
    if (suppression.some((field) => field !== null) && (suppression.some((field) => field === null) ||
        !['bounced', 'complained'].includes(value.suppression_status) ||
        ![value.suppression_receipt_sha256, value.source_invite_hmac_sha256,
          value.source_outbox_hmac_sha256].every((field) => HEX_64.test(field || '')))) {
      throw new Error('review-recipient-control-pending-suppression-invalid');
    }
    if (value.suppressed_at !== null) iso(value.suppressed_at, 'Review recipient suppressed_at');
  } else {
    if (value.authority_operation_hmac_sha256 !== null || value.authority_expires_at !== null ||
        !['bounced', 'complained'].includes(value.suppression_status) ||
        ![value.suppression_receipt_sha256, value.source_invite_hmac_sha256,
          value.source_outbox_hmac_sha256].every((field) => HEX_64.test(field || ''))) {
      throw new Error('review-recipient-control-suppressed-invalid');
    }
    iso(value.suppressed_at, 'Review recipient suppressed_at');
  }
  verifySource(value, secret, 'arc-preview-review-email-recipient-control-signature-v1');
  return value;
}

function validateReviewRecipientSuppression(value, key, context) {
  const secret = context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET;
  if (!exactKeys(value, REVIEW_RECIPIENT_SUPPRESSION_FIELDS) ||
      value.schema !== 'arc-preview-review-email-recipient-suppression-v1' || value.version !== 1 ||
      !Number.isSafeInteger(value.record_revision) || value.record_revision < 1 ||
      !['bounced', 'complained'].includes(value.suppression_status) ||
      ![value.recipient_suppression_hmac_sha256, value.recipient_email_sha256,
        value.suppression_receipt_sha256, value.source_invite_hmac_sha256,
        value.source_outbox_hmac_sha256].every((field) => HEX_64.test(field || '')) ||
      value.recipient_suppression_hmac_sha256 !== hmac(secret,
        `arc-preview-review-email-recipient-suppression-id-v1\n${value.recipient_email_sha256}`) ||
      key !== `review-email-recipient-suppression/${value.recipient_suppression_hmac_sha256}`) {
    throw new Error('review-recipient-suppression-invalid');
  }
  iso(value.suppressed_at, 'Review recipient suppression suppressed_at');
  verifySource(value, secret, 'arc-preview-review-email-recipient-suppression-signature-v1');
  return value;
}

async function handleReviewRecipient(entry, context) {
  const { key, value } = entry;
  try {
    if (key.startsWith('review-email-recipient-suppression/')) {
      validateReviewRecipientSuppression(value, key, context);
      // Bounce/complaint suppressions are durable safety controls. Retention
      // never removes them automatically because doing so could reopen email.
      return baseResult({ held: 1 });
    }
    validateReviewRecipientControl(value, key, context);
    // Recipient controls are reusable synchronization/suppression authority.
    // ACTIVE rows must remain available for future review emails; AUTHORIZING
    // and SUPPRESSED rows are fail-closed safety state and are also durable.
    return baseResult({ held: 1 });
  } catch {
    return { ...baseResult(), ...await quarantine(context, 'review', key, value, 'REVIEW_RECIPIENT_CONTROL_INVALID') };
  }
}

async function checkoutHasBoundChildren(context, bindingId) {
  for (const prefix of ['review-checkout-revocation-alert/', 'review-checkout-recipient-index/']) {
    const remains = await scanEntries(context.stores.review, prefix, async (key, entry) => {
      if (!entry) {
        await persistMissingSourceAnomaly(context, 'checkout', context.stores.review, key, null,
          'CHECKOUT_BOUND_CHILD_LISTED_SOURCE_MISSING');
        return true;
      }
      if (isRetentionTombstone(entry.value)) return false;
      if (prefix === 'review-checkout-revocation-alert/') {
        return entry.value?.binding_hmac_sha256 === bindingId;
      }
      try {
        const index = validateReviewCheckoutIndex(entry.value, key, context);
        return index.bindings.some((binding) => binding.binding_hmac_sha256 === bindingId);
      } catch {
        return true;
      }
    }, 500, context);
    if (remains) return true;
  }
  return false;
}

function appendSubjectMutation(context, mutations, identities, input) {
  const storeName = input.storeName || retentionStoreName(context, input.store);
  const identity = `${storeName}\n${input.key}`;
  if (identities.has(identity)) return;
  identities.add(identity);
  mutations.push({ ...input, storeName });
}

function appendSubjectTombstone(context, mutations, identities, family, storeName, store,
  key, source, role = 'CHILD') {
  const sourceRecordSha256 = recordSha(source);
  const output = buildRetentionTombstone(context, family, key, sourceRecordSha256);
  appendSubjectMutation(context, mutations, identities, {
    action: 'TOMBSTONE', family, key, output, outputRecordSha256: recordSha(output), role,
    sourceRecordSha256, sourceValue: source, store, storeName,
  });
}

async function collectCheckoutSubjectMutations(context, bindingId, primary) {
  const mutations = [];
  const identities = new Set();
  let blocked = false;
  let listedSourceMissing = false;
  await scanEntries(context.stores.review, 'review-checkout-revocation-alert/', async (key, entry) => {
    if (!entry) {
      await persistMissingSourceAnomaly(context, 'checkout', context.stores.review, key, null,
        'CHECKOUT_MANIFEST_LISTED_SOURCE_MISSING');
      listedSourceMissing = true;
      return false;
    }
    if (isRetentionTombstone(entry.value) || entry.value?.binding_hmac_sha256 !== bindingId) return false;
    try {
      verifySource(entry.value, context.env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET,
        'arc-review-checkout-revocation-alert-signature-v1');
      appendSubjectTombstone(context, mutations, identities, 'checkout', 'review',
        context.stores.review, key, entry.value);
    } catch {
      blocked = true;
      await quarantine(context, 'checkout', key, entry.value, 'CHECKOUT_ALERT_INVALID', context.stores.review);
    }
    return false;
  });
  await scanEntries(context.stores.review, 'review-checkout-recipient-index/', async (key, entry) => {
    if (!entry) {
      await persistMissingSourceAnomaly(context, 'checkout', context.stores.review, key, null,
        'CHECKOUT_MANIFEST_LISTED_SOURCE_MISSING');
      listedSourceMissing = true;
      return false;
    }
    if (isRetentionTombstone(entry.value)) return false;
    try {
      const value = validateReviewCheckoutIndex(entry.value, key, context);
      if (!value.bindings.some((binding) => binding.binding_hmac_sha256 === bindingId)) return false;
      const retained = value.bindings.filter((binding) => binding.binding_hmac_sha256 !== bindingId);
      const output = sign({ ...unsigned(value), record_revision: value.record_revision + 1,
        bindings: retained, updated_at: context.startedAt },
      'arc-review-checkout-recipient-index-signature-v1',
      context.env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET);
      appendSubjectMutation(context, mutations, identities, {
        action: 'REWRITE', family: 'checkout', key, output,
        outputRecordSha256: recordSha(output), role: 'CHILD',
        sourceRecordSha256: recordSha(value), sourceValue: value,
        store: context.stores.review, storeName: 'review',
      });
    } catch {
      blocked = true;
      await quarantine(context, 'checkout', key, entry.value, 'CHECKOUT_INDEX_INVALID', context.stores.review);
    }
    return false;
  });
  appendSubjectTombstone(context, mutations, identities, 'checkout', 'review', context.stores.review,
    `review-checkout-binding/${bindingId}`, primary.value, 'PRIMARY');
  return { blocked, listedSourceMissing, mutations };
}

async function reviewOutboxBelongsTo(context, outboxId, inviteId) {
  const current = await getEntryUnderFence(context, context.stores.review,
    `review-email-outbox/${outboxId}`);
  if (current && !isRetentionTombstone(current.value)) {
    return current.value?.invite_hmac_sha256 === inviteId;
  }
  const marker = await getEntryUnderFence(context, context.stores.control,
    outboxCandidateKey(context.sweep, outboxId));
  if (!marker) {
    await persistMissingSourceAnomaly(context, 'review', context.stores.review,
      `review-email-outbox/${outboxId}`, null, 'PROVIDER_BOUND_OUTBOX_SOURCE_MISSING');
    return true;
  }
  return marker.value?.invite_hmac_sha256 === inviteId;
}

async function reviewHasBoundChildren(context, inviteId, invite) {
  const scans = [
    ['revision', 'review-revision-work/'],
    ['revision', 'review-revision-pending/'],
    ['review', 'review-email-outbox/'],
    ['review', 'review-email-resend-attempt/'],
    ['review', 'review-email-renewal/'],
    ['review', 'review-email-provider-event/'],
    ['review', 'review-email-provider-message/'],
    ['review', 'review-email-pending/'],
  ];
  for (const [storeName, prefix] of scans) {
    const store = context.stores[storeName];
    const remains = await scanEntries(store, prefix, async (key, entry) => {
      if (!entry) {
        await persistMissingSourceAnomaly(context, 'review', store, key, null,
          'REVIEW_BOUND_CHILD_LISTED_SOURCE_MISSING');
        return true;
      }
      if (isRetentionTombstone(entry.value)) return false;
      const value = entry.value;
      if (prefix === 'review-revision-work/' || prefix === 'review-revision-pending/') {
        return [value.source_invite_hmac_sha256, value.successor_invite_hmac_sha256]
          .includes(inviteId);
      }
      if (prefix === 'review-email-outbox/' || prefix === 'review-email-resend-attempt/') {
        return value.invite_hmac_sha256 === inviteId;
      }
      if (prefix === 'review-email-renewal/') {
        return [value.replaced_invite_hmac_sha256, value.replacement_invite_hmac_sha256]
          .includes(inviteId);
      }
      if (prefix === 'review-email-provider-event/' || prefix === 'review-email-provider-message/') {
        return reviewOutboxBelongsTo(context, value.outbox_hmac_sha256, inviteId);
      }
      return Array.isArray(value.entries) &&
        value.entries.some((item) => item?.invite_hmac_sha256 === inviteId);
    }, 500, context);
    if (remains) return true;
  }
  if (invite?.decision?.action === 'APPROVE_AND_PAY') {
    const bindingId = checkoutBindingId(invite.decision, context.env);
    const binding = await getEntryUnderFence(context, context.stores.review,
      `review-checkout-binding/${bindingId}`);
    if (binding && !isRetentionTombstone(binding.value)) return true;
  }
  return false;
}

async function handleCheckoutPrimary(entry, context) {
  const id = entry.key.match(/^review-checkout-binding\/([a-f0-9]{64})$/)?.[1];
  const current = id ? await currentCandidate(context, 'checkout', id) : null;
  if (!current) return baseResult({ held: 1 });
  const open = await ensureRetentionGenerationFence(context.stores.control, context.env,
    { clock: () => liveFenceClock(context) });
  if (open.record.status !== 'OPEN') return baseResult({ held: 1, retryable: true });
  const collected = await collectCheckoutSubjectMutations(context, id, current);
  if (collected.blocked || collected.listedSourceMissing) return baseResult({ held: 1 });
  return baseResult(await runFrozenSubjectMutation(context, {
    family: 'checkout', subject: id, open, mutations: collected.mutations,
    recheck: async (frozenContext) => ({
      allowed: Boolean(await currentCandidate(frozenContext, 'checkout', id)),
      legal_holds_rechecked: [id],
    }),
    primaryAfterChildren: true,
    beforePrimary: async (frozenContext) => !await checkoutHasBoundChildren(frozenContext, id),
  }));
}

function derivedReviewOutbox(invite, env) {
  return hmac(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    `arc-preview-review-email-outbox-id-v1\n${invite}`);
}

function derivedRevisionWork(invite, env) {
  return hmac(env.ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET,
    `arc-preview-review-revision-work-id-v2\n${invite}`);
}

function validateBoundReviewOutbox(value, key, context) {
  verifySource(value, context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    'arc-preview-review-email-outbox-record-signature-v1');
  const id = key.match(/^review-email-outbox\/([a-f0-9]{64})$/)?.[1];
  if (!id || !exactKeys(value, REVIEW_OUTBOX_FIELDS) ||
      value.schema !== 'arc-preview-review-email-outbox-v1' || value.outbox_hmac_sha256 !== id ||
      !HEX_64.test(value.invite_hmac_sha256 || '')) throw new Error('review-outbox-invalid');
  return value;
}

function validateBoundReviewProvider(value, key, outbox) {
  const event = key.startsWith('review-email-provider-event/');
  const fields = event ? REVIEW_PROVIDER_EVENT_FIELDS : REVIEW_PROVIDER_MESSAGE_FIELDS;
  const kind = event ? 'provider-event' : 'provider-message';
  const identity = key.match(/^review-email-provider-(?:event|message)\/([a-f0-9]{64})$/)?.[1];
  if (!identity || !exactKeys(value, fields) ||
      value.schema !== 'arc-preview-review-email-provider-identity-v1' || value.kind !== kind ||
      value.identity_hmac_sha256 !== identity || value.outbox_hmac_sha256 !== outbox.outbox_hmac_sha256 ||
      value.provider !== outbox.provider ||
      value.provider_account_hmac_sha256 !== outbox.provider_account_hmac_sha256 ||
      (event ? outbox.provider_event_id_hmac_sha256 : outbox.provider_message_id_hmac_sha256) !== identity ||
      event && value.delivery_receipt_sha256 !== outbox.delivery_receipt_sha256) {
    throw new Error('review-provider-binding-invalid');
  }
  return value;
}

async function collectReviewSubjectMutations(context, inviteId, primary) {
  const mutations = [];
  const identities = new Set();
  const authorizationSubjects = new Set([inviteId]);
  const boundOutboxes = new Map();
  let blocked = false;
  let listedSourceMissing = false;
  const missing = async (store, key, reason) => {
    await persistMissingSourceAnomaly(context, 'review', store, key, null, reason);
    listedSourceMissing = true;
  };

  await scanEntries(context.stores.revision, 'review-revision-work/', async (key, entry) => {
    if (!entry) {
      await missing(context.stores.revision, key, 'REVIEW_MANIFEST_LISTED_SOURCE_MISSING');
      return false;
    }
    if (isRetentionTombstone(entry.value)) return false;
    const value = entry.value;
    if (![value?.source_invite_hmac_sha256, value?.successor_invite_hmac_sha256].includes(inviteId)) return false;
    try {
      verifySource(value, context.env.ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET,
        'arc-preview-review-revision-work-record-v2');
      const id = key.match(/^review-revision-work\/([a-f0-9]{64})$/)?.[1];
      if (!id || value.schema !== 'arc-preview-review-revision-work-v2' ||
          value.work_hmac_sha256 !== id || value.state !== 'COMPLETED' ||
          ![value.source_invite_hmac_sha256, value.successor_invite_hmac_sha256]
            .every((subject) => HEX_64.test(subject || '')) ||
          iso(value.completed_at || value.reserved_at, 'Revision retention time') > context.unpaidCutoff) {
        throw new Error('review-revision-work-invalid');
      }
      authorizationSubjects.add(value.source_invite_hmac_sha256);
      authorizationSubjects.add(value.successor_invite_hmac_sha256);
      appendSubjectTombstone(context, mutations, identities, 'review', 'revision',
        context.stores.revision, key, value);
    } catch {
      blocked = true;
      await quarantine(context, 'review', key, value, 'REVISION_RECORD_INVALID', context.stores.revision);
    }
    return false;
  });

  await scanEntries(context.stores.revision, 'review-revision-pending/', async (key, entry) => {
    if (!entry) {
      await missing(context.stores.revision, key, 'REVIEW_MANIFEST_LISTED_SOURCE_MISSING');
      return false;
    }
    if (isRetentionTombstone(entry.value)) return false;
    const value = entry.value;
    if (![value?.source_invite_hmac_sha256, value?.successor_invite_hmac_sha256].includes(inviteId)) return false;
    try {
      verifySource(value, context.env.ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET,
        'arc-preview-review-revision-pending-signature-v1');
      const id = key.match(/^review-revision-pending\/([a-f0-9]{64})$/)?.[1];
      if (!id || value.schema !== 'arc-preview-review-revision-pending-v1' ||
          value.work_hmac_sha256 !== id || !HEX_64.test(value.source_invite_hmac_sha256 || '')) {
        throw new Error('review-revision-pending-invalid');
      }
      authorizationSubjects.add(value.source_invite_hmac_sha256);
      if (HEX_64.test(value.successor_invite_hmac_sha256 || '')) {
        authorizationSubjects.add(value.successor_invite_hmac_sha256);
      }
      const workKey = `review-revision-work/${id}`;
      const work = await getEntry(context.stores.revision, workKey);
      if (!work) {
        await missing(context.stores.revision, workKey, 'REVIEW_REVISION_WORK_SOURCE_MISSING');
        return false;
      }
      if (!isRetentionTombstone(work.value) && !identities.has(`revision\n${workKey}`)) {
        throw new Error('review-revision-work-not-authorized');
      }
      appendSubjectTombstone(context, mutations, identities, 'review', 'revision',
        context.stores.revision, key, value);
    } catch {
      blocked = true;
      await quarantine(context, 'review', key, value, 'REVISION_PENDING_INVALID', context.stores.revision);
    }
    return false;
  });

  await scanEntries(context.stores.review, 'review-email-outbox/', async (key, entry) => {
    if (!entry) {
      await missing(context.stores.review, key, 'REVIEW_MANIFEST_LISTED_SOURCE_MISSING');
      return false;
    }
    if (isRetentionTombstone(entry.value)) return false;
    const value = entry.value;
    if (value?.invite_hmac_sha256 !== inviteId) return false;
    try {
      const outbox = validateBoundReviewOutbox(value, key, context);
      const old = iso(outbox.terminal_at || outbox.expires_at,
        'Review outbox retention time') <= context.unpaidCutoff;
      if (!old || !['DELIVERED', 'BOUNCED', 'COMPLAINED'].includes(outbox.state)) {
        throw new Error('review-outbox-not-terminal');
      }
      boundOutboxes.set(outbox.outbox_hmac_sha256, outbox);
      appendSubjectTombstone(context, mutations, identities, 'review', 'review',
        context.stores.review, key, outbox);
    } catch {
      blocked = true;
      await quarantine(context, 'review', key, value, 'REVIEW_OUTBOX_INVALID', context.stores.review);
    }
    return false;
  });

  for (const [outboxId, outbox] of boundOutboxes) {
    for (const [kind, identity] of [['event', outbox.provider_event_id_hmac_sha256],
      ['message', outbox.provider_message_id_hmac_sha256]]) {
      const key = `review-email-provider-${kind}/${identity}`;
      const provider = await getEntry(context.stores.review, key);
      if (!provider) {
        await missing(context.stores.review, key, 'REVIEW_PROVIDER_SOURCE_MISSING');
        continue;
      }
      if (isRetentionTombstone(provider.value)) continue;
      try {
        validateBoundReviewProvider(provider.value, key, outbox);
        appendSubjectTombstone(context, mutations, identities, 'review', 'review',
          context.stores.review, key, provider.value);
      } catch {
        blocked = true;
        await quarantine(context, 'review', key, provider.value,
          'REVIEW_PROVIDER_IDENTITY_INVALID', context.stores.review);
      }
    }
  }

  for (const prefix of ['review-email-provider-event/', 'review-email-provider-message/']) {
    await scanEntries(context.stores.review, prefix, async (key, entry) => {
      if (!entry) {
        await missing(context.stores.review, key, 'REVIEW_MANIFEST_LISTED_SOURCE_MISSING');
        return false;
      }
      if (isRetentionTombstone(entry.value)) return false;
      const outbox = boundOutboxes.get(entry.value?.outbox_hmac_sha256);
      if (!outbox) return false;
      try {
        validateBoundReviewProvider(entry.value, key, outbox);
        appendSubjectTombstone(context, mutations, identities, 'review', 'review',
          context.stores.review, key, entry.value);
      } catch {
        blocked = true;
        await quarantine(context, 'review', key, entry.value,
          'REVIEW_PROVIDER_IDENTITY_INVALID', context.stores.review);
      }
      return false;
    });
  }

  await scanEntries(context.stores.review, 'review-email-resend-attempt/', async (key, entry) => {
    if (!entry) {
      await missing(context.stores.review, key, 'REVIEW_MANIFEST_LISTED_SOURCE_MISSING');
      return false;
    }
    if (isRetentionTombstone(entry.value) || entry.value?.invite_hmac_sha256 !== inviteId) return false;
    const value = entry.value;
    try {
      const id = key.match(/^review-email-resend-attempt\/([a-f0-9]{64})$/)?.[1];
      if (!id || !exactKeys(value, REVIEW_RESEND_ATTEMPT_FIELDS) ||
          value.schema !== 'arc-preview-review-email-resend-attempt-binding-v1' || value.version !== 1 ||
          value.attempt_hmac_sha256 !== id || !boundOutboxes.has(value.outbox_hmac_sha256)) {
        throw new Error('review-resend-attempt-invalid');
      }
      verifySource(value, context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
        'arc-preview-review-email-resend-attempt-binding-record-v1');
      appendSubjectTombstone(context, mutations, identities, 'review', 'review',
        context.stores.review, key, value);
    } catch {
      blocked = true;
      await quarantine(context, 'review', key, value,
        'REVIEW_RESEND_ATTEMPT_INVALID', context.stores.review);
    }
    return false;
  });

  await scanEntries(context.stores.review, 'review-email-renewal/', async (key, entry) => {
    if (!entry) {
      await missing(context.stores.review, key, 'REVIEW_MANIFEST_LISTED_SOURCE_MISSING');
      return false;
    }
    if (isRetentionTombstone(entry.value)) return false;
    const value = entry.value;
    if (![value?.replaced_invite_hmac_sha256, value?.replacement_invite_hmac_sha256].includes(inviteId)) {
      return false;
    }
    try {
      const renewal = validateReviewEmailRenewal(value, context.env);
      if (key !== reviewEmailRenewalKey(renewal.renewal_hmac_sha256) || renewal.state !== 'READY' ||
          iso(renewal.replacement_expires_at, 'Review renewal expires_at') > context.unpaidCutoff) {
        throw new Error('review-renewal-not-ready');
      }
      authorizationSubjects.add(renewal.replaced_invite_hmac_sha256);
      authorizationSubjects.add(renewal.replacement_invite_hmac_sha256);
      appendSubjectTombstone(context, mutations, identities, 'review', 'review',
        context.stores.review, key, renewal);
    } catch {
      blocked = true;
      await quarantine(context, 'review', key, value,
        'REVIEW_RENEWAL_INVALID_OR_NOT_READY', context.stores.review);
    }
    return false;
  });

  await scanEntries(context.stores.review, 'review-email-pending/', async (key, entry) => {
    if (!entry) {
      await missing(context.stores.review, key, 'REVIEW_MANIFEST_LISTED_SOURCE_MISSING');
      return false;
    }
    if (isRetentionTombstone(entry.value)) return false;
    const value = entry.value;
    const entries = Array.isArray(value?.entries) ? value.entries : [];
    if (!entries.some((item) => item?.invite_hmac_sha256 === inviteId)) return false;
    try {
      verifySource(value, context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
        'arc-preview-review-email-pending-record-signature-v1');
      if (value.schema !== 'arc-preview-review-email-pending-v1' || value.version !== 1 ||
          !Number.isSafeInteger(value.record_revision) || value.record_revision < 1) {
        throw new Error('review-pending-invalid');
      }
      const retained = entries.filter((item) => item?.invite_hmac_sha256 !== inviteId);
      const output = sign({ ...unsigned(value), record_revision: value.record_revision + 1,
        entries: retained, updated_at: context.startedAt },
      'arc-preview-review-email-pending-record-signature-v1',
      context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET);
      appendSubjectMutation(context, mutations, identities, {
        action: 'REWRITE', family: 'review', key, output,
        outputRecordSha256: recordSha(output), role: 'CHILD',
        sourceRecordSha256: recordSha(value), sourceValue: value,
        store: context.stores.review, storeName: 'review',
      });
    } catch {
      blocked = true;
      await quarantine(context, 'review', key, value, 'REVIEW_PENDING_INVALID', context.stores.review);
    }
    return false;
  });

  appendSubjectTombstone(context, mutations, identities, 'review', 'review', context.stores.review,
    `review-invites/${inviteId}`, primary.value, 'PRIMARY');
  return { authorizationSubjects: [...authorizationSubjects].sort(), blocked,
    listedSourceMissing, mutations };
}

async function handleReviewPrimary(entry, context) {
  const id = entry.key.match(/^review-invites\/([a-f0-9]{64})$/)?.[1];
  let current = id ? await currentCandidate(context, 'review', id) : null;
  if (!current) return baseResult({ held: 1 });
  const value = current.value;
  if (value.prior_invite_hmac_sha256 !== null &&
      !await currentOrCascadedCandidate(context, 'review', value.prior_invite_hmac_sha256) ||
      value.successor_invite_hmac_sha256 !== null &&
      !await currentOrCascadedCandidate(context, 'review', value.successor_invite_hmac_sha256)) return baseResult({ held: 1 });
  if (value.decision?.action === 'APPROVE_AND_PAY') {
    const bindingId = checkoutBindingId(value.decision, context.env);
    if (await cascadeRecordRemains(context, 'checkout', context.stores.review,
      `review-checkout-binding/${bindingId}`)) return baseResult({ held: 1 });
  }
  // Re-read after every child/lineage check so a reopened review or newly
  // added hold cannot reuse the earlier candidate authorization.
  current = await currentCandidate(context, 'review', id);
  if (!current) return baseResult({ held: 1 });
  const open = await ensureRetentionGenerationFence(context.stores.control, context.env,
    { clock: () => liveFenceClock(context) });
  if (open.record.status !== 'OPEN') return baseResult({ held: 1, retryable: true });
  const collected = await collectReviewSubjectMutations(context, id, current);
  if (collected.blocked || collected.listedSourceMissing) return baseResult({ held: 1 });
  return baseResult(await runFrozenSubjectMutation(context, {
    family: 'review', subject: id, open, mutations: collected.mutations,
    recheck: async (frozenContext) => {
      for (const subject of collected.authorizationSubjects) {
        if (await activeLegalHold(frozenContext, 'review', subject)) {
          return { allowed: false, legal_holds_rechecked: collected.authorizationSubjects };
        }
      }
      for (const subject of collected.authorizationSubjects) {
        const authorized = subject === id
          ? await currentCandidate(frozenContext, 'review', subject)
          : await currentOrCascadedCandidate(frozenContext, 'review', subject);
        if (!authorized) {
          return { allowed: false, legal_holds_rechecked: collected.authorizationSubjects };
        }
      }
      return { allowed: true, legal_holds_rechecked: collected.authorizationSubjects };
    },
    primaryAfterChildren: true,
    beforePrimary: async (frozenContext) =>
      !await reviewHasBoundChildren(frozenContext, id, current.value),
  }));
}

async function validatePaidRelease(context, record) {
  const entry = await getEntryUnderFence(context, context.stores.control,
    paidHandoffRetentionReleaseKey(record.handoff_id));
  if (!entry) return false;
  const value = entry.value;
  if (value.schema !== 'arc-first-party-paid-handoff-retention-release-v1' || value.handoff_id !== record.handoff_id ||
      value.source_record_sha256 !== recordSha(record) || value.customer_data_stored !== false || value.legal_hold !== false ||
      value.netlify_transfer_verified !== true || value.payment_retention_complete !== true ||
      value.tax_retention_complete !== true || value.dispute_refund_retention_complete !== true) return false;
  verify(value, 'arc-first-party-paid-handoff-retention-release-record-v1', context.configuration.secret);
  return iso(value.issued_at, 'Paid handoff release issued_at') <= context.now.getTime() &&
    iso(value.expires_at, 'Paid handoff release expires_at') > context.now.getTime();
}

const paymentBridgeMarkerKey = (sweep, reviewSessionBinding) =>
  `first-party-retention/payment-bridge/${sweep}/${reviewSessionBinding}`;

function validatePaymentReviewBinding(value, key, context) {
  if (!exactKeys(value, PAYMENT_REVIEW_BINDING_FIELDS) ||
      value.schema !== 'arc-payment-review-session-binding-v1' ||
      !exactKeys(value.immutable, PAYMENT_REVIEW_IMMUTABLE_FIELDS) ||
      value.immutable.schema !== 'arc-payment-review-session-immutable-v1' ||
      !HEX_64.test(value.immutable.invite_hmac_sha256 || '') ||
      !HEX_64.test(value.immutable_sha256 || '') ||
      value.immutable_sha256 !== recordSha(value.immutable) ||
      key !== `payment-review-session-binding/${hmac(context.env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET,
        `arc-payment-review-session-binding-key-v1\n${value.immutable.invite_hmac_sha256}`)}`) {
    throw new Error('payment-review-binding-invalid');
  }
  iso(value.created_at, 'Payment review binding created_at');
  return value;
}

function validatePaymentStartOutbox(value, key, context) {
  if (!exactKeys(value, PAYMENT_START_OUTBOX_FIELDS) || value.schema !== 'arc-payment-arc2-start-outbox-v2' ||
      !exactKeys(value.immutable, PAYMENT_START_IMMUTABLE_FIELDS) ||
      value.immutable.schema !== 'arc-payment-arc2-start-binding-v2' ||
      !HEX_64.test(value.immutable_sha256 || '') || value.immutable_sha256 !== recordSha(value.immutable) ||
      key !== `payment-arc2-start-outbox/${hmac(context.env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET,
        `arc-payment-arc2-start-outbox-key-v2\n${value.immutable_sha256}`)}` ||
      !Number.isSafeInteger(value.record_revision) || value.record_revision < 1 ||
      !Number.isSafeInteger(value.claim_attempt_count) || value.claim_attempt_count < 0) {
    throw new Error('payment-start-outbox-invalid');
  }
  iso(value.created_at, 'Payment start outbox created_at');
  iso(value.updated_at, 'Payment start outbox updated_at');
  if (value.status !== 'COMPLETED') return { value, terminal: false };
  if ([value.lease_claim_hmac_sha256, value.lease_claimed_at, value.lease_expires_at].some((field) => field !== null) ||
      ![value.completion_claim_hmac_sha256, value.arc2_start_receipt_sha256,
        value.completion_receipt_sha256].every((field) => HEX_64.test(field || ''))) {
    throw new Error('payment-start-outbox-completion-invalid');
  }
  iso(value.completed_at, 'Payment start outbox completed_at');
  return { value, terminal: true };
}

function validateStripeReviewCheckoutBinding(value, key, handoff = null) {
  if (!exactKeys(value, STRIPE_REVIEW_CHECKOUT_HANDOFF_FIELDS) ||
      value.schema !== 'arc-stripe-review-checkout-handoff-binding-v1' ||
      !HEX_64.test(value.handoff_id || '') || key !== `stripe-checkout-handoff/${value.handoff_id}` ||
      value.payment_link_id_hmac_sha256 !== null ||
      !['checkout_session_id_hmac_sha256', 'payment_intent_id_hmac_sha256', 'payment_evidence_sha256',
        'bridge_immutable_binding_sha256', 'review_session_binding_sha256', 'approval_receipt_sha256',
        'recipient_email_sha256', 'payer_email_sha256', 'review_checkout_binding_sha256',
        'stripe_account_id_sha256'].every((field) => HEX_64.test(value[field] || '')) ||
      typeof value.livemode !== 'boolean' || handoff &&
      (value.handoff_id !== handoff.handoff_id || value.payment_evidence_sha256 !== handoff.payment_evidence_sha256)) {
    throw new Error('stripe-review-checkout-handoff-invalid');
  }
  return value;
}

async function paymentBridgeHandoff(context, outbox) {
  let match = null;
  await scanEntries(context.stores.handoff, 'stripe-checkout-handoff/', async (key, entry) => {
    if (!entry) {
      await persistMissingSourceAnomaly(context, 'handoff', context.stores.handoff,
        key, null, 'PAYMENT_BRIDGE_LISTED_SOURCE_MISSING');
      throw new Error('payment-bridge-listed-source-missing');
    }
    if (isRetentionTombstone(entry.value) ||
        entry.value?.schema !== 'arc-stripe-review-checkout-handoff-binding-v1') return false;
    let binding;
    try { binding = validateStripeReviewCheckoutBinding(entry.value, key); } catch { return false; }
    if (binding.bridge_immutable_binding_sha256 !== outbox.immutable_sha256 ||
        binding.review_session_binding_sha256 !== outbox.immutable.review_session_binding_sha256 ||
        binding.checkout_session_id_hmac_sha256 !== outbox.immutable.checkout_session_id_hmac_sha256 ||
        binding.payment_intent_id_hmac_sha256 !== outbox.immutable.payment_intent_id_hmac_sha256 ||
        binding.approval_receipt_sha256 !== outbox.immutable.approval_receipt_sha256 ||
        binding.recipient_email_sha256 !== outbox.immutable.recipient_email_sha256 ||
        binding.payer_email_sha256 !== outbox.immutable.payer_email_sha256 ||
        binding.stripe_account_id_sha256 !== outbox.immutable.stripe_account_id_sha256 ||
        binding.livemode !== outbox.immutable.livemode) return false;
    if (match) throw new Error('payment-bridge-handoff-ambiguous');
    match = binding;
    return false;
  });
  if (!match) return null;
  const current = await currentCandidate(context, 'handoff', match.handoff_id);
  if (!current) return null;
  validateStripeReviewCheckoutBinding(match, `stripe-checkout-handoff/${match.handoff_id}`, current.value);
  return { binding: match, handoff: current.value };
}

async function handlePaymentChild(entry, context) {
  void entry;
  void context;
  return baseResult({ held: 1 });
}

async function handleHandoffAlert(entry, context) {
  const { key, value } = entry;
  try {
    const reversal = key.startsWith('alerts/stripe-reversal/');
    const unbound = key.startsWith('alerts/stripe-reversal-unbound/');
    const checkout = key.startsWith('alerts/stripe-checkout-review/');
    const identity = key.split('/').at(-1);
    if ((!reversal && !unbound && !checkout) || !HEX_64.test(identity || '') ||
        !exactKeys(value, REVERSAL_ALERT_FIELDS) || value.schema !== 'arc-operational-alert-v1' ||
        value.status !== 'OPEN' || value.delivery_status !== 'PENDING' ||
        value.contains_customer_data !== false || value.subject_hmac_sha256 !== identity ||
        value.severity !== (checkout || unbound ? 'critical' : value.severity) ||
        !['high', 'critical'].includes(value.severity) ||
        value.category !== (checkout ? 'stripe-checkout-review' : unbound ? 'stripe-reversal-unbound' : 'stripe-reversal') ||
        (reversal ? !HEX_64.test(value.handoff_id || '') : value.handoff_id !== null)) {
      throw new Error('handoff-alert-invalid');
    }
    iso(value.detected_at, 'Handoff alert detected_at');
    return { ...baseResult({ held: 1 }), ...await quarantine(
      context, 'handoff', key, value, 'UNRESOLVED_PAYMENT_SAFETY_ALERT',
    ) };
  } catch {
    return { ...baseResult({ held: 1 }), ...await quarantine(
      context, 'handoff', key, value, 'HANDOFF_ALERT_INVALID',
    ) };
  }
}

async function handleHandoffCandidate(entry, context) {
  const { key, value } = entry;
  const id = key.match(/^handoffs\/([a-f0-9]{64})$/)?.[1];
  try {
    if (!id) throw new Error('handoff-invalid');
    const record = validateExpectedBindings(value);
    if (await activeLegalHold(context, 'handoff', id)) return baseResult({ held: 1 });
    if (await handoffCandidateStateValid(record, id, context)) {
      await markCandidate(context, 'handoff', id, record);
      return baseResult({ candidates: 1 });
    }
    return baseResult({ held: 1 });
  } catch {
    return { ...baseResult(), ...await quarantine(context, 'handoff', key, value, 'HANDOFF_RECORD_INVALID') };
  }
}

async function paymentCandidate(context, id) {
  if (!HEX_64.test(id || '')) return false;
  const entry = await getEntry(context.stores.control, paymentCandidateKey(context.sweep, id));
  if (!entry) return false;
  verify(entry.value, 'arc-first-party-retention-payment-candidate-record-v1', context.configuration.secret);
  if (!exactKeys(entry.value, ['customer_data_stored', 'handoff_id', 'marked_at',
    'payment_intent_id_hmac_sha256', 'record_hmac_sha256', 'schema', 'source_record_sha256',
    'sweep_hmac_sha256', 'version']) ||
      entry.value.schema !== 'arc-first-party-retention-payment-candidate-v1' || entry.value.version !== 1 ||
      entry.value.payment_intent_id_hmac_sha256 !== id || entry.value.sweep_hmac_sha256 !== context.sweep ||
      !HEX_64.test(entry.value.handoff_id || '') || !HEX_64.test(entry.value.source_record_sha256 || '') ||
      entry.value.customer_data_stored !== false ||
      !await currentCandidate(context, 'handoff', entry.value.handoff_id)) return null;
  const source = await getEntry(context.stores.handoff, `stripe-payment-intent/${id}`);
  if (!source) {
    await recordMissingMarkedSource(context, 'handoff', entry.value.handoff_id,
      context.stores.handoff, `stripe-payment-intent/${id}`,
      entry.value.source_record_sha256, 'MARKED_PAYMENT_SOURCE_MISSING');
    return null;
  }
  if (source && (recordSha(source.value) !== entry.value.source_record_sha256 ||
      source.value?.payment_intent_id_hmac_sha256 !== id || source.value?.handoff_id !== entry.value.handoff_id)) return null;
  return entry.value;
}

async function collectHandoffSubjectMutations(context, handoffId, primary) {
  const mutations = [];
  const scanned = new Set();
  let listedSourceMissing = false;
  for (const phase of PHASES.filter((value) =>
    ['handoff-child', 'payment-child', 'handoff-alert'].includes(value.kind))) {
    const identity = `${phase.store}\n${phase.prefix}`;
    if (scanned.has(identity)) continue;
    scanned.add(identity);
    const store = context.stores[phase.store];
    await scanEntries(store, phase.prefix, async (key, entry) => {
      if (!entry) {
        await persistMissingSourceAnomaly(context, 'handoff', store, key, null,
          'HANDOFF_MANIFEST_LISTED_SOURCE_MISSING');
        listedSourceMissing = true;
        return false;
      }
      if (isRetentionTombstone(entry.value)) return false;
      const owner = phase.store === 'payment'
        ? await handoffIdForPaymentChild(context, key, entry.value)
        : phase.store === 'alerts'
          ? await handoffAlertBelongsTo(context, key, entry.value, handoffId) ? handoffId : null
          : await handoffIdForRawChild(context, key, entry.value);
      if (owner !== handoffId) return false;
      const sourceRecordSha256 = recordSha(entry.value);
      const output = buildRetentionTombstone(context, 'handoff', key, sourceRecordSha256);
      mutations.push({
        action: 'TOMBSTONE', family: 'handoff', key, output,
        outputRecordSha256: recordSha(output), role: 'CHILD',
        sourceRecordSha256, sourceValue: entry.value, store, storeName: phase.store,
      });
      return false;
    });
  }
  const sourceRecordSha256 = recordSha(primary.value);
  const key = `handoffs/${handoffId}`;
  const output = buildRetentionTombstone(context, 'handoff', key, sourceRecordSha256);
  mutations.push({
    action: 'TOMBSTONE', family: 'handoff', key, output,
    outputRecordSha256: recordSha(output), role: 'PRIMARY',
    sourceRecordSha256, sourceValue: primary.value, store: context.stores.handoff,
    storeName: 'handoff',
  });
  return { listedSourceMissing, mutations };
}

async function paymentChildPlanValid(context, mutation, handoffId) {
  const { key, sourceValue: value } = mutation;
  if (await handoffIdForPaymentChild(context, key, value) !== handoffId) return false;
  if (key.startsWith('payment-arc2-start-outbox/')) {
    return validatePaymentStartOutbox(value, key, context).terminal;
  }
  if (key.startsWith('payment-review-session-binding/')) {
    validatePaymentReviewBinding(value, key, context);
    return true;
  }
  if (key.startsWith('payment-arc2-pending/')) {
    if (!exactKeys(value, PAYMENT_PENDING_FIELDS) || value.schema !== 'arc-payment-arc2-pending-index-v1' ||
        !/^payment-arc2-start-outbox\/[a-f0-9]{64}$/.test(value.outbox_key) ||
        key !== `payment-arc2-pending/${value.outbox_key.split('/').at(-1)}` ||
        !HEX_64.test(value.immutable_binding_sha256 || '')) return false;
    const outbox = await getEntryUnderFence(context, context.stores.payment, value.outbox_key);
    return Boolean(outbox && !isRetentionTombstone(outbox.value) &&
      validatePaymentStartOutbox(outbox.value, value.outbox_key, context).terminal);
  }
  return false;
}

async function authorizeHandoffSubjectPlan(context, handoffId, primary, mutations) {
  const children = mutations.filter((value) => value.role === 'CHILD');
  const plannedChildren = children;
  const plans = await planHandoffChildSet({
    entries: plannedChildren.map((value) => ({ key: value.key, value: value.sourceValue })),
    primary: primary.value,
    env: context.env,
    read: async (key) =>
      (await getEntryUnderFence(context, context.stores.handoff, key))?.value || null,
  });
  let allowed = true;
  for (const planned of plans) {
    const mutation = plannedChildren.find((value) => value.key === planned.key);
    if (mutation.storeName === 'payment') continue;
    const accountableReversal = planned.key.startsWith('stripe-reversal-event/') &&
      planned.plan.validated && planned.plan.reason === 'REVERSAL_EVENT_REQUIRES_ACCOUNTABLE_RELEASE';
    const action = planned.plan.action === HANDOFF_CHILD_RETENTION_ACTION.CASCADE || accountableReversal
      ? 'CASCADE' : 'PRESERVE';
    await persistHandoffChildPlan(context, handoffId, mutation.storeName,
      planned.key, mutation.sourceValue,
      action, planned.plan.reason, planned.plan.family);
    if (action !== 'CASCADE') allowed = false;
  }
  for (const mutation of children.filter((value) => value.storeName === 'payment')) {
    let valid = false;
    try { valid = await paymentChildPlanValid(context, mutation, handoffId); } catch { valid = false; }
    await persistHandoffChildPlan(context, handoffId, mutation.storeName,
      mutation.key, mutation.sourceValue,
      valid ? 'CASCADE' : 'PRESERVE', valid ? 'EXACT_HANDOFF_PAYMENT_BINDING' :
        'HANDOFF_PAYMENT_BINDING_INVALID', 'payment');
    if (!valid) allowed = false;
  }
  return { allowed, child_count: children.length, handoff_id: handoffId,
    plan_count: plans.length };
}

async function handleHandoffChild(entry, context) {
  void entry;
  void context;
  // Handoff children are planned as one immutable overlay and cascaded only by
  // the handoff-primary phase while the global generation fence is FROZEN.
  return baseResult({ held: 1 });
}

async function handoffHasRemainingChildren(context, handoffId) {
  for (const phase of PHASES.filter((value) => value.store === 'handoff' && value.kind === 'handoff-child')) {
    const blocked = await scanEntries(context.stores.handoff, phase.prefix, async (key, entry) => {
      if (!entry) {
        await persistMissingSourceAnomaly(
          context, 'handoff', context.stores.handoff, key, null,
          'HANDOFF_CHILD_LISTED_SOURCE_MISSING',
        );
        return true;
      }
      if (isRetentionTombstone(entry.value)) {
        try {
          validateRetentionTombstone(entry.value, context, 'handoff', key);
          return false;
        } catch {
          return true;
        }
      }
      const owner = await handoffIdForRawChild(context, key, entry.value);
      if (owner === handoffId) return true;
      return false;
    }, 500, context);
    if (blocked) return true;
  }
  return false;
}

async function handoffIdForPaymentChild(context, key, value) {
  if (key.startsWith('payment-arc2-pending/')) {
    const outbox = typeof value?.outbox_key === 'string'
      ? await getEntryUnderFence(context, context.stores.payment, value.outbox_key) : null;
    return outbox && !isRetentionTombstone(outbox.value)
      ? handoffIdForPaymentChild(context, value.outbox_key, outbox.value) : null;
  }
  const bridgeBinding = key.startsWith('payment-arc2-start-outbox/')
    ? value?.immutable_sha256 : null;
  const reviewBinding = key.startsWith('payment-review-session-binding/')
    ? value?.immutable_sha256 : value?.immutable?.review_session_binding_sha256 || null;
  if (!HEX_64.test(bridgeBinding || '') && !HEX_64.test(reviewBinding || '')) return null;
  let matched = null;
  const ambiguous = await scanEntries(context.stores.handoff, 'stripe-checkout-handoff/',
    async (bindingKey, entry) => {
      const binding = entry?.value;
      if (!entry) {
        await persistMissingSourceAnomaly(context, 'handoff', context.stores.handoff,
          bindingKey, null, 'PAYMENT_OWNER_LISTED_SOURCE_MISSING');
        return true;
      }
      if (isRetentionTombstone(binding) ||
          binding?.schema !== 'arc-stripe-review-checkout-handoff-binding-v1' ||
          bridgeBinding && binding.bridge_immutable_binding_sha256 !== bridgeBinding ||
          reviewBinding && binding.review_session_binding_sha256 !== reviewBinding ||
          !HEX_64.test(binding.handoff_id || '')) return false;
      if (matched && matched !== binding.handoff_id) return true;
      matched = binding.handoff_id;
      return false;
    }, 500, context);
  return ambiguous ? null : matched;
}

async function handoffHasRemainingPaymentChildren(context, handoffId) {
  for (const phase of PHASES.filter((value) => value.store === 'payment')) {
    const blocked = await scanEntries(context.stores.payment, phase.prefix, async (key, entry) => {
      if (!entry) {
        await persistMissingSourceAnomaly(
          context, 'handoff', context.stores.payment, key, null,
          'PAYMENT_CHILD_LISTED_SOURCE_MISSING',
        );
        return true;
      }
      if (isRetentionTombstone(entry.value)) {
        try {
          validateRetentionTombstone(entry.value, context, 'handoff', key);
          return false;
        } catch { return true; }
      }
      const owner = await handoffIdForPaymentChild(context, key, entry.value);
      if (owner === handoffId) return true;
      return false;
    }, 500, context);
    if (blocked) return true;
  }
  return false;
}

async function handoffHasRemainingAlerts(context, handoffId) {
  for (const phase of PHASES.filter((value) => value.store === 'alerts')) {
    if (await scanEntries(context.stores.alerts, phase.prefix, async (key, entry) => {
      if (!entry) {
        await persistMissingSourceAnomaly(context, 'handoff', context.stores.alerts, key, null,
          'HANDOFF_FINAL_ALERT_LISTED_SOURCE_MISSING');
        return true;
      }
      return !isRetentionTombstone(entry.value) &&
        await handoffAlertBelongsTo(context, key, entry.value, handoffId);
    }, 500, context)) {
      return true;
    }
  }
  return false;
}

async function handleHandoffPrimary(entry, context) {
  const id = entry.key.match(/^handoffs\/([a-f0-9]{64})$/)?.[1];
  const current = id ? await currentCandidate(context, 'handoff', id) : null;
  if (!current) return baseResult({ held: 1 });
  const open = await ensureRetentionGenerationFence(context.stores.control, context.env,
    { clock: () => liveFenceClock(context) });
  if (open.record.status !== 'OPEN') return baseResult({ held: 1, retryable: true });
  const collected = await collectHandoffSubjectMutations(context, id, current);
  if (collected.listedSourceMissing) return baseResult({ held: 1 });
  return baseResult(await runFrozenSubjectMutation(context, {
    family: 'handoff',
    subject: id,
    open,
    mutations: collected.mutations,
    recheck: async (frozenContext) => ({
      allowed: Boolean(await currentCandidate(frozenContext, 'handoff', id)),
      legal_holds_rechecked: [id],
      paid_release_rechecked: await validatePaidRelease(frozenContext, current.value),
    }),
    beforeMutate: (frozenContext, frozenMutations) =>
      authorizeHandoffSubjectPlan(frozenContext, id, current, frozenMutations),
    primaryAfterChildren: true,
    beforePrimary: async (frozenContext) =>
      !await handoffHasRemainingChildren(frozenContext, id) &&
      !await handoffHasRemainingPaymentChildren(frozenContext, id) &&
      !await handoffHasRemainingAlerts(frozenContext, id),
  }));
}

async function resumeHandoffSubjectPlan(context, handoffId, primary, mutations) {
  const children = mutations.filter((value) => value.role === 'CHILD');
  let missingPlan = false;
  let preserved = false;
  for (const mutation of children) {
    const plan = await readHandoffChildPlan(
      context, handoffId, mutation.storeName, mutation.key, mutation.sourceRecordSha256,
    );
    if (!plan) missingPlan = true;
    else if (plan.plan_action !== 'CASCADE') preserved = true;
  }
  if (!missingPlan) return { allowed: !preserved, handoff_id: handoffId,
    plan_count: children.length, resumed_plan: true };
  if (children.some((value) => value.currentIsOutput)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_PARTIAL_HANDOFF_PLAN_MISSING');
  }
  return authorizeHandoffSubjectPlan(context, handoffId, primary, mutations);
}

async function reconstructRewriteOutput(context, item, source) {
  if (source.schema === 'arc-review-checkout-recipient-index-v1') {
    validateReviewCheckoutIndex(source, item.source_key, context);
    const retained = [];
    for (const binding of source.bindings) {
      if (!await currentCandidate(context, 'checkout', binding.binding_hmac_sha256)) {
        retained.push(binding);
      }
    }
    return sign({ ...unsigned(source), record_revision: source.record_revision + 1,
      bindings: retained, updated_at: context.startedAt },
    'arc-review-checkout-recipient-index-signature-v1',
    context.env.ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET);
  }
  if (source.schema === 'arc-preview-review-email-pending-v1') {
    verifySource(source, context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
      'arc-preview-review-email-pending-record-signature-v1');
    const retained = [];
    for (const entry of source.entries || []) {
      if (!await currentCandidate(context, 'review', entry.invite_hmac_sha256)) retained.push(entry);
    }
    return sign({ ...unsigned(source), record_revision: source.record_revision + 1,
      entries: retained, updated_at: context.startedAt },
    'arc-preview-review-email-pending-record-signature-v1',
    context.env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET);
  }
  throw new Error('ARC_FIRST_PARTY_RETENTION_REWRITE_RECONSTRUCTION_UNAVAILABLE');
}

async function persistedFrozenSubjectContext(env, stores, adapters, configuration, now, state) {
  const intentEntry = await getEntry(stores.control,
    retentionGenerationFenceKeys.freezeIntent(state.operation_hmac_sha256));
  if (!intentEntry) throw new Error('ARC_FIRST_PARTY_RETENTION_FREEZE_INTENT_MISSING');
  const intent = validateRetentionFreezeIntent(intentEntry.value, env);
  if (intent.operation_hmac_sha256 !== state.operation_hmac_sha256 ||
      intent.generation !== state.generation) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_FREEZE_INTENT_MISBOUND');
  }
  const manifestEntry = await getEntry(stores.control,
    retentionManifestKey(intent.generation, intent.subject_hmac_sha256, intent.manifest_sha256));
  if (!manifestEntry) throw new Error('ARC_FIRST_PARTY_RETENTION_SUBJECT_MANIFEST_MISSING');
  const manifest = validateSubjectManifest(manifestEntry.value, intent, env);
  const context = {
    env, stores, adapters, configuration, sweep: manifest.sweep_hmac_sha256, now,
    startedAt: manifest.built_at,
    unpaidCutoff: now.getTime() - configuration.unpaid_days * 24 * 60 * 60_000,
    paidCutoff: now.getTime() - configuration.paid_days * 24 * 60 * 60_000,
  };
  const descriptor = {
    generation: intent.generation,
    manifest_entry_count: intent.manifest_entry_count,
    manifest_sha256: intent.manifest_sha256,
    subject_hmac_sha256: intent.subject_hmac_sha256,
  };
  context.freezeDescriptor = descriptor;
  const mutations = [];
  for (const item of manifest.entries) {
    const store = stores[item.store];
    if (!store) throw new Error('ARC_FIRST_PARTY_RETENTION_MANIFEST_STORE_UNAVAILABLE');
    const current = await getEntry(store, item.source_key);
    if (!current) {
      await persistMissingSourceAnomaly({ ...context, freezeDescriptor: {
        generation: intent.generation,
        manifest_entry_count: intent.manifest_entry_count,
        manifest_sha256: intent.manifest_sha256,
        subject_hmac_sha256: intent.subject_hmac_sha256,
      } }, item.family, store, item.source_key, item.source_record_sha256,
      'RESUMED_FROZEN_MANIFEST_SOURCE_MISSING');
      return { blocked: true, context, intent, manifest, mutations: [] };
    }
    const currentSha = recordSha(current.value);
    if (currentSha !== item.source_record_sha256 && currentSha !== item.output_record_sha256) {
      throw new Error('ARC_FIRST_PARTY_RETENTION_RESUMED_SOURCE_DRIFT');
    }
    let output = current.value;
    if (item.action === 'TOMBSTONE') {
      output = buildRetentionTombstone(context, item.family, item.source_key,
        item.source_record_sha256);
      if (recordSha(output) !== item.output_record_sha256) {
        throw new Error('ARC_FIRST_PARTY_RETENTION_RESUMED_TOMBSTONE_MISMATCH');
      }
    } else if (item.action === 'REWRITE' && currentSha !== item.output_record_sha256) {
      try { output = await reconstructRewriteOutput(context, item, current.value); } catch {
        return { blocked: true, unresumableRewrite: true, context, intent, manifest, mutations: [] };
      }
      if (recordSha(output) !== item.output_record_sha256) {
        return { blocked: true, unresumableRewrite: true, context, intent, manifest, mutations: [] };
      }
    }
    mutations.push({
      action: item.action, family: item.family, key: item.source_key, output,
      outputRecordSha256: item.output_record_sha256, role: item.role,
      sourceRecordSha256: item.source_record_sha256, sourceValue: current.value,
      currentIsOutput: currentSha === item.output_record_sha256, store, storeName: item.store,
    });
  }
  return { blocked: false, context, intent, manifest, mutations };
}

async function resumePersistedRetentionFreeze(env, stores, adapters, configuration, now, state) {
  let persisted;
  try {
    persisted = await persistedFrozenSubjectContext(
      env, stores, adapters, configuration, now, state,
    );
  } catch {
    const recovery = await recoverStaleRetentionGenerationFence(stores.control, env, {
      clock: () => now,
      emitCriticalAlert: adapters.emitCriticalAlert,
      validateCompletion: async () => false,
    });
    return { blocked: true, recovery };
  }
  if (persisted.blocked) {
    const recovery = await recoverStaleRetentionGenerationFence(stores.control, env, {
      clock: () => now,
      emitCriticalAlert: adapters.emitCriticalAlert,
      validateCompletion: async () => false,
    });
    return { blocked: true, missing_source: !persisted.unresumableRewrite, recovery };
  }
  const { context, intent, manifest, mutations } = persisted;
  const descriptor = {
    generation: intent.generation,
    manifest_entry_count: intent.manifest_entry_count,
    manifest_sha256: intent.manifest_sha256,
    subject_hmac_sha256: intent.subject_hmac_sha256,
  };
  const primary = mutations.find((value) => value.role === 'PRIMARY');
  const subjectId = primary?.key.split('/').at(-1) || null;
  const primarySource = primary && !primary.currentIsOutput ? { value: primary.sourceValue } : null;
  const input = {
    family: manifest.family,
    subject: subjectId || manifest.subject_hmac_sha256,
    resumeDescriptor: descriptor,
    persistedManifest: manifest,
    mutations,
    recheck: async (frozenContext) => {
      if (!subjectId || manifest.family === 'intake_abuse') return { allowed: true, resumed: true };
      if (await activeLegalHold(frozenContext, manifest.family, subjectId)) {
        return { allowed: false, legal_holds_rechecked: [subjectId], resumed: true };
      }
      if (primary?.currentIsOutput) return { allowed: true, legal_holds_rechecked: [subjectId], resumed: true };
      return { allowed: Boolean(await currentCandidate(frozenContext, manifest.family, subjectId)),
        legal_holds_rechecked: [subjectId], resumed: true };
    },
  };
  if (manifest.family === 'checkout') {
    input.primaryAfterChildren = true;
    input.beforePrimary = async (frozenContext) =>
      !await checkoutHasBoundChildren(frozenContext, subjectId);
  } else if (manifest.family === 'review') {
    input.primaryAfterChildren = true;
    input.beforePrimary = async (frozenContext) =>
      !await reviewHasBoundChildren(frozenContext, subjectId, primarySource?.value);
  } else if (manifest.family === 'handoff') {
    input.beforeMutate = (frozenContext, frozenMutations) =>
      resumeHandoffSubjectPlan(frozenContext, subjectId, primarySource || { value: primary.sourceValue },
        frozenMutations);
    input.primaryAfterChildren = true;
    input.beforePrimary = async (frozenContext) =>
      !await handoffHasRemainingChildren(frozenContext, subjectId) &&
      !await handoffHasRemainingPaymentChildren(frozenContext, subjectId) &&
      !await handoffHasRemainingAlerts(frozenContext, subjectId);
  }
  return runFrozenSubjectMutation(context, input);
}

async function handleDeferredSubjectChild() {
  // Review and Checkout children are discovered again with full pagination
  // and mutated only by their primary's single FROZEN subject manifest.
  return baseResult({ held: 1 });
}

const HANDLERS = Object.freeze({
  abuse: handleAbuse,
  'checkout-candidate': handleCheckoutCandidate,
  'review-candidate': handleReviewCandidate,
  'revision-work': handleDeferredSubjectChild,
  'revision-pending': handleDeferredSubjectChild,
  'review-outbox': handleDeferredSubjectChild,
  'review-resend-attempt': handleDeferredSubjectChild,
  'review-provider-index': handleDeferredSubjectChild,
  'review-renewal': handleDeferredSubjectChild,
  'checkout-alert': handleDeferredSubjectChild,
  'checkout-index': handleDeferredSubjectChild,
  'review-pending': handleDeferredSubjectChild,
  'review-recipient': handleReviewRecipient,
  'checkout-primary': handleCheckoutPrimary,
  'review-primary': handleReviewPrimary,
  'handoff-candidate': handleHandoffCandidate,
  'payment-child': handlePaymentChild,
  'handoff-child': handleHandoffChild,
  'handoff-alert': handleHandoffAlert,
  'handoff-primary': handleHandoffPrimary,
});

async function finalizedManifestReplayDeletionCount(context, primaryKey, tombstone) {
  if (tombstone.sweep_hmac_sha256 !== context.sweep) return 0;
  const primaryDigest = recordSha(tombstone);
  let recovered = null;
  await scanEntries(context.stores.control, 'first-party-retention/generation-manifests/',
    async (key, entry) => {
      if (!entry) {
        await persistMissingSourceAnomaly(context, tombstone.family, context.stores.control,
          key, null, 'FINALIZED_MANIFEST_LISTED_SOURCE_MISSING');
        throw new Error('ARC_FIRST_PARTY_RETENTION_FINALIZED_MANIFEST_SOURCE_MISSING');
      }
      const candidate = entry.value;
      if (candidate?.schema !== RETENTION_SUBJECT_MANIFEST_SCHEMA ||
          candidate.sweep_hmac_sha256 !== context.sweep || candidate.family !== tombstone.family ||
          !Array.isArray(candidate.entries) || !candidate.entries.some((item) =>
            item.role === 'PRIMARY' && item.source_key === primaryKey &&
            item.output_record_sha256 === primaryDigest)) return false;
      const descriptor = {
        generation: candidate.generation,
        manifest_entry_count: candidate.entries.length,
        manifest_sha256: recordSha(candidate),
        subject_hmac_sha256: candidate.subject_hmac_sha256,
      };
      const manifest = validateSubjectManifest(candidate, descriptor, context.env);
      const operation = retentionFreezeOperationHmac(descriptor, context.env);
      const intentEntry = await getEntry(context.stores.control,
        retentionGenerationFenceKeys.freezeIntent(operation));
      const receiptEntry = await getEntry(context.stores.control,
        retentionGenerationFenceKeys.finalizeReceipt(operation));
      if (!intentEntry || !receiptEntry) return false;
      const intent = validateRetentionFreezeIntent(intentEntry.value, context.env);
      const receipt = validateRetentionFinalizeReceipt(receiptEntry.value, intent, context.env);
      if (receipt.primary_tombstone_sha256 !== primaryDigest) return false;
      const count = manifest.entries.filter((item) => item.action !== 'PRESERVE').length;
      if (recovered !== null && recovered !== count) {
        throw new Error('ARC_FIRST_PARTY_RETENTION_FINALIZED_MANIFEST_COUNT_AMBIGUOUS');
      }
      recovered = count;
      return false;
    });
  return recovered || 0;
}

async function processPhase(phase, cursor, limit, context) {
  const store = context.stores[phase.store];
  if (!store) throw new Error('ARC_FIRST_PARTY_RETENTION_STORE_UNAVAILABLE');
  const listed = await listEntries(store, phase.prefix, cursor, limit);
  const totals = Object.fromEntries(COUNT_FIELDS.map((field) => [field, 0]));
  let processedCursor = cursor;
  for (const item of listed.entries) {
    const phaseContext = { ...context, phaseStore: store };
    const entry = await getEntry(store, item.key);
    if (!entry) {
      await persistMissingSourceAnomaly(
        phaseContext, phase.family, store, item.key, null, 'LISTED_SOURCE_MISSING_BEFORE_REVIEW',
      );
      totals.held += 1;
      totals.quarantined += 1;
      continue;
    }
    let result;
    if (isRetentionTombstone(entry.value)) {
      try {
        validateRetentionTombstone(entry.value, phaseContext, phase.family, item.key);
        result = baseResult({
          deleted: await finalizedManifestReplayDeletionCount(phaseContext, item.key, entry.value),
        });
      } catch {
        result = { ...baseResult({ held: 1 }), ...await quarantine(
          phaseContext, phase.family, item.key, entry.value, 'RETENTION_TOMBSTONE_INVALID', store,
        ) };
      }
    } else {
      result = await HANDLERS[phase.kind]({ key: item.key, value: entry.value, etag: entry.etag }, phaseContext);
    }
    if (result.retryable) {
      return { counts: totals, next_cursor: processedCursor, complete: false, retryable: true };
    }
    for (const field of COUNT_FIELDS) totals[field] += result[field];
    processedCursor = item.key;
  }
  return { counts: totals, next_cursor: listed.next_cursor, complete: listed.next_cursor === null };
}

async function readState(store, secret) {
  const entry = await getEntry(store, FIRST_PARTY_RETENTION_STATE_KEY);
  return entry ? { value: validateState(entry.value, secret), etag: entry.etag } : null;
}

async function replaceState(store, entry, value, secret) {
  const signed = sign(value, 'arc-first-party-retention-sweep-record-v1', secret);
  validateState(signed, secret);
  const result = await store.setJSON(FIRST_PARTY_RETENTION_STATE_KEY, signed, { onlyIfMatch: entry.etag });
  if (!result?.modified || typeof result.etag !== 'string') throw new Error('ARC_FIRST_PARTY_RETENTION_STATE_CONTENTION');
  return { value: signed, etag: result.etag };
}

function freshState(now, sweep, deploymentSha) {
  return {
    schema: FIRST_PARTY_RETENTION_SWEEP_SCHEMA, version: 1, status: 'IDLE',
    sweep_hmac_sha256: sweep, deployment_sha: deploymentSha, phase_index: 0, cursor: null,
    counts: emptyCounts(), started_at: now.toISOString(), completed_at: null, next_sweep_at: null,
    lease_hmac_sha256: null, lease_expires_at: null, run_count: 0,
  };
}

async function createState(store, value, secret) {
  const signed = sign(value, 'arc-first-party-retention-sweep-record-v1', secret);
  try { await store.setJSON(FIRST_PARTY_RETENTION_STATE_KEY, signed, { onlyIfNew: true }); } catch {}
  const entry = await readState(store, secret);
  if (!entry) throw new Error('ARC_FIRST_PARTY_RETENTION_STATE_UNAVAILABLE');
  return entry;
}

const receiptKey = (sweep) => `first-party-retention/completions/${sweep}`;

async function ensureReceipt(store, state, completedAt, secret) {
  const value = sign({
    schema: FIRST_PARTY_RETENTION_RECEIPT_SCHEMA, version: 1,
    sweep_hmac_sha256: state.sweep_hmac_sha256, deployment_sha: state.deployment_sha,
    families: [...FAMILIES], started_at: state.started_at, completed_at: completedAt,
    next_sweep_at: new Date(Date.parse(completedAt) + FIRST_PARTY_RETENTION_INTERVAL_MS).toISOString(),
    counts: state.counts, customer_data_stored: false,
  }, 'arc-first-party-retention-completion-record-v1', secret);
  try { await store.setJSON(receiptKey(state.sweep_hmac_sha256), value, { onlyIfNew: true }); } catch {}
  const stored = await getEntry(store, receiptKey(state.sweep_hmac_sha256));
  if (!stored || canonicalJson(stored.value) !== canonicalJson(value)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_RECEIPT_CONFLICT');
  }
  return stored.value;
}

function completedState(state, receipt) {
  return { ...state, status: 'COMPLETE', phase_index: PHASES.length, cursor: null,
    counts: receipt.counts, completed_at: receipt.completed_at, next_sweep_at: receipt.next_sweep_at,
    lease_hmac_sha256: null, lease_expires_at: null };
}

export async function runFirstPartyRetentionSweepCycle(env, stores, adapters = {}) {
  if (!stores?.control || !stores?.abuse || !stores?.review || !stores?.revision || !stores?.handoff ||
      !stores?.payment || !stores?.alerts) {
    throw new TypeError('First-party retention stores are invalid.');
  }
  const requested = firstPartyRetentionConfiguration(env);
  if (!requested.enabled) return Object.freeze({ state: 'DISABLED', phase: null, next_cursor: null });
  const configuration = requireConfiguration(env);
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('First-party retention clock is invalid.');
  const initialFence = await ensureRetentionGenerationFence(stores.control, env, { clock: () => now });
  if (initialFence.record.status === 'WRITING') {
    const recovery = await recoverStaleRetentionGenerationFence(stores.control, env, {
      clock: () => now,
      emitCriticalAlert: adapters.emitCriticalAlert,
      validateCompletion: async (evidence) => typeof adapters.validateFenceCompletion === 'function' &&
        await adapters.validateFenceCompletion(evidence) === true,
    });
    if (recovery.state !== 'RECOVERED') {
      return Object.freeze({
        state: recovery.critical_alert ? 'BLOCKED' : 'IN_PROGRESS', phase: null,
        next_cursor: null, idempotent_replay: true,
        critical_alert: recovery.critical_alert === true,
        ...(recovery.reason_code ? { reason_code: recovery.reason_code } : {}),
      });
    }
  } else if (initialFence.record.status === 'FROZEN') {
    const resumed = await resumePersistedRetentionFreeze(
      env, stores, adapters, configuration, now, initialFence.record,
    );
    if (resumed.retryable) {
      return Object.freeze({ state: 'IN_PROGRESS', phase: null, next_cursor: null,
        idempotent_replay: true });
    }
    if (resumed.blocked || resumed.missing_source) {
      return Object.freeze({ state: 'BLOCKED', phase: null, next_cursor: null,
        idempotent_replay: true, critical_alert: Boolean(resumed.recovery?.critical_alert),
        ...(resumed.recovery?.reason_code ? { reason_code: resumed.recovery.reason_code } : {}) });
    }
  }
  const uuid = String((adapters.uuid || randomUUID)());
  const newSweep = () => hmac(configuration.secret,
    `arc-first-party-retention-sweep-id-v1\n${configuration.deployment_sha}\n${now.toISOString()}\n${uuid}`);
  let entry = await readState(stores.control, configuration.secret);
  if (!entry) entry = await createState(stores.control,
    freshState(now, newSweep(), configuration.deployment_sha), configuration.secret);
  const existingReceipt = await getEntry(stores.control, receiptKey(entry.value.sweep_hmac_sha256));
  if (existingReceipt && entry.value.status !== 'COMPLETE') {
    const receipt = validateFirstPartyRetentionReceipt(existingReceipt.value, env);
    entry = await replaceState(stores.control, entry, completedState(entry.value, receipt), configuration.secret);
  }
  if (entry.value.status === 'COMPLETE' && Date.parse(entry.value.next_sweep_at) > now.getTime()) {
    return Object.freeze({ state: 'COMPLETE', phase: null, next_cursor: null,
      sweep_hmac_sha256: entry.value.sweep_hmac_sha256, idempotent_replay: true,
      receipt: existingReceipt?.value || (await getEntry(stores.control, receiptKey(entry.value.sweep_hmac_sha256)))?.value });
  }
  if (entry.value.status === 'COMPLETE') {
    entry = await replaceState(stores.control, entry,
      freshState(now, newSweep(), configuration.deployment_sha), configuration.secret);
  }
  if (entry.value.status === 'RUNNING' && Date.parse(entry.value.lease_expires_at) > now.getTime()) {
    return Object.freeze({ state: 'IN_PROGRESS', phase: PHASES[entry.value.phase_index]?.kind || null,
      next_cursor: entry.value.cursor, sweep_hmac_sha256: entry.value.sweep_hmac_sha256,
      idempotent_replay: true });
  }
  const lease = hmac(configuration.secret,
    `arc-first-party-retention-lease-v1\n${entry.value.sweep_hmac_sha256}\n${now.toISOString()}\n${uuid}`);
  entry = await replaceState(stores.control, entry, { ...entry.value, status: 'RUNNING',
    lease_hmac_sha256: lease, lease_expires_at: new Date(now.getTime() + LEASE_MS).toISOString(),
    run_count: entry.value.run_count + 1 }, configuration.secret);
  const limit = adapters.limit === undefined ? 100 : adapters.limit;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new TypeError('First-party retention limit is invalid.');
  const phase = PHASES[entry.value.phase_index];
  const context = {
    env, stores, adapters, configuration, sweep: entry.value.sweep_hmac_sha256, now,
    startedAt: entry.value.started_at,
    unpaidCutoff: now.getTime() - configuration.unpaid_days * 24 * 60 * 60_000,
    paidCutoff: now.getTime() - configuration.paid_days * 24 * 60 * 60_000,
  };
  const result = await processPhase(phase, entry.value.cursor, limit, context);
  const current = await readState(stores.control, configuration.secret);
  if (!current || current.value.status !== 'RUNNING' || current.value.lease_hmac_sha256 !== lease) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_STATE_CONTENTION');
  }
  const counts = structuredClone(current.value.counts);
  for (const field of COUNT_FIELDS) counts[phase.family][field] += result.counts[field];
  let next = { ...current.value, status: 'IDLE', counts, cursor: result.next_cursor,
    lease_hmac_sha256: null, lease_expires_at: null };
  let receipt = null;
  if (result.complete) {
    next = { ...next, phase_index: current.value.phase_index + 1, cursor: null };
    if (next.phase_index === PHASES.length) {
      const fence = await readRetentionGenerationFence(stores.control, env);
      if (await auditMarkedCandidateSources(context) ||
          await hasBlockingMissingSourceAnomaly(context) || fence?.record.status !== 'OPEN') {
        next = { ...next, phase_index: PHASES.length - 1, cursor: null };
      } else {
        receipt = await ensureReceipt(stores.control, next, now.toISOString(), configuration.secret);
        next = completedState(next, receipt);
      }
    }
  }
  entry = await replaceState(stores.control, current, next, configuration.secret);
  if (result.retryable) {
    const recovery = await recoverStaleRetentionGenerationFence(stores.control, env, {
      clock: () => now,
      emitCriticalAlert: adapters.emitCriticalAlert,
      validateCompletion: async (evidence) => typeof adapters.validateFenceCompletion === 'function' &&
        await adapters.validateFenceCompletion(evidence) === true,
    });
    if (recovery.critical_alert) {
      return Object.freeze({
        state: 'BLOCKED', phase: PHASES[entry.value.phase_index]?.kind || null,
        next_cursor: entry.value.cursor, sweep_hmac_sha256: entry.value.sweep_hmac_sha256,
        idempotent_replay: false, critical_alert: true, reason_code: recovery.reason_code,
      });
    }
  }
  return Object.freeze({
    state: entry.value.status === 'COMPLETE' ? 'COMPLETE' : 'PARTIAL',
    phase: entry.value.status === 'COMPLETE' ? null : PHASES[entry.value.phase_index]?.kind || null,
    next_cursor: entry.value.cursor, sweep_hmac_sha256: entry.value.sweep_hmac_sha256,
    idempotent_replay: false, ...(receipt ? { receipt } : {}),
  });
}

export const firstPartyRetentionContract = Object.freeze({
  families: FAMILIES,
  phases: PHASES.map(({ family, kind, prefix, store }) => Object.freeze({ family, kind, prefix, store })),
});
