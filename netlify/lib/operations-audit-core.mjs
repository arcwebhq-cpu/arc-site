import {
  OUTBOX_CLAIM_VERSION,
  canonicalJson,
  hmacHex,
  sha256Hex,
  validateExpectedBindings,
} from './arc2-handoff-core.mjs';
import { normalizeStoredIntakeSubmissionForBridge } from './intake-arc1-bridge-core.mjs';
import {
  STRIPE_PAYMENT_INTENT_INDEX_SCHEMA,
  STRIPE_PENDING_PAYMENT_SCHEMA,
  STRIPE_REVERSAL_ALERT_SCHEMA,
  STRIPE_REVERSAL_BINDING_SCHEMA,
  STRIPE_REVERSAL_EVENT_SCHEMA,
  STRIPE_REVERSAL_EVENT_TYPES,
  STRIPE_REVERSAL_SCHEMA,
} from './stripe-reversal-core.mjs';
import {
  validateRetentionDeleteIntent,
  validateRetentionDeleteReceipt,
} from './retention-control-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const OPERATIONS_ALERT_STORE = 'arc-operations-alerts';
export const OPERATIONS_AUDIT_MAX_RECORDS = 5_000;
export const OPERATIONS_AUDIT_MAX_RECORDS_PER_RUN = 100;
export const OPERATIONS_AUDIT_MAX_PAGES_PER_RUN = 20;
export const OPERATIONS_AUDIT_BUDGET_MS = 8_000;
export const OPERATIONS_AUDIT_MAX_PENDING_EVENT_PROBES = 8;
export const HANDOFF_STUCK_AFTER_MS = 60 * 60_000;
export const FINAL_OUTBOX_STUCK_AFTER_MS = 30 * 60_000;
export const RETENTION_INTENT_STUCK_AFTER_MS = 15 * 60_000;

const HEX_64 = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LEGACY_INVITATION_OUTBOX_SCHEMA = 'arc2-claim-invitation-ready-outbox-v1';
const INVITATION_OUTBOX_SCHEMA = 'arc2-claim-invitation-ready-outbox-v2';
const INVITATION_CURRENT_SCHEMA = 'arc2-claim-invitation-current-v1';
const FINAL_OUTBOX_CLAIMED_FIELDS = Object.freeze([
  'handoff_id', 'netlify_deploy_id_sha256', 'netlify_site_id_sha256',
  'outbox_claim_key_hmac_sha256', 'schema', 'status',
]);
const FINAL_OUTBOX_RECEIPT_FIELDS = Object.freeze([
  ...FINAL_OUTBOX_CLAIMED_FIELDS,
  'delivered_at', 'delivery_receipt_sha256', 'delivery_status', 'event_type', 'provider',
  'provider_account_hmac_sha256', 'provider_event_id_hmac_sha256', 'provider_message_id_hmac_sha256',
  'receipt_issued_at',
]);
const INVITATION_OUTBOX_FIELDS = Object.freeze([
  'claim_invitation_generation', 'claim_token_hmac_sha256', 'expires_at', 'handoff_id',
  'recipient_email_sha256', 'schema', 'status',
]);
const LEGACY_INVITATION_OUTBOX_FIELDS = Object.freeze([
  'claim_token_hmac_sha256', 'expires_at', 'handoff_id', 'recipient_email_sha256', 'schema', 'status',
]);
const INVITATION_CURRENT_FIELDS = Object.freeze([
  'binding_hmac_sha256', 'claim_invitation_generation', 'claim_token_hmac_sha256', 'expires_at',
  'handoff_id', 'outbox_key_sha256', 'schema',
]);
const REVERSAL_FIELDS = Object.freeze([
  'automatic_refund_requested', 'checkout_session_id_hmac_sha256', 'currency', 'delivery_halted',
  'dispute_observed', 'dispute_state', 'first_event_created_at', 'handoff_id', 'latest_amount_minor_units',
  'latest_event_created_at', 'latest_event_id_hmac_sha256', 'latest_event_sha256', 'latest_event_status',
  'latest_event_type', 'latest_object_id_hmac_sha256', 'livemode', 'manual_review_required',
  'payment_intent_id_hmac_sha256', 'refund_observed', 'refund_state', 'schema', 'severity',
  'stripe_account_id_sha256',
]);
const REVERSAL_BINDING_FIELDS = Object.freeze([
  'binding_evidence_sha256', 'checkout_session_id_hmac_sha256', 'handoff_id', 'livemode',
  'payment_evidence_sha256', 'payment_intent_id_hmac_sha256', 'schema', 'stripe_account_id_sha256',
]);
const REVERSAL_EVENT_FIELDS = Object.freeze([
  'amount_minor_units', 'checkout_session_id_hmac_sha256', 'currency', 'event_created_at',
  'event_id_hmac_sha256', 'event_sha256', 'event_status', 'event_type', 'handoff_id', 'kind',
  'livemode', 'object_id_hmac_sha256', 'payment_intent_id_hmac_sha256', 'schema',
  'stripe_account_id_sha256',
]);
const PENDING_PAYMENT_FIELDS = Object.freeze([
  'delivery_halted', 'livemode', 'payment_intent_id_hmac_sha256', 'schema', 'stripe_account_id_sha256',
]);
const CHECKOUT_REFERENCE_INDEX_FIELDS = Object.freeze([
  'artifact_evidence_sha256', 'client_reference_id_sha256', 'handoff_id', 'payment_evidence_sha256',
  'preview_source_commit_sha', 'schema', 'winning_checkout_session_id', 'winning_payment_link_id_hmac_sha256',
]);
const CHECKOUT_SESSION_INDEX_FIELDS = Object.freeze([
  'artifact_evidence_sha256', 'bundle_fingerprint', 'handoff_id', 'payment_evidence_sha256', 'schema',
]);
const DUPLICATE_PAYMENT_REVIEW_FIELDS = Object.freeze([
  'automatic_refund_requested', 'checkout_reference_sha256', 'duplicate_checkout_session_id_hmac_sha256',
  'duplicate_payment_evidence_sha256', 'duplicate_payment_link_id_hmac_sha256', 'review_hmac_sha256', 'schema',
  'status', 'winning_artifact_evidence_sha256', 'winning_checkout_session_id_hmac_sha256', 'winning_handoff_id',
  'winning_payment_evidence_sha256', 'winning_payment_link_id_hmac_sha256',
]);
const DUPLICATE_PAYMENT_REVIEW_SCHEMA = 'arc2-duplicate-payment-review-v1';
const CHECKOUT_REFERENCE_INDEX_SCHEMA = 'arc2-checkout-reference-index-v1';
const CHECKOUT_SESSION_INDEX_SCHEMA = 'arc2-checkout-session-index-v1';
const AUDIT_CURSOR_VERSION = 3;
const AUDIT_CURSOR_TOKEN_MAX_BYTES = 2_048;
const AUDIT_SHARD_COUNT = 256;
const AUDIT_CATCH_ALL_SHARD = AUDIT_SHARD_COUNT;
const AUDIT_SHARD_WIDTH = 2;
const AUDIT_PHASES = Object.freeze([
  ['handoff', 'handoffs/'],
  ['invitation', 'invitation-ready-outbox/'],
  ['reversal', 'stripe-reversal/handoff/'],
  ['event', 'stripe-reversal-event/'],
  ['pending-payment', 'stripe-reversal-pending-payment/'],
  ['pending-event', 'stripe-reversal-pending/'],
  ['payment-binding', 'stripe-payment-intent/'],
  ['handoff-binding', 'stripe-reversal-binding/handoff/'],
  ['retention-intent', 'delete-intents/'],
  ['retention-receipt', 'delete-receipts/'],
  ['intake', 'submissions/'],
  // Append-only so already-issued v3 cursors retain their phase meaning. A
  // cursor at an earlier former-final phase naturally continues through every
  // new integrity phase before it can report completion.
  ['invitation-current', 'invitation-ready-current/'],
  ['duplicate-payment-review', 'duplicate-payment-review/'],
]);

function validSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}

function exactStored(left, right) {
  return left && canonicalJson(left) === canonicalJson(right);
}

async function getValue(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  return entry?.data || null;
}

async function listBlobs(store, prefix, budget) {
  const blobs = [];
  const pages = store.list({ prefix, paginate: true });
  if (!pages || typeof pages[Symbol.asyncIterator] !== 'function') throw new Error('ARC_OPERATIONS_AUDIT_PAGINATION_REQUIRED');
  for await (const page of pages) {
    if (!page || !Array.isArray(page.blobs)) throw new Error('ARC_OPERATIONS_AUDIT_PAGINATION_REQUIRED');
    if (budget.scanned + page.blobs.length > OPERATIONS_AUDIT_MAX_RECORDS) throw new Error('ARC_OPERATIONS_AUDIT_RECORD_LIMIT');
    budget.scanned += page.blobs.length;
    blobs.push(...page.blobs);
  }
  return blobs;
}

function auditWallNow(adapters) {
  const value = (adapters.wallClock || Date.now)();
  if (!Number.isFinite(value)) throw new TypeError('Operations audit wall clock is invalid.');
  return value;
}

function auditCursorSignature(raw, env) {
  return hmacHex(env.ARC_OPERATIONS_AUDIT_SECRET, `arc-operations-audit-cursor-v3\n${raw}`);
}

function encodeAuditCursor(value, env) {
  if (!Number.isSafeInteger(value.position) || value.position < 0 ||
      !(value.sequence_hmac_sha256 === null ? value.position === 0 : value.position > 0 && HEX_64.test(value.sequence_hmac_sha256))) {
    throw new TypeError('Operations audit sequence checkpoint is invalid.');
  }
  const raw = Buffer.from(JSON.stringify({
    v: AUDIT_CURSOR_VERSION,
    phase: value.phase,
    shard: value.shard,
    position: value.position,
    sequence_hmac_sha256: value.sequence_hmac_sha256,
  }), 'utf8').toString('base64url');
  return `${raw}.${auditCursorSignature(raw, env)}`;
}

function decodeAuditCursor(token, env) {
  if (token === null || token === undefined || token === '') {
    return { phase: 0, shard: 0, position: 0, sequence_hmac_sha256: null };
  }
  if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > AUDIT_CURSOR_TOKEN_MAX_BYTES ||
      !/^[A-Za-z0-9_-]+\.[a-f0-9]{64}$/.test(token)) {
    throw new TypeError('Operations audit cursor is invalid.');
  }
  const [raw, signature] = token.split('.');
  if (!safeAuditEqual(signature, auditCursorSignature(raw, env))) throw new TypeError('Operations audit cursor signature mismatch.');
  let value;
  try { value = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')); } catch { throw new TypeError('Operations audit cursor is invalid.'); }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['phase', 'position', 'sequence_hmac_sha256', 'shard', 'v']) ||
      value.v !== AUDIT_CURSOR_VERSION || !Number.isInteger(value.phase) || value.phase < 0 || value.phase >= AUDIT_PHASES.length ||
      !Number.isInteger(value.shard) || value.shard < 0 || value.shard > AUDIT_CATCH_ALL_SHARD ||
      !Number.isSafeInteger(value.position) || value.position < 0 ||
      !(value.sequence_hmac_sha256 === null ? value.position === 0 : value.position > 0 && HEX_64.test(value.sequence_hmac_sha256))) {
    throw new TypeError('Operations audit cursor fields are invalid.');
  }
  return {
    phase: value.phase,
    shard: value.shard,
    position: value.position,
    sequence_hmac_sha256: value.sequence_hmac_sha256,
  };
}

function auditSequenceInitial(env, phase, shard, prefix) {
  return hmacHex(env.ARC_OPERATIONS_AUDIT_SECRET,
    `arc-operations-audit-provider-sequence-v1\n${phase}\n${shard}\n${Buffer.byteLength(prefix, 'utf8')}\n${prefix}`);
}

function auditSequenceNext(env, previous, key) {
  const bytes = Buffer.from(key, 'utf8');
  return hmacHex(env.ARC_OPERATIONS_AUDIT_SECRET, Buffer.concat([
    Buffer.from(`arc-operations-audit-provider-sequence-step-v1\n${previous}\n${bytes.length}\n`, 'utf8'),
    bytes,
  ]));
}

function safeAuditEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function requestAuditCursor(adapters) {
  if (Object.hasOwn(adapters, 'cursor')) return adapters.cursor;
  const request = adapters.request;
  if (!request) return null;
  let url;
  try { url = new URL(request.url); } catch { throw new TypeError('Operations audit request URL is invalid.'); }
  const values = url.searchParams.getAll('cursor');
  if (values.length > 1) throw new TypeError('Operations audit cursor is ambiguous.');
  return values[0] || null;
}

export function operationsAuditConfiguration(env = process.env) {
  const secretNames = [
    'ARC_OPERATIONS_AUDIT_SECRET', 'ARC_OPERATIONS_ALERT_HMAC_SECRET',
    'ARC_EMAIL_CLAIM_BINDING_SECRET', 'ARC_HANDOFF_STATE_SECRET',
  ];
  const secretsValid = secretNames.every((name) => validSecret(env[name])) &&
    sensitiveCredentialsAreIsolated(env, secretNames);
  return { enabled: env.ARC_OPERATIONS_AUDIT_ENABLED === 'true' && secretsValid, secretsValid };
}

function iso(value) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}

function exactKeys(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}

function hourBucket(now) {
  const value = new Date(now);
  value.setUTCMinutes(0, 0, 0);
  return value.toISOString();
}

function alertDefinition(condition, env, now) {
  const conditionValue = {
    category: condition.category,
    detail_code: condition.detailCode,
    source_timestamp: condition.sourceTimestamp || hourBucket(now),
    subject: condition.subject,
  };
  const subjectHmac = hmacHex(env.ARC_OPERATIONS_ALERT_HMAC_SECRET, `arc-operations-alert-subject-v1\n${condition.subject}`);
  const conditionHmac = hmacHex(env.ARC_OPERATIONS_ALERT_HMAC_SECRET, `arc-operations-alert-condition-v1\n${canonicalJson(conditionValue)}`);
  return {
    key: `alerts/${condition.category}/${conditionHmac}`,
    value: {
      schema: STRIPE_REVERSAL_ALERT_SCHEMA,
      status: 'OPEN',
      category: condition.category,
      severity: condition.severity,
      handoff_id: condition.handoffId || null,
      subject_hmac_sha256: subjectHmac,
      condition_hmac_sha256: conditionHmac,
      detail_code: condition.detailCode,
      detected_at: conditionValue.source_timestamp,
      delivery_status: 'PENDING',
      contains_customer_data: false,
    },
  };
}

async function ensureAlert(store, definition) {
  const existing = await getValue(store, definition.key);
  if (existing) {
    if (!exactStored(existing, definition.value)) throw new Error('ARC_OPERATIONS_ALERT_CONFLICT');
    return false;
  }
  const result = await store.setJSON(definition.key, definition.value, { onlyIfNew: true });
  if (result?.modified) return true;
  const raced = await getValue(store, definition.key);
  if (!exactStored(raced, definition.value)) throw new Error('ARC_OPERATIONS_ALERT_CONFLICT');
  return false;
}

// Shared, PII-free alert enqueue for authenticated internal state machines.
// The delivery worker remains independently gated; this function only writes
// the existing signed/deduplicated operations queue record.
export async function enqueueOperationsAlertCondition(store, input, env = process.env, adapters = {}) {
  if (!operationsAuditConfiguration(env).enabled) {
    return Object.freeze({ enabled: false, created: false });
  }
  const fields = ['category', 'detail_code', 'handoff_id', 'severity', 'source_timestamp', 'subject'];
  if (!exactKeys(input, fields) || !/^[a-z0-9][a-z0-9-]{1,63}$/.test(input.category) ||
      !['high', 'critical'].includes(input.severity) ||
      !/^[a-z0-9][a-z0-9-]{1,127}$/.test(input.detail_code) ||
      !HEX_64.test(String(input.handoff_id || '')) ||
      typeof input.subject !== 'string' || input.subject.length < 8 ||
      Buffer.byteLength(input.subject, 'utf8') > 512 || /[\u0000-\u001f\u007f]/.test(input.subject) ||
      iso(input.source_timestamp) === null) {
    throw new TypeError('Operations alert enqueue input is invalid.');
  }
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Operations alert clock is invalid.');
  const definition = alertDefinition({
    category: input.category,
    severity: input.severity,
    detailCode: input.detail_code,
    handoffId: input.handoff_id,
    subject: input.subject,
    sourceTimestamp: input.source_timestamp,
  }, env, now);
  return Object.freeze({ enabled: true, created: await ensureAlert(store, definition) });
}

function pushCondition(conditions, value) {
  conditions.push(value);
}

function finalOutboxIntegrity(value, outboxDigest, record) {
  if (!value || value.schema !== OUTBOX_CLAIM_VERSION || !['CLAIMED', 'DELIVERY_ACK_PENDING', 'DELIVERED'].includes(value.status) ||
      !exactKeys(value, value.status === 'CLAIMED' ? FINAL_OUTBOX_CLAIMED_FIELDS : FINAL_OUTBOX_RECEIPT_FIELDS) ||
      value.handoff_id !== record.handoff_id || value.outbox_claim_key_hmac_sha256 !== outboxDigest ||
      outboxDigest !== record.outbox_claim_key_hmac_sha256 || value.netlify_site_id_sha256 !== sha256Hex(record.netlify_site_id) ||
      value.netlify_deploy_id_sha256 !== sha256Hex(record.final_deploy_id)) return false;
  if (value.status === 'CLAIMED') return true;
  const deliveredAt = iso(value.delivered_at);
  const issuedAt = iso(value.receipt_issued_at);
  if (!HEX_64.test(value.delivery_receipt_sha256) || typeof value.provider !== 'string' ||
      !/^[a-z0-9][a-z0-9_.-]{1,63}$/.test(value.provider) || !HEX_64.test(value.provider_account_hmac_sha256) ||
      !HEX_64.test(value.provider_event_id_hmac_sha256) || !HEX_64.test(value.provider_message_id_hmac_sha256) ||
      value.event_type !== 'message.delivered' || value.delivery_status !== 'delivered' || deliveredAt === null || issuedAt === null ||
      deliveredAt < Date.parse(record.final_deploy_ready_at) || issuedAt < deliveredAt || issuedAt - deliveredAt > 10 * 60_000) return false;
  if (record.state !== 'DELIVERED') return true;
  return value.status === 'DELIVERED' && value.delivery_receipt_sha256 === record.final_delivery_receipt_sha256 &&
    value.provider === record.final_delivery_provider &&
    value.provider_account_hmac_sha256 === record.final_delivery_provider_account_hmac_sha256 &&
    value.provider_event_id_hmac_sha256 === record.final_delivery_provider_event_id_hmac_sha256 &&
    value.provider_message_id_hmac_sha256 === record.final_delivery_provider_message_id_hmac_sha256 &&
    value.event_type === record.final_delivery_event_type && value.delivery_status === record.final_delivery_status &&
    value.delivered_at === record.delivered_at && value.receipt_issued_at === record.final_delivery_receipt_issued_at;
}

function invitationReached(record) {
  return ['INVITATION_READY', 'CLAIM_WRAPPER_CONSUMED', 'CLAIM_CALLBACK_RECEIVED', 'CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED']
    .includes(record.state);
}

function currentInvitationToken(record) {
  if (!invitationReached(record)) return null;
  return record.state === 'INVITATION_READY' ? record.claim_token_hmac_sha256 : record.claim_token_consumed_hmac_sha256;
}

function expectedInvitationAuthority(record, env) {
  const token = currentInvitationToken(record);
  const generation = record.claim_invitation_generation;
  if (!HEX_64.test(token || '') || !Number.isSafeInteger(generation) || generation < 0 || generation > 1_000_000 ||
      iso(record.claim_token_expires_at) === null) return null;
  const outboxBinding = {
    version: INVITATION_OUTBOX_SCHEMA,
    handoff_id: record.handoff_id,
    recipient_email_sha256: record.customer_email_sha256,
    claim_invitation_generation: generation,
    claim_token_hmac_sha256: token,
    expires_at: record.claim_token_expires_at,
  };
  const outboxDigest = hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET, canonicalJson(outboxBinding));
  const outbox = {
    key: `invitation-ready-outbox/${outboxDigest}`,
    value: {
      schema: INVITATION_OUTBOX_SCHEMA,
      status: 'READY',
      handoff_id: record.handoff_id,
      claim_invitation_generation: generation,
      recipient_email_sha256: record.customer_email_sha256,
      claim_token_hmac_sha256: token,
      expires_at: record.claim_token_expires_at,
    },
  };
  const currentBinding = {
    schema: INVITATION_CURRENT_SCHEMA,
    handoff_id: record.handoff_id,
    claim_invitation_generation: generation,
    claim_token_hmac_sha256: token,
    expires_at: record.claim_token_expires_at,
    outbox_key_sha256: sha256Hex(outbox.key),
  };
  return {
    outbox,
    current: {
      key: `invitation-ready-current/${record.handoff_id}`,
      value: {
        ...currentBinding,
        binding_hmac_sha256: hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET,
          `${INVITATION_CURRENT_SCHEMA}\n${canonicalJson(currentBinding)}`),
      },
    },
  };
}

function parseInvitationOutbox(value, key, record, env) {
  const legacy = value?.schema === LEGACY_INVITATION_OUTBOX_SCHEMA;
  const fields = legacy ? LEGACY_INVITATION_OUTBOX_FIELDS : INVITATION_OUTBOX_FIELDS;
  const generation = legacy ? 0 : value?.claim_invitation_generation;
  if (!exactKeys(value, fields) || (!legacy && value.schema !== INVITATION_OUTBOX_SCHEMA) || value.status !== 'READY' ||
      value.handoff_id !== record.handoff_id || value.recipient_email_sha256 !== record.customer_email_sha256 ||
      !Number.isSafeInteger(generation) || generation < 0 || generation > 1_000_000 ||
      iso(value.expires_at) === null || !HEX_64.test(value.claim_token_hmac_sha256)) return null;
  const binding = legacy ? {
    version: LEGACY_INVITATION_OUTBOX_SCHEMA,
    handoff_id: value.handoff_id,
    recipient_email_sha256: value.recipient_email_sha256,
    claim_token_hmac_sha256: value.claim_token_hmac_sha256,
    expires_at: value.expires_at,
  } : {
    version: INVITATION_OUTBOX_SCHEMA,
    handoff_id: value.handoff_id,
    recipient_email_sha256: value.recipient_email_sha256,
    claim_invitation_generation: generation,
    claim_token_hmac_sha256: value.claim_token_hmac_sha256,
    expires_at: value.expires_at,
  };
  const digest = hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET, canonicalJson(binding));
  if (key !== `invitation-ready-outbox/${digest}`) return null;
  return { generation, legacy };
}

async function readInvitationAuthority(record, stores, env) {
  const expected = expectedInvitationAuthority(record, env);
  if (!expected) return { expected: null, pointer: null, outbox: null, valid: false };
  const pointer = await getValue(stores.handoff, expected.current.key);
  const outbox = await getValue(stores.handoff, expected.outbox.key);
  const valid = exactKeys(pointer, INVITATION_CURRENT_FIELDS) && exactStored(pointer, expected.current.value) &&
    exactStored(outbox, expected.outbox.value) && Boolean(parseInvitationOutbox(outbox, expected.outbox.key, record, env));
  return { expected, pointer, outbox, valid };
}

async function classifyInvitationOutbox(value, key, record, stores, env) {
  if (!invitationReached(record)) return 'INVALID';
  const parsed = parseInvitationOutbox(value, key, record, env);
  if (!parsed) return 'INVALID';
  const authority = await readInvitationAuthority(record, stores, env);
  if (authority.expected && key === authority.expected.outbox.key && exactStored(value, authority.expected.outbox.value)) {
    return authority.valid ? 'CURRENT' : 'CURRENT_AUTHORITY_UNAVAILABLE';
  }
  // Immutable older rows are safe to retain only when a fully validated v2
  // pointer selects a strictly newer generation. They are then historical,
  // never sender authority and never an expired-current alert.
  if (authority.valid && parsed.generation < record.claim_invitation_generation &&
      (!parsed.legacy || record.claim_invitation_generation > 0)) return 'SUPERSEDED';
  if (parsed.legacy || parsed.generation < record.claim_invitation_generation) return 'MIGRATION_REQUIRED';
  return 'INVALID';
}

function reversalIntegrity(value, handoffId, binding, handoff) {
  if (!exactKeys(value, REVERSAL_FIELDS) || value.schema !== STRIPE_REVERSAL_SCHEMA || value.handoff_id !== handoffId ||
      value.delivery_halted !== true || value.automatic_refund_requested !== false || value.manual_review_required !== true ||
      !['REVIEW_REQUIRED', 'FUNDS_AT_RISK', 'FUNDS_REVERSED'].includes(value.severity) ||
      !['NONE', 'ATTEMPT_RECORDED', 'FUNDS_REVERSED'].includes(value.refund_state) ||
      !['NONE', 'OPEN', 'RESOLVED'].includes(value.dispute_state) || typeof value.refund_observed !== 'boolean' ||
      typeof value.dispute_observed !== 'boolean' || !STRIPE_REVERSAL_EVENT_TYPES.includes(value.latest_event_type) ||
      typeof value.latest_event_status !== 'string' || value.latest_event_status.length < 1 ||
      !HEX_64.test(value.latest_event_id_hmac_sha256) || !HEX_64.test(value.latest_event_sha256) ||
      !HEX_64.test(value.latest_object_id_hmac_sha256) || !Number.isSafeInteger(value.latest_amount_minor_units) ||
      value.latest_amount_minor_units < 1 || value.currency !== 'usd' || iso(value.first_event_created_at) === null ||
      iso(value.latest_event_created_at) === null || Date.parse(value.first_event_created_at) > Date.parse(value.latest_event_created_at)) return false;
  if (!exactKeys(binding, REVERSAL_BINDING_FIELDS) || binding.schema !== STRIPE_REVERSAL_BINDING_SCHEMA ||
      binding.handoff_id !== handoffId || !HEX_64.test(binding.checkout_session_id_hmac_sha256) ||
      !HEX_64.test(binding.payment_intent_id_hmac_sha256) || !HEX_64.test(binding.stripe_account_id_sha256) ||
      typeof binding.livemode !== 'boolean' || !HEX_64.test(binding.payment_evidence_sha256) ||
      !HEX_64.test(binding.binding_evidence_sha256) || binding.payment_evidence_sha256 !== handoff.payment_evidence_sha256) return false;
  return value.checkout_session_id_hmac_sha256 === binding.checkout_session_id_hmac_sha256 &&
    value.payment_intent_id_hmac_sha256 === binding.payment_intent_id_hmac_sha256 &&
    value.stripe_account_id_sha256 === binding.stripe_account_id_sha256 && value.livemode === binding.livemode;
}

function reversalBindingIntegrity(value, schema = STRIPE_REVERSAL_BINDING_SCHEMA) {
  return exactKeys(value, REVERSAL_BINDING_FIELDS) && value.schema === schema && HEX_64.test(value.handoff_id) &&
    HEX_64.test(value.checkout_session_id_hmac_sha256) && HEX_64.test(value.payment_intent_id_hmac_sha256) &&
    HEX_64.test(value.stripe_account_id_sha256) && typeof value.livemode === 'boolean' &&
    HEX_64.test(value.payment_evidence_sha256) && HEX_64.test(value.binding_evidence_sha256);
}

function reversalEventIntegrity(value, eventHmac, paymentIntentHmac) {
  if (!exactKeys(value, REVERSAL_EVENT_FIELDS) || value.schema !== STRIPE_REVERSAL_EVENT_SCHEMA ||
      value.handoff_id !== null || value.checkout_session_id_hmac_sha256 !== null ||
      value.event_id_hmac_sha256 !== eventHmac || value.payment_intent_id_hmac_sha256 !== paymentIntentHmac ||
      !HEX_64.test(value.object_id_hmac_sha256) || !HEX_64.test(value.event_sha256) ||
      !HEX_64.test(value.stripe_account_id_sha256) || typeof value.livemode !== 'boolean' ||
      !STRIPE_REVERSAL_EVENT_TYPES.includes(value.event_type) || typeof value.event_status !== 'string' ||
      value.event_status.length < 1 || value.event_status.length > 64 || iso(value.event_created_at) === null ||
      !Number.isSafeInteger(value.amount_minor_units) || value.amount_minor_units < 1 || value.currency !== 'usd') return false;
  if (value.event_type.startsWith('refund.')) return value.kind === 'refund' &&
    ['pending', 'requires_action', 'succeeded', 'failed', 'canceled'].includes(value.event_status) &&
    (value.event_type !== 'refund.failed' || value.event_status === 'failed');
  if (value.event_type === 'charge.refunded') return value.kind === 'charge-refund' &&
    ['fully_refunded', 'partially_refunded'].includes(value.event_status);
  return value.event_type.startsWith('charge.dispute.') && value.kind === 'dispute' &&
    ['warning_needs_response', 'warning_under_review', 'warning_closed', 'needs_response', 'under_review', 'won', 'lost', 'prevented']
      .includes(value.event_status) &&
    (value.event_type !== 'charge.dispute.closed' || ['lost', 'warning_closed', 'won', 'prevented'].includes(value.event_status));
}

function pendingPaymentIntegrity(value, paymentIntentHmac) {
  return exactKeys(value, PENDING_PAYMENT_FIELDS) && value.schema === STRIPE_PENDING_PAYMENT_SCHEMA &&
    value.payment_intent_id_hmac_sha256 === paymentIntentHmac && HEX_64.test(value.stripe_account_id_sha256) &&
    typeof value.livemode === 'boolean' && value.delivery_halted === true;
}

function checkoutReferenceIndexIntegrity(value) {
  return exactKeys(value, CHECKOUT_REFERENCE_INDEX_FIELDS) && value.schema === CHECKOUT_REFERENCE_INDEX_SCHEMA &&
    HEX_64.test(value.client_reference_id_sha256) && HEX_64.test(value.winning_payment_link_id_hmac_sha256) &&
    HEX_64.test(value.handoff_id) && /^[a-f0-9]{40}$/.test(value.preview_source_commit_sha) &&
    HEX_64.test(value.payment_evidence_sha256) && HEX_64.test(value.artifact_evidence_sha256) &&
    /^cs_(?:test|live)_[A-Za-z0-9_]+$/.test(value.winning_checkout_session_id);
}

function checkoutSessionIndexIntegrity(value) {
  return exactKeys(value, CHECKOUT_SESSION_INDEX_FIELDS) && value.schema === CHECKOUT_SESSION_INDEX_SCHEMA &&
    HEX_64.test(value.handoff_id) && HEX_64.test(value.payment_evidence_sha256) &&
    HEX_64.test(value.artifact_evidence_sha256) && HEX_64.test(value.bundle_fingerprint);
}

async function duplicatePaymentReviewIntegrity(value, key, stores, env) {
  if (!exactKeys(value, DUPLICATE_PAYMENT_REVIEW_FIELDS) || value.schema !== DUPLICATE_PAYMENT_REVIEW_SCHEMA ||
      value.status !== 'CRITICAL_DUPLICATE_PAID_SESSION_REVIEW_REQUIRED' || value.automatic_refund_requested !== false ||
      !['checkout_reference_sha256', 'winning_checkout_session_id_hmac_sha256', 'duplicate_checkout_session_id_hmac_sha256',
        'winning_payment_link_id_hmac_sha256', 'duplicate_payment_link_id_hmac_sha256', 'winning_handoff_id',
        'winning_payment_evidence_sha256', 'winning_artifact_evidence_sha256', 'duplicate_payment_evidence_sha256',
        'review_hmac_sha256'].every((field) => HEX_64.test(value[field]))) return false;
  const expectedKeyDigest = hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `duplicate-payment-review-key-v1\n${value.checkout_reference_sha256}\n${value.duplicate_checkout_session_id_hmac_sha256}`);
  if (key !== `duplicate-payment-review/${expectedKeyDigest}`) return false;
  const unsigned = Object.fromEntries(Object.entries(value).filter(([field]) => field !== 'review_hmac_sha256'));
  if (!safeAuditEqual(value.review_hmac_sha256, hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `arc2-duplicate-payment-review-signature-v1\n${canonicalJson(unsigned)}`))) return false;
  const referenceKey = `checkout-reference-index/${hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `checkout-reference-index-v1\n${value.checkout_reference_sha256}`)}`;
  const winner = await getValue(stores.handoff, referenceKey);
  if (!checkoutReferenceIndexIntegrity(winner) || winner.client_reference_id_sha256 !== value.checkout_reference_sha256 ||
      winner.handoff_id !== value.winning_handoff_id || winner.winning_payment_link_id_hmac_sha256 !== value.winning_payment_link_id_hmac_sha256 ||
      winner.payment_evidence_sha256 !== value.winning_payment_evidence_sha256 ||
      winner.artifact_evidence_sha256 !== value.winning_artifact_evidence_sha256) return false;
  if (!safeAuditEqual(value.winning_checkout_session_id_hmac_sha256, hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `duplicate-payment-session-id-v1\n${winner.winning_checkout_session_id}`))) return false;
  let handoff;
  try { handoff = validateExpectedBindings(await getValue(stores.handoff, `handoffs/${value.winning_handoff_id}`)); } catch { return false; }
  const checkoutSessionKey = `checkout-session-index/${hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `checkout-session-index-v1\n${winner.winning_checkout_session_id}`)}`;
  const checkoutSession = await getValue(stores.handoff, checkoutSessionKey);
  return value.winning_checkout_session_id_hmac_sha256 !== value.duplicate_checkout_session_id_hmac_sha256 &&
    value.winning_payment_evidence_sha256 !== value.duplicate_payment_evidence_sha256 &&
    handoff.payment_evidence_sha256 === value.winning_payment_evidence_sha256 &&
    handoff.artifact_evidence_sha256 === value.winning_artifact_evidence_sha256 &&
    checkoutSessionIndexIntegrity(checkoutSession) && checkoutSession.handoff_id === value.winning_handoff_id &&
    checkoutSession.payment_evidence_sha256 === value.winning_payment_evidence_sha256 &&
    checkoutSession.artifact_evidence_sha256 === value.winning_artifact_evidence_sha256 &&
    checkoutSession.bundle_fingerprint === handoff.bundle_fingerprint;
}

async function auditHandoffs(stores, env, now, conditions, budget) {
  const handoffs = new Map();
  for (const { key } of await listBlobs(stores.handoff, 'handoffs/', budget)) {
    const handoffId = key.match(/^handoffs\/([a-f0-9]{64})$/)?.[1];
    if (!handoffId) {
      pushCondition(conditions, { category: 'handoff-integrity', detailCode: 'invalid-handoff-key', severity: 'critical', subject: key });
      continue;
    }
    let record;
    try {
      record = validateExpectedBindings(await getValue(stores.handoff, key));
    } catch {
      pushCondition(conditions, { category: 'handoff-integrity', detailCode: 'invalid-handoff-record', severity: 'critical', subject: handoffId, handoffId });
      continue;
    }
    handoffs.set(handoffId, record);
    if (invitationReached(record)) {
      const expected = expectedInvitationAuthority(record, env);
      // A missing current pointer must remain visible even when there is no
      // outbox key for the invitation phase to discover.
      if (!expected || !await getValue(stores.handoff, expected.current.key)) {
        pushCondition(conditions, {
          category: 'claim-invitation-migration', detailCode: 'current-pointer-missing', severity: 'high',
          subject: handoffId, handoffId, sourceTimestamp: record.claim_invitation_ready_at,
        });
      }
    }
    if (record.state !== 'DELIVERED') {
      const updatedAt = iso(record.updated_at);
      if (updatedAt === null || now.getTime() - updatedAt > HANDOFF_STUCK_AFTER_MS) {
        pushCondition(conditions, {
          category: 'handoff-stuck', detailCode: `state-${record.state.toLowerCase()}`, severity: 'high',
          subject: handoffId, handoffId, sourceTimestamp: updatedAt === null ? null : record.updated_at,
        });
      }
    }
    if (record.state === 'INVITATION_READY' && Date.parse(record.claim_token_expires_at) <= now.getTime()) {
      pushCondition(conditions, {
        category: 'claim-invitation-expired', detailCode: 'bearer-expired-before-consumption', severity: 'high',
        subject: handoffId, handoffId, sourceTimestamp: record.claim_token_expires_at,
      });
    }
    if (record.state === 'FINAL_DEPLOY_READY' && now.getTime() - Date.parse(record.final_deploy_ready_at) > FINAL_OUTBOX_STUCK_AFTER_MS) {
      const outbox = await getValue(stores.handoff, `outbox/${record.outbox_claim_key_hmac_sha256}`);
      if (!finalOutboxIntegrity(outbox, record.outbox_claim_key_hmac_sha256, record)) {
        pushCondition(conditions, {
          category: 'final-delivery-integrity', detailCode: 'outbox-missing-or-invalid', severity: 'critical',
          subject: record.outbox_claim_key_hmac_sha256, handoffId, sourceTimestamp: record.final_deploy_ready_at,
        });
      } else {
        pushCondition(conditions, {
          category: outbox.status === 'DELIVERED' ? 'final-delivery-integrity' : 'final-delivery-outbox-stuck',
          detailCode: outbox.status === 'DELIVERY_ACK_PENDING' ? 'delivery-ack-pending' :
            outbox.status === 'CLAIMED' ? 'claimed-not-delivered' : 'terminal-outbox-with-nonterminal-handoff',
          severity: outbox.status === 'DELIVERED' ? 'critical' : 'high',
          subject: record.outbox_claim_key_hmac_sha256, handoffId, sourceTimestamp: record.final_deploy_ready_at,
        });
      }
    }
    if (record.state === 'DELIVERED') {
      const outbox = await getValue(stores.handoff, `outbox/${record.outbox_claim_key_hmac_sha256}`);
      if (!finalOutboxIntegrity(outbox, record.outbox_claim_key_hmac_sha256, record)) {
        pushCondition(conditions, {
          category: 'final-delivery-integrity', detailCode: 'delivered-handoff-without-exact-terminal-outbox', severity: 'critical',
          subject: record.outbox_claim_key_hmac_sha256, handoffId, sourceTimestamp: record.delivered_at,
        });
      }
    }
  }
  return handoffs;
}

async function auditInvitationOutboxes(stores, handoffs, env, now, conditions, budget) {
  for (const { key } of await listBlobs(stores.handoff, 'invitation-ready-outbox/', budget)) {
    const outbox = await getValue(stores.handoff, key);
    const handoff = HEX_64.test(outbox?.handoff_id || '') ? handoffs.get(outbox.handoff_id) : null;
    if (!handoff) {
      pushCondition(conditions, {
        category: 'claim-outbox-integrity', detailCode: 'orphan-ready-outbox', severity: 'critical',
        subject: key, handoffId: HEX_64.test(outbox?.handoff_id || '') ? outbox.handoff_id : undefined,
        sourceTimestamp: iso(outbox?.expires_at) === null ? null : outbox.expires_at,
      });
    } else {
      const classification = await classifyInvitationOutbox(outbox, key, handoff, stores, env);
      if (classification === 'INVALID') {
        pushCondition(conditions, { category: 'claim-outbox-integrity', detailCode: 'invalid-ready-outbox', severity: 'critical', subject: key });
      } else if (classification === 'CURRENT_AUTHORITY_UNAVAILABLE') {
        pushCondition(conditions, {
          category: 'claim-outbox-integrity', detailCode: 'current-authority-missing-or-invalid', severity: 'critical',
          subject: key, handoffId: outbox.handoff_id, sourceTimestamp: outbox.expires_at,
        });
      } else if (classification === 'MIGRATION_REQUIRED') {
        pushCondition(conditions, {
          category: 'claim-invitation-migration', detailCode: 'historical-outbox-without-newer-current-pointer', severity: 'high',
          subject: key, handoffId: outbox.handoff_id, sourceTimestamp: outbox.expires_at,
        });
      } else if (classification === 'CURRENT' && handoff.state === 'INVITATION_READY' && Date.parse(outbox.expires_at) <= now.getTime()) {
        pushCondition(conditions, {
          category: 'claim-outbox-expired', detailCode: 'ready-outbox-past-expiry', severity: 'high',
          subject: key, handoffId: outbox.handoff_id, sourceTimestamp: outbox.expires_at,
        });
      }
      // CURRENT_AUTHORITY_UNAVAILABLE is reported once by the current-pointer
      // scan (or by the missing-pointer handoff check), and SUPERSEDED is a
      // healthy immutable history row that must never authorize a send.
    }
  }
}

async function auditInvitationCurrentPointers(stores, handoffs, env, conditions, budget) {
  for (const { key } of await listBlobs(stores.handoff, 'invitation-ready-current/', budget)) {
    const handoffId = key.match(/^invitation-ready-current\/([a-f0-9]{64})$/)?.[1];
    const record = handoffId ? handoffs.get(handoffId) : null;
    if (!record || !invitationReached(record)) {
      pushCondition(conditions, {
        category: 'claim-outbox-integrity', detailCode: 'orphan-current-pointer', severity: 'critical',
        subject: key, handoffId: handoffId || undefined,
      });
      continue;
    }
    const authority = await readInvitationAuthority(record, stores, env);
    if (!authority.valid || key !== authority.expected?.current.key) pushCondition(conditions, {
      category: 'claim-outbox-integrity', detailCode: 'invalid-current-pointer', severity: 'critical',
      subject: key, handoffId,
    });
  }
}

async function auditDuplicatePaymentReviews(stores, env, conditions, budget) {
  for (const { key } of await listBlobs(stores.handoff, 'duplicate-payment-review/', budget)) {
    const value = await getValue(stores.handoff, key);
    if (!await duplicatePaymentReviewIntegrity(value, key, stores, env)) {
      pushCondition(conditions, {
        category: 'duplicate-payment-integrity', detailCode: 'invalid-or-orphan-duplicate-payment-review',
        severity: 'critical', subject: key,
      });
      continue;
    }
    pushCondition(conditions, {
      category: 'duplicate-payment-review', detailCode: 'duplicate-paid-session-review-required',
      severity: 'critical', subject: key, handoffId: value.winning_handoff_id,
    });
  }
}

async function auditReversals(stores, handoffs, conditions, budget) {
  const reversals = new Map();
  for (const { key } of await listBlobs(stores.handoff, 'stripe-reversal/handoff/', budget)) {
    const value = await getValue(stores.handoff, key);
    const handoffId = key.match(/^stripe-reversal\/handoff\/([a-f0-9]{64})$/)?.[1];
    const handoff = handoffId ? handoffs.get(handoffId) : null;
    const binding = handoffId ? await getValue(stores.handoff, `stripe-reversal-binding/handoff/${handoffId}`) : null;
    if (!handoffId || !handoff || !reversalIntegrity(value, handoffId, binding, handoff)) {
      pushCondition(conditions, { category: 'stripe-reversal-integrity', detailCode: 'invalid-reversal-state', severity: 'critical', subject: key });
      continue;
    }
    reversals.set(handoffId, value);
    pushCondition(conditions, {
      category: 'stripe-reversal-review', detailCode: `halt-${String(value.severity || 'unknown').toLowerCase()}`,
      severity: value.severity === 'FUNDS_REVERSED' ? 'critical' : 'high', subject: handoffId, handoffId,
      sourceTimestamp: iso(value.latest_event_created_at) === null ? null : value.latest_event_created_at,
    });
  }
  return reversals;
}

function pushReversalIntegrity(conditions, detailCode, subject, sourceTimestamp = null, handoffId = undefined) {
  pushCondition(conditions, {
    category: 'stripe-reversal-integrity', detailCode, severity: 'critical', subject, sourceTimestamp, handoffId,
  });
}

async function auditReversalIndexes(stores, handoffs, reversals, conditions, budget) {
  const reservations = new Map();
  const pendingPayments = new Map();
  const pendingEvents = new Map();
  const paymentBindings = new Map();
  const handoffBindings = new Map();

  for (const { key } of await listBlobs(stores.handoff, 'stripe-reversal-event/', budget)) {
    const eventHmac = key.match(/^stripe-reversal-event\/([a-f0-9]{64})$/)?.[1];
    const value = await getValue(stores.handoff, key);
    if (!eventHmac || !reversalEventIntegrity(value, eventHmac, value?.payment_intent_id_hmac_sha256)) {
      pushReversalIntegrity(conditions, 'invalid-event-reservation', key, iso(value?.event_created_at) === null ? null : value.event_created_at);
      continue;
    }
    reservations.set(eventHmac, value);
  }

  for (const { key } of await listBlobs(stores.handoff, 'stripe-reversal-pending-payment/', budget)) {
    const paymentIntentHmac = key.match(/^stripe-reversal-pending-payment\/([a-f0-9]{64})$/)?.[1];
    const value = await getValue(stores.handoff, key);
    if (!paymentIntentHmac || !pendingPaymentIntegrity(value, paymentIntentHmac)) {
      pushReversalIntegrity(conditions, 'invalid-pending-payment-halt', key);
      continue;
    }
    pendingPayments.set(paymentIntentHmac, value);
  }

  for (const { key } of await listBlobs(stores.handoff, 'stripe-reversal-pending/', budget)) {
    const path = key.match(/^stripe-reversal-pending\/([a-f0-9]{64})\/([a-f0-9]{64})$/);
    const value = await getValue(stores.handoff, key);
    if (!path || !reversalEventIntegrity(value, path[2], path[1])) {
      pushReversalIntegrity(conditions, 'invalid-pending-event', key, iso(value?.event_created_at) === null ? null : value.event_created_at);
      continue;
    }
    pendingEvents.set(`${path[1]}/${path[2]}`, value);
  }

  for (const { key } of await listBlobs(stores.handoff, 'stripe-payment-intent/', budget)) {
    const paymentIntentHmac = key.match(/^stripe-payment-intent\/([a-f0-9]{64})$/)?.[1];
    const value = await getValue(stores.handoff, key);
    if (!paymentIntentHmac || !reversalBindingIntegrity(value, STRIPE_PAYMENT_INTENT_INDEX_SCHEMA) ||
        value.payment_intent_id_hmac_sha256 !== paymentIntentHmac) {
      pushReversalIntegrity(conditions, 'invalid-payment-intent-binding', key);
      continue;
    }
    paymentBindings.set(paymentIntentHmac, value);
  }

  for (const { key } of await listBlobs(stores.handoff, 'stripe-reversal-binding/handoff/', budget)) {
    const handoffId = key.match(/^stripe-reversal-binding\/handoff\/([a-f0-9]{64})$/)?.[1];
    const value = await getValue(stores.handoff, key);
    if (!handoffId || !reversalBindingIntegrity(value) || value.handoff_id !== handoffId) {
      pushReversalIntegrity(conditions, 'invalid-handoff-binding', key, null, handoffId);
      continue;
    }
    handoffBindings.set(handoffId, value);
  }

  for (const [eventHmac, value] of reservations) {
    const pending = pendingEvents.get(`${value.payment_intent_id_hmac_sha256}/${eventHmac}`);
    if (!exactStored(pending, value)) pushReversalIntegrity(
      conditions, 'event-reservation-without-exact-pending-event', eventHmac, value.event_created_at,
    );
  }

  for (const [path, value] of pendingEvents) {
    const [paymentIntentHmac, eventHmac] = path.split('/');
    const marker = pendingPayments.get(paymentIntentHmac);
    if (!exactStored(reservations.get(eventHmac), value)) pushReversalIntegrity(
      conditions, 'pending-event-without-exact-reservation', path, value.event_created_at,
    );
    if (!marker || marker.stripe_account_id_sha256 !== value.stripe_account_id_sha256 || marker.livemode !== value.livemode) {
      pushReversalIntegrity(conditions, 'pending-event-without-exact-payment-halt', path, value.event_created_at);
    }
  }

  for (const [paymentIntentHmac, marker] of pendingPayments) {
    const events = [...pendingEvents.entries()].filter(([path]) => path.startsWith(`${paymentIntentHmac}/`));
    if (events.length === 0) {
      pushReversalIntegrity(conditions, 'payment-halt-without-pending-event', paymentIntentHmac);
      continue;
    }
    const binding = paymentBindings.get(paymentIntentHmac);
    if (!binding) {
      pushCondition(conditions, {
        category: 'stripe-reversal-unbound', detailCode: 'verified-payment-reversal-awaiting-binding', severity: 'critical',
        subject: paymentIntentHmac, sourceTimestamp: events.map(([, value]) => value.event_created_at).sort()[0],
      });
      continue;
    }
    if (binding.stripe_account_id_sha256 !== marker.stripe_account_id_sha256 || binding.livemode !== marker.livemode) {
      pushReversalIntegrity(conditions, 'payment-halt-binding-mismatch', paymentIntentHmac, null, binding.handoff_id);
      continue;
    }
    const handoffBinding = handoffBindings.get(binding.handoff_id);
    const paired = exactStored(handoffBinding, { ...binding, schema: STRIPE_REVERSAL_BINDING_SCHEMA });
    const handoff = handoffs.get(binding.handoff_id);
    if (!paired || !handoff || handoff.payment_evidence_sha256 !== binding.payment_evidence_sha256) {
      pushReversalIntegrity(conditions, 'pending-reversal-binding-chain-invalid', paymentIntentHmac, null, binding.handoff_id);
      continue;
    }
    if (!reversals.has(binding.handoff_id)) pushReversalIntegrity(
      conditions, 'pending-reversal-not-reconciled', paymentIntentHmac, null, binding.handoff_id,
    );
  }

  for (const [paymentIntentHmac, binding] of paymentBindings) {
    const handoffBinding = handoffBindings.get(binding.handoff_id);
    if (!exactStored(handoffBinding, { ...binding, schema: STRIPE_REVERSAL_BINDING_SCHEMA })) pushReversalIntegrity(
      conditions, 'payment-binding-without-exact-handoff-binding', paymentIntentHmac, null, binding.handoff_id,
    );
  }
  for (const [handoffId, binding] of handoffBindings) {
    const paymentBinding = paymentBindings.get(binding.payment_intent_id_hmac_sha256);
    const handoff = handoffs.get(handoffId);
    if (!exactStored(paymentBinding, { ...binding, schema: STRIPE_PAYMENT_INTENT_INDEX_SCHEMA }) ||
        !handoff || handoff.payment_evidence_sha256 !== binding.payment_evidence_sha256) pushReversalIntegrity(
      conditions, 'handoff-binding-chain-invalid', handoffId, null, handoffId,
    );
  }
}

async function auditRetentionIntents(stores, now, conditions, budget) {
  const seenReceipts = new Set();
  for (const { key } of await listBlobs(stores.retention, 'delete-intents/', budget)) {
    const intent = await getValue(stores.retention, key);
    const receiptPath = key.replace(/^delete-intents\//, 'delete-receipts/');
    const receipt = await getValue(stores.retention, receiptPath);
    const path = key.match(/^delete-intents\/([a-f0-9]{64})\/([a-f0-9]{64})$/);
    let validIntent = false;
    try {
      validateRetentionDeleteIntent(intent);
      validIntent = Boolean(path && intent.target_hmac_sha256 === path[1] && intent.manifest_sha256 === path[2]);
    } catch { validIntent = false; }
    if (!validIntent) {
      pushCondition(conditions, { category: 'retention-integrity', detailCode: 'invalid-delete-intent', severity: 'critical', subject: key });
      continue;
    }
    let validReceipt = false;
    if (receipt) {
      seenReceipts.add(receiptPath);
      try {
        validateRetentionDeleteReceipt(receipt, intent);
        validReceipt = true;
      } catch {
        pushCondition(conditions, {
          category: 'retention-integrity', detailCode: 'invalid-delete-receipt', severity: 'critical',
          subject: receiptPath, sourceTimestamp: intent.authorized_at,
        });
      }
    }
    const authorizedAt = iso(intent.authorized_at);
    if (!validReceipt && (authorizedAt === null || now.getTime() - authorizedAt > RETENTION_INTENT_STUCK_AFTER_MS)) {
      pushCondition(conditions, {
        category: 'retention-delete-stuck', detailCode: 'intent-without-receipt', severity: 'critical',
        subject: intent.target_hmac_sha256, sourceTimestamp: authorizedAt === null ? null : intent.authorized_at,
      });
    }
  }
  for (const { key } of await listBlobs(stores.retention, 'delete-receipts/', budget)) {
    if (seenReceipts.has(key)) continue;
    const path = key.match(/^delete-receipts\/([a-f0-9]{64})\/([a-f0-9]{64})$/);
    const intentPath = path ? `delete-intents/${path[1]}/${path[2]}` : null;
    const intent = intentPath ? await getValue(stores.retention, intentPath) : null;
    const receipt = await getValue(stores.retention, key);
    let valid = false;
    try {
      validateRetentionDeleteIntent(intent);
      validateRetentionDeleteReceipt(receipt, intent);
      valid = intent.target_hmac_sha256 === path?.[1] && intent.manifest_sha256 === path?.[2];
    } catch { valid = false; }
    if (!valid) pushCondition(conditions, {
      category: 'retention-integrity', detailCode: 'orphan-or-invalid-delete-receipt', severity: 'critical', subject: key,
    });
  }
}

async function auditIntake(stores, now, conditions, budget) {
  if (!stores.intake) throw new Error('ARC_OPERATIONS_AUDIT_INTAKE_STORE_REQUIRED');
  for (const { key } of await listBlobs(stores.intake, 'submissions/', budget)) {
    const submissionId = key.match(/^submissions\/([0-9a-f-]{36})$/)?.[1];
    let record;
    try {
      if (!UUID.test(submissionId || '')) throw new TypeError('invalid key');
      record = normalizeStoredIntakeSubmissionForBridge(await getValue(stores.intake, key));
    } catch {
      pushCondition(conditions, {
        category: 'intake-arc1-integrity', detailCode: 'invalid-intake-bridge-record', severity: 'critical', subject: key,
      });
      continue;
    }
    const states = [
      { category: 'intake-arc1-delivery', value: record.arc1_delivery },
      { category: 'intake-arc1-dispatch', value: record.arc1_dispatch },
    ];
    for (const state of states) {
      if (state.value.alert_status === 'PENDING' || state.value.status === 'DEAD_LETTER') {
        pushCondition(conditions, {
          category: state.category,
          detailCode: state.value.status === 'DEAD_LETTER' ? 'dead-letter' : `pending-${String(state.value.alert_code || 'failure').toLowerCase()}`,
          severity: state.value.status === 'DEAD_LETTER' ? 'critical' : 'high',
          subject: `${submissionId}:${state.category}`,
          sourceTimestamp: state.value.alert_updated_at || record.received_at,
        });
      }
    }
    if (record.arc1_delivery.status === 'CLAIMED' && Date.parse(record.arc1_delivery.lease_expires_at) <= now.getTime()) {
      pushCondition(conditions, {
        category: 'intake-arc1-delivery', detailCode: 'expired-delivery-lease', severity: 'high',
        subject: `${submissionId}:expired-lease`, sourceTimestamp: record.arc1_delivery.lease_expires_at,
      });
    }
  }
}

async function auditOneHandoff(key, stores, env, now, conditions) {
  const handoffId = key.match(/^handoffs\/([a-f0-9]{64})$/)?.[1];
  if (!handoffId) {
    pushCondition(conditions, { category: 'handoff-integrity', detailCode: 'invalid-handoff-key', severity: 'critical', subject: key });
    return;
  }
  let record;
  try { record = validateExpectedBindings(await getValue(stores.handoff, key)); } catch {
    pushCondition(conditions, { category: 'handoff-integrity', detailCode: 'invalid-handoff-record', severity: 'critical', subject: handoffId, handoffId });
    return;
  }
  if (invitationReached(record)) {
    const authority = await readInvitationAuthority(record, stores, env);
    if (!authority.valid) pushCondition(conditions, {
      category: authority.pointer ? 'claim-outbox-integrity' : 'claim-invitation-migration',
      detailCode: authority.pointer ? 'current-pointer-or-outbox-mismatch' : 'current-pointer-missing',
      severity: authority.pointer ? 'critical' : 'high', subject: handoffId, handoffId,
      sourceTimestamp: record.claim_invitation_ready_at,
    });
  }
  const updatedAt = iso(record.updated_at);
  if (record.state !== 'DELIVERED' && (updatedAt === null || now.getTime() - updatedAt > HANDOFF_STUCK_AFTER_MS)) {
    pushCondition(conditions, {
      category: 'handoff-stuck', detailCode: `state-${record.state.toLowerCase()}`, severity: 'high',
      subject: handoffId, handoffId, sourceTimestamp: updatedAt === null ? null : record.updated_at,
    });
  }
  if (record.state === 'INVITATION_READY' && Date.parse(record.claim_token_expires_at) <= now.getTime()) pushCondition(conditions, {
    category: 'claim-invitation-expired', detailCode: 'bearer-expired-before-consumption', severity: 'high',
    subject: handoffId, handoffId, sourceTimestamp: record.claim_token_expires_at,
  });
  if (record.state === 'FINAL_DEPLOY_READY' && now.getTime() - Date.parse(record.final_deploy_ready_at) > FINAL_OUTBOX_STUCK_AFTER_MS) {
    const outbox = await getValue(stores.handoff, `outbox/${record.outbox_claim_key_hmac_sha256}`);
    if (!finalOutboxIntegrity(outbox, record.outbox_claim_key_hmac_sha256, record)) pushCondition(conditions, {
      category: 'final-delivery-integrity', detailCode: 'outbox-missing-or-invalid', severity: 'critical',
      subject: record.outbox_claim_key_hmac_sha256, handoffId, sourceTimestamp: record.final_deploy_ready_at,
    });
    else pushCondition(conditions, {
      category: outbox.status === 'DELIVERED' ? 'final-delivery-integrity' : 'final-delivery-outbox-stuck',
      detailCode: outbox.status === 'DELIVERY_ACK_PENDING' ? 'delivery-ack-pending' :
        outbox.status === 'CLAIMED' ? 'claimed-not-delivered' : 'terminal-outbox-with-nonterminal-handoff',
      severity: outbox.status === 'DELIVERED' ? 'critical' : 'high', subject: record.outbox_claim_key_hmac_sha256,
      handoffId, sourceTimestamp: record.final_deploy_ready_at,
    });
  }
  if (record.state === 'DELIVERED') {
    const outbox = await getValue(stores.handoff, `outbox/${record.outbox_claim_key_hmac_sha256}`);
    if (!finalOutboxIntegrity(outbox, record.outbox_claim_key_hmac_sha256, record)) pushCondition(conditions, {
      category: 'final-delivery-integrity', detailCode: 'delivered-handoff-without-exact-terminal-outbox', severity: 'critical',
      subject: record.outbox_claim_key_hmac_sha256, handoffId, sourceTimestamp: record.delivered_at,
    });
  }
}

async function auditOneInvitation(key, stores, env, now, conditions) {
  const outbox = await getValue(stores.handoff, key);
  const handoffId = HEX_64.test(outbox?.handoff_id || '') ? outbox.handoff_id : null;
  let record = null;
  if (handoffId) {
    try { record = validateExpectedBindings(await getValue(stores.handoff, `handoffs/${handoffId}`)); } catch { record = null; }
  }
  if (!record) pushCondition(conditions, {
    category: 'claim-outbox-integrity', detailCode: 'orphan-ready-outbox', severity: 'critical', subject: key,
    handoffId: handoffId || undefined, sourceTimestamp: iso(outbox?.expires_at) === null ? null : outbox.expires_at,
  });
  else {
    const classification = await classifyInvitationOutbox(outbox, key, record, stores, env);
    if (classification === 'INVALID') pushCondition(conditions, {
      category: 'claim-outbox-integrity', detailCode: 'invalid-ready-outbox', severity: 'critical', subject: key,
    });
    else if (classification === 'CURRENT_AUTHORITY_UNAVAILABLE') pushCondition(conditions, {
      category: 'claim-outbox-integrity', detailCode: 'current-authority-missing-or-invalid', severity: 'critical',
      subject: key, handoffId, sourceTimestamp: outbox.expires_at,
    });
    else if (classification === 'MIGRATION_REQUIRED') pushCondition(conditions, {
      category: 'claim-invitation-migration', detailCode: 'historical-outbox-without-newer-current-pointer', severity: 'high',
      subject: key, handoffId, sourceTimestamp: outbox.expires_at,
    });
    else if (classification === 'CURRENT' && record.state === 'INVITATION_READY' && Date.parse(outbox.expires_at) <= now.getTime()) {
      pushCondition(conditions, {
        category: 'claim-outbox-expired', detailCode: 'ready-outbox-past-expiry', severity: 'high', subject: key,
        handoffId, sourceTimestamp: outbox.expires_at,
      });
    }
  }
}

async function auditOneInvitationCurrent(key, stores, env, conditions) {
  const handoffId = key.match(/^invitation-ready-current\/([a-f0-9]{64})$/)?.[1];
  const record = handoffId ? await readBoundHandoff(stores, handoffId) : null;
  if (!record || !invitationReached(record)) return pushCondition(conditions, {
    category: 'claim-outbox-integrity', detailCode: 'orphan-current-pointer', severity: 'critical',
    subject: key, handoffId: handoffId || undefined,
  });
  const authority = await readInvitationAuthority(record, stores, env);
  if (!authority.valid || key !== authority.expected?.current.key) pushCondition(conditions, {
    category: 'claim-outbox-integrity', detailCode: 'invalid-current-pointer', severity: 'critical', subject: key, handoffId,
  });
}

async function auditOneDuplicatePaymentReview(key, stores, env, conditions) {
  const value = await getValue(stores.handoff, key);
  if (!await duplicatePaymentReviewIntegrity(value, key, stores, env)) return pushCondition(conditions, {
    category: 'duplicate-payment-integrity', detailCode: 'invalid-or-orphan-duplicate-payment-review',
    severity: 'critical', subject: key,
  });
  pushCondition(conditions, {
    category: 'duplicate-payment-review', detailCode: 'duplicate-paid-session-review-required',
    severity: 'critical', subject: key, handoffId: value.winning_handoff_id,
  });
}

async function readBoundHandoff(stores, handoffId) {
  try { return validateExpectedBindings(await getValue(stores.handoff, `handoffs/${handoffId}`)); } catch { return null; }
}

async function auditOneReversal(key, stores, conditions) {
  const value = await getValue(stores.handoff, key);
  const handoffId = key.match(/^stripe-reversal\/handoff\/([a-f0-9]{64})$/)?.[1];
  const handoff = handoffId ? await readBoundHandoff(stores, handoffId) : null;
  const binding = handoffId ? await getValue(stores.handoff, `stripe-reversal-binding/handoff/${handoffId}`) : null;
  if (!handoffId || !handoff || !reversalIntegrity(value, handoffId, binding, handoff)) return pushReversalIntegrity(
    conditions, 'invalid-reversal-state', key,
  );
  pushCondition(conditions, {
    category: 'stripe-reversal-review', detailCode: `halt-${String(value.severity || 'unknown').toLowerCase()}`,
    severity: value.severity === 'FUNDS_REVERSED' ? 'critical' : 'high', subject: handoffId, handoffId,
    sourceTimestamp: iso(value.latest_event_created_at) === null ? null : value.latest_event_created_at,
  });
}

async function auditOneReversalEvent(key, stores, conditions) {
  const eventHmac = key.match(/^stripe-reversal-event\/([a-f0-9]{64})$/)?.[1];
  const value = await getValue(stores.handoff, key);
  if (!eventHmac || !reversalEventIntegrity(value, eventHmac, value?.payment_intent_id_hmac_sha256)) return pushReversalIntegrity(
    conditions, 'invalid-event-reservation', key, iso(value?.event_created_at) === null ? null : value.event_created_at,
  );
  const pending = await getValue(stores.handoff, `stripe-reversal-pending/${value.payment_intent_id_hmac_sha256}/${eventHmac}`);
  if (!exactStored(pending, value)) pushReversalIntegrity(
    conditions, 'event-reservation-without-exact-pending-event', eventHmac, value.event_created_at,
  );
}

async function auditOnePendingPayment(key, stores, conditions) {
  const paymentIntentHmac = key.match(/^stripe-reversal-pending-payment\/([a-f0-9]{64})$/)?.[1];
  const marker = await getValue(stores.handoff, key);
  if (!paymentIntentHmac || !pendingPaymentIntegrity(marker, paymentIntentHmac)) return pushReversalIntegrity(
    conditions, 'invalid-pending-payment-halt', key,
  );
  const pendingPrefix = `stripe-reversal-pending/${paymentIntentHmac}/`;
  const iterable = stores.handoff.list({ prefix: pendingPrefix, paginate: true });
  if (!iterable || typeof iterable[Symbol.asyncIterator] !== 'function') throw new Error('ARC_OPERATIONS_AUDIT_PAGINATION_REQUIRED');
  let exactPendingEvent = false;
  for await (const page of iterable) {
    if (!page || !Array.isArray(page.blobs)) throw new Error('ARC_OPERATIONS_AUDIT_PAGINATION_REQUIRED');
    const candidates = page.blobs.slice(0, OPERATIONS_AUDIT_MAX_PENDING_EVENT_PROBES);
    for (const blob of candidates) {
      const eventHmac = String(blob?.key || '').match(new RegExp(`^${pendingPrefix}([a-f0-9]{64})$`))?.[1];
      const event = eventHmac ? await getValue(stores.handoff, blob.key) : null;
      if (eventHmac && reversalEventIntegrity(event, eventHmac, paymentIntentHmac) &&
          exactStored(await getValue(stores.handoff, `stripe-reversal-event/${eventHmac}`), event)) {
        exactPendingEvent = true;
        break;
      }
    }
    if (!exactPendingEvent && page.blobs.length > OPERATIONS_AUDIT_MAX_PENDING_EVENT_PROBES) {
      return pushReversalIntegrity(conditions, 'pending-event-probe-limit', paymentIntentHmac);
    }
    // A fixed small probe prevents one corrupt marker from consuming a whole
    // Function deadline. Per-event phases report exact malformed identities.
    break;
  }
  if (!exactPendingEvent) return pushReversalIntegrity(
    conditions, 'payment-halt-without-pending-event', paymentIntentHmac,
  );
  const binding = await getValue(stores.handoff, `stripe-payment-intent/${paymentIntentHmac}`);
  if (!binding) return pushCondition(conditions, {
    category: 'stripe-reversal-unbound', detailCode: 'verified-payment-reversal-awaiting-binding', severity: 'critical',
    subject: paymentIntentHmac,
  });
  if (!reversalBindingIntegrity(binding, STRIPE_PAYMENT_INTENT_INDEX_SCHEMA) ||
      binding.payment_intent_id_hmac_sha256 !== paymentIntentHmac || binding.stripe_account_id_sha256 !== marker.stripe_account_id_sha256 ||
      binding.livemode !== marker.livemode) return pushReversalIntegrity(
    conditions, 'payment-halt-binding-mismatch', paymentIntentHmac, null, binding?.handoff_id,
  );
  const handoffBinding = await getValue(stores.handoff, `stripe-reversal-binding/handoff/${binding.handoff_id}`);
  const handoff = await readBoundHandoff(stores, binding.handoff_id);
  if (!exactStored(handoffBinding, { ...binding, schema: STRIPE_REVERSAL_BINDING_SCHEMA }) || !handoff ||
      handoff.payment_evidence_sha256 !== binding.payment_evidence_sha256) return pushReversalIntegrity(
    conditions, 'pending-reversal-binding-chain-invalid', paymentIntentHmac, null, binding.handoff_id,
  );
  if (!await getValue(stores.handoff, `stripe-reversal/handoff/${binding.handoff_id}`)) pushReversalIntegrity(
    conditions, 'pending-reversal-not-reconciled', paymentIntentHmac, null, binding.handoff_id,
  );
}

async function auditOnePendingEvent(key, stores, conditions) {
  const path = key.match(/^stripe-reversal-pending\/([a-f0-9]{64})\/([a-f0-9]{64})$/);
  const value = await getValue(stores.handoff, key);
  if (!path || !reversalEventIntegrity(value, path[2], path[1])) return pushReversalIntegrity(
    conditions, 'invalid-pending-event', key, iso(value?.event_created_at) === null ? null : value.event_created_at,
  );
  if (!exactStored(await getValue(stores.handoff, `stripe-reversal-event/${path[2]}`), value)) pushReversalIntegrity(
    conditions, 'pending-event-without-exact-reservation', `${path[1]}/${path[2]}`, value.event_created_at,
  );
  const marker = await getValue(stores.handoff, `stripe-reversal-pending-payment/${path[1]}`);
  if (!pendingPaymentIntegrity(marker, path[1]) || marker.stripe_account_id_sha256 !== value.stripe_account_id_sha256 ||
      marker.livemode !== value.livemode) pushReversalIntegrity(
    conditions, 'pending-event-without-exact-payment-halt', `${path[1]}/${path[2]}`, value.event_created_at,
  );
}

async function auditOnePaymentBinding(key, stores, conditions) {
  const paymentIntentHmac = key.match(/^stripe-payment-intent\/([a-f0-9]{64})$/)?.[1];
  const binding = await getValue(stores.handoff, key);
  if (!paymentIntentHmac || !reversalBindingIntegrity(binding, STRIPE_PAYMENT_INTENT_INDEX_SCHEMA) ||
      binding.payment_intent_id_hmac_sha256 !== paymentIntentHmac) return pushReversalIntegrity(
    conditions, 'invalid-payment-intent-binding', key,
  );
  const paired = await getValue(stores.handoff, `stripe-reversal-binding/handoff/${binding.handoff_id}`);
  if (!exactStored(paired, { ...binding, schema: STRIPE_REVERSAL_BINDING_SCHEMA })) pushReversalIntegrity(
    conditions, 'payment-binding-without-exact-handoff-binding', paymentIntentHmac, null, binding.handoff_id,
  );
}

async function auditOneHandoffBinding(key, stores, conditions) {
  const handoffId = key.match(/^stripe-reversal-binding\/handoff\/([a-f0-9]{64})$/)?.[1];
  const binding = await getValue(stores.handoff, key);
  if (!handoffId || !reversalBindingIntegrity(binding) || binding.handoff_id !== handoffId) return pushReversalIntegrity(
    conditions, 'invalid-handoff-binding', key, null, handoffId,
  );
  const payment = await getValue(stores.handoff, `stripe-payment-intent/${binding.payment_intent_id_hmac_sha256}`);
  const handoff = await readBoundHandoff(stores, handoffId);
  if (!exactStored(payment, { ...binding, schema: STRIPE_PAYMENT_INTENT_INDEX_SCHEMA }) || !handoff ||
      handoff.payment_evidence_sha256 !== binding.payment_evidence_sha256) pushReversalIntegrity(
    conditions, 'handoff-binding-chain-invalid', handoffId, null, handoffId,
  );
}

async function auditOneRetentionIntent(key, stores, now, conditions) {
  const intent = await getValue(stores.retention, key);
  const path = key.match(/^delete-intents\/([a-f0-9]{64})\/([a-f0-9]{64})$/);
  let valid = false;
  try { validateRetentionDeleteIntent(intent); valid = Boolean(path && intent.target_hmac_sha256 === path[1] && intent.manifest_sha256 === path[2]); } catch { valid = false; }
  if (!valid) return pushCondition(conditions, {
    category: 'retention-integrity', detailCode: 'invalid-delete-intent', severity: 'critical', subject: key,
  });
  const receiptPath = key.replace(/^delete-intents\//, 'delete-receipts/');
  const receipt = await getValue(stores.retention, receiptPath);
  let validReceipt = false;
  if (receipt) {
    try { validateRetentionDeleteReceipt(receipt, intent); validReceipt = true; } catch {
      pushCondition(conditions, {
        category: 'retention-integrity', detailCode: 'invalid-delete-receipt', severity: 'critical',
        subject: receiptPath, sourceTimestamp: intent.authorized_at,
      });
    }
  }
  const authorizedAt = iso(intent.authorized_at);
  if (!validReceipt && (authorizedAt === null || now.getTime() - authorizedAt > RETENTION_INTENT_STUCK_AFTER_MS)) pushCondition(conditions, {
    category: 'retention-delete-stuck', detailCode: 'intent-without-receipt', severity: 'critical',
    subject: intent.target_hmac_sha256, sourceTimestamp: authorizedAt === null ? null : intent.authorized_at,
  });
}

async function auditOneRetentionReceipt(key, stores, conditions) {
  const path = key.match(/^delete-receipts\/([a-f0-9]{64})\/([a-f0-9]{64})$/);
  const intent = path ? await getValue(stores.retention, `delete-intents/${path[1]}/${path[2]}`) : null;
  const receipt = await getValue(stores.retention, key);
  let valid = false;
  try {
    validateRetentionDeleteIntent(intent); validateRetentionDeleteReceipt(receipt, intent);
    valid = intent.target_hmac_sha256 === path?.[1] && intent.manifest_sha256 === path?.[2];
  } catch { valid = false; }
  if (!valid) pushCondition(conditions, {
    category: 'retention-integrity', detailCode: 'orphan-or-invalid-delete-receipt', severity: 'critical', subject: key,
  });
}

async function auditOneIntake(key, stores, now, conditions) {
  const submissionId = key.match(/^submissions\/([0-9a-f-]{36})$/)?.[1];
  let record;
  try {
    if (!UUID.test(submissionId || '')) throw new TypeError('invalid key');
    record = normalizeStoredIntakeSubmissionForBridge(await getValue(stores.intake, key));
  } catch {
    return pushCondition(conditions, {
      category: 'intake-arc1-integrity', detailCode: 'invalid-intake-bridge-record', severity: 'critical', subject: key,
    });
  }
  for (const state of [
    { category: 'intake-arc1-delivery', value: record.arc1_delivery },
    { category: 'intake-arc1-dispatch', value: record.arc1_dispatch },
  ]) {
    if (state.value.alert_status === 'PENDING' || state.value.status === 'DEAD_LETTER') pushCondition(conditions, {
      category: state.category,
      detailCode: state.value.status === 'DEAD_LETTER' ? 'dead-letter' : `pending-${String(state.value.alert_code || 'failure').toLowerCase()}`,
      severity: state.value.status === 'DEAD_LETTER' ? 'critical' : 'high', subject: `${submissionId}:${state.category}`,
      sourceTimestamp: state.value.alert_updated_at || record.received_at,
    });
  }
  if (record.arc1_delivery.status === 'CLAIMED' && Date.parse(record.arc1_delivery.lease_expires_at) <= now.getTime()) pushCondition(conditions, {
    category: 'intake-arc1-delivery', detailCode: 'expired-delivery-lease', severity: 'high',
    subject: `${submissionId}:expired-lease`, sourceTimestamp: record.arc1_delivery.lease_expires_at,
  });
}

async function auditOneKey(phase, key, stores, env, now, conditions) {
  if (phase === 0) return auditOneHandoff(key, stores, env, now, conditions);
  if (phase === 1) return auditOneInvitation(key, stores, env, now, conditions);
  if (phase === 2) return auditOneReversal(key, stores, conditions);
  if (phase === 3) return auditOneReversalEvent(key, stores, conditions);
  if (phase === 4) return auditOnePendingPayment(key, stores, conditions);
  if (phase === 5) return auditOnePendingEvent(key, stores, conditions);
  if (phase === 6) return auditOnePaymentBinding(key, stores, conditions);
  if (phase === 7) return auditOneHandoffBinding(key, stores, conditions);
  if (phase === 8) return auditOneRetentionIntent(key, stores, now, conditions);
  if (phase === 9) return auditOneRetentionReceipt(key, stores, conditions);
  if (phase === 10) return auditOneIntake(key, stores, now, conditions);
  if (phase === 11) return auditOneInvitationCurrent(key, stores, env, conditions);
  if (phase === 12) return auditOneDuplicatePaymentReview(key, stores, env, conditions);
  throw new Error('ARC_OPERATIONS_AUDIT_PHASE_INVALID');
}

function auditPhaseStore(phase, stores) {
  if (phase <= 7 || phase === 11 || phase === 12) return stores.handoff;
  if (phase <= 9) return stores.retention;
  if (!stores.intake) throw new Error('ARC_OPERATIONS_AUDIT_INTAKE_STORE_REQUIRED');
  return stores.intake;
}

async function persistConditions(conditions, stores, env, now, counts) {
  for (const condition of conditions) {
    if (await ensureAlert(stores.alerts, alertDefinition(condition, env, now))) counts.created += 1;
    else counts.replayed += 1;
    counts.conditions += 1;
    counts.categories[condition.category] = (counts.categories[condition.category] || 0) + 1;
  }
}

async function runIncrementalOperationsAudit(env, stores, adapters, now) {
  const startedAt = auditWallNow(adapters);
  const deadlineMs = startedAt + OPERATIONS_AUDIT_BUDGET_MS;
  const resumeCursor = decodeAuditCursor(requestAuditCursor(adapters), env);
  let cursor = { ...resumeCursor };
  const counts = { conditions: 0, created: 0, replayed: 0, categories: {} };
  let scanned = 0;
  let pages = 0;
  const initialCursor = (phase, shard) => ({ phase, shard, position: 0, sequence_hmac_sha256: null });
  const partial = () => ({
    state: 'AUDIT_PARTIAL', scanned, alert_conditions: counts.conditions, alerts_created: counts.created,
    alerts_replayed: counts.replayed, categories: counts.categories, next_cursor: encodeAuditCursor(cursor, env),
    alert_delivery_implemented: false,
  });
  for (let phase = resumeCursor.phase; phase < AUDIT_PHASES.length; phase += 1) {
    const store = auditPhaseStore(phase, stores);
    for (let shard = phase === resumeCursor.phase ? resumeCursor.shard : 0; shard <= AUDIT_CATCH_ALL_SHARD; shard += 1) {
      const basePrefix = AUDIT_PHASES[phase][1];
      const catchAll = shard === AUDIT_CATCH_ALL_SHARD;
      const prefix = catchAll ? basePrefix : `${basePrefix}${shard.toString(16).padStart(AUDIT_SHARD_WIDTH, '0')}`;
      const checkpoint = phase === resumeCursor.phase && shard === resumeCursor.shard ? resumeCursor : initialCursor(phase, shard);
      cursor = { ...checkpoint };
      const iterable = store.list({ prefix, paginate: true });
      if (!iterable || typeof iterable[Symbol.asyncIterator] !== 'function') throw new Error('ARC_OPERATIONS_AUDIT_PAGINATION_REQUIRED');
      let position = 0;
      let sequenceSha256 = auditSequenceInitial(env, phase, shard, prefix);
      let checkpointVerified = checkpoint.position === 0;
      for await (const page of iterable) {
        if (!page || !Array.isArray(page.blobs)) throw new Error('ARC_OPERATIONS_AUDIT_PAGINATION_REQUIRED');
        if (auditWallNow(adapters) >= deadlineMs) return partial();
        let pageCounted = false;
        // Preserve the provider's exact sequence. Netlify Blobs exposes neither
        // its opaque continuation nor a key-ordering contract through Store.list,
        // so sorting a page or comparing keys would make a cross-run checkpoint
        // capable of silently skipping later, lower-valued keys.
        for (const blob of page.blobs) {
          if (typeof blob?.key !== 'string' || blob.key.length === 0) {
            throw new Error('ARC_OPERATIONS_AUDIT_PAGINATION_REQUIRED');
          }
          const key = blob.key;
          const nextSequenceSha256 = auditSequenceNext(env, sequenceSha256, key);
          position += 1;
          if (!checkpointVerified) {
            sequenceSha256 = nextSequenceSha256;
            if (position < checkpoint.position) continue;
            if (position === checkpoint.position && sequenceSha256 === checkpoint.sequence_hmac_sha256) {
              checkpointVerified = true;
              continue;
            }
            // Provider membership or ordering moved before the authenticated
            // checkpoint. Restart only this prefix; never report completion or
            // apply side effects against an unverified continuation.
            cursor = initialCursor(phase, shard);
            return partial();
          }
          if (!pageCounted) {
            pages += 1;
            pageCounted = true;
            if (pages > OPERATIONS_AUDIT_MAX_PAGES_PER_RUN) return partial();
          }
          if (auditWallNow(adapters) >= deadlineMs) return partial();
          // The catch-all traversal must checkpoint ordinary sharded keys too.
          // Otherwise a deadline reached before a late malformed key would
          // restart the broad provider listing at its head forever.
          if (catchAll && /^[a-f0-9]{2}/.test(key.slice(basePrefix.length))) {
            sequenceSha256 = nextSequenceSha256;
            cursor = { phase, shard, position, sequence_hmac_sha256: sequenceSha256 };
            continue;
          }
          if (scanned >= OPERATIONS_AUDIT_MAX_RECORDS_PER_RUN) return partial();
          scanned += 1;
          const conditions = [];
          await auditOneKey(phase, key, stores, env, now, conditions);
          await persistConditions(conditions, stores, env, now, counts);
          sequenceSha256 = nextSequenceSha256;
          cursor = { phase, shard, position, sequence_hmac_sha256: sequenceSha256 };
        }
      }
      if (!checkpointVerified) {
        // A truncated sequence is also drift. A stale position must not let a
        // shorter listing masquerade as a completed prefix.
        cursor = initialCursor(phase, shard);
        return partial();
      }
      const nextCursor = shard < AUDIT_CATCH_ALL_SHARD ? initialCursor(phase, shard + 1) :
        phase + 1 < AUDIT_PHASES.length ? initialCursor(phase + 1, 0) : null;
      if (nextCursor) cursor = nextCursor;
      if (nextCursor && auditWallNow(adapters) >= deadlineMs) return partial();
    }
    if (phase + 1 < AUDIT_PHASES.length) cursor = initialCursor(phase + 1, 0);
  }
  return {
    state: 'AUDIT_COMPLETE', scanned, alert_conditions: counts.conditions, alerts_created: counts.created,
    alerts_replayed: counts.replayed, categories: counts.categories, next_cursor: null, alert_delivery_implemented: false,
  };
}

export async function runOperationsAudit(env, stores, adapters = {}) {
  if (!operationsAuditConfiguration(env).enabled) throw new Error('ARC_OPERATIONS_AUDIT_DISABLED');
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('Operations audit clock is invalid.');
  if (adapters.incremental === true || adapters.request || Object.hasOwn(adapters, 'cursor')) {
    return runIncrementalOperationsAudit(env, stores, adapters, now);
  }
  const conditions = [];
  const budget = { scanned: 0 };
  const handoffs = await auditHandoffs(stores, env, now, conditions, budget);
  await auditInvitationOutboxes(stores, handoffs, env, now, conditions, budget);
  await auditInvitationCurrentPointers(stores, handoffs, env, conditions, budget);
  await auditDuplicatePaymentReviews(stores, env, conditions, budget);
  const reversals = await auditReversals(stores, handoffs, conditions, budget);
  await auditReversalIndexes(stores, handoffs, reversals, conditions, budget);
  await auditRetentionIntents(stores, now, conditions, budget);
  await auditIntake(stores, now, conditions, budget);
  let created = 0;
  for (const condition of conditions) {
    if (await ensureAlert(stores.alerts, alertDefinition(condition, env, now))) created += 1;
  }
  const categories = Object.fromEntries([...new Set(conditions.map((condition) => condition.category))].sort().map((category) => [
    category,
    conditions.filter((condition) => condition.category === category).length,
  ]));
  return {
    alert_conditions: conditions.length,
    alerts_created: created,
    alerts_replayed: conditions.length - created,
    categories,
    alert_delivery_implemented: false,
  };
}
