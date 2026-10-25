import {
  createHmac,
  timingSafeEqual,
} from 'node:crypto';

import {
  CLAIM_TOKEN_TTL_SECONDS,
  OUTBOX_CLAIM_VERSION,
  canonicalJson,
  handoffKeyFromId,
  hmacHex,
  reviseRecord,
} from './arc2-handoff-core.mjs';
import {
  readEntry,
  readIndexEntry,
  replaceEntry,
  replaceIndex,
} from './arc2-handoff-store.mjs';
import { deleteEmailRecipientCapsule } from './email-recipient-vault-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET_ENV =
  'ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET';
export const ARC2_EMAIL_NEGATIVE_EVENT_PREFIX = 'arc2-email-negative-events/';
export const ARC2_EMAIL_NEGATIVE_CONTROL_PREFIX = 'arc2-email-negative-controls/';
export const ARC2_EMAIL_LOCAL_ALERT_PREFIX = 'arc2-email-local-alerts/';
export const ARC2_CLAIM_EMAIL_REVIEW_REQUIRED = 'CLAIM_EMAIL_REVIEW_REQUIRED';
export const ARC2_DELIVERY_REVIEW_REQUIRED = 'DELIVERY_REVIEW_REQUIRED';

const CLAIM_FLAG = 'ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED';
const FINAL_FLAG = 'ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED';
const NEGATIVE_TYPES = new Set([
  'email.bounced',
  'email.complained',
  'email.failed',
  'email.suppressed',
]);
const HEX_64 = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const CONTROL = /[\u0000-\u001f\u007f]/;
const CONTROL_SCHEMA = 'arc2-email-negative-control-v1';
const ATTEMPT_BINDING_SCHEMA = 'arc2-email-negative-attempt-binding-v1';
const EVENT_SCHEMA = 'arc2-email-negative-event-v1';
const ALERT_SCHEMA = 'arc2-email-local-alert-v1';
const REMEDIATION_SCHEMA = 'arc2-email-negative-remediation-v1';
const CLAIM_CURRENT_PREFIX = 'invitation-ready-current/';
const OUTBOX_PREFIX = 'outbox/';
const CLAIM_BEARER_DERIVATION_PREFIX = 'arc2-claim-bearer-derivation-v1\n';
const CLAIM_BEARER_STORAGE_PREFIX = 'arc2-claim-bearer-at-rest-v1\n';
const CLAIM_BEARER_REVOCATION_PREFIX = 'arc2-claim-bearer-revocation-v1\n';

const exactKeys = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
const safeEqual = (left, right) => {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
};

function secret(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 32 ||
      Buffer.byteLength(value, 'utf8') > 256 || CONTROL.test(value)) {
    throw new TypeError(`${ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET_ENV} is invalid.`);
  }
  return value;
}

function stamp(value, label) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new TypeError(`${label} is invalid.`);
  }
  return parsed;
}

function kindFlag(kind) {
  if (kind === 'claim_invitation') return CLAIM_FLAG;
  if (kind === 'final_delivery') return FINAL_FLAG;
  throw new TypeError('ARC2 email negative-state kind is invalid.');
}

function reviewState(kind) {
  return kind === 'claim_invitation'
    ? ARC2_CLAIM_EMAIL_REVIEW_REQUIRED
    : ARC2_DELIVERY_REVIEW_REQUIRED;
}

function resolvedSecret(env) {
  if (!sensitiveCredentialsAreIsolated(env, [ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET_ENV])) {
    throw new TypeError(`${ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET_ENV} is not isolated.`);
  }
  return secret(env[ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET_ENV]);
}

function hmac(secretValue, domain, value) {
  return createHmac('sha256', secretValue).update(`${domain}\n${value}`).digest('hex');
}

function unsigned(value) {
  const { record_hmac_sha256: ignored, ...record } = value;
  return record;
}

function sign(value, domain, secretValue) {
  return {
    ...value,
    record_hmac_sha256: hmac(secretValue, domain, canonicalJson(value)),
  };
}

function verifySignature(value, domain, secretValue) {
  const expected = hmac(secretValue, domain, canonicalJson(unsigned(value)));
  if (!HEX_64.test(String(value?.record_hmac_sha256 || '')) ||
      !safeEqual(value.record_hmac_sha256, expected)) {
    throw new Error('ARC2_EMAIL_NEGATIVE_STATE_SIGNATURE_INVALID');
  }
}

function validateAttemptBinding(value, secretValue) {
  const fields = [
    'attempt_hmac_sha256', 'created_at', 'handoff_id', 'job_key', 'job_kind',
    'record_hmac_sha256', 'schema', 'version',
  ];
  if (!exactKeys(value, fields) || value.schema !== ATTEMPT_BINDING_SCHEMA || value.version !== 1 ||
      !HEX_64.test(String(value.attempt_hmac_sha256 || '')) ||
      !HEX_64.test(String(value.handoff_id || '')) || !HEX_64.test(String(value.job_key || '')) ||
      !['claim_invitation', 'final_delivery'].includes(value.job_kind)) {
    throw new TypeError('ARC2 email negative attempt binding is invalid.');
  }
  stamp(value.created_at, 'ARC2 email negative attempt binding timestamp');
  verifySignature(value, 'arc2-email-negative-attempt-binding-record-v1', secretValue);
  return value;
}

function validateEventRecord(value, secretValue) {
  const fields = [
    'attempt_hmac_sha256', 'event_hmac_sha256', 'event_type', 'handoff_id', 'job_kind',
    'occurred_at', 'provider', 'provider_event_id_hmac_sha256',
    'provider_message_id_hmac_sha256', 'record_hmac_sha256', 'recorded_at', 'schema', 'version',
  ];
  if (!exactKeys(value, fields) || value.schema !== EVENT_SCHEMA || value.version !== 1 ||
      value.provider !== 'resend' || !NEGATIVE_TYPES.has(value.event_type) ||
      !['claim_invitation', 'final_delivery'].includes(value.job_kind) ||
      ![value.attempt_hmac_sha256, value.event_hmac_sha256, value.handoff_id,
        value.provider_event_id_hmac_sha256, value.provider_message_id_hmac_sha256]
        .every((item) => HEX_64.test(String(item || '')))) {
    throw new TypeError('ARC2 email negative event record is invalid.');
  }
  stamp(value.occurred_at, 'ARC2 email negative event timestamp');
  stamp(value.recorded_at, 'ARC2 email negative event recorded timestamp');
  verifySignature(value, 'arc2-email-negative-event-record-v1', secretValue);
  return value;
}

function validateControl(value, secretValue) {
  const fields = [
    'attempt_hmac_sha256', 'event_hmac_sha256', 'first_event_type', 'handoff_id',
    'job_kind', 'record_hmac_sha256', 'required_at', 'schema', 'state', 'version',
  ];
  if (!exactKeys(value, fields) || value.schema !== CONTROL_SCHEMA || value.version !== 1 ||
      value.state !== reviewState(value.job_kind) || !NEGATIVE_TYPES.has(value.first_event_type) ||
      ![value.attempt_hmac_sha256, value.event_hmac_sha256, value.handoff_id]
        .every((item) => HEX_64.test(String(item || '')))) {
    throw new TypeError('ARC2 email negative control is invalid.');
  }
  stamp(value.required_at, 'ARC2 email negative control timestamp');
  verifySignature(value, 'arc2-email-negative-control-record-v1', secretValue);
  return value;
}

function validateAlert(value, secretValue) {
  const fields = [
    'alert_hmac_sha256', 'category', 'detail_code', 'event_hmac_sha256', 'handoff_id',
    'job_kind', 'queued_at', 'record_hmac_sha256', 'required_state', 'schema', 'severity',
    'source_timestamp', 'state', 'version',
  ];
  const allowedDetails = new Set([
    'claim-invitation-bounced',
    'claim-invitation-complained',
    'claim-invitation-failed',
    'claim-invitation-suppressed',
    'final-delivery-bounced',
    'final-delivery-complained',
    'final-delivery-failed',
    'final-delivery-suppressed',
  ]);
  if (!exactKeys(value, fields) || value.schema !== ALERT_SCHEMA || value.version !== 1 ||
      value.category !== 'transactional-email' ||
      !['claim_invitation', 'final_delivery'].includes(value.job_kind) ||
      value.required_state !== reviewState(value.job_kind) || value.state !== 'OPEN' ||
      !allowedDetails.has(value.detail_code) ||
      value.severity !== (value.detail_code.endsWith('-complained') ? 'critical' : 'high') ||
      ![value.alert_hmac_sha256, value.event_hmac_sha256, value.handoff_id]
        .every((item) => HEX_64.test(String(item || '')))) {
    throw new TypeError('ARC2 email local alert is invalid.');
  }
  stamp(value.queued_at, 'ARC2 email local alert queued timestamp');
  stamp(value.source_timestamp, 'ARC2 email local alert source timestamp');
  verifySignature(value, 'arc2-email-local-alert-record-v1', secretValue);
  return value;
}

function controlKey(handoffId, kind) {
  return `${ARC2_EMAIL_NEGATIVE_CONTROL_PREFIX}by-handoff/${handoffId}/${kind}`;
}

function attemptKey(attemptHmac) {
  return `${ARC2_EMAIL_NEGATIVE_CONTROL_PREFIX}by-attempt/${attemptHmac}`;
}

function eventKey(eventHmac) {
  return `${ARC2_EMAIL_NEGATIVE_EVENT_PREFIX}${eventHmac}`;
}

function alertKey(eventHmac) {
  return `${ARC2_EMAIL_LOCAL_ALERT_PREFIX}${eventHmac}`;
}

function remediationKey(controlHmac) {
  return `${ARC2_EMAIL_NEGATIVE_CONTROL_PREFIX}remediation/${controlHmac}`;
}

async function createAndRead(store, key, value, validate) {
  let created = false;
  try {
    const result = await store.setJSON(key, value, { onlyIfNew: true });
    created = result?.modified === true;
  } catch {}
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!entry) throw new Error('ARC2_EMAIL_NEGATIVE_STATE_WRITE_UNAVAILABLE');
  return { value: validate(entry.data), created };
}

export function arc2NegativeEmailStateConfiguration(env = process.env) {
  const requested = env[CLAIM_FLAG] === 'true' || env[FINAL_FLAG] === 'true';
  if (!requested) return Object.freeze({ requested: false, enabled: false });
  try {
    resolvedSecret(env);
    return Object.freeze({ requested: true, enabled: true });
  } catch {
    return Object.freeze({ requested: true, enabled: false });
  }
}

function requireForKind(kind, env) {
  const flag = kindFlag(kind);
  if (env[flag] !== 'true') throw new Error(`ARC2_${kind.toUpperCase()}_EMAIL_DISABLED`);
  const configuration = arc2NegativeEmailStateConfiguration(env);
  if (!configuration.enabled) throw new Error('ARC2_EMAIL_NEGATIVE_STATE_DISABLED');
  return resolvedSecret(env);
}

function normalizedContext(context) {
  if (!context || !HEX_64.test(String(context.attempt_hmac_sha256 || '')) ||
      !HEX_64.test(String(context.handoff_id || '')) || !HEX_64.test(String(context.job_key || '')) ||
      !['claim_invitation', 'final_delivery'].includes(context.kind)) {
    throw new TypeError('ARC2 email negative context is invalid.');
  }
  return context;
}

function normalizedEvent(event, kind) {
  if (!event || event.job_kind !== kind || event.provider !== 'resend' ||
      !HEX_64.test(String(event.attempt_hmac_sha256 || '')) ||
      !NEGATIVE_TYPES.has(event.event_type) || typeof event.provider_event_id !== 'string' ||
      event.provider_event_id.length < 1 || event.provider_event_id.length > 512 ||
      CONTROL.test(event.provider_event_id) || !UUID.test(String(event.provider_message_id || '')) ||
      event.provider_message_id.length > 512) {
    throw new TypeError('ARC2 email negative event is invalid.');
  }
  stamp(event.occurred_at, 'ARC2 email negative event timestamp');
  return event;
}

async function ensureAttemptBinding(store, context, secretValue, now) {
  const expected = sign({
    schema: ATTEMPT_BINDING_SCHEMA,
    version: 1,
    attempt_hmac_sha256: context.attempt_hmac_sha256,
    handoff_id: context.handoff_id,
    job_kind: context.kind,
    job_key: context.job_key,
    created_at: now.toISOString(),
  }, 'arc2-email-negative-attempt-binding-record-v1', secretValue);
  const result = await createAndRead(store, attemptKey(context.attempt_hmac_sha256), expected,
    (value) => validateAttemptBinding(value, secretValue));
  const value = result.value;
  if (value.attempt_hmac_sha256 !== context.attempt_hmac_sha256 ||
      value.handoff_id !== context.handoff_id || value.job_kind !== context.kind ||
      value.job_key !== context.job_key) {
    throw new Error('ARC2_EMAIL_NEGATIVE_ATTEMPT_BINDING_CONFLICT');
  }
  return result;
}

export async function recoverArc2NegativeAttemptBinding(store, input, env = process.env) {
  if (!input || !HEX_64.test(String(input.attempt_hmac_sha256 || '')) ||
      !['claim_invitation', 'final_delivery'].includes(input.job_kind)) {
    throw new TypeError('ARC2 email negative attempt lookup is invalid.');
  }
  const secretValue = requireForKind(input.job_kind, env);
  const entry = await store.getWithMetadata(attemptKey(input.attempt_hmac_sha256),
    { type: 'json', consistency: 'strong' });
  if (!entry) throw new Error('ARC2_EMAIL_NEGATIVE_ATTEMPT_BINDING_NOT_FOUND');
  const value = validateAttemptBinding(entry.data, secretValue);
  if (value.attempt_hmac_sha256 !== input.attempt_hmac_sha256 ||
      value.job_kind !== input.job_kind) {
    throw new Error('ARC2_EMAIL_NEGATIVE_ATTEMPT_BINDING_CONFLICT');
  }
  return Object.freeze({
    kind: value.job_kind,
    attempt_hmac_sha256: value.attempt_hmac_sha256,
    handoff_id: value.handoff_id,
    job_key: value.job_key,
  });
}

async function ensureEvent(store, context, event, secretValue, now) {
  const providerEventHmac = hmac(secretValue,
    'arc2-email-negative-provider-event-id-v1', `resend\n${event.provider_event_id}`);
  const providerMessageHmac = hmac(secretValue,
    'arc2-email-negative-provider-message-id-v1', `resend\n${event.provider_message_id.toLowerCase()}`);
  const eventHmac = hmac(secretValue, 'arc2-email-negative-event-id-v1',
    `${context.attempt_hmac_sha256}\n${providerEventHmac}`);
  const expected = sign({
    schema: EVENT_SCHEMA,
    version: 1,
    event_hmac_sha256: eventHmac,
    attempt_hmac_sha256: context.attempt_hmac_sha256,
    handoff_id: context.handoff_id,
    job_kind: context.kind,
    provider: 'resend',
    provider_event_id_hmac_sha256: providerEventHmac,
    provider_message_id_hmac_sha256: providerMessageHmac,
    event_type: event.event_type,
    occurred_at: event.occurred_at,
    recorded_at: now.toISOString(),
  }, 'arc2-email-negative-event-record-v1', secretValue);
  const result = await createAndRead(store, eventKey(eventHmac), expected,
    (value) => validateEventRecord(value, secretValue));
  const value = result.value;
  for (const field of ['event_hmac_sha256', 'attempt_hmac_sha256', 'handoff_id', 'job_kind',
    'provider_event_id_hmac_sha256', 'provider_message_id_hmac_sha256', 'event_type', 'occurred_at']) {
    if (value[field] !== expected[field]) throw new Error('ARC2_EMAIL_NEGATIVE_EVENT_CONFLICT');
  }
  return result;
}

async function ensureControl(store, context, eventRecord, secretValue) {
  const expected = sign({
    schema: CONTROL_SCHEMA,
    version: 1,
    handoff_id: context.handoff_id,
    job_kind: context.kind,
    state: reviewState(context.kind),
    attempt_hmac_sha256: context.attempt_hmac_sha256,
    event_hmac_sha256: eventRecord.event_hmac_sha256,
    first_event_type: eventRecord.event_type,
    required_at: eventRecord.recorded_at,
  }, 'arc2-email-negative-control-record-v1', secretValue);
  const result = await createAndRead(store, controlKey(context.handoff_id, context.kind), expected,
    (value) => validateControl(value, secretValue));
  const value = result.value;
  if (value.handoff_id !== context.handoff_id || value.job_kind !== context.kind ||
      value.state !== reviewState(context.kind)) {
    throw new Error('ARC2_EMAIL_NEGATIVE_CONTROL_CONFLICT');
  }
  return result;
}

async function ensureLocalAlert(store, context, eventRecord, secretValue, now) {
  const alertHmac = hmac(secretValue, 'arc2-email-local-alert-id-v1',
    `${context.handoff_id}\n${eventRecord.event_hmac_sha256}`);
  const detail = eventRecord.event_type.slice('email.'.length).replaceAll('_', '-');
  const channel = context.kind.replaceAll('_', '-');
  const expected = sign({
    schema: ALERT_SCHEMA,
    version: 1,
    alert_hmac_sha256: alertHmac,
    category: 'transactional-email',
    severity: eventRecord.event_type === 'email.complained' ? 'critical' : 'high',
    detail_code: `${channel}-${detail}`,
    handoff_id: context.handoff_id,
    job_kind: context.kind,
    event_hmac_sha256: eventRecord.event_hmac_sha256,
    required_state: reviewState(context.kind),
    state: 'OPEN',
    source_timestamp: eventRecord.occurred_at,
    queued_at: now.toISOString(),
  }, 'arc2-email-local-alert-record-v1', secretValue);
  const result = await createAndRead(store, alertKey(eventRecord.event_hmac_sha256), expected,
    (value) => validateAlert(value, secretValue));
  const value = result.value;
  if (value.alert_hmac_sha256 !== alertHmac || value.handoff_id !== context.handoff_id ||
      value.event_hmac_sha256 !== eventRecord.event_hmac_sha256) {
    throw new Error('ARC2_EMAIL_LOCAL_ALERT_CONFLICT');
  }
  return result;
}

function validateRemediation(value, secretValue) {
  const fields = [
    'bearer_rotated', 'completed_at', 'control_hmac_sha256', 'handoff_id', 'job_kind',
    'local_alert_required', 'outbox_marked', 'record_hmac_sha256', 'schema', 'state', 'version',
  ];
  if (!exactKeys(value, fields) || value.schema !== REMEDIATION_SCHEMA || value.version !== 1 ||
      value.state !== 'COMPLETED' || !['claim_invitation', 'final_delivery'].includes(value.job_kind) ||
      !HEX_64.test(String(value.control_hmac_sha256 || '')) ||
      !HEX_64.test(String(value.handoff_id || '')) ||
      typeof value.bearer_rotated !== 'boolean' || typeof value.outbox_marked !== 'boolean' ||
      typeof value.local_alert_required !== 'boolean' ||
      value.bearer_rotated !== (value.job_kind === 'claim_invitation') ||
      value.outbox_marked !== (value.job_kind === 'final_delivery') ||
      value.local_alert_required !== true) {
    throw new TypeError('ARC2 email negative remediation is invalid.');
  }
  stamp(value.completed_at, 'ARC2 email negative remediation timestamp');
  verifySignature(value, 'arc2-email-negative-remediation-record-v1', secretValue);
  return value;
}

async function readRemediation(store, control, context, secretValue) {
  const entry = await store.getWithMetadata(remediationKey(control.record_hmac_sha256),
    { type: 'json', consistency: 'strong' });
  if (!entry) return null;
  const value = validateRemediation(entry.data, secretValue);
  if (value.control_hmac_sha256 !== control.record_hmac_sha256 ||
      value.handoff_id !== context.handoff_id || value.job_kind !== context.kind) {
    throw new Error('ARC2_EMAIL_NEGATIVE_REMEDIATION_CONFLICT');
  }
  return value;
}

async function ensureRemediation(store, control, context, secretValue, now) {
  const expected = sign({
    schema: REMEDIATION_SCHEMA,
    version: 1,
    control_hmac_sha256: control.record_hmac_sha256,
    handoff_id: context.handoff_id,
    job_kind: context.kind,
    state: 'COMPLETED',
    bearer_rotated: context.kind === 'claim_invitation',
    outbox_marked: context.kind === 'final_delivery',
    local_alert_required: true,
    completed_at: now.toISOString(),
  }, 'arc2-email-negative-remediation-record-v1', secretValue);
  const result = await createAndRead(store, remediationKey(control.record_hmac_sha256), expected,
    (value) => validateRemediation(value, secretValue));
  const value = result.value;
  if (value.control_hmac_sha256 !== control.record_hmac_sha256 ||
      value.handoff_id !== context.handoff_id || value.job_kind !== context.kind) {
    throw new Error('ARC2_EMAIL_NEGATIVE_REMEDIATION_CONFLICT');
  }
  return result;
}

function deriveClaimBearer(record, env) {
  const materialValue = {
    handoff_id: record.handoff_id,
    lead_route_receipt_sha256: record.lead_route_receipt_sha256,
    claim_invitation_ready_at: record.claim_invitation_ready_at,
    claim_token_expires_at: record.claim_token_expires_at,
  };
  if (record.claim_invitation_generation > 0) {
    materialValue.claim_invitation_generation = record.claim_invitation_generation;
  }
  return createHmac('sha256', env.ARC_CLAIM_TOKEN_SECRET)
    .update(`${CLAIM_BEARER_DERIVATION_PREFIX}${canonicalJson(materialValue)}`)
    .digest('base64url');
}

async function deleteAndVerifyIndex(store, key) {
  await store.delete(key);
  if (await store.getWithMetadata(key, { type: 'json', consistency: 'strong' })) {
    throw new Error('ARC2_EMAIL_NEGATIVE_INDEX_DELETE_UNAVAILABLE');
  }
}

async function revokeClaimBearer(store, handoffId, env, now) {
  await deleteAndVerifyIndex(store, `${CLAIM_CURRENT_PREFIX}${handoffId}`);
  const key = handoffKeyFromId(handoffId);
  let entry = await readEntry(store, key);
  if (!entry) throw new Error('ARC2_EMAIL_NEGATIVE_HANDOFF_NOT_FOUND');
  for (let attempt = 0; attempt < 4; attempt += 1) {
    if (!['INVITATION_READY', 'CLAIM_WRAPPER_CONSUMED'].includes(entry.record.state)) {
      return Object.freeze({ rotated: false, state: entry.record.state });
    }
    if (entry.record.state === 'CLAIM_WRAPPER_CONSUMED') {
      const currentTombstone = hmacHex(env.ARC_CLAIM_TOKEN_SECRET,
        `${CLAIM_BEARER_REVOCATION_PREFIX}${handoffId}\n${entry.record.claim_invitation_generation}`);
      if (safeEqual(entry.record.claim_token_consumed_hmac_sha256, currentTombstone)) {
        return Object.freeze({ rotated: false, state: entry.record.state });
      }
      const generation = entry.record.claim_invitation_generation + 1;
      const revoked = reviseRecord(entry.record, {
        claim_invitation_generation: generation,
        claim_token_consumed_hmac_sha256: hmacHex(env.ARC_CLAIM_TOKEN_SECRET,
          `${CLAIM_BEARER_REVOCATION_PREFIX}${handoffId}\n${generation}`),
      }, now);
      try {
        entry = await replaceEntry(store, key, entry, revoked);
        return Object.freeze({ rotated: true, state: entry.record.state });
      } catch (error) {
        if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 3) throw error;
        entry = await readEntry(store, key);
        if (!entry) throw new Error('ARC2_EMAIL_NEGATIVE_HANDOFF_NOT_FOUND');
        continue;
      }
    }
    const readyMs = Math.max(now.getTime(), Date.parse(entry.record.updated_at));
    const readyAt = new Date(readyMs);
    const expiresAt = new Date(readyMs + CLAIM_TOKEN_TTL_SECONDS * 1000);
    const draft = reviseRecord(entry.record, {
      claim_invitation_generation: entry.record.claim_invitation_generation + 1,
      claim_invitation_ready_at: readyAt.toISOString(),
      claim_token_expires_at: expiresAt.toISOString(),
    }, readyAt);
    const token = deriveClaimBearer(draft, env);
    const rotated = {
      ...draft,
      claim_token_hmac_sha256: hmacHex(env.ARC_CLAIM_TOKEN_SECRET,
        `${CLAIM_BEARER_STORAGE_PREFIX}${token}`),
    };
    try {
      entry = await replaceEntry(store, key, entry, rotated);
      return Object.freeze({ rotated: true, state: entry.record.state });
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 3) throw error;
      entry = await readEntry(store, key);
      if (!entry) throw new Error('ARC2_EMAIL_NEGATIVE_HANDOFF_NOT_FOUND');
    }
  }
  throw new Error('ARC2_EMAIL_NEGATIVE_HANDOFF_CONTENTION');
}

function basicFinalOutboxValid(value, context) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype && value.schema === OUTBOX_CLAIM_VERSION &&
    value.handoff_id === context.handoff_id && value.outbox_claim_key_hmac_sha256 === context.job_key &&
    HEX_64.test(String(value.netlify_site_id_sha256 || '')) &&
    HEX_64.test(String(value.netlify_deploy_id_sha256 || '')) &&
    ['CLAIMED', 'DELIVERY_ACK_PENDING', 'DELIVERED', ARC2_DELIVERY_REVIEW_REQUIRED]
      .includes(value.status);
}

async function markFinalOutboxReviewRequired(store, context, control) {
  const key = `${OUTBOX_PREFIX}${context.job_key}`;
  let entry = await readIndexEntry(store, key);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    if (!entry || !basicFinalOutboxValid(entry.value, context)) {
      throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_CONFLICT');
    }
    if (entry.value.status === ARC2_DELIVERY_REVIEW_REQUIRED) {
      if (entry.value.negative_control_hmac_sha256 !== control.record_hmac_sha256 ||
          entry.value.review_required_at !== control.required_at) {
        throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_CONFLICT');
      }
      return Object.freeze({ idempotent_replay: true });
    }
    const value = {
      ...entry.value,
      status: ARC2_DELIVERY_REVIEW_REQUIRED,
      negative_control_hmac_sha256: control.record_hmac_sha256,
      review_required_at: control.required_at,
    };
    try {
      entry = await replaceIndex(store, key, entry, value);
      return Object.freeze({ idempotent_replay: false });
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 3) throw error;
      entry = await readIndexEntry(store, key);
    }
  }
  throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_CONFLICT');
}

async function deleteChannelCapsules(vaultStore, context, env) {
  const bindings = [
    { job_kind: context.kind, job_key: context.handoff_id },
    { job_kind: context.kind, job_key: `attempt-context:${context.attempt_hmac_sha256}` },
    { job_kind: context.kind, job_key: `attempt-acceptance:${context.attempt_hmac_sha256}` },
  ];
  if (context.kind === 'claim_invitation') {
    bindings.push({ job_kind: 'final_delivery', job_key: context.handoff_id });
  }
  let deleted = 0;
  for (const binding of bindings) {
    const result = await deleteEmailRecipientCapsule(vaultStore, binding, env);
    if (result.deleted) deleted += 1;
  }
  return deleted;
}

export async function assertArc2EmailNegativeStateAllows(store, handoffId, kind,
  env = process.env) {
  if (!HEX_64.test(String(handoffId || ''))) {
    throw new TypeError('ARC2 email negative-state handoff id is invalid.');
  }
  const flag = kindFlag(kind);
  const entry = await store.getWithMetadata(controlKey(handoffId, kind),
    { type: 'json', consistency: 'strong' });
  if (!entry && env[flag] !== 'true') {
    return Object.freeze({ enabled: false, allowed: true });
  }
  const secretValue = env[flag] === 'true'
    ? requireForKind(kind, env)
    : resolvedSecret(env);
  if (!entry) return Object.freeze({ enabled: true, allowed: true });
  const control = validateControl(entry.data, secretValue);
  if (control.handoff_id !== handoffId || control.job_kind !== kind) {
    throw new Error('ARC2_EMAIL_NEGATIVE_CONTROL_CONFLICT');
  }
  throw new Error(kind === 'claim_invitation'
    ? 'ARC2_CLAIM_EMAIL_REVIEW_REQUIRED'
    : 'ARC2_DELIVERY_REVIEW_REQUIRED');
}

export async function persistArc2NegativeEmailState(stores, rawContext, rawEvent,
  env = process.env, adapters = {}) {
  const context = normalizedContext(rawContext);
  const event = normalizedEvent(rawEvent, context.kind);
  if (event.attempt_hmac_sha256 !== context.attempt_hmac_sha256) {
    throw new Error('ARC2_EMAIL_NEGATIVE_EVENT_BINDING_INVALID');
  }
  if (!stores?.ledger || !stores?.vault) {
    throw new TypeError('ARC2 email negative-state stores are invalid.');
  }
  const secretValue = requireForKind(context.kind, env);
  const now = new Date((adapters.clock || (() => new Date()))());
  if (!Number.isFinite(now.getTime())) throw new TypeError('ARC2 email negative-state clock is invalid.');

  // Persist the fail-closed state before any best-effort cleanup. A crash at
  // any later point leaves claim/final authority blocked and a retry converges.
  await ensureAttemptBinding(stores.ledger, context, secretValue, now);
  const eventResult = await ensureEvent(stores.ledger, context, event, secretValue, now);
  const controlResult = await ensureControl(stores.ledger, context, eventResult.value, secretValue);

  // Every negative event gets its own local, PII-free alert, including a
  // later complaint that supersedes an earlier bounce.
  const alert = await ensureLocalAlert(stores.ledger, context, eventResult.value, secretValue, now);
  const remediated = await readRemediation(stores.ledger, controlResult.value, context, secretValue);
  if (remediated) {
    return Object.freeze({
      state: reviewState(context.kind),
      idempotent_replay: !eventResult.created,
      control_created: false,
      bearer_rotated: false,
      outbox_marked: context.kind === 'final_delivery',
      local_alert_queued: true,
      deleted_capsules: 0,
    });
  }

  let bearer = null;
  let outbox = null;
  if (context.kind === 'claim_invitation') {
    bearer = await revokeClaimBearer(stores.ledger, context.handoff_id, env, now);
  } else {
    outbox = await markFinalOutboxReviewRequired(stores.ledger, context, controlResult.value);
  }
  const deletedCapsules = await deleteChannelCapsules(stores.vault, context, env);
  await ensureRemediation(stores.ledger, controlResult.value, context, secretValue, now);
  return Object.freeze({
    state: reviewState(context.kind),
    idempotent_replay: !eventResult.created,
    control_created: controlResult.created,
    bearer_rotated: bearer?.rotated === true,
    outbox_marked: outbox !== null,
    local_alert_queued: true,
    deleted_capsules: deletedCapsules,
  });
}

export const arc2NegativeEmailEventTypes = Object.freeze([...NEGATIVE_TYPES]);
