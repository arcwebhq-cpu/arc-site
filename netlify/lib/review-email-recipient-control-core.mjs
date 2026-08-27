import { createHmac, timingSafeEqual } from 'node:crypto';

export const REVIEW_EMAIL_RECIPIENT_CONTROL_SCHEMA =
  'arc-preview-review-email-recipient-control-v1';
export const REVIEW_EMAIL_RECIPIENT_AUTHORITY_LEASE_MS = 60_000;

const CONTROL_ID_PREFIX = 'arc-preview-review-email-recipient-control-id-v1\n';
const CONTROL_SIGNATURE_PREFIX = 'arc-preview-review-email-recipient-control-signature-v1\n';
const AUTHORITY_OPERATION_PREFIX = 'arc-preview-review-email-recipient-authority-operation-v1\n';
const HEX_64 = /^[a-f0-9]{64}$/;
const FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'state', 'recipient_control_hmac_sha256',
  'recipient_email_sha256', 'authority_operation_hmac_sha256', 'authority_expires_at',
  'suppression_receipt_sha256', 'suppression_status', 'suppressed_at',
  'source_invite_hmac_sha256', 'source_outbox_hmac_sha256', 'record_hmac_sha256',
]);

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const output = JSON.stringify(value);
  if (output === undefined) throw new TypeError('Canonical JSON does not support undefined.');
  return output;
}

function hmacHex(secret, value) {
  return createHmac('sha256', secret).update(value).digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw new TypeError(`${label} fields are invalid.`);
  }
}

function hex64(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function isoTimestamp(value, label) {
  if (typeof value !== 'string' || value.length < 20 || value.length > 32 ||
      new Date(value).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return value;
}

function nowDate(value) {
  const now = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(now.getTime())) throw new TypeError('Review email recipient control clock is invalid.');
  return now;
}

function controlSecret(env) {
  const secret = env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET;
  const distinct = [
    env.ARC_REVIEW_INVITE_HMAC_SECRET,
    env.ARC_REVIEW_SESSION_HMAC_SECRET,
    env.ARC_REVIEW_RECORD_HMAC_SECRET,
    env.ARC_REVIEW_DECISION_HMAC_SECRET,
    env.ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET,
  ];
  if (env.ARC_REVIEW_EMAIL_OUTBOX_ENABLED !== 'true' || typeof secret !== 'string' ||
      secret.length < 32 || secret.length > 512 || distinct.includes(secret)) {
    throw new Error('ARC_REVIEW_EMAIL_OUTBOX_DISABLED');
  }
  return secret;
}

function controlHmac(recipientEmailSha256, env) {
  return hmacHex(controlSecret(env), CONTROL_ID_PREFIX +
    hex64(recipientEmailSha256, 'Review email recipient digest'));
}

export function reviewEmailRecipientControlKey(recipientControlHmacSha256) {
  return `review-email-recipient-control/${hex64(recipientControlHmacSha256,
    'Review email recipient control HMAC')}`;
}

function unsignedRecord(record) {
  const { record_hmac_sha256: _signature, ...unsigned } = record;
  return unsigned;
}

function signRecord(record, env) {
  const unsigned = unsignedRecord(record);
  return {
    ...unsigned,
    record_hmac_sha256: hmacHex(controlSecret(env), CONTROL_SIGNATURE_PREFIX + canonicalJson(unsigned)),
  };
}

function suppressionPriority(status) {
  return status === 'complained' ? 2 : status === 'bounced' ? 1 : 0;
}

function validateRecord(record, env) {
  exactKeys(record, FIELDS, 'Review email recipient control');
  if (record.schema !== REVIEW_EMAIL_RECIPIENT_CONTROL_SCHEMA || record.version !== 1 ||
      !Number.isSafeInteger(record.record_revision) || record.record_revision < 1 ||
      !['ACTIVE', 'AUTHORIZING', 'SUPPRESSED'].includes(record.state)) {
    throw new TypeError('Review email recipient control is invalid.');
  }
  hex64(record.recipient_control_hmac_sha256, 'Review email recipient control HMAC');
  hex64(record.recipient_email_sha256, 'Review email recipient digest');
  if (record.recipient_control_hmac_sha256 !== controlHmac(record.recipient_email_sha256, env)) {
    throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_CONTROL_BINDING_INVALID');
  }
  if (record.state === 'ACTIVE') {
    if ([record.authority_operation_hmac_sha256, record.authority_expires_at,
      record.suppression_receipt_sha256, record.suppression_status, record.suppressed_at,
      record.source_invite_hmac_sha256, record.source_outbox_hmac_sha256].some(value => value !== null)) {
      throw new TypeError('Review email recipient active control is invalid.');
    }
  } else if (record.state === 'AUTHORIZING') {
    hex64(record.authority_operation_hmac_sha256, 'Review email recipient authority operation');
    isoTimestamp(record.authority_expires_at, 'Review email recipient authority expiration');
    const suppressionValues = [record.suppression_receipt_sha256, record.suppression_status,
      record.suppressed_at, record.source_invite_hmac_sha256, record.source_outbox_hmac_sha256];
    if (suppressionValues.some(value => value !== null)) {
      if (suppressionValues.some(value => value === null) ||
          !['bounced', 'complained'].includes(record.suppression_status)) {
        throw new TypeError('Review email recipient authorizing control is invalid.');
      }
      hex64(record.suppression_receipt_sha256, 'Review email pending suppression receipt');
      isoTimestamp(record.suppressed_at, 'Review email pending suppression timestamp');
      hex64(record.source_invite_hmac_sha256, 'Review email pending suppression source invite');
      hex64(record.source_outbox_hmac_sha256, 'Review email pending suppression source outbox');
    }
  } else {
    if (record.authority_operation_hmac_sha256 !== null || record.authority_expires_at !== null ||
        !['bounced', 'complained'].includes(record.suppression_status)) {
      throw new TypeError('Review email recipient suppressed control is invalid.');
    }
    hex64(record.suppression_receipt_sha256, 'Review email suppression receipt');
    isoTimestamp(record.suppressed_at, 'Review email suppression timestamp');
    hex64(record.source_invite_hmac_sha256, 'Review email suppression source invite');
    hex64(record.source_outbox_hmac_sha256, 'Review email suppression source outbox');
  }
  hex64(record.record_hmac_sha256, 'Review email recipient control signature');
  const expected = hmacHex(controlSecret(env), CONTROL_SIGNATURE_PREFIX + canonicalJson(unsignedRecord(record)));
  if (!safeEqual(expected, record.record_hmac_sha256)) {
    throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_CONTROL_SIGNATURE_INVALID');
  }
  return record;
}

async function readEntry(store, recipientEmailSha256, env) {
  const id = controlHmac(recipientEmailSha256, env);
  const entry = await store.getWithMetadata(reviewEmailRecipientControlKey(id),
    { type: 'json', consistency: 'strong' });
  return entry ? { record: validateRecord(entry.data, env), etag: entry.etag } : null;
}

export async function readReviewEmailRecipientControl(store, recipientEmailSha256, env = process.env) {
  return readEntry(store, recipientEmailSha256, env);
}

export async function ensureReviewEmailRecipientControl(store, recipientEmailSha256,
  env = process.env, nowValue = new Date()) {
  const recipient = hex64(recipientEmailSha256, 'Review email recipient digest');
  const existing = await readEntry(store, recipient, env);
  if (existing) return existing;
  const now = nowDate(nowValue);
  const record = signRecord({
    schema: REVIEW_EMAIL_RECIPIENT_CONTROL_SCHEMA,
    version: 1,
    record_revision: 1,
    state: 'ACTIVE',
    recipient_control_hmac_sha256: controlHmac(recipient, env),
    recipient_email_sha256: recipient,
    authority_operation_hmac_sha256: null,
    authority_expires_at: null,
    suppression_receipt_sha256: null,
    suppression_status: null,
    suppressed_at: null,
    source_invite_hmac_sha256: null,
    source_outbox_hmac_sha256: null,
  }, env);
  const created = await store.setJSON(reviewEmailRecipientControlKey(record.recipient_control_hmac_sha256),
    record, { onlyIfNew: true });
  if (created?.modified) return { record, etag: created.etag };
  const raced = await readEntry(store, recipient, env);
  if (!raced) throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
  void now;
  return raced;
}

export async function acquireReviewEmailRecipientAuthority(store, recipientEmailSha256, operationReference,
  env = process.env, nowValue = new Date()) {
  const now = nowDate(nowValue);
  if (typeof operationReference !== 'string' || operationReference.length < 1 ||
      operationReference.length > 256 || /[\u0000-\u001f\u007f]/.test(operationReference)) {
    throw new TypeError('Review email recipient authority reference is invalid.');
  }
  const recipient = hex64(recipientEmailSha256, 'Review email recipient digest');
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const entry = await ensureReviewEmailRecipientControl(store, recipient, env, now);
    if (entry.record.state === 'SUPPRESSED') throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_SUPPRESSED');
    if (entry.record.state === 'AUTHORIZING' && entry.record.suppression_receipt_sha256 !== null) {
      if (Date.parse(entry.record.authority_expires_at) <= now.getTime()) {
        await suppressReviewEmailRecipientControl(store, {
          recipient_email_sha256: entry.record.recipient_email_sha256,
          suppression_receipt_sha256: entry.record.suppression_receipt_sha256,
          suppression_status: entry.record.suppression_status,
          suppressed_at: entry.record.suppressed_at,
          source_invite_hmac_sha256: entry.record.source_invite_hmac_sha256,
          source_outbox_hmac_sha256: entry.record.source_outbox_hmac_sha256,
        }, env, now);
      }
      throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_SUPPRESSED');
    }
    if (entry.record.state === 'AUTHORIZING' && Date.parse(entry.record.authority_expires_at) > now.getTime()) {
      throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_AUTHORITY_CONTENTION');
    }
    const operationHmac = hmacHex(controlSecret(env), AUTHORITY_OPERATION_PREFIX + operationReference + '\n' +
      now.toISOString() + '\n' + String(entry.record.record_revision + 1));
    const authorizing = signRecord({
      ...unsignedRecord(entry.record),
      record_revision: entry.record.record_revision + 1,
      state: 'AUTHORIZING',
      authority_operation_hmac_sha256: operationHmac,
      authority_expires_at: new Date(now.getTime() + REVIEW_EMAIL_RECIPIENT_AUTHORITY_LEASE_MS).toISOString(),
      suppression_receipt_sha256: null,
      suppression_status: null,
      suppressed_at: null,
      source_invite_hmac_sha256: null,
      source_outbox_hmac_sha256: null,
    }, env);
    const replaced = await store.setJSON(reviewEmailRecipientControlKey(authorizing.recipient_control_hmac_sha256),
      authorizing, { onlyIfMatch: entry.etag });
    if (replaced?.modified) return { operation_hmac_sha256: operationHmac, record: authorizing };
  }
  throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_AUTHORITY_CONTENTION');
}

export async function releaseReviewEmailRecipientAuthority(store, recipientEmailSha256, operationHmacSha256,
  env = process.env, nowValue = new Date()) {
  const now = nowDate(nowValue);
  const operation = hex64(operationHmacSha256, 'Review email recipient authority operation');
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const entry = await readEntry(store, recipientEmailSha256, env);
    if (!entry || entry.record.state !== 'AUTHORIZING' ||
        !safeEqual(entry.record.authority_operation_hmac_sha256, operation)) {
      if (entry?.record.state === 'SUPPRESSED') throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_SUPPRESSED');
      throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_AUTHORITY_LOST');
    }
    const suppressionPending = entry.record.suppression_receipt_sha256 !== null;
    const active = signRecord({
      ...unsignedRecord(entry.record),
      record_revision: entry.record.record_revision + 1,
      state: suppressionPending ? 'SUPPRESSED' : 'ACTIVE',
      authority_operation_hmac_sha256: null,
      authority_expires_at: null,
    }, env);
    const replaced = await store.setJSON(reviewEmailRecipientControlKey(active.recipient_control_hmac_sha256),
      active, { onlyIfMatch: entry.etag });
    if (replaced?.modified) {
      if (suppressionPending) throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_SUPPRESSED');
      return active;
    }
  }
  void now;
  throw new Error('ARC_REVIEW_EMAIL_RECIPIENT_AUTHORITY_CONTENTION');
}

export async function suppressReviewEmailRecipientControl(store, evidence,
  env = process.env, nowValue = new Date()) {
  exactKeys(evidence, [
    'recipient_email_sha256', 'suppression_receipt_sha256', 'suppression_status', 'suppressed_at',
    'source_invite_hmac_sha256', 'source_outbox_hmac_sha256',
  ], 'Review email recipient control suppression');
  const now = nowDate(nowValue);
  const recipient = hex64(evidence.recipient_email_sha256, 'Review email recipient digest');
  hex64(evidence.suppression_receipt_sha256, 'Review email suppression receipt');
  if (!['bounced', 'complained'].includes(evidence.suppression_status)) {
    throw new TypeError('Review email suppression status is invalid.');
  }
  isoTimestamp(evidence.suppressed_at, 'Review email suppression timestamp');
  hex64(evidence.source_invite_hmac_sha256, 'Review email suppression source invite');
  hex64(evidence.source_outbox_hmac_sha256, 'Review email suppression source outbox');
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const entry = await ensureReviewEmailRecipientControl(store, recipient, env, now);
    if (entry.record.state === 'AUTHORIZING' && Date.parse(entry.record.authority_expires_at) > now.getTime()) {
      if (entry.record.suppression_receipt_sha256 !== null &&
          suppressionPriority(evidence.suppression_status) <= suppressionPriority(entry.record.suppression_status)) {
        return { idempotent_replay: true, pending: true, record: entry.record };
      }
      const pending = signRecord({
        ...unsignedRecord(entry.record),
        record_revision: entry.record.record_revision + 1,
        suppression_receipt_sha256: evidence.suppression_receipt_sha256,
        suppression_status: evidence.suppression_status,
        suppressed_at: evidence.suppressed_at,
        source_invite_hmac_sha256: evidence.source_invite_hmac_sha256,
        source_outbox_hmac_sha256: evidence.source_outbox_hmac_sha256,
      }, env);
      const attached = await store.setJSON(
        reviewEmailRecipientControlKey(pending.recipient_control_hmac_sha256), pending,
        { onlyIfMatch: entry.etag },
      );
      if (attached?.modified) return { idempotent_replay: false, pending: true, record: pending };
      continue;
    }
    if (entry.record.state === 'SUPPRESSED' &&
        suppressionPriority(evidence.suppression_status) <= suppressionPriority(entry.record.suppression_status)) {
      return { idempotent_replay: true, pending: false, record: entry.record };
    }
    const suppressed = signRecord({
      ...unsignedRecord(entry.record),
      record_revision: entry.record.record_revision + 1,
      state: 'SUPPRESSED',
      authority_operation_hmac_sha256: null,
      authority_expires_at: null,
      suppression_receipt_sha256: evidence.suppression_receipt_sha256,
      suppression_status: evidence.suppression_status,
      suppressed_at: evidence.suppressed_at,
      source_invite_hmac_sha256: evidence.source_invite_hmac_sha256,
      source_outbox_hmac_sha256: evidence.source_outbox_hmac_sha256,
    }, env);
    const replaced = await store.setJSON(reviewEmailRecipientControlKey(suppressed.recipient_control_hmac_sha256),
      suppressed, { onlyIfMatch: entry.etag });
    if (replaced?.modified) return { idempotent_replay: false, pending: false, record: suppressed };
  }
  throw new Error('ARC_REVIEW_EMAIL_STATE_CONTENTION');
}
