import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const OPERATIONS_ALERT_DELIVERY_STORE = 'arc-operations-alert-delivery';
export const OPERATIONS_ALERT_DELIVERY_ENABLED_ENV = 'ARC_OPERATIONS_ALERT_DELIVERY_ENABLED';
export const OPERATIONS_ALERT_DELIVERY_HMAC_SECRET_ENV = 'ARC_OPERATIONS_ALERT_DELIVERY_HMAC_SECRET';
export const OPERATIONS_ALERT_DELIVERY_BEARER_ENV = 'ARC_OPERATIONS_ALERT_DELIVERY_BEARER';
export const OPERATIONS_ALERT_RECIPIENT_ENV = 'ARC_OPERATIONS_ALERT_RECIPIENT_EMAIL';
export const OPERATIONS_ALERT_PROVIDER_ENV = 'ARC_OPERATIONS_ALERT_EMAIL_PROVIDER';
export const OPERATIONS_ALERT_SENDER_ENV = 'ARC_OPERATIONS_ALERT_SENDER';

export const OPERATIONS_ALERT_DELIVERY_SCHEMA = 'arc-operations-alert-delivery-v1';
export const OPERATIONS_ALERT_PROVIDER_EVENT_SCHEMA = 'arc-operations-alert-provider-event-v1';

const ALERT_SCHEMA = 'arc-operational-alert-v1';
const DELIVERY_KEY_PREFIX = 'deliveries/';
const DELIVERY_KEY_DOMAIN = 'arc-operations-alert-delivery-id-v1\n';
const DELIVERY_SIGNATURE_DOMAIN = 'arc-operations-alert-delivery-signature-v1\n';
const PROVIDER_IDEMPOTENCY_DOMAIN = 'arc-operations-alert-provider-idempotency-v1\n';
const LEASE_DOMAIN = 'arc-operations-alert-delivery-lease-v1\n';
const WORKER_LEASE_TOKEN_DOMAIN = 'arc-operations-alert-worker-lease-token-v1\n';
const PROVIDER_VALUE_DOMAIN = 'arc-operations-alert-provider-value-v1\n';
const RECEIPT_DOMAIN = 'arc-operations-alert-delivery-receipt-v1\n';
const HEX_64 = /^[a-f0-9]{64}$/;
const TOKEN = /^[A-Za-z0-9_-]{24,192}$/;
const PROVIDER = /^[a-z0-9][a-z0-9_.-]{1,63}$/;
const CATEGORY = /^[a-z0-9][a-z0-9-]{1,63}$/;
const DETAIL = /^[a-z0-9][a-z0-9-]{1,127}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_ALERT_SCAN = 1_000;
const LEASE_MS = 10 * 60_000;

const DELIVERY_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'delivery_hmac_sha256', 'alert_condition_hmac_sha256',
  'alert_category', 'alert_severity', 'alert_detail_code', 'alert_detected_at', 'provider', 'state',
  'attempt_count', 'lease_hmac_sha256', 'lease_expires_at', 'provider_message_id_hmac_sha256',
  'provider_event_id_hmac_sha256', 'provider_event_type', 'delivered_at', 'receipt_sha256',
  'created_at', 'updated_at', 'record_hmac_sha256',
]);

function byteLength(value) {
  return Buffer.byteLength(String(value || ''), 'utf8');
}

function validSecret(value) {
  return typeof value === 'string' && byteLength(value) >= 32 && byteLength(value) <= 256;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const output = JSON.stringify(value);
  if (output === undefined) throw new TypeError('Canonical JSON does not support undefined.');
  return output;
}

function hmac(secret, value) {
  return createHmac('sha256', secret).update(value).digest('hex');
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function exactKeys(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}

function iso(value, label) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new TypeError(`${label} is invalid.`);
  }
  return parsed;
}

function nowDate(value) {
  const result = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(result.getTime())) throw new TypeError('Operations alert clock is invalid.');
  return result;
}

function unsignedDelivery(record) {
  const { record_hmac_sha256: ignored, ...unsigned } = record;
  return unsigned;
}

function signDelivery(record, env) {
  const unsigned = unsignedDelivery(record);
  return {
    ...unsigned,
    record_hmac_sha256: hmac(env[OPERATIONS_ALERT_DELIVERY_HMAC_SECRET_ENV],
      DELIVERY_SIGNATURE_DOMAIN + canonicalJson(unsigned)),
  };
}

function validateDelivery(record, env) {
  if (!exactKeys(record, DELIVERY_FIELDS) || record.schema !== OPERATIONS_ALERT_DELIVERY_SCHEMA ||
      record.version !== 1 || !Number.isSafeInteger(record.record_revision) || record.record_revision < 1 ||
      !HEX_64.test(record.delivery_hmac_sha256) || !HEX_64.test(record.alert_condition_hmac_sha256) ||
      !CATEGORY.test(record.alert_category) || !['high', 'critical'].includes(record.alert_severity) ||
      !DETAIL.test(record.alert_detail_code) || !PROVIDER.test(record.provider) ||
      !['PENDING', 'CLAIMED', 'DELIVERED'].includes(record.state) ||
      !Number.isSafeInteger(record.attempt_count) || record.attempt_count < 0 || record.attempt_count > 10) {
    throw new TypeError('Operations alert delivery record is invalid.');
  }
  iso(record.alert_detected_at, 'Operations alert detected timestamp');
  iso(record.created_at, 'Operations alert created timestamp');
  iso(record.updated_at, 'Operations alert updated timestamp');
  const nullableHex = ['lease_hmac_sha256', 'provider_message_id_hmac_sha256',
    'provider_event_id_hmac_sha256', 'receipt_sha256'];
  if (nullableHex.some((name) => record[name] !== null && !HEX_64.test(record[name]))) {
    throw new TypeError('Operations alert delivery digest is invalid.');
  }
  for (const name of ['lease_expires_at', 'delivered_at']) {
    if (record[name] !== null) iso(record[name], `Operations alert ${name}`);
  }
  if (record.provider_event_type !== null && record.provider_event_type !== 'email.delivered') {
    throw new TypeError('Operations alert provider event type is invalid.');
  }
  if (record.state === 'PENDING' && (record.attempt_count !== 0 || record.lease_hmac_sha256 !== null ||
      record.lease_expires_at !== null || record.provider_message_id_hmac_sha256 !== null ||
      record.provider_event_id_hmac_sha256 !== null || record.provider_event_type !== null ||
      record.delivered_at !== null || record.receipt_sha256 !== null)) {
    throw new TypeError('Operations alert pending state is invalid.');
  }
  if (record.state === 'CLAIMED' && (record.attempt_count < 1 || !HEX_64.test(record.lease_hmac_sha256) ||
      record.lease_expires_at === null || record.provider_message_id_hmac_sha256 !== null ||
      record.provider_event_id_hmac_sha256 !== null || record.provider_event_type !== null ||
      record.delivered_at !== null || record.receipt_sha256 !== null)) {
    throw new TypeError('Operations alert claimed state is invalid.');
  }
  if (record.state === 'DELIVERED' && (record.attempt_count < 1 || record.lease_hmac_sha256 !== null ||
      record.lease_expires_at !== null || !HEX_64.test(record.provider_message_id_hmac_sha256) ||
      !HEX_64.test(record.provider_event_id_hmac_sha256) || record.provider_event_type !== 'email.delivered' ||
      record.delivered_at === null || !HEX_64.test(record.receipt_sha256))) {
    throw new TypeError('Operations alert delivered state is invalid.');
  }
  const expected = hmac(env[OPERATIONS_ALERT_DELIVERY_HMAC_SECRET_ENV],
    DELIVERY_SIGNATURE_DOMAIN + canonicalJson(unsignedDelivery(record)));
  if (!HEX_64.test(record.record_hmac_sha256) || !safeEqual(record.record_hmac_sha256, expected)) {
    throw new Error('ARC_OPERATIONS_ALERT_DELIVERY_SIGNATURE_INVALID');
  }
  return record;
}

function validateAlert(value) {
  const fields = ['schema', 'status', 'category', 'severity', 'handoff_id', 'subject_hmac_sha256',
    'condition_hmac_sha256', 'detail_code', 'detected_at', 'delivery_status', 'contains_customer_data'];
  if (!exactKeys(value, fields) || value.schema !== ALERT_SCHEMA || value.status !== 'OPEN' ||
      !CATEGORY.test(value.category) || !['high', 'critical'].includes(value.severity) ||
      (value.handoff_id !== null && !HEX_64.test(value.handoff_id)) ||
      !HEX_64.test(value.subject_hmac_sha256) || !HEX_64.test(value.condition_hmac_sha256) ||
      !DETAIL.test(value.detail_code) || value.delivery_status !== 'PENDING' ||
      value.contains_customer_data !== false) {
    throw new TypeError('Operations alert record is invalid.');
  }
  iso(value.detected_at, 'Operations alert detected timestamp');
  return value;
}

function deliveryId(conditionHmac, env) {
  return hmac(env[OPERATIONS_ALERT_DELIVERY_HMAC_SECRET_ENV], DELIVERY_KEY_DOMAIN + conditionHmac);
}

function deliveryKey(id) {
  return `${DELIVERY_KEY_PREFIX}${id}`;
}

function leaseHmac(deliveryHmac, leaseToken, env) {
  return hmac(env[OPERATIONS_ALERT_DELIVERY_HMAC_SECRET_ENV],
    `${LEASE_DOMAIN}${deliveryHmac}\n${leaseToken}`);
}

function providerValueHmac(kind, value, env) {
  return hmac(env[OPERATIONS_ALERT_DELIVERY_HMAC_SECRET_ENV],
    `${PROVIDER_VALUE_DOMAIN}${kind}\n${value}`);
}

function deliveryPayload(record, leaseToken, env) {
  const providerIdempotencyKey = hmac(env[OPERATIONS_ALERT_DELIVERY_HMAC_SECRET_ENV],
    PROVIDER_IDEMPOTENCY_DOMAIN + record.delivery_hmac_sha256);
  return Object.freeze({
    status: 'OPERATIONS_ALERT_SEND_AUTHORIZED',
    send_alert_email: true,
    delivery_hmac_sha256: record.delivery_hmac_sha256,
    provider: record.provider,
    provider_idempotency_key: providerIdempotencyKey,
    lease_token_private: leaseToken,
    recipient_email_private: env[OPERATIONS_ALERT_RECIPIENT_ENV],
    sender_private: env[OPERATIONS_ALERT_SENDER_ENV],
    email_subject: `[ARC ${record.alert_severity.toUpperCase()}] ${record.alert_category}`,
    email_text_body: `ARC detected ${record.alert_detail_code}. Detected: ${record.alert_detected_at}. Review the operations dashboard before retrying automation.`,
    lease_expires_at: record.lease_expires_at,
  });
}

export function operationsAlertWorkerLeaseToken(deliveryHmacSha256, env = process.env) {
  if (!operationsAlertDeliveryConfiguration(env).enabled) {
    throw new Error('ARC_OPERATIONS_ALERT_DELIVERY_DISABLED');
  }
  if (!HEX_64.test(String(deliveryHmacSha256 || ''))) {
    throw new TypeError('Operations alert delivery HMAC is invalid.');
  }
  // The secret-derived capability is stable for an exact delivery retry but
  // isolated per alert. Leaking one worker response cannot authorize a later
  // delivery, and plaintext capabilities are never persisted.
  return hmac(env[OPERATIONS_ALERT_DELIVERY_HMAC_SECRET_ENV],
    WORKER_LEASE_TOKEN_DOMAIN + canonicalJson({
      delivery_hmac_sha256: deliveryHmacSha256,
      provider: env[OPERATIONS_ALERT_PROVIDER_ENV],
    }));
}

export function operationsAlertDeliveryConfiguration(env = process.env) {
  const names = [OPERATIONS_ALERT_DELIVERY_HMAC_SECRET_ENV, OPERATIONS_ALERT_DELIVERY_BEARER_ENV];
  const secrets = names.map((name) => env[name]).filter(validSecret);
  const otherSecrets = Object.entries(env).filter(([name]) => /(?:_SECRET|_BEARER|_TOKEN|_KEY)$/.test(name) &&
    !names.includes(name)).map(([, value]) => value).filter(validSecret);
  const secretsValid = secrets.length === names.length && new Set(secrets).size === secrets.length &&
    !secrets.some((secret) => otherSecrets.includes(secret));
  const provider = String(env[OPERATIONS_ALERT_PROVIDER_ENV] || '');
  const sender = String(env[OPERATIONS_ALERT_SENDER_ENV] || '');
  const recipient = String(env[OPERATIONS_ALERT_RECIPIENT_ENV] || '').toLowerCase();
  return Object.freeze({
    enabled: env[OPERATIONS_ALERT_DELIVERY_ENABLED_ENV] === 'true' && secretsValid &&
      PROVIDER.test(provider) && EMAIL.test(sender) && EMAIL.test(recipient),
    secrets_valid: secretsValid,
    provider,
    sender,
    recipient,
  });
}

export function authenticateOperationsAlertWorker(request, env = process.env) {
  const configuration = operationsAlertDeliveryConfiguration(env);
  if (!configuration.enabled) return false;
  const authorization = request.headers.get('authorization') || '';
  const match = authorization.match(/^Bearer ([A-Za-z0-9_-]{24,192})$/);
  return Boolean(match && safeEqual(match[1], env[OPERATIONS_ALERT_DELIVERY_BEARER_ENV]));
}

async function readDelivery(store, id, env) {
  const entry = await store.getWithMetadata(deliveryKey(id), { type: 'json', consistency: 'strong' });
  return entry ? { record: validateDelivery(entry.data, env), etag: entry.etag } : null;
}

async function ensurePendingDelivery(deliveryStore, alert, env, now) {
  const id = deliveryId(alert.condition_hmac_sha256, env);
  const existing = await readDelivery(deliveryStore, id, env);
  if (existing) return existing;
  const stamp = now.toISOString();
  const pending = signDelivery({
    schema: OPERATIONS_ALERT_DELIVERY_SCHEMA,
    version: 1,
    record_revision: 1,
    delivery_hmac_sha256: id,
    alert_condition_hmac_sha256: alert.condition_hmac_sha256,
    alert_category: alert.category,
    alert_severity: alert.severity,
    alert_detail_code: alert.detail_code,
    alert_detected_at: alert.detected_at,
    provider: env[OPERATIONS_ALERT_PROVIDER_ENV],
    state: 'PENDING',
    attempt_count: 0,
    lease_hmac_sha256: null,
    lease_expires_at: null,
    provider_message_id_hmac_sha256: null,
    provider_event_id_hmac_sha256: null,
    provider_event_type: null,
    delivered_at: null,
    receipt_sha256: null,
    created_at: stamp,
    updated_at: stamp,
    record_hmac_sha256: '',
  }, env);
  const result = await deliveryStore.setJSON(deliveryKey(id), pending, { onlyIfNew: true });
  if (result?.modified) return readDelivery(deliveryStore, id, env);
  const raced = await readDelivery(deliveryStore, id, env);
  if (!raced || raced.record.alert_condition_hmac_sha256 !== alert.condition_hmac_sha256) {
    throw new Error('ARC_OPERATIONS_ALERT_DELIVERY_CONFLICT');
  }
  return raced;
}

async function claimDelivery(deliveryStore, entry, leaseToken, env, now) {
  const resolvedLeaseToken = leaseToken === undefined
    ? operationsAlertWorkerLeaseToken(entry.record.delivery_hmac_sha256, env)
    : leaseToken;
  if (!TOKEN.test(resolvedLeaseToken)) throw new TypeError('Operations alert lease token is invalid.');
  const expired = entry.record.state === 'CLAIMED' &&
    Date.parse(entry.record.lease_expires_at) <= now.getTime();
  if (entry.record.state === 'DELIVERED') return null;
  if (entry.record.state === 'CLAIMED' && !expired) {
    return safeEqual(entry.record.lease_hmac_sha256,
      leaseHmac(entry.record.delivery_hmac_sha256, resolvedLeaseToken, env))
      ? deliveryPayload(entry.record, resolvedLeaseToken, env)
      : null;
  }
  const claimed = signDelivery({
    ...entry.record,
    record_revision: entry.record.record_revision + 1,
    state: 'CLAIMED',
    attempt_count: entry.record.attempt_count + 1,
    lease_hmac_sha256: leaseHmac(entry.record.delivery_hmac_sha256, resolvedLeaseToken, env),
    lease_expires_at: new Date(now.getTime() + LEASE_MS).toISOString(),
    updated_at: now.toISOString(),
  }, env);
  const replaced = await deliveryStore.setJSON(deliveryKey(entry.record.delivery_hmac_sha256), claimed,
    { onlyIfMatch: entry.etag });
  if (!replaced?.modified) {
    const current = await readDelivery(deliveryStore, entry.record.delivery_hmac_sha256, env);
    if (current?.record.state === 'CLAIMED' &&
        Date.parse(current.record.lease_expires_at) > now.getTime() &&
        safeEqual(current.record.lease_hmac_sha256,
          leaseHmac(current.record.delivery_hmac_sha256, resolvedLeaseToken, env))) {
      return deliveryPayload(current.record, resolvedLeaseToken, env);
    }
    return null;
  }
  return deliveryPayload(claimed, resolvedLeaseToken, env);
}

export async function claimNextOperationsAlert(alertStore, deliveryStore, env = process.env, options = {}) {
  if (!operationsAlertDeliveryConfiguration(env).enabled) {
    throw new Error('ARC_OPERATIONS_ALERT_DELIVERY_DISABLED');
  }
  const now = nowDate((options.clock || (() => new Date()))());
  const leaseToken = options.leaseToken;
  const iterable = alertStore.list({ prefix: 'alerts/', paginate: true });
  if (!iterable || typeof iterable[Symbol.asyncIterator] !== 'function') {
    throw new Error('ARC_OPERATIONS_ALERT_LIST_UNAVAILABLE');
  }
  let scanned = 0;
  for await (const page of iterable) {
    if (!page || !Array.isArray(page.blobs)) throw new Error('ARC_OPERATIONS_ALERT_LIST_UNAVAILABLE');
    for (const blob of page.blobs) {
      scanned += 1;
      if (scanned > MAX_ALERT_SCAN) return Object.freeze({ status: 'OPERATIONS_ALERT_SCAN_LIMIT', send_alert_email: false });
      const source = await alertStore.getWithMetadata(blob.key, { type: 'json', consistency: 'strong' });
      if (!source) continue;
      const alert = validateAlert(source.data);
      const entry = await ensurePendingDelivery(deliveryStore, alert, env, now);
      const claimed = await claimDelivery(deliveryStore, entry, leaseToken, env, now);
      if (claimed) return claimed;
    }
  }
  return Object.freeze({ status: 'NO_PENDING_OPERATIONS_ALERTS', send_alert_email: false });
}

export async function acknowledgeOperationsAlertDelivery(deliveryStore, input, env = process.env, options = {}) {
  if (!operationsAlertDeliveryConfiguration(env).enabled) {
    throw new Error('ARC_OPERATIONS_ALERT_DELIVERY_DISABLED');
  }
  const now = nowDate((options.clock || (() => new Date()))());
  if (!exactKeys(input, ['delivery_hmac_sha256', 'lease_token', 'provider', 'provider_message_id',
    'provider_event_id', 'provider_event_type', 'delivered_at']) ||
      !HEX_64.test(String(input.delivery_hmac_sha256 || '')) || !TOKEN.test(String(input.lease_token || '')) ||
      input.provider !== env[OPERATIONS_ALERT_PROVIDER_ENV] || input.provider_event_type !== 'email.delivered' ||
      typeof input.provider_message_id !== 'string' || byteLength(input.provider_message_id) < 1 ||
      byteLength(input.provider_message_id) > 256 || typeof input.provider_event_id !== 'string' ||
      byteLength(input.provider_event_id) < 1 || byteLength(input.provider_event_id) > 256) {
    throw new TypeError('Operations alert delivery acknowledgement is invalid.');
  }
  const deliveredMs = iso(input.delivered_at, 'Operations alert delivered timestamp');
  if (deliveredMs > now.getTime() + 60_000 || now.getTime() - deliveredMs > 24 * 60 * 60_000) {
    throw new TypeError('Operations alert delivery acknowledgement is stale.');
  }
  const entry = await readDelivery(deliveryStore, input.delivery_hmac_sha256, env);
  if (!entry) throw new Error('ARC_OPERATIONS_ALERT_DELIVERY_NOT_FOUND');
  if (entry.record.state === 'DELIVERED') {
    const messageHmac = providerValueHmac('message', input.provider_message_id, env);
    const eventHmac = providerValueHmac('event', input.provider_event_id, env);
    if (entry.record.provider_message_id_hmac_sha256 !== messageHmac ||
        entry.record.provider_event_id_hmac_sha256 !== eventHmac ||
        entry.record.delivered_at !== input.delivered_at) {
      throw new Error('ARC_OPERATIONS_ALERT_DELIVERY_CONFLICT');
    }
    return Object.freeze({ status: 'OPERATIONS_ALERT_DELIVERY_ALREADY_RECORDED', delivered: true,
      receipt_sha256: entry.record.receipt_sha256 });
  }
  if (entry.record.state !== 'CLAIMED' || Date.parse(entry.record.lease_expires_at) <= now.getTime() ||
      !safeEqual(entry.record.lease_hmac_sha256,
        leaseHmac(entry.record.delivery_hmac_sha256, input.lease_token, env))) {
    throw new Error('ARC_OPERATIONS_ALERT_DELIVERY_LEASE_INVALID');
  }
  const providerMessageHmac = providerValueHmac('message', input.provider_message_id, env);
  const providerEventHmac = providerValueHmac('event', input.provider_event_id, env);
  const receiptCore = {
    schema: OPERATIONS_ALERT_PROVIDER_EVENT_SCHEMA,
    version: 1,
    delivery_hmac_sha256: entry.record.delivery_hmac_sha256,
    provider: input.provider,
    provider_message_id_hmac_sha256: providerMessageHmac,
    provider_event_id_hmac_sha256: providerEventHmac,
    provider_event_type: input.provider_event_type,
    delivered_at: input.delivered_at,
  };
  const receiptSha = sha256(`${RECEIPT_DOMAIN}${canonicalJson(receiptCore)}`);
  const delivered = signDelivery({
    ...entry.record,
    record_revision: entry.record.record_revision + 1,
    state: 'DELIVERED',
    lease_hmac_sha256: null,
    lease_expires_at: null,
    provider_message_id_hmac_sha256: providerMessageHmac,
    provider_event_id_hmac_sha256: providerEventHmac,
    provider_event_type: input.provider_event_type,
    delivered_at: input.delivered_at,
    receipt_sha256: receiptSha,
    updated_at: now.toISOString(),
  }, env);
  const replaced = await deliveryStore.setJSON(deliveryKey(entry.record.delivery_hmac_sha256), delivered,
    { onlyIfMatch: entry.etag });
  if (!replaced?.modified) throw new Error('ARC_OPERATIONS_ALERT_DELIVERY_CONTENTION');
  return Object.freeze({ status: 'OPERATIONS_ALERT_DELIVERED', delivered: true, receipt_sha256: receiptSha });
}

export async function readOperationsAlertDelivery(deliveryStore, deliveryHmac, env = process.env) {
  if (!HEX_64.test(String(deliveryHmac || ''))) throw new TypeError('Operations alert delivery ID is invalid.');
  return readDelivery(deliveryStore, deliveryHmac, env);
}
