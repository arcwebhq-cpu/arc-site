import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const REVIEW_STORE = 'arc-preview-reviews';
export const REVIEW_INVITE_SCHEMA = 'arc-preview-review-invite-v1';
export const REVIEW_DECISION_SCHEMA = 'arc-preview-review-decision-v1';
export const REVIEW_APPROVAL_SCHEMA = 'arc-preview-customer-approval-v1';
export const REVIEW_SESSION_SCHEMA = 'arc-preview-review-session-v1';
export const REVIEW_MAX_REVISION_ROUNDS = 2;
export const REVIEW_SESSION_TTL_SECONDS = 24 * 60 * 60;

const RECORD_SIGNATURE_PREFIX = 'arc-preview-review-record-signature-v1\n';
const INVITE_ID_PREFIX = 'arc-preview-review-invite-id-v1\n';
const SESSION_SIGNATURE_PREFIX = 'arc-preview-review-session-signature-v1\n';
const SESSION_NONCE_PREFIX = 'arc-preview-review-session-nonce-v1\n';
const DECISION_IDEMPOTENCY_PREFIX = 'arc-preview-review-decision-idempotency-v1\n';
const APPROVAL_SIGNATURE_PREFIX = 'arc-preview-customer-approval-signature-v1\n';
const CHECKOUT_IDEMPOTENCY_PREFIX = 'arc-preview-checkout-idempotency-v1\n';
const REVIEW_STATES = new Set(['OPEN', 'REVISION_REQUESTED', 'REVISION_SUPERSEDED', 'APPROVED']);
const ACTIONS = new Set(['APPROVE_AND_PAY', 'REQUEST_CHANGES']);
const HEX_40 = /^[a-f0-9]{40}$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const TOKEN = /^[A-Za-z0-9_-]{43,128}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const REPOSITORY = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const PAGE_PATHS = Object.freeze([
  'about/index.html',
  'contact/index.html',
  'index.html',
  'process/index.html',
  'services/index.html',
]);
const RECORD_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'state', 'invite_hmac_sha256', 'created_at', 'expires_at',
  'recipient_email_sha256', 'email_delivery_receipt_sha256', 'preview_url', 'preview_source_repository',
  'preview_source_commit_sha', 'preview_manifest_sha256', 'preview_content_sha256', 'brief_sha256',
  'scope_version', 'page_bindings', 'revision_round', 'prior_invite_hmac_sha256',
  'prior_preview_manifest_sha256', 'session_nonce_hmac_sha256', 'exchanged_at', 'decision',
  'successor_invite_hmac_sha256', 'record_hmac_sha256',
]);
const DECISION_FIELDS = Object.freeze([
  'schema', 'action', 'action_payload_sha256', 'idempotency_hmac_sha256', 'decided_at',
  'revision_notes', 'revision_notes_sha256', 'approval_receipt_sha256', 'approval_receipt_hmac_sha256',
  'checkout_idempotency_key_sha256',
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

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
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
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw new TypeError(`${label} fields are invalid.`);
  }
}

function isoTimestamp(value, label) {
  if (typeof value !== 'string' || value.length < 20 || value.length > 32 || new Date(value).toISOString() !== value) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function hex64(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function nullableHex64(value, label) {
  if (value === null) return null;
  return hex64(value, label);
}

function validSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}

function exactBoolean(value) {
  return value === 'true' || value === 'false';
}

function configuredOrigin(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value && !url.username && !url.password ? url.origin : null;
  } catch {
    return null;
  }
}

export function reviewPortalConfiguration(env = process.env) {
  const portalFlagValid = exactBoolean(env.ARC_REVIEW_PORTAL_ENABLED);
  const checkoutFlagValid = exactBoolean(env.ARC_REVIEW_CHECKOUT_ENABLED);
  const secrets = [
    env.ARC_REVIEW_INVITE_HMAC_SECRET,
    env.ARC_REVIEW_SESSION_HMAC_SECRET,
    env.ARC_REVIEW_RECORD_HMAC_SECRET,
    env.ARC_REVIEW_DECISION_HMAC_SECRET,
  ];
  const secretsValid = secrets.every(validSecret) && new Set(secrets).size === secrets.length;
  const previewOrigin = configuredOrigin(env.ARC_REVIEW_PREVIEW_ORIGIN);
  const checkoutOrigin = configuredOrigin(env.ARC_REVIEW_CHECKOUT_ORIGIN);
  const enabled = portalFlagValid && env.ARC_REVIEW_PORTAL_ENABLED === 'true' && secretsValid && Boolean(previewOrigin);
  return {
    checkoutEnabled: enabled && checkoutFlagValid && env.ARC_REVIEW_CHECKOUT_ENABLED === 'true' && Boolean(checkoutOrigin),
    checkoutFlagValid,
    checkoutOrigin,
    enabled,
    portalFlagValid,
    previewOrigin,
    secretsValid,
  };
}

function requirePortal(env) {
  const configuration = reviewPortalConfiguration(env);
  if (!configuration.enabled) throw new Error('ARC_REVIEW_PORTAL_DISABLED');
  return configuration;
}

function normalizePreviewUrl(value, configuration) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Preview URL is invalid.'); }
  if (url.origin !== configuration.previewOrigin || url.protocol !== 'https:' || url.username || url.password ||
      url.search || url.hash || !url.pathname.endsWith('/') || url.pathname === '/') {
    throw new TypeError('Preview URL is invalid.');
  }
  return url.href;
}

function normalizePageBindings(value) {
  if (!Array.isArray(value) || value.length !== PAGE_PATHS.length) throw new TypeError('Preview page bindings are invalid.');
  const output = value.map((entry, index) => {
    exactKeys(entry, ['path', 'sha256'], 'Preview page binding');
    if (entry.path !== PAGE_PATHS[index]) throw new TypeError('Preview page bindings are invalid.');
    return { path: entry.path, sha256: hex64(entry.sha256, 'Preview page digest') };
  });
  return output;
}

function normalizeScopeVersion(value) {
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9.-]{5,79}$/.test(value)) {
    throw new TypeError('Review scope version is invalid.');
  }
  return value;
}

function normalizeInviteInput(input, configuration) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Review invite is invalid.');
  if (!TOKEN.test(String(input.invite_token || ''))) throw new TypeError('Review invite token is invalid.');
  if (!REPOSITORY.test(String(input.preview_source_repository || ''))) throw new TypeError('Preview repository is invalid.');
  if (!HEX_40.test(String(input.preview_source_commit_sha || ''))) throw new TypeError('Preview commit is invalid.');
  const prior = input.prior_invite_hmac_sha256 === undefined || input.prior_invite_hmac_sha256 === null
    ? null : hex64(input.prior_invite_hmac_sha256, 'Prior review invite');
  return {
    invite_token: input.invite_token,
    brief_sha256: hex64(input.brief_sha256, 'Brief digest'),
    email_delivery_receipt_sha256: hex64(input.email_delivery_receipt_sha256, 'Email delivery receipt digest'),
    expires_at: isoTimestamp(input.expires_at, 'Review invite expiration'),
    page_bindings: normalizePageBindings(input.page_bindings),
    preview_content_sha256: hex64(input.preview_content_sha256, 'Preview content digest'),
    preview_manifest_sha256: hex64(input.preview_manifest_sha256, 'Preview manifest digest'),
    preview_source_commit_sha: input.preview_source_commit_sha,
    preview_source_repository: input.preview_source_repository,
    preview_url: normalizePreviewUrl(input.preview_url, configuration),
    prior_invite_hmac_sha256: prior,
    recipient_email_sha256: hex64(input.recipient_email_sha256, 'Recipient email digest'),
    scope_version: normalizeScopeVersion(input.scope_version),
  };
}

function unsignedRecord(record) {
  const { record_hmac_sha256: _signature, ...unsigned } = record;
  return unsigned;
}

function signRecord(record, env) {
  const unsigned = unsignedRecord(record);
  return {
    ...unsigned,
    record_hmac_sha256: hmacHex(env.ARC_REVIEW_RECORD_HMAC_SECRET,
      RECORD_SIGNATURE_PREFIX + canonicalJson(unsigned)),
  };
}

function validateDecision(decision, state) {
  if (decision === null) {
    if (state !== 'OPEN') throw new TypeError('Review decision state is invalid.');
    return;
  }
  exactKeys(decision, DECISION_FIELDS, 'Review decision');
  if (decision.schema !== REVIEW_DECISION_SCHEMA || !ACTIONS.has(decision.action)) throw new TypeError('Review decision is invalid.');
  hex64(decision.action_payload_sha256, 'Review action payload digest');
  hex64(decision.idempotency_hmac_sha256, 'Review idempotency digest');
  isoTimestamp(decision.decided_at, 'Review decision timestamp');
  if (decision.action === 'REQUEST_CHANGES') {
    if (typeof decision.revision_notes !== 'string' || decision.revision_notes.length < 10 ||
        decision.revision_notes.length > 4000 ||
        /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(decision.revision_notes)) {
      throw new TypeError('Revision notes are invalid.');
    }
    hex64(decision.revision_notes_sha256, 'Revision notes digest');
    if (sha256Hex(decision.revision_notes) !== decision.revision_notes_sha256) {
      throw new TypeError('Revision notes binding is invalid.');
    }
    if (decision.approval_receipt_sha256 !== null || decision.approval_receipt_hmac_sha256 !== null ||
        decision.checkout_idempotency_key_sha256 !== null || !['REVISION_REQUESTED', 'REVISION_SUPERSEDED'].includes(state)) {
      throw new TypeError('Review revision decision is invalid.');
    }
  } else {
    if (decision.revision_notes !== null || decision.revision_notes_sha256 !== null || state !== 'APPROVED') {
      throw new TypeError('Review approval decision is invalid.');
    }
    hex64(decision.approval_receipt_sha256, 'Approval receipt digest');
    hex64(decision.approval_receipt_hmac_sha256, 'Approval receipt signature');
    hex64(decision.checkout_idempotency_key_sha256, 'Checkout idempotency key digest');
  }
}

function validateReviewRecord(record, env, configuration = requirePortal(env)) {
  exactKeys(record, RECORD_FIELDS, 'Review record');
  if (record.schema !== REVIEW_INVITE_SCHEMA || record.version !== 1 || !Number.isSafeInteger(record.record_revision) ||
      record.record_revision < 1 || !REVIEW_STATES.has(record.state)) throw new TypeError('Review record is invalid.');
  hex64(record.invite_hmac_sha256, 'Review invite HMAC');
  isoTimestamp(record.created_at, 'Review creation timestamp');
  isoTimestamp(record.expires_at, 'Review expiration timestamp');
  if (Date.parse(record.expires_at) <= Date.parse(record.created_at)) throw new TypeError('Review expiration is invalid.');
  hex64(record.recipient_email_sha256, 'Recipient email digest');
  hex64(record.email_delivery_receipt_sha256, 'Email delivery receipt digest');
  normalizePreviewUrl(record.preview_url, configuration);
  if (!REPOSITORY.test(record.preview_source_repository) || !HEX_40.test(record.preview_source_commit_sha)) {
    throw new TypeError('Review source binding is invalid.');
  }
  hex64(record.preview_manifest_sha256, 'Preview manifest digest');
  hex64(record.preview_content_sha256, 'Preview content digest');
  hex64(record.brief_sha256, 'Brief digest');
  normalizeScopeVersion(record.scope_version);
  normalizePageBindings(record.page_bindings);
  if (!Number.isSafeInteger(record.revision_round) || record.revision_round < 0 ||
      record.revision_round > REVIEW_MAX_REVISION_ROUNDS) throw new TypeError('Review revision round is invalid.');
  nullableHex64(record.prior_invite_hmac_sha256, 'Prior review invite');
  nullableHex64(record.prior_preview_manifest_sha256, 'Prior preview manifest');
  if ((record.revision_round === 0) !== (record.prior_invite_hmac_sha256 === null && record.prior_preview_manifest_sha256 === null)) {
    throw new TypeError('Review revision lineage is invalid.');
  }
  nullableHex64(record.session_nonce_hmac_sha256, 'Review session nonce');
  if ((record.session_nonce_hmac_sha256 === null) !== (record.exchanged_at === null)) {
    throw new TypeError('Review exchange state is invalid.');
  }
  if (record.exchanged_at !== null) isoTimestamp(record.exchanged_at, 'Review exchange timestamp');
  nullableHex64(record.successor_invite_hmac_sha256, 'Successor review invite');
  if ((record.state === 'REVISION_SUPERSEDED') !== (record.successor_invite_hmac_sha256 !== null)) {
    throw new TypeError('Review successor state is invalid.');
  }
  validateDecision(record.decision, record.state);
  hex64(record.record_hmac_sha256, 'Review record signature');
  const expected = hmacHex(env.ARC_REVIEW_RECORD_HMAC_SECRET,
    RECORD_SIGNATURE_PREFIX + canonicalJson(unsignedRecord(record)));
  if (!safeEqual(expected, record.record_hmac_sha256)) throw new Error('ARC_REVIEW_RECORD_SIGNATURE_INVALID');
  return record;
}

export function reviewInviteKey(inviteHmac) {
  return `review-invites/${hex64(inviteHmac, 'Review invite HMAC')}`;
}

async function readInviteEntry(store, inviteHmac, env, configuration) {
  const entry = await store.getWithMetadata(reviewInviteKey(inviteHmac), { type: 'json', consistency: 'strong' });
  if (!entry) throw new Error('ARC_REVIEW_INVITE_NOT_FOUND');
  return { record: validateReviewRecord(entry.data, env, configuration), etag: entry.etag };
}

function sameIssuedInvite(left, right) {
  const ignored = new Set(['created_at', 'record_hmac_sha256']);
  const filtered = value => Object.fromEntries(Object.entries(value).filter(([key]) => !ignored.has(key)));
  return canonicalJson(filtered(left)) === canonicalJson(filtered(right));
}

export async function issueReviewInvite(store, rawInput, env = process.env, adapters = {}) {
  const configuration = requirePortal(env);
  const input = normalizeInviteInput(rawInput, configuration);
  const now = adapters.clock?.() || new Date();
  const createdAt = now.toISOString();
  if (Date.parse(input.expires_at) <= now.getTime() || Date.parse(input.expires_at) > now.getTime() + 30 * 24 * 60 * 60_000) {
    throw new TypeError('Review invite expiration is invalid.');
  }
  const inviteHmac = hmacHex(env.ARC_REVIEW_INVITE_HMAC_SECRET, INVITE_ID_PREFIX + input.invite_token);
  let revisionRound = 0;
  let priorManifest = null;
  let priorEntry = null;
  if (input.prior_invite_hmac_sha256 !== null) {
    priorEntry = await readInviteEntry(store, input.prior_invite_hmac_sha256, env, configuration);
    const prior = priorEntry.record;
    if (!['REVISION_REQUESTED', 'REVISION_SUPERSEDED'].includes(prior.state) ||
        prior.revision_round >= REVIEW_MAX_REVISION_ROUNDS ||
        prior.recipient_email_sha256 !== input.recipient_email_sha256 || prior.brief_sha256 !== input.brief_sha256 ||
        prior.scope_version !== input.scope_version || prior.preview_source_repository !== input.preview_source_repository ||
        prior.preview_manifest_sha256 === input.preview_manifest_sha256 || prior.preview_content_sha256 === input.preview_content_sha256) {
      throw new Error('ARC_REVIEW_REVISION_BINDING_INVALID');
    }
    if (prior.state === 'REVISION_SUPERSEDED' && prior.successor_invite_hmac_sha256 !== inviteHmac) {
      throw new Error('ARC_REVIEW_SUCCESSOR_CONFLICT');
    }
    revisionRound = prior.revision_round + 1;
    priorManifest = prior.preview_manifest_sha256;
  }
  const record = signRecord({
    schema: REVIEW_INVITE_SCHEMA,
    version: 1,
    record_revision: 1,
    state: 'OPEN',
    invite_hmac_sha256: inviteHmac,
    created_at: createdAt,
    expires_at: input.expires_at,
    recipient_email_sha256: input.recipient_email_sha256,
    email_delivery_receipt_sha256: input.email_delivery_receipt_sha256,
    preview_url: input.preview_url,
    preview_source_repository: input.preview_source_repository,
    preview_source_commit_sha: input.preview_source_commit_sha,
    preview_manifest_sha256: input.preview_manifest_sha256,
    preview_content_sha256: input.preview_content_sha256,
    brief_sha256: input.brief_sha256,
    scope_version: input.scope_version,
    page_bindings: input.page_bindings,
    revision_round: revisionRound,
    prior_invite_hmac_sha256: input.prior_invite_hmac_sha256,
    prior_preview_manifest_sha256: priorManifest,
    session_nonce_hmac_sha256: null,
    exchanged_at: null,
    decision: null,
    successor_invite_hmac_sha256: null,
  }, env);

  if (priorEntry && priorEntry.record.state === 'REVISION_REQUESTED') {
    const superseded = signRecord({
      ...unsignedRecord(priorEntry.record),
      record_revision: priorEntry.record.record_revision + 1,
      state: 'REVISION_SUPERSEDED',
      successor_invite_hmac_sha256: inviteHmac,
    }, env);
    const replaced = await store.setJSON(reviewInviteKey(priorEntry.record.invite_hmac_sha256), superseded,
      { onlyIfMatch: priorEntry.etag });
    if (!replaced?.modified) {
      const current = await readInviteEntry(store, priorEntry.record.invite_hmac_sha256, env, configuration);
      if (current.record.state !== 'REVISION_SUPERSEDED' || current.record.successor_invite_hmac_sha256 !== inviteHmac) {
        throw new Error('ARC_REVIEW_STATE_CONTENTION');
      }
    }
  }

  const key = reviewInviteKey(inviteHmac);
  const created = await store.setJSON(key, record, { onlyIfNew: true });
  if (!created?.modified) {
    const existing = await readInviteEntry(store, inviteHmac, env, configuration);
    if (!sameIssuedInvite(existing.record, record)) throw new Error('ARC_REVIEW_INVITE_CONFLICT');
    return { idempotent_replay: true, record: existing.record };
  }
  return { idempotent_replay: false, record };
}

function encodeSession(payload, env) {
  const encoded = Buffer.from(canonicalJson(payload)).toString('base64url');
  const signature = hmacHex(env.ARC_REVIEW_SESSION_HMAC_SECRET, SESSION_SIGNATURE_PREFIX + encoded);
  return `${encoded}.${signature}`;
}

function decodeSession(value, env) {
  if (typeof value !== 'string' || value.length < 100 || value.length > 1024) throw new Error('ARC_REVIEW_SESSION_INVALID');
  const [encoded, signature, extra] = value.split('.');
  if (!encoded || !HEX_64.test(signature || '') || extra !== undefined) throw new Error('ARC_REVIEW_SESSION_INVALID');
  const expected = hmacHex(env.ARC_REVIEW_SESSION_HMAC_SECRET, SESSION_SIGNATURE_PREFIX + encoded);
  if (!safeEqual(expected, signature)) throw new Error('ARC_REVIEW_SESSION_INVALID');
  let payload;
  try { payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')); } catch { throw new Error('ARC_REVIEW_SESSION_INVALID'); }
  exactKeys(payload, ['schema', 'invite_hmac_sha256', 'session_nonce', 'expires_at'], 'Review session');
  if (payload.schema !== REVIEW_SESSION_SCHEMA || !TOKEN.test(payload.session_nonce)) throw new Error('ARC_REVIEW_SESSION_INVALID');
  hex64(payload.invite_hmac_sha256, 'Review session invite');
  isoTimestamp(payload.expires_at, 'Review session expiration');
  return payload;
}

export async function exchangeReviewInvite(store, inviteToken, env = process.env, adapters = {}) {
  const configuration = requirePortal(env);
  if (!TOKEN.test(String(inviteToken || ''))) throw new Error('ARC_REVIEW_INVITE_INVALID');
  const inviteHmac = hmacHex(env.ARC_REVIEW_INVITE_HMAC_SECRET, INVITE_ID_PREFIX + inviteToken);
  const entry = await readInviteEntry(store, inviteHmac, env, configuration);
  const now = adapters.clock?.() || new Date();
  if (Date.parse(entry.record.expires_at) <= now.getTime()) throw new Error('ARC_REVIEW_INVITE_EXPIRED');
  if (entry.record.state !== 'OPEN') throw new Error('ARC_REVIEW_INVITE_INACTIVE');
  if (entry.record.session_nonce_hmac_sha256 !== null) throw new Error('ARC_REVIEW_INVITE_ALREADY_EXCHANGED');
  const random = adapters.randomBytes?.(32);
  if (!Buffer.isBuffer(random) || random.length !== 32) throw new Error('ARC_REVIEW_SESSION_RANDOMNESS_UNAVAILABLE');
  const sessionNonce = random.toString('base64url');
  const sessionNonceHmac = hmacHex(env.ARC_REVIEW_SESSION_HMAC_SECRET, SESSION_NONCE_PREFIX + sessionNonce);
  const sessionExpiresAt = new Date(Math.min(Date.parse(entry.record.expires_at),
    now.getTime() + REVIEW_SESSION_TTL_SECONDS * 1000)).toISOString();
  const updated = signRecord({
    ...unsignedRecord(entry.record),
    record_revision: entry.record.record_revision + 1,
    session_nonce_hmac_sha256: sessionNonceHmac,
    exchanged_at: now.toISOString(),
  }, env);
  const result = await store.setJSON(reviewInviteKey(inviteHmac), updated, { onlyIfMatch: entry.etag });
  if (!result?.modified) throw new Error('ARC_REVIEW_STATE_CONTENTION');
  const sessionToken = encodeSession({
    schema: REVIEW_SESSION_SCHEMA,
    invite_hmac_sha256: inviteHmac,
    session_nonce: sessionNonce,
    expires_at: sessionExpiresAt,
  }, env);
  return { max_age: Math.max(1, Math.floor((Date.parse(sessionExpiresAt) - now.getTime()) / 1000)), session_token: sessionToken };
}

export async function authorizeReviewSession(store, sessionToken, env = process.env, now = new Date()) {
  const configuration = requirePortal(env);
  const session = decodeSession(sessionToken, env);
  if (Date.parse(session.expires_at) <= now.getTime()) throw new Error('ARC_REVIEW_SESSION_EXPIRED');
  const entry = await readInviteEntry(store, session.invite_hmac_sha256, env, configuration);
  if (Date.parse(entry.record.expires_at) <= now.getTime()) throw new Error('ARC_REVIEW_INVITE_EXPIRED');
  const nonceHmac = hmacHex(env.ARC_REVIEW_SESSION_HMAC_SECRET, SESSION_NONCE_PREFIX + session.session_nonce);
  if (!safeEqual(nonceHmac, entry.record.session_nonce_hmac_sha256)) throw new Error('ARC_REVIEW_SESSION_INVALID');
  return { ...entry, session };
}

export async function readReviewStatus(store, sessionToken, env = process.env, now = new Date()) {
  const configuration = reviewPortalConfiguration(env);
  const { record } = await authorizeReviewSession(store, sessionToken, env, now);
  return {
    schema: 'arc-preview-review-status-v1',
    state: record.state,
    record_revision: record.record_revision,
    preview_url: record.preview_url,
    preview_manifest_sha256: record.preview_manifest_sha256,
    revision_round: record.revision_round,
    revision_rounds_remaining: REVIEW_MAX_REVISION_ROUNDS - record.revision_round,
    can_request_changes: record.state === 'OPEN' && record.revision_round < REVIEW_MAX_REVISION_ROUNDS,
    can_approve_and_pay: record.state === 'OPEN' && configuration.checkoutEnabled,
  };
}

function normalizeDecisionInput(input, record, env) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || !ACTIONS.has(input.action) ||
      !Number.isSafeInteger(input.expected_revision) || !UUID.test(String(input.idempotency_key || ''))) {
    throw new TypeError('Review decision request is invalid.');
  }
  const expectedFields = input.action === 'REQUEST_CHANGES'
    ? ['action', 'expected_revision', 'idempotency_key', 'revision_notes']
    : ['action', 'expected_revision', 'idempotency_key'];
  if (JSON.stringify(Object.keys(input).sort()) !== JSON.stringify(expectedFields.sort())) {
    throw new TypeError('Review decision request fields are invalid.');
  }
  let notes = null;
  if (input.action === 'REQUEST_CHANGES') {
    notes = typeof input.revision_notes === 'string' ? input.revision_notes.trim().replace(/\r\n/g, '\n') : '';
    if (notes.length < 10 || notes.length > 4000 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(notes)) {
      throw new TypeError('Revision notes are invalid.');
    }
  } else if (input.revision_notes !== undefined && input.revision_notes !== null && input.revision_notes !== '') {
    throw new TypeError('Approval cannot contain revision notes.');
  }
  const actionPayload = { action: input.action, revision_notes_sha256: notes === null ? null : sha256Hex(notes) };
  return {
    action: input.action,
    action_payload_sha256: sha256Hex(canonicalJson(actionPayload)),
    expected_revision: input.expected_revision,
    idempotency_hmac_sha256: hmacHex(env.ARC_REVIEW_DECISION_HMAC_SECRET,
      DECISION_IDEMPOTENCY_PREFIX + input.idempotency_key),
    revision_notes: notes,
    revision_notes_sha256: actionPayload.revision_notes_sha256,
  };
}

function approvalReceipt(record, decision, sessionNonceHmac) {
  return {
    schema: REVIEW_APPROVAL_SCHEMA,
    invite_hmac_sha256: record.invite_hmac_sha256,
    recipient_email_sha256: record.recipient_email_sha256,
    email_delivery_receipt_sha256: record.email_delivery_receipt_sha256,
    preview_url: record.preview_url,
    preview_source_repository: record.preview_source_repository,
    preview_source_commit_sha: record.preview_source_commit_sha,
    preview_manifest_sha256: record.preview_manifest_sha256,
    preview_content_sha256: record.preview_content_sha256,
    brief_sha256: record.brief_sha256,
    scope_version: record.scope_version,
    page_bindings: record.page_bindings,
    revision_round: record.revision_round,
    session_nonce_hmac_sha256: sessionNonceHmac,
    action_payload_sha256: decision.action_payload_sha256,
    decided_at: decision.decided_at,
  };
}

function exactDecisionReplay(record, normalized) {
  return record.decision !== null && record.decision.action === normalized.action &&
    record.decision.action_payload_sha256 === normalized.action_payload_sha256;
}

export async function decideReview(store, sessionToken, input, env = process.env, adapters = {}) {
  const configuration = requirePortal(env);
  const now = adapters.clock?.() || new Date();
  const authorized = await authorizeReviewSession(store, sessionToken, env, now);
  const normalized = normalizeDecisionInput(input, authorized.record, env);
  if (normalized.action === 'APPROVE_AND_PAY' && !configuration.checkoutEnabled) {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE');
  }
  if (authorized.record.state !== 'OPEN') {
    if (exactDecisionReplay(authorized.record, normalized)) {
      return { idempotent_replay: true, record_revision: authorized.record.record_revision, state: authorized.record.state };
    }
    throw new Error('ARC_REVIEW_DECISION_CONFLICT');
  }
  if (normalized.expected_revision !== authorized.record.record_revision) throw new Error('ARC_REVIEW_STALE_DECISION');
  if (normalized.action === 'REQUEST_CHANGES' && authorized.record.revision_round >= REVIEW_MAX_REVISION_ROUNDS) {
    throw new Error('ARC_REVIEW_REVISION_LIMIT');
  }
  const decidedAt = now.toISOString();
  const checkoutIdempotencyKey = normalized.action === 'APPROVE_AND_PAY'
    ? hmacHex(env.ARC_REVIEW_DECISION_HMAC_SECRET, CHECKOUT_IDEMPOTENCY_PREFIX + authorized.record.invite_hmac_sha256)
    : null;
  const decision = {
    schema: REVIEW_DECISION_SCHEMA,
    action: normalized.action,
    action_payload_sha256: normalized.action_payload_sha256,
    idempotency_hmac_sha256: normalized.idempotency_hmac_sha256,
    decided_at: decidedAt,
    revision_notes: normalized.revision_notes,
    revision_notes_sha256: normalized.revision_notes_sha256,
    approval_receipt_sha256: null,
    approval_receipt_hmac_sha256: null,
    checkout_idempotency_key_sha256: checkoutIdempotencyKey === null ? null : sha256Hex(checkoutIdempotencyKey),
  };
  if (normalized.action === 'APPROVE_AND_PAY') {
    const receipt = approvalReceipt(authorized.record, decision, authorized.record.session_nonce_hmac_sha256);
    decision.approval_receipt_sha256 = sha256Hex(canonicalJson(receipt));
    decision.approval_receipt_hmac_sha256 = hmacHex(env.ARC_REVIEW_DECISION_HMAC_SECRET,
      APPROVAL_SIGNATURE_PREFIX + canonicalJson(receipt));
  }
  const updated = signRecord({
    ...unsignedRecord(authorized.record),
    record_revision: authorized.record.record_revision + 1,
    state: normalized.action === 'APPROVE_AND_PAY' ? 'APPROVED' : 'REVISION_REQUESTED',
    decision,
  }, env);
  const result = await store.setJSON(reviewInviteKey(authorized.record.invite_hmac_sha256), updated,
    { onlyIfMatch: authorized.etag });
  if (!result?.modified) {
    const current = await authorizeReviewSession(store, sessionToken, env, now);
    if (exactDecisionReplay(current.record, normalized)) {
      return { idempotent_replay: true, record_revision: current.record.record_revision, state: current.record.state };
    }
    throw new Error('ARC_REVIEW_DECISION_CONFLICT');
  }
  return { idempotent_replay: false, record_revision: updated.record_revision, state: updated.state };
}

export async function createApprovedCheckout(store, sessionToken, env = process.env, adapters = {}) {
  const configuration = requirePortal(env);
  if (!configuration.checkoutEnabled || typeof adapters.createCheckout !== 'function') {
    throw new Error('ARC_REVIEW_CHECKOUT_UNAVAILABLE');
  }
  const now = adapters.clock?.() || new Date();
  const { record } = await authorizeReviewSession(store, sessionToken, env, now);
  if (record.state !== 'APPROVED' || record.decision?.action !== 'APPROVE_AND_PAY') {
    throw new Error('ARC_REVIEW_APPROVAL_REQUIRED');
  }
  const receipt = approvalReceipt(record, record.decision, record.session_nonce_hmac_sha256);
  const receiptSha = sha256Hex(canonicalJson(receipt));
  const receiptHmac = hmacHex(env.ARC_REVIEW_DECISION_HMAC_SECRET,
    APPROVAL_SIGNATURE_PREFIX + canonicalJson(receipt));
  if (!safeEqual(receiptSha, record.decision.approval_receipt_sha256) ||
      !safeEqual(receiptHmac, record.decision.approval_receipt_hmac_sha256)) {
    throw new Error('ARC_REVIEW_APPROVAL_BINDING_INVALID');
  }
  const idempotencyKey = hmacHex(env.ARC_REVIEW_DECISION_HMAC_SECRET,
    CHECKOUT_IDEMPOTENCY_PREFIX + record.invite_hmac_sha256);
  if (!safeEqual(sha256Hex(idempotencyKey), record.decision.checkout_idempotency_key_sha256)) {
    throw new Error('ARC_REVIEW_CHECKOUT_BINDING_INVALID');
  }
  const created = await adapters.createCheckout({
    idempotency_key: `arc_review_${idempotencyKey}`,
    approval_receipt_sha256: receiptSha,
    approval_receipt_hmac_sha256: receiptHmac,
    invite_hmac_sha256: record.invite_hmac_sha256,
    preview_manifest_sha256: record.preview_manifest_sha256,
    recipient_email_sha256: record.recipient_email_sha256,
    scope_version: record.scope_version,
  });
  let url;
  try { url = new URL(created?.url); } catch { throw new Error('ARC_REVIEW_CHECKOUT_RESPONSE_INVALID'); }
  if (url.protocol !== 'https:' || url.origin !== configuration.checkoutOrigin || url.username || url.password || url.hash) {
    throw new Error('ARC_REVIEW_CHECKOUT_RESPONSE_INVALID');
  }
  return { checkout_url: url.href, state: 'APPROVED' };
}
