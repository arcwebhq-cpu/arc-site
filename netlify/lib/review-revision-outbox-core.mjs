import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import {
  REVIEW_MAX_REVISION_ROUNDS,
  readReviewInviteForEmail,
  renewExpiredReviewSuccessor,
  reviewPortalConfiguration,
} from './review-flow-core.mjs';
import {
  prepareReviewInviteEmail,
  readReviewEmailOutbox,
  reviewEmailOutboxConfiguration,
} from './review-email-outbox-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';

export const REVIEW_REVISION_OUTBOX_STORE = 'arc-preview-review-revision-outbox';
export const REVIEW_REVISION_OUTBOX_SCHEMA = 'arc-preview-review-revision-work-v2';
export const REVIEW_REVISION_OUTBOX_ENABLED_ENV = 'ARC_REVIEW_REVISION_OUTBOX_ENABLED';
export const REVIEW_REVISION_OUTBOX_SECRET_ENV = 'ARC_REVIEW_REVISION_OUTBOX_HMAC_SECRET';
export const REVIEW_REVISION_SUPPLY_CHAIN_SECRET_ENV = 'ARC_REVIEW_REVISION_SUPPLY_CHAIN_HMAC_SECRET';
export const REVIEW_REVISION_INVITE_RESERVATION_SECRET_ENV =
  'ARC_REVIEW_REVISION_INVITE_RESERVATION_HMAC_SECRET';
export const REVIEW_REVISION_INTERNAL_AUTH_SECRET_ENV = 'ARC_REVIEW_REVISION_INTERNAL_AUTH_SECRET';
export const REVIEW_REVISION_LEASE_TTL_SECONDS = 5 * 60;
export const REVIEW_REVISION_ARTIFACT_EVIDENCE_SCHEMA = 'arc-preview-revision-artifact-evidence-v1';
export const REVIEW_REVISION_INVITE_RESERVATION_SCHEMA = 'arc-preview-revision-invite-reservation-v1';
export const REVIEW_REVISION_ARTIFACT_EVIDENCE_SIGNATURE_PREFIX =
  'arc-preview-revision-artifact-evidence-signature-v1\n';
export const REVIEW_REVISION_INVITE_RESERVATION_SIGNATURE_PREFIX =
  'arc-preview-revision-invite-reservation-signature-v1\n';

const REVIEW_INVITE_ID_PREFIX = 'arc-preview-review-invite-id-v1\n';
const REVIEW_EMAIL_OUTBOX_ID_PREFIX = 'arc-preview-review-email-outbox-id-v1\n';
const WORK_ID_PREFIX = 'arc-preview-review-revision-work-id-v2\n';
const PENDING_KEY_PREFIX = 'review-revision-pending/';
const PENDING_RECORD_SIGNATURE_PREFIX = 'arc-preview-review-revision-pending-signature-v1\n';
const WORK_RECORD_SIGNATURE_PREFIX = 'arc-preview-review-revision-work-record-v2\n';
const LEASE_TOKEN_PREFIX = 'arc-preview-review-revision-work-lease-v2\n';
const LEASE_TOKEN_DIGEST_PREFIX = 'arc-preview-review-revision-work-lease-digest-v2\n';
const INTERNAL_WORKER_ID_PREFIX = 'arc-preview-review-revision-internal-worker-v1\n';
const HEX_40 = /^[a-f0-9]{40}$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const TOKEN = /^[A-Za-z0-9_-]{43,128}$/;
const LEASE_TOKEN = /^[A-Za-z0-9_-]{43}$/;
const REPOSITORY = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const SCOPE_VERSION = /^[a-z0-9][a-z0-9.-]{5,79}$/;
const WORK_STATES = new Set(['PENDING', 'CLAIMED', 'ISSUING', 'EMAIL_READY', 'COMPLETED']);
const PAGE_PATHS = Object.freeze([
  'about/index.html',
  'contact/index.html',
  'index.html',
  'process/index.html',
  'services/index.html',
]);
const WORK_RECORD_FIELDS = Object.freeze([
  'schema', 'version', 'record_revision', 'state', 'work_hmac_sha256',
  'source_invite_hmac_sha256', 'source_record_revision', 'source_repository', 'source_commit_sha',
  'source_manifest_sha256', 'source_content_sha256', 'source_page_bindings_sha256', 'brief_sha256',
  'scope_version', 'decision_action_payload_sha256', 'revision_notes_sha256',
  'source_revision_round', 'target_revision_round', 'reserved_at', 'attempt_count',
  'lease_worker_sha256', 'lease_token_hmac_sha256', 'lease_claimed_at', 'lease_expires_at',
  'successor_repository', 'successor_commit_sha', 'successor_manifest_sha256',
  'successor_content_sha256', 'successor_page_bindings_sha256', 'successor_preview_url_sha256',
  'successor_invite_hmac_sha256', 'successor_invite_expires_at',
  'successor_email_delivery_receipt_sha256', 'artifact_authority_hmac_sha256',
  'invite_reservation_hmac_sha256', 'issuance_planned_at', 'successor_email_outbox_hmac_sha256',
  'issuance_generation', 'replaced_successor_invite_hmac_sha256',
  'completion_worker_sha256',
  'completion_lease_token_hmac_sha256', 'completed_at', 'record_hmac_sha256',
]);
const ARTIFACT_EVIDENCE_FIELDS = Object.freeze([
  'schema', 'work_hmac_sha256', 'source_invite_hmac_sha256', 'source_repository', 'source_commit_sha',
  'source_manifest_sha256', 'source_page_bindings_sha256', 'target_revision_round', 'repository',
  'commit_sha', 'manifest_sha256', 'content_sha256', 'page_bindings', 'preview_url', 'verified_at',
  'authority_hmac_sha256',
]);
const INVITE_RESERVATION_FIELDS = Object.freeze([
  'schema', 'work_hmac_sha256', 'artifact_authority_hmac_sha256', 'invite_token', 'expires_at',
  'email_delivery_receipt_sha256', 'reserved_at', 'reservation_hmac_sha256',
]);
const COMPLETION_INPUT_FIELDS = Object.freeze([
  'lease_token', 'successor_repository', 'successor_commit_sha', 'successor_manifest_sha256',
]);

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
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

function hex64(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function commitSha(value, label) {
  if (typeof value !== 'string' || !HEX_40.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function isoTimestamp(value, label) {
  if (typeof value !== 'string' || value.length < 20 || value.length > 32 || new Date(value).toISOString() !== value) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function validSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}

function exactBoolean(value) {
  return value === 'true' || value === 'false';
}

function nowFrom(adapters = {}) {
  const value = adapters.clock?.() || new Date();
  const now = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(now.getTime())) throw new TypeError('Revision outbox clock is invalid.');
  return now;
}

function normalizePageBindings(value, label = 'Preview page bindings') {
  if (!Array.isArray(value) || value.length !== PAGE_PATHS.length) throw new TypeError(`${label} are invalid.`);
  return value.map((entry, index) => {
    exactKeys(entry, ['path', 'sha256'], label.slice(0, -1));
    if (entry.path !== PAGE_PATHS[index]) throw new TypeError(`${label} are invalid.`);
    return { path: entry.path, sha256: hex64(entry.sha256, `${label} digest`) };
  });
}

function pageBindingsSha256(value) {
  return sha256Hex(canonicalJson(normalizePageBindings(value)));
}

function normalizePreviewUrl(value, env) {
  const configuration = reviewPortalConfiguration(env);
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Preview URL is invalid.'); }
  if (!configuration.enabled || url.protocol !== 'https:' || url.origin !== configuration.previewOrigin ||
      url.username || url.password || url.search || url.hash || url.pathname === '/' || !url.pathname.endsWith('/')) {
    throw new TypeError('Preview URL is invalid.');
  }
  return url.href;
}

async function readReviewEntry(store, inviteHmac, env) {
  // This exported review-flow read performs strong-consistency retrieval plus
  // the canonical signed-record/schema validation. Workers never need a
  // customer session credential and this module never accepts an unsigned
  // review object from an adapter.
  return readReviewInviteForEmail(store, inviteHmac, env);
}

export function reviewRevisionOutboxConfiguration(env = process.env) {
  const portal = reviewPortalConfiguration(env);
  const email = reviewEmailOutboxConfiguration(env);
  const flagValid = exactBoolean(env[REVIEW_REVISION_OUTBOX_ENABLED_ENV]);
  const secretNames = [
    'ARC_REVIEW_INVITE_HMAC_SECRET',
    'ARC_REVIEW_SESSION_HMAC_SECRET',
    'ARC_REVIEW_RECORD_HMAC_SECRET',
    'ARC_REVIEW_DECISION_HMAC_SECRET',
    REVIEW_REVISION_OUTBOX_SECRET_ENV,
    REVIEW_REVISION_SUPPLY_CHAIN_SECRET_ENV,
    REVIEW_REVISION_INVITE_RESERVATION_SECRET_ENV,
    REVIEW_REVISION_INTERNAL_AUTH_SECRET_ENV,
    'ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET',
    'ARC_REVIEW_EMAIL_RECEIPT_HMAC_SECRET',
  ];
  const allSecrets = secretNames.map((name) => env[name]);
  const secretsValid = allSecrets.every(validSecret) && new Set(allSecrets).size === allSecrets.length &&
    sensitiveCredentialsAreIsolated(env, secretNames);
  return {
    enabled: portal.enabled && email.enabled && flagValid &&
      env[REVIEW_REVISION_OUTBOX_ENABLED_ENV] === 'true' && secretsValid,
    emailOutboxEnabled: email.enabled,
    flagValid,
    portalEnabled: portal.enabled,
    secretsValid,
  };
}

export function reviewRevisionInternalWorkerAdapter(env = process.env) {
  const selectedNames = [REVIEW_REVISION_INTERNAL_AUTH_SECRET_ENV, REVIEW_REVISION_OUTBOX_SECRET_ENV];
  const isolated = sensitiveCredentialsAreIsolated(env, selectedNames);
  const expected = isolated ? env[REVIEW_REVISION_INTERNAL_AUTH_SECRET_ENV] : null;
  return async ({ authorization }) => ({
    authorized: validSecret(expected) && typeof authorization === 'string' && safeEqual(authorization, expected),
    worker_id_sha256: isolated && validSecret(expected)
      ? hmacHex(env[REVIEW_REVISION_OUTBOX_SECRET_ENV], INTERNAL_WORKER_ID_PREFIX + expected)
      : '0'.repeat(64),
  });
}

function requireOutbox(env) {
  if (!reviewRevisionOutboxConfiguration(env).enabled) throw new Error('ARC_REVIEW_REVISION_OUTBOX_DISABLED');
}

function workHmacForInvite(inviteHmac, env) {
  return hmacHex(env[REVIEW_REVISION_OUTBOX_SECRET_ENV],
    WORK_ID_PREFIX + hex64(inviteHmac, 'Source review invite HMAC'));
}

function inviteHmacForToken(inviteToken, env) {
  if (typeof inviteToken !== 'string' || !TOKEN.test(inviteToken)) throw new TypeError('Successor invite token is invalid.');
  return hmacHex(env.ARC_REVIEW_INVITE_HMAC_SECRET, REVIEW_INVITE_ID_PREFIX + inviteToken);
}

function emailOutboxHmacForInvite(inviteHmac, env) {
  return hmacHex(env.ARC_REVIEW_EMAIL_OUTBOX_HMAC_SECRET,
    REVIEW_EMAIL_OUTBOX_ID_PREFIX + hex64(inviteHmac, 'Successor invite HMAC'));
}

export function reviewRevisionWorkKey(workHmac) {
  return `review-revision-work/${hex64(workHmac, 'Revision work HMAC')}`;
}

export function reviewRevisionPendingKey(workHmac) {
  return `${PENDING_KEY_PREFIX}${hex64(workHmac, 'Revision work HMAC')}`;
}

function pendingMarker(workHmac, sourceInviteHmac, env) {
  const unsigned = {
    schema: 'arc-preview-review-revision-pending-v1',
    source_invite_hmac_sha256: hex64(sourceInviteHmac, 'Pending source invite HMAC'),
    work_hmac_sha256: hex64(workHmac, 'Pending revision work HMAC'),
  };
  return { ...unsigned, record_hmac_sha256: hmacHex(env[REVIEW_REVISION_OUTBOX_SECRET_ENV],
    PENDING_RECORD_SIGNATURE_PREFIX + canonicalJson(unsigned)) };
}

function validatePendingMarker(value, expectedWorkHmac, env) {
  exactKeys(value, ['schema', 'source_invite_hmac_sha256', 'work_hmac_sha256', 'record_hmac_sha256'],
    'Revision pending marker');
  const expected = pendingMarker(value.work_hmac_sha256, value.source_invite_hmac_sha256, env);
  if (value.schema !== expected.schema || value.work_hmac_sha256 !== expectedWorkHmac ||
      value.work_hmac_sha256 !== workHmacForInvite(value.source_invite_hmac_sha256, env) ||
      !safeEqual(value.record_hmac_sha256, expected.record_hmac_sha256)) {
    throw new Error('ARC_REVIEW_REVISION_PENDING_INDEX_INVALID');
  }
  return value;
}

async function readPendingIndex(store, workHmac, env) {
  const entry = await store.getWithMetadata(reviewRevisionPendingKey(workHmac),
    { type: 'json', consistency: 'strong' });
  if (!entry) throw new Error('ARC_REVIEW_REVISION_PENDING_INDEX_NOT_FOUND');
  return validatePendingMarker(entry.data, workHmac, env);
}

async function ensurePendingIndex(store, workHmac, sourceInviteHmac, env) {
  const marker = pendingMarker(workHmac, sourceInviteHmac, env);
  const created = await store.setJSON(reviewRevisionPendingKey(workHmac), marker, { onlyIfNew: true });
  if (!created?.modified) {
    const existing = await readPendingIndex(store, workHmac, env);
    if (existing.source_invite_hmac_sha256 !== sourceInviteHmac) {
      throw new Error('ARC_REVIEW_REVISION_PENDING_INDEX_INVALID');
    }
  }
}

async function removePendingIndex(store, workHmac) {
  if (typeof store.delete !== 'function') throw new Error('ARC_REVIEW_REVISION_PENDING_INDEX_UNAVAILABLE');
  await store.delete(reviewRevisionPendingKey(workHmac));
}

export async function prepareReviewRevisionPendingIndex(outboxStore, sourceInviteHmac, authorization,
  env = process.env, adapters = {}) {
  requireOutbox(env);
  const now = nowFrom(adapters);
  const workHmac = workHmacForInvite(sourceInviteHmac, env);
  await authorizeInternalWorker(adapters, authorization, 'PREPARE_PENDING', workHmac, now);
  await ensurePendingIndex(outboxStore, workHmac, sourceInviteHmac, env);
  return { work_hmac_sha256: workHmac };
}

function unsignedWorkRecord(record) {
  const { record_hmac_sha256: _signature, ...unsigned } = record;
  return unsigned;
}

function signWorkRecord(record, env) {
  const unsigned = unsignedWorkRecord(record);
  return {
    ...unsigned,
    record_hmac_sha256: hmacHex(env[REVIEW_REVISION_OUTBOX_SECRET_ENV],
      WORK_RECORD_SIGNATURE_PREFIX + canonicalJson(unsigned)),
  };
}

function planFields(record) {
  return [
    record.successor_repository, record.successor_commit_sha, record.successor_manifest_sha256,
    record.successor_content_sha256, record.successor_page_bindings_sha256,
    record.successor_preview_url_sha256, record.successor_invite_hmac_sha256,
    record.successor_invite_expires_at, record.successor_email_delivery_receipt_sha256,
    record.artifact_authority_hmac_sha256, record.invite_reservation_hmac_sha256,
    record.issuance_planned_at,
  ];
}

export function validateReviewRevisionWorkRecord(record, env = process.env) {
  requireOutbox(env);
  exactKeys(record, WORK_RECORD_FIELDS, 'Revision work record');
  if (record.schema !== REVIEW_REVISION_OUTBOX_SCHEMA || record.version !== 2 ||
      !Number.isSafeInteger(record.record_revision) || record.record_revision < 1 || !WORK_STATES.has(record.state)) {
    throw new TypeError('Revision work record is invalid.');
  }
  hex64(record.record_hmac_sha256, 'Revision work signature');
  const expected = hmacHex(env[REVIEW_REVISION_OUTBOX_SECRET_ENV],
    WORK_RECORD_SIGNATURE_PREFIX + canonicalJson(unsignedWorkRecord(record)));
  if (!safeEqual(expected, record.record_hmac_sha256)) {
    throw new Error('ARC_REVIEW_REVISION_WORK_SIGNATURE_INVALID');
  }
  hex64(record.work_hmac_sha256, 'Revision work HMAC');
  hex64(record.source_invite_hmac_sha256, 'Source invite HMAC');
  if (record.work_hmac_sha256 !== workHmacForInvite(record.source_invite_hmac_sha256, env)) {
    throw new Error('ARC_REVIEW_REVISION_WORK_ID_INVALID');
  }
  if (!Number.isSafeInteger(record.source_record_revision) || record.source_record_revision < 1 ||
      !REPOSITORY.test(record.source_repository)) throw new TypeError('Revision work source is invalid.');
  commitSha(record.source_commit_sha, 'Source commit');
  hex64(record.source_manifest_sha256, 'Source manifest');
  hex64(record.source_content_sha256, 'Source content');
  hex64(record.source_page_bindings_sha256, 'Source page bindings');
  hex64(record.brief_sha256, 'Revision brief');
  if (typeof record.scope_version !== 'string' || !SCOPE_VERSION.test(record.scope_version)) {
    throw new TypeError('Revision scope version is invalid.');
  }
  hex64(record.decision_action_payload_sha256, 'Revision action payload');
  hex64(record.revision_notes_sha256, 'Revision notes digest');
  if (!Number.isSafeInteger(record.source_revision_round) || record.source_revision_round < 0 ||
      record.source_revision_round >= REVIEW_MAX_REVISION_ROUNDS ||
      record.target_revision_round !== record.source_revision_round + 1 ||
      record.target_revision_round > REVIEW_MAX_REVISION_ROUNDS) {
    throw new TypeError('Revision work round is invalid.');
  }
  isoTimestamp(record.reserved_at, 'Revision reservation');
  if (!Number.isSafeInteger(record.attempt_count) || record.attempt_count < 0) {
    throw new TypeError('Revision attempt count is invalid.');
  }
  const hasLease = [record.lease_worker_sha256, record.lease_token_hmac_sha256,
    record.lease_claimed_at, record.lease_expires_at].every((value) => value !== null);
  const anyLease = [record.lease_worker_sha256, record.lease_token_hmac_sha256,
    record.lease_claimed_at, record.lease_expires_at].some((value) => value !== null);
  const hasPlan = planFields(record).every((value) => value !== null);
  const anyPlan = planFields(record).some((value) => value !== null);
  const hasEmailOutbox = record.successor_email_outbox_hmac_sha256 !== null;
  if (record.replaced_successor_invite_hmac_sha256 !== null) {
    hex64(record.replaced_successor_invite_hmac_sha256, 'Replaced successor invite');
    if (!hasPlan || record.replaced_successor_invite_hmac_sha256 === record.successor_invite_hmac_sha256) {
      throw new TypeError('Replaced successor invite is invalid.');
    }
  }
  if (hasPlan) {
    if (!Number.isSafeInteger(record.issuance_generation) || record.issuance_generation < 1 ||
        record.issuance_generation > 100 ||
        (record.issuance_generation === 1) !== (record.replaced_successor_invite_hmac_sha256 === null)) {
      throw new TypeError('Revision issuance generation is invalid.');
    }
  } else if (record.issuance_generation !== null) {
    throw new TypeError('Revision issuance generation is invalid.');
  }
  const hasCompletion = [record.completion_worker_sha256, record.completion_lease_token_hmac_sha256,
    record.completed_at].every((value) => value !== null);
  const anyCompletion = [record.completion_worker_sha256, record.completion_lease_token_hmac_sha256,
    record.completed_at].some((value) => value !== null);
  if (record.state === 'PENDING') {
    if (anyLease || anyPlan || hasEmailOutbox || anyCompletion || record.attempt_count !== 0) {
      throw new TypeError('Pending work is invalid.');
    }
  } else if (record.state === 'CLAIMED') {
    if (!hasLease || anyPlan || hasEmailOutbox || anyCompletion || record.attempt_count < 1) {
      throw new TypeError('Claimed work is invalid.');
    }
  } else if (record.state === 'ISSUING') {
    if (!hasLease || !hasPlan || hasEmailOutbox || anyCompletion || record.attempt_count < 1) {
      throw new TypeError('Issuing work is invalid.');
    }
  } else if (record.state === 'EMAIL_READY') {
    if (!hasLease || !hasPlan || !hasEmailOutbox || anyCompletion || record.attempt_count < 1) {
      throw new TypeError('Email-ready work is invalid.');
    }
  } else if (anyLease || !hasPlan || !hasEmailOutbox || !hasCompletion || record.attempt_count < 1) {
    throw new TypeError('Completed work is invalid.');
  }
  if (hasEmailOutbox) hex64(record.successor_email_outbox_hmac_sha256, 'Successor email outbox');
  if (hasLease) {
    hex64(record.lease_worker_sha256, 'Revision worker digest');
    hex64(record.lease_token_hmac_sha256, 'Revision lease digest');
    isoTimestamp(record.lease_claimed_at, 'Revision lease claim');
    isoTimestamp(record.lease_expires_at, 'Revision lease expiration');
    if (Date.parse(record.lease_expires_at) <= Date.parse(record.lease_claimed_at)) {
      throw new TypeError('Revision lease interval is invalid.');
    }
  } else if (anyLease) throw new TypeError('Revision lease is incomplete.');
  if (hasPlan) {
    if (!REPOSITORY.test(record.successor_repository) || record.successor_repository !== record.source_repository) {
      throw new TypeError('Successor repository is invalid.');
    }
    commitSha(record.successor_commit_sha, 'Successor commit');
    for (const [value, label] of [
      [record.successor_manifest_sha256, 'Successor manifest'],
      [record.successor_content_sha256, 'Successor content'],
      [record.successor_page_bindings_sha256, 'Successor page bindings'],
      [record.successor_preview_url_sha256, 'Successor preview URL'],
      [record.successor_invite_hmac_sha256, 'Successor invite'],
      [record.successor_email_delivery_receipt_sha256, 'Successor email receipt'],
      [record.artifact_authority_hmac_sha256, 'Artifact authority receipt'],
      [record.invite_reservation_hmac_sha256, 'Invite reservation receipt'],
    ]) hex64(value, label);
    isoTimestamp(record.successor_invite_expires_at, 'Successor invite expiration');
    isoTimestamp(record.issuance_planned_at, 'Successor issuance plan');
    if (record.successor_commit_sha === record.source_commit_sha ||
        record.successor_manifest_sha256 === record.source_manifest_sha256 ||
        record.successor_content_sha256 === record.source_content_sha256) {
      throw new TypeError('Successor artifact is not immutable new work.');
    }
  } else if (anyPlan) throw new TypeError('Successor issuance plan is incomplete.');
  if (hasCompletion) {
    hex64(record.completion_worker_sha256, 'Completing worker digest');
    hex64(record.completion_lease_token_hmac_sha256, 'Completing lease digest');
    isoTimestamp(record.completed_at, 'Revision completion');
  } else if (anyCompletion) throw new TypeError('Revision completion is incomplete.');
  return record;
}

async function readWorkEntry(store, workHmac, env) {
  const entry = await store.getWithMetadata(reviewRevisionWorkKey(workHmac),
    { type: 'json', consistency: 'strong' });
  if (!entry) throw new Error('ARC_REVIEW_REVISION_WORK_NOT_FOUND');
  return { record: validateReviewRevisionWorkRecord(entry.data, env), etag: entry.etag };
}

export async function readReviewRevisionWork(store, workHmac, env = process.env) {
  requireOutbox(env);
  return readWorkEntry(store, workHmac, env);
}

async function authorizeInternalWorker(adapters, authorization, action, workHmac, now) {
  if (authorization === undefined || authorization === null || typeof adapters.authorizeInternalWorker !== 'function') {
    throw new Error('ARC_REVIEW_REVISION_WORKER_UNAUTHORIZED');
  }
  const result = await adapters.authorizeInternalWorker({
    action,
    authorization,
    work_hmac_sha256: workHmac,
    requested_at: now.toISOString(),
  });
  exactKeys(result, ['authorized', 'worker_id_sha256'], 'Internal worker authorization');
  if (result.authorized !== true) throw new Error('ARC_REVIEW_REVISION_WORKER_UNAUTHORIZED');
  return hex64(result.worker_id_sha256, 'Internal worker digest');
}

function revisionSource(record) {
  if (!['REVISION_REQUESTED', 'REVISION_SUPERSEDED'].includes(record.state) ||
      record.decision?.action !== 'REQUEST_CHANGES') {
    throw new Error('ARC_REVIEW_REVISION_SOURCE_NOT_READY');
  }
  if (record.revision_round >= REVIEW_MAX_REVISION_ROUNDS) throw new Error('ARC_REVIEW_REVISION_LIMIT');
  return record;
}

function sourceBinding(record) {
  return {
    source_invite_hmac_sha256: record.invite_hmac_sha256,
    source_record_revision: record.record_revision,
    source_repository: record.preview_source_repository,
    source_commit_sha: record.preview_source_commit_sha,
    source_manifest_sha256: record.preview_manifest_sha256,
    source_content_sha256: record.preview_content_sha256,
    source_page_bindings_sha256: pageBindingsSha256(record.page_bindings),
    brief_sha256: record.brief_sha256,
    scope_version: record.scope_version,
    decision_action_payload_sha256: record.decision.action_payload_sha256,
    revision_notes_sha256: record.decision.revision_notes_sha256,
    source_revision_round: record.revision_round,
    target_revision_round: record.revision_round + 1,
  };
}

function sameSourceBinding(work, source) {
  const binding = sourceBinding(source);
  binding.source_record_revision = work.source_record_revision;
  const revisionValid = source.state === 'REVISION_REQUESTED'
    ? source.record_revision === work.source_record_revision
    : source.record_revision > work.source_record_revision;
  return revisionValid && Object.entries(binding).every(([key, value]) => work[key] === value);
}

function assertWorkSourceLineage(work, source) {
  revisionSource(source);
  if (!sameSourceBinding(work, source)) throw new Error('ARC_REVIEW_REVISION_SOURCE_CHANGED');
  if (source.state === 'REVISION_REQUESTED') return;
  if (!['ISSUING', 'EMAIL_READY', 'COMPLETED'].includes(work.state) ||
      ![work.successor_invite_hmac_sha256,
        work.state === 'ISSUING' ? work.replaced_successor_invite_hmac_sha256 : null]
        .includes(source.successor_invite_hmac_sha256)) {
    throw new Error('ARC_REVIEW_REVISION_STALE_SUCCESSOR');
  }
}

function revisionInput(work, source) {
  return {
    schema: 'arc-preview-revision-worker-input-v1',
    work_hmac_sha256: work.work_hmac_sha256,
    source_repository: source.preview_source_repository,
    source_commit_sha: source.preview_source_commit_sha,
    source_manifest_sha256: source.preview_manifest_sha256,
    source_content_sha256: source.preview_content_sha256,
    source_preview_url: source.preview_url,
    page_bindings: structuredClone(source.page_bindings),
    brief_sha256: source.brief_sha256,
    scope_version: source.scope_version,
    revision_notes: source.decision.revision_notes,
    revision_notes_sha256: source.decision.revision_notes_sha256,
    target_revision_round: work.target_revision_round,
  };
}

export async function reserveReviewRevisionWork(outboxStore, reviewStore, sourceInviteHmac, authorization,
  env = process.env, adapters = {}) {
  requireOutbox(env);
  const now = nowFrom(adapters);
  const workHmac = workHmacForInvite(sourceInviteHmac, env);
  await authorizeInternalWorker(adapters, authorization, 'RESERVE', workHmac, now);
  const source = revisionSource((await readReviewEntry(reviewStore, sourceInviteHmac, env)).record);
  // The discoverable marker is written first. A crash can therefore leave a
  // harmless marker with no work record, but never invisible durable work.
  await ensurePendingIndex(outboxStore, workHmac, sourceInviteHmac, env);
  const existingRaw = await outboxStore.getWithMetadata(reviewRevisionWorkKey(workHmac),
    { type: 'json', consistency: 'strong' });
  if (existingRaw) {
    const existing = validateReviewRevisionWorkRecord(existingRaw.data, env);
    assertWorkSourceLineage(existing, source);
    return { idempotent_replay: true, record: existing };
  }
  if (source.state !== 'REVISION_REQUESTED') throw new Error('ARC_REVIEW_REVISION_STALE_SUCCESSOR');
  const record = signWorkRecord({
    schema: REVIEW_REVISION_OUTBOX_SCHEMA,
    version: 2,
    record_revision: 1,
    state: 'PENDING',
    work_hmac_sha256: workHmac,
    ...sourceBinding(source),
    reserved_at: now.toISOString(),
    attempt_count: 0,
    lease_worker_sha256: null,
    lease_token_hmac_sha256: null,
    lease_claimed_at: null,
    lease_expires_at: null,
    successor_repository: null,
    successor_commit_sha: null,
    successor_manifest_sha256: null,
    successor_content_sha256: null,
    successor_page_bindings_sha256: null,
    successor_preview_url_sha256: null,
    successor_invite_hmac_sha256: null,
    successor_invite_expires_at: null,
    successor_email_delivery_receipt_sha256: null,
    artifact_authority_hmac_sha256: null,
    invite_reservation_hmac_sha256: null,
    issuance_planned_at: null,
    successor_email_outbox_hmac_sha256: null,
    issuance_generation: null,
    replaced_successor_invite_hmac_sha256: null,
    completion_worker_sha256: null,
    completion_lease_token_hmac_sha256: null,
    completed_at: null,
  }, env);
  validateReviewRevisionWorkRecord(record, env);
  const created = await outboxStore.setJSON(reviewRevisionWorkKey(workHmac), record, { onlyIfNew: true });
  if (created?.modified) {
    return { idempotent_replay: false, record };
  }
  const existing = await readWorkEntry(outboxStore, workHmac, env);
  assertWorkSourceLineage(existing.record, source);
  return { idempotent_replay: true, record: existing.record };
}

function leaseTokenFor(record, env) {
  const token = createHmac('sha256', env[REVIEW_REVISION_OUTBOX_SECRET_ENV]).update(
    LEASE_TOKEN_PREFIX + canonicalJson({
      work_hmac_sha256: record.work_hmac_sha256,
      attempt_count: record.attempt_count,
      lease_worker_sha256: record.lease_worker_sha256,
      lease_claimed_at: record.lease_claimed_at,
      lease_expires_at: record.lease_expires_at,
    }),
  ).digest('base64url');
  const digest = hmacHex(env[REVIEW_REVISION_OUTBOX_SECRET_ENV], LEASE_TOKEN_DIGEST_PREFIX + token);
  if (!safeEqual(digest, record.lease_token_hmac_sha256)) {
    throw new Error('ARC_REVIEW_REVISION_LEASE_BINDING_INVALID');
  }
  return token;
}

function activeLeaseReplay(record, workerSha, now, env) {
  if (!['CLAIMED', 'ISSUING', 'EMAIL_READY'].includes(record.state) ||
      Date.parse(record.lease_expires_at) <= now.getTime() ||
      record.lease_worker_sha256 !== workerSha) return null;
  return {
    idempotent_replay: true,
    lease_expires_at: record.lease_expires_at,
    lease_token: leaseTokenFor(record, env),
    record,
  };
}

function claimRecord(entry, workerSha, now, env) {
  const claimedAt = now.toISOString();
  const leaseExpiresAt = new Date(now.getTime() + REVIEW_REVISION_LEASE_TTL_SECONDS * 1000).toISOString();
  const unsigned = {
    ...unsignedWorkRecord(entry.record),
    record_revision: entry.record.record_revision + 1,
    state: ['ISSUING', 'EMAIL_READY'].includes(entry.record.state) ? entry.record.state : 'CLAIMED',
    attempt_count: entry.record.attempt_count + 1,
    lease_worker_sha256: workerSha,
    lease_token_hmac_sha256: null,
    lease_claimed_at: claimedAt,
    lease_expires_at: leaseExpiresAt,
  };
  const token = createHmac('sha256', env[REVIEW_REVISION_OUTBOX_SECRET_ENV]).update(
    LEASE_TOKEN_PREFIX + canonicalJson({
      work_hmac_sha256: unsigned.work_hmac_sha256,
      attempt_count: unsigned.attempt_count,
      lease_worker_sha256: unsigned.lease_worker_sha256,
      lease_claimed_at: unsigned.lease_claimed_at,
      lease_expires_at: unsigned.lease_expires_at,
    }),
  ).digest('base64url');
  const record = signWorkRecord({
    ...unsigned,
    lease_token_hmac_sha256: hmacHex(env[REVIEW_REVISION_OUTBOX_SECRET_ENV],
      LEASE_TOKEN_DIGEST_PREFIX + token),
  }, env);
  validateReviewRevisionWorkRecord(record, env);
  return { record, token };
}

export async function claimReviewRevisionWork(outboxStore, reviewStore, workHmac, authorization,
  env = process.env, adapters = {}) {
  requireOutbox(env);
  const now = nowFrom(adapters);
  hex64(workHmac, 'Revision work HMAC');
  const workerSha = await authorizeInternalWorker(adapters, authorization, 'CLAIM', workHmac, now);
  const entry = await readWorkEntry(outboxStore, workHmac, env);
  const source = (await readReviewEntry(reviewStore, entry.record.source_invite_hmac_sha256, env)).record;
  assertWorkSourceLineage(entry.record, source);
  if (entry.record.state === 'COMPLETED') throw new Error('ARC_REVIEW_REVISION_WORK_COMPLETED');
  const replay = activeLeaseReplay(entry.record, workerSha, now, env);
  if (replay) return { ...replay, revision_input: revisionInput(entry.record, source) };
  if (['CLAIMED', 'ISSUING', 'EMAIL_READY'].includes(entry.record.state) &&
      Date.parse(entry.record.lease_expires_at) > now.getTime()) {
    throw new Error('ARC_REVIEW_REVISION_LEASE_ACTIVE');
  }
  const claimed = claimRecord(entry, workerSha, now, env);
  const replaced = await outboxStore.setJSON(reviewRevisionWorkKey(workHmac), claimed.record,
    { onlyIfMatch: entry.etag });
  if (!replaced?.modified) {
    const current = await readWorkEntry(outboxStore, workHmac, env);
    const converged = activeLeaseReplay(current.record, workerSha, now, env);
    if (converged) return { ...converged, revision_input: revisionInput(current.record, source) };
    throw new Error('ARC_REVIEW_REVISION_WORK_CONTENTION');
  }
  return {
    idempotent_replay: false,
    lease_expires_at: claimed.record.lease_expires_at,
    lease_token: claimed.token,
    record: claimed.record,
    revision_input: revisionInput(claimed.record, source),
  };
}

export async function claimNextReviewRevisionWork(outboxStore, reviewStore, cursor, authorization,
  env = process.env, adapters = {}) {
  requireOutbox(env);
  const now = nowFrom(adapters);
  const normalizedCursor = cursor === null || cursor === undefined ? null : hex64(cursor, 'Revision queue cursor');
  await authorizeInternalWorker(adapters, authorization, 'CLAIM_NEXT', '0'.repeat(64), now);
  if (typeof outboxStore.list !== 'function') throw new Error('ARC_REVIEW_REVISION_PENDING_INDEX_UNAVAILABLE');
  const listed = await outboxStore.list({ prefix: PENDING_KEY_PREFIX });
  const candidates = (Array.isArray(listed?.blobs) ? listed.blobs : [])
    .map(entry => entry?.key)
    .filter(key => typeof key === 'string' && key.startsWith(PENDING_KEY_PREFIX))
    .map(key => key.slice(PENDING_KEY_PREFIX.length))
    .filter(value => HEX_64.test(value) && (normalizedCursor === null || value > normalizedCursor))
    .sort();
  for (const workHmac of candidates) {
    try {
      const claimed = await claimReviewRevisionWork(outboxStore, reviewStore, workHmac,
        authorization, env, { ...adapters, clock: () => new Date(now) });
      return { ...claimed, next_cursor: workHmac };
    } catch (error) {
      if (/WORK_COMPLETED/.test(error?.message || '')) {
        await removePendingIndex(outboxStore, workHmac);
        continue;
      }
      if (/WORK_NOT_FOUND/.test(error?.message || '')) {
        const marker = await readPendingIndex(outboxStore, workHmac, env);
        try {
          await reserveReviewRevisionWork(outboxStore, reviewStore, marker.source_invite_hmac_sha256,
            authorization, env, { ...adapters, clock: () => new Date(now) });
          const recovered = await claimReviewRevisionWork(outboxStore, reviewStore, workHmac,
            authorization, env, { ...adapters, clock: () => new Date(now) });
          return { ...recovered, next_cursor: workHmac };
        } catch (recoveryError) {
          if (/SOURCE_NOT_READY/.test(recoveryError?.message || '')) continue;
          throw recoveryError;
        }
      }
      if (/LEASE_ACTIVE|WORK_CONTENTION/.test(error?.message || '')) continue;
      throw error;
    }
  }
  return { empty: true, next_cursor: null };
}

function normalizeCompletionInput(input) {
  exactKeys(input, COMPLETION_INPUT_FIELDS, 'Revision completion');
  if (typeof input.lease_token !== 'string' || !LEASE_TOKEN.test(input.lease_token) ||
      !REPOSITORY.test(input.successor_repository)) throw new TypeError('Revision completion is invalid.');
  return {
    lease_token: input.lease_token,
    successor_repository: input.successor_repository,
    successor_commit_sha: commitSha(input.successor_commit_sha, 'Proposed successor commit'),
    successor_manifest_sha256: hex64(input.successor_manifest_sha256, 'Proposed successor manifest'),
  };
}

function verifyLease(record, workerSha, leaseToken, now, env) {
  if (!['CLAIMED', 'ISSUING', 'EMAIL_READY'].includes(record.state)) {
    throw new Error('ARC_REVIEW_REVISION_LEASE_REQUIRED');
  }
  if (Date.parse(record.lease_expires_at) <= now.getTime()) throw new Error('ARC_REVIEW_REVISION_LEASE_EXPIRED');
  if (record.lease_worker_sha256 !== workerSha) throw new Error('ARC_REVIEW_REVISION_LEASE_OWNER_INVALID');
  const supplied = hmacHex(env[REVIEW_REVISION_OUTBOX_SECRET_ENV], LEASE_TOKEN_DIGEST_PREFIX + leaseToken);
  if (!safeEqual(supplied, record.lease_token_hmac_sha256) || !safeEqual(leaseToken, leaseTokenFor(record, env))) {
    throw new Error('ARC_REVIEW_REVISION_LEASE_INVALID');
  }
  return supplied;
}

function unsignedArtifactEvidence(value) {
  const { authority_hmac_sha256: _signature, ...unsigned } = value;
  return unsigned;
}

async function authoritativeArtifactEvidence(work, source, input, env, adapters) {
  if (typeof adapters.verifySuccessorArtifacts !== 'function') {
    throw new Error('ARC_REVIEW_REVISION_SUPPLY_CHAIN_UNAVAILABLE');
  }
  const evidence = await adapters.verifySuccessorArtifacts({
    schema: 'arc-preview-revision-artifact-verification-request-v1',
    work_hmac_sha256: work.work_hmac_sha256,
    source_invite_hmac_sha256: work.source_invite_hmac_sha256,
    source_repository: work.source_repository,
    source_commit_sha: work.source_commit_sha,
    source_manifest_sha256: work.source_manifest_sha256,
    source_page_bindings_sha256: work.source_page_bindings_sha256,
    revision_notes: source.decision.revision_notes,
    revision_notes_sha256: work.revision_notes_sha256,
    target_revision_round: work.target_revision_round,
    expected_repository: input.successor_repository,
    expected_commit_sha: input.successor_commit_sha,
    expected_manifest_sha256: input.successor_manifest_sha256,
  });
  exactKeys(evidence, ARTIFACT_EVIDENCE_FIELDS, 'Artifact verification evidence');
  if (evidence.schema !== REVIEW_REVISION_ARTIFACT_EVIDENCE_SCHEMA) {
    throw new TypeError('Artifact verification evidence is invalid.');
  }
  hex64(evidence.authority_hmac_sha256, 'Artifact authority signature');
  const expectedSignature = hmacHex(env[REVIEW_REVISION_SUPPLY_CHAIN_SECRET_ENV],
    REVIEW_REVISION_ARTIFACT_EVIDENCE_SIGNATURE_PREFIX + canonicalJson(unsignedArtifactEvidence(evidence)));
  if (!safeEqual(expectedSignature, evidence.authority_hmac_sha256)) {
    throw new Error('ARC_REVIEW_REVISION_SUPPLY_CHAIN_EVIDENCE_INVALID');
  }
  if (evidence.work_hmac_sha256 !== work.work_hmac_sha256 ||
      evidence.source_invite_hmac_sha256 !== work.source_invite_hmac_sha256 ||
      evidence.source_repository !== work.source_repository || evidence.source_commit_sha !== work.source_commit_sha ||
      evidence.source_manifest_sha256 !== work.source_manifest_sha256 ||
      evidence.source_page_bindings_sha256 !== work.source_page_bindings_sha256 ||
      evidence.target_revision_round !== work.target_revision_round ||
      evidence.repository !== input.successor_repository || evidence.repository !== work.source_repository ||
      evidence.commit_sha !== input.successor_commit_sha ||
      evidence.manifest_sha256 !== input.successor_manifest_sha256) {
    throw new Error('ARC_REVIEW_REVISION_SUPPLY_CHAIN_BINDING_INVALID');
  }
  commitSha(evidence.commit_sha, 'Verified successor commit');
  hex64(evidence.manifest_sha256, 'Verified successor manifest');
  hex64(evidence.content_sha256, 'Verified successor content');
  const pages = normalizePageBindings(evidence.page_bindings, 'Verified page bindings');
  const previewUrl = normalizePreviewUrl(evidence.preview_url, env);
  isoTimestamp(evidence.verified_at, 'Artifact verification timestamp');
  if (Date.parse(evidence.verified_at) < Date.parse(work.reserved_at) ||
      evidence.commit_sha === work.source_commit_sha || evidence.manifest_sha256 === work.source_manifest_sha256 ||
      evidence.content_sha256 === work.source_content_sha256) {
    throw new Error('ARC_REVIEW_REVISION_SUPPLY_CHAIN_BINDING_INVALID');
  }
  return { ...evidence, page_bindings: pages, preview_url: previewUrl };
}

function unsignedInviteReservation(value) {
  const { reservation_hmac_sha256: _signature, ...unsigned } = value;
  return unsigned;
}

async function authoritativeInviteReservation(work, source, evidence, issuanceGeneration,
  replacesInviteHmac, env, adapters) {
  if (typeof adapters.reserveSuccessorInvite !== 'function') {
    throw new Error('ARC_REVIEW_REVISION_INVITE_RESERVATION_UNAVAILABLE');
  }
  const reservation = await adapters.reserveSuccessorInvite({
    schema: 'arc-preview-revision-invite-reservation-request-v1',
    idempotency_key: issuanceGeneration === 1
      ? `arc_review_revision_${work.work_hmac_sha256}`
      : `arc_review_revision_${work.work_hmac_sha256}_renew_${issuanceGeneration}`,
    work_hmac_sha256: work.work_hmac_sha256,
    artifact_authority_hmac_sha256: evidence.authority_hmac_sha256,
    recipient_email_sha256: source.recipient_email_sha256,
    issuance_generation: issuanceGeneration,
    replaces_invite_hmac_sha256: replacesInviteHmac,
    target_revision_round: work.target_revision_round,
  });
  exactKeys(reservation, INVITE_RESERVATION_FIELDS, 'Successor invite reservation');
  if (reservation.schema !== REVIEW_REVISION_INVITE_RESERVATION_SCHEMA ||
      reservation.work_hmac_sha256 !== work.work_hmac_sha256 ||
      reservation.artifact_authority_hmac_sha256 !== evidence.authority_hmac_sha256) {
    throw new Error('ARC_REVIEW_REVISION_INVITE_RESERVATION_INVALID');
  }
  if (typeof reservation.invite_token !== 'string' || !TOKEN.test(reservation.invite_token)) {
    throw new TypeError('Successor invite reservation token is invalid.');
  }
  isoTimestamp(reservation.expires_at, 'Successor invite expiration');
  isoTimestamp(reservation.reserved_at, 'Successor invite reservation timestamp');
  hex64(reservation.email_delivery_receipt_sha256, 'Successor email reservation receipt');
  hex64(reservation.reservation_hmac_sha256, 'Successor invite reservation signature');
  const expected = hmacHex(env[REVIEW_REVISION_INVITE_RESERVATION_SECRET_ENV],
    REVIEW_REVISION_INVITE_RESERVATION_SIGNATURE_PREFIX + canonicalJson(unsignedInviteReservation(reservation)));
  if (!safeEqual(expected, reservation.reservation_hmac_sha256)) {
    throw new Error('ARC_REVIEW_REVISION_INVITE_RESERVATION_INVALID');
  }
  return reservation;
}

function planFrom(evidence, reservation, now, env, issuanceGeneration = 1, replacedInviteHmac = null) {
  return {
    successor_repository: evidence.repository,
    successor_commit_sha: evidence.commit_sha,
    successor_manifest_sha256: evidence.manifest_sha256,
    successor_content_sha256: evidence.content_sha256,
    successor_page_bindings_sha256: pageBindingsSha256(evidence.page_bindings),
    successor_preview_url_sha256: sha256Hex(evidence.preview_url),
    successor_invite_hmac_sha256: inviteHmacForToken(reservation.invite_token, env),
    successor_invite_expires_at: reservation.expires_at,
    successor_email_delivery_receipt_sha256: reservation.email_delivery_receipt_sha256,
    artifact_authority_hmac_sha256: evidence.authority_hmac_sha256,
    invite_reservation_hmac_sha256: reservation.reservation_hmac_sha256,
    issuance_planned_at: now.toISOString(),
    issuance_generation: issuanceGeneration,
    replaced_successor_invite_hmac_sha256: replacedInviteHmac,
  };
}

function samePlan(record, plan) {
  return Object.entries(plan).every(([key, value]) => key === 'issuance_planned_at' || record[key] === value);
}

function assertPlanEvidence(record, evidence, reservation, env) {
  const recovered = planFrom(evidence, reservation, new Date(record.issuance_planned_at), env,
    record.issuance_generation, record.replaced_successor_invite_hmac_sha256);
  if (!samePlan(record, recovered) || record.issuance_planned_at !== recovered.issuance_planned_at) {
    throw new Error('ARC_REVIEW_REVISION_ISSUANCE_PLAN_CONFLICT');
  }
}

function sameCompletion(record, input, workerSha, env) {
  const leaseDigest = hmacHex(env[REVIEW_REVISION_OUTBOX_SECRET_ENV],
    LEASE_TOKEN_DIGEST_PREFIX + input.lease_token);
  return record.state === 'COMPLETED' && record.successor_repository === input.successor_repository &&
    record.successor_commit_sha === input.successor_commit_sha &&
    record.successor_manifest_sha256 === input.successor_manifest_sha256 &&
    record.completion_worker_sha256 === workerSha &&
    safeEqual(record.completion_lease_token_hmac_sha256, leaseDigest);
}

function successorInviteMatchesPlan(invite, work) {
  return invite.invite_hmac_sha256 === work.successor_invite_hmac_sha256 &&
    invite.prior_invite_hmac_sha256 === work.source_invite_hmac_sha256 &&
    invite.revision_round === work.target_revision_round && invite.state === 'OPEN' && invite.decision === null &&
    invite.preview_source_repository === work.successor_repository &&
    invite.preview_source_commit_sha === work.successor_commit_sha &&
    invite.preview_manifest_sha256 === work.successor_manifest_sha256 &&
    invite.preview_content_sha256 === work.successor_content_sha256 &&
    pageBindingsSha256(invite.page_bindings) === work.successor_page_bindings_sha256 &&
    sha256Hex(invite.preview_url) === work.successor_preview_url_sha256 &&
    invite.expires_at === work.successor_invite_expires_at;
}

async function assertExpiredPlanRenewable(reviewStore, work, source, renewalBaseHmac, env, now) {
  if (Date.parse(work.successor_invite_expires_at) > now.getTime()) {
    throw new Error('ARC_REVIEW_REVISION_RENEWAL_NOT_REQUIRED');
  }
  let oldInvite = null;
  try {
    oldInvite = (await readReviewEntry(reviewStore, renewalBaseHmac, env)).record;
  } catch (error) {
    if (error?.message !== 'ARC_REVIEW_INVITE_NOT_FOUND') throw error;
  }
  if (source.state === 'REVISION_SUPERSEDED') {
    if (source.successor_invite_hmac_sha256 !== renewalBaseHmac || !oldInvite || oldInvite.state !== 'OPEN' ||
        oldInvite.prior_invite_hmac_sha256 !== source.invite_hmac_sha256 ||
        oldInvite.session_nonce_hmac_sha256 !== null || oldInvite.exchanged_at !== null ||
        oldInvite.email_delivery_receipt_sha256 !== null || oldInvite.email_suppression_receipt_sha256 !== null ||
        Date.parse(oldInvite.expires_at) > now.getTime()) {
      throw new Error('ARC_REVIEW_REVISION_SUCCESSOR_NOT_RENEWABLE');
    }
  } else if (source.state !== 'REVISION_REQUESTED') {
    throw new Error('ARC_REVIEW_REVISION_SUCCESSOR_NOT_RENEWABLE');
  }
  const oldOutboxHmac = emailOutboxHmacForInvite(renewalBaseHmac, env);
  let oldOutbox = null;
  try {
    oldOutbox = (await readReviewEmailOutbox(reviewStore, oldOutboxHmac, env)).record;
  } catch (error) {
    if (error?.message !== 'ARC_REVIEW_EMAIL_OUTBOX_NOT_FOUND') throw error;
  }
  if (oldOutbox && (oldOutbox.state !== 'READY' || oldOutbox.invite_hmac_sha256 !== renewalBaseHmac ||
      Date.parse(oldOutbox.expires_at) > now.getTime())) {
    throw new Error('ARC_REVIEW_REVISION_SUCCESSOR_NOT_RENEWABLE');
  }
}

function successorInviteInput(work, source, evidence, reservation) {
  return {
    invite_token: reservation.invite_token,
    brief_sha256: source.brief_sha256,
    expires_at: reservation.expires_at,
    page_bindings: evidence.page_bindings,
    preview_content_sha256: evidence.content_sha256,
    preview_manifest_sha256: evidence.manifest_sha256,
    preview_source_commit_sha: evidence.commit_sha,
    preview_source_repository: evidence.repository,
    preview_url: evidence.preview_url,
    prior_invite_hmac_sha256: work.source_invite_hmac_sha256,
    recipient_email_sha256: source.recipient_email_sha256,
    scope_version: source.scope_version,
  };
}

async function prepareAndVerifySuccessorEmail(reviewStore, work, source, evidence, reservation, env, now) {
  const expectedOutboxHmac = emailOutboxHmacForInvite(work.successor_invite_hmac_sha256, env);
  let existingOutbox = null;
  try {
    existingOutbox = await readReviewEmailOutbox(reviewStore, expectedOutboxHmac, env);
  } catch (error) {
    if (error?.message !== 'ARC_REVIEW_EMAIL_OUTBOX_NOT_FOUND') throw error;
  }
  let preparedInviteHmac = null;
  if (!existingOutbox) {
    if (Date.parse(reservation.expires_at) <= now.getTime() ||
        Date.parse(reservation.expires_at) > now.getTime() + 30 * 24 * 60 * 60_000) {
      throw new Error('ARC_REVIEW_REVISION_INVITE_RESERVATION_EXPIRED');
    }
    const inviteInput = successorInviteInput(work, source, evidence, reservation);
    if (work.replaced_successor_invite_hmac_sha256 !== null && source.state === 'REVISION_SUPERSEDED' &&
        source.successor_invite_hmac_sha256 === work.replaced_successor_invite_hmac_sha256) {
      await renewExpiredReviewSuccessor(reviewStore, work.replaced_successor_invite_hmac_sha256,
        inviteInput, env, { clock: () => new Date(now) });
    }
    const prepared = await prepareReviewInviteEmail(reviewStore, inviteInput, env, {
      clock: () => new Date(now),
      sourceReferenceHmacSha256: work.work_hmac_sha256,
    });
    preparedInviteHmac = prepared.invite.invite_hmac_sha256;
  }
  const [linkedSource, successor, emailOutbox] = await Promise.all([
    readReviewEntry(reviewStore, work.source_invite_hmac_sha256, env),
    readReviewEntry(reviewStore, work.successor_invite_hmac_sha256, env),
    readReviewEmailOutbox(reviewStore, expectedOutboxHmac, env),
  ]);
  const next = successor.record;
  if (linkedSource.record.state !== 'REVISION_SUPERSEDED' ||
      linkedSource.record.successor_invite_hmac_sha256 !== work.successor_invite_hmac_sha256 ||
      linkedSource.record.record_revision <= work.source_record_revision ||
      !successorInviteMatchesPlan(next, work) ||
      ![null, emailOutbox.record.delivery_receipt_sha256].includes(next.email_delivery_receipt_sha256) ||
      ![null, 'signed-outbox'].includes(next.email_delivery_binding_mode) ||
      next.recipient_email_sha256 !== source.recipient_email_sha256 || next.brief_sha256 !== source.brief_sha256 ||
      next.scope_version !== source.scope_version || next.expires_at !== work.successor_invite_expires_at ||
      preparedInviteHmac !== null && preparedInviteHmac !== next.invite_hmac_sha256 ||
      emailOutbox.record.invite_hmac_sha256 !== next.invite_hmac_sha256 ||
      emailOutbox.record.recipient_email_sha256 !== next.recipient_email_sha256 ||
      emailOutbox.record.preview_manifest_sha256 !== next.preview_manifest_sha256 ||
      emailOutbox.record.expires_at !== next.expires_at ||
      ['BOUNCED', 'COMPLAINED'].includes(emailOutbox.record.state)) {
    throw new Error('ARC_REVIEW_REVISION_SUCCESSOR_LINK_INVALID');
  }
  if ((next.email_delivery_receipt_sha256 === null && emailOutbox.record.state === 'DELIVERED') ||
      (next.email_delivery_receipt_sha256 !== null &&
        (emailOutbox.record.state !== 'DELIVERED' ||
         next.email_delivery_receipt_sha256 !== emailOutbox.record.delivery_receipt_sha256 ||
         next.email_delivery_outbox_hmac_sha256 !== emailOutbox.record.outbox_hmac_sha256))) {
    throw new Error('ARC_REVIEW_REVISION_SUCCESSOR_EMAIL_BINDING_INVALID');
  }
  return { invite: next, outbox: emailOutbox.record };
}

export async function completeReviewRevisionWork(outboxStore, reviewStore, workHmac, authorization, input,
  env = process.env, adapters = {}) {
  requireOutbox(env);
  const now = nowFrom(adapters);
  hex64(workHmac, 'Revision work HMAC');
  const normalized = normalizeCompletionInput(input);
  const workerSha = await authorizeInternalWorker(adapters, authorization, 'COMPLETE', workHmac, now);
  let entry = await readWorkEntry(outboxStore, workHmac, env);
  if (entry.record.state === 'COMPLETED') {
    if (sameCompletion(entry.record, normalized, workerSha, env)) {
      await removePendingIndex(outboxStore, workHmac);
      return { idempotent_replay: true, record: entry.record };
    }
    throw new Error('ARC_REVIEW_REVISION_COMPLETION_CONFLICT');
  }
  let source = (await readReviewEntry(reviewStore, entry.record.source_invite_hmac_sha256, env)).record;
  assertWorkSourceLineage(entry.record, source);
  const completionLeaseDigest = verifyLease(entry.record, workerSha, normalized.lease_token, now, env);
  const evidence = await authoritativeArtifactEvidence(entry.record, source, normalized, env, adapters);
  const expiredPlan = ['ISSUING', 'EMAIL_READY'].includes(entry.record.state) &&
    Date.parse(entry.record.successor_invite_expires_at) <= now.getTime();
  const replacedInviteHmac = expiredPlan
    ? (source.state === 'REVISION_SUPERSEDED'
      ? source.successor_invite_hmac_sha256 : entry.record.successor_invite_hmac_sha256)
    : entry.record.replaced_successor_invite_hmac_sha256;
  const issuanceGeneration = entry.record.state === 'CLAIMED'
    ? 1 : entry.record.issuance_generation + (expiredPlan ? 1 : 0);
  if (issuanceGeneration > 100) throw new Error('ARC_REVIEW_REVISION_RENEWAL_LIMIT');
  if (expiredPlan) {
    await assertExpiredPlanRenewable(reviewStore, entry.record, source, replacedInviteHmac, env, now);
  }
  const reservation = await authoritativeInviteReservation(entry.record, source, evidence,
    issuanceGeneration, replacedInviteHmac, env, adapters);

  if (entry.record.state === 'CLAIMED') {
    if (source.state !== 'REVISION_REQUESTED') throw new Error('ARC_REVIEW_REVISION_STALE_SUCCESSOR');
    const plan = planFrom(evidence, reservation, now, env, 1, null);
    const issuing = signWorkRecord({
      ...unsignedWorkRecord(entry.record),
      record_revision: entry.record.record_revision + 1,
      state: 'ISSUING',
      ...plan,
    }, env);
    validateReviewRevisionWorkRecord(issuing, env);
    const replaced = await outboxStore.setJSON(reviewRevisionWorkKey(workHmac), issuing, { onlyIfMatch: entry.etag });
    if (!replaced?.modified) {
      const current = await readWorkEntry(outboxStore, workHmac, env);
      if (current.record.state !== 'ISSUING' || !samePlan(current.record, plan) ||
          current.record.lease_worker_sha256 !== workerSha ||
          !safeEqual(current.record.lease_token_hmac_sha256, completionLeaseDigest)) {
        throw new Error('ARC_REVIEW_REVISION_WORK_CONTENTION');
      }
      entry = current;
    } else {
      entry = { record: issuing, etag: replaced.etag };
    }
  } else if (expiredPlan) {
    if (Date.parse(reservation.expires_at) <= now.getTime() ||
        inviteHmacForToken(reservation.invite_token, env) === entry.record.successor_invite_hmac_sha256 ||
        inviteHmacForToken(reservation.invite_token, env) === replacedInviteHmac) {
      throw new Error('ARC_REVIEW_REVISION_RENEWAL_INVALID');
    }
    const plan = planFrom(evidence, reservation, now, env, issuanceGeneration, replacedInviteHmac);
    const issuing = signWorkRecord({
      ...unsignedWorkRecord(entry.record),
      record_revision: entry.record.record_revision + 1,
      state: 'ISSUING',
      successor_email_outbox_hmac_sha256: null,
      completion_worker_sha256: null,
      completion_lease_token_hmac_sha256: null,
      completed_at: null,
      ...plan,
    }, env);
    validateReviewRevisionWorkRecord(issuing, env);
    const replaced = await outboxStore.setJSON(reviewRevisionWorkKey(workHmac), issuing,
      { onlyIfMatch: entry.etag });
    if (!replaced?.modified) {
      const current = await readWorkEntry(outboxStore, workHmac, env);
      if (current.record.state !== 'ISSUING' || !samePlan(current.record, plan) ||
          current.record.lease_worker_sha256 !== workerSha ||
          !safeEqual(current.record.lease_token_hmac_sha256, completionLeaseDigest)) {
        throw new Error('ARC_REVIEW_REVISION_WORK_CONTENTION');
      }
      entry = current;
    } else {
      entry = { record: issuing, etag: replaced.etag };
    }
  } else {
    if (!['ISSUING', 'EMAIL_READY'].includes(entry.record.state)) {
      throw new Error('ARC_REVIEW_REVISION_LEASE_REQUIRED');
    }
    assertPlanEvidence(entry.record, evidence, reservation, env);
  }

  source = (await readReviewEntry(reviewStore, entry.record.source_invite_hmac_sha256, env)).record;
  assertWorkSourceLineage(entry.record, source);
  const prepared = await prepareAndVerifySuccessorEmail(
    reviewStore, entry.record, source, evidence, reservation, env, now,
  );
  if (entry.record.state === 'ISSUING') {
    const emailReady = signWorkRecord({
      ...unsignedWorkRecord(entry.record),
      record_revision: entry.record.record_revision + 1,
      state: 'EMAIL_READY',
      successor_email_outbox_hmac_sha256: prepared.outbox.outbox_hmac_sha256,
    }, env);
    validateReviewRevisionWorkRecord(emailReady, env);
    const linked = await outboxStore.setJSON(reviewRevisionWorkKey(workHmac), emailReady,
      { onlyIfMatch: entry.etag });
    if (!linked?.modified) {
      const current = await readWorkEntry(outboxStore, workHmac, env);
      if (current.record.state !== 'EMAIL_READY' ||
          current.record.successor_email_outbox_hmac_sha256 !== prepared.outbox.outbox_hmac_sha256 ||
          current.record.lease_worker_sha256 !== workerSha ||
          !safeEqual(current.record.lease_token_hmac_sha256, completionLeaseDigest)) {
        throw new Error('ARC_REVIEW_REVISION_WORK_CONTENTION');
      }
      entry = current;
    } else {
      entry = { record: emailReady, etag: linked.etag };
    }
  } else if (entry.record.successor_email_outbox_hmac_sha256 !== prepared.outbox.outbox_hmac_sha256) {
    throw new Error('ARC_REVIEW_REVISION_SUCCESSOR_EMAIL_OUTBOX_CONFLICT');
  }
  const completed = signWorkRecord({
    ...unsignedWorkRecord(entry.record),
    record_revision: entry.record.record_revision + 1,
    state: 'COMPLETED',
    lease_worker_sha256: null,
    lease_token_hmac_sha256: null,
    lease_claimed_at: null,
    lease_expires_at: null,
    completion_worker_sha256: workerSha,
    completion_lease_token_hmac_sha256: completionLeaseDigest,
    completed_at: now.toISOString(),
  }, env);
  validateReviewRevisionWorkRecord(completed, env);
  const replaced = await outboxStore.setJSON(reviewRevisionWorkKey(workHmac), completed, { onlyIfMatch: entry.etag });
  if (!replaced?.modified) {
    const current = await readWorkEntry(outboxStore, workHmac, env);
    if (sameCompletion(current.record, normalized, workerSha, env)) {
      await removePendingIndex(outboxStore, workHmac);
      return { idempotent_replay: true, record: current.record };
    }
    throw new Error('ARC_REVIEW_REVISION_WORK_CONTENTION');
  }
  await removePendingIndex(outboxStore, workHmac);
  return {
    idempotent_replay: false,
    record: completed,
    successor_invite_hmac_sha256: completed.successor_invite_hmac_sha256,
  };
}
