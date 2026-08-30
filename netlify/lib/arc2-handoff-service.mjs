import { createHmac } from 'node:crypto';
import {
  ARC2_PRECLAIM_HEADERS_FILE,
  CLAIM_STATE_EVIDENCE_SCOPE,
  CLAIM_STATE_EVIDENCE_VERSION,
  CLAIM_STATE_SIGNATURE_PREFIX,
  CLAIM_JWT_TTL_SECONDS,
  CLAIM_TOKEN_TTL_SECONDS,
  FINAL_DELIVERY_PROVIDER_EVENT_ID_PREFIX,
  FINAL_DELIVERY_PROVIDER_MESSAGE_ID_PREFIX,
  FINAL_DELIVERY_RECEIPT_SCOPE,
  FINAL_DELIVERY_RECEIPT_SIGNATURE_PREFIX,
  FINAL_DELIVERY_RECEIPT_VERSION,
  OUTBOX_CLAIM_VERSION,
  canonicalNetlifySiteUrl,
  canonicalJson,
  createClaimStateEvidence,
  createClaimableSite,
  createInitialRecord,
  createOutboxClaim,
  createStoredZip,
  deployArtifactsForPhase,
  deployZip,
  ensureEmailHook,
  findNetlifyForm,
  handoffIdFromKey,
  handoffKey,
  handoffKeyFromId,
  hmacHex,
  netlifyClaimUrl,
  normalizeClaimWebhook,
  normalizeProductionUrl,
  normalizeReviewStartPayload,
  normalizeStartPayload,
  netlifyRequest,
  pollDeployReady,
  publicStatus,
  readNetlifyJsonBounded,
  reviseRecord,
  safeEqual,
  sha256Hex,
  siteIndexKey,
  transitionRecord,
  validateExpectedBindings,
  verifyNetlifyHandoff,
} from './arc2-handoff-core.mjs';
import {
  createEntry,
  createIndex,
  readEntry,
  readIndex,
  readIndexEntry,
  replaceEntry,
  replaceIndex,
} from './arc2-handoff-store.mjs';
import {
  STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS,
  assertHandoffFulfillmentAllowed,
} from './stripe-reversal-core.mjs';
import {
  STRIPE_REVIEW_CHECKOUT_HANDOFF_BINDING_SCHEMA,
  assertHandoffStripeCheckoutPaid,
  bindStripeReviewCheckoutToHandoff,
  bindStripeCheckoutToHandoff,
} from './stripe-checkout-core.mjs';
import { readReviewEmailRecipientControl } from './review-email-recipient-control-core.mjs';
import { assertReviewCheckoutFulfillmentAllowed } from './review-checkout-revocation-core.mjs';
import { assertArc2EmailNegativeStateAllows } from './arc2-negative-email-state-core.mjs';
import { sensitiveCredentialsAreIsolated } from './sensitive-credential-isolation.mjs';
import {
  assertClaimSandboxBootstrapBound,
  claimSandboxBootstrapConfiguration,
  reserveClaimSandboxBootstrap,
} from './claim-sandbox-bootstrap-core.mjs';

const LEAD_ROUTE_RECEIPT_VERSION = 'arc2-lead-route-inbox-receipt-v1';
const LEAD_ROUTE_RECEIPT_SCOPE = 'authoritative-lead-route-inbox-receipt';
const LEAD_ROUTE_RECEIPT_PREFIX = 'arc2-lead-route-inbox-receipt-signature-v1\n';
const PRODUCER_LEAD_ROUTE_VERSION = 'arc-lead-route-evidence-v1';
const PRODUCER_LEAD_ROUTE_SCOPE = 'arc-controlled-netlify-staging';
const PRODUCER_LEAD_ROUTE_PREFIX = 'arc-lead-route-evidence-signature-v1\n';
const CLAIM_BEARER_DERIVATION_PREFIX = 'arc2-claim-bearer-derivation-v1\n';
const CLAIM_BEARER_STORAGE_PREFIX = 'arc2-claim-bearer-at-rest-v1\n';
const CLAIM_INVITATION_RENEWAL_OPERATION_PREFIX = 'arc2-claim-invitation-renewal-operation-v1\n';
const INVITATION_READY_OUTBOX_VERSION = 'arc2-claim-invitation-ready-outbox-v2';
const INVITATION_CURRENT_VERSION = 'arc2-claim-invitation-current-v1';
const RECEIPT_FRESHNESS_MS = 10 * 60_000;
const PRODUCER_SOURCE_FRESHNESS_MS = 30 * 60_000;
const PRODUCER_EXTERNAL_ID_PATTERN = /^(?:[a-f0-9]{24}|[a-f0-9]{40}|[a-f0-9]{8}-[a-f0-9]{4}-[1-5a-f][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/;
const PRODUCER_LEAD_ROUTE_FIELDS = Object.freeze([
  'version', 'scope', 'preview_folder', 'production_content_sha256', 'artifact_manifest_sha256',
  'handoff_artifact_evidence_sha256', 'bundle_fingerprint', 'netlify_account_id', 'staging_site_id',
  'staging_site_url', 'staging_deploy_id', 'staging_deploy_url', 'deploy_file_manifest_sha256',
  'served_html_sha256', 'staging_robots_header_sha256', 'staging_form_id', 'notification_hook_id',
  'form_name', 'recipient_hmac_sha256', 'synthetic_submission_id', 'synthetic_probe_sha256',
  'netlify_submission_timestamp', 'inbox_provider', 'inbox_account_hmac_sha256',
  'inbox_message_id_hmac_sha256', 'inbox_received_timestamp', 'inbox_receipt_evidence_sha256',
]);
const FINAL_DELIVERY_RECEIPT_FIELDS = Object.freeze([
  'delivered_at',
  'delivery_status',
  'event_type',
  'handoff_id',
  'issued_at',
  'netlify_deploy_id_sha256',
  'netlify_site_id_sha256',
  'outbox_claim_key_hmac_sha256',
  'production_url_sha256',
  'provider',
  'provider_account_hmac_sha256',
  'provider_event_id',
  'provider_message_id',
  'recipient_email_sha256',
  'scope',
  'version',
]);
const FINAL_DELIVERY_EVENT_INDEX_SCHEMA = 'arc2-final-delivery-provider-event-index-v1';
const FINAL_DELIVERY_MESSAGE_INDEX_SCHEMA = 'arc2-final-delivery-provider-message-index-v1';
const LEGACY_SITE_NAME_PATTERN = /^arc-[a-f0-9]{24}$/;
const PRE_INVITATION_STATES = new Set([
  'PAYMENT_VERIFIED',
  'SITE_INTENT',
  'SITE_CREATED',
  'PRECLAIM_DEPLOY_READY',
  'LEAD_ROUTE_VERIFIED',
]);

const PROVIDER_STAGE_BUDGET_MS = 8_000;
export const REVIEW_HANDOFF_START_RECEIPT_SCHEMA = 'arc2-review-handoff-start-receipt-v2';
export const REVIEW_HANDOFF_START_RECEIPT_PREFIX = 'arc2-review-handoff-start-receipt-signature-v2\n';

function providerStageDeadline(adapters) {
  if (Number.isFinite(adapters.providerStageDeadlineMs)) return adapters.providerStageDeadlineMs;
  return Date.now() + PROVIDER_STAGE_BUDGET_MS;
}

function providerStageWait(adapters, deadlineMs) {
  const custom = adapters.wait;
  return async (attempt) => {
    const nowMs = Date.now();
    const delayMs = Math.min(250 * (2 ** attempt), 1000);
    if (!Number.isFinite(nowMs) || nowMs + delayMs > deadlineMs) throw new Error('ARC2_PROVIDER_STAGE_DEADLINE');
    if (custom) return custom(attempt);
    return new Promise((resolve) => setTimeout(resolve, delayMs));
  };
}

function exactReplay(record, normalized) {
  return record.payment_evidence_sha256 === normalized.payment.digest &&
    record.artifact_evidence_sha256 === normalized.artifact.digest &&
    record.bundle_fingerprint === normalized.artifact.value.bundle_fingerprint &&
    record.lead_notification_email_sha256 === normalized.leadEmailHash &&
    (record.lead_route_recipient_hmac_sha256 === null ||
      record.lead_route_recipient_hmac_sha256 === normalized.leadRouteRecipientHmacSha256) &&
    record.form_name === normalized.formName && record.lead_route_mode === normalized.artifact.value.lead_route_mode;
}

function rejectQuarantinedLegacyNamespace(record) {
  if (LEGACY_SITE_NAME_PATTERN.test(record.netlify_site_name) && PRE_INVITATION_STATES.has(record.state)) {
    throw new Error('ARC2_LEGACY_SITE_NAMESPACE_QUARANTINED');
  }
}

function checkoutSessionIndexKey(paymentEvidence, env) {
  const digest = hmacHex(env.ARC_HANDOFF_STATE_SECRET, `checkout-session-index-v1\n${paymentEvidence.checkout_session_id}`);
  return `checkout-session-index/${digest}`;
}

function checkoutSessionIndexValue(handoffId, normalized) {
  return {
    schema: 'arc2-checkout-session-index-v1',
    handoff_id: handoffId,
    payment_evidence_sha256: normalized.payment.digest,
    artifact_evidence_sha256: normalized.artifact.digest,
    bundle_fingerprint: normalized.artifact.value.bundle_fingerprint,
  };
}

function checkoutReferenceIndexKey(paymentEvidence, env) {
  const digest = hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `checkout-reference-index-v1\n${paymentEvidence.client_reference_id_sha256}`);
  return `checkout-reference-index/${digest}`;
}

function checkoutReferenceIndexValue(handoffId, normalized) {
  return {
    schema: 'arc2-checkout-reference-index-v1',
    client_reference_id_sha256: normalized.payment.value.client_reference_id_sha256,
    winning_checkout_session_id: normalized.payment.value.checkout_session_id,
    winning_payment_link_id_hmac_sha256: hmacHex(normalized.payment.selectedCheckoutBindingSecret,
      `arc2-payment-link-review-id-v1\n${normalized.payment.stripeMode}\n${normalized.payment.value.payment_link_id}`),
    handoff_id: handoffId,
    preview_source_commit_sha: normalized.payment.value.preview_source_commit_sha,
    payment_evidence_sha256: normalized.payment.digest,
    artifact_evidence_sha256: normalized.artifact.digest,
  };
}

function reviewCheckoutReferenceIndexValue(handoffId, normalized) {
  return {
    schema: 'arc2-review-checkout-reference-index-v1',
    client_reference_id_sha256: normalized.payment.value.client_reference_id_sha256,
    checkout_session_id_hmac_sha256: normalized.payment.value.checkout_session_id_hmac_sha256,
    payment_intent_id_hmac_sha256: normalized.payment.value.payment_intent_id_hmac_sha256,
    payment_link_id_hmac_sha256: null,
    bridge_immutable_binding_sha256: normalized.payment.value.bridge_immutable_binding_sha256,
    review_session_binding_sha256: normalized.payment.value.review_session_binding_sha256,
    handoff_id: handoffId,
    preview_source_commit_sha: normalized.payment.value.preview_source_commit_sha,
    payment_evidence_sha256: normalized.payment.digest,
    artifact_evidence_sha256: normalized.artifact.digest,
  };
}

function reviewDuplicatePaymentValue(winner, normalized, env) {
  const unsigned = {
    schema: 'arc2-review-duplicate-payment-review-v1',
    status: 'CRITICAL_DUPLICATE_PAID_SESSION_REVIEW_REQUIRED',
    automatic_refund_requested: false,
    checkout_reference_sha256: normalized.payment.value.client_reference_id_sha256,
    winning_checkout_session_id_hmac_sha256: winner.checkout_session_id_hmac_sha256,
    duplicate_checkout_session_id_hmac_sha256: normalized.payment.value.checkout_session_id_hmac_sha256,
    winning_payment_link_id_hmac_sha256: null,
    duplicate_payment_link_id_hmac_sha256: null,
    winning_handoff_id: winner.handoff_id,
    winning_payment_evidence_sha256: winner.payment_evidence_sha256,
    winning_artifact_evidence_sha256: winner.artifact_evidence_sha256,
    duplicate_payment_evidence_sha256: normalized.payment.digest,
  };
  return {
    ...unsigned,
    review_hmac_sha256: hmacHex(env.ARC_HANDOFF_STATE_SECRET,
      `arc2-review-duplicate-payment-review-signature-v1\n${canonicalJson(unsigned)}`),
  };
}

function duplicateCheckoutSessionIdHmac(normalized, env) {
  return hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `duplicate-payment-session-id-v1\n${normalized.payment.value.checkout_session_id}`);
}

export function duplicatePaymentReviewKey(normalized, env) {
  const duplicateCheckoutSessionIdHmacSha256 = duplicateCheckoutSessionIdHmac(normalized, env);
  const digest = hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `duplicate-payment-review-key-v1\n${normalized.payment.value.client_reference_id_sha256}\n${duplicateCheckoutSessionIdHmacSha256}`);
  return `duplicate-payment-review/${digest}`;
}

export function duplicatePaymentReviewValue(winner, normalized, env) {
  const unsigned = {
    schema: 'arc2-duplicate-payment-review-v1',
    status: 'CRITICAL_DUPLICATE_PAID_SESSION_REVIEW_REQUIRED',
    automatic_refund_requested: false,
    checkout_reference_sha256: normalized.payment.value.client_reference_id_sha256,
    winning_checkout_session_id_hmac_sha256: hmacHex(env.ARC_HANDOFF_STATE_SECRET,
      `duplicate-payment-session-id-v1\n${winner.winning_checkout_session_id}`),
    duplicate_checkout_session_id_hmac_sha256: duplicateCheckoutSessionIdHmac(normalized, env),
    winning_payment_link_id_hmac_sha256: winner.winning_payment_link_id_hmac_sha256,
    duplicate_payment_link_id_hmac_sha256: hmacHex(normalized.payment.selectedCheckoutBindingSecret,
      `arc2-payment-link-review-id-v1\n${normalized.payment.stripeMode}\n${normalized.payment.value.payment_link_id}`),
    winning_handoff_id: winner.handoff_id,
    winning_payment_evidence_sha256: winner.payment_evidence_sha256,
    winning_artifact_evidence_sha256: winner.artifact_evidence_sha256,
    duplicate_payment_evidence_sha256: normalized.payment.digest,
  };
  return {
    ...unsigned,
    review_hmac_sha256: hmacHex(env.ARC_HANDOFF_STATE_SECRET,
      `arc2-duplicate-payment-review-signature-v1\n${canonicalJson(unsigned)}`),
  };
}

function exactObjectKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function sha256(value, label) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) throw new TypeError(`${label} must be lowercase SHA-256.`);
  return value;
}

function identifier(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function iso(value, label) {
  if (typeof value !== 'string' || new Date(value).toISOString() !== value) throw new TypeError(`${label} is invalid.`);
  return value;
}

async function ensureImmutableIndex(store, key, value) {
  const existing = await readIndex(store, key);
  if (existing) {
    if (canonicalJson(existing) !== canonicalJson(value)) throw new Error('ARC2_INDEX_CONFLICT');
    return existing;
  }
  try {
    await createIndex(store, key, value);
    return value;
  } catch (error) {
    if (error.message !== 'ARC2_INDEX_CONFLICT') throw error;
    const raced = await readIndex(store, key);
    if (!raced || canonicalJson(raced) !== canonicalJson(value)) throw error;
    return raced;
  }
}

function remainingStageTimeout(deadlineMs) {
  if (!Number.isFinite(deadlineMs)) return undefined;
  const remainingMs = Math.floor(deadlineMs - Date.now());
  if (remainingMs <= 0) throw new Error('ARC2_PROVIDER_STAGE_DEADLINE');
  return Math.min(10_000, remainingMs);
}

async function netlifyJson(path, env, fetchImpl, deadlineMs) {
  const timeoutMs = remainingStageTimeout(deadlineMs);
  const response = await netlifyRequest(path, { method: 'GET' }, env, fetchImpl, timeoutMs);
  const maximumBytes = /\/hooks(?:\?|$)|\/deploys(?:\?|$)/.test(path) ? 1_000_000 : 256_000;
  return readNetlifyJsonBounded(response, maximumBytes, `Netlify ${path} response`);
}

async function assertProviderMutationAllowed(record, env, adapters, operation) {
  if (typeof adapters.beforeProviderMutation === 'function') {
    await adapters.beforeProviderMutation(operation, record);
  }
  const clock = adapters.clock || (() => new Date());
  await assertCheckoutAndReversalAllowed(record, env, adapters, { now: clock() });
}

async function assertCheckoutAndReversalAllowed(record, env, adapters, reversalOptions = {}) {
  const checkout = await assertHandoffStripeCheckoutPaid(
    adapters.store,
    record.handoff_id,
    record.payment_evidence_sha256,
    env,
    { accountFetch: adapters.stripeAccountFetch },
  );
  const reviewBinding = checkout.binding?.schema === STRIPE_REVIEW_CHECKOUT_HANDOFF_BINDING_SCHEMA;
  const assertReviewAuthority = async () => {
    if (!reviewBinding) return;
    if (!adapters.reviewStore?.getWithMetadata) {
      throw new Error('ARC_PAYMENT_ARC2_REVIEW_AUTHORITY_REQUIRED');
    }
    const binding = checkout.binding;
    const recipientControl = await readReviewEmailRecipientControl(
      adapters.reviewStore,
      binding.recipient_email_sha256,
      env,
    );
    if (!recipientControl || recipientControl.record.state !== 'ACTIVE' ||
        recipientControl.record.recipient_email_sha256 !== binding.recipient_email_sha256) {
      throw new Error('ARC_PAYMENT_ARC2_REVIEW_REQUIRED');
    }
    const authority = await assertReviewCheckoutFulfillmentAllowed(
      adapters.reviewStore,
      binding.approval_receipt_sha256,
      env,
    );
    const metadata = checkout.summary?.review_checkout_binding;
    const sessionIdHmac = hmacHex(
      env.ARC_STRIPE_REVERSAL_HMAC_SECRET,
      `stripe-checkout-session-id-v1\n${authority.session_id}`,
    );
    if (!metadata || authority.approval_receipt_sha256 !== binding.approval_receipt_sha256 ||
        authority.recipient_email_sha256 !== binding.recipient_email_sha256 ||
        authority.invite_hmac_sha256 !== metadata.invite_hmac_sha256 ||
        authority.preview_manifest_sha256 !== metadata.preview_manifest_sha256 ||
        authority.scope_version !== metadata.scope_version ||
        authority.session_livemode !== binding.livemode ||
        authority.integration_identifier !== env.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER ||
        !safeEqual(sessionIdHmac, binding.checkout_session_id_hmac_sha256)) {
      throw new Error('ARC_PAYMENT_ARC2_REVIEW_REQUIRED');
    }
  };
  await assertReviewAuthority();
  await assertHandoffFulfillmentAllowed(adapters.store, record.handoff_id, env, reversalOptions);
  // These authorities live in separate durable stores. Re-read the review
  // control after the Stripe reversal guard so a complaint/revocation racing
  // the payment check cannot authorize the following provider mutation.
  await assertReviewAuthority();
}

async function clearRetryableProviderIntent(adapters, key, entry, attemptedField, attemptedValue, completedField, clock) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (entry.record[completedField] || entry.record[attemptedField] === null) return entry;
    if (entry.record[attemptedField] !== attemptedValue) throw new Error('ARC2_PROVIDER_INTENT_CONTENTION');
    try {
      return await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { [attemptedField]: null }, clock()));
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 2) throw error;
      entry = await readEntry(adapters.store, key);
      if (!entry) throw new Error('ARC2_PROVIDER_INTENT_CONTENTION');
    }
  }
  throw new Error('ARC2_PROVIDER_INTENT_CONTENTION');
}

function validateSiteIntent(site, record, env, allowDestination = false) {
  if (!site || identifier(site.id, 'Netlify site id') !== site.id || site.name !== record.netlify_site_name || site.session_id !== record.netlify_session_id) {
    throw new Error('ARC2_SITE_INTENT_MISMATCH');
  }
  if (allowDestination) {
    if (site.account_id === record.netlify_source_account_id) throw new Error('ARC2_SITE_NOT_CLAIMED');
  } else if (site.account_id !== env.NETLIFY_TEAM_ACCOUNT_ID || site.account_slug !== env.NETLIFY_TEAM_SLUG) {
    throw new Error('ARC2_SITE_SOURCE_ACCOUNT_MISMATCH');
  }
  return site;
}

async function recoverSiteByIntent(record, env, fetchImpl, deadlineMs) {
  const query = new URLSearchParams({ name: record.netlify_site_name, filter: 'owner' });
  const sites = await netlifyJson(`/sites?${query}`, env, fetchImpl, deadlineMs);
  const matches = (Array.isArray(sites) ? sites : []).filter((site) => site?.name === record.netlify_site_name);
  if (matches.length > 1) throw new Error('ARC2_DUPLICATE_DETERMINISTIC_SITE');
  if (matches.length === 0) return null;
  const site = await netlifyJson(`/sites/${encodeURIComponent(identifier(matches[0].id, 'Netlify site id'))}`, env, fetchImpl, deadlineMs);
  return validateSiteIntent(site, record, env);
}

async function createOrRecoverSite(record, env, adapters) {
  const fetchImpl = adapters.fetch || fetch;
  const deadlineMs = providerStageDeadline(adapters);
  const wait = providerStageWait(adapters, deadlineMs);
  const existing = await recoverSiteByIntent(record, env, fetchImpl, deadlineMs);
  if (existing) return existing;
  await assertProviderMutationAllowed(record, env, adapters, 'create-site');
  try {
    return await createClaimableSite(record, env, fetchImpl, remainingStageTimeout(deadlineMs));
  } catch (cause) {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await wait(attempt);
      const recovered = await recoverSiteByIntent(record, env, fetchImpl, deadlineMs);
      if (recovered) return recovered;
    }
    throw new Error('ARC2_SITE_CREATE_AMBIGUOUS', { cause });
  }
}

function deployTitle(record, phase) {
  return `ARC ${phase} ${record.handoff_id.slice(0, 16)} ${record.bundle_fingerprint.slice(0, 12)}`;
}

async function recoverDeploy(record, phase, env, fetchImpl, deadlineMs) {
  const candidateId = record[`${phase}_deploy_candidate_id`];
  if (candidateId) return { id: identifier(candidateId, 'Netlify deploy candidate id'), site_id: record.netlify_site_id };
  const deploys = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}/deploys?per_page=100`, env, fetchImpl, deadlineMs);
  const title = deployTitle(record, phase);
  const matches = (Array.isArray(deploys) ? deploys : []).filter((deploy) => deploy?.site_id === record.netlify_site_id && deploy?.title === title);
  if (matches.length > 1) throw new Error(`ARC2_DUPLICATE_${phase.toUpperCase()}_DEPLOY`);
  if (matches.length === 0) return null;
  identifier(matches[0].id, 'Netlify deploy id');
  return matches[0];
}

async function ensurePublished(record, deployId, env, adapters, deadlineMs) {
  const fetchImpl = adapters.fetch || fetch;
  let site = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl, deadlineMs);
  if (site?.published_deploy?.id === deployId) return;
  await assertProviderMutationAllowed(record, env, adapters, 'restore-deploy');
  try {
    const response = await netlifyRequest(
      `/sites/${encodeURIComponent(record.netlify_site_id)}/deploys/${encodeURIComponent(deployId)}/restore`,
      { method: 'POST' },
      env,
      fetchImpl,
      remainingStageTimeout(deadlineMs),
    );
    // Consume even an empty success body so netlifyRequest can release its
    // bounded response timer. Ignoring the Response would leave that timer
    // armed until it aborted after the caller had already moved on.
    await response.arrayBuffer();
  } catch (cause) {
    site = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl, deadlineMs);
    if (site?.published_deploy?.id !== deployId) throw new Error('ARC2_DEPLOY_RESTORE_AMBIGUOUS', { cause });
    return;
  }
  site = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl, deadlineMs);
  if (site?.published_deploy?.id !== deployId) throw new Error('ARC2_DEPLOY_RESTORE_UNVERIFIED');
}

async function ensureDeploy(entry, key, artifacts, phase, env, adapters) {
  const fetchImpl = adapters.fetch || fetch;
  const deadlineMs = providerStageDeadline(adapters);
  const wait = providerStageWait(adapters, deadlineMs);
  const clock = adapters.clock || (() => new Date());
  const attemptedField = `${phase}_deploy_attempted_at`;
  const candidateField = `${phase}_deploy_candidate_id`;
  let candidate = await recoverDeploy(entry.record, phase, env, fetchImpl, deadlineMs);
  if (!candidate && entry.record[attemptedField]) {
    for (let attempt = 0; attempt < 5 && !candidate; attempt += 1) {
      await wait(attempt);
      candidate = await recoverDeploy(entry.record, phase, env, fetchImpl, deadlineMs);
    }
  }
  if (!candidate) {
    if (entry.record[attemptedField]) throw new Error(`ARC2_${phase.toUpperCase()}_DEPLOY_AMBIGUOUS`);
    await assertProviderMutationAllowed(entry.record, env, adapters, `preflight-create-${phase}-deploy`);
    const attemptedValue = clock().toISOString();
    entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { [attemptedField]: attemptedValue }, clock()));
    const zip = createStoredZip(deployArtifactsForPhase(artifacts, phase));
    try {
      await assertProviderMutationAllowed(entry.record, env, adapters, `create-${phase}-deploy`);
    } catch (error) {
      await clearRetryableProviderIntent(adapters, key, entry, attemptedField, attemptedValue, candidateField, clock);
      throw error;
    }
    let providerMutationEntered = false;
    const mutationFetch = (...args) => {
      providerMutationEntered = true;
      return fetchImpl(...args);
    };
    try {
      candidate = await deployZip(
        entry.record.netlify_site_id,
        zip,
        deployTitle(entry.record, phase),
        env,
        mutationFetch,
        remainingStageTimeout(deadlineMs),
      );
      entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { [candidateField]: candidate.id }, clock()));
    } catch (cause) {
      if (!providerMutationEntered) {
        await clearRetryableProviderIntent(adapters, key, entry, attemptedField, attemptedValue, candidateField, clock);
        throw cause;
      }
      for (let attempt = 0; attempt < 5 && !candidate; attempt += 1) {
        await wait(attempt);
        candidate = await recoverDeploy(entry.record, phase, env, fetchImpl, deadlineMs);
      }
      if (!candidate) throw new Error(`ARC2_${phase.toUpperCase()}_DEPLOY_AMBIGUOUS`, { cause });
    }
  }
  if (!entry.record[candidateField]) {
    entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { [candidateField]: candidate.id }, clock()));
  } else if (entry.record[candidateField] !== candidate.id) {
    throw new Error(`ARC2_${phase.toUpperCase()}_DEPLOY_CANDIDATE_CONFLICT`);
  }
  const ready = await pollDeployReady(entry.record.netlify_site_id, candidate.id, env, fetchImpl, {
    wait,
    deadlineMs,
    clock: adapters.clock,
  });
  await ensurePublished(entry.record, ready.id, env, adapters, deadlineMs);
  return { entry, ready };
}

async function recoverEmailHook(siteId, formId, leadEmail, env, fetchImpl, deadlineMs) {
  const hooks = await netlifyJson(`/hooks?site_id=${encodeURIComponent(siteId)}`, env, fetchImpl, deadlineMs);
  const forForm = (Array.isArray(hooks) ? hooks : []).filter((hook) => hook?.site_id === siteId && hook?.form_id === formId &&
    hook?.type === 'email' && hook?.event === 'submission_created' && hook?.disabled !== true);
  if (forForm.some((hook) => String(hook.data?.email || '').trim().toLowerCase() !== leadEmail)) throw new Error('ARC2_EMAIL_HOOK_CONFLICT');
  if (forForm.length > 1) throw new Error('ARC2_DUPLICATE_EMAIL_HOOK');
  return forForm[0] || null;
}

async function ensureLeadHook(entry, key, leadEmail, env, adapters) {
  const fetchImpl = adapters.fetch || fetch;
  const deadlineMs = providerStageDeadline(adapters);
  const wait = providerStageWait(adapters, deadlineMs);
  const clock = adapters.clock || (() => new Date());
  const form = await findNetlifyForm(entry.record.netlify_site_id, entry.record.form_name, env, fetchImpl, {
    wait,
    deadlineMs,
    clock: adapters.clock,
  });
  let hook = await recoverEmailHook(entry.record.netlify_site_id, form.id, leadEmail, env, fetchImpl, deadlineMs);
  if (!hook && entry.record.email_hook_attempted_at) {
    for (let attempt = 0; attempt < 5 && !hook; attempt += 1) {
      await wait(attempt);
      hook = await recoverEmailHook(entry.record.netlify_site_id, form.id, leadEmail, env, fetchImpl, deadlineMs);
    }
  }
  if (!hook) {
    if (entry.record.email_hook_attempted_at) throw new Error('ARC2_EMAIL_HOOK_CREATE_AMBIGUOUS');
    await assertProviderMutationAllowed(entry.record, env, adapters, 'preflight-create-email-hook');
    const attemptedValue = clock().toISOString();
    entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { email_hook_attempted_at: attemptedValue }, clock()));
    let providerMutationEntered = false;
    try {
      hook = await ensureEmailHook(entry.record.netlify_site_id, form.id, leadEmail, env, fetchImpl, {
        deadlineMs,
        beforeMutation: async () => {
          await assertProviderMutationAllowed(entry.record, env, adapters, 'create-email-hook');
        },
        onMutationFetch: () => { providerMutationEntered = true; },
      });
    } catch (cause) {
      if (!providerMutationEntered) {
        await clearRetryableProviderIntent(adapters, key, entry, 'email_hook_attempted_at', attemptedValue, 'hook_id', clock);
        throw cause;
      }
      for (let attempt = 0; attempt < 5 && !hook; attempt += 1) {
        await wait(attempt);
        hook = await recoverEmailHook(entry.record.netlify_site_id, form.id, leadEmail, env, fetchImpl, deadlineMs);
      }
      if (!hook) throw new Error('ARC2_EMAIL_HOOK_CREATE_AMBIGUOUS', { cause });
    }
  }
  identifier(hook.id, 'Netlify hook id');
  if (entry.record.form_id !== form.id || entry.record.hook_id !== hook.id) {
    entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { form_id: form.id, hook_id: hook.id }, clock()));
  }
  return entry;
}

async function startHandoffByKind(input, env, adapters = {}, paymentKind = 'payment-link') {
  const clock = adapters.clock || (() => new Date());
  const fetchImpl = adapters.fetch || fetch;
  const reviewSession = paymentKind === 'review-session';
  let normalized = reviewSession
    ? normalizeReviewStartPayload(input, env, clock(), { enforceFreshness: false })
    : normalizeStartPayload(input, env, clock(), { enforceFreshness: false, allowLegacyV3: true });
  normalized.leadEmailHash = sha256Hex(normalized.leadEmail);
  if (normalized.payment.value.client_reference_mismatch_review_required) {
    throw new Error('ARC2_CHECKOUT_REFERENCE_REVIEW_REQUIRED');
  }
  const key = handoffKey(normalized.payment.value, env.ARC_HANDOFF_STATE_SECRET);
  const handoffId = handoffIdFromKey(key);
  const bootstrapAt = adapters.activationClock?.() || new Date();
  const bootstrapConfiguration = claimSandboxBootstrapConfiguration(env, bootstrapAt);
  if (bootstrapConfiguration.bootstrap_active && !reviewSession) {
    throw new Error('ARC_CLAIM_SANDBOX_BOOTSTRAP_REVIEW_SESSION_REQUIRED');
  }
  // This reservation precedes every handoff/store/provider mutation. A
  // TEST_BOOTSTRAP may seed one paid review-session handoff and exact retries
  // of that same handoff only; all normal manifests simply recheck authority.
  await reserveClaimSandboxBootstrap(adapters.store, handoffId, env, bootstrapAt);
  let entry = await readEntry(adapters.store, key);
  const checkoutIndexKey = checkoutSessionIndexKey(normalized.payment.value, env);
  const checkoutIndexValue = checkoutSessionIndexValue(handoffId, normalized);
  const referenceIndexKey = checkoutReferenceIndexKey(normalized.payment.value, env);
  const referenceIndexValue = reviewSession
    ? reviewCheckoutReferenceIndexValue(handoffId, normalized)
    : checkoutReferenceIndexValue(handoffId, normalized);
  const checkoutReservation = await readIndex(adapters.store, checkoutIndexKey);
  const referenceReservation = await readIndex(adapters.store, referenceIndexKey);
  const existedAtStart = Boolean(entry);
  if (entry) rejectQuarantinedLegacyNamespace(entry.record);
  const exactEntry = Boolean(entry && exactReplay(entry.record, normalized));
  const exactCheckoutReservation = Boolean(checkoutReservation && canonicalJson(checkoutReservation) === canonicalJson(checkoutIndexValue));
  const exactReferenceReservation = Boolean(referenceReservation && canonicalJson(referenceReservation) === canonicalJson(referenceIndexValue));
  if (!reviewSession && normalized.legacyV3 && !exactEntry && !exactCheckoutReservation && !exactReferenceReservation) {
    throw new Error('ARC2_LEGACY_V3_NEW_START_REJECTED');
  }
  if (entry && !exactReplay(entry.record, normalized)) throw new Error('ARC2_IDEMPOTENCY_CONFLICT');
  if (checkoutReservation && canonicalJson(checkoutReservation) !== canonicalJson(checkoutIndexValue)) {
    throw new Error('ARC2_INDEX_CONFLICT');
  }
  if (referenceReservation && canonicalJson(referenceReservation) !== canonicalJson(referenceIndexValue)) {
    await ensureImmutableIndex(adapters.store, duplicatePaymentReviewKey(normalized, env),
      reviewSession
        ? reviewDuplicatePaymentValue(referenceReservation, normalized, env)
        : duplicatePaymentReviewValue(referenceReservation, normalized, env));
    throw new Error('ARC2_DUPLICATE_PAID_SESSION_REVIEW_REQUIRED');
  }
  // Only v4 may create a new handoff. Frozen v3 parsing above exists solely to
  // identify an exact durable row/reservation before any Checkout-ledger or
  // provider mutation. A truly brand-new v4 handoff still requires fresh evidence.
  if (!entry && !checkoutReservation && !referenceReservation) {
    normalized = reviewSession
      ? normalizeReviewStartPayload(input, env, clock())
      : normalizeStartPayload(input, env, clock());
    normalized.leadEmailHash = sha256Hex(normalized.leadEmail);
  }
  // Live fulfillment requires a separately authenticated, durable Checkout
  // webhook receipt plus an immutable handoff binding. This remains before
  // any handoff reservation, state mutation, or provider request.
  await (reviewSession ? bindStripeReviewCheckoutToHandoff : bindStripeCheckoutToHandoff)(
    adapters.store,
    handoffId,
    normalized.payment.value,
    normalized.payment.digest,
    env,
    { accountFetch: adapters.stripeAccountFetch },
  );
  // Reserve one immutable handoff per authenticated Checkout Session before
  // any Netlify write. The key is an HMAC, and the value stores only digests.
  try {
    await ensureImmutableIndex(adapters.store, referenceIndexKey, referenceIndexValue);
  } catch (error) {
    if (error.message !== 'ARC2_INDEX_CONFLICT') throw error;
    const winner = await readIndex(adapters.store, referenceIndexKey);
    if (!winner || canonicalJson(winner) === canonicalJson(referenceIndexValue)) throw error;
    await ensureImmutableIndex(adapters.store, duplicatePaymentReviewKey(normalized, env),
      reviewSession
        ? reviewDuplicatePaymentValue(winner, normalized, env)
        : duplicatePaymentReviewValue(winner, normalized, env));
    throw new Error('ARC2_DUPLICATE_PAID_SESSION_REVIEW_REQUIRED');
  }
  await ensureImmutableIndex(adapters.store, checkoutIndexKey, checkoutIndexValue);
  if (!entry) {
    const initial = createInitialRecord(normalized, env, key, clock(), { uuid: adapters.uuid });
    entry = await createEntry(adapters.store, key, initial.record);
    if (!entry) {
      entry = await readEntry(adapters.store, key);
      if (!entry || !exactReplay(entry.record, normalized)) throw new Error('ARC2_IDEMPOTENCY_CONFLICT');
    }
  }
  if (entry.record.lead_route_recipient_hmac_sha256 === null) {
    entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, {
      lead_route_recipient_hmac_sha256: normalized.leadRouteRecipientHmacSha256,
    }, clock()));
  }
  let reversalControlReady = true;
  if (entry.record.state !== 'DELIVERED') {
    // When the reversal control is required, the first invocation may reserve
    // the handoff and stop here until the verified Checkout Session ->
    // PaymentIntent binding is registered. No provider mutation happens first.
    try {
      await assertCheckoutAndReversalAllowed(entry.record, env, adapters, {
        checkoutSessionId: normalized.payment.value.checkout_session_id,
        now: clock(),
      });
    } catch (error) {
      if (/^ARC_STRIPE_REVERSAL_(?:BINDING|RECHECK)_REQUIRED$/.test(error?.message || '')) {
        reversalControlReady = false;
      } else {
        throw error;
      }
    }
  }
  if (!reversalControlReady) {
    return { handoffId, record: entry.record, idempotentReplay: existedAtStart, reversalControlReady };
  }
  if (entry.record.state === 'PAYMENT_VERIFIED') entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'SITE_INTENT', {}, clock()));
  if (entry.record.state === 'SITE_INTENT') {
    await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
    const site = await createOrRecoverSite(entry.record, env, adapters);
    await ensureImmutableIndex(adapters.store, siteIndexKey(site.id), {
      schema: 'arc2-site-index-v1', handoff_id: handoffId, netlify_site_id: site.id, netlify_session_id: entry.record.netlify_session_id,
    });
    entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'SITE_CREATED', {
      netlify_site_id: site.id, site_created_at: clock().toISOString(),
    }, clock()));
    return { handoffId, record: entry.record, idempotentReplay: existedAtStart, reversalControlReady };
  }
  if (entry.record.state === 'SITE_CREATED') {
    await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
    const deployed = await ensureDeploy(entry, key, normalized.deployArtifacts, 'preclaim', env, adapters);
    entry = await replaceEntry(adapters.store, key, deployed.entry, transitionRecord(deployed.entry.record, 'PRECLAIM_DEPLOY_READY', {
      preclaim_deploy_id: deployed.ready.id,
    }, clock()));
    return { handoffId, record: entry.record, idempotentReplay: existedAtStart, reversalControlReady };
  }
  if (entry.record.state === 'PRECLAIM_DEPLOY_READY') {
    await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
    const deadlineMs = providerStageDeadline(adapters);
    const stageAdapters = { ...adapters, providerStageDeadlineMs: deadlineMs };
    if (entry.record.lead_route_mode === 'netlify_form' && (!entry.record.form_id || !entry.record.hook_id)) {
      entry = await ensureLeadHook(entry, key, normalized.leadEmail, env, stageAdapters);
    }
    await verifyNetlifyHandoff(entry.record, {
      accountId: env.NETLIFY_TEAM_ACCOUNT_ID,
      artifacts: deployArtifactsForPhase(normalized.deployArtifacts, 'preclaim').map(({ path, bytes }) => ({
        path, size: bytes.length, sha256: sha256Hex(bytes),
      })),
      phase: 'preclaim',
      deployId: entry.record.preclaim_deploy_id,
      formId: entry.record.form_id, formName: entry.record.form_name, hookId: entry.record.hook_id,
      leadEmailSha256: entry.record.lead_notification_email_sha256,
    }, env, fetchImpl, { deadlineMs });
    if (entry.record.lead_route_mode === 'not_required') {
      const readyAt = clock();
      const expiresAt = new Date(readyAt.getTime() + CLAIM_TOKEN_TTL_SECONDS * 1000);
      const draft = transitionRecord(entry.record, 'INVITATION_READY', {
        lead_route_receipt_sha256: entry.record.artifact_evidence_sha256,
        claim_invitation_generation: 1,
        claim_invitation_ready_at: readyAt.toISOString(),
        lead_route_provider_message_id_sha256: entry.record.artifact_evidence_sha256,
        claim_token_expires_at: expiresAt.toISOString(),
      }, readyAt);
      const token = deriveClaimBearer(draft, env);
      entry = await replaceEntry(adapters.store, key, entry, { ...draft, claim_token_hmac_sha256: claimBearerDigest(token, env) });
    }
  }
  let claimBearer = null;
  if (entry.record.lead_route_mode === 'not_required' && entry.record.state === 'INVITATION_READY') {
    const observedAt = clock();
    entry = await rotateExpiredInvitation(entry, key, env, adapters, observedAt);
    // Re-ensure this immutable outbox on every exact replay. If the previous
    // invocation crashed after the state CAS, replay converges before returning
    // the deterministic bearer and never persists the bearer itself.
    await ensureInvitationDeliveryAuthority(entry.record, env, adapters);
    claimBearer = deriveClaimBearer(entry.record, env);
    if (!safeEqual(claimBearerDigest(claimBearer, env), entry.record.claim_token_hmac_sha256)) {
      throw new Error('ARC2_CLAIM_BEARER_BINDING_FAILED');
    }
  }
  return { handoffId, record: entry.record, idempotentReplay: existedAtStart, reversalControlReady, claimBearer };
}

export async function startHandoff(input, env, adapters = {}) {
  return startHandoffByKind(input, env, adapters, 'payment-link');
}

function signedReviewStartReceipt(result, payment, env) {
  const continuationReady = result.reversalControlReady === true &&
    !PRE_INVITATION_STATES.has(result.record.state);
  const receipt = {
    schema: REVIEW_HANDOFF_START_RECEIPT_SCHEMA,
    accepted: true,
    handoff_id: result.handoffId,
    started_at: result.record.created_at,
    payment_evidence_sha256: result.record.payment_evidence_sha256,
    artifact_evidence_sha256: result.record.artifact_evidence_sha256,
    bridge_immutable_binding_sha256: payment.bridge_immutable_binding_sha256,
    review_session_binding_sha256: payment.review_session_binding_sha256,
    checkout_session_id_hmac_sha256: payment.checkout_session_id_hmac_sha256,
    payment_intent_id_hmac_sha256: payment.payment_intent_id_hmac_sha256,
    recipient_email_sha256: payment.claim_recipient_email_sha256,
    payer_email_sha256: payment.payer_email_sha256,
    handoff_state: result.record.state,
    reversal_control_ready: result.reversalControlReady === true,
    continuation_ready: continuationReady,
  };
  const canonical = canonicalJson(receipt);
  return Object.freeze({
    canonical,
    digest: sha256Hex(canonical),
    signature: hmacHex(env.ARC_PAYMENT_ARC2_BRIDGE_HMAC_SECRET,
      `${REVIEW_HANDOFF_START_RECEIPT_PREFIX}${canonical}`),
    value: Object.freeze(receipt),
  });
}

export async function startReviewHandoff(input, env, adapters = {}) {
  // Capture the already-validated payment before any awaited provider/store
  // adapter can mutate the caller-owned raw input.
  const clock = adapters.clock || (() => new Date());
  const normalized = normalizeReviewStartPayload(input, env, clock(), { enforceFreshness: false });
  const result = await startHandoffByKind(input, env, adapters, 'review-session');
  if (!safeEqual(result.record.payment_evidence_sha256, normalized.payment.digest)) {
    throw new Error('ARC2_REVIEW_PAYMENT_EVIDENCE_CHANGED');
  }
  return { ...result, startReceipt: signedReviewStartReceipt(result, normalized.payment.value, env) };
}

function verifyLeadRouteSignature(signature, raw, prefix, env) {
  const suppliedSignature = sha256(signature, 'Lead-route receipt signature');
  if (!safeEqual(suppliedSignature, hmacHex(env.ARC_LEAD_ROUTE_EVIDENCE_SECRET, `${prefix}${raw}`))) {
    throw new TypeError('Lead-route receipt signature mismatch.');
  }
}

function normalizeLegacyLeadRouteReceipt(raw, value, signature, record, env, now, options) {
  const keys = ['form_id_sha256', 'handoff_id', 'hook_id_sha256', 'inbox_receipt_id_sha256', 'issued_at', 'netlify_site_id_sha256',
    'provider_message_id_sha256', 'received_at', 'recipient_email_sha256', 'scope', 'version'];
  if (!exactObjectKeys(value, keys) || canonicalJson(value) !== raw || value.version !== LEAD_ROUTE_RECEIPT_VERSION ||
      value.scope !== LEAD_ROUTE_RECEIPT_SCOPE || value.handoff_id !== record.handoff_id) throw new TypeError('Lead-route receipt evidence fields are invalid.');
  verifyLeadRouteSignature(signature, raw, LEAD_ROUTE_RECEIPT_PREFIX, env);
  const issuedAt = Date.parse(iso(value.issued_at, 'Lead-route receipt issued_at'));
  const receivedAt = Date.parse(iso(value.received_at, 'Lead-route receipt received_at'));
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) ||
      (options.enforceFreshness !== false && (issuedAt > nowMs + 60_000 || issuedAt < nowMs - RECEIPT_FRESHNESS_MS)) ||
      receivedAt > issuedAt || receivedAt < issuedAt - RECEIPT_FRESHNESS_MS) {
    throw new TypeError('Lead-route receipt evidence is stale or out of order.');
  }
  const bindings = {
    netlify_site_id_sha256: sha256Hex(record.netlify_site_id), form_id_sha256: sha256Hex(record.form_id),
    hook_id_sha256: sha256Hex(record.hook_id), recipient_email_sha256: record.lead_notification_email_sha256,
  };
  for (const [field, expected] of Object.entries(bindings)) if (!safeEqual(sha256(value[field], field), expected)) throw new TypeError('Lead-route receipt binding mismatch.');
  sha256(value.provider_message_id_sha256, 'provider_message_id_sha256');
  sha256(value.inbox_receipt_id_sha256, 'inbox_receipt_id_sha256');
  return { canonical: raw, digest: sha256Hex(raw), value };
}

function plainHttpsRoot(value, label) {
  if (typeof value !== 'string' || value.length < 12 || value.length > 512 || value !== value.trim()) {
    throw new TypeError(`${label} is invalid.`);
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${label} is invalid.`);
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/' || url.toString() !== value) {
    throw new TypeError(`${label} must be a canonical HTTPS root.`);
  }
  return value;
}

function normalizeProducerLeadRouteReceipt(raw, value, signature, record, env, now, options) {
  if (!exactObjectKeys(value, PRODUCER_LEAD_ROUTE_FIELDS) ||
      JSON.stringify(Object.keys(value)) !== JSON.stringify(PRODUCER_LEAD_ROUTE_FIELDS) || JSON.stringify(value) !== raw ||
      value.version !== PRODUCER_LEAD_ROUTE_VERSION || value.scope !== PRODUCER_LEAD_ROUTE_SCOPE) {
    throw new TypeError('Lead-route producer evidence fields are invalid.');
  }
  verifyLeadRouteSignature(signature, raw, PRODUCER_LEAD_ROUTE_PREFIX, env);

  for (const field of ['staging_site_id', 'staging_deploy_id', 'staging_form_id', 'notification_hook_id', 'synthetic_submission_id']) {
    if (typeof value[field] !== 'string' || !PRODUCER_EXTERNAL_ID_PATTERN.test(value[field])) {
      throw new TypeError(`Lead-route producer ${field} is invalid.`);
    }
  }
  identifier(value.netlify_account_id, 'Lead-route producer Netlify account id');
  if (typeof value.inbox_provider !== 'string' || !/^[a-z0-9][a-z0-9_.-]{1,63}$/.test(value.inbox_provider)) {
    throw new TypeError('Lead-route producer inbox provider is invalid.');
  }
  const digestFields = [
    'production_content_sha256', 'artifact_manifest_sha256', 'handoff_artifact_evidence_sha256', 'bundle_fingerprint',
    'deploy_file_manifest_sha256', 'served_html_sha256', 'staging_robots_header_sha256', 'recipient_hmac_sha256',
    'synthetic_probe_sha256', 'inbox_account_hmac_sha256', 'inbox_message_id_hmac_sha256', 'inbox_receipt_evidence_sha256',
  ];
  for (const field of digestFields) sha256(value[field], field);

  const bindings = {
    preview_folder: record.preview_folder,
    production_content_sha256: record.production_content_sha256,
    artifact_manifest_sha256: record.artifact_manifest_sha256,
    handoff_artifact_evidence_sha256: record.artifact_evidence_sha256,
    bundle_fingerprint: record.bundle_fingerprint,
    netlify_account_id: record.netlify_source_account_id,
    staging_site_id: record.netlify_site_id,
    staging_deploy_id: record.preclaim_deploy_id,
    staging_form_id: record.form_id,
    notification_hook_id: record.hook_id,
    form_name: record.form_name,
    recipient_hmac_sha256: record.lead_route_recipient_hmac_sha256,
  };
  for (const [field, expected] of Object.entries(bindings)) {
    if (typeof expected !== 'string' || !safeEqual(value[field], expected)) throw new TypeError('Lead-route producer evidence binding mismatch.');
  }
  const expectedSiteUrl = canonicalNetlifySiteUrl(record.netlify_site_name);
  const expectedDeployUrl = `https://${record.preclaim_deploy_id}--${record.netlify_site_name}.netlify.app/`;
  if (plainHttpsRoot(value.staging_site_url, 'Lead-route producer staging site URL') !== expectedSiteUrl ||
      plainHttpsRoot(value.staging_deploy_url, 'Lead-route producer staging deploy URL') !== expectedDeployUrl) {
    throw new TypeError('Lead-route producer URL binding mismatch.');
  }

  const submissionAt = Date.parse(iso(value.netlify_submission_timestamp, 'Lead-route producer Netlify submission timestamp'));
  const receivedAt = Date.parse(iso(value.inbox_received_timestamp, 'Lead-route producer inbox received timestamp'));
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || submissionAt > receivedAt || receivedAt - submissionAt > PRODUCER_SOURCE_FRESHNESS_MS ||
      (options.enforceFreshness !== false && (receivedAt > nowMs + 60_000 || receivedAt < nowMs - RECEIPT_FRESHNESS_MS ||
        submissionAt < nowMs - PRODUCER_SOURCE_FRESHNESS_MS))) {
    throw new TypeError('Lead-route producer evidence is stale or out of order.');
  }

  const normalized = {
    version: LEAD_ROUTE_RECEIPT_VERSION,
    scope: LEAD_ROUTE_RECEIPT_SCOPE,
    handoff_id: record.handoff_id,
    netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
    form_id_sha256: sha256Hex(record.form_id),
    hook_id_sha256: sha256Hex(record.hook_id),
    recipient_email_sha256: record.lead_notification_email_sha256,
    provider_message_id_sha256: sha256Hex(value.inbox_message_id_hmac_sha256),
    inbox_receipt_id_sha256: value.inbox_receipt_evidence_sha256,
    received_at: value.inbox_received_timestamp,
    issued_at: value.inbox_received_timestamp,
  };
  return { canonical: canonicalJson(normalized), digest: sha256Hex(raw), value: normalized };
}

function normalizeLeadRouteReceipt(raw, signature, record, env, now, options = {}) {
  if (typeof raw !== 'string' || raw.length < 2 || raw.length > 20_000) throw new TypeError('Lead-route receipt evidence is invalid.');
  const value = JSON.parse(raw);
  if (value?.version === PRODUCER_LEAD_ROUTE_VERSION && value?.scope === PRODUCER_LEAD_ROUTE_SCOPE) {
    return normalizeProducerLeadRouteReceipt(raw, value, signature, record, env, now, options);
  }
  return normalizeLegacyLeadRouteReceipt(raw, value, signature, record, env, now, options);
}

function deriveClaimBearer(record, env) {
  const materialValue = {
    handoff_id: record.handoff_id, lead_route_receipt_sha256: record.lead_route_receipt_sha256,
    claim_invitation_ready_at: record.claim_invitation_ready_at, claim_token_expires_at: record.claim_token_expires_at,
  };
  // Generation zero preserves already-issued pre-rotation bearer bytes.
  if (record.claim_invitation_generation > 0) materialValue.claim_invitation_generation = record.claim_invitation_generation;
  const material = canonicalJson(materialValue);
  return createHmac('sha256', env.ARC_CLAIM_TOKEN_SECRET).update(`${CLAIM_BEARER_DERIVATION_PREFIX}${material}`).digest('base64url');
}

function renewalOperationHmac(handoffId, env, adapters) {
  const operationId = adapters.renewalOperationId;
  if (operationId === undefined || operationId === null) return null;
  if (typeof operationId !== 'string' || operationId.length < 16 || operationId.length > 512 ||
      !/^[A-Za-z0-9._~-]+$/.test(operationId)) {
    throw new TypeError('ARC2 claim invitation renewal operation identity is invalid.');
  }
  return hmacHex(env.ARC_HANDOFF_STATE_SECRET,
    `${CLAIM_INVITATION_RENEWAL_OPERATION_PREFIX}${handoffId}\n${operationId}`);
}

function renewalBindingPatch(record, operationHmac, env) {
  if (operationHmac === null) return {
    claim_invitation_renewal_operation_hmac_sha256: null,
    claim_invitation_renewal_previous_expires_at: null,
    claim_invitation_renewal_previous_job_key: null,
    claim_invitation_renewal_source_generation: null,
  };
  const previousJobKey = invitationReadyOutbox(record, env).key.slice(
    'invitation-ready-outbox/'.length);
  return {
    claim_invitation_renewal_operation_hmac_sha256: operationHmac,
    claim_invitation_renewal_previous_expires_at: record.claim_token_expires_at,
    claim_invitation_renewal_previous_job_key: previousJobKey,
    claim_invitation_renewal_source_generation: record.claim_invitation_generation,
  };
}

function renewalOperationReplays(record, operationHmac, now) {
  return operationHmac !== null && record.state === 'INVITATION_READY' &&
    Date.parse(record.claim_token_expires_at) > now.getTime() &&
    record.claim_invitation_renewal_source_generation + 1 === record.claim_invitation_generation &&
    safeEqual(record.claim_invitation_renewal_operation_hmac_sha256 || '', operationHmac);
}

async function rotateExpiredInvitation(entry, key, env, adapters, observedAt, operationHmac = null) {
  if (entry.record.state !== 'INVITATION_READY') return entry;
  if (Date.parse(entry.record.claim_token_expires_at) > observedAt.getTime()) return entry;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const readyAt = observedAt;
    const expiresAt = new Date(readyAt.getTime() + CLAIM_TOKEN_TTL_SECONDS * 1000);
    const generation = Number.isSafeInteger(entry.record.claim_invitation_generation)
      ? entry.record.claim_invitation_generation + 1
      : 1;
    const draft = reviseRecord(entry.record, {
      claim_invitation_generation: generation,
      claim_invitation_ready_at: readyAt.toISOString(),
      claim_token_expires_at: expiresAt.toISOString(),
      ...renewalBindingPatch(entry.record, operationHmac, env),
    }, readyAt);
    const token = deriveClaimBearer(draft, env);
    try {
      return await replaceEntry(adapters.store, key, entry, { ...draft, claim_token_hmac_sha256: claimBearerDigest(token, env) });
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 2) throw error;
      entry = await readEntry(adapters.store, key);
      if (!entry || entry.record.state !== 'INVITATION_READY') throw new Error('ARC2_CLAIM_RENEWAL_STATE_CONFLICT');
      if (Date.parse(entry.record.claim_token_expires_at) > observedAt.getTime()) return entry;
    }
  }
  return entry;
}

function claimBearerDigest(token, env) {
  return hmacHex(env.ARC_CLAIM_TOKEN_SECRET, `${CLAIM_BEARER_STORAGE_PREFIX}${token}`);
}

function invitationReadyOutbox(record, env) {
  const canonical = canonicalJson({
    version: INVITATION_READY_OUTBOX_VERSION, handoff_id: record.handoff_id, recipient_email_sha256: record.customer_email_sha256,
    claim_invitation_generation: record.claim_invitation_generation,
    claim_token_hmac_sha256: record.claim_token_hmac_sha256, expires_at: record.claim_token_expires_at,
  });
  const digest = hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET, canonical);
  return { key: `invitation-ready-outbox/${digest}`, value: {
    schema: INVITATION_READY_OUTBOX_VERSION, status: 'READY', handoff_id: record.handoff_id,
    claim_invitation_generation: record.claim_invitation_generation,
    recipient_email_sha256: record.customer_email_sha256, claim_token_hmac_sha256: record.claim_token_hmac_sha256,
    expires_at: record.claim_token_expires_at,
  } };
}

function invitationCurrentKey(handoffId) {
  return `invitation-ready-current/${handoffId}`;
}

function invitationCurrentValue(record, outbox, env) {
  const binding = {
    schema: INVITATION_CURRENT_VERSION,
    handoff_id: record.handoff_id,
    claim_invitation_generation: record.claim_invitation_generation,
    claim_token_hmac_sha256: record.claim_token_hmac_sha256,
    expires_at: record.claim_token_expires_at,
    outbox_key_sha256: sha256Hex(outbox.key),
  };
  return {
    ...binding,
    binding_hmac_sha256: hmacHex(env.ARC_EMAIL_CLAIM_BINDING_SECRET,
      `${INVITATION_CURRENT_VERSION}\n${canonicalJson(binding)}`),
  };
}

async function ensureInvitationCurrent(record, outbox, env, adapters) {
  const key = invitationCurrentKey(record.handoff_id);
  const value = invitationCurrentValue(record, outbox, env);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const existing = await readIndexEntry(adapters.store, key);
    if (!existing) {
      try {
        await createIndex(adapters.store, key, value);
        return value;
      } catch (error) {
        if (error?.message !== 'ARC2_INDEX_CONFLICT' || attempt === 3) throw error;
        continue;
      }
    }
    if (canonicalJson(existing.value) === canonicalJson(value)) return value;
    const generation = existing.value?.claim_invitation_generation;
    if (!Number.isSafeInteger(generation) || generation >= record.claim_invitation_generation) {
      throw new Error('ARC2_CLAIM_INVITATION_CURRENT_CONFLICT');
    }
    try {
      await replaceIndex(adapters.store, key, existing, value);
      return value;
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 3) throw error;
    }
  }
  throw new Error('ARC2_CLAIM_INVITATION_CURRENT_CONFLICT');
}

async function ensureInvitationDeliveryAuthority(record, env, adapters) {
  const outbox = invitationReadyOutbox(record, env);
  await ensureImmutableIndex(adapters.store, outbox.key, outbox.value);
  await ensureInvitationCurrent(record, outbox, env, adapters);
  return outbox;
}

async function rotateAbandonedConsumedInvitation(entry, key, env, adapters, observedAt,
  operationHmac = null) {
  if (entry.record.state !== 'CLAIM_WRAPPER_CONSUMED') return entry;
  if (Date.parse(entry.record.claim_token_expires_at) > observedAt.getTime()) {
    throw new Error('ARC2_CLAIM_RENEWAL_NOT_EXPIRED');
  }
  const fetchImpl = adapters.fetch || fetch;
  const deadlineMs = providerStageDeadline(adapters);
  const observedSite = await netlifyJson(`/sites/${encodeURIComponent(entry.record.netlify_site_id)}`,
    env, fetchImpl, deadlineMs);
  // This intentionally uses the source-account validator: a destination-owned
  // site proves the provider claim completed and must never be reissued.
  validateSiteIntent(observedSite, entry.record, env, false);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const readyAt = observedAt;
    const expiresAt = new Date(readyAt.getTime() + CLAIM_TOKEN_TTL_SECONDS * 1000);
    const generation = entry.record.claim_invitation_generation + 1;
    const draft = transitionRecord(entry.record, 'INVITATION_READY', {
      claim_invitation_generation: generation,
      claim_invitation_ready_at: readyAt.toISOString(),
      claim_token_expires_at: expiresAt.toISOString(),
      claim_token_consumed_hmac_sha256: null,
      claim_token_used_at: null,
      claim_wrapper_consumed_at: null,
      claim_jwt_issued_at: null,
      ...renewalBindingPatch(entry.record, operationHmac, env),
    }, readyAt);
    const token = deriveClaimBearer(draft, env);
    try {
      return await replaceEntry(adapters.store, key, entry, {
        ...draft,
        claim_token_hmac_sha256: claimBearerDigest(token, env),
      });
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 2) throw error;
      entry = await readEntry(adapters.store, key);
      if (entry?.record.state === 'INVITATION_READY' &&
          Date.parse(entry.record.claim_token_expires_at) > observedAt.getTime()) return entry;
      if (!entry || entry.record.state !== 'CLAIM_WRAPPER_CONSUMED' ||
          Date.parse(entry.record.claim_token_expires_at) > observedAt.getTime()) {
        throw new Error('ARC2_CLAIM_RENEWAL_STATE_CONFLICT');
      }
    }
  }
  throw new Error('ARC2_CLAIM_RENEWAL_STATE_CONFLICT');
}

export async function renewClaimInvitation(handoffId, env, adapters = {}) {
  const key = handoffKeyFromId(handoffId);
  const clock = adapters.clock || (() => new Date());
  await assertClaimSandboxBootstrapBound(adapters.store, handoffId, env,
    adapters.activationClock?.() || new Date());
  let entry = await readEntry(adapters.store, key);
  if (!entry) return null;
  const observedAt = clock();
  const operationHmac = renewalOperationHmac(handoffId, env, adapters);
  await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: observedAt });
  if (entry.record.state === 'INVITATION_READY') {
    if (Date.parse(entry.record.claim_token_expires_at) > observedAt.getTime()) {
      if (!renewalOperationReplays(entry.record, operationHmac, observedAt)) {
        throw new Error('ARC2_CLAIM_RENEWAL_NOT_EXPIRED');
      }
    } else {
      entry = await rotateExpiredInvitation(entry, key, env, adapters, observedAt, operationHmac);
    }
  } else if (entry.record.state === 'CLAIM_WRAPPER_CONSUMED') {
    entry = await rotateAbandonedConsumedInvitation(entry, key, env, adapters, observedAt,
      operationHmac);
  } else {
    throw new Error('ARC2_CLAIM_RENEWAL_STATE_CONFLICT');
  }
  if (operationHmac !== null &&
      !safeEqual(entry.record.claim_invitation_renewal_operation_hmac_sha256 || '', operationHmac)) {
    throw new Error('ARC2_CLAIM_RENEWAL_STATE_CONFLICT');
  }
  const token = deriveClaimBearer(entry.record, env);
  if (!safeEqual(claimBearerDigest(token, env), entry.record.claim_token_hmac_sha256)) {
    throw new Error('ARC2_CLAIM_BEARER_BINDING_FAILED');
  }
  await ensureInvitationDeliveryAuthority(entry.record, env, adapters);
  return { handoffId, record: entry.record, claimBearer: token };
}

// Customer recovery authority for an invitation that has aged out before it
// was exchanged. The expired bearer is proof of possession, but it is never
// returned, persisted, or accepted for an early rotation. A caller-provided
// delivery guard must verify the encrypted recipient capsule and suppression
// state before the generation is changed. The new immutable invitation outbox
// then becomes a distinct Resend job while the previous bearer stops matching
// the handoff record immediately.
export async function renewClaimInvitationFromExpiredBearer(
  handoffId,
  suppliedBearer,
  env,
  adapters = {},
) {
  if (typeof suppliedBearer !== 'string' || suppliedBearer.length !== 43 ||
      !/^[A-Za-z0-9_-]+$/.test(suppliedBearer)) {
    throw new Error('ARC2_CLAIM_BEARER_INVALID');
  }
  if (typeof adapters.assertRenewalEmailAllowed !== 'function') {
    throw new Error('ARC2_CLAIM_RENEWAL_EMAIL_GUARD_REQUIRED');
  }
  const key = handoffKeyFromId(handoffId);
  const clock = adapters.clock || (() => new Date());
  await assertClaimSandboxBootstrapBound(adapters.store, handoffId, env,
    adapters.activationClock?.() || new Date());
  let entry = await readEntry(adapters.store, key);
  if (!entry) return null;
  const observedAt = clock();
  if (!(observedAt instanceof Date) || !Number.isFinite(observedAt.getTime())) {
    throw new TypeError('ARC2 claim renewal clock is invalid.');
  }
  const operationHmac = renewalOperationHmac(handoffId, env, adapters);
  const suppliedDigest = claimBearerDigest(suppliedBearer, env);
  if (renewalOperationReplays(entry.record, operationHmac, observedAt)) {
    const previousJobKey = entry.record.claim_invitation_renewal_previous_job_key;
    await adapters.assertRenewalEmailAllowed(Object.freeze({
      handoff_id: entry.record.handoff_id,
      job_key: previousJobKey,
      recipient_email_sha256: entry.record.customer_email_sha256,
      claim_invitation_generation: entry.record.claim_invitation_renewal_source_generation,
      expires_at: entry.record.claim_invitation_renewal_previous_expires_at,
    }));
    await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: observedAt });
    const nextOutbox = await ensureInvitationDeliveryAuthority(entry.record, env, adapters);
    const nextJobKey = nextOutbox.key.slice('invitation-ready-outbox/'.length);
    await assertCheckoutAndReversalAllowed(entry.record, env, adapters, {
      maxRecheckAgeMs: STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS,
      now: clock(),
    });
    return Object.freeze({
      handoff_id: entry.record.handoff_id,
      claim_invitation_generation: entry.record.claim_invitation_generation,
      previous_job_key: previousJobKey,
      job_key: nextJobKey,
      expires_at: entry.record.claim_token_expires_at,
      idempotent_replay: true,
    });
  }
  const remainingMs = Date.parse(entry.record.claim_token_expires_at) - observedAt.getTime();
  if (entry.record.state !== 'INVITATION_READY' ||
      !safeEqual(suppliedDigest, entry.record.claim_token_hmac_sha256 || '') ||
      !safeEqual(deriveClaimBearer(entry.record, env), suppliedBearer)) {
    throw new Error('ARC2_CLAIM_BEARER_INVALID');
  }
  if (remainingMs >= 1000) throw new Error('ARC2_CLAIM_RENEWAL_NOT_EXPIRED');

  const previousGeneration = entry.record.claim_invitation_generation;
  const previousOutbox = invitationReadyOutbox(entry.record, env);
  const previousJobKey = previousOutbox.key.slice('invitation-ready-outbox/'.length);
  const guardAuthority = Object.freeze({
    handoff_id: entry.record.handoff_id,
    job_key: previousJobKey,
    recipient_email_sha256: entry.record.customer_email_sha256,
    claim_invitation_generation: previousGeneration,
    expires_at: entry.record.claim_token_expires_at,
  });
  await adapters.assertRenewalEmailAllowed(guardAuthority);

  // The delivery/suppression read can race another request. Re-read the exact
  // bearer authority before any provider check or state mutation.
  entry = await readEntry(adapters.store, key);
  if (!entry || entry.record.state !== 'INVITATION_READY' ||
      entry.record.claim_invitation_generation !== previousGeneration ||
      !safeEqual(entry.record.claim_token_hmac_sha256 || '', suppliedDigest) ||
      Date.parse(entry.record.claim_token_expires_at) - observedAt.getTime() >= 1000) {
    throw new Error('ARC2_CLAIM_BEARER_INVALID');
  }

  await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: observedAt });
  entry = await rotateExpiredInvitation(entry, key, env, adapters, observedAt, operationHmac);
  if (entry.record.claim_invitation_generation !== previousGeneration + 1) {
    throw new Error('ARC2_CLAIM_RENEWAL_STATE_CONFLICT');
  }
  if (operationHmac !== null &&
      !safeEqual(entry.record.claim_invitation_renewal_operation_hmac_sha256 || '', operationHmac)) {
    throw new Error('ARC2_CLAIM_RENEWAL_STATE_CONFLICT');
  }
  const newBearer = deriveClaimBearer(entry.record, env);
  if (safeEqual(newBearer, suppliedBearer) ||
      !safeEqual(claimBearerDigest(newBearer, env), entry.record.claim_token_hmac_sha256)) {
    throw new Error('ARC2_CLAIM_BEARER_BINDING_FAILED');
  }
  const nextOutbox = await ensureInvitationDeliveryAuthority(entry.record, env, adapters);
  const nextJobKey = nextOutbox.key.slice('invitation-ready-outbox/'.length);
  if (!/^[a-f0-9]{64}$/.test(nextJobKey) || safeEqual(previousJobKey, nextJobKey)) {
    throw new Error('ARC2_CLAIM_RENEWAL_OUTBOX_CONFLICT');
  }
  await assertCheckoutAndReversalAllowed(entry.record, env, adapters, {
    maxRecheckAgeMs: STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS,
    now: clock(),
  });
  return Object.freeze({
    handoff_id: entry.record.handoff_id,
    claim_invitation_generation: entry.record.claim_invitation_generation,
    previous_job_key: previousJobKey,
    job_key: nextJobKey,
    expires_at: entry.record.claim_token_expires_at,
    idempotent_replay: false,
  });
}

// Private send authority for the white-glove ARC claim-wrapper email. The
// wrapper URL is derived only after a fresh paid/reversal readback and is never
// written to an index or handoff record. Expired generations are rotated under
// CAS before the bearer is derived, so the immutable invitation outbox digest
// remains the unique email job key for that generation.
export async function getClaimInvitationEmailAuthority(handoffId, env, adapters = {}) {
  const key = handoffKeyFromId(handoffId);
  const clock = adapters.clock || (() => new Date());
  await assertClaimSandboxBootstrapBound(adapters.store, handoffId, env,
    adapters.activationClock?.() || new Date());
  let entry = await readEntry(adapters.store, key);
  if (!entry) return null;
  if (entry.record.state !== 'INVITATION_READY') {
    throw new Error('ARC2_CLAIM_INVITATION_EMAIL_STATE_CONFLICT');
  }
  const observedAt = clock();
  const freshGuard = {
    maxRecheckAgeMs: STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS,
    now: observedAt,
  };
  await assertCheckoutAndReversalAllowed(entry.record, env, adapters, freshGuard);
  entry = await rotateExpiredInvitation(entry, key, env, adapters, observedAt);
  if (entry.record.state !== 'INVITATION_READY') {
    throw new Error('ARC2_CLAIM_INVITATION_EMAIL_STATE_CONFLICT');
  }
  const claimBearer = deriveClaimBearer(entry.record, env);
  if (!safeEqual(claimBearerDigest(claimBearer, env), entry.record.claim_token_hmac_sha256)) {
    throw new Error('ARC2_CLAIM_BEARER_BINDING_FAILED');
  }
  const outbox = await ensureInvitationDeliveryAuthority(entry.record, env, adapters);
  await assertCheckoutAndReversalAllowed(entry.record, env, adapters, {
    maxRecheckAgeMs: STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS,
    now: clock(),
  });
  const origin = new URL(env.ARC_PUBLIC_ORIGIN);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.port ||
      origin.pathname !== '/' || origin.search || origin.hash) {
    throw new Error('ARC2_CLAIM_INVITATION_EMAIL_ORIGIN_INVALID');
  }
  const outboxDigest = outbox.key.slice('invitation-ready-outbox/'.length);
  if (!/^[a-f0-9]{64}$/.test(outboxDigest)) {
    throw new Error('ARC2_CLAIM_INVITATION_EMAIL_OUTBOX_INVALID');
  }
  return Object.freeze({
    handoff_id: entry.record.handoff_id,
    job_key: outboxDigest,
    recipient_email_sha256: entry.record.customer_email_sha256,
    claim_invitation_generation: entry.record.claim_invitation_generation,
    claim_token_hmac_sha256: entry.record.claim_token_hmac_sha256,
    claim_url: `${origin.origin}/claim/#arc2.${entry.record.handoff_id}.${claimBearer}`,
    expires_at: entry.record.claim_token_expires_at,
  });
}

export async function markClaimInvitationReady(handoffId, evidence, signature, env, adapters = {}) {
  const key = handoffKeyFromId(handoffId);
  const clock = adapters.clock || (() => new Date());
  await assertClaimSandboxBootstrapBound(adapters.store, handoffId, env,
    adapters.activationClock?.() || new Date());
  let entry = await readEntry(adapters.store, key);
  if (!entry) return null;
  if (entry.record.lead_route_mode === 'not_required') {
    throw new Error('ARC2_LEAD_ROUTE_RECEIPT_NOT_REQUIRED');
  }
  await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
  // The committed producer can address only arc-lead-route-* sites. An older
  // namespace record that never reached invitation readiness has no valid
  // receipt path, so reject it before parsing evidence or changing state.
  rejectQuarantinedLegacyNamespace(entry.record);
  const observedAt = clock();
  // Replays re-check the exact source signature, shape, ordering, and durable
  // bindings, but do not pretend an already-bound receipt was newly observed.
  const receipt = normalizeLeadRouteReceipt(evidence, signature, entry.record, env, observedAt, {
    enforceFreshness: entry.record.lead_route_receipt_sha256 === null,
  });
  if (!['PRECLAIM_DEPLOY_READY', 'LEAD_ROUTE_VERIFIED', 'INVITATION_READY'].includes(entry.record.state)) {
    if (entry.record.lead_route_receipt_sha256 !== receipt.digest) throw new Error('ARC2_CLAIM_INVITATION_STATE_CONFLICT');
    return { handoffId, record: entry.record, claimBearer: null, alreadyConsumed: true };
  }
  if (entry.record.state === 'PRECLAIM_DEPLOY_READY' || entry.record.state === 'LEAD_ROUTE_VERIFIED') {
    const readyAt = observedAt;
    const expiresAt = new Date(readyAt.getTime() + CLAIM_TOKEN_TTL_SECONDS * 1000);
    const draft = transitionRecord(entry.record, 'INVITATION_READY', {
      lead_route_receipt_sha256: receipt.digest, claim_invitation_ready_at: readyAt.toISOString(),
      claim_invitation_generation: 1,
      lead_route_provider_message_id_sha256: receipt.value.provider_message_id_sha256,
      claim_token_expires_at: expiresAt.toISOString(),
    }, readyAt);
    const token = deriveClaimBearer(draft, env);
    entry = await replaceEntry(adapters.store, key, entry, { ...draft, claim_token_hmac_sha256: claimBearerDigest(token, env) });
  } else if (entry.record.lead_route_receipt_sha256 !== receipt.digest) throw new Error('ARC2_CLAIM_INVITATION_EVIDENCE_CONFLICT');
  entry = await rotateExpiredInvitation(entry, key, env, adapters, observedAt);
  const token = deriveClaimBearer(entry.record, env);
  if (!safeEqual(claimBearerDigest(token, env), entry.record.claim_token_hmac_sha256)) throw new Error('ARC2_CLAIM_BEARER_BINDING_FAILED');
  await ensureInvitationDeliveryAuthority(entry.record, env, adapters);
  return { handoffId, record: entry.record, claimBearer: token, alreadyConsumed: false };
}

export async function exchangeClaimBearer(handoffId, suppliedBearer, env, adapters = {}) {
  if (typeof suppliedBearer !== 'string' || suppliedBearer.length !== 43 || !/^[A-Za-z0-9_-]+$/.test(suppliedBearer)) throw new Error('ARC2_CLAIM_BEARER_INVALID');
  const key = handoffKeyFromId(handoffId);
  const clock = adapters.clock || (() => new Date());
  await assertClaimSandboxBootstrapBound(adapters.store, handoffId, env,
    adapters.activationClock?.() || new Date());
  let entry = await readEntry(adapters.store, key);
  if (!entry) return null;
  await assertArc2EmailNegativeStateAllows(adapters.store, handoffId,
    'claim_invitation', env);
  await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
  const suppliedDigest = claimBearerDigest(suppliedBearer, env);
  if (entry.record.state === 'INVITATION_READY') {
    const usedAt = clock();
    const expiresAt = Date.parse(entry.record.claim_token_expires_at);
    if (expiresAt - usedAt.getTime() < 1000 || !safeEqual(suppliedDigest, entry.record.claim_token_hmac_sha256) ||
        !safeEqual(deriveClaimBearer(entry.record, env), suppliedBearer)) throw new Error('ARC2_CLAIM_BEARER_INVALID');
    const projected = transitionRecord(entry.record, 'CLAIM_WRAPPER_CONSUMED', {
      claim_token_hmac_sha256: null, claim_token_consumed_hmac_sha256: suppliedDigest,
      claim_token_used_at: usedAt.toISOString(), claim_wrapper_consumed_at: usedAt.toISOString(),
      claim_jwt_issued_at: Math.floor(usedAt.getTime() / 1000),
    }, usedAt);
    // Validate the exact provider URL before consuming the wrapper state so an
    // expiry-rounding failure cannot permanently brick an otherwise valid row.
    const projectedClaimUrl = netlifyClaimUrl(projected, env);
    try {
      entry = await replaceEntry(adapters.store, key, entry, projected);
      return { handoffId, record: entry.record, claimUrl: projectedClaimUrl };
    } catch (error) {
      if (error.message !== 'ARC2_STATE_CONTENTION') throw error;
      entry = await readEntry(adapters.store, key);
    }
  }
  const replayedAt = clock();
  if (entry.record.state !== 'CLAIM_WRAPPER_CONSUMED' || Date.parse(entry.record.claim_token_expires_at) - replayedAt.getTime() < 1000 ||
      !safeEqual(entry.record.claim_token_consumed_hmac_sha256 || '', suppliedDigest)) throw new Error('ARC2_CLAIM_BEARER_INVALID');
  const issuedAt = Math.floor(replayedAt.getTime() / 1000);
  const currentJwtExpiresAt = Math.min(
    Math.floor(Date.parse(entry.record.claim_token_expires_at) / 1000),
    entry.record.claim_jwt_issued_at + CLAIM_JWT_TTL_SECONDS,
  );
  if (currentJwtExpiresAt <= issuedAt) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        entry = await replaceEntry(adapters.store, key, entry, reviseRecord(entry.record, { claim_jwt_issued_at: issuedAt }, replayedAt));
        break;
      } catch (error) {
        if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 2) throw error;
        entry = await readEntry(adapters.store, key);
        if (!entry || entry.record.state !== 'CLAIM_WRAPPER_CONSUMED' ||
            !safeEqual(entry.record.claim_token_consumed_hmac_sha256 || '', suppliedDigest)) {
          throw new Error('ARC2_CLAIM_BEARER_INVALID');
        }
        if (entry.record.claim_jwt_issued_at >= issuedAt) break;
      }
    }
  }
  return { handoffId, record: entry.record, claimUrl: netlifyClaimUrl(entry.record, env) };
}

async function verifyClaimedRecord(record, deployId, destinationAccountId, env, fetchImpl, deadlineMs) {
  if (destinationAccountId === record.netlify_source_account_id) {
    throw new Error('ARC2_POSTCLAIM_ACCOUNT_OR_DEPLOY_MISMATCH');
  }
  const observedSite = await netlifyJson(`/sites/${encodeURIComponent(record.netlify_site_id)}`, env, fetchImpl, deadlineMs);
  validateSiteIntent(observedSite, record, env, true);
  if (observedSite.account_id !== destinationAccountId || observedSite.published_deploy?.id !== deployId) {
    throw new Error('ARC2_POSTCLAIM_ACCOUNT_OR_DEPLOY_MISMATCH');
  }
  const preclaim = deployId === record.preclaim_deploy_id;
  const expectedArtifacts = preclaim ? record.artifacts.map((artifact, index) => index === 0 ? {
    path: artifact.path,
    size: Buffer.byteLength(ARC2_PRECLAIM_HEADERS_FILE),
    sha256: sha256Hex(ARC2_PRECLAIM_HEADERS_FILE),
  } : artifact) : record.artifacts;
  const verified = await verifyNetlifyHandoff(record, {
    accountId: destinationAccountId,
    artifacts: expectedArtifacts,
    phase: preclaim ? 'preclaim' : 'final',
    deployId,
    formId: record.form_id,
    formName: record.form_name,
    hookId: record.hook_id,
    leadEmailSha256: record.lead_notification_email_sha256,
  }, env, fetchImpl, { deadlineMs });
  validateSiteIntent(verified.site, record, env, true);
  return verified;
}

async function finishClaim(entry, key, hint, env, adapters) {
  const fetchImpl = adapters.fetch || fetch;
  const clock = adapters.clock || (() => new Date());
  const deadlineMs = providerStageDeadline(adapters);
  const stageAdapters = { ...adapters, providerStageDeadlineMs: deadlineMs };
  // One authenticated provider hint must converge all bounded post-claim
  // stages. Each durable transition remains individually replayable, and a
  // fresh reversal guard runs before every read or provider mutation.
  while (true) {
    if (entry.record.state === 'CLAIM_WRAPPER_CONSUMED') {
      await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
      const verified = await verifyClaimedRecord(entry.record, entry.record.preclaim_deploy_id,
        hint.destinationAccountId, env, fetchImpl, deadlineMs);
      entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'CLAIM_CALLBACK_RECEIVED', {
        destination_account_id: hint.destinationAccountId,
        claim_callback_received_at: clock().toISOString(),
        production_url: verified.productionUrl,
      }, clock()));
      continue;
    }
    if (entry.record.state === 'CLAIM_CALLBACK_RECEIVED') {
      if (entry.record.destination_account_id !== hint.destinationAccountId) throw new Error('ARC2_CLAIM_DESTINATION_CONFLICT');
      await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
      const verified = await verifyClaimedRecord(entry.record, entry.record.preclaim_deploy_id,
        hint.destinationAccountId, env, fetchImpl, deadlineMs);
      entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'CLAIMED_VERIFIED', {
        claimed_verified_at: clock().toISOString(), production_url: verified.productionUrl,
      }, clock()));
      continue;
    }
    if (entry.record.state === 'CLAIMED_VERIFIED') {
      if (entry.record.destination_account_id !== hint.destinationAccountId) throw new Error('ARC2_CLAIM_DESTINATION_CONFLICT');
      await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
      const preclaim = await verifyClaimedRecord(entry.record, entry.record.preclaim_deploy_id,
        hint.destinationAccountId, env, fetchImpl, deadlineMs);
      const deployed = await ensureDeploy(entry, key, preclaim.artifactBytes, 'final', env, stageAdapters);
      entry = deployed.entry;
      await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
      const final = await verifyClaimedRecord(entry.record, deployed.ready.id,
        hint.destinationAccountId, env, fetchImpl, deadlineMs);
      const verifiedFinalRecord = {
        ...entry.record,
        final_deploy_id: deployed.ready.id,
        production_url: final.productionUrl,
      };
      const outbox = createOutboxClaim(verifiedFinalRecord, env);
      await ensureImmutableIndex(adapters.store, outbox.key, outbox.value);
      entry = await replaceEntry(adapters.store, key, entry, transitionRecord(entry.record, 'FINAL_DEPLOY_READY', {
        final_deploy_id: deployed.ready.id, production_url: final.productionUrl,
        final_deploy_ready_at: clock().toISOString(), outbox_claim_status: 'CLAIMED', outbox_claim_key_hmac_sha256: outbox.digest,
      }, clock()));
      continue;
    }
    if (entry.record.state === 'FINAL_DEPLOY_READY' || entry.record.state === 'DELIVERED') {
      if (entry.record.destination_account_id !== hint.destinationAccountId) throw new Error('ARC2_CLAIM_DESTINATION_CONFLICT');
      if (entry.record.state !== 'DELIVERED') {
        await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
      }
      await verifyClaimedRecord(entry.record, entry.record.final_deploy_id,
        hint.destinationAccountId, env, fetchImpl, deadlineMs);
      return entry;
    }
    throw new Error('ARC2_CLAIM_STATE_CONFLICT');
  }
}

export async function processClaimWebhook(input, env, adapters = {}) {
  const hint = normalizeClaimWebhook(input);
  const index = await readIndex(adapters.store, siteIndexKey(hint.siteId));
  if (!index || index.netlify_site_id !== hint.siteId) throw new Error('ARC2_UNKNOWN_CLAIM_SITE');
  await assertClaimSandboxBootstrapBound(adapters.store, index.handoff_id, env,
    adapters.activationClock?.() || new Date());
  const key = handoffKeyFromId(index.handoff_id);
  const entry = await readEntry(adapters.store, key);
  if (!entry || entry.record.netlify_site_id !== hint.siteId || entry.record.netlify_session_id !== index.netlify_session_id ||
      hint.destinationAccountId === entry.record.netlify_source_account_id) throw new Error('ARC2_CLAIM_BINDING_FAILED');
  if (!['CLAIM_WRAPPER_CONSUMED', 'CLAIM_CALLBACK_RECEIVED', 'CLAIMED_VERIFIED', 'FINAL_DEPLOY_READY', 'DELIVERED'].includes(entry.record.state)) {
    throw new Error('ARC2_CLAIM_STATE_CONFLICT');
  }
  await assertArc2EmailNegativeStateAllows(adapters.store, entry.record.handoff_id,
    'claim_invitation', env);
  if (entry.record.state !== 'DELIVERED') {
    await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: adapters.clock?.() || new Date() });
  }
  const finished = await finishClaim(entry, key, hint, env, adapters);
  return { handoffId: index.handoff_id, record: finished.record };
}

function normalizeFinalDeliveryReceipt(raw, signature, record, env, now, options = {}) {
  if (typeof raw !== 'string' || raw.length < 2 || raw.length > 20_000) {
    throw new TypeError('Final delivery receipt evidence is invalid.');
  }
  const value = JSON.parse(raw);
  if (!exactObjectKeys(value, FINAL_DELIVERY_RECEIPT_FIELDS) || canonicalJson(value) !== raw ||
      value.version !== FINAL_DELIVERY_RECEIPT_VERSION || value.scope !== FINAL_DELIVERY_RECEIPT_SCOPE) {
    throw new TypeError('Final delivery receipt fields are invalid.');
  }
  const receiptSecret = env.ARC_FINAL_DELIVERY_RECEIPT_SECRET;
  if (typeof receiptSecret !== 'string' || receiptSecret.length < 32 || receiptSecret.length > 512 ||
      receiptSecret === env.ARC_EMAIL_CLAIM_BINDING_SECRET || receiptSecret === env.ARC_HANDOFF_TRIGGER_SECRET ||
      receiptSecret === env.ARC_CLAIM_STATE_EVIDENCE_SECRET || receiptSecret === env.ARC_FINAL_DELIVERY_ACK_SECRET ||
      !sensitiveCredentialsAreIsolated(env, ['ARC_FINAL_DELIVERY_RECEIPT_SECRET'])) {
    throw new TypeError('Final delivery receipt secret is unavailable or not distinct.');
  }
  const suppliedSignature = sha256(signature, 'Final delivery receipt signature');
  if (!safeEqual(suppliedSignature, hmacHex(receiptSecret, `${FINAL_DELIVERY_RECEIPT_SIGNATURE_PREFIX}${raw}`))) {
    throw new TypeError('Final delivery receipt signature mismatch.');
  }
  if (typeof value.provider !== 'string' || !/^[a-z0-9][a-z0-9_.-]{1,63}$/.test(value.provider) ||
      value.delivery_status !== 'delivered' || value.event_type !== 'message.delivered') {
    throw new TypeError('Final delivery provider, status, or event type is invalid.');
  }
  sha256(value.provider_account_hmac_sha256, 'provider_account_hmac_sha256');
  for (const [field, label] of [['provider_event_id', 'event'], ['provider_message_id', 'message']]) {
    if (typeof value[field] !== 'string' || value[field].length < 1 || value[field].length > 512 ||
        value[field] !== value[field].trim() || /[\u0000-\u001f\u007f]/.test(value[field])) {
      throw new TypeError(`Final delivery provider ${label} id is invalid.`);
    }
  }
  const expectedBindings = {
    handoff_id: record.handoff_id,
    outbox_claim_key_hmac_sha256: record.outbox_claim_key_hmac_sha256,
    recipient_email_sha256: record.customer_email_sha256,
    production_url_sha256: sha256Hex(normalizeProductionUrl(record.production_url)),
    netlify_deploy_id_sha256: sha256Hex(record.final_deploy_id),
    netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
  };
  for (const [field, expected] of Object.entries(expectedBindings)) {
    sha256(value[field], field);
    if (!safeEqual(value[field], expected)) throw new TypeError('Final delivery receipt binding mismatch.');
  }
  const receiptTimestamp = (timestamp, label) => {
    if (typeof timestamp !== 'string') throw new TypeError(`${label} is invalid.`);
    const parsed = Date.parse(timestamp);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== timestamp) throw new TypeError(`${label} is invalid.`);
    return parsed;
  };
  const deliveredAt = receiptTimestamp(value.delivered_at, 'Final delivery delivered_at');
  const issuedAt = receiptTimestamp(value.issued_at, 'Final delivery issued_at');
  const finalReadyAt = receiptTimestamp(record.final_deploy_ready_at, 'Final deploy ready timestamp');
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || deliveredAt < finalReadyAt || deliveredAt > issuedAt ||
      issuedAt - deliveredAt > RECEIPT_FRESHNESS_MS ||
      (options.enforceFreshness !== false && (issuedAt > nowMs + 60_000 || issuedAt < nowMs - RECEIPT_FRESHNESS_MS))) {
    throw new TypeError('Final delivery receipt is stale or out of order.');
  }
  return {
    canonical: raw,
    digest: sha256Hex(raw),
    providerEventIdHmacSha256: hmacHex(receiptSecret, `${FINAL_DELIVERY_PROVIDER_EVENT_ID_PREFIX}${canonicalJson({
      provider: value.provider,
      provider_account_hmac_sha256: value.provider_account_hmac_sha256,
      provider_event_id: value.provider_event_id,
    })}`),
    providerMessageIdHmacSha256: hmacHex(receiptSecret, `${FINAL_DELIVERY_PROVIDER_MESSAGE_ID_PREFIX}${canonicalJson({
      provider: value.provider,
      provider_account_hmac_sha256: value.provider_account_hmac_sha256,
      provider_message_id: value.provider_message_id,
    })}`),
    issuedAt,
    value,
  };
}

function finalDeliveryIdentityReservations(record, receipt) {
  const common = {
    handoff_id: record.handoff_id,
    delivery_receipt_sha256: receipt.digest,
    provider: receipt.value.provider,
    provider_account_hmac_sha256: receipt.value.provider_account_hmac_sha256,
  };
  return [{
    key: `final-delivery-provider-event/${receipt.providerEventIdHmacSha256}`,
    value: {
      schema: FINAL_DELIVERY_EVENT_INDEX_SCHEMA,
      kind: 'provider-event',
      ...common,
      identity_hmac_sha256: receipt.providerEventIdHmacSha256,
    },
  }, {
    key: `final-delivery-provider-message/${receipt.providerMessageIdHmacSha256}`,
    value: {
      schema: FINAL_DELIVERY_MESSAGE_INDEX_SCHEMA,
      kind: 'provider-message',
      ...common,
      identity_hmac_sha256: receipt.providerMessageIdHmacSha256,
    },
  }];
}

function finalDeliveryOutboxValues(record, receipt) {
  const common = {
    schema: OUTBOX_CLAIM_VERSION,
    handoff_id: record.handoff_id,
    netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
    netlify_deploy_id_sha256: sha256Hex(record.final_deploy_id),
    outbox_claim_key_hmac_sha256: record.outbox_claim_key_hmac_sha256,
  };
  const receiptBinding = {
    delivery_receipt_sha256: receipt.digest,
    provider: receipt.value.provider,
    provider_account_hmac_sha256: receipt.value.provider_account_hmac_sha256,
    provider_event_id_hmac_sha256: receipt.providerEventIdHmacSha256,
    provider_message_id_hmac_sha256: receipt.providerMessageIdHmacSha256,
    event_type: receipt.value.event_type,
    delivery_status: receipt.value.delivery_status,
    delivered_at: receipt.value.delivered_at,
    receipt_issued_at: receipt.value.issued_at,
  };
  return {
    key: `outbox/${record.outbox_claim_key_hmac_sha256}`,
    claimed: { ...common, status: 'CLAIMED' },
    pending: { ...common, status: 'DELIVERY_ACK_PENDING', ...receiptBinding },
    delivered: {
      ...common,
      status: 'DELIVERED',
      ...receiptBinding,
    },
  };
}

function exactStoredValue(actual, expected) {
  return actual && canonicalJson(actual) === canonicalJson(expected);
}

async function inspectFinalDeliveryReservations(store, reservations) {
  let found = false;
  for (const reservation of reservations) {
    const existing = await readIndex(store, reservation.key);
    if (existing && !exactStoredValue(existing, reservation.value)) throw new Error('ARC2_FINAL_DELIVERY_IDENTITY_CONFLICT');
    if (existing) found = true;
  }
  return found;
}

async function inspectFinalDeliveryOutbox(store, values) {
  const entry = await readIndexEntry(store, values.key);
  if (!entry) throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_MISSING');
  if (exactStoredValue(entry.value, values.delivered)) return { entry, status: 'DELIVERED' };
  if (exactStoredValue(entry.value, values.pending)) return { entry, status: 'DELIVERY_ACK_PENDING' };
  if (exactStoredValue(entry.value, values.claimed)) return { entry, status: 'CLAIMED' };
  throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_CONFLICT');
}

async function makeFinalDeliveryOutboxPending(store, values) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const current = await inspectFinalDeliveryOutbox(store, values);
    if (current.status !== 'CLAIMED') return current;
    try {
      const entry = await replaceIndex(store, values.key, current.entry, values.pending);
      return { entry, status: 'DELIVERY_ACK_PENDING' };
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 2) throw error;
    }
  }
  throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_CONFLICT');
}

async function makeFinalDeliveryOutboxTerminal(store, values) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const current = await inspectFinalDeliveryOutbox(store, values);
    if (current.status === 'DELIVERED') return current.entry;
    if (current.status !== 'DELIVERY_ACK_PENDING') throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_CONFLICT');
    try {
      return await replaceIndex(store, values.key, current.entry, values.delivered);
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 2) throw error;
    }
  }
  throw new Error('ARC2_FINAL_DELIVERY_OUTBOX_CONFLICT');
}

function finalDeliveryMatchesRecord(record, receipt) {
  return record.state === 'DELIVERED' &&
    safeEqual(record.final_delivery_receipt_sha256, receipt.digest) &&
    record.final_delivery_provider === receipt.value.provider &&
    safeEqual(record.final_delivery_provider_account_hmac_sha256, receipt.value.provider_account_hmac_sha256) &&
    safeEqual(record.final_delivery_provider_event_id_hmac_sha256, receipt.providerEventIdHmacSha256) &&
    safeEqual(record.final_delivery_provider_message_id_hmac_sha256, receipt.providerMessageIdHmacSha256) &&
    record.final_delivery_event_type === receipt.value.event_type &&
    record.final_delivery_status === receipt.value.delivery_status &&
    record.delivered_at === receipt.value.delivered_at &&
    record.final_delivery_receipt_issued_at === receipt.value.issued_at;
}

export async function acknowledgeFinalDelivery(handoffId, evidence, signature, env, adapters = {}) {
  const key = handoffKeyFromId(handoffId);
  const clock = adapters.clock || (() => new Date());
  await assertClaimSandboxBootstrapBound(adapters.store, handoffId, env,
    adapters.activationClock?.() || new Date());
  let entry = await readEntry(adapters.store, key);
  if (!entry) return null;
  await assertArc2EmailNegativeStateAllows(adapters.store, handoffId,
    'claim_invitation', env);
  await assertArc2EmailNegativeStateAllows(adapters.store, handoffId,
    'final_delivery', env);
  if (!['FINAL_DEPLOY_READY', 'DELIVERED'].includes(entry.record.state)) throw new Error('ARC2_FINAL_DELIVERY_STATE_CONFLICT');
  const receipt = normalizeFinalDeliveryReceipt(evidence, signature, entry.record, env, clock(), { enforceFreshness: false });
  if (entry.record.state === 'DELIVERED' && !finalDeliveryMatchesRecord(entry.record, receipt)) {
    throw new Error('ARC2_FINAL_DELIVERY_RECEIPT_CONFLICT');
  }
  const reservations = finalDeliveryIdentityReservations(entry.record, receipt);
  const outboxValues = finalDeliveryOutboxValues(entry.record, receipt);
  await inspectFinalDeliveryReservations(adapters.store, reservations);
  const outboxBefore = await inspectFinalDeliveryOutbox(adapters.store, outboxValues);
  const durablyBound = outboxBefore.status !== 'CLAIMED' || entry.record.state === 'DELIVERED';
  if (!durablyBound) {
    normalizeFinalDeliveryReceipt(evidence, signature, entry.record, env, clock(), { enforceFreshness: true });
    await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
  }

  // First bind this handoff/outbox to one exact signed receipt. Competing
  // receipts cannot reserve provider identities for the same handoff.
  if (!durablyBound) {
    await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
  }
  await makeFinalDeliveryOutboxPending(adapters.store, outboxValues);
  for (const reservation of reservations) {
    if (!durablyBound) {
      await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
    }
    await ensureImmutableIndex(adapters.store, reservation.key, reservation.value);
  }

  // Blob keys cannot be committed atomically. DELIVERY_ACK_PENDING is the
  // receipt lock/no-resend latch; DELIVERED is terminal. A retry converges the
  // provider reservations, terminal outbox, and handoff before success.
  if (!durablyBound) {
    await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
  }
  await makeFinalDeliveryOutboxTerminal(adapters.store, outboxValues);
  if (entry.record.state === 'DELIVERED') return { handoffId, record: entry.record, idempotentReplay: true };

  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (!durablyBound) {
      await assertCheckoutAndReversalAllowed(entry.record, env, adapters, { now: clock() });
    }
    const delivered = transitionRecord(entry.record, 'DELIVERED', {
      delivered_at: receipt.value.delivered_at,
      final_delivery_receipt_sha256: receipt.digest,
      final_delivery_provider: receipt.value.provider,
      final_delivery_provider_account_hmac_sha256: receipt.value.provider_account_hmac_sha256,
      final_delivery_provider_event_id_hmac_sha256: receipt.providerEventIdHmacSha256,
      final_delivery_provider_message_id_hmac_sha256: receipt.providerMessageIdHmacSha256,
      final_delivery_event_type: receipt.value.event_type,
      final_delivery_status: receipt.value.delivery_status,
      final_delivery_receipt_issued_at: receipt.value.issued_at,
    }, clock());
    try {
      entry = await replaceEntry(adapters.store, key, entry, delivered);
      return { handoffId, record: entry.record, idempotentReplay: false };
    } catch (error) {
      if (error?.message !== 'ARC2_STATE_CONTENTION' || attempt === 2) throw error;
      entry = await readEntry(adapters.store, key);
      if (!entry) throw new Error('ARC2_FINAL_DELIVERY_STATE_CONFLICT');
      if (entry.record.state === 'DELIVERED') {
        if (!finalDeliveryMatchesRecord(entry.record, receipt)) throw new Error('ARC2_FINAL_DELIVERY_RECEIPT_CONFLICT');
        return { handoffId, record: entry.record, idempotentReplay: true };
      }
      if (entry.record.state !== 'FINAL_DEPLOY_READY') throw new Error('ARC2_FINAL_DELIVERY_STATE_CONFLICT');
    }
  }
  throw new Error('ARC2_FINAL_DELIVERY_STATE_CONFLICT');
}

export async function getHandoffStatus(handoffId, env, adapters = {}, options = {}) {
  const clock = adapters.clock || (() => new Date());
  await assertClaimSandboxBootstrapBound(adapters.store, handoffId, env,
    adapters.activationClock?.() || new Date());
  const entry = await readEntry(adapters.store, handoffKeyFromId(handoffId));
  if (!entry) return null;
  const record = validateExpectedBindings(entry.record);
  const status = { ...publicStatus(record, clock()), claim_available: record.state === 'INVITATION_READY' && Date.parse(record.claim_token_expires_at) > clock().getTime() };
  if (options.includePrivate && record.state === 'FINAL_DEPLOY_READY') {
    // Private claim-state evidence is the final email worker's send authority.
    // It requires a Stripe observation that does not predate final-deploy
    // readiness and is no more than one minute old. Guard both sides of the
    // Netlify readback so provider latency cannot turn an old preflight check
    // into send authority.
    const providerObservedAt = clock();
    const guardOptions = {
      maxRecheckAgeMs: STRIPE_REVERSAL_SEND_AUTHORITY_MAX_AGE_MS,
      recheckNotBefore: record.final_deploy_ready_at,
      recheckNotAfter: providerObservedAt.toISOString(),
    };
    await assertCheckoutAndReversalAllowed(record, env, adapters, {
      ...guardOptions,
      now: providerObservedAt,
    });
    const deadlineMs = providerStageDeadline(adapters);
    await verifyClaimedRecord(record, record.final_deploy_id, record.destination_account_id,
      env, adapters.fetch || fetch, deadlineMs);
    await assertCheckoutAndReversalAllowed(record, env, adapters, { ...guardOptions, now: clock() });
    Object.assign(status, createClaimStateEvidence(record, env, providerObservedAt));
  }
  return status;
}

// Private send authority for the final-delivery worker. This deliberately
// delegates to getHandoffStatus(includePrivate:true), which performs the fresh
// Stripe reversal checks around the exact final Netlify readback. Only the
// transient return value contains the production URL.
export async function getFinalDeliveryEmailAuthority(handoffId, env, adapters = {}) {
  const status = await getHandoffStatus(handoffId, env, adapters, { includePrivate: true });
  if (!status) return null;
  if (status.status !== 'FINAL_DEPLOY_READY' || typeof status.claim_state_evidence_private !== 'string' ||
      !/^[a-f0-9]{64}$/.test(String(status.claim_state_evidence_hmac_sha256 || ''))) {
    throw new Error('ARC2_FINAL_DELIVERY_EMAIL_STATE_CONFLICT');
  }
  let evidence;
  try { evidence = JSON.parse(status.claim_state_evidence_private); }
  catch { throw new Error('ARC2_FINAL_DELIVERY_EMAIL_AUTHORITY_INVALID'); }
  const fields = [
    'authorization_nonce_sha256', 'bundle_fingerprint', 'claim_callback_received_at',
    'claim_invitation_ready_at', 'claimed_verified_at', 'customer_email_sha256',
    'final_deploy_ready_at', 'handoff_artifact_evidence_sha256', 'issued_at',
    'netlify_deploy_id_sha256', 'netlify_destination_account_id_sha256',
    'netlify_session_id', 'netlify_site_id_sha256', 'outbox_claim_key_hmac_sha256',
    'outbox_claim_status', 'payment_evidence_sha256', 'preview_folder',
    'production_url', 'provider_observed_at', 'scope', 'status', 'version',
  ];
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence) ||
      Object.getPrototypeOf(evidence) !== Object.prototype ||
      JSON.stringify(Object.keys(evidence).sort()) !== JSON.stringify([...fields].sort()) ||
      canonicalJson(evidence) !== status.claim_state_evidence_private ||
      evidence.version !== CLAIM_STATE_EVIDENCE_VERSION || evidence.scope !== CLAIM_STATE_EVIDENCE_SCOPE ||
      evidence.status !== 'FINAL_DEPLOY_READY' || evidence.outbox_claim_status !== 'CLAIMED' ||
      evidence.production_url !== status.production_url ||
      !safeEqual(status.claim_state_evidence_hmac_sha256,
        hmacHex(env.ARC_CLAIM_STATE_EVIDENCE_SECRET,
          `${CLAIM_STATE_SIGNATURE_PREFIX}${status.claim_state_evidence_private}`))) {
    throw new Error('ARC2_FINAL_DELIVERY_EMAIL_AUTHORITY_INVALID');
  }
  return Object.freeze({
    handoff_id: handoffId,
    job_key: evidence.outbox_claim_key_hmac_sha256,
    recipient_email_sha256: evidence.customer_email_sha256,
    production_url: evidence.production_url,
    production_url_sha256: sha256Hex(evidence.production_url),
    netlify_site_id_sha256: evidence.netlify_site_id_sha256,
    netlify_deploy_id_sha256: evidence.netlify_deploy_id_sha256,
    final_deploy_ready_at: evidence.final_deploy_ready_at,
    authorized_at: evidence.issued_at,
    claim_state_evidence_sha256: sha256Hex(status.claim_state_evidence_private),
  });
}

export const leadRouteReceiptContract = Object.freeze({
  version: LEAD_ROUTE_RECEIPT_VERSION,
  scope: LEAD_ROUTE_RECEIPT_SCOPE,
  signaturePrefix: LEAD_ROUTE_RECEIPT_PREFIX,
  producerVersion: PRODUCER_LEAD_ROUTE_VERSION,
  producerScope: PRODUCER_LEAD_ROUTE_SCOPE,
  producerSignaturePrefix: PRODUCER_LEAD_ROUTE_PREFIX,
});

export const finalDeliveryReceiptContract = Object.freeze({
  version: FINAL_DELIVERY_RECEIPT_VERSION,
  scope: FINAL_DELIVERY_RECEIPT_SCOPE,
  signaturePrefix: FINAL_DELIVERY_RECEIPT_SIGNATURE_PREFIX,
  fields: FINAL_DELIVERY_RECEIPT_FIELDS,
});
