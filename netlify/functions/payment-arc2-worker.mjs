import { getStore } from '@netlify/blobs';

import {
  HANDOFF_STORE,
  authenticateBearer,
  canonicalJson,
  jsonResponse,
  parseJsonBodyText,
  sha256Hex,
} from '../lib/arc2-handoff-core.mjs';
import { startReviewHandoff } from '../lib/arc2-handoff-service.mjs';
import {
  arc2TransactionalEmailConfiguration,
  completePaidRecipientCapsuleHandoff,
  deletePaidPreviewRecipientCapsule,
  openPaidPreviewRecipientCapsule,
} from '../lib/arc2-transactional-email-core.mjs';
import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';
import { EMAIL_RECIPIENT_VAULT_STORE } from '../lib/email-recipient-vault-core.mjs';
import {
  PAYMENT_ARC2_OUTBOX_STORE,
  claimNextPaymentArc2StartOutbox,
  claimPaymentArc2StartOutbox,
  completePaymentArc2StartOutbox,
  createPaymentArc2ReviewEvidence,
  markPaymentArc2StartOutboxManualReview,
  paymentArc2BridgeConfiguration,
  releasePaymentArc2StartOutbox,
} from '../lib/payment-arc2-bridge-core.mjs';
import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import { retrieveStripeReviewCheckoutAuthority } from '../lib/stripe-review-checkout-adapter.mjs';
import { assertClaimMutationActivationAuthority } from '../lib/claim-sandbox-bootstrap-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';
import { sensitiveCredentialsAreIsolated } from '../lib/sensitive-credential-isolation.mjs';
import {
  StripeReversalHaltError,
  stripeReversalSandboxExemption,
} from '../lib/stripe-reversal-core.mjs';

const CLAIM_PATH = '/internal/payment-arc2/claim';
const COMPLETE_PATH = '/internal/payment-arc2/complete';
const START_PATH = '/internal/payment-arc2/start';
const BODY_LIMIT_BYTES = 16_000;
const START_BODY_LIMIT_BYTES = 4_800_000;

function exactBoolean(value) {
  return value === 'true' || value === 'false';
}

function validSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}

export function paymentArc2WorkerConfiguration(env = process.env) {
  const flagValid = exactBoolean(env.ARC_PAYMENT_ARC2_WORKER_ENABLED);
  const workerSecretValid = validSecret(env.ARC_PAYMENT_ARC2_WORKER_SECRET);
  const secretReused = workerSecretValid && !sensitiveCredentialsAreIsolated(
    env,
    ['ARC_PAYMENT_ARC2_WORKER_SECRET'],
  );
  const reversalFlagValid = exactBoolean(env.ARC_STRIPE_REVERSAL_CONTROL_REQUIRED);
  const reversalControlRequired = env.ARC_STRIPE_REVERSAL_CONTROL_REQUIRED === 'true';
  const sandboxMode = env.ARC_RUNTIME_ENVIRONMENT === 'sandbox' &&
    env.ARC_STRIPE_LIVE_MODE_ENABLED === 'false' &&
    env.ARC_ALLOW_TEST_MODE_EVENTS === 'true' &&
    env.ARC_HANDOFF_ENABLED === 'false';
  const productionMode = env.ARC_RUNTIME_ENVIRONMENT === 'production' &&
    env.ARC_STRIPE_LIVE_MODE_ENABLED === 'true' &&
    env.ARC_ALLOW_TEST_MODE_EVENTS === 'false' &&
    env.ARC_HANDOFF_ENABLED === 'true';
  const runtimeEnvironmentValid = sandboxMode || productionMode;
  const sandboxReversalExemption = stripeReversalSandboxExemption(env);
  const reversalPolicyValid = reversalFlagValid && runtimeEnvironmentValid &&
    (reversalControlRequired || sandboxReversalExemption);
  const bridgeEnabled = paymentArc2BridgeConfiguration(env).enabled;
  return Object.freeze({
    bridgeEnabled,
    enabled: bridgeEnabled && flagValid && env.ARC_PAYMENT_ARC2_WORKER_ENABLED === 'true' &&
      workerSecretValid && !secretReused && reversalPolicyValid,
    flagValid,
    productionMode,
    reversalControlRequired,
    reversalFlagValid,
    reversalPolicyValid,
    runtimeEnvironmentValid,
    sandboxMode,
    sandboxReversalExemption,
    secretReused,
    workerSecretValid,
  });
}

function exactFields(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}

const handler = async (request, context = {}) => {
  const configuration = paymentArc2WorkerConfiguration(process.env);
  if (!configuration.enabled) {
    return jsonResponse(503, {
      error: configuration.reversalControlRequired
        ? 'payment_arc2_consumer_reversal_control_required'
        : 'payment_arc2_worker_disabled',
    });
  }
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_PAYMENT_ARC2_WORKER_SECRET)) {
    return jsonResponse(401, { error: 'unauthorized' });
  }
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return jsonResponse(415, { error: 'json_required' });
  }
  let path;
  try { path = new URL(request.url).pathname; } catch {
    return jsonResponse(400, { error: 'invalid_worker_request' });
  }
  if (path !== CLAIM_PATH && path !== COMPLETE_PATH && path !== START_PATH) {
    return jsonResponse(404, { error: 'not_found' });
  }

  try {
    const bodyLimit = path === START_PATH ? START_BODY_LIMIT_BYTES : BODY_LIMIT_BYTES;
    const body = parseJsonBodyText(await readBoundedRequestText(request, bodyLimit), bodyLimit);
    const claimNext = path === CLAIM_PATH && exactFields(body, ['claim_token']);
    const claimExact = path === CLAIM_PATH && exactFields(body, ['claim_token', 'outbox_key']);
    const completeExact = path === COMPLETE_PATH && exactFields(
      body,
      ['claim_token', 'completion', 'outbox_key'],
    );
    const startExact = path === START_PATH && exactFields(body, [
      'artifact_evidence', 'artifact_evidence_hmac_sha256', 'checkout_session_id', 'claim_token',
      'deploy_artifacts', 'lead_notification_email', 'lead_route_recipient_hmac_sha256', 'outbox_key',
    ]);
    if ((!claimNext && !claimExact && !completeExact && !startExact) ||
        (body.outbox_key !== undefined && typeof body.outbox_key !== 'string') ||
        typeof body.claim_token !== 'string' ||
        (path === COMPLETE_PATH && !exactFields(body.completion, [
          'accepted',
          'arc2_start_receipt',
          'arc2_start_receipt_hmac_sha256',
          'immutable_binding_sha256',
          'schema',
        ]))) {
      return jsonResponse(400, { error: 'invalid_worker_request' });
    }
    if (path === START_PATH) {
      assertClaimMutationActivationAuthority(
        process.env,
        context.activationClock?.() || new Date(),
      );
    }
    const stores = {
      review: context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' }),
      ledger: context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' }),
      bridge: context.paymentArc2BridgeStore ||
        getStore({ name: PAYMENT_ARC2_OUTBOX_STORE, consistency: 'strong' }),
    };
    const arc2Email = arc2TransactionalEmailConfiguration(process.env);
    if (!arc2Email.flags_valid || (arc2Email.requested && !arc2Email.capsule_producer_enabled)) {
      throw new Error('ARC2_TRANSACTIONAL_EMAIL_CONFIGURATION_INVALID');
    }
    if (arc2Email.requested) {
      stores.vault = context.emailRecipientVaultStore ||
        getStore({ name: EMAIL_RECIPIENT_VAULT_STORE, consistency: 'strong' });
    }
    const adapters = { clock: context.clock };
    if (path === CLAIM_PATH) {
      const result = claimNext
        ? await claimNextPaymentArc2StartOutbox(stores, body.claim_token, process.env, adapters)
        : await claimPaymentArc2StartOutbox(
          stores,
          body.outbox_key,
          body.claim_token,
          process.env,
          adapters,
        );
      if (result === null) return jsonResponse(200, { accepted: true, state: 'EMPTY' });
      if (result.state === 'REVIEW_REQUIRED') {
        return jsonResponse(409, {
          accepted: false,
          error: 'payment_arc2_authority_halted',
          ...result,
        });
      }
      return jsonResponse(200, { accepted: true, ...result });
    }
    if (path === START_PATH) {
      const claimed = await claimPaymentArc2StartOutbox(
        stores, body.outbox_key, body.claim_token, process.env, adapters,
      );
      if (claimed.state === 'COMPLETED') {
        if (arc2Email.requested) {
          if (!claimed.payload) throw new Error('ARC2_PAID_RECIPIENT_CLEANUP_BINDING_REQUIRED');
          await deletePaidPreviewRecipientCapsule(stores.vault, stores.review, {
            invite_hmac_sha256: claimed.payload.invite_hmac_sha256,
            recipient_email_sha256: claimed.payload.recipient_email_sha256,
          }, process.env);
        }
        const { payload: ignored, ...publicClaimed } = claimed;
        return jsonResponse(200, { accepted: true, ...publicClaimed });
      }
      if (claimed.state === 'REVIEW_REQUIRED') {
        return jsonResponse(409, {
          accepted: false,
          error: 'payment_arc2_authority_halted',
          ...claimed,
        });
      }
      if (claimed.state !== 'CLAIMED') throw new Error('ARC_PAYMENT_ARC2_CLAIM_REQUIRED');
      if (typeof body.artifact_evidence !== 'string') throw new TypeError('Artifact evidence is invalid.');
      const artifact = JSON.parse(body.artifact_evidence);
      if (!exactFields(artifact, [
        'approval_content_sha256', 'artifact_manifest_sha256', 'artifacts',
        'asset_publication_receipt_sha256', 'bundle_fingerprint', 'checkout_binding_key_id',
        'checkout_config_snapshot_sha256', 'checkout_reference_sha256', 'issued_at',
        'lead_route_form_name', 'lead_route_mode', 'lead_route_recipient_hmac_sha256',
        'preview_folder', 'preview_source_commit_sha', 'preview_source_repository',
        'preview_source_tag_sha256', 'production_content_sha256', 'scope', 'version',
      ]) || canonicalJson(artifact) !== body.artifact_evidence) {
        throw new TypeError('Artifact evidence is invalid.');
      }
      const retrieveCheckoutSessionAuthority = context.paymentArc2ProviderAuthority ||
        ((sessionId, options) => retrieveStripeReviewCheckoutAuthority(
          sessionId,
          options,
          process.env,
          { stripeClient: context.stripeCheckoutAuthorityClient },
        ));
      const evidence = await createPaymentArc2ReviewEvidence(stores, {
        artifact_binding: {
          artifact_evidence_sha256: sha256Hex(body.artifact_evidence),
          artifact_manifest_sha256: artifact.artifact_manifest_sha256,
          bundle_fingerprint: artifact.bundle_fingerprint,
          checkout_reference_sha256: artifact.checkout_reference_sha256,
          preview_folder: artifact.preview_folder,
          preview_source_commit_sha: artifact.preview_source_commit_sha,
          preview_source_repository: artifact.preview_source_repository,
          production_content_sha256: artifact.production_content_sha256,
        },
        checkout_session_id: body.checkout_session_id,
        claim_token: body.claim_token,
        outbox_key: body.outbox_key,
      }, process.env, { ...adapters, retrieveCheckoutSessionAuthority });
      const sourceRecipient = arc2Email.requested
        ? await openPaidPreviewRecipientCapsule(stores.vault, stores.review, {
          invite_hmac_sha256: claimed.payload.invite_hmac_sha256,
          recipient_email_sha256: claimed.payload.recipient_email_sha256,
        }, process.env, { clock: context.clock })
        : null;
      let started;
      try {
        started = await startReviewHandoff({
          artifact_evidence: body.artifact_evidence,
          artifact_evidence_hmac_sha256: body.artifact_evidence_hmac_sha256,
          deploy_artifacts: body.deploy_artifacts,
          lead_notification_email: body.lead_notification_email,
          lead_route_recipient_hmac_sha256: body.lead_route_recipient_hmac_sha256,
          payment_evidence: evidence.canonical,
          payment_evidence_hmac_sha256: evidence.signature,
        }, process.env, {
          store: stores.ledger,
          reviewStore: stores.review,
          clock: context.clock,
          activationClock: context.activationClock,
          fetch: context.netlifyFetch,
          stripeAccountFetch: context.stripeAccountFetch,
          uuid: context.uuid,
        });
      } catch (error) {
        if (!(error instanceof StripeReversalHaltError)) throw error;
        const halted = await markPaymentArc2StartOutboxManualReview(
          stores,
          body.outbox_key,
          body.claim_token,
          error.handoffId,
          process.env,
          adapters,
        );
        return jsonResponse(409, {
          accepted: false,
          error: 'payment_arc2_authority_halted',
          ...halted,
        });
      }
      if (started.startReceipt.value.continuation_ready !== true) {
        const released = await releasePaymentArc2StartOutbox(
          stores,
          body.outbox_key,
          body.claim_token,
          process.env,
          adapters,
        );
        return jsonResponse(202, {
          accepted: true,
          handoff_id: started.handoffId,
          handoff_state: started.record.state,
          reversal_control_ready: started.reversalControlReady,
          retry_required: true,
          start_receipt: started.startReceipt.canonical,
          start_receipt_hmac_sha256: started.startReceipt.signature,
          ...released,
        });
      }
      const completion = {
          schema: 'arc2-start-processing-receipt-v2',
          accepted: true,
          immutable_binding_sha256: claimed.immutable_binding_sha256,
          arc2_start_receipt: started.startReceipt.canonical,
          arc2_start_receipt_hmac_sha256: started.startReceipt.signature,
      };
      const completed = sourceRecipient
        ? (await completePaidRecipientCapsuleHandoff(stores.vault, stores.review, {
          handoff: {
            handoff_id: started.handoffId,
            created_at: started.record.created_at,
          },
          source: sourceRecipient,
        }, process.env, {
          clock: context.clock,
          randomBytes: context.randomBytes,
          completePaymentArc2StartOutbox: () => completePaymentArc2StartOutbox(
            stores, body.outbox_key, body.claim_token, completion, process.env, adapters,
          ),
        })).completion
        : await completePaymentArc2StartOutbox(
          stores, body.outbox_key, body.claim_token, completion, process.env, adapters,
        );
      return jsonResponse(200, {
        accepted: true,
        handoff_id: started.handoffId,
        handoff_state: started.record.state,
        reversal_control_ready: started.reversalControlReady,
        start_receipt: started.startReceipt.canonical,
        start_receipt_hmac_sha256: started.startReceipt.signature,
        ...completed,
      });
    }
    const result = await completePaymentArc2StartOutbox(
      stores,
      body.outbox_key,
      body.claim_token,
      body.completion,
      process.env,
      adapters,
    );
    if (result.state === 'REVIEW_REQUIRED') {
      return jsonResponse(409, {
        accepted: false,
        error: 'payment_arc2_authority_halted',
        ...result,
      });
    }
    return jsonResponse(200, { accepted: true, ...result });
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) {
      return jsonResponse(413, { error: 'worker_request_too_large' });
    }
    if (error instanceof TypeError || error?.name === 'SyntaxError') {
      return jsonResponse(400, { error: 'invalid_worker_request' });
    }
    if (/COMPLETION_MISMATCH|START_RECEIPT_(?:INVALID|MISMATCH)/.test(error?.message || '')) {
      return jsonResponse(400, { error: 'invalid_worker_request' });
    }
    if (/REVIEW_REQUIRED|APPROVAL_|LEDGER_|PAYMENT_NOT_AUTHORIZED|AUTHORITY_CHANGED|MANUAL_REVIEW_REQUIRED/.test(error?.message || '')) {
      return jsonResponse(409, { error: 'payment_arc2_authority_halted' });
    }
    if (/LEASED|LEASE_EXPIRED|CLAIM_REQUIRED|CLAIM_MISMATCH|COMPLETION_CONFLICT|CONTENTION|CONFLICT/.test(
      error?.message || '',
    )) {
      return jsonResponse(409, { error: 'payment_arc2_worker_conflict' });
    }
    return jsonResponse(503, { error: 'payment_arc2_worker_unavailable' });
  }
};

export default createRetentionFencedRouteHandler({
  route: 'payment-arc2-worker',
  paths: [CLAIM_PATH, START_PATH, COMPLETE_PATH],
  active: ({ env }) => paymentArc2WorkerConfiguration(env).enabled,
  handler,
});

// This surface deliberately stops at authenticated leasing/completion. It is
// disabled when production reversal control is required until a provider-bound
// consumer can build the full ARC2 v4 handoff evidence, run startHandoff, and
// complete only from its signed durable start receipt.
export const config = {
  path: ['/internal/payment-arc2/claim', '/internal/payment-arc2/start', '/internal/payment-arc2/complete'],
  method: 'POST',
  rateLimit: { windowLimit: 60, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
