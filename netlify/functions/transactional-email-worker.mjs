import { getStore } from '@netlify/blobs';

import { HANDOFF_STORE } from '../lib/arc2-handoff-core.mjs';
import { EMAIL_SEND_ATTEMPT_STORE } from '../lib/email-send-attempt-core.mjs';
import { EMAIL_RECIPIENT_VAULT_STORE } from '../lib/email-recipient-vault-core.mjs';
import { INTAKE_CONFIRMATION_OUTBOX_STORE } from '../lib/intake-confirmation-outbox-core.mjs';
import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import {
  runTransactionalEmailWorkerCycle,
  transactionalEmailWorkerConfiguration,
} from '../lib/transactional-email-worker-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';
import { enqueueRetentionGenerationFenceCriticalAlert } from
  '../lib/retention-generation-fence-alert-queue-core.mjs';
import { RETENTION_GENERATION_FENCE_STORE } from '../lib/retention-generation-fence-core.mjs';
import { runTransactionalEmailRetentionSweepCycle } from
  '../lib/transactional-email-retention-sweep-core.mjs';

const json = (status, value) => new Response(JSON.stringify(value), { status, headers: {
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
} });

export function createTransactionalEmailWorkerHandler() {
  return async (_request, context = {}) => {
    // The schedule is inert by default and must not even create Blob handles
    // until every dedicated provider, vault, and intake switch is valid.
    const configuration = transactionalEmailWorkerConfiguration(process.env);
    if (!configuration.enabled) return new Response(null, { status: 204 });
    try {
      const stores = {
        attempt: context.attemptStore || getStore({ name: EMAIL_SEND_ATTEMPT_STORE, consistency: 'strong' }),
        vault: context.vaultStore || getStore({ name: EMAIL_RECIPIENT_VAULT_STORE, consistency: 'strong' }),
        ...(configuration.intake_enabled ? {
          confirmation: context.confirmationStore ||
            getStore({ name: INTAKE_CONFIRMATION_OUTBOX_STORE, consistency: 'strong' }),
        } : {}),
        ...(configuration.preview_review_enabled || configuration.claim_invitation_enabled ||
            configuration.final_delivery_enabled ? {
          review: context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' }),
        } : {}),
        ...(configuration.claim_invitation_enabled || configuration.final_delivery_enabled ? {
          ledger: context.arc2Store || getStore({ name: HANDOFF_STORE, consistency: 'strong' }),
        } : {}),
      };
      const result = await runTransactionalEmailWorkerCycle(process.env, stores, {
        clock: context.clock,
        fetch: context.fetch,
        randomBytes: context.randomBytes,
        stripeAccountFetch: context.stripeAccountFetch,
        stripeFactory: context.stripeFactory,
        stripeClient: context.stripeClient,
      });
      return json(200, result);
    } catch {
      return json(503, { error: 'transactional_email_worker_unavailable' });
    }
  };
}

const handler = createTransactionalEmailWorkerHandler();

const producerHandler = createRetentionFencedRouteHandler({
  route: 'transactional-email-worker',
  methods: null,
  active: ({ env }) => transactionalEmailWorkerConfiguration(env).enabled,
  handler,
});

async function transactionalEmailWorkerDispatch(request, context = {}) {
  const configuration = transactionalEmailWorkerConfiguration(process.env);
  if (!configuration.enabled || process.env.ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED !== 'true') {
    return handler(request, context);
  }
  try {
    const stores = {
      attempt: context.attemptStore ||
        getStore({ name: EMAIL_SEND_ATTEMPT_STORE, consistency: 'strong' }),
      vault: context.vaultStore ||
        getStore({ name: EMAIL_RECIPIENT_VAULT_STORE, consistency: 'strong' }),
      control: context.retentionFenceStore ||
        getStore({ name: RETENTION_GENERATION_FENCE_STORE, consistency: 'strong' }),
      review: context.reviewStore ||
        getStore({ name: REVIEW_STORE, consistency: 'strong' }),
      ledger: context.arc2Store ||
        getStore({ name: HANDOFF_STORE, consistency: 'strong' }),
    };
    const retention = await runTransactionalEmailRetentionSweepCycle(process.env, stores, {
      clock: context.retentionFenceClock || context.clock,
      uuid: context.uuid,
      staleAfterMs: context.retentionFenceStaleAfterMs,
      emitCriticalAlert: context.emitRetentionCriticalAlert || ((alert) => {
        const alertStore = context.retentionFenceAlertStore || context.operationsAlertStore;
        return enqueueRetentionGenerationFenceCriticalAlert(alert, process.env, {
          clock: context.retentionFenceClock || context.clock,
          ...(alertStore ? { store: alertStore } : {}),
        });
      }),
    });
    if (retention.state === 'IN_PROGRESS') {
      return json(503, { error: 'retention_generation_fence_contention', retryable: true });
    }
  } catch {
    return json(503, { error: 'transactional_email_retention_unavailable' });
  }
  return producerHandler(request, context);
}

// When retention is enabled the dispatcher must run outside WRITING so it can
// acquire FROZEN first; it then invokes the separately fenced producer. With
// retention disabled, this outer route fence directly protects the producer.
export default createRetentionFencedRouteHandler({
  route: 'transactional-email-worker',
  methods: null,
  active: ({ env }) => transactionalEmailWorkerConfiguration(env).enabled &&
    env.ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED !== 'true',
  handler: transactionalEmailWorkerDispatch,
});

export const config = { schedule: '* * * * *' };
