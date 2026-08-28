import { getStore } from '@netlify/blobs';

import { HANDOFF_STORE } from '../lib/arc2-handoff-core.mjs';
import {
  FIRST_PARTY_RETENTION_ENABLED_ENV,
  firstPartyRetentionConfiguration,
  runFirstPartyRetentionSweepCycle,
} from '../lib/first-party-retention-core.mjs';
import { INTAKE_ABUSE_STORE } from '../lib/intake-abuse-protection-core.mjs';
import { OPERATIONS_ALERT_STORE, operationsAuditConfiguration } from
  '../lib/operations-audit-core.mjs';
import { PAYMENT_ARC2_OUTBOX_STORE } from '../lib/payment-arc2-bridge-core.mjs';
import { RETENTION_CONTROL_STORE } from '../lib/retention-control-core.mjs';
import { enqueueRetentionGenerationFenceCriticalAlert } from
  '../lib/retention-generation-fence-alert-queue-core.mjs';
import { REVIEW_REVISION_OUTBOX_STORE } from '../lib/review-revision-outbox-core.mjs';
import { REVIEW_STORE } from '../lib/review-flow-core.mjs';

const json = (status, value) => new Response(JSON.stringify(value), { status, headers: {
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
} });

export function createFirstPartyRetentionWorkerHandler() {
  return async (_request, context = {}) => {
    // This scheduled function is an exact no-op by default. Blob handles are
    // not opened until the complete, distinct retention configuration is ON.
    const configuration = firstPartyRetentionConfiguration(process.env);
    if (!configuration.requested) return new Response(null, { status: 204 });
    if (!configuration.enabled || !operationsAuditConfiguration(process.env).enabled) {
      return json(503, { error: 'first_party_retention_unavailable' });
    }
    try {
      const stores = {
        control: context.controlStore || getStore({ name: RETENTION_CONTROL_STORE, consistency: 'strong' }),
        abuse: context.abuseStore || getStore({ name: INTAKE_ABUSE_STORE, consistency: 'strong' }),
        review: context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' }),
        revision: context.revisionStore || getStore({ name: REVIEW_REVISION_OUTBOX_STORE, consistency: 'strong' }),
        handoff: context.handoffStore || getStore({ name: HANDOFF_STORE, consistency: 'strong' }),
        payment: context.paymentStore || getStore({ name: PAYMENT_ARC2_OUTBOX_STORE, consistency: 'strong' }),
        alerts: context.alertStore || getStore({ name: OPERATIONS_ALERT_STORE, consistency: 'strong' }),
      };
      const result = await runFirstPartyRetentionSweepCycle(process.env, stores, {
        clock: context.clock,
        limit: context.limit,
        uuid: context.uuid,
        emitCriticalAlert: (alert) => enqueueRetentionGenerationFenceCriticalAlert(
          alert, process.env, { clock: context.clock, store: stores.alerts },
        ),
      });
      return json(200, result);
    } catch {
      return json(503, { error: 'first_party_retention_unavailable' });
    }
  };
}

export default createFirstPartyRetentionWorkerHandler();

export const config = { schedule: '*/5 * * * *' };

export const firstPartyRetentionWorkerContract = Object.freeze({
  enabled_environment: FIRST_PARTY_RETENTION_ENABLED_ENV,
  default_enabled: false,
});
