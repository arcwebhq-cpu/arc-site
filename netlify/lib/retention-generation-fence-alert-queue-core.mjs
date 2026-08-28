import { getStore } from '@netlify/blobs';

import {
  OPERATIONS_ALERT_STORE,
  enqueueOperationsAlertCondition,
  operationsAuditConfiguration,
} from './operations-audit-core.mjs';
import { validateRetentionGenerationFenceAlert } from
  './retention-generation-fence-core.mjs';

export const RETENTION_GENERATION_FENCE_ALERT_CATEGORY =
  'retention-generation-fence';

// Stale-fence evidence is already signed and contains no customer data. This
// adapter maps it into the existing signed, create-only operations queue. The
// queue configuration is checked before a default Blob handle is opened so
// inactive and ordinary-contention paths remain storage no-ops.
export async function enqueueRetentionGenerationFenceCriticalAlert(
  rawAlert,
  env = process.env,
  adapters = {},
) {
  if (!operationsAuditConfiguration(env).enabled) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_ALERT_QUEUE_DISABLED');
  }
  const alert = validateRetentionGenerationFenceAlert(rawAlert, env);
  const store = adapters.store || getStore({
    name: OPERATIONS_ALERT_STORE,
    consistency: 'strong',
  });
  const queued = await enqueueOperationsAlertCondition(store, {
    category: RETENTION_GENERATION_FENCE_ALERT_CATEGORY,
    detail_code: alert.reason_code.toLowerCase().replaceAll('_', '-'),
    handoff_id: alert.operation_hmac_sha256,
    severity: 'critical',
    source_timestamp: alert.detected_at,
    subject: [
      RETENTION_GENERATION_FENCE_ALERT_CATEGORY,
      alert.fence_status,
      alert.generation,
      alert.operation_kind,
      alert.operation_hmac_sha256,
      alert.intent_sha256,
      alert.reason_code,
    ].join(':'),
  }, env, { clock: adapters.clock });
  if (!queued.enabled) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_ALERT_QUEUE_DISABLED');
  }
  return Object.freeze({ alert, ...queued });
}
