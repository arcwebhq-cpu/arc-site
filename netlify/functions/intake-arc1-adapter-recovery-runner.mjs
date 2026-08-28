import { getStore } from '@netlify/blobs';

import { publicIntakeAuthorityReady } from '../lib/activation-manifest-core.mjs';
import { INTAKE_ARC1_ADAPTER_STORE } from '../lib/intake-arc1-adapter-core.mjs';
import {
  INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED_ENV,
  arc1RecoveryAutomationEnabled,
  runArc1AdapterRecoveryCycle,
} from '../lib/intake-arc1-adapter-recovery-runner-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';
import { createRetentionFencedRouteHandler } from '../lib/retention-fenced-route-core.mjs';

export function createIntakeArc1AdapterRecoveryRunnerHandler() {
  return async (_request, context = {}) => {
    // The schedule is inert in every default deployment and performs no Blob
    // or network work until its dedicated switch and full protocol are on.
    if (process.env[INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED_ENV] !== 'true') return new Response(null, { status: 204 });
    if (!publicIntakeAuthorityReady(process.env)) {
      return new Response(JSON.stringify({ error: 'public_intake_authority_required' }), {
        status: 503, headers: { 'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8' },
      });
    }
    try {
      const source = context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' });
      const adapter = context.adapterStore || getStore({ name: INTAKE_ARC1_ADAPTER_STORE, consistency: 'strong' });
      const result = await runArc1AdapterRecoveryCycle(process.env, { source, adapter }, {
        clock: context.clock, wallClock: context.wallClock, uuid: context.uuid, fetch: context.fetch,
      });
      return new Response(JSON.stringify(result), {
        status: 200, headers: { 'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8' },
      });
    } catch {
      return new Response(JSON.stringify({ error: 'recovery_unavailable' }), {
        status: 503, headers: { 'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8' },
      });
    }
  };
}

const handler = createIntakeArc1AdapterRecoveryRunnerHandler();

export default createRetentionFencedRouteHandler({
  route: 'intake-arc1-adapter-recovery-runner',
  methods: null,
  active: ({ env }) => publicIntakeAuthorityReady(env) && arc1RecoveryAutomationEnabled(env),
  handler,
});

export const config = { schedule: '*/5 * * * *' };
