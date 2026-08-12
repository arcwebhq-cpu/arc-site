import { jsonResponse } from '../lib/arc2-handoff-core.mjs';

// Intentionally non-runnable until state-by-state reconciliation proves that
// ambiguous Netlify writes cannot orphan or duplicate customer assets.
export default async () => jsonResponse(503, { error: 'resumable_recovery_not_implemented' });

export const config = {
  path: '/api/arc2/handoff/start',
  method: 'POST',
  rateLimit: { windowLimit: 12, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
