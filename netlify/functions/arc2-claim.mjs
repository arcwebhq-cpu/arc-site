import { jsonResponse } from '../lib/arc2-handoff-core.mjs';

// Intentionally non-runnable until a lost HTTP response can be recovered
// without replaying a consumed bearer or issuing a second claim artifact.
export default async () => jsonResponse(503, { error: 'resumable_claim_exchange_not_implemented' });

export const config = {
  path: '/api/arc2/claim',
  method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
