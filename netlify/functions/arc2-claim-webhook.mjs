import { jsonResponse } from '../lib/arc2-handoff-core.mjs';

// Netlify's unsigned callback cannot prove destination-account control. Keep
// this endpoint non-runnable until customer-authorized post-claim readback exists.
export default async () => jsonResponse(503, { error: 'postclaim_reverification_not_implemented' });

export const config = {
  path: '/api/arc2/claim-webhook',
  method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
