import { jsonResponse } from '../lib/arc2-handoff-core.mjs';

// No externally created ARC2 records can exist while the write path is
// disabled. Do not expose future-only or fabricated state as operational status.
export default async () => jsonResponse(503, { error: 'handoff_status_not_implemented' });

export const config = {
  path: '/internal/arc2/handoff-status',
  method: 'GET',
  rateLimit: { windowLimit: 60, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
