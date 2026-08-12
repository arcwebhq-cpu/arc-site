import { jsonResponse } from '../lib/arc2-handoff-core.mjs';

// A Netlify email hook is not proof that a rendered synthetic submission
// reached the authoritative inbox. This remains structurally disabled until
// signed fresh route evidence and a durable invitation outbox both exist.
export default async () => jsonResponse(503, { error: 'lead_route_evidence_endpoint_not_implemented' });

export const config = {
  path: '/internal/arc2/claim-invitation-sent',
  method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
