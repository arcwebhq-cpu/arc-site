import { getStore } from '@netlify/blobs';
import {
  ANALYTICS_STORE,
  eventKey,
  expirationTimestamp,
  normalizeAnalyticsEvent,
} from '../lib/analytics-core.mjs';

const ALLOWED_HOSTS = new Set(['arcweb.onl', 'arcsites.netlify.app']);
const MAX_BODY_BYTES = 2048;

function response(status) {
  return new Response(null, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export default async (request) => {
  if (request.method !== 'POST') return response(405);
  const requestUrl = new URL(request.url);
  if (!ALLOWED_HOSTS.has(requestUrl.hostname)) return response(403);
  const origin = request.headers.get('origin');
  if (origin && origin !== requestUrl.origin) return response(403);
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') return response(415);

  const declaredLength = Number(request.headers.get('content-length') || 0);
  if (declaredLength > MAX_BODY_BYTES) return response(413);

  const body = await request.text();
  if (!body || new TextEncoder().encode(body).byteLength > MAX_BODY_BYTES) return response(413);
  let event;
  try {
    event = normalizeAnalyticsEvent(JSON.parse(body), new Date());
  } catch {
    return response(400);
  }
  try {
    const store = getStore({ name: ANALYTICS_STORE, consistency: 'strong' });
    await store.setJSON(eventKey(event), event, {
      onlyIfNew: true,
      metadata: { expires_at: expirationTimestamp(event.received_at) },
    });
    return response(202);
  } catch {
    return response(503);
  }
};

export const config = {
  path: '/api/analytics/event',
  method: 'POST',
  rateLimit: {
    windowLimit: 60,
    windowSize: 60,
    aggregateBy: ['ip', 'domain'],
  },
};
