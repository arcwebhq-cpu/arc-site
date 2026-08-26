import { getStore } from '@netlify/blobs';
import {
  ANALYTICS_STORE,
  analyticsCollectionReady,
  eventKey,
  expirationTimestamp,
  normalizeAnalyticsEvent,
} from '../lib/analytics-core.mjs';

const ALLOWED_HOSTS = new Set(['arcweb.onl', 'arcsites.netlify.app']);
const MAX_BODY_BYTES = 2048;

async function boundedBodyText(request) {
  const reader = request.body?.getReader?.();
  if (!reader) throw new TypeError('Analytics body is unavailable.');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new TypeError('Analytics body chunk is invalid.');
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        try { await reader.cancel(); } catch {}
        throw new RangeError('Analytics body is too large.');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally { try { reader.releaseLock(); } catch {} }
  if (total === 0) throw new TypeError('Analytics body is empty.');
  return Buffer.concat(chunks, total).toString('utf8');
}

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
  if (!analyticsCollectionReady(process.env)) return response(503);
  if (request.method !== 'POST') return response(405);
  const requestUrl = new URL(request.url);
  if (!ALLOWED_HOSTS.has(requestUrl.hostname)) return response(403);
  const origin = request.headers.get('origin');
  if (origin && origin !== requestUrl.origin) return response(403);
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') return response(415);

  const declaredLength = Number(request.headers.get('content-length') || 0);
  if (declaredLength > MAX_BODY_BYTES) return response(413);

  let body;
  try { body = await boundedBodyText(request); } catch (error) {
    return response(error instanceof RangeError ? 413 : 400);
  }
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
