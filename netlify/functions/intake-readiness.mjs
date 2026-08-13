const ALLOWED_HOSTS = new Set(['arcweb.onl', 'arcsites.netlify.app']);

function response(status, value) {
  return new Response(JSON.stringify(value), { status, headers: {
    'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8',
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY', 'X-Robots-Tag': 'noindex, nofollow, noarchive',
  } });
}

export default async (request) => {
  if (request.method !== 'GET') return response(405, { error: 'method_not_allowed' });
  if (!ALLOWED_HOSTS.has(new URL(request.url).hostname)) return response(403, { error: 'forbidden' });
  const enabled = process.env.ARC_INTAKE_ENABLED === 'true' && process.env.ARC_LEAD_ROUTE_VERIFIED === 'true';
  return response(200, { schema: 'arc-intake-readiness-v1', intake_enabled: enabled });
};

export const config = {
  path: '/api/intake/readiness', method: 'GET',
  rateLimit: { windowLimit: 60, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
