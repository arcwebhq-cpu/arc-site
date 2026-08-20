import { timingSafeEqual } from 'node:crypto';
import { getStore } from '@netlify/blobs';
import {
  aggregateAnalytics,
  ANALYTICS_STORE,
  EVENT_NAMES,
  RETENTION_DAYS,
} from '../lib/analytics-core.mjs';

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function credentials(request) {
  const header = request.headers.get('authorization') || '';
  if (!header.startsWith('Basic ')) return null;
  try {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    if (separator < 0) return null;
    return { user: decoded.slice(0, separator), password: decoded.slice(separator + 1) };
  } catch {
    return null;
  }
}

function unauthorized(status = 401) {
  const headers = {
    'Cache-Control': 'no-store',
    'Content-Type': 'text/plain; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
  };
  if (status === 401) headers['WWW-Authenticate'] = 'Basic realm="ARC analytics", charset="UTF-8"';
  return new Response(status === 503 ? 'Analytics dashboard is not configured.' : 'Authentication required.', { status, headers });
}

async function readEvents(store) {
  const { blobs } = await store.list({ prefix: 'events/' });
  const output = [];
  for (let index = 0; index < blobs.length; index += 25) {
    const batch = blobs.slice(index, index + 25);
    const values = await Promise.all(batch.map(({ key }) => store.get(key, { consistency: 'strong', type: 'json' })));
    for (const value of values) if (value) output.push(value);
  }
  return output;
}

function dashboardHtml(periods, generatedAt) {
  const labels = {
    arc_page_view: 'Page views',
    arc_cta_click: 'CTA clicks',
    arc_form_start: 'Form starts',
    arc_form_step: 'Form-step reach',
    arc_preview_request: 'Completed requests',
  };
  const cards = [7, 30, 90].map((days) => {
    const period = periods[days];
    const rows = EVENT_NAMES.map((event) => `<tr><th>${labels[event]}</th><td>${period.counts[event]}</td></tr>`).join('');
    return `<section><h2>${days} days</h2><table>${rows}<tr class="conversion"><th>View → request</th><td>${period.conversion_rate}%</td></tr></table></section>`;
  }).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive"><title>ARC Analytics</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#080808;color:#faf7ef;font:700 16px/1.4 system-ui,sans-serif}main{width:min(1080px,calc(100% - 32px));margin:auto;padding:64px 0}p{color:#a9a49c}h1{font-size:clamp(42px,7vw,82px);letter-spacing:-.06em;margin:0}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:38px}section{border:1px solid #2d2d2d;border-radius:24px;padding:22px;background:#111}h2{margin:0 0 15px;font-size:28px}table{width:100%;border-collapse:collapse}th,td{padding:11px 0;border-top:1px solid #292929;text-align:left}td{text-align:right;color:#d8f76c}.conversion th,.conversion td{padding-top:18px;color:#97dcff}@media(max-width:760px){.grid{grid-template-columns:1fr}}</style></head><body><main><h1>ARC Analytics</h1><p>Unique pseudonymous browser sessions. No names, emails, phones, form answers, IP addresses, user agents, referrers, or UTM values are stored here. The retention target is ${RETENTION_DAYS} days; deletion is manual until the separately approved pruning control is enabled and verified.</p><div class="grid">${cards}</div><p>Generated ${generatedAt}</p></main></body></html>`;
}

export default async (request) => {
  const expectedUser = process.env.ARC_ANALYTICS_DASHBOARD_USER;
  const expectedPassword = process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD;
  if (!expectedUser || !expectedPassword) return unauthorized(503);
  const supplied = credentials(request);
  if (!supplied || !safeEqual(supplied.user, expectedUser) || !safeEqual(supplied.password, expectedPassword)) return unauthorized();

  const store = getStore({ name: ANALYTICS_STORE, consistency: 'strong' });
  const now = new Date();
  const periods = aggregateAnalytics(await readEvents(store), now);
  return new Response(dashboardHtml(periods, now.toISOString()), {
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-Robots-Tag': 'noindex, nofollow, noarchive',
    },
  });
};

export const config = {
  path: '/internal/analytics',
  method: 'GET',
  rateLimit: {
    windowLimit: 30,
    windowSize: 60,
    aggregateBy: ['ip', 'domain'],
  },
};
