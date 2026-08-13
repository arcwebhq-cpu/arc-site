import assert from 'node:assert/strict';
import handler, { config } from '../netlify/functions/intake-readiness.mjs';

const saved = { intake: process.env.ARC_INTAKE_ENABLED, route: process.env.ARC_LEAD_ROUTE_VERIFIED };
try {
  delete process.env.ARC_INTAKE_ENABLED;
  delete process.env.ARC_LEAD_ROUTE_VERIFIED;
  let response = await handler(new Request('https://arcweb.onl/api/intake/readiness'));
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { schema: 'arc-intake-readiness-v1', intake_enabled: false });
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('access-control-allow-origin'), null);

  process.env.ARC_INTAKE_ENABLED = 'true';
  process.env.ARC_LEAD_ROUTE_VERIFIED = 'false';
  response = await handler(new Request('https://arcweb.onl/api/intake/readiness'));
  assert.equal((await response.json()).intake_enabled, false);

  process.env.ARC_LEAD_ROUTE_VERIFIED = 'true';
  response = await handler(new Request('https://arcweb.onl/api/intake/readiness'));
  assert.equal((await response.json()).intake_enabled, true);

  assert.equal((await handler(new Request('https://example.com/api/intake/readiness'))).status, 403);
  assert.equal((await handler(new Request('https://arcweb.onl/api/intake/readiness', { method: 'POST' }))).status, 405);
  assert.equal(config.path, '/api/intake/readiness');
  assert.equal(config.method, 'GET');
} finally {
  if (saved.intake === undefined) delete process.env.ARC_INTAKE_ENABLED; else process.env.ARC_INTAKE_ENABLED = saved.intake;
  if (saved.route === undefined) delete process.env.ARC_LEAD_ROUTE_VERIFIED; else process.env.ARC_LEAD_ROUTE_VERIFIED = saved.route;
}

console.log('ARC intake readiness contract passed.');
