import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { createSupportRequestHandler } from '../netlify/functions/support-request.mjs';
import { SUPPORT_REQUEST_SCHEMA } from '../netlify/lib/support-request-core.mjs';

class MemoryStore {
  constructor() { this.values = new Map(); }
  async setJSON(key, data, options = {}) {
    if (options.onlyIfNew && this.values.has(key)) return { modified: false };
    this.values.set(key, structuredClone(data));
    return { modified: true };
  }
  async getWithMetadata(key) {
    return this.values.has(key) ? { data: structuredClone(this.values.get(key)), etag: `e-${key}` } : null;
  }
}

const root = new URL('../', import.meta.url);
const [support, script, sitemap, scope, terms, privacy, refunds, packageText] = await Promise.all([
  readFile(new URL('support/index.html', root), 'utf8'),
  readFile(new URL('support/support.js', root), 'utf8'),
  readFile(new URL('sitemap.xml', root), 'utf8'),
  readFile(new URL('service-scope/index.html', root), 'utf8'),
  readFile(new URL('terms/index.html', root), 'utf8'),
  readFile(new URL('privacy/index.html', root), 'utf8'),
  readFile(new URL('refunds/index.html', root), 'utf8'),
  readFile(new URL('package.json', root), 'utf8'),
]);

assert.match(support, /<link rel="canonical" href="https:\/\/arcweb\.onl\/support\/">/);
assert.match(support, /<form id="support-form" novalidate>/);
assert.match(support, /Send Support Request/);
assert.match(support, /One simple form/);
assert.match(support, /30-day launch support/i);
assert.match(support, /does not offer 24\/7 monitoring/i);
assert.doesNotMatch([support, scope, terms, privacy, refunds].join('\n'), /mailto:|arcwebhq@gmail\.com/i);
assert.doesNotMatch(support, /data-netlify|name="form-name"|method="POST"/i);
assert.match(script, /fetch\('\/api\/support\/request'/);
assert.match(script, /result\.request_id !== requestId/);
assert.match(sitemap, /<loc>https:\/\/arcweb\.onl\/support\/<\/loc>/);
const chain = JSON.parse(packageText).scripts.test.split(' && ');
assert.ok(chain.includes('node tests/support-route-contract.mjs'));
assert.ok(chain.includes('node tests/production-route-retry-contract.mjs'));

const now = new Date('2026-08-27T12:00:00.000Z');
const requestId = '11111111-1111-4111-8111-111111111111';
const payload = {
  request_id: requestId,
  form_started_at: now.getTime() - 5_000,
  name: 'Jordan Lee',
  email: 'Jordan@Example.com',
  business: 'Evergreen Home Services',
  category: 'launch_bug',
  project_url: 'https://example.com/contact',
  details: 'The contact button does not open on mobile.',
  company_website: '',
};
const store = new MemoryStore();
const handler = createSupportRequestHandler();
const call = (body = payload, origin = 'https://arcweb.onl') => handler(new Request('https://arcweb.onl/api/support/request', {
  method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' },
  body: JSON.stringify(body),
}), { supportStore: store, clock: () => now });

let response = await call();
assert.equal(response.status, 201);
assert.deepEqual(await response.json(), {
  schema: 'arc-support-request-accepted-v1', accepted: true, request_id: requestId,
});
const record = store.values.get(`support-outbox/${requestId}`);
assert.equal(record.schema, SUPPORT_REQUEST_SCHEMA);
assert.equal(record.state, 'PENDING');
assert.equal(record.email, 'jordan@example.com');
assert.equal(record.attempt_count, 0);
assert.equal(record.provider_receipt_sha256, null);

response = await call();
assert.equal(response.status, 200, 'An exact browser retry must be idempotent.');
response = await call({ ...payload, details: 'A different issue using the same retry identity.' });
assert.equal(response.status, 409, 'A changed payload must not overwrite an accepted request.');
assert.equal((await call(payload, 'https://evil.example')).status, 403);
assert.equal((await call({ ...payload, request_id: crypto.randomUUID(), form_started_at: now.getTime() - 100 })).status, 400);
assert.equal((await call({ ...payload, request_id: crypto.randomUUID(), company_website: 'bot.example' })).status, 400);

console.log('ARC automated support route contract passed.');
