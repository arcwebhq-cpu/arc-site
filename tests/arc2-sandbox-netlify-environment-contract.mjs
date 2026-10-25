import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { PROVIDER_SAFE_OFF_FLAG_NAMES } from '../scripts/provider-sandbox-safe-off-preflight.mjs';

const manifest = JSON.parse(await readFile(
  new URL('../operations/arc2-sandbox-netlify-environment.json', import.meta.url),
  'utf8',
));
const entries = manifest.environment;
const digest = (value) => createHash('sha256').update(value).digest('hex');

assert.equal(manifest.schema, 'arc2-sandbox-netlify-environment-v1');
assert.equal(manifest.version, 1);
assert.equal(manifest.state, 'SAFE_OFF');
assert.equal(manifest.launch_ready, false);
assert.deepEqual(manifest.target, {
  site_id: 'e2b737ab-70e1-48d2-9d99-a6718c04fa86',
  origin: 'https://arc2-sandbox.netlify.app',
  branch: 'codex/arc-v11-site-final-pair-20260830',
  context: 'production',
});
assert.equal(entries.length, 87);
assert.equal(new Set(entries.map(({ name }) => name)).size, 87);
for (const entry of entries) {
  assert.deepEqual(Object.keys(entry).sort(),
    ['category', 'contexts', 'name', 'scopes', 'secret', 'value']);
  assert.equal(entry.secret, false);
  assert.deepEqual(entry.contexts, ['production']);
  assert.ok(typeof entry.name === 'string' && typeof entry.value === 'string');
}

const byCategory = Object.groupBy(entries, ({ category }) => category);
assert.equal(byCategory.safe_off_control.length, 64);
assert.equal(byCategory.fixed_public_binding.length, 19);
assert.equal(byCategory.verified_resend_binding.length, 4);
assert.deepEqual(byCategory.safe_off_control.map(({ name }) => name).sort(),
  [...PROVIDER_SAFE_OFF_FLAG_NAMES]);
assert.ok(byCategory.safe_off_control.every(({ value }) => value === 'false'));

const scopeKey = ({ scopes }) => JSON.stringify(scopes);
assert.equal(entries.filter((entry) => scopeKey(entry) === '["builds"]').length, 2);
assert.equal(entries.filter((entry) => scopeKey(entry) === '["builds","functions"]').length, 1);
assert.equal(entries.filter((entry) => scopeKey(entry) === '["functions"]').length, 84);

const values = Object.fromEntries(entries.map(({ name, value }) => [name, value]));
assert.equal(values.ARC_STRIPE_WEBHOOK_API_VERSION, '2026-08-26.dahlia');
assert.equal(values.ARC_RESEND_FROM, 'ARC <preview@send.arcweb.onl>');
assert.equal(values.ARC_RESEND_PROVIDER_ACCOUNT_ID,
  '39f8376b-d8b5-40e3-b95c-37e62efe1233');
assert.equal(values.ARC_REVIEW_EMAIL_PROVIDER_ACCOUNT_ID_SHA256,
  digest(values.ARC_RESEND_PROVIDER_ACCOUNT_ID));
assert.equal(values.ARC_REVIEW_EMAIL_SENDER_IDENTITY_SHA256,
  digest(values.ARC_RESEND_FROM));
assert.equal(values.ARC_PUBLIC_ORIGIN, manifest.target.origin);
assert.equal(values.ARC_EXPECTED_NETLIFY_SITE_ID, manifest.target.site_id);
assert.equal(values.URL, manifest.target.origin);
assert.match(values.ARC_STRIPE_CHECKOUT_INTEGRATION_IDENTIFIER,
  /^arc_review_checkout_[a-z]{8}$/);

for (const forbidden of [
  'ARC_RESEND_API_KEY',
  'ARC_RESEND_WEBHOOK_SECRET',
  'ARC_STRIPE_ACCOUNT_VERIFICATION_KEY',
  'ARC_STRIPE_REVIEW_SECRET_KEY',
  'ARC_STRIPE_WEBHOOK_SIGNING_SECRET',
]) assert.equal(Object.hasOwn(values, forbidden), false);
assert.doesNotMatch(JSON.stringify(manifest),
  /(?:[sr]k_(?:test|live)|whsec_|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY)[A-Za-z0-9_+/=-]{8,}/);

console.log('ARC2 sandbox Netlify environment contract passed.');
