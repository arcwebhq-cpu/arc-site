import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deterministicSiteName, hmacHex } from '../netlify/lib/arc2-handoff-core.mjs';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const previewsRoot = path.resolve(process.env.ARC_PREVIEWS_DIR || path.join(siteRoot, '../arc-previews'));
const producerPath = path.join(previewsRoot, 'zapier/arc2_verify_lead_route_staging.js');
const producerTestPath = path.join(previewsRoot, 'tests/arc2_lead_route_staging_contract.mjs');
await stat(producerPath);
await stat(producerTestPath);

const [producer, producerTest] = await Promise.all([
  readFile(producerPath, 'utf8'),
  readFile(producerTestPath, 'utf8'),
]);
assert.match(producer, /\^arc-lead-route-\[a-z0-9-\]\{1,40\}\$/,
  'Committed ARC2 producer must require the arc-lead-route- hostname namespace.');
assert.match(producer, /version: "arc-lead-route-evidence-v1"/);
assert.match(producer, /scope: "arc-controlled-netlify-staging"/);
assert.match(producer, /staging_site_url: siteUrl\.toString\(\)/);
assert.match(producer, /staging_deploy_url: immutableDeployUrl\.toString\(\)/);
assert.match(producerTest, /const stagingName = "arc-lead-route-a1b2c3d4"/,
  'The committed executable producer contract must exercise the same namespace.');
assert.match(producerTest, /const issued = await runVerifier/,
  'Cross-repository source-and-fixture guard must be backed by the producer executable contract.');

const payment = { checkout_session_id: 'cs_test_arc2_compatibility', bundle_fingerprint: 'a'.repeat(64) };
const stateSecret = 'arc2-producer-compatibility-secret-0123456789abcdef';
const expected = `arc-lead-route-${hmacHex(stateSecret, `site-name-v1\n${payment.checkout_session_id}\n${payment.bundle_fingerprint}`).slice(0, 24)}`;
assert.equal(deterministicSiteName(payment, stateSecret), expected);
assert.match(expected, /^arc-lead-route-[a-f0-9]{24}$/);
assert.match(`${expected}.netlify.app`, /^arc-lead-route-[a-z0-9-]{1,40}\.netlify\.app$/,
  'Every consumer-created site name must satisfy the committed producer precondition.');

console.log('ARC2 cross-repository producer source-and-fixture compatibility guard passed.');
