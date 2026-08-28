import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deterministicSiteName, hmacHex } from '../netlify/lib/arc2-handoff-core.mjs';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const previewsRoot = path.resolve(process.env.ARC_PREVIEWS_DIR || path.join(siteRoot, '../arc-previews'));
const producerPath = path.join(previewsRoot, 'zapier/arc2_verify_lead_route_staging.js');
const producerTestPath = path.join(previewsRoot, 'tests/arc2_lead_route_staging_contract.mjs');
const resolverPath = path.join(previewsRoot, 'zapier/arc2_checkout_session_artifact_adapter.js');
const retiredResolverPath = path.join(previewsRoot, 'zapier/arc2_resolve_and_finalize.js');
await stat(producerPath);
await stat(producerTestPath);

const [producer, producerTest, resolver, retiredResolver] = await Promise.all([
  readFile(producerPath, 'utf8'),
  readFile(producerTestPath, 'utf8'),
  readFile(resolverPath, 'utf8'),
  readFile(retiredResolverPath, 'utf8'),
]);
assert.match(producer, /\^arc-lead-route-\[a-z0-9-\]\{1,40\}\$/,
  'Committed ARC2 producer must require the arc-lead-route- hostname namespace.');
assert.match(producer, /version: "arc-lead-route-evidence-v1"/);
assert.match(producer, /scope: "arc-controlled-netlify-staging"/);
assert.match(producer, /staging_site_url: siteUrl\.toString\(\)/);
assert.match(producer, /staging_deploy_url: immutableDeployUrl\.toString\(\)/);
assert.match(producerTest, /const siteName = "arc-lead-route-a1b2c3d4"/,
  'The committed executable producer contract must exercise the same namespace.');
assert.match(producerTest, /const output = await runVerifier/,
  'Cross-repository source-and-fixture guard must be backed by the producer executable contract.');
assert.match(producerTest, /await runVerifier\(withAsset\.input/,
  'The executable producer contract must verify self-contained asset readback.');
assert.match(producer, /deploy_artifacts_private/);
assert.match(producer, /live asset bytes changed/);
assert.match(resolver, /preview_source_commit_sha: sourceCommitSha/);
assert.match(resolver, /payment_arc2_claim_private/,
  'The consumer must bind artifacts to a leased first-party paid outbox.');
assert.match(resolver, /arc-checkout-offer-snapshot-signature-v2/,
  'The consumer must authenticate the immutable private Checkout Session offer.');
assert.match(resolver, /arc-review-approved-source-v1/,
  'Paid production must bind the immutable approved preview source commit.');
assert.match(resolver, /split\(asset\.sourceUrl\)\.join\(`\/\$\{asset\.path\}`\)/,
  'ARC2 must rewrite receipt-bound preview assets to deterministic local paths.');
assert.match(resolver, /https:\/\/arcweb\.onl\/internal\/payment-arc2\/start/,
  'The artifact adapter must delegate payment authentication and handoff to the first-party worker.');
assert.doesNotMatch(resolver,
  /api\.stripe\.com|buy\.stripe\.com|private_link_reverse_state|payment_link_id|\bplink_/i,
  'The active V11 adapter must not regain Payment Link or direct Stripe authority.');
assert.match(retiredResolver, /ARC2_RETIRED_RESOLVER/,
  'The former Payment Link resolver must remain fail-closed.');

const payment = { checkout_session_id: 'cs_test_arc2_compatibility', bundle_fingerprint: 'a'.repeat(64) };
const stateSecret = 'arc2-producer-compatibility-secret-0123456789abcdef';
const expected = `arc-lead-route-${hmacHex(stateSecret, `site-name-v1\n${payment.checkout_session_id}\n${payment.bundle_fingerprint}`).slice(0, 24)}`;
assert.equal(deterministicSiteName(payment, stateSecret), expected);
assert.match(expected, /^arc-lead-route-[a-f0-9]{24}$/);
assert.match(`${expected}.netlify.app`, /^arc-lead-route-[a-z0-9-]{1,40}\.netlify\.app$/,
  'Every consumer-created site name must satisfy the committed producer precondition.');

console.log('ARC2 cross-repository producer source-and-fixture compatibility guard passed.');
