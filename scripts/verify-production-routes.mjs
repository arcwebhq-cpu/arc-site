import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';

const expectedDeploySha = (process.env.ARC_EXPECTED_DEPLOY_SHA || '').trim();
assert.match(expectedDeploySha, /^[a-f0-9]{40}$/, 'ARC_EXPECTED_DEPLOY_SHA must be the exact main commit SHA.');

const origin = 'https://arcweb.onl';
const metadataUrl = 'https://api.netlify.com/api/v1/sites/arcsites.netlify.app';
const fetchOptions = Object.freeze({ redirect: 'error', signal: AbortSignal.timeout(15_000) });
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

async function fetchExact(url, options = {}) {
  return fetch(url, { ...fetchOptions, ...options, headers: {
    'User-Agent': 'ARC-production-route-smoke/1', ...(options.headers || {}),
  } });
}

let deployment;
for (let attempt = 0; attempt < 48; attempt += 1) {
  const response = await fetchExact(metadataUrl);
  assert.equal(response.status, 200, 'Netlify public deployment metadata must remain available.');
  const site = await response.json();
  assert.equal(site.name, 'arcsites');
  assert.equal(site.custom_domain, 'arcweb.onl');
  assert.equal(site.repo_url, 'https://github.com/arcwebhq-cpu/arc-site');
  if (site.published_deploy?.commit_ref === expectedDeploySha && site.published_deploy?.state === 'ready') {
    deployment = site.published_deploy;
    break;
  }
  await delay(5_000);
}
assert.ok(deployment, `Netlify did not publish ready commit ${expectedDeploySha} within four minutes.`);
assert.equal(deployment.context, 'production');
assert.equal(deployment.branch, 'main');

const customRoutes = [
  ['/internal/intake/arc1/adapter/claim', 503, 'consumer_claim_disabled'],
  ['/internal/intake/arc1/adapter/complete', 503, 'consumer_completion_disabled'],
  ['/internal/intake/arc1/adapter/migrate-legacy', 401, 'unauthorized'],
];
for (const [path, status, error] of customRoutes) {
  const response = await fetchExact(`${origin}${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
  });
  assert.equal(response.status, status, `${path} must reach its fail-closed Function handler.`);
  assert.match(response.headers.get('content-type') || '', /^application\/json\b/);
  assert.match(response.headers.get('cache-control') || '', /\bno-store\b/);
  assert.deepEqual(await response.json(), { error });
}

for (const functionName of [
  'intake-arc1-adapter-claim',
  'intake-arc1-adapter-complete',
  'intake-arc1-adapter-legacy-migration',
]) {
  const response = await fetchExact(`${origin}/.netlify/functions/${functionName}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
  });
  assert.equal(response.status, 404,
    `${functionName} must not remain exposed at Netlify's default Function path.`);
}

const readinessResponse = await fetchExact(`${origin}/api/intake/readiness`);
assert.equal(readinessResponse.status, 200);
assert.deepEqual(await readinessResponse.json(), { schema: 'arc-intake-readiness-v1', intake_enabled: false });

for (const [path, localPath] of [
  ['/', '../dist/index.html'],
  ['/assets/arc-social-card.png', '../dist/assets/arc-social-card.png'],
]) {
  const [remoteResponse, localBytes] = await Promise.all([
    fetchExact(`${origin}${path}`), readFile(new URL(localPath, import.meta.url)),
  ]);
  assert.equal(remoteResponse.status, 200);
  const remoteBytes = Buffer.from(await remoteResponse.arrayBuffer());
  assert.equal(sha256(remoteBytes), sha256(localBytes), `${path} must match the tested build byte-for-byte.`);
}

console.log(`ARC production route smoke passed for Netlify deploy ${deployment.id} at ${expectedDeploySha}.`);
