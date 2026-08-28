import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { fetchAndVerifyWithRetries } from './lib/verify-production-route-retry.mjs';

const expectedDeploySha = (process.env.ARC_EXPECTED_DEPLOY_SHA || '').trim();
assert.match(expectedDeploySha, /^[a-f0-9]{40}$/, 'ARC_EXPECTED_DEPLOY_SHA must be the exact main commit SHA.');
const intakeBuildEnabled = process.env.ARC_BUILD_INTAKE_ENABLED === 'true';

const origin = 'https://arcweb.onl';
const metadataUrl = 'https://api.netlify.com/api/v1/sites/arcsites.netlify.app';
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

async function fetchExact(url, options = {}) {
  const { timeoutMs = 15_000, ...requestOptions } = options;
  return fetch(url, { redirect: 'error', cache: 'no-store', ...requestOptions,
    signal: AbortSignal.timeout(timeoutMs), headers: {
    'User-Agent': 'ARC-production-route-smoke/1', ...(requestOptions.headers || {}),
  } });
}

let deployment;
let lastTransientState = 'the expected deploy was not visible';
const deployDeadline = Date.now() + 4 * 60_000;
while (Date.now() < deployDeadline) {
  const remainingMs = deployDeadline - Date.now();
  let response;
  try {
    response = await fetchExact(metadataUrl, { timeoutMs: Math.min(15_000, remainingMs) });
  } catch (error) {
    lastTransientState = `metadata request failed: ${error?.name || 'unknown error'}`;
    const pauseMs = Math.min(5_000, deployDeadline - Date.now());
    if (pauseMs > 0) await delay(pauseMs);
    continue;
  }
  if (response.status === 429 || response.status >= 500) {
    lastTransientState = `metadata returned transient HTTP ${response.status}`;
    const pauseMs = Math.min(5_000, deployDeadline - Date.now());
    if (pauseMs > 0) await delay(pauseMs);
    continue;
  }
  assert.equal(response.status, 200, 'Netlify public deployment metadata must remain available.');
  const site = await response.json();
  assert.equal(site.name, 'arcsites');
  assert.equal(site.custom_domain, 'arcweb.onl');
  assert.equal(site.repo_url, 'https://github.com/arcwebhq-cpu/arc-site');
  if (site.published_deploy?.commit_ref === expectedDeploySha && site.published_deploy?.state === 'ready') {
    deployment = site.published_deploy;
    break;
  }
  lastTransientState = `published commit was ${site.published_deploy?.commit_ref || 'missing'}`;
  const pauseMs = Math.min(5_000, deployDeadline - Date.now());
  if (pauseMs > 0) await delay(pauseMs);
}
assert.ok(deployment,
  `Netlify did not publish ready commit ${expectedDeploySha} within four minutes; ${lastTransientState}.`);
assert.equal(deployment.context, 'production');
assert.equal(deployment.branch, 'main');

const customRoutes = [
  ['/internal/intake/arc1/adapter/claim', 503, 'public_intake_authority_required'],
  ['/internal/intake/arc1/adapter/complete', 503, 'public_intake_authority_required'],
  ['/internal/intake/arc1/adapter/migrate-legacy', 503, 'public_intake_authority_required'],
];
const functionNames = [
  'intake-arc1-adapter-claim',
  'intake-arc1-adapter-complete',
  'intake-arc1-adapter-legacy-migration',
];
const staticRoutes = [
  ['/', '../dist/index.html'],
  ['/assets/arc-social-card.png', '../dist/assets/arc-social-card.png'],
];

await Promise.all([
  ...customRoutes.map(([path, status, error]) => fetchAndVerifyWithRetries({
    label: path,
    fetchResponse: timeoutMs => fetchExact(`${origin}${path}`, {
      timeoutMs, method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    }),
    verifyResponse: async response => {
      assert.equal(response.status, status, `${path} must reach its fail-closed Function handler.`);
      assert.match(response.headers.get('content-type') || '', /^application\/json\b/);
      assert.match(response.headers.get('cache-control') || '', /\bno-store\b/);
      assert.deepEqual(await response.json(), { error });
    },
  })),
  ...functionNames.map(functionName => fetchAndVerifyWithRetries({
    label: `/.netlify/functions/${functionName}`,
    fetchResponse: timeoutMs => fetchExact(`${origin}/.netlify/functions/${functionName}`, {
      timeoutMs, method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    }),
    verifyResponse: async response => {
      assert.equal(response.status, 404,
        `${functionName} must not remain exposed at Netlify's default Function path.`);
    },
  })),
  ...staticRoutes.map(async ([path, localPath]) => {
    const localBytes = await readFile(new URL(localPath, import.meta.url));
    return fetchAndVerifyWithRetries({
      label: path,
      fetchResponse: timeoutMs => fetchExact(`${origin}${path}`, { timeoutMs }),
      verifyResponse: async remoteResponse => {
        assert.equal(remoteResponse.status, 200);
        const remoteBytes = Buffer.from(await remoteResponse.arrayBuffer());
        assert.equal(sha256(remoteBytes), sha256(localBytes), `${path} must match the tested build byte-for-byte.`);
        if (path === '/') {
          const home = remoteBytes.toString('utf8');
          assert.doesNotMatch(home, /\bdata-netlify\b|\bnetlify-honeypot\b|name="form-name"|name="arc-preview"/i,
            'Production must not register a bypassing native Netlify form.');
          if (intakeBuildEnabled) {
            assert.match(home, /<form\b[^>]*action="\/api\/intake\/submit"[^>]*aria-disabled="false"[^>]*data-intake-enabled="true"[^>]*method="POST"/i,
              'An enabled production build must post only to the first-party intake Function.');
            assert.match(home, /Free preview requests are open\./i);
          } else {
            const form = home.match(/<form\b[^>]*\bid="projectForm"[^>]*>/i)?.[0] || '';
            assert.match(form, /aria-disabled="true"/);
            assert.match(form, /data-intake-enabled="false"/);
            assert.match(form, /\binert\b/);
            assert.doesNotMatch(form, /\baction=|\bmethod=/i);
            assert.doesNotMatch(home, /\/api\/intake\/submit/i);
            assert.match(home, /Free preview requests are paused\./i);
          }
        }
      },
    });
  }),
]);

console.log(`ARC production route smoke passed for Netlify deploy ${deployment.id} at ${expectedDeploySha}.`);
