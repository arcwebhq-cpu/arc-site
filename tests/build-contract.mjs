import assert from 'node:assert/strict';
import { readdir, readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = path.join(root, 'dist');
const expectedRoots = ['assets', 'claim', 'favicon.svg', 'index.html', 'payment-success', 'privacy', 'refunds', 'robots.txt', 'service-scope', 'sitemap.xml', 'terms', 'thank-you'];
assert.deepEqual((await readdir(dist)).sort(), expectedRoots.sort());

const files = [];
async function walk(directory) {
  for (const name of await readdir(directory)) {
    const absolute = path.join(directory, name);
    const info = await stat(absolute);
    if (info.isDirectory()) await walk(absolute);
    else files.push(path.relative(dist, absolute).replaceAll(path.sep, '/'));
  }
}
await walk(dist);

for (const forbidden of ['operations/', 'tests/', 'netlify/', 'vendor/', '.github/', 'node_modules/', 'package.json', 'package-lock.json']) {
  assert.ok(!files.some((file) => file === forbidden || file.startsWith(forbidden)), `${forbidden} must not enter the public build.`);
}
assert.ok(files.includes('index.html'));
assert.ok(files.includes('privacy/index.html'));
assert.ok(files.includes('assets/legal.css'));
assert.ok(files.includes('claim/index.html'));
assert.ok(files.includes('claim/claim.js'));
assert.ok(files.includes('robots.txt'));
assert.ok(files.includes('sitemap.xml'));
const home = await readFile(path.join(dist, 'index.html'), 'utf8');
const intakeBuildMarker = await readFile(path.join(root, 'netlify/lib/intake-build-marker.mjs'), 'utf8');
assert.doesNotMatch(home, /data-netlify=|name="form-name"|netlify-honeypot=|method="POST"/, 'Disabled production build must not register or expose a directly postable Netlify form.');
assert.doesNotMatch(home, /<form\b[^>]*action="\/api\/intake\/submit"/, 'Disabled production build must not expose a postable intake action.');
assert.match(home, /data-intake-enabled="false"/);
assert.match(home, /data-intake-build-enabled="false"/, 'Default production build must keep the intake UI compiled closed.');
assert.match(intakeBuildMarker, /schema: 'arc-intake-build-marker-v1'/);
assert.match(intakeBuildMarker, /intake_enabled: false/, 'Default Function bundle marker must match the compiled-closed HTML.');
assert.match(home, /data-analytics-build-enabled="false"/,
  'Default production build must not invoke automatic analytics collection.');
assert.match(await readFile(path.join(dist, 'thank-you/index.html'), 'utf8'), /data-analytics-build-enabled="false"/,
  'The default thank-you build must not flush automatic analytics collection.');

for (const file of files.filter((name) => name.endsWith('.html'))) {
  const html = await readFile(path.join(dist, file), 'utf8');
  for (const match of html.matchAll(/(?:href|src)="(\/[^"#?]*)[^\"]*"/g)) {
    const relative = match[1].replace(/^\//, '');
    const target = !relative || relative.endsWith('/') ? path.join(relative, 'index.html') : relative;
    await assert.doesNotReject(stat(path.join(dist, target)), `${file} contains a broken internal path: ${match[1]}`);
  }
}
console.log(`ARC build contract passed with ${files.length} public files.`);
