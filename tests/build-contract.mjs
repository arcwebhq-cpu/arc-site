import assert from 'node:assert/strict';
import { readdir, readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = path.join(root, 'dist');
const expectedRoots = ['assets', 'favicon.svg', 'index.html', 'privacy', 'refunds', 'service-scope', 'terms', 'thank-you'];
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

for (const forbidden of ['operations/', 'tests/', 'netlify/', '.github/', 'node_modules/', 'package.json', 'package-lock.json']) {
  assert.ok(!files.some((file) => file === forbidden || file.startsWith(forbidden)), `${forbidden} must not enter the public build.`);
}
assert.ok(files.includes('index.html'));
assert.ok(files.includes('privacy/index.html'));
assert.ok(files.includes('assets/legal.css'));
const home = await readFile(path.join(dist, 'index.html'), 'utf8');
assert.match(home, /name="form-name" value="arc-preview"/);
console.log(`ARC build contract passed with ${files.length} public files.`);
