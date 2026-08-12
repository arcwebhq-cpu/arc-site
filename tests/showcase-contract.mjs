import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const previewsRoot = path.resolve(process.env.ARC_PREVIEWS_DIR || path.join(siteRoot, '../arc-previews'));
const home = await readFile(path.join(siteRoot, 'index.html'), 'utf8');
const manifest = JSON.parse(await readFile(path.join(previewsRoot, 'showcases/manifest.json'), 'utf8'));
const expected = Object.freeze({
  roofing: 'Ironwood Roofing Concept',
  dental: 'Cedar Dental Concept',
  finance: 'Clearwater Finance Concept',
});

assert.deepEqual(manifest.map(({ profile }) => profile).sort(), Object.keys(expected).sort(), 'Showcase profile set changed.');
for (const entry of manifest) {
  const expectedName = expected[entry.profile];
  assert.equal(entry.name, expectedName, `${entry.profile}: manifest name changed`);
  assert.equal(entry.file, `showcases/${entry.profile}/index.html`, `${entry.profile}: unexpected public path`);
  assert.match(home, new RegExp(`href="https:\\/\\/arcwebhq-cpu\\.github\\.io\\/arc-previews\\/showcases\\/${entry.profile}\\/"`), `${entry.profile}: homepage link is missing`);
  assert.match(home, new RegExp(`<h3>${expectedName}<\\/h3>`), `${entry.profile}: homepage display name does not match the live showcase`);
  assert.match(home, new RegExp(`alt="${expectedName} (?:website preview|showcase homepage)"`), `${entry.profile}: homepage alt text does not match the live showcase`);

  const showcase = await readFile(path.join(previewsRoot, entry.file), 'utf8');
  assert.match(showcase, new RegExp(`<title>${expectedName.replace(' Concept', ' Concept')} \\|`), `${entry.profile}: live showcase title does not match its manifest`);
  assert.match(showcase, /<meta name="arc-template-version" content="10\.0">/, `${entry.profile}: showcase is not a validated v10 artifact`);
}

for (const staleName of ['Summit Ridge Roofing', 'Lumen Dental', 'Clarity Capital']) {
  assert.doesNotMatch(home, new RegExp(staleName), `Stale showcase identity remains on the homepage: ${staleName}`);
}

console.log('ARC cross-repository showcase contract passed.');
