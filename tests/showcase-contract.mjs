import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
const thumbnailDigests = Object.freeze({
  roofing: '6298bf1aac8f554fd058f560e02a288c8fe64c216c7c61a75602028dc4991a4a',
  dental: 'aad7fe472e210dd711629eb378c09b51efb2eb90bb5291ffafa72f216c34cc39',
  finance: 'e4f93365229ac781ec395c649374159692f829a0de4dd7c6a9a6ae96c01755e7',
});

assert.deepEqual(manifest.map(({ profile }) => profile).sort(), Object.keys(expected).sort(), 'Showcase profile set changed.');
for (const entry of manifest) {
  const expectedName = expected[entry.profile];
  assert.equal(entry.name, expectedName, `${entry.profile}: manifest name changed`);
  assert.equal(entry.file, `showcases/${entry.profile}/index.html`, `${entry.profile}: unexpected public path`);
  assert.equal(entry.heroAsset?.ownership, 'arc-generated-project-bound', `${entry.profile}: hero ownership provenance is missing`);
  assert.equal(entry.heroAsset?.provider, 'arc-generated', `${entry.profile}: hero media provider is inaccurate`);
  assert.equal(entry.heroAsset?.file, `showcases/assets/${entry.heroAsset?.sha256}.webp`, `${entry.profile}: hero asset is not content-addressed`);
  assert.equal(entry.heroAsset?.width, 1122, `${entry.profile}: hero asset width changed`);
  assert.equal(entry.heroAsset?.height, 1402, `${entry.profile}: hero asset height changed`);
  assert.match(home, new RegExp(`href="https:\\/\\/arcwebhq-cpu\\.github\\.io\\/arc-previews\\/showcases\\/${entry.profile}\\/"`), `${entry.profile}: homepage link is missing`);
  assert.match(home, new RegExp(`<h3>${expectedName}<\\/h3>`), `${entry.profile}: homepage display name does not match the live showcase`);
  assert.match(home, new RegExp(`alt="${expectedName} (?:website preview|showcase homepage)"`), `${entry.profile}: homepage alt text does not match the live showcase`);

  const showcase = await readFile(path.join(previewsRoot, entry.file), 'utf8');
  assert.match(showcase, new RegExp(`<title>${expectedName.replace(' Concept', ' Concept')} \\|`), `${entry.profile}: live showcase title does not match its manifest`);
  assert.match(showcase, /<meta name="arc-template-version" content="10\.0">/, `${entry.profile}: showcase is not a validated v10 artifact`);
  assert.match(showcase, new RegExp(`data-arc-showcase-photo="${entry.profile}"[^>]+data-arc-owned-asset="true"[^>]+data-arc-media-provider="arc-generated"`), `${entry.profile}: live showcase lacks its truthful ARC-generated profile photo classification`);
  assert.match(showcase, /Original ARC-generated concept imagery/, `${entry.profile}: live showcase lacks accurate image provenance copy`);
  assert.doesNotMatch(showcase, /licensed stock imagery/i, `${entry.profile}: stale stock-image claim remains`);
  const thumbnail = await readFile(path.join(siteRoot, `assets/showcases/arc-${entry.profile}-showcase-1785497742846.jpg`));
  assert.equal(createHash('sha256').update(thumbnail).digest('hex'), thumbnailDigests[entry.profile], `${entry.profile}: approved overlapping homepage thumbnail changed`);
}

for (const staleName of ['Summit Ridge Roofing', 'Lumen Dental', 'Clarity Capital']) {
  assert.doesNotMatch(home, new RegExp(staleName), `Stale showcase identity remains on the homepage: ${staleName}`);
}

console.log('ARC cross-repository showcase contract passed.');
