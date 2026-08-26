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
  assert.equal(entry.contractVersion, 'arc-five-page-site-v1', `${entry.profile}: five-page contract changed`);
  assert.equal(entry.templateVersion, '11.0', `${entry.profile}: template version changed`);
  assert.equal(entry.page_count, 5, `${entry.profile}: page count changed`);
  assert.deepEqual(entry.pages.map(page => page.path), [
    'index.html', 'services/index.html', 'about/index.html', 'process/index.html', 'contact/index.html',
  ], `${entry.profile}: route vector changed`);
  assert.equal(entry.heroAsset?.ownership, 'arc-generated-project-bound', `${entry.profile}: hero ownership provenance is missing`);
  assert.equal(entry.heroAsset?.provider, 'arc-generated', `${entry.profile}: hero media provider is inaccurate`);
  assert.equal(entry.heroAsset?.file, `showcases/assets/${entry.heroAsset?.sha256}.webp`, `${entry.profile}: hero asset is not content-addressed`);
  assert.equal(entry.heroAsset?.width, 1122, `${entry.profile}: hero asset width changed`);
  assert.equal(entry.heroAsset?.height, 1402, `${entry.profile}: hero asset height changed`);
  assert.match(home, new RegExp(`href="https:\\/\\/arcwebhq-cpu\\.github\\.io\\/arc-previews\\/showcases\\/${entry.profile}\\/"`), `${entry.profile}: homepage link is missing`);
  assert.match(home, new RegExp(`<h3>${expectedName}<\\/h3>`), `${entry.profile}: homepage display name does not match the live showcase`);
  assert.match(home, new RegExp(`alt="${expectedName} (?:website preview|showcase homepage)"`), `${entry.profile}: homepage alt text does not match the live showcase`);

  let totalBytes = 0;
  for (const page of entry.pages) {
    assert.equal(page.file, `showcases/${entry.profile}/${page.path}`, `${entry.profile}: unexpected five-page public path`);
    const showcase = await readFile(path.join(previewsRoot, page.file), 'utf8');
    const bytes = Buffer.byteLength(showcase);
    totalBytes += bytes;
    assert.equal(bytes, page.bytes, `${entry.profile}/${page.path}: byte count changed`);
    assert.equal(createHash('sha256').update(showcase).digest('hex'), page.sha256, `${entry.profile}/${page.path}: digest changed`);
    assert.match(showcase, /<meta name="arc-template-version" content="11\.0">/, `${entry.profile}/${page.path}: showcase is not a validated v11 artifact`);
    assert.match(showcase, /<meta name="robots" content="noindex,nofollow,noarchive,nosnippet">/, `${entry.profile}/${page.path}: showcase lost noindex`);
    assert.doesNotMatch(showcase, /licensed stock imagery/i, `${entry.profile}/${page.path}: stale stock-image claim remains`);
    if (page.path === 'index.html') {
      assert.match(showcase, new RegExp(`<title>${expectedName.replace(' Concept', ' Concept')} \\|`), `${entry.profile}: live showcase title does not match its manifest`);
      assert.match(showcase, new RegExp(`data-arc-showcase-photo="${entry.profile}"[^>]+data-arc-owned-asset="true"[^>]+data-arc-media-provider="arc-generated"`), `${entry.profile}: live showcase lacks its truthful ARC-generated profile photo classification`);
    }
  }
  assert.equal(totalBytes, entry.total_bytes, `${entry.profile}: aggregate five-page byte count changed`);
  const thumbnail = await readFile(path.join(siteRoot, `assets/showcases/arc-${entry.profile}-showcase-1785497742846.jpg`));
  assert.equal(createHash('sha256').update(thumbnail).digest('hex'), thumbnailDigests[entry.profile], `${entry.profile}: approved overlapping homepage thumbnail changed`);
}

for (const staleName of ['Summit Ridge Roofing', 'Lumen Dental', 'Clarity Capital']) {
  assert.doesNotMatch(home, new RegExp(staleName), `Stale showcase identity remains on the homepage: ${staleName}`);
}

console.log('ARC cross-repository showcase contract passed.');
