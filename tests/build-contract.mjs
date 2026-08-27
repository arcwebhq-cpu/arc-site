import assert from 'node:assert/strict';
import { readdir, readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = path.join(root, 'dist');
const expectedRoots = ['assets', 'claim', 'favicon.svg', 'index.html', 'payment-success', 'privacy', 'refunds', 'review', 'robots.txt', 'service-scope', 'sitemap.xml', 'support', 'terms', 'thank-you'];
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
assert.ok(files.includes('support/index.html'));
assert.ok(files.includes('assets/legal.css'));
assert.ok(files.includes('claim/index.html'));
assert.ok(files.includes('claim/claim.js'));
assert.ok(files.includes('review/index.html'));
assert.ok(files.includes('review/review.js'));
assert.ok(files.includes('robots.txt'));
assert.ok(files.includes('sitemap.xml'));
const home = await readFile(path.join(dist, 'index.html'), 'utf8');
const support = await readFile(path.join(dist, 'support/index.html'), 'utf8');
const intakeBuildMarker = await readFile(path.join(root, 'netlify/lib/intake-build-marker.mjs'), 'utf8');
const activationBuildIdentity = await readFile(path.join(root, 'netlify/lib/activation-build-identity.mjs'), 'utf8');
assert.match(home, /<form\b[^>]*action="\/thank-you\/"[^>]*data-intake-enabled="true"[^>]*data-netlify="true"[^>]*method="POST"[^>]*name="arc-preview"[^>]*netlify-honeypot="bot-field"/i,
  'Production must register the active native ARC preview form.');
assert.match(home, /<input type="hidden" name="form-name" value="arc-preview">/,
  'The native form must post the exact name consumed by ARC1.');
assert.doesNotMatch(home, /\/api\/intake\/(?:readiness|submit)/,
  'Production intake must not depend on the unused first-party readiness path.');
const intakeCtas = [...home.matchAll(/<a\b[^>]*\bdata-intake-cta\b[^>]*>[\s\S]*?<\/a>/g)].map((match) => match[0]);
assert.equal(intakeCtas.length, 2, 'The homepage must expose exactly two intake actions.');
for (const cta of intakeCtas) {
  assert.match(cta, /\bhref="#start"/, 'Every intake action must reveal the truthful intake state.');
  assert.match(cta, />\s*Get Free Preview\s*<\/a>$/, 'Every intake action must use the exact visible label “Get Free Preview”.');
}
assert.doesNotMatch(home, /mailto:arcwebhq@gmail\.com\?subject=ARC%20preview%20request/i,
  'The homepage must not fall back to an unverified preview email path.');
assert.doesNotMatch(home, /Email ARC/i, 'The homepage must not advertise an email fallback.');
const intakeStatus = home.match(/<div\b[^>]*\bid="intakeStatus"[^>]*>[\s\S]*?<\/div>/)?.[0] || '';
assert.match(intakeStatus, /\brole="status"/);
assert.match(intakeStatus, /\baria-live="polite"/);
assert.match(intakeStatus, /Free preview requests are open\./i,
  'The production page must plainly disclose that preview requests are open.');
assert.match(home, /<form\b[^>]*\baria-disabled="false"[^>]*\bdata-intake-enabled="true"/i,
  'The production form must remain active and semantically enabled.');
assert.match(home, /See Your New Website Before You Pay\./i,
  'The homepage must lead with the preview-before-payment promise.');
assert.match(home, /Get a custom five-page preview free\. Approve it, then pay\./i,
  'The homepage must explain the free-preview and approval-first flow.');
for (const removedClass of ['showcase-stamp', 'tags', 'form-promise', 'form-meta', 'privacy-note', 'process-note', 'review-confirm']) {
  assert.doesNotMatch(home, new RegExp(`class="[^"]*\\b${removedClass}\\b`), `${removedClass} clutter must not render on the homepage.`);
}
assert.doesNotMatch(home, /Secure Stripe checkout after preview approval\./,
  'The footer must not repeat sales-flow fine print.');
assert.match(intakeBuildMarker, /schema: 'arc-intake-build-marker-v1'/);
assert.match(intakeBuildMarker, /intake_enabled: false/,
  'The unused advanced Function bundle must remain fail-closed by default.');
assert.match(activationBuildIdentity, /"deployment_sha": null/,
  'A local/default build without COMMIT_REF must leave activation authority fail-closed.');
assert.match(home, /data-analytics-build-enabled="false"/,
  'Default production build must not invoke automatic analytics collection.');
assert.match(await readFile(path.join(dist, 'thank-you/index.html'), 'utf8'), /data-analytics-build-enabled="false"/,
  'The default thank-you build must not flush automatic analytics collection.');
assert.match(support, /<form id="support-form" novalidate>/i);
assert.match(support, /Send Support Request/);
assert.match(support, /One simple form/);
assert.match(support, /does not offer 24\/7 monitoring/i);
assert.match(support, /30 calendar days of support for reproducible launch-related bugs/i);
assert.doesNotMatch(support, /data-netlify|name="form-name"|method="POST"|mailto:/i);

for (const file of files.filter((name) => name.endsWith('.html'))) {
  const html = await readFile(path.join(dist, file), 'utf8');
  assert.doesNotMatch(html, /mailto:|arcwebhq@gmail\.com/i,
    `${file} must not require a customer to email ARC manually.`);
  for (const match of html.matchAll(/(?:href|src)="(\/[^"#?]*)[^\"]*"/g)) {
    const relative = match[1].replace(/^\//, '');
    const target = !relative || relative.endsWith('/') ? path.join(relative, 'index.html') : relative;
    await assert.doesNotReject(stat(path.join(dist, target)), `${file} contains a broken internal path: ${match[1]}`);
  }
}
console.log(`ARC build contract passed with ${files.length} public files.`);
