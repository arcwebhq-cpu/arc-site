import assert from 'node:assert/strict';
import { readdir, readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = path.join(root, 'dist');
const turnstileBuildConfigured = process.env.ARC_BUILD_TURNSTILE_ENABLED === 'true' &&
  /^[A-Za-z0-9_-]{20,80}$/.test(String(process.env.ARC_TURNSTILE_SITE_KEY || '')) &&
  process.env.ARC_TURNSTILE_EXPECTED_ACTION === 'arc_intake_submit';
const intakeBuildEnabled = process.env.ARC_BUILD_INTAKE_ENABLED === 'true' && turnstileBuildConfigured;
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
assert.doesNotMatch(home, /\bdata-netlify\b|\bnetlify-honeypot\b|name="form-name"|name="arc-preview"/i,
  'The public build must not register a bypassing native Netlify form.');
assert.doesNotMatch(home, /\/api\/intake\/readiness/,
  'The browser must not treat a public readiness endpoint as activation authority.');
if (intakeBuildEnabled) {
  assert.match(home, /<form\b[^>]*action="\/api\/intake\/submit"[^>]*aria-disabled="false"[^>]*data-intake-enabled="true"[^>]*method="POST"/i,
    'An enabled build must post only to the first-party intake Function.');
  assert.doesNotMatch(home, /<form\b[^>]*\binert\b/i);
  assert.match(home, /Free preview requests are open\./i);
  assert.match(home, /<button class="btn black" type="submit" id="submit">Request Free Preview<\/button>/);
  assert.match(home, /id="turnstileWidget"/);
  assert.match(home, /https:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js\?render=explicit/);
  assert.match(home, /action:turnstileAction,cData:ensureSubmissionRequestId\(\)/,
    'The challenge must bind its exact action and per-submission nonce.');
} else {
  const form = home.match(/<form\b[^>]*\bid="projectForm"[^>]*>/i)?.[0] || '';
  assert.match(form, /aria-disabled="true"/);
  assert.match(form, /data-intake-enabled="false"/);
  assert.match(form, /\binert\b/);
  assert.doesNotMatch(form, /\baction=|\bmethod=/i,
    'A closed build must strip both the intake endpoint and POST method.');
  assert.doesNotMatch(home, /\/api\/intake\/submit/i);
  assert.match(home, /Free preview requests are paused\./i);
  assert.match(home, /<button class="btn black" type="submit" id="submit" disabled>Request Free Preview<\/button>/);
  assert.doesNotMatch(home, /id="turnstileWidget"|challenges\.cloudflare\.com\/turnstile/,
    'A closed or unconfigured build must not load the challenge provider.');
}
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
assert.match(intakeStatus, intakeBuildEnabled ? /Free preview requests are open\./i : /Free preview requests are paused\./i,
  'The production page must plainly disclose its compiled intake state.');
assert.match(home, /See Your Website Before You Pay\./i,
  'The homepage must lead with the preview-before-payment promise.');
assert.match(home, /We build it first\. Pay only if you approve\./i,
  'The homepage must explain the free-preview and approval-first flow.');
for (const removedClass of ['showcase-stamp', 'tags', 'form-promise', 'form-meta', 'privacy-note', 'process-note', 'review-confirm']) {
  assert.doesNotMatch(home, new RegExp(`class="[^"]*\\b${removedClass}\\b`), `${removedClass} clutter must not render on the homepage.`);
}
assert.doesNotMatch(home, /Secure Stripe checkout after preview approval\./,
  'The footer must not repeat sales-flow fine print.');
assert.match(intakeBuildMarker, /schema: 'arc-intake-build-marker-v1'/);
assert.match(intakeBuildMarker, new RegExp(`intake_enabled: ${intakeBuildEnabled}`),
  'The bundled Function marker must match the compiled public form state.');
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
