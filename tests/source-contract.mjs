import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const [
  home,
  thankYou,
  paymentSuccess,
  privacy,
  terms,
  refunds,
  scope,
  support,
  robots,
  sitemap,
  packageText,
  buildScript,
] = await Promise.all([
  readFile(new URL('index.html', root), 'utf8'),
  readFile(new URL('thank-you/index.html', root), 'utf8'),
  readFile(new URL('payment-success/index.html', root), 'utf8'),
  readFile(new URL('privacy/index.html', root), 'utf8'),
  readFile(new URL('terms/index.html', root), 'utf8'),
  readFile(new URL('refunds/index.html', root), 'utf8'),
  readFile(new URL('service-scope/index.html', root), 'utf8'),
  readFile(new URL('support/index.html', root), 'utf8'),
  readFile(new URL('robots.txt', root), 'utf8'),
  readFile(new URL('sitemap.xml', root), 'utf8'),
  readFile(new URL('package.json', root), 'utf8'),
  readFile(new URL('scripts/build-site.mjs', root), 'utf8'),
]);
const packageJson = JSON.parse(packageText);

// Public metadata and navigation.
assert.match(home, /<html lang="en">/);
assert.match(home, /<meta name="viewport" content="width=device-width, initial-scale=1">/);
assert.match(home, /<title>ARC — Free Website Preview<\/title>/);
assert.match(home, /<meta name="description" content="Get a free five-page website preview by email\. Pay only if you approve it\.">/);
assert.match(home, /<link rel="canonical" href="https:\/\/arcweb\.onl\/">/);
assert.match(home, /<meta property="og:url" content="https:\/\/arcweb\.onl\/">/);
assert.match(home, /<meta property="og:image" content="https:\/\/arcweb\.onl\/assets\/arc-social-card\.png">/);
assert.match(home, /<meta property="og:image:width" content="1200">/);
assert.match(home, /<meta property="og:image:height" content="630">/);
assert.match(home, /<meta name="twitter:card" content="summary_large_image">/);
assert.match(home, /<meta name="twitter:image" content="https:\/\/arcweb\.onl\/assets\/arc-social-card\.png">/);
assert.match(home, /<a class="skip-link" href="#top">Skip to main content<\/a>/);
assert.match(home, /<nav class="nav" aria-label="Primary navigation">/);
assert.match(home, /<main id="top" class="page" tabindex="-1">/);

for (const path of ['#work', '#scope', '#process', '#start']) {
  assert.match(home, new RegExp(`href="${path}"`));
}
for (const path of ['/support/', '/service-scope/', '/terms/', '/privacy/', '/refunds/']) {
  assert.match(home, new RegExp(`href="${path.replaceAll('/', '\\/')}"`));
}

// The homepage has one plain customer journey: free preview, email delivery,
// approval, payment, launch, and ownership.
assert.match(home, /<h1>See Your New Website Before You Pay\.<\/h1>/);
assert.match(home, /Get a custom five-page preview free\. Approve it, then pay\./);
assert.match(home, /<h2>Get your free preview\.<\/h2>/);
assert.match(home, /We(?:’|')ll email your five-page preview\. Pay only if you approve\./);
assert.match(home, /<div class="step"><b>1<\/b><h3>Free Preview<\/h3><\/div>/);
assert.match(home, /<div class="step"><b>2<\/b><h3>Approve &amp; Pay<\/h3><\/div>/);
assert.match(home, /<div class="step"><b>3<\/b><h3>Launch &amp; Own<\/h3><\/div>/);

const intakeCtas = [...home.matchAll(/<a\b([^>]*)\bdata-intake-cta\b([^>]*)>([\s\S]*?)<\/a>/g)];
assert.equal(intakeCtas.length, 2, 'Expected exactly the navigation and hero preview actions.');
for (const [, beforeAttribute, afterAttribute, label] of intakeCtas) {
  assert.match(`${beforeAttribute}${afterAttribute}`, /\bhref="#start"/,
    'Every preview action must lead to the on-page request state.');
  assert.equal(label.trim(), 'Get Free Preview', 'Every preview action must use the same short label.');
}
assert.doesNotMatch(home, /Email ARC/i, 'The homepage must not advertise a manual email fallback.');
assert.doesNotMatch(home, /mailto:/i, 'The homepage must not contain a mail link.');

// Keep the offer concise and consistent.
assert.match(home, /Concept previews — not client work\./);
assert.match(home, /<h2 class="section-title reveal">ARC website concepts\.<\/h2>/);
assert.doesNotMatch(home, /showcase-label|work-kicker|View preview/i,
  'The homepage must not repeat tiny showcase badges or card helper labels.');
assert.match(home, /<h2 class="section-title small reveal">\$5,000 once\. Five pages\.<\/h2>/);
assert.match(home, /Five-page website\.[\s\S]*?Home, Services, About, Process, and Contact\./);
assert.match(home, /One clear lead path\.[\s\S]*?A form, booking link, order link, or phone number\./);
assert.match(home, /Ready to launch\.[\s\S]*?Responsive build, basic accessibility, metadata, and launch setup\./);
assert.match(home, /See it first\.[\s\S]*?Review all five preview pages before deciding to buy\./);
assert.match(home, /You own it\.[\s\S]*?Ownership after payment, plus 30 days of launch bug support\./);
assert.match(home, /\$5,000 USD once\. Pay only if you approve\. Your ownership handoff starts automatically after payment\./);
assert.match(home, /Extra pages, domain, hosting, paid tools, ecommerce, and ongoing service cost extra\./);
assert.doesNotMatch(home, /bank or card issuer|currency conversion|destination address/i,
  'Detailed purchase caveats belong on policy pages, not the sales homepage.');
assert.doesNotMatch(home, /\$500\s*\/\s*(?:mo|month)|monthly maintenance/i);
assert.doesNotMatch(home, /Secure .* after preview approval\./i);
for (const removedClass of ['showcase-stamp', 'tags', 'form-promise', 'form-meta', 'privacy-note', 'process-note', 'review-confirm']) {
  assert.doesNotMatch(home, new RegExp(`class="[^"]*\\b${removedClass}\\b`),
    `Homepage clutter class ${removedClass} must stay removed.`);
}

// The production form is a native Netlify form so the existing ARC1 provider
// trigger receives form-name=arc-preview without a separate readiness gate.
assert.match(home, /<div class="intake-status open" id="intakeStatus" role="status" aria-live="polite" tabindex="-1">Free preview requests are open\.<\/div>/);
assert.match(home, /<form\b[^>]*\baction="\/thank-you\/"[^>]*\baria-disabled="false"[^>]*\bdata-intake-enabled="true"[^>]*\bdata-netlify="true"[^>]*\bmethod="POST"[^>]*\bname="arc-preview"[^>]*\bnetlify-honeypot="bot-field"[^>]*>/i);
assert.match(home, /<input type="hidden" name="form-name" value="arc-preview">/);
assert.match(home, /<button class="btn ghost" type="button" id="prev">/);
assert.match(home, /<button class="btn black" type="button" id="next">/);
assert.match(home, /<button class="btn black" type="submit" id="submit">Request Free Preview<\/button>/);
assert.match(home, /form\.addEventListener\('submit',event=>\{/);
assert.doesNotMatch(home, /\/api\/intake\/(?:readiness|submit)/,
  'Native intake must not depend on the unused first-party readiness path.');
assert.doesNotMatch(home, /HTMLFormElement\.prototype\.submit/);

// The build preserves the native form while the unused advanced Function bundle
// retains its separate build marker and fail-closed controls.
assert.doesNotMatch(buildScript, /Production intake could not be compiled fail-closed/);
assert.doesNotMatch(buildScript, /action="\/api\/intake\/submit"/);
assert.match(buildScript, /intake_enabled: \$\{intakeBuildEnabled\}/);
assert.match(buildScript, /'support'/, 'The support route must be included in the public build allowlist.');

// Form accessibility, data minimization, and local-draft behavior.
assert.match(home, /id="formProgress" role="progressbar" aria-label="Preview request progress" aria-valuemin="1" aria-valuemax="4" aria-valuenow="1"/);
assert.equal((home.match(/class="form-step(?: active)?"/g) || []).length, 4,
  'Expected three request steps plus review.');
assert.match(home, /id="error" role="alert" aria-live="polite"/);
assert.match(home, /function openAncestorDetails\(element\)/);
assert.match(home, /field\.setAttribute\('aria-invalid','true'\)/);
assert.match(home, /if\(first\)\{openAncestorDetails\(first\);first\.scrollIntoView/);
assert.match(home, /const freshConfirmationFields=new Set\(\['asset_permission','budget_confirmed','terms_accepted'\]\)/);
assert.match(home, /I can legally use these files, and they have no watermarks\./);
assert.match(home, /finished five-page website costs \$5,000 once, payable only if I approve the preview\./);
assert.match(home, /I(?:’|')m authorized and accept[\s\S]{0,280}I(?:’|')m not charged today\./);
for (const policyPath of ['/terms/', '/privacy/', '/refunds/', '/service-scope/']) {
  assert.match(home, new RegExp(`href="${policyPath.replaceAll('/', '\\/')}"`));
}

const fileInputs = [...home.matchAll(/<input\b[^>]*\btype="file"[^>]*>/g)].map((match) => match[0]);
assert.equal(fileInputs.length, 3, 'Expected the logo and two photo inputs.');
for (const input of fileInputs) {
  assert.match(input, /accept="image\/png,image\/jpeg,image\/webp"/);
  assert.match(input, /data-max-bytes="1250000"/);
  assert.doesNotMatch(input, /svg/i);
}
assert.match(home, /const uploadMaxFileBytes=1250000,uploadMaxTotalBytes=3000000/);
assert.match(home, /PNG\/JPG\/WebP · 1\.25 MB each · 3 MB total/);
assert.match(home, /const draftTtlMs=7\*24\*60\*60\*1000/);
assert.match(home, /saved\.expiresAt<=now/);
assert.match(thankYou, /removeItem\('arc-preview-draft-v8'\)/);
assert.match(privacy, /not restored after seven days/i);
assert.match(privacy, /cannot delete browser storage while the site is closed/i);
assert.doesNotMatch(home, /landingPath\.value=.*location\.search/);
for (const hiddenName of ['submission_timestamp', 'submission_id', 'lead_route_status', 'terms_accepted_at']) {
  assert.doesNotMatch(home, new RegExp(`name="${hiddenName}"`));
}

// Images and motion must stay usable on slow networks and reduced-motion setups.
const images = [...home.matchAll(/<img\b[^>]*>/g)].map((match) => match[0]);
assert.equal(images.length, 6, 'Expected three hero images and three work previews.');
for (const image of images) assert.match(image, /\balt="[^"]+"/);
assert.equal((home.match(/loading="lazy" decoding="async"/g) || []).length, 3);
assert.equal((home.match(/fetchpriority="high"/g) || []).length, 1);
assert.match(home, /@media\(prefers-reduced-motion:reduce\)/);
assert.match(home, /document\.documentElement\.classList\.add\('reveal-ready'\)/);
assert.doesNotMatch(home, /function resetReveal\(|classList\.remove\('show'\)/);

// Public post-request and policy pages must agree with the homepage offer.
assert.match(thankYou, /complete, unlisted five-page ARC preview/i);
assert.match(thankYou, /Pay only if you approve the complete website\./i);
assert.match(paymentSuccess, /verification in progress/i);
assert.match(paymentSuccess, /You may close this page/i);
assert.doesNotMatch(paymentSuccess, /Payment received|Payment confirmed|moving to production/i,
  'The public success page must not claim unverified payment or production state.');
assert.match(paymentSuccess, /noindex,nofollow,noarchive/i);
assert.match(paymentSuccess, /<meta name="referrer" content="no-referrer">/);

for (const document of [home, terms, refunds, scope, paymentSuccess]) assert.match(document, /\$5,000/);
assert.doesNotMatch([home, terms, refunds, scope, paymentSuccess].join('\n'),
  /applicable sales tax|destination-based sales tax|\+ tax/i,
  'Customer-facing pages must present the flat $5,000 price used by live checkout.');
assert.match(terms, /free preview request applies only to that request and does not authorize a charge/i);
assert.match(terms, /A preview request is free and does not require a purchase/i);
assert.match(terms, /costs \$5,000 USD, paid once after approval of the complete preview/i);
assert.match(terms, /There is no subscription or automatic renewal/i);
assert.match(terms, /does not guarantee traffic, search ranking, leads, revenue/i);
assert.match(refunds, /If you do not approve it, do not purchase it/i);
assert.match(refunds, /No refund request is needed because no payment was made/i);
assert.match(scope, /exactly five connected marketing pages/i);
assert.match(scope, /Home, Services, About, Process, and Contact/);
assert.match(scope, /Review all five pages before deciding whether to purchase/i);
assert.match(scope, /ownership handoff starts automatically after successful payment verification/i);
assert.doesNotMatch([home, terms, scope].join('\n'), /preview revision rounds?|Two revision rounds/i,
  'The automated offer must not promise a manual pre-purchase revision loop.');
assert.match(scope, /30 calendar days of support/i);
assert.match(scope, /does not include new pages or sections, new integrations, ongoing content changes/i);

// Support remains separate from the sales CTA and uses one automated request form.
assert.match(support, /<link rel="canonical" href="https:\/\/arcweb\.onl\/support\/">/);
assert.match(support, /<form id="support-form" novalidate>/i);
assert.match(support, /Send Support Request/);
assert.match(support, /One simple form/);
assert.match(support, /30 calendar days of support for reproducible launch-related bugs/i);
assert.doesNotMatch(support, /data-netlify|name="form-name"|method="POST"|mailto:/i);
assert.doesNotMatch([home, paymentSuccess, privacy, terms, refunds, scope, support].join('\n'),
  /mailto:|arcwebhq@gmail\.com/i, 'No customer-facing page may require a manual email to ARC.');

// Search indexing includes public policy/support pages and excludes state pages.
assert.match(robots, /Disallow: \/thank-you\//);
assert.match(robots, /Disallow: \/payment-success\//);
assert.match(robots, /Sitemap: https:\/\/arcweb\.onl\/sitemap\.xml/);
for (const path of ['/', '/service-scope/', '/terms/', '/privacy/', '/refunds/', '/support/']) {
  assert.match(sitemap, new RegExp(`<loc>https:\\/\\/arcweb\\.onl${path.replaceAll('/', '\\/')}<\\/loc>`));
}
assert.doesNotMatch(sitemap, /thank-you|payment-success/i);

// The standard test command must keep the source, built-output, and browser
// contracts in the release path without duplicating operational checks here.
assert.equal(packageJson.scripts.build, 'node scripts/build-site.mjs');
const testChain = packageJson.scripts.test.split(' && ');
for (const required of [
  'node tests/source-contract.mjs',
  'node tests/support-route-contract.mjs',
  'node tests/production-route-retry-contract.mjs',
  'npm run build',
  'node tests/build-contract.mjs',
  'node tests/browser-contract.mjs',
]) {
  assert.ok(testChain.includes(required), `npm test must include ${required}.`);
}
assert.ok(testChain.indexOf('node tests/source-contract.mjs') < testChain.indexOf('npm run build'));
assert.ok(testChain.indexOf('npm run build') < testChain.indexOf('node tests/build-contract.mjs'));
assert.ok(testChain.indexOf('node tests/build-contract.mjs') < testChain.indexOf('node tests/browser-contract.mjs'));

for (const script of [...home.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]) {
  Function(script[1]);
}
for (const script of [...thankYou.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]) {
  Function(script[1]);
}

console.log('ARC public source contract passed.');
