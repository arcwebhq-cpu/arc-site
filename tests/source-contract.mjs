import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const [home, thankYou, privacy, terms, refunds, scope, readinessText, retentionControl, netlifyConfig, packageText, analyticsCore, analyticsEvent, analyticsDashboard, analyticsPrune] = await Promise.all([
  readFile(new URL('index.html', root), 'utf8'),
  readFile(new URL('thank-you/index.html', root), 'utf8'),
  readFile(new URL('privacy/index.html', root), 'utf8'),
  readFile(new URL('terms/index.html', root), 'utf8'),
  readFile(new URL('refunds/index.html', root), 'utf8'),
  readFile(new URL('service-scope/index.html', root), 'utf8'),
  readFile(new URL('operations/readiness.json', root), 'utf8'),
  readFile(new URL('operations/data-retention.md', root), 'utf8'),
  readFile(new URL('netlify.toml', root), 'utf8'),
  readFile(new URL('package.json', root), 'utf8'),
  readFile(new URL('netlify/lib/analytics-core.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/analytics-event.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/analytics-dashboard.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/analytics-prune.mjs', root), 'utf8'),
]);
const readiness = JSON.parse(readinessText);
const packageJson = JSON.parse(packageText);

assert.match(home, /<link rel="canonical" href="https:\/\/arcweb\.onl\/">/);
assert.match(home, /<meta property="og:url" content="https:\/\/arcweb\.onl\/">/);
assert.doesNotMatch(`${home}\n${privacy}\n${terms}\n${refunds}\n${scope}`, /arcsites\.netlify\.app/);
assert.doesNotMatch(privacy, /where users stopped/i);

assert.doesNotMatch(
  `${home}\n${thankYou}`,
  /\bprivate (?:ARC )?(?:website )?preview(?: link)?\b/i,
  'Preview copy must describe links as unlisted, not private.',
);
assert.match(home, /<span>Unlisted preview<\/span>/);
assert.match(thankYou, /unlisted preview link/i);
assert.match(scope, /unlisted preview controls/i);

assert.match(home, /landingPath\.value=location\.pathname\.slice\(0,500\)/);
assert.doesNotMatch(home, /landingPath\.value=.*location\.search/);
for (const name of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term']) {
  assert.match(home, new RegExp(`name="${name}"`));
}

const fileInputs = [...home.matchAll(/<input\b[^>]*\btype="file"[^>]*>/g)].map((match) => match[0]);
assert.equal(fileInputs.length, 3, 'Expected the logo and two photo inputs.');
for (const input of fileInputs) {
  assert.match(input, /accept="image\/png,image\/jpeg,image\/webp"/);
  assert.doesNotMatch(input, /svg/i);
}
assert.match(home, /const allowedRasterTypes=new Set\(\['image\/png','image\/jpeg','image\/webp'\]\)/);
assert.match(home, /if\(!isAllowedRaster\(file\)\)/);

assert.match(home, /const draftKey='arc-preview-draft-v7'/);
assert.match(home, /const draftTtlMs=7\*24\*60\*60\*1000/);
assert.match(home, /JSON\.stringify\(\{savedAt,expiresAt:savedAt\+draftTtlMs,data:draftData\(\)\}\)/);
assert.match(home, /saved\.expiresAt<=now/);
assert.match(thankYou, /removeItem\('arc-preview-draft-v7'\)/);
assert.match(privacy, /saved in this browser expire after seven days/i);

for (const untrustedHiddenName of ['submission_timestamp', 'submission_id', 'lead_route', 'lead_route_status', 'lead_route_verification', 'checkout_consent_required', 'terms_version', 'terms_accepted_at']) {
  assert.doesNotMatch(home, new RegExp(`name="${untrustedHiddenName}"`));
}
assert.match(home, /This does not authorize a charge\./);
assert.match(home, /adult purchaser must accept the then-current purchase terms again at checkout/i);
assert.match(terms, /does not authorize a charge/i);
assert.match(terms, /affirmatively accept the then-current purchase terms again at checkout/i);

assert.match(home, /const analyticsEndpoint='\/api\/analytics\/event'/);
assert.match(home, /credentials:'omit',keepalive:true/);
assert.match(home, /sessionStorage\.setItem\(pendingAnalyticsKey/);
assert.doesNotMatch(home, /name="analytics_session_id"/);
assert.match(home, /event:'arc_preview_request',event_id:randomId\(\)/);
assert.doesNotMatch(home, /track\('arc_preview_request'/);
assert.match(home, /showStep\(0,false,false\)/);
assert.match(home, /event:'arc_preview_request'/);
assert.match(thankYou, /fetch\('\/api\/analytics\/event'/);
assert.match(thankYou, /if\(response\.ok\)sessionStorage\.removeItem\(pendingKey\)/);
assert.match(privacy, /Netlify Function and Blobs store/i);
assert.match(privacy, /does not store names, business names, emails, phone numbers, addresses, form answers, IP addresses, user agents, referrers, or UTM values/i);
assert.match(privacy, /scheduled for deletion after 90 days/i);

assert.match(home, /<b>3–4 minutes<\/b>/);
assert.match(home, /id="stepCount">1 \/ 3</);
assert.match(home, /aria-valuemax="4"/);
assert.equal((home.match(/class="form-step(?: active)?"/g) || []).length, 4, 'Expected three intake steps plus review.');
assert.match(home, /Add audience or offer details/);
assert.match(home, /Adjust website structure/);
assert.match(home, /Add brand direction or proof/);
assert.match(home, /Add assets or launch details/);
assert.doesNotMatch(home, /name="target_customer"[^>]*\brequired\b/);
assert.doesNotMatch(home, /name="why_choose_you"[^>]*\brequired\b/);
assert.match(home, /function openAncestorDetails\(element\)/);
assert.match(home, /if\(first\)\{openAncestorDetails\(first\);first\.scrollIntoView/);

assert.match(home, /Before production launch, ARC must send a real test submission to this address and the recipient must confirm receipt\./);

assert.equal(readiness.schema, 'arc-operations-readiness-v1');
assert.deepEqual(readiness.offer, {
  currency: 'USD',
  amount: 5000,
  billing: 'one-time',
  deliverable: 'one-premium-single-page-website',
});
assert.equal(readiness.checkout.status, 'blocked');
assert.equal(readiness.checkout.allowed_mode, 'test-only');
assert.ok(readiness.checkout.required_evidence.includes('adult-purchaser-affirmative-acceptance'));
assert.equal(readiness.analytics.status, 'pending-live-verification');
assert.equal(readiness.analytics.receiver, 'Netlify Function /api/analytics/event');
assert.equal(readiness.analytics.dashboard, 'Basic-auth Netlify Function /internal/analytics');
assert.equal(readiness.analytics.storage, 'Netlify Blobs arc-analytics');
assert.equal(readiness.analytics.retention_days, 90);
assert.deepEqual(readiness.analytics.verified_live_events, []);
assert.ok(readiness.analytics.environment_requirements.includes('ARC_ANALYTICS_DASHBOARD_PASSWORD'));
assert.ok(readiness.analytics.activation_requirements.includes('live-event-receipt-verified'));
assert.equal(readiness.intake_routing.status, 'unverified');
assert.equal(readiness.intake_routing.verified_recipient, null);
assert.equal(readiness.customer_lead_routing.must_block_production_when_unverified, true);
assert.equal(readiness.intake_trust_boundary.status, 'pending-server-verification');
assert.equal(readiness.intake_trust_boundary.client_hidden_fields_are_authoritative, false);
assert.ok(readiness.intake_trust_boundary.required_pipeline_evidence.includes('provider-submission-id-used-for-folder-identity'));
assert.equal(readiness.asset_uploads.status, 'pending-server-verification');
assert.equal(readiness.asset_uploads.client_checks_are_security_boundary, false);
assert.ok(readiness.asset_uploads.required_pipeline_evidence.includes('content-type-and-magic-byte-match'));
assert.equal(readiness.data_retention.status, 'pending-provider-enforcement');
assert.equal(readiness.data_retention.live_compliance_claim_allowed, false);
assert.match(retentionControl, /Netlify Forms\/uploads, Zapier Tables, Gmail, GitHub, Stripe, and backup locations/);
assert.match(retentionControl, /Apollo must remain off and live checkout must remain blocked/);
assert.equal(readiness.legal_and_outreach_compliance.status, 'blocked');
assert.equal(readiness.legal_and_outreach_compliance.adult_contracting_representative, null);
assert.equal(readiness.legal_and_outreach_compliance.legal_operator, null);
assert.equal(readiness.legal_and_outreach_compliance.mailing_address, null);
assert.equal(readiness.legal_and_outreach_compliance.apollo_must_remain_off, true);
assert.match(netlifyConfig, /from = "\/operations\/\*"[\s\S]*?status = 404[\s\S]*?force = true/);
assert.match(netlifyConfig, /from = "\/tests\/\*"[\s\S]*?status = 404[\s\S]*?force = true/);
assert.match(netlifyConfig, /\[functions\][\s\S]*?directory = "netlify\/functions"/);
assert.match(netlifyConfig, /\[build\][\s\S]*?command = "npm run build"[\s\S]*?publish = "dist"/);
for (const blockedPath of ['netlify', 'node_modules']) {
  assert.match(netlifyConfig, new RegExp(`from = "\\/${blockedPath}\\/\\*"[\\s\\S]*?status = 404[\\s\\S]*?force = true`));
}
for (const blockedFile of ['package.json', 'package-lock.json']) {
  assert.match(netlifyConfig, new RegExp(`from = "\\/${blockedFile.replace('.', '\\.')}"[\\s\\S]*?status = 404[\\s\\S]*?force = true`));
}

assert.equal(packageJson.dependencies['@netlify/blobs'], '10.7.12');
assert.equal(packageJson.scripts.build, 'node scripts/build-site.mjs');
assert.equal(packageJson.scripts.test, 'node tests/source-contract.mjs && node tests/analytics-contract.mjs && npm run build && node tests/build-contract.mjs');
assert.match(analyticsCore, /const ALLOWED_KEYS = new Set\(\['event', 'event_id', 'session_id', 'path', 'cta', 'step', 'step_name'\]\)/);
assert.match(analyticsCore, /STEP_LABELS = Object\.freeze\(\{ 1: 'Business', 2: 'Offer', 3: 'Details & consent', 4: 'Review' \}\)/);
assert.match(analyticsCore, /Unexpected analytics field/);
assert.match(analyticsEvent, /new Set\(\['arcweb\.onl', 'arcsites\.netlify\.app'\]\)/);
assert.match(analyticsEvent, /onlyIfNew: true/);
assert.match(analyticsEvent, /windowLimit: 60/);
assert.doesNotMatch(analyticsEvent, /user-agent|x-forwarded|client-ip/i);
assert.match(analyticsDashboard, /ARC_ANALYTICS_DASHBOARD_USER/);
assert.match(analyticsDashboard, /ARC_ANALYTICS_DASHBOARD_PASSWORD/);
assert.match(analyticsDashboard, /timingSafeEqual/);
assert.match(analyticsDashboard, /X-Robots-Tag.*noindex/si);
assert.match(analyticsPrune, /schedule: '17 4 \* \* \*'/);
assert.match(analyticsPrune, /isExpiredMetadata/);

for (const script of [...home.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]) {
  Function(script[1]);
}
for (const script of [...thankYou.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]) {
  Function(script[1]);
}

console.log('ARC source contract passed.');
