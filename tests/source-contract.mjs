import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const [home, thankYou, paymentSuccess, claimPage, claimScript, privacy, terms, refunds, scope, robots, sitemap, readinessText, manualActivation, retentionControl, customerEmailContract, netlifyConfig, packageText, imageSizePackageText, imageSizeDisabled, analyticsCore, analyticsEvent, analyticsDashboard, analyticsPrune, arc2Core, arc2Service, arc2Store, arc2Start, arc2Claim, arc2Webhook, arc2Invitation, arc2Status, intakeSubmissionCore, intakeSubmit] = await Promise.all([
  readFile(new URL('index.html', root), 'utf8'),
  readFile(new URL('thank-you/index.html', root), 'utf8'),
  readFile(new URL('payment-success/index.html', root), 'utf8'),
  readFile(new URL('claim/index.html', root), 'utf8'),
  readFile(new URL('claim/claim.js', root), 'utf8'),
  readFile(new URL('privacy/index.html', root), 'utf8'),
  readFile(new URL('terms/index.html', root), 'utf8'),
  readFile(new URL('refunds/index.html', root), 'utf8'),
  readFile(new URL('service-scope/index.html', root), 'utf8'),
  readFile(new URL('robots.txt', root), 'utf8'),
  readFile(new URL('sitemap.xml', root), 'utf8'),
  readFile(new URL('operations/readiness.json', root), 'utf8'),
  readFile(new URL('operations/manual-activation.md', root), 'utf8'),
  readFile(new URL('operations/data-retention.md', root), 'utf8'),
  readFile(new URL('operations/customer-email-contract.md', root), 'utf8'),
  readFile(new URL('netlify.toml', root), 'utf8'),
  readFile(new URL('package.json', root), 'utf8'),
  readFile(new URL('vendor/image-size-disabled/package.json', root), 'utf8'),
  readFile(new URL('vendor/image-size-disabled/index.mjs', root), 'utf8'),
  readFile(new URL('netlify/lib/analytics-core.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/analytics-event.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/analytics-dashboard.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/analytics-prune.mjs', root), 'utf8'),
  readFile(new URL('netlify/lib/arc2-handoff-core.mjs', root), 'utf8'),
  readFile(new URL('netlify/lib/arc2-handoff-service.mjs', root), 'utf8'),
  readFile(new URL('netlify/lib/arc2-handoff-store.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/arc2-handoff-start.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/arc2-claim.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/arc2-claim-webhook.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/arc2-claim-invitation-ready.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/arc2-handoff-status.mjs', root), 'utf8'),
  readFile(new URL('netlify/lib/intake-submission-core.mjs', root), 'utf8'),
  readFile(new URL('netlify/functions/intake-submit.mjs', root), 'utf8'),
]);
const readiness = JSON.parse(readinessText);
const packageJson = JSON.parse(packageText);
const imageSizePackage = JSON.parse(imageSizePackageText);
const intakeBuildMarker = await readFile(new URL('netlify/lib/intake-build-marker.mjs', root), 'utf8');
const buildScript = await readFile(new URL('scripts/build-site.mjs', root), 'utf8');
const stripeCheckoutCore = await readFile(new URL('netlify/lib/stripe-checkout-core.mjs', root), 'utf8');
const stripeAccountVerification = await readFile(new URL('netlify/lib/stripe-account-verification.mjs', root), 'utf8');
const stripeWebhook = await readFile(new URL('netlify/functions/stripe-reversal-webhook.mjs', root), 'utf8');

assert.match(home, /<link rel="canonical" href="https:\/\/arcweb\.onl\/">/);
assert.match(home, /<meta property="og:url" content="https:\/\/arcweb\.onl\/">/);
assert.match(home, /<meta property="og:image" content="https:\/\/arcweb\.onl\/assets\/showcases\//);
assert.match(home, /<meta name="twitter:card" content="summary_large_image">/);
for (const category of ['roofing', 'dental', 'finance']) {
  assert.match(home, new RegExp(`https:\\/\\/arcwebhq-cpu\\.github\\.io\\/arc-previews\\/showcases\\/${category}\\/`));
}
assert.doesNotMatch(home, /summit-ridge-roofing-qa-v20|lumen-dental-showcase|clarity-capital-showcase/);
assert.doesNotMatch(`${home}\n${privacy}\n${terms}\n${refunds}\n${scope}`, /arcsites\.netlify\.app/);
assert.doesNotMatch(privacy, /where users stopped/i);
assert.match(paymentSuccess, /Stripe verification in progress/i);
assert.match(paymentSuccess, /verifies the Checkout Session directly with Stripe/i);
assert.match(paymentSuccess, /You may close this page/i);
assert.match(paymentSuccess, /seven business days/i);
assert.match(paymentSuccess, /ownership handoff/i);
assert.doesNotMatch(paymentSuccess, /Payment received|Payment confirmed|Your ARC build is moving to production/i);
assert.match(paymentSuccess, /noindex,nofollow,noarchive/i);
assert.match(paymentSuccess, /<meta name="referrer" content="no-referrer">/);
assert.match(paymentSuccess, /<script>if\(location\.search\)history\.replaceState\(null,'','\/payment-success\/'\)<\/script>[\s\S]*?<link rel="icon"/);
assert.match(claimPage, /noindex,nofollow,noarchive/i);
assert.match(claimPage, /no-referrer/i);
assert.match(claimScript, /history\.replaceState\(null, '', '\/claim\/'\)/);
assert.match(claimPage, /Preparing your secure handoff/i);
assert.ok(claimScript.includes("rawFragment.match(/^#arc2\\.([a-f0-9]{64})\\.([A-Za-z0-9_-]{43})$/)"));
assert.match(claimScript, /fetch\('\/api\/arc2\/claim'/);
assert.match(claimScript, /Authorization: `Bearer \$\{bearer\}`/);
assert.match(claimScript, /'X-ARC-Handoff-Id': handoffId/);
assert.match(claimScript, /credentials: 'omit'/);
assert.match(claimScript, /referrerPolicy: 'no-referrer'/);
assert.match(claimScript, /hostname !== 'app\.netlify\.com'/);
assert.match(claimScript, /location\.replace\(target\.toString\(\)\)/);
assert.doesNotMatch(claimScript, /localStorage|sessionStorage|console\.|dataLayer|analytics/i);
assert.doesNotMatch(claimScript, /[?&](?:token|secret|handoff)=/i);

assert.doesNotMatch(
  `${home}\n${thankYou}`,
  /\bprivate (?:ARC )?(?:website )?preview(?: link)?\b/i,
  'Preview copy must describe links as unlisted, not private.',
);
assert.match(home, /<span>Unlisted preview<\/span>/);
assert.match(thankYou, /unlisted preview link/i);
assert.match(scope, /unlisted preview controls/i);
assert.match(home, /class="skip-link" href="#top">Skip to main content<\/a>/);
assert.match(home, /<nav class="nav" aria-label="Primary navigation">/);
assert.match(home, /<main id="top" class="page" tabindex="-1">/);
assert.match(home, /\.js\.reveal-ready \.reveal/);
assert.match(home, /document\.documentElement\.classList\.add\('reveal-ready'\)/);
assert.match(home, /\.js\.reveal-ready \.work-item \.work-copy/);
assert.match(home, /\.js\.reveal-ready \.offer-row h3/);
assert.match(home, /\.js\.reveal-ready \.process-line \.step/);
assert.match(home, /\.js\.reveal-ready \.work-item\.show \.work-copy/);
assert.match(home, /\.js\.reveal-ready \.offer-row\.show h3/);
assert.match(home, /\.js\.reveal-ready \.process-line\.show \.step/);
assert.doesNotMatch(home, /function resetReveal\(|classList\.remove\('show'\)/);
assert.equal((home.match(/loading="lazy" decoding="async"/g) || []).length, 3, 'Below-fold showcase images must be lazy and asynchronously decoded.');
assert.equal((home.match(/fetchpriority="high"/g) || []).length, 1, 'Only the main hero image should receive high fetch priority.');

assert.match(home, /landingPath\.value=location\.pathname\.slice\(0,500\)/);
assert.doesNotMatch(home, /landingPath\.value=.*location\.search/);
for (const name of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term']) {
  assert.match(home, new RegExp(`name="${name}"`));
}

const fileInputs = [...home.matchAll(/<input\b[^>]*\btype="file"[^>]*>/g)].map((match) => match[0]);
assert.equal(fileInputs.length, 3, 'Expected the logo and two photo inputs.');
for (const input of fileInputs) {
  assert.match(input, /accept="image\/png,image\/jpeg,image\/webp"/);
  assert.match(input, /data-max-bytes="1250000"/);
  assert.doesNotMatch(input, /data-max-mb=/);
  assert.doesNotMatch(input, /svg/i);
}
assert.match(home, /const allowedRasterTypes=new Set\(\['image\/png','image\/jpeg','image\/webp'\]\)/);
assert.match(home, /const uploadMaxFileBytes=1250000,uploadMaxTotalBytes=3000000/);
assert.match(home, /Maximum 1\.25 MB per file and 3 MB total/);
assert.match(home, /if\(!isAllowedRaster\(file\)\)/);

assert.match(home, /const draftKey='arc-preview-draft-v7'/);
assert.match(home, /data-intake-enabled="false"/);
assert.match(home, /data-intake-build-enabled="true"/);
assert.match(home, /form\.dataset\.intakeBuildEnabled==='true'/);
assert.match(home, /id="projectForm" inert/);
assert.equal((home.match(/<a\b[^>]*\bdata-intake-cta\b[^>]*>/g) || []).length, 2, 'Expected the navigation and hero intake actions.');
assert.doesNotMatch(home, /data-intake-cta[^>]*href="#start"/,
  'The source/default intake actions must fail closed to a truthful manual-email fallback.');
assert.match(home, /data-intake-cta[^>]*href="mailto:arcwebhq@gmail\.com\?subject=ARC%20preview%20request"[^>]*>Email ARC About a Preview<\/a>/);
assert.match(home, /Online preview requests are paused\.[\s\S]*?Email ARC about a manual preview/);
assert.match(home, /intakeCtas\.forEach\(link=>\{link\.href=enabled\?'#start':'mailto:arcwebhq@gmail\.com\?subject=ARC%20preview%20request'/,
  'Only exact live readiness may restore the online-intake CTA.');
assert.match(home, /fetchWithTimeout\('\/api\/intake\/readiness'/);
assert.match(home, /ARC_INTAKE_ENABLED|intake_enabled/);
assert.match(home, /<form action="\/api\/intake\/submit"/);
assert.match(home, /name="submission_request_id" id="submissionRequestId"/);
assert.match(home, /crypto\.randomUUID/);
assert.match(home, /crypto\.getRandomValues/);
assert.match(home, /fetchWithTimeout\('\/api\/intake\/submit',\{method:'POST',body:new FormData\(form\)/);
assert.match(home, /fetchWithTimeout\('\/api\/intake\/readiness',[\s\S]*?,8000\)/,
  'Readiness requests must fail closed instead of hanging the intake UI.');
assert.match(home, /fetchWithTimeout\('\/api\/intake\/submit',[\s\S]*?,60000\)/,
  'Preview submission must have a bounded wait on slow or failed networks.');
assert.match(home, /Your answers are still here—wait a moment, then try once or email ARC/);
assert.doesNotMatch(home, /data-netlify=|name="form-name"|netlify-honeypot=/,
  'Even an enabled build must not register a native Netlify Form that bypasses runtime readiness.');
assert.doesNotMatch(home, /HTMLFormElement\.prototype\.submit/);
assert.match(home, /const draftTtlMs=7\*24\*60\*60\*1000/);
assert.match(home, /const freshConfirmationFields=new Set\(\['asset_permission','budget_confirmed','terms_accepted'\]\)/);
assert.match(home, /freshConfirmationFields\.has\(field\.name\)/);
assert.match(home, /JSON\.stringify\(\{savedAt,expiresAt:savedAt\+draftTtlMs,requestId:ensureSubmissionRequestId\(\),data:draftData\(\)\}\)/);
assert.match(home, /submissionRequestIdPattern\.test\(saved\.requestId\|\|''\)/,
  'The idempotency nonce must survive a retained-form reload for an exact retry.');
assert.match(home, /saved\.expiresAt<=now/);
assert.match(thankYou, /removeItem\('arc-preview-draft-v7'\)/);
const acceptedResponseIndex = home.indexOf('const accepted=(response.status===200||response.status===201)');
const acceptedDraftRemovalIndex = home.indexOf('localStorage.removeItem(draftKey)', acceptedResponseIndex);
const acceptedRedirectIndex = home.indexOf("location.assign('/thank-you/')", acceptedResponseIndex);
assert.ok(acceptedResponseIndex > -1 && acceptedDraftRemovalIndex > acceptedResponseIndex && acceptedDraftRemovalIndex < acceptedRedirectIndex,
  'A verified accepted response must clear the browser draft before navigation.');
assert.match(privacy, /not restored after seven days/i);
assert.match(privacy, /cleared the next time you open ARC after they expire/i);
assert.match(privacy, /cannot delete browser storage while the site is closed/i);
assert.match(retentionControl, /never restored after 7 days/i);
assert.match(retentionControl, /cannot delete local browser storage\s+while the site is closed/i);

for (const untrustedHiddenName of ['submission_timestamp', 'submission_id', 'lead_route', 'lead_route_status', 'lead_route_verification', 'checkout_consent_required', 'terms_version', 'terms_accepted_at']) {
  assert.doesNotMatch(home, new RegExp(`name="${untrustedHiddenName}"`));
}
assert.match(home, /This does not authorize a charge\./);
assert.match(home, /adult purchaser must accept the then-current purchase terms and checkout total again at checkout/i);
assert.match(terms, /does not authorize a charge/i);
assert.match(terms, /affirmatively accept the then-current purchase terms again at checkout/i);
assert.match(terms, /Version 2026-08-12/);
assert.match(terms, /bearer credential/i);
assert.match(terms, /creator application can retain a limited ability to push deploys/i);
assert.match(terms, /will not deploy afterward without new written authorization/i);
assert.match(terms, /production bundle for deployment to a fresh client-created project/i);
assert.match(terms, /later revision receives a new version identifier/i);
assert.match(privacy, /Handoff records:/);
assert.match(privacy, /does not intentionally place names, email addresses, form answers, or other customer details inside claim credentials/i);
assert.match(privacy, /Treat a Netlify claim invitation like a password/i);
assert.match(privacy, /pause the handoff/i);
assert.match(scope, /verification of the claimed destination account and exact final deploy/i);
assert.match(scope, /limited deploy access to the claimed project/i);
assert.match(scope, /production bundle for deployment to a fresh client-created project/i);
assert.match(refunds, /Sending a claim invitation by itself is not an ownership handoff/i);
assert.match(refunds, /successful Netlify claim and exact final deploy/i);
assert.doesNotMatch(`${terms}\n${scope}`, /technical revocation|immutable (?:copy|terms)|automatically (?:delete|expire)/i);

assert.match(home, /const analyticsEndpoint='\/api\/analytics\/event'/);
assert.match(home, /credentials:'omit',keepalive:true/);
assert.match(home, /sessionStorage\.setItem\(pendingAnalyticsKey/);
assert.match(home, /if\(analyticsBuildEnabled\)[\s\S]*?sessionStorage\.setItem\(analyticsSessionKey/,
  'Analytics browser identity may only be created in an analytics-enabled build.');
assert.match(home, /sessionStorage\.removeItem\(analyticsSessionKey\);sessionStorage\.removeItem\(pendingAnalyticsKey\)/,
  'An analytics-disabled build must clear stale analytics browser state.');
assert.match(thankYou, /sessionStorage\.removeItem\(pendingKey\);sessionStorage\.removeItem\(sessionKey\)/,
  'The analytics-disabled thank-you page must clear stale analytics browser state.');
assert.doesNotMatch(home, /name="analytics_session_id"/);
assert.match(home, /event:'arc_preview_request',event_id:randomId\(\)/);
assert.doesNotMatch(home, /track\('arc_preview_request'/);
assert.match(home, /showStep\(0,false,false\)/);
assert.match(home, /event:'arc_preview_request'/);
assert.match(thankYou, /fetch\('\/api\/analytics\/event'/);
assert.match(thankYou, /if\(response\.ok\)sessionStorage\.removeItem\(pendingKey\)/);
assert.match(privacy, /Netlify Function and Blobs store/i);
assert.match(privacy, /does not store names, business names, emails, phone numbers, addresses, form answers, IP addresses, user agents, referrers, or UTM values/i);
assert.match(privacy, /retention target for first-party analytics events is 90 days/i);
assert.match(privacy, /deletion control is currently disabled pending operator approval/i);

assert.match(home, /<b>3–4 minutes<\/b>/);
assert.match(home, /Pay the \$5,000 service subtotal plus applicable sales tax only when you approve it/i);
assert.match(home, /service subtotal is \$5,000 USD/i);
assert.match(home, /Applicable sales tax is calculated from the purchaser’s destination address/i);
assert.match(home, /subtotal, tax, and final total must be shown before payment/i);
assert.match(home, /\.form-section\{[^}]*scroll-margin-top:90px/);
assert.match(home, /\.form-card\{[^}]*scroll-margin-top:104px/);
assert.match(home, /id="stepCount">1 \/ 3</);
assert.match(home, /aria-valuemax="4"/);
assert.equal((home.match(/class="form-step(?: active)?"/g) || []).length, 4, 'Expected three intake steps plus review.');
assert.match(home, /Add audience or offer details/);
assert.match(home, /Confirm contact form and website structure/);
assert.match(home, /Add brand direction or proof/);
assert.match(home, /Add assets or launch details/);
assert.doesNotMatch(home, /name="target_customer"[^>]*\brequired\b/);
assert.doesNotMatch(home, /name="why_choose_you"[^>]*\brequired\b/);
assert.match(home, /function openAncestorDetails\(element\)/);
assert.match(home, /\['http:','https:'\]\.includes\(new URL\(field\.value\)\.protocol\)/);
assert.match(home, /if\(field\.type==='url'\)field\.setCustomValidity\(''\)/);
assert.match(home, /if\(first\)\{openAncestorDetails\(first\);first\.scrollIntoView/);
assert.match(home, /function requiredGroupsComplete\(step,markErrors=true\)/);
assert.match(home, /requiredGroupContainers\(step\)/);
assert.match(home, /if\(!requiredGroupsComplete\(step\)\)ok=false/);
assert.match(home, /let missingGroup=!requiredGroupsComplete\(step,false\)/);
assert.match(home, /role="group" aria-labelledby="goalsLabel"/);
assert.match(home, /role="radiogroup" aria-labelledby="ctaLabel"/);
assert.match(home, /function markFieldError\(field\)/);
assert.match(home, /field\.setAttribute\('aria-invalid','true'\)/);
assert.match(home, /data-required-group="sections" id="structureDetails"/);
assert.match(home, /structureStatus\.textContent=show\?'Lead routing required':'Defaults selected'/);
assert.match(home, /if\(show\)structureDetails\.open=true/);
assert.match(home, /contactFormSection\.checked=show/,
  'The selected site sections must stay consistent with the verified lead-route choice.');
assert.match(home, /Confirm its routing email in the next step/);
assert.match(home, /const clickedCta=/);
assert.match(home, /track\('arc_cta_click',\{cta:clickedCta\}\)/);

assert.match(home, /Before production launch, ARC must send a real test submission to this address and the recipient must confirm receipt\./);

for (const document of [home, terms, refunds, scope]) assert.match(document, /\$5,000/);
for (const document of [home, terms, refunds, scope]) assert.match(document, /applicable sales tax/i);
assert.match(terms, /required tax registration and Stripe automatic-tax configuration are verified/i);
assert.match(scope, /required tax registration and automatic-tax configuration are verified/i);
assert.match(scope, /reusable design system, templates, components, and automation/i);
assert.match(terms, /not represented as an entirely from-scratch software build/i);
assert.match(home, /One premium single-page site\./);
assert.match(scope, /single-page marketing website/);
assert.match(home, /Two preview revision rounds\./);
assert.match(scope, /Two consolidated revision rounds before purchase/);
assert.match(scope, /Payment confirms approval of the then-current preview/);
assert.match(terms, /Completing payment confirms approval of the then-current preview/);
assert.match(home, /seven business days/i);
assert.match(scope, /within seven business days/i);
assert.match(home, /30 calendar days of launch-related bug support/i);
assert.match(scope, /30 calendar days of support/i);
assert.match(scope, /Ongoing maintenance/);
assert.doesNotMatch(home, /\$500\s*\/\s*(?:mo|month)|monthly maintenance/i);

assert.match(robots, /Disallow: \/thank-you\//);
assert.match(robots, /Disallow: \/payment-success\//);
assert.match(robots, /Sitemap: https:\/\/arcweb\.onl\/sitemap\.xml/);
for (const path of ['/', '/service-scope/', '/terms/', '/privacy/', '/refunds/']) {
  assert.match(sitemap, new RegExp(`<loc>https:\\/\\/arcweb\\.onl${path.replaceAll('/', '\\/')}<\\/loc>`));
}
assert.doesNotMatch(sitemap, /thank-you/);

assert.equal(readiness.schema, 'arc-operations-readiness-v1');
assert.equal(readiness.reviewed_at, '2026-08-25');
assert.deepEqual(readiness.deployment_observation, {
  observed_at: '2026-08-25',
  repository_ref: 'main',
  repository_commit_sha: '5c4b853133e526f7ccbbf7d4e44a006a172f1fd0',
  repository_tree_sha: '5e3e6dd5fa425ed6a9820c62873be43874fc65b0',
  quality_workflow_name: 'ARC site quality',
  quality_workflow_run_id: 32821861690,
  quality_workflow_conclusion: 'success',
  canonical_origin: 'https://arcweb.onl',
  legacy_alias_origin: 'https://arcsites.netlify.app',
  reviewed_build_index_sha256: '2811e658cd21ea93d025ee8c9802400a7f49b8835e9d2b81d574ce9a54b7d3ea',
  canonical_live_index_sha256: '2811e658cd21ea93d025ee8c9802400a7f49b8835e9d2b81d574ce9a54b7d3ea',
  legacy_alias_live_index_sha256: '2811e658cd21ea93d025ee8c9802400a7f49b8835e9d2b81d574ce9a54b7d3ea',
  reviewed_build_and_live_index_bytes_match: true,
  public_intake_readiness: {
    schema: 'arc-intake-readiness-v1',
    intake_enabled: false,
  },
  legacy_alias_redirect_status: 'deferred-pending-provider-url-inventory',
  production_activation_claim_allowed: false,
});
assert.deepEqual(readiness.offer, {
  currency: 'USD',
  subtotal_amount: 5000,
  tax: 'applicable-destination-based-sales-tax-added-at-checkout',
  billing: 'one-time',
  deliverable: 'one-premium-single-page-website',
});
assert.equal(readiness.checkout.status, 'blocked');
assert.equal(readiness.checkout.allowed_mode, 'test-only');
assert.ok(readiness.checkout.required_evidence.includes('adult-purchaser-affirmative-acceptance'));
assert.ok(readiness.checkout.required_evidence.includes('automatic-tax-complete'));
assert.equal(readiness.checkout.blockers.includes('arc-stripe-public-profile-is-stale'), false);
for (const blocker of [
  'stripe-test-or-sandbox-context-unavailable',
  'live-website-build-link-has-no-verified-success-handoff',
  'active-monthly-support-offer-conflicts-with-published-one-time-scope',
  'stale-live-100-dollar-price-and-unrefunded-payment-require-adult-review',
]) assert.ok(readiness.checkout.blockers.includes(blocker));
assert.deepEqual(readiness.checkout.provider_observation, {
  observed_at: '2026-08-25',
  account_name: 'ARC',
  connected_context_count: 1,
  connected_context_modes: ['live'],
  test_or_sandbox_context_available: false,
  charges_enabled: true,
  payouts_enabled: true,
  details_submitted: true,
  representative_record_present: true,
  representative_legal_age_verified: false,
  representative_contracting_authority_verified: false,
  public_profile_matches_arc: true,
  public_profile_url: 'https://arcweb.onl',
  support_contact_configured: true,
  tax_status: 'pending',
  head_office_configured: false,
  tax_registration_count: 0,
  automatic_tax_on_observed_live_links: false,
  webhook_endpoint_count: 0,
  live_website_build_payment_link: {
    active: true,
    currency: 'USD',
    amount_minor: 500000,
    automatic_tax_enabled: false,
    billing_address_collection: 'auto',
    phone_collection_enabled: true,
    tax_id_collection_enabled: false,
    invoice_creation_enabled: false,
    promotion_codes_enabled: false,
    terms_of_service_consent_required: false,
    success_behavior: 'stripe-hosted-confirmation-only',
    successful_payment_count: 0,
  },
  stale_legacy_100_dollar_price: {
    active: true,
    successful_live_payment_count: 1,
    unrefunded_live_payment_count: 1,
  },
  monthly_support_offer: {
    active: true,
    currency: 'USD',
    amount_minor: 50000,
    interval: 'month',
    successful_subscription_count: 0,
    conflicts_with_published_offer: true,
  },
  live_checkout_activation_allowed: false,
});
assert.equal(readiness.checkout.sandbox_evidence.length, 1);
assert.deepEqual(readiness.checkout.sandbox_evidence[0], {
  observed_at: '2026-08-13',
  environment: 'stripe-test-mode',
  payment_link_id: 'plink_1U3t07Gv1R7moOUqoaUjIIHI',
  payment_intent_id: 'pi_3U3t38Gv1R7moOUq1qCOkiyV',
  currency: 'USD',
  subtotal_amount_minor: 500000,
  tax_amount_minor: 0,
  total_amount_minor: 500000,
  payment_result: 'succeeded',
  stripe_tax: 'inactive',
  consent_ui_observed: 'custom-dropdown',
  redirect_path_observed: '/payment-success/',
  handoff_created: false,
  scope: 'sandbox-checkout-and-success-redirect-only',
});
assert.equal(readiness.manual_activation_gates.status, 'blocked');
assert.equal(readiness.manual_activation_gates.stripe_live_mode_default, false);
assert.deepEqual(readiness.manual_activation_gates.verified_attestations, []);
assert.ok(readiness.manual_activation_gates.required_exact_environment_attestations.includes('ARC_BUILD_INTAKE_ENABLED=true'));
assert.ok(readiness.manual_activation_gates.required_exact_environment_attestations.some((value) => value.startsWith('ARC_INTAKE_READINESS_ATTESTATION=')));
assert.equal(readiness.manual_activation_gates.required_exact_environment_attestations.includes('ARC_INTAKE_ENABLED=true'), false);
assert.equal(readiness.analytics.status, 'pending-live-verification');
assert.equal(readiness.analytics.receiver, 'Netlify Function /api/analytics/event');
assert.equal(readiness.analytics.dashboard, 'Basic-auth Netlify Function /internal/analytics');
assert.equal(readiness.analytics.storage, 'Netlify Blobs arc-analytics');
assert.equal(readiness.analytics.retention_days, 90);
assert.equal(readiness.analytics.automatic_retention_enforcement_active, false);
assert.ok(readiness.analytics.environment_requirements.includes('ARC_BUILD_ANALYTICS_ENABLED=true'));
assert.ok(readiness.analytics.environment_requirements.includes('ARC_ANALYTICS_COLLECTION_ENABLED=true'));
assert.deepEqual(readiness.analytics.verified_live_events, []);
assert.ok(readiness.analytics.environment_requirements.includes('ARC_ANALYTICS_DASHBOARD_PASSWORD'));
assert.ok(readiness.analytics.activation_requirements.includes('live-event-receipt-verified'));
assert.equal(readiness.intake_routing.status, 'unverified');
assert.equal(readiness.intake_routing.verified_recipient, null);
assert.deepEqual(readiness.intake_routing.runtime_attestation, {
  required_build_runtime_gate: 'ARC_BUILD_INTAKE_ENABLED=true',
  required_same_deploy_build_marker: 'arc-intake-build-marker-v1 intake_enabled=true',
  environment_variable: 'ARC_INTAKE_READINESS_ATTESTATION',
  schema: 'arc-intake-readiness-attestation-v1',
  version: 1,
  default_enabled: false,
  reject_unknown_or_partial_records: true,
  required_exact_boolean_fields: [
    'intake_enabled',
    'route_verified',
    'recipient_verified',
    'dedupe_verified',
    'failure_alert_verified',
    'transactional_sender_verified',
    'adult_operator_verified',
    'legal_readiness_verified',
    'tax_readiness_verified',
    'payment_readiness_verified',
    'arc1_consumer_adapter_verified',
    'native_netlify_forms_disabled_verified',
    'retention_verified',
    'asset_pipeline_verified',
  ],
});
assert.equal(readiness.customer_lead_routing.must_block_production_when_unverified, true);
assert.equal(readiness.intake_trust_boundary.status, 'pending-server-verification');
assert.equal(readiness.intake_trust_boundary.client_hidden_fields_are_authoritative, false);
assert.equal(readiness.intake_routing.native_netlify_form_registered, false);
assert.equal(readiness.intake_routing.submission_endpoint, 'Netlify Function /api/intake/submit');
assert.equal(readiness.intake_routing.stored_schema, 'arc-intake-function-submission-v1');
assert.equal(readiness.intake_routing.workflow_route, 'first-party-adapter-present-downstream-provider-proof-required');
assert.equal(readiness.intake_routing.arc1_consumer_compatible, false);
assert.deepEqual(readiness.intake_routing.arc1_adapter_observation, {
  observed_at: '2026-08-25',
  endpoint: '/internal/intake/arc1/adapter',
  deployment_state: 'present-in-observed-production-commit',
  activation_state: 'default-off',
  provider_invocation_verified: false,
  signed_ack_verified: false,
  consumer_completion_verified: false,
});
assert.ok(readiness.intake_routing.verification_requirements.includes('build-runtime-gate-blocks-before-body-parse-and-storage'));
assert.ok(readiness.intake_routing.verification_requirements.includes('same-deploy-immutable-build-marker-enabled'));
assert.ok(readiness.intake_routing.verification_requirements.includes('provider-form-detection-disabled-and-legacy-direct-post-rejected-after-deploy'));
assert.ok(readiness.intake_trust_boundary.required_pipeline_evidence.includes('server-issued-submission-id-used-for-preview-identity'));
assert.ok(readiness.asset_uploads.required_pipeline_evidence.includes('legacy-folder-link-field-rejected-until-private-provider-adapter-is-verified'));
assert.equal(readiness.asset_uploads.status, 'pending-server-verification');
assert.equal(readiness.asset_uploads.client_checks_are_security_boundary, false);
assert.deepEqual(readiness.asset_uploads.limits, {
  netlify_buffered_payload_bytes: 6000000,
  netlify_effective_binary_payload: 'approximately-4.5-MB',
  request_max_bytes: 4000000,
  request_base64_bytes_at_max: 5333336,
  platform_buffer_headroom_bytes: 666664,
  per_file_max_bytes: 1250000,
  total_file_max_bytes: 3000000,
  text_max_bytes: 262144,
  multipart_headroom_after_max_files_and_text_bytes: 737856,
});
assert.ok(readiness.asset_uploads.required_pipeline_evidence.includes('content-type-and-magic-byte-match'));
assert.equal(readiness.data_retention.status, 'pending-provider-enforcement');
assert.equal(readiness.data_retention.live_compliance_claim_allowed, false);
assert.ok(readiness.data_retention.unverified_stores.includes('netlify-blobs-intake-records-and-assets'));
assert.equal(readiness.data_retention.unverified_stores.includes('netlify-forms-and-uploads'), false);
assert.match(retentionControl, /first-party Netlify Function\/Blobs intake records and uploads, Zapier Tables, Gmail, GitHub, Stripe, and backup locations/);
assert.match(retentionControl, /Apollo must remain off and live checkout must remain blocked/);
assert.match(customerEmailContract, /checkout verification in progress/i);
assert.match(customerEmailContract, /not confirmation that payment succeeded/i);
assert.match(customerEmailContract, /time-limited claim invitation/i);
assert.match(customerEmailContract, /may be\s+retried until that window closes/i);
assert.match(customerEmailContract, /exact synthetic\s+submission through its rendered Netlify form/i);
assert.match(customerEmailContract, /verified receipt in the\s+authoritative lead inbox/i);
assert.match(customerEmailContract, /Form and hook configuration alone never authorizes this email/i);
assert.match(customerEmailContract, /Sending this\s+invitation does not prove ownership handoff/i);
assert.match(customerEmailContract, /final email must not include a claim URL/i);
assert.match(customerEmailContract, /or other bearer secret/i);
assert.match(customerEmailContract, /destination-account control, the exact final deploy, and the durable\s+delivery outbox/i);
assert.match(customerEmailContract, /not a claim that the\s+site is fully launch-ready/i);
assert.match(customerEmailContract, /durable\s+`READY` invitation outbox and bearer/i);
assert.match(customerEmailContract, /must never be represented as sent/i);
assert.match(customerEmailContract, /separate provider receipt is\s+required before any workflow records email delivery/i);
assert.match(customerEmailContract, /https:\/\/arcweb\.onl\/claim\/#arc2\./i);
assert.match(customerEmailContract, /never appear in a URL\s+path, query, server log, browser storage, DOM text, or analytics event/i);
assert.equal(readiness.legal_and_outreach_compliance.status, 'blocked');
assert.equal(readiness.legal_and_outreach_compliance.adult_contracting_representative, null);
assert.equal(readiness.legal_and_outreach_compliance.legal_operator, null);
assert.equal(readiness.legal_and_outreach_compliance.mailing_address, null);
assert.equal(readiness.legal_and_outreach_compliance.apollo_must_remain_off, true);
assert.match(manualActivation, /only connected context observed during the August 25, 2026 audit was the ARC\s+live Stripe account/i);
assert.match(manualActivation, /representative\s+record present; the accessible fields did not verify legal age or contracting\s+authority/i);
assert.match(manualActivation, /public profile now identifies ARC, links\s+`https:\/\/arcweb\.onl`, and has support contact details configured/i);
assert.match(manualActivation, /stale active \$100 Price has one successful live payment that\s+remains unrefunded/i);
assert.match(manualActivation, /active \$500 monthly support offer has no subscriptions but\s+contradicts the published one-time, no-renewal scope/i);
assert.doesNotMatch(manualActivation, /unrelated sunglasses business|default-OFF, not-yet-deployed/i);
assert.match(manualActivation, /observed production commit now contain the \*\*default-OFF\*\*[\s\S]*?no provider invocation or exact\s+signed ACK has been verified/i);
assert.match(manualActivation, /Do not add a catch-all redirect from `arcsites\.netlify\.app` to `arcweb\.onl` until\s+every provider callback, webhook, API, claim, and stored workflow URL/i);
assert.doesNotMatch(netlifyConfig, /from = "https:\/\/arcsites\.netlify\.app\/\*"/,
  'The legacy alias redirect must remain deferred until provider URLs are inventoried.');
assert.match(netlifyConfig, /from = "\/operations\/\*"[\s\S]*?status = 404[\s\S]*?force = true/);
assert.match(netlifyConfig, /from = "\/tests\/\*"[\s\S]*?status = 404[\s\S]*?force = true/);
assert.match(netlifyConfig, /\[functions\][\s\S]*?directory = "netlify\/functions"/);
assert.match(netlifyConfig, /\[build\][\s\S]*?command = "npm run build"[\s\S]*?publish = "dist"/);
assert.match(netlifyConfig, /Content-Security-Policy = "[^"]*default-src 'self'[^"]*form-action 'self'[^"]*frame-ancestors 'none'/);
assert.match(netlifyConfig, /Strict-Transport-Security = "max-age=31536000"/);
assert.match(netlifyConfig, /for = "\/thank-you\/\*"[\s\S]*?X-Robots-Tag = "noindex, nofollow, noarchive"/);
assert.match(netlifyConfig, /for = "\/payment-success\/\*"[\s\S]*?Cache-Control = "no-store"[\s\S]*?Referrer-Policy = "no-referrer"[\s\S]*?X-Robots-Tag = "noindex, nofollow, noarchive"/);
for (const blockedPath of ['netlify', 'node_modules']) {
  assert.match(netlifyConfig, new RegExp(`from = "\\/${blockedPath}\\/\\*"[\\s\\S]*?status = 404[\\s\\S]*?force = true`));
}
for (const blockedFile of ['package.json', 'package-lock.json']) {
  assert.match(netlifyConfig, new RegExp(`from = "\\/${blockedFile.replace('.', '\\.')}"[\\s\\S]*?status = 404[\\s\\S]*?force = true`));
}

assert.equal(packageJson.dependencies['@netlify/blobs'], '10.7.12');
assert.equal(packageJson.overrides['image-size'], 'file:vendor/image-size-disabled');
assert.equal(imageSizePackage.name, 'image-size');
assert.equal(imageSizePackage.version, '3.0.0-arc-disabled.0');
assert.match(imageSizeDisabled, /throw new Error\('Image parsing is intentionally disabled/);
assert.equal(packageJson.devDependencies['@sparticuz/chromium'], '149.0.0');
assert.equal(packageJson.devDependencies.playwright, '1.62.0');
assert.equal(packageJson.scripts.build, 'node scripts/build-site.mjs');
assert.equal(packageJson.scripts.preflight, 'node scripts/launch-preflight.mjs --mode=safety');
assert.equal(packageJson.scripts['preflight:sandbox'], 'node scripts/launch-preflight.mjs --mode=sandbox');
assert.equal(packageJson.scripts['preflight:live'], 'node scripts/launch-preflight.mjs --mode=live');
assert.deepEqual(packageJson.scripts.test.split(' && '), [
  'npm run preflight',
  'node tests/launch-preflight-contract.mjs',
  'node tests/source-contract.mjs',
  'node tests/analytics-contract.mjs',
  'node tests/intake-readiness-contract.mjs',
  'node tests/intake-private-asset-contract.mjs',
  'node tests/intake-arc1-bridge-contract.mjs',
  'node tests/intake-arc1-adapter-contract.mjs',
  'node tests/intake-arc1-dispatch-contract.mjs',
  'node tests/stripe-checkout-contract.mjs',
  'node tests/stripe-reversal-contract.mjs',
  'node tests/retention-control-contract.mjs',
  'node tests/operations-audit-contract.mjs',
  'node tests/arc2-handoff-contract.mjs',
  'node tests/arc2-resumable-service.mjs',
  'node tests/arc2-final-delivery-ack.mjs',
  'node tests/arc2-producer-compatibility.mjs',
  'node tests/showcase-contract.mjs',
  'npm run build',
  'node tests/build-contract.mjs',
  'node tests/browser-contract.mjs',
]);
assert.match(analyticsCore, /const ALLOWED_KEYS = new Set\(\['event', 'event_id', 'session_id', 'path', 'cta', 'step', 'step_name'\]\)/);
assert.match(analyticsCore, /STEP_LABELS = Object\.freeze\(\{ 1: 'Business', 2: 'Offer', 3: 'Details & consent', 4: 'Review' \}\)/);
assert.match(analyticsCore, /Unexpected analytics field/);
assert.match(analyticsEvent, /new Set\(\['arcweb\.onl', 'arcsites\.netlify\.app'\]\)/);
assert.match(analyticsEvent, /onlyIfNew: true/);
assert.match(analyticsEvent, /ARC_ANALYTICS_COLLECTION_ENABLED !== 'true'/,
  'The analytics receiver must remain exact default-off while automation is disabled.');
assert.match(analyticsEvent, /windowLimit: 60/);
assert.doesNotMatch(analyticsEvent, /user-agent|x-forwarded|client-ip/i);
assert.match(analyticsDashboard, /ARC_ANALYTICS_DASHBOARD_USER/);
assert.match(analyticsDashboard, /ARC_ANALYTICS_DASHBOARD_PASSWORD/);
assert.match(analyticsDashboard, /timingSafeEqual/);
assert.match(analyticsDashboard, /X-Robots-Tag.*noindex/si);
assert.match(analyticsDashboard, /retention target is \$\{RETENTION_DAYS\} days; deletion is manual until the separately approved pruning control is enabled and verified/i);
assert.doesNotMatch(analyticsDashboard, /events expire after/i,
  'The dashboard must not claim automatic expiry while analytics pruning is disabled.');
assert.doesNotMatch(analyticsPrune, /\bschedule\s*:/,
  'No analytics scheduled invocation may be registered while all automation is off.');
assert.match(analyticsPrune, /ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED !== 'true'/,
  'The analytics prune handler must remain an exact default-off no-op even if invoked manually.');
assert.match(analyticsPrune, /isExpiredMetadata/);
assert.match(arc2Core, /PAYMENT_FIELDS = Object\.freeze\(\[/);
assert.match(arc2Core, /terms_of_service_consent/);
assert.doesNotMatch(arc2Core, /ARC_EXPECTED_(?:PAYMENT_LINK_ID|PRICE_ID|PRODUCT_TAX_CODE)/,
  'V3 fulfillment must use the immutable private policy instead of mutable checkout singletons.');
assert.match(arc2Core, /arc-private-checkout-policy-v1/);
assert.match(arc2Core, /ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256/);
assert.match(arc2Core, /ARC_EXPECTED_NETLIFY_SITE_ID/);
assert.match(arc2Core, /ARC_PRODUCTION_SITE_BINDING/);
assert.match(arc2Core, /ARC_PRODUCTION_ORIGIN_BINDING/);
assert.match(arc2Core, /ARC_HANDOFF_ENABLED/);
assert.match(arc2Core, /ARC_STRIPE_REVERSAL_CONTROL_REQUIRED/,
  'Handoff readiness must require the reversal control instead of allowing an optional bypass.');
assert.match(arc2Core, /ARC_STRIPE_CHECKOUT_LEDGER_REQUIRED/,
  'Live handoff readiness must require an independently authenticated Checkout event ledger.');
assert.match(stripeCheckoutCore, /checkout\.session\.completed/);
assert.match(stripeCheckoutCore, /checkout\.session\.async_payment_succeeded/);
assert.match(stripeCheckoutCore, /checkout\.session\.async_payment_failed/);
assert.match(stripeCheckoutCore, /checkout\.session\.expired/);
assert.match(stripeCheckoutCore, /ARC_STRIPE_CHECKOUT_EVENT_CONFLICT/);
assert.match(stripeCheckoutCore, /ARC_STRIPE_CHECKOUT_RECEIPT_CONFLICT/);
assert.match(stripeCheckoutCore, /REVIEW_REQUIRED/);
assert.match(stripeCheckoutCore, /assertStripeCheckoutPaid/);
assert.match(stripeCheckoutCore, /bindStripeCheckoutToHandoff/);
assert.match(stripeCheckoutCore, /assertHandoffStripeCheckoutPaid/);
assert.match(stripeCheckoutCore, /processed_event_hmacs_sha256/,
  'Checkout retries must retain an applied-event marker across ambiguous CAS results.');
assert.match(stripeAccountVerification, /stripeGetJson\('\/v1\/account'/);
assert.match(stripeAccountVerification, /stripeGetJson\(`\/v1\/events\/\$\{encodeURIComponent\(event\.eventId\)\}`/);
assert.match(stripeAccountVerification, /\^rk_\(test\|live\)_/,
  'Account verification must reject unrestricted or mode-mismatched Stripe keys.');
assert.match(stripeWebhook, /processStripeCheckoutEvent/,
  'The authenticated Stripe destination must dispatch allowlisted Checkout events into the durable ledger.');
assert.match(arc2Service, /const key = handoffKey[\s\S]*?bindStripeCheckoutToHandoff[\s\S]*?let entry = await readEntry/,
  'Checkout ledger binding must precede the first handoff reservation.');
assert.equal((arc2Service.match(/await assertHandoffFulfillmentAllowed/g) || []).length, 1,
  'Every reversal gate must be encapsulated by the combined Checkout-and-reversal guard.');
assert.ok((arc2Service.match(/await assertCheckoutAndReversalAllowed/g) || []).length >= 15,
  'Claim, deploy, invitation, webhook, and private send-authority stages must all recheck Checkout state.');
assert.match(arc2Service, /assertProviderMutationAllowed/);
assert.match(intakeSubmissionCore, /ARC_INTAKE_IDEMPOTENCY_SECRET/);
assert.match(intakeSubmissionCore, /arc-intake-request-id-v1\\n/);
assert.match(intakeSubmit, /getWithMetadata\(normalized\.key, \{ type: 'json', consistency: 'strong' \}\)/,
  'An ambiguous intake create must use strong readback before deciding whether the request failed.');
assert.match(intakeSubmit, /created \? 201 : 200/,
  'An exact lost-response retry must recover with HTTP 200 instead of creating another lead.');
assert.match(arc2Service, /create-site/);
assert.match(arc2Service, /create-\$\{phase\}-deploy/);
assert.match(arc2Service, /restore-deploy/);
assert.match(arc2Service, /create-email-hook/);
assert.match(arc2Core, /ARC_STRIPE_LIVE_MODE_ENABLED/);
assert.match(arc2Core, /ARC_RUNTIME_ENVIRONMENT/,
  'Function runtime identity must use an explicit deployment attestation instead of build-only Netlify CONTEXT.');
assert.doesNotMatch(arc2Core, /env\.CONTEXT/,
  'Build-only Netlify CONTEXT must not authorize Function runtime mutations.');
assert.match(arc2Core, /subtotal_amount_minor_units/);
assert.match(arc2Core, /tax_amount_minor_units/);
assert.match(arc2Core, /automatic_tax_enabled/);
assert.match(arc2Core, /tax_registration_status/);
assert.match(arc2Core, /stripe_account_id_sha256/);
assert.doesNotMatch(arc2Core, /payment_method_types|payment_methods/,
  'Checkout policy must omit manual payment-method lists so Stripe can select eligible methods dynamically.');
assert.match(arc2Core, /ARC_SECRETS_MUST_BE_DISTINCT/);
assert.match(arc2Core, /arc2-claim-state-evidence-signature-v3\\n/);
assert.doesNotMatch(arc2Core, /arc_callback|ARC_CLAIM_WEBHOOK_SECRET/);
assert.doesNotMatch(arc2Core, /arc_callback|ARC_CLAIM_WEBHOOK_SECRET/);
assert.match(arc2Service, /filter: 'owner'/);
assert.match(arc2Service, /deploys\?per_page=100/);
assert.match(arc2Service, /restore/);
assert.match(arc2Service, /claim_token_consumed_hmac_sha256/);
assert.match(arc2Service, /lead-route-inbox-receipt/);
assert.doesNotMatch(arc2Service, /destination_account_id_hint_sha256/);
assert.doesNotMatch(arc2Service, /console\.(?:log|error|warn)/);
assert.match(arc2Store, /onlyIfNew: true/);
assert.match(arc2Store, /onlyIfMatch: entry\.etag/);
assert.match(arc2Store, /if \(!result\?\.modified/);
for (const source of [arc2Start, arc2Claim, arc2Webhook, arc2Invitation, arc2Status]) {
  assert.match(source, /configuredEnvironment\(process\.env\)\.enabled/);
  assert.match(source, /getStore\(\{ name: HANDOFF_STORE, consistency: 'strong' \}\)/);
  assert.doesNotMatch(source, /Access-Control-Allow-Origin|console\.(?:log|error|warn)/i);
}
assert.match(netlifyConfig, /for = "\/claim\/\*"[\s\S]*?Cache-Control = "no-store"[\s\S]*?Referrer-Policy = "no-referrer"[\s\S]*?X-Robots-Tag = "noindex, nofollow, noarchive"/);
assert.match(arc2Start, /authenticateBearer\(request, process\.env\.ARC_HANDOFF_TRIGGER_SECRET\)/);
assert.match(arc2Invitation, /authenticateBearer\(request, process\.env\.ARC_HANDOFF_TRIGGER_SECRET\)/);
assert.match(arc2Invitation, /invitation_status: 'READY'/);
assert.doesNotMatch(arc2Invitation, /invitation[_ -]sent/i);
assert.match(arc2Claim, /exchangeClaimBearer/);
assert.match(arc2Webhook, /processClaimWebhook/);
assert.match(arc2Status, /authenticateBearer\(request, process\.env\.ARC_HANDOFF_TRIGGER_SECRET\)/);
assert.match(intakeSubmissionCore, /arc-intake-function-submission-v1/);
assert.match(intakeSubmissionCore, /arc1_consumer_compatible: false/);
assert.match(intakeSubmissionCore, /INTAKE_MAX_REQUEST_BYTES = 4_000_000/);
assert.match(intakeSubmissionCore, /INTAKE_MAX_FILE_BYTES = 1_250_000/);
assert.match(intakeSubmissionCore, /INTAKE_MAX_TOTAL_FILE_BYTES = 3_000_000/);
assert.match(intakeSubmissionCore, /'primary_style'/);
assert.match(intakeSubmissionCore, /values\.get\('asset_permission'\) !== 'Confirmed'/);
assert.match(intakeBuildMarker, /schema: 'arc-intake-build-marker-v1'/);
assert.match(intakeBuildMarker, /intake_enabled: false/);
assert.match(buildScript, /intakeBuildMarkerPath/);
assert.match(buildScript, /intake_enabled: \$\{intakeBuildEnabled\}/);
assert.match(intakeSubmit, /process\.env\.ARC_BUILD_INTAKE_ENABLED !== 'true'/);
assert.match(intakeSubmit, /intakeEnabledFromBuildMarker\(buildMarker\)/);
assert.match(intakeSubmit, /intakeEnabledFromAttestation\(process\.env\[INTAKE_READINESS_ENV\]\)/);
assert.match(intakeSubmit, /Number\(contentLength\) > INTAKE_MAX_REQUEST_BYTES/);
assert.match(intakeSubmit, /total > INTAKE_MAX_REQUEST_BYTES/);
assert.match(intakeSubmit, /request\.body\?\.getReader/);
assert.match(intakeSubmit, /getStore\(\{ name: INTAKE_STORE, consistency: 'strong' \}\)/);
assert.match(intakeSubmit, /onlyIfNew: true/);
assert.doesNotMatch(intakeSubmit, /fetch\(|Access-Control-Allow-Origin|console\.(?:log|error|warn)/i);

for (const script of [...home.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]) {
  Function(script[1]);
}
for (const script of [...thankYou.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]) {
  Function(script[1]);
}

console.log('ARC source contract passed.');
