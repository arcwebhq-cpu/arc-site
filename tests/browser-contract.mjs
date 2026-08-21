import assert from 'node:assert/strict';
import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

// tar-fs attempts chown when tests run as root in some CI/container filesystems.
if (process.getuid?.() === 0) process.getuid = () => 1000;
const { default: serverlessChromium } = await import('@sparticuz/chromium');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../dist');
const contentTypes = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
};

function safePublicFile(urlPath) {
  let relative = decodeURIComponent(urlPath.split('?')[0]).replace(/^\/+/, '');
  if (!relative || relative.endsWith('/')) relative += 'index.html';
  const absolute = path.resolve(root, relative);
  return absolute.startsWith(`${root}${path.sep}`) ? absolute : null;
}

const claimRequests = [];
const server = http.createServer(async (request, response) => {
  if (request.method === 'GET' && request.url?.split('?')[0] === '/api/intake/readiness') {
    response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(JSON.stringify({ schema: 'arc-intake-readiness-v1', intake_enabled: true }));
    return;
  }
  if (request.method === 'POST' && request.url?.split('?')[0] === '/api/analytics/event') {
    response.writeHead(202, { 'cache-control': 'no-store' }).end();
    return;
  }
  if (request.method === 'POST' && request.url?.split('?')[0] === '/api/arc2/claim') {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    claimRequests.push({ method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks).toString('utf8') });
    await new Promise((resolve) => setTimeout(resolve, 150));
    response.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
      .end(JSON.stringify({ claim_url: 'https://app.netlify.com/claim#header.payload.signature' }));
    return;
  }
  try {
    const file = safePublicFile(request.url || '/');
    if (!file || !(await stat(file)).isFile()) throw new Error('Not found');
    response.writeHead(200, { 'content-type': contentTypes[path.extname(file)] || 'application/octet-stream' });
    if (file === path.join(root, 'index.html')) {
      // Build-contract proves the deploy is compiled closed. The browser harness
      // opts into the separately gated activation variant to exercise the full UI.
      response.end((await readFile(file, 'utf8')).replace('data-intake-build-enabled="false"', 'data-intake-build-enabled="true"'));
      return;
    }
    createReadStream(file).pipe(response);
  } catch {
    response.writeHead(404).end('Not found');
  }
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({
  args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  executablePath: await serverlessChromium.executablePath(),
  headless: true,
});

const requestedViewport = process.env.ARC_SITE_QA_VIEWPORT;
const viewports = [
  { name: 'desktop', width: 1440, height: 900, isMobile: false },
  { name: 'tablet', width: 768, height: 1024, isMobile: true },
  { name: 'iphone', width: 390, height: 844, isMobile: true },
  { name: 'small-mobile', width: 320, height: 568, isMobile: true },
].filter((viewport) => !requestedViewport || viewport.name === requestedViewport);
assert.ok(viewports.length, `Unknown ARC_SITE_QA_VIEWPORT: ${requestedViewport}`);

try {
  for (const viewport of viewports) {
    const page = await browser.newPage({
      viewport: { width: viewport.width, height: viewport.height },
      isMobile: viewport.isMobile,
      hasTouch: viewport.isMobile,
    });
    const errors = [];
    const analyticsRequests = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => {
      if (message.type() === 'error') errors.push(message.text());
    });
    page.on('request', (request) => {
      if (new URL(request.url()).pathname === '/api/analytics/event') analyticsRequests.push(request.url());
    });
    await page.addInitScript(() => {
      sessionStorage.setItem('arc-analytics-session', 'stale-session');
      sessionStorage.setItem('arc-pending-preview-analytics', 'stale-pending-event');
    });

    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    await page.waitForTimeout(1150);
    const analyticsOffState = await page.evaluate(() => ({
      session: sessionStorage.getItem('arc-analytics-session'),
      pending: sessionStorage.getItem('arc-pending-preview-analytics'),
      dataLayerCreated: Object.prototype.hasOwnProperty.call(window, 'dataLayer'),
    }));
    assert.deepEqual(analyticsOffState, { session: null, pending: null, dataLayerCreated: false },
      `${viewport.name}: compiled analytics-off state created or retained browser tracking state`);
    assert.deepEqual(analyticsRequests, [], `${viewport.name}: compiled analytics-off state sent an analytics request`);
    assert.equal(await page.locator('h1').count(), 1, `${viewport.name}: expected one h1`);
    assert.equal(await page.locator('.hero-copy-block').evaluate((element) => getComputedStyle(element).opacity), '1', `${viewport.name}: hero copy is hidden`);
    const heroLayout = await page.evaluate(() => {
      const block = document.querySelector('.hero-copy-block').getBoundingClientRect();
      const actions = document.querySelector('.actions').getBoundingClientRect();
      return { blockRight: block.right, actionsBottom: actions.bottom, viewportWidth: innerWidth, viewportHeight: innerHeight };
    });
    assert.ok(heroLayout.blockRight <= heroLayout.viewportWidth + 1, `${viewport.name}: hero copy overflows horizontally`);
    assert.ok(viewport.name !== 'desktop' || heroLayout.actionsBottom <= heroLayout.viewportHeight, `${viewport.name}: exact offer is pushed below the opening viewport`);

    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => document.activeElement?.classList.contains('skip-link')), true, `${viewport.name}: skip link is not first in keyboard order`);
    await page.keyboard.press('Enter');
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'top', `${viewport.name}: skip link did not focus main content`);

    const revealCount = await page.locator('.reveal').count();
    for (let index = 0; index < revealCount; index += 1) {
      await page.locator('.reveal').nth(index).scrollIntoViewIfNeeded();
      await page.waitForTimeout(50);
    }
    await page.waitForTimeout(1100);
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(100);
    const hiddenReveals = await page.locator('.reveal').evaluateAll((elements) => elements
      .filter((element) => getComputedStyle(element).opacity !== '1')
      .map((element) => element.className));
    assert.deepEqual(hiddenReveals, [], `${viewport.name}: revealed content became hidden again`);
    const hiddenRevealChildren = await page.locator('.work-copy,.work-item .mockup-big,.offer-row h3,.process-line .step,.form-card').evaluateAll((elements) => elements
      .filter((element) => {
        const style = getComputedStyle(element);
        return style.opacity !== '1' || style.visibility === 'hidden' || style.display === 'none';
      })
      .map((element) => element.className));
    assert.deepEqual(hiddenRevealChildren, [], `${viewport.name}: content inside a revealed section remains hidden`);

    const layout = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    assert.ok(layout.scrollWidth <= layout.clientWidth + 1, `${viewport.name}: horizontal page overflow (${layout.scrollWidth}px > ${layout.clientWidth}px)`);

    await page.locator('a[href="#start"]').first().click();
    await page.waitForTimeout(550);
    const overlap = await page.evaluate(() => {
      const nav = document.querySelector('.nav').getBoundingClientRect();
      const card = document.getElementById('formCard').getBoundingClientRect();
      return { navBottom: nav.bottom, cardTop: card.top };
    });
    assert.ok(overlap.cardTop >= overlap.navBottom - 1, `${viewport.name}: sticky navigation overlaps the form card`);

    await page.locator('#next').click({ position: { x: 20, y: 20 } });
    assert.equal(await page.locator('#name').getAttribute('aria-invalid'), 'true', `${viewport.name}: invalid required field lacks aria-invalid`);
    assert.equal(await page.locator('#name').getAttribute('aria-describedby'), 'error', `${viewport.name}: invalid field is not associated with the error alert`);

    await page.locator('#name').fill('Jordan Lee');
    await page.locator('#email').fill('jordan@example.com');
    await page.locator('#business').fill('Evergreen Home Services');
    await page.locator('#industry').fill('Home services');
    await page.locator('#city').fill('Everett, WA');
    await page.locator('#next').click({ position: { x: 20, y: 20 } });
    assert.equal(await page.locator('#stepCount').textContent(), '2 / 3', `${viewport.name}: could not advance to offer step`);

    await page.locator('#services').fill('Roof repair and replacement');
    await page.locator('input[name="goals"]').first().check();
    await page.locator('input[name="main_call_to_action"][value="Contact"]').check();
    await page.locator('#next').click({ position: { x: 20, y: 20 } });
    assert.equal(await page.locator('#stepCount').textContent(), '3 / 3', `${viewport.name}: could not advance to details step`);
    assert.equal(await page.locator('#structureDetails').getAttribute('open'), '', `${viewport.name}: required lead routing details are still collapsed`);
    await page.waitForTimeout(400);

    await page.locator('#budget').check();
    await page.locator('#termsAccepted').check();
    await page.waitForTimeout(500);
    const savedDraft = JSON.parse(await page.evaluate(() => localStorage.getItem('arc-preview-draft-v7')));
    assert.equal('asset_permission' in savedDraft.data, false, `${viewport.name}: asset permission was persisted`);
    assert.equal('budget_confirmed' in savedDraft.data, false, `${viewport.name}: budget confirmation was persisted`);
    assert.equal('terms_accepted' in savedDraft.data, false, `${viewport.name}: legal consent was persisted`);

    await page.evaluate(() => document.getElementById('next').click());
    const finalStep = await page.locator('#stepCount').textContent();
    const finalDiagnostics = await page.evaluate(() => ({
      error: document.getElementById('error').textContent,
      invalid: [...document.querySelectorAll('.form-step.active :invalid')].map((field) => field.name),
      groupErrors: [...document.querySelectorAll('.form-step.active .group-error')].map((group) => group.id || group.dataset.group || group.className),
    }));
    assert.equal(finalStep, 'Review', `${viewport.name}: complete request did not reach review (${JSON.stringify(finalDiagnostics)})`);
    assert.equal(await page.locator('#submit').isVisible(), true, `${viewport.name}: submit action is not visible on review`);

    const shortTargets = await page.locator('.form-nav button:visible').evaluateAll((elements) => elements
      .map((element) => ({ text: element.textContent.trim(), ...element.getBoundingClientRect().toJSON() }))
      .filter((rect) => rect.width < 48 || rect.height < 48));
    assert.deepEqual(shortTargets, [], `${viewport.name}: ARC form action is smaller than the 48px design target`);
    assert.deepEqual(errors, [], `${viewport.name}: browser errors: ${errors.join('; ')}`);
    await page.close();
  }

  if (!requestedViewport || requestedViewport === 'desktop') {
    const noScriptPage = await browser.newPage({
      viewport: { width: 1440, height: 900 },
      javaScriptEnabled: false,
    });
    await noScriptPage.goto(baseUrl, { waitUntil: 'networkidle' });
    const hiddenWithoutScript = await noScriptPage.locator('.work-copy,.mockup-big,.offer-row h3,.process-line .step,.form-card').evaluateAll((elements) => elements
      .filter((element) => {
        const style = getComputedStyle(element);
        return style.opacity === '0' || style.visibility === 'hidden' || style.display === 'none';
      })
      .map((element) => element.className));
    assert.deepEqual(hiddenWithoutScript, [], 'Core content must remain visible if JavaScript fails or is unavailable.');
    assert.equal(await noScriptPage.locator('[data-intake-cta][href^="mailto:arcwebhq@gmail.com"]').count(), 2,
      'The no-script compiled-closed page must retain its manual email fallbacks.');
    await noScriptPage.close();

    const disabledThankYouPage = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await disabledThankYouPage.addInitScript(() => {
      sessionStorage.setItem('arc-analytics-session', 'stale-session');
      sessionStorage.setItem('arc-pending-preview-analytics', 'stale-pending-event');
      localStorage.setItem('arc-preview-draft-v7', 'stale-draft');
    });
    await disabledThankYouPage.goto(`${baseUrl}/thank-you/`, { waitUntil: 'networkidle' });
    assert.deepEqual(await disabledThankYouPage.evaluate(() => ({
      session: sessionStorage.getItem('arc-analytics-session'),
      pending: sessionStorage.getItem('arc-pending-preview-analytics'),
      draft: localStorage.getItem('arc-preview-draft-v7'),
    })), { session: null, pending: null, draft: null },
    'The analytics-disabled thank-you page must clear stale analytics state and the accepted draft.');
    await disabledThankYouPage.close();

    const paymentPage = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const paymentRequests = [];
    paymentPage.on('request', (request) => paymentRequests.push({ url: request.url(), headers: request.headers() }));
    await paymentPage.goto(`${baseUrl}/payment-success/?session_id=cs_test_sensitive_return_value`, { waitUntil: 'networkidle' });
    const scrubbedPaymentUrl = new URL(paymentPage.url());
    assert.equal(scrubbedPaymentUrl.pathname, '/payment-success/', 'Payment return path changed while scrubbing the Stripe session id.');
    assert.equal(scrubbedPaymentUrl.search, '', 'Stripe session id remained in the browser URL.');
    await Promise.all([
      paymentPage.waitForURL('**/service-scope/'),
      paymentPage.locator('a.secondary').click(),
    ]);
    const scopeNavigation = paymentRequests.find((request) => new URL(request.url).pathname === '/service-scope/');
    assert.ok(scopeNavigation, 'Payment-success scope navigation was not observed.');
    assert.ok(!scopeNavigation.headers.referer, 'Payment-success navigation leaked a Referer header.');
    await paymentPage.close();

    const claimPage = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await claimPage.route('https://app.netlify.com/claim*', (route) => route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<!doctype html><title>Netlify claim test destination</title>',
    }));
    const handoffId = 'a'.repeat(64);
    const claimBearer = 'B'.repeat(43);
    const claimRequestObserved = claimPage.waitForRequest((request) => new URL(request.url()).pathname === '/api/arc2/claim');
    await claimPage.goto(`${baseUrl}/claim/#arc2.${handoffId}.${claimBearer}`, { waitUntil: 'domcontentloaded' });
    await claimRequestObserved;
    const scrubbedClaimState = await claimPage.evaluate(() => ({
      pathname: location.pathname,
      search: location.search,
      hash: location.hash,
      body: document.body.textContent,
      localValues: Object.values(localStorage),
      sessionValues: Object.values(sessionStorage),
    }));
    assert.equal(scrubbedClaimState.pathname, '/claim/', 'Claim wrapper changed path while scrubbing its fragment.');
    assert.equal(scrubbedClaimState.search, '', 'Claim wrapper retained a query string.');
    assert.equal(scrubbedClaimState.hash, '', 'Claim wrapper did not immediately scrub its bearer fragment.');
    assert.doesNotMatch(scrubbedClaimState.body, new RegExp(`${handoffId}|${claimBearer}`), 'Claim credential entered rendered DOM text.');
    assert.doesNotMatch(JSON.stringify([...scrubbedClaimState.localValues, ...scrubbedClaimState.sessionValues]), new RegExp(`${handoffId}|${claimBearer}`), 'Claim credential entered browser storage.');
    await claimPage.waitForURL('https://app.netlify.com/claim#header.payload.signature');
    assert.equal(claimRequests.length, 1, 'Valid claim wrapper did not exchange exactly once.');
    assert.equal(claimRequests[0].method, 'POST');
    assert.equal(claimRequests[0].url, '/api/arc2/claim');
    assert.equal(claimRequests[0].headers.authorization, `Bearer ${claimBearer}`);
    assert.equal(claimRequests[0].headers['x-arc-handoff-id'], handoffId);
    assert.equal(claimRequests[0].headers.referer, undefined, 'Claim exchange leaked a Referer header.');
    assert.equal(claimRequests[0].body, '', 'Claim exchange unexpectedly put credentials in its body.');
    await claimPage.close();

    const invalidClaimPage = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await invalidClaimPage.goto(`${baseUrl}/claim/?token=forbidden#invalid`, { waitUntil: 'networkidle' });
    assert.equal(new URL(invalidClaimPage.url()).pathname, '/claim/');
    assert.equal(new URL(invalidClaimPage.url()).search, '', 'Invalid claim query was not scrubbed.');
    assert.equal(new URL(invalidClaimPage.url()).hash, '', 'Invalid claim fragment was not scrubbed.');
    assert.match(await invalidClaimPage.locator('h1').textContent(), /invitation is unavailable/i);
    assert.equal(claimRequests.length, 1, 'Invalid claim credential reached the exchange endpoint.');
    await invalidClaimPage.close();
  }
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

console.log(`ARC browser contract passed for ${viewports.length} desktop/tablet/mobile viewports.`);
