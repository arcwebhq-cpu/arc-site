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

const intakeRequests = [];
const server = http.createServer(async (request, response) => {
  if (request.method === 'GET' && request.url?.split('?')[0] === '/api/intake/readiness') {
    response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(JSON.stringify({ schema: 'arc-intake-readiness-v1', intake_enabled: true }));
    return;
  }
  if (request.method === 'POST' && request.url?.split('?')[0] === '/api/analytics/event') {
    response.writeHead(202, { 'cache-control': 'no-store' }).end();
    return;
  }
  if (request.method === 'POST' && request.url?.split('?')[0] === '/api/intake/submit') {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    intakeRequests.push({ headers: request.headers, body: Buffer.concat(chunks) });
    response.writeHead(201, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
      .end(JSON.stringify({ schema: 'arc-intake-submission-accepted-v1', accepted: true, submission_id: '11111111-1111-4111-8111-111111111111' }));
    return;
  }
  try {
    const file = safePublicFile(request.url || '/');
    if (!file || !(await stat(file)).isFile()) throw new Error('Not found');
    response.writeHead(200, { 'content-type': contentTypes[path.extname(file)] || 'application/octet-stream' });
    if (file === path.join(root, 'index.html')) {
      // Build-contract proves the deploy is compiled closed. The browser harness
      // opts into the separately gated activation variant to exercise the full UI.
      const html = await readFile(file, 'utf8');
      const compiledClosed = new URL(request.url || '/', 'http://127.0.0.1').searchParams.get('intake') === 'closed';
      response.end(compiledClosed ? html : html.replace('data-intake-build-enabled="false"', 'data-intake-build-enabled="true"'));
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

const publicRoutes = ['/support/', '/service-scope/', '/terms/', '/privacy/', '/refunds/'];

async function waitForScrollSettled(page) {
  await page.evaluate(() => new Promise((resolve, reject) => {
    const deadline = performance.now() + 5_000;
    let lastX = scrollX;
    let lastY = scrollY;
    let stableFrames = 0;
    const observe = () => {
      const nextX = scrollX;
      const nextY = scrollY;
      stableFrames = Math.abs(nextX - lastX) < 0.5 && Math.abs(nextY - lastY) < 0.5 ? stableFrames + 1 : 0;
      lastX = nextX;
      lastY = nextY;
      if (stableFrames >= 6) resolve();
      else if (performance.now() >= deadline) reject(new Error('Smooth scrolling did not settle.'));
      else requestAnimationFrame(observe);
    };
    requestAnimationFrame(() => requestAnimationFrame(observe));
  }));
}

async function clickWrappedCheckbox(page, selector) {
  const input = page.locator(selector);
  const label = input.locator('xpath=ancestor::label[1]');
  await label.click({ position: { x: 18, y: 18 } });
  await page.waitForFunction((target) => document.querySelector(target)?.checked === true, selector);
}

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
    assert.equal(await page.locator('[data-intake-cta]').count(), 2, `${viewport.name}: expected exactly two intake actions`);
    assert.deepEqual(await page.locator('[data-intake-cta]').evaluateAll((elements) => elements.map((element) => ({
      href: element.getAttribute('href'),
      label: element.textContent.trim(),
    }))), [
      { href: '#start', label: 'Get Free Preview' },
      { href: '#start', label: 'Get Free Preview' },
    ], `${viewport.name}: intake actions do not use one clear label and destination`);
    assert.deepEqual(await page.locator('.work-item').evaluateAll((elements) => elements.map((element) => {
      const destination = new URL(element.href);
      return {
        path: destination.pathname,
        target: element.getAttribute('target'),
        rel: (element.getAttribute('rel') || '').split(/\s+/).filter(Boolean).sort(),
      };
    })), [
      { path: '/arc-previews/showcases/roofing/', target: '_blank', rel: ['noopener'] },
      { path: '/arc-previews/showcases/dental/', target: '_blank', rel: ['noopener'] },
      { path: '/arc-previews/showcases/finance/', target: '_blank', rel: ['noopener'] },
    ], `${viewport.name}: public showcase links are incomplete or unsafe`);
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
    await page.waitForFunction(() => location.hash === '#start');
    await waitForScrollSettled(page);
    const overlap = await page.evaluate(() => {
      const nav = document.querySelector('.nav').getBoundingClientRect();
      const card = document.getElementById('formCard').getBoundingClientRect();
      return { navBottom: nav.bottom, cardTop: card.top };
    });
    assert.ok(overlap.cardTop >= overlap.navBottom - 1, `${viewport.name}: sticky navigation overlaps the form card`);

    await page.locator('#next').click({ position: { x: 20, y: 20 } });
    assert.equal(await page.locator('#name').getAttribute('aria-invalid'), 'true', `${viewport.name}: invalid required field lacks aria-invalid`);
    assert.equal(await page.locator('#name').getAttribute('aria-describedby'), 'error', `${viewport.name}: invalid field is not associated with the error alert`);
    await waitForScrollSettled(page);

    await page.locator('#name').fill('Jordan Lee');
    await page.locator('#email').fill('jordan@example.com');
    await page.locator('#business').fill('Evergreen Home Services');
    await page.locator('#industry').fill('Home services');
    await page.locator('#city').fill('Everett, WA');
    await page.locator('#next').click({ position: { x: 20, y: 20 } });
    await page.waitForFunction(() => document.getElementById('stepCount')?.textContent === '2 / 3');
    assert.equal(await page.locator('#stepCount').textContent(), '2 / 3', `${viewport.name}: could not advance to offer step`);
    await waitForScrollSettled(page);

    await page.locator('#services').fill('Roof repair and replacement');
    await page.locator('input[name="goals"]').first().check();
    await page.locator('input[name="main_call_to_action"][value="Contact"]').check();
    await page.locator('#next').click({ position: { x: 20, y: 20 } });
    await page.waitForFunction(() => document.getElementById('stepCount')?.textContent === '3 / 3');
    assert.equal(await page.locator('#stepCount').textContent(), '3 / 3', `${viewport.name}: could not advance to details step`);
    assert.equal(await page.locator('#structureDetails').getAttribute('open'), '', `${viewport.name}: required lead routing details are still collapsed`);
    assert.equal(await page.locator('#contactFormSection').isChecked(), true,
      `${viewport.name}: the Contact CTA did not keep the contact-form section and verified lead route aligned`);
    await waitForScrollSettled(page);

    await clickWrappedCheckbox(page, '#budget');
    await clickWrappedCheckbox(page, '#termsAccepted');
    await page.waitForTimeout(500);
    const savedDraft = JSON.parse(await page.evaluate(() => localStorage.getItem('arc-preview-draft-v8')));
    assert.match(savedDraft.requestId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      `${viewport.name}: retained answers lost their exact-retry nonce`);
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
    const priorIntakeRequests = intakeRequests.length;
    await Promise.all([
      page.waitForURL('**/thank-you/'),
      page.locator('#submit').click(),
    ]);
    assert.equal(intakeRequests.length, priorIntakeRequests + 1, `${viewport.name}: complete brief was not submitted exactly once`);
    const intakeRequest = intakeRequests.at(-1);
    assert.match(intakeRequest.headers['content-type'] || '', /^multipart\/form-data;\s*boundary=/i,
      `${viewport.name}: intake did not use a multipart request`);
    assert.ok(intakeRequest.body.length > 0, `${viewport.name}: intake request body was empty`);
    assert.match(intakeRequest.body.toString('utf8'),
      /name="submission_request_id"\r\n\r\n[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\r\n/i,
      `${viewport.name}: multipart intake omitted its exact-retry nonce`);
    assert.deepEqual(errors, [], `${viewport.name}: browser errors: ${errors.join('; ')}`);
    await page.close();

    for (const publicRoute of publicRoutes) {
      const routePage = await browser.newPage({
        viewport: { width: viewport.width, height: viewport.height },
        isMobile: viewport.isMobile,
        hasTouch: viewport.isMobile,
      });
      const response = await routePage.goto(`${baseUrl}${publicRoute}`, { waitUntil: 'networkidle' });
      assert.equal(response?.status(), 200, `${viewport.name}: ${publicRoute} did not return 200`);
      assert.equal(await routePage.locator('h1').count(), 1, `${viewport.name}: ${publicRoute} must have one h1`);
      const routeLayout = await routePage.evaluate(() => ({
        clientWidth: document.documentElement.clientWidth,
        scrollWidth: document.documentElement.scrollWidth,
      }));
      assert.ok(routeLayout.scrollWidth <= routeLayout.clientWidth + 1,
        `${viewport.name}: ${publicRoute} overflows horizontally (${routeLayout.scrollWidth}px > ${routeLayout.clientWidth}px)`);
      await routePage.close();
    }
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
    assert.deepEqual(await noScriptPage.locator('[data-intake-cta]').evaluateAll((elements) => elements.map((element) => ({
      href: element.getAttribute('href'),
      label: element.textContent.trim(),
    }))), [
      { href: '#start', label: 'Get Free Preview' },
      { href: '#start', label: 'Get Free Preview' },
    ], 'The no-script page must direct both “Get Free Preview” actions to its truthful paused state.');
    assert.equal(await noScriptPage.locator('#projectForm').getAttribute('aria-disabled'), 'true',
      'The no-script compiled-closed form must remain semantically disabled.');
    assert.equal(await noScriptPage.locator('#projectForm').getAttribute('inert'), '',
      'The no-script compiled-closed form must remain inert.');
    assert.match(await noScriptPage.locator('#intakeStatus').textContent(), /Free preview requests are (?:currently|temporarily) paused\./i,
      'The no-script page must plainly disclose the paused state.');
    await noScriptPage.close();

    const compiledClosedPage = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await compiledClosedPage.goto(`${baseUrl}/?intake=closed`, { waitUntil: 'networkidle' });
    await compiledClosedPage.locator('[data-intake-cta]').first().click();
    await compiledClosedPage.waitForFunction(() => location.hash === '#start');
    await compiledClosedPage.waitForFunction(() => document.activeElement?.id === 'intakeStatus');
    await waitForScrollSettled(compiledClosedPage);
    assert.equal(await compiledClosedPage.locator('#projectForm').getAttribute('data-intake-enabled'), 'false',
      'The compiled-closed browser state unexpectedly opened intake.');
    assert.equal(await compiledClosedPage.locator('#projectForm').getAttribute('aria-disabled'), 'true',
      'The compiled-closed browser state is not semantically disabled.');
    assert.equal(await compiledClosedPage.locator('#projectForm').getAttribute('inert'), '',
      'The compiled-closed browser state is not inert.');
    assert.deepEqual(await compiledClosedPage.locator('#projectForm button').evaluateAll((buttons) => buttons.map((button) => button.disabled)),
      [true, true, true], 'The compiled-closed browser state exposed a form action.');
    assert.match(await compiledClosedPage.locator('#intakeStatus').textContent(), /Free preview requests are (?:currently|temporarily) paused\./i,
      'The intake action did not expose the truthful paused state.');
    const statusPosition = await compiledClosedPage.locator('#intakeStatus').evaluate((element) => {
      const bounds = element.getBoundingClientRect();
      return { top: bounds.top, bottom: bounds.bottom, viewportHeight: innerHeight };
    });
    assert.ok(statusPosition.bottom > 0 && statusPosition.top < statusPosition.viewportHeight,
      'The intake action did not bring the paused state into view.');
    const priorClosedIntakeRequests = intakeRequests.length;
    await compiledClosedPage.locator('#projectForm').evaluate((form) => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
    await compiledClosedPage.waitForTimeout(100);
    assert.equal(intakeRequests.length, priorClosedIntakeRequests,
      'The compiled-closed form issued an intake POST.');
    assert.match(await compiledClosedPage.locator('#error').textContent(), /Free preview requests are (?:currently|temporarily) paused\./i,
      'A blocked submit did not report the truthful paused state.');
    await compiledClosedPage.close();

    const disabledThankYouPage = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await disabledThankYouPage.addInitScript(() => {
      sessionStorage.setItem('arc-analytics-session', 'stale-session');
      sessionStorage.setItem('arc-pending-preview-analytics', 'stale-pending-event');
      localStorage.setItem('arc-preview-draft-v8', 'current-draft');
      localStorage.setItem('arc-preview-draft-v7', 'stale-draft');
    });
    await disabledThankYouPage.goto(`${baseUrl}/thank-you/`, { waitUntil: 'networkidle' });
    assert.deepEqual(await disabledThankYouPage.evaluate(() => ({
      session: sessionStorage.getItem('arc-analytics-session'),
      pending: sessionStorage.getItem('arc-pending-preview-analytics'),
      draft: localStorage.getItem('arc-preview-draft-v8'),
      legacyDraft: localStorage.getItem('arc-preview-draft-v7'),
    })), { session: null, pending: null, draft: null, legacyDraft: null },
    'The analytics-disabled thank-you page must clear stale analytics state and the accepted draft.');
    await disabledThankYouPage.close();

  }
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

console.log(`ARC browser contract passed for ${viewports.length} desktop/tablet/mobile viewports.`);
