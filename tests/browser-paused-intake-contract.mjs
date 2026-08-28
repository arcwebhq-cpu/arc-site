import assert from 'node:assert/strict';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

if (process.getuid?.() === 0) process.getuid = () => 1000;
const { default: serverlessChromium } = await import('@sparticuz/chromium');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../dist');
const contentTypes = { '.html': 'text/html; charset=utf-8', '.jpg': 'image/jpeg', '.png': 'image/png', '.svg': 'image/svg+xml' };

function safePublicFile(urlPath) {
  let relative = decodeURIComponent(urlPath.split('?')[0]).replace(/^\/+/, '');
  if (!relative || relative.endsWith('/')) relative += 'index.html';
  const absolute = path.resolve(root, relative);
  return absolute.startsWith(`${root}${path.sep}`) ? absolute : null;
}

let postCount = 0;
const server = http.createServer(async (request, response) => {
  if (request.method === 'POST') {
    postCount += 1;
    response.writeHead(500, { 'content-type': 'text/plain' }).end('A paused build must not POST.');
    return;
  }
  try {
    const file = safePublicFile(request.url || '/');
    if (!file || !(await stat(file)).isFile()) throw new Error('Not found');
    response.writeHead(200, { 'content-type': contentTypes[path.extname(file)] || 'application/octet-stream' });
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

try {
  for (const javaScriptEnabled of [true, false]) {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 }, javaScriptEnabled });
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    const form = page.locator('#projectForm');
    assert.equal(await form.getAttribute('data-intake-enabled'), 'false');
    assert.equal(await form.getAttribute('aria-disabled'), 'true');
    assert.equal(await form.getAttribute('inert'), '');
    assert.equal(await form.getAttribute('action'), null);
    assert.equal(await form.getAttribute('method'), null);
    assert.equal(await form.getAttribute('data-netlify'), null);
    assert.equal(await page.locator('#submit').isDisabled(), true);
    assert.match(await page.locator('#intakeStatus').textContent(), /Free preview requests are paused\./i);
    assert.equal(await page.locator('#intakeStatus').isVisible(), true);
    assert.deepEqual(await page.locator('[data-intake-cta]').evaluateAll((elements) => elements.map((element) => ({
      href: element.getAttribute('href'), label: element.textContent.trim(),
    }))), [
      { href: '#start', label: 'Get Free Preview' },
      { href: '#start', label: 'Get Free Preview' },
    ]);
    await page.locator('[data-intake-cta]').first().click();
    await page.waitForTimeout(javaScriptEnabled ? 500 : 50);
    assert.equal(new URL(page.url()).hash, '#start');
    if (javaScriptEnabled) assert.equal(await page.evaluate(() => document.activeElement?.id), 'intakeStatus',
      'The paused CTA must focus the visible status instead of an inert field.');
    assert.equal(postCount, 0);
    await page.close();
  }
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

console.log('ARC paused-intake browser contract passed with and without JavaScript.');
