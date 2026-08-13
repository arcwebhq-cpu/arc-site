import { cp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = path.join(root, 'dist');
const intakeBuildEnabled = process.env.ARC_BUILD_INTAKE_ENABLED === 'true';
const publicEntries = Object.freeze([
  'index.html',
  'favicon.svg',
  'robots.txt',
  'sitemap.xml',
  'assets',
  'thank-you',
  'payment-success',
  'claim',
  'privacy',
  'terms',
  'refunds',
  'service-scope',
]);

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
for (const entry of publicEntries) {
  await cp(path.join(root, entry), path.join(output, entry), { recursive: true, errorOnExist: true });
}

if (!intakeBuildEnabled) {
  // Production intake is deliberately compiled closed. Keeping the form fields
  // in source supports local QA, but the default deploy must not register a
  // Netlify-managed form or accept a direct POST. Activation needs an explicit
  // reviewed build flag as well as the independent runtime readiness gates.
  const builtHomePath = path.join(output, 'index.html');
  const builtHome = await readFile(builtHomePath, 'utf8');
  const closedHome = builtHome
    .replace(' data-intake-build-enabled="true"', ' data-intake-build-enabled="false"')
    .replace(' action="/thank-you/"', ' action="/"')
    .replace(' data-netlify="true"', '')
    .replace(' enctype="multipart/form-data"', '')
    .replace(' method="POST" name="arc-preview" netlify-honeypot="bot-field"', ' name="arc-preview"')
    .replace(/\s*<input type="hidden" name="form-name" value="arc-preview">/, '');
  if (closedHome === builtHome || !/data-intake-build-enabled="false"/.test(closedHome) || /data-netlify=|name="form-name"|netlify-honeypot=|method="POST"/.test(closedHome)) {
    throw new Error('Production intake could not be compiled fail-closed.');
  }
  await writeFile(builtHomePath, closedHome);
}

const built = (await readdir(output)).sort();
if (JSON.stringify(built) !== JSON.stringify([...publicEntries].sort())) {
  throw new Error(`Unexpected deploy output: ${built.join(', ')}`);
}
console.log(`ARC public build created with ${built.length} allowlisted root entries.`);
