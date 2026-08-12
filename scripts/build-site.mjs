import { cp, mkdir, readdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = path.join(root, 'dist');
const publicEntries = Object.freeze([
  'index.html',
  'favicon.svg',
  'assets',
  'thank-you',
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

const built = (await readdir(output)).sort();
if (JSON.stringify(built) !== JSON.stringify([...publicEntries].sort())) {
  throw new Error(`Unexpected deploy output: ${built.join(', ')}`);
}
console.log(`ARC public build created with ${built.length} allowlisted root entries.`);
