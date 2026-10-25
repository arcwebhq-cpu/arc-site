import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const PARTNER_CONTRACT_SCHEMA = 'arc-site-partner-contract-bundle-v1';
export const PARTNER_CONTRACT_DIRECTORIES = Object.freeze([
  'netlify/lib',
  'vendor/image-size-disabled',
]);
export const PARTNER_CONTRACT_FILES = Object.freeze([
  'netlify/functions/arc2-handoff-start.mjs',
  'operations/review-activation-environment.json',
  'package-lock.json',
  'package.json',
]);

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = path.join(projectRoot, 'operations/arc-site-partner-contract.json');
const sha256 = value => createHash('sha256').update(value).digest('hex');
const allowedBuiltins = new Set(['node:crypto', 'node:net', 'node:url']);
const allowedCoveredDataFiles = new Set(['vendor/image-size-disabled/package.json']);
const forbiddenNpmControlFiles = Object.freeze(['.npmrc', 'npm-shrinkwrap.json']);
const dynamicImportPattern = /\bimport(?:(?:\s+)|(?:\/\*[\s\S]*?\*\/)|(?:\/\/[^\n]*(?:\n|$)))*\(/;
const moduleScanner = `
import vm from 'node:vm';
let input = '';
for await (const chunk of process.stdin) input += chunk;
const sources = JSON.parse(input);
const result = {};
for (const [name, source] of Object.entries(sources)) {
  const parsed = new vm.SourceTextModule(source, { identifier: name });
  result[name] = parsed.moduleRequests
    ? parsed.moduleRequests.map(request => request.specifier)
    : parsed.dependencySpecifiers;
}
process.stdout.write(JSON.stringify(result));
`;
const comparePortablePaths = (left, right) => left === right ? 0 : left < right ? -1 : 1;

function assertPortablePath(relativePath) {
  assert.match(relativePath, /^[A-Za-z0-9._/-]+$/,
    `${relativePath} contains a nonportable partner-contract path character`);
  assert.ok(!relativePath.split('/').some(part => part === '' || part === '.' || part === '..'),
    `${relativePath} must be a normalized relative partner-contract path`);
}

async function assertNoSymlinkAncestors(root, relativePath) {
  assertPortablePath(relativePath);
  const rootRealPath = await realpath(root);
  let current = root;
  for (const part of relativePath.split('/')) {
    current = path.join(current, part);
    const stat = await lstat(current);
    assert.equal(stat.isSymbolicLink(), false,
      `${relativePath} contains a symbolic-link path component: ${part}`);
  }
  const targetRealPath = await realpath(current);
  assert.ok(targetRealPath.startsWith(`${rootRealPath}${path.sep}`),
    `${relativePath} resolves outside the partner contract root`);
}

async function regularFileEntry(root, relativePath) {
  assertPortablePath(relativePath);
  const absolutePath = path.join(root, ...relativePath.split('/'));
  await assertNoSymlinkAncestors(root, relativePath);
  const stat = await lstat(absolutePath);
  assert.equal(stat.isSymbolicLink(), false, `${relativePath} must not be a symbolic link`);
  assert.equal(stat.isFile(), true, `${relativePath} must be a regular file`);
  const bytes = await readFile(absolutePath);
  return { path: relativePath, size: bytes.byteLength, sha256: sha256(bytes) };
}

async function directoryEntries(root, relativeDirectory) {
  const absoluteDirectory = path.join(root, ...relativeDirectory.split('/'));
  await assertNoSymlinkAncestors(root, relativeDirectory);
  const rootStat = await lstat(absoluteDirectory);
  assert.equal(rootStat.isSymbolicLink(), false, `${relativeDirectory} must not be a symbolic link`);
  assert.equal(rootStat.isDirectory(), true, `${relativeDirectory} must be a directory`);

  const output = [];
  async function visit(absolute, relative) {
    const entries = await readdir(absolute, { withFileTypes: true });
    for (const entry of entries.sort((left, right) => comparePortablePaths(left.name, right.name))) {
      assert.match(entry.name, /^[A-Za-z0-9._-]+$/,
        `${relative}/${entry.name} contains a nonportable partner-contract filename`);
      const childRelative = `${relative}/${entry.name}`;
      const childAbsolute = path.join(absolute, entry.name);
      assert.equal(entry.isSymbolicLink(), false, `${childRelative} must not be a symbolic link`);
      if (entry.isDirectory()) await visit(childAbsolute, childRelative);
      else {
        assert.equal(entry.isFile(), true, `${childRelative} must be a regular file`);
        output.push(await regularFileEntry(root, childRelative));
      }
    }
  }
  await visit(absoluteDirectory, relativeDirectory);
  return output;
}

async function assertAbsent(root, relativePath) {
  try {
    await lstat(path.join(root, relativePath));
    assert.fail(`${relativePath} is forbidden in the partner contract checkout`);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

function packageName(specifier) {
  const parts = specifier.split('/');
  return specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
}

function integrityAncestor(packages, packagePath) {
  return Object.entries(packages)
    .filter(([candidate, value]) => candidate && packagePath.startsWith(`${candidate}/`) &&
      /^sha512-[A-Za-z0-9+/]+={0,2}$/.test(String(value.integrity || '')))
    .sort(([left], [right]) => right.length - left.length)[0]?.[0] || null;
}

function fileReferences(value, output = []) {
  if (typeof value === 'string' && value.startsWith('file:')) output.push(value.slice(5));
  else if (Array.isArray(value)) value.forEach(item => fileReferences(item, output));
  else if (value && typeof value === 'object') Object.values(value).forEach(item => fileReferences(item, output));
  return output;
}

async function verifyDependencyLockClosure(root) {
  const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  const packageLock = JSON.parse(await readFile(path.join(root, 'package-lock.json'), 'utf8'));
  assert.equal(packageLock.lockfileVersion, 3, 'Partner dependency lock must remain npm lockfile v3');
  assert.ok(packageLock.packages && typeof packageLock.packages === 'object');
  assert.deepEqual(packageLock.packages['']?.dependencies || {}, packageJson.dependencies || {},
    'Locked production dependencies changed');
  assert.deepEqual(packageLock.packages['']?.devDependencies || {}, packageJson.devDependencies || {},
    'Locked development dependencies changed');

  for (const reference of fileReferences(packageJson)) {
    const normalized = path.posix.normalize(reference.replaceAll('\\', '/')).replace(/^\.\//, '');
    assert.ok(PARTNER_CONTRACT_DIRECTORIES.some(directory =>
      normalized === directory || normalized.startsWith(`${directory}/`)),
    `Local npm reference escapes the covered partner set: ${reference}`);
  }
  for (const reference of fileReferences(packageLock)) {
    const normalized = path.posix.normalize(reference.replaceAll('\\', '/')).replace(/^\.\//, '');
    assert.ok(PARTNER_CONTRACT_DIRECTORIES.some(directory =>
      normalized === directory || normalized.startsWith(`${directory}/`)),
    `Locked local npm reference escapes the covered partner set: ${reference}`);
  }
  for (const [packagePath, value] of Object.entries(packageLock.packages)) {
    if (!packagePath) continue;
    if (value.link) {
      assert.equal(typeof value.resolved, 'string', `${packagePath} link must have a target`);
      const normalizedTarget = path.posix.normalize(value.resolved.replaceAll('\\', '/'));
      assert.equal(normalizedTarget, value.resolved, `${packagePath} link target must be normalized`);
      assert.ok(normalizedTarget.startsWith('node_modules/') && !normalizedTarget.includes('/../'),
        `${packagePath} link target escapes node_modules`);
      assert.ok(packageLock.packages[normalizedTarget], `${packagePath} link target is not lock-bound`);
      assert.ok(packageLock.packages[normalizedTarget].integrity ||
        integrityAncestor(packageLock.packages, normalizedTarget),
      `${packagePath} link target is not integrity-bound`);
      continue;
    }
    if (value.integrity) {
      assert.match(value.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/,
        `${packagePath} must use SHA-512 package integrity`);
      const artifact = new URL(String(value.resolved || ''));
      assert.equal(artifact.protocol, 'https:', `${packagePath} must use an HTTPS package artifact`);
      assert.equal(artifact.hostname, 'registry.npmjs.org',
        `${packagePath} must use the reviewed npm registry host`);
      assert.equal(artifact.username, '', `${packagePath} artifact URL must not contain credentials`);
      assert.equal(artifact.password, '', `${packagePath} artifact URL must not contain credentials`);
      continue;
    }
    assert.ok(integrityAncestor(packageLock.packages, packagePath),
      `${packagePath} is not contained in an integrity-bound package`);
  }
  return new Set(Object.keys(packageJson.dependencies || {}));
}

async function verifyImportClosure(root, entries, allowedPackages) {
  const coveredPaths = new Set(entries.map(entry => entry.path));
  const sources = {};
  for (const entry of entries.filter(candidate => candidate.path.endsWith('.mjs'))) {
    const source = await readFile(path.join(root, ...entry.path.split('/')), 'utf8');
    assert.doesNotMatch(source, dynamicImportPattern,
      `${entry.path} must not use a dynamic import in the partner contract`);
    sources[entry.path] = source;
  }
  const scan = spawnSync(process.execPath,
    ['--no-warnings', '--experimental-vm-modules', '--input-type=module', '-e', moduleScanner], {
      encoding: 'utf8',
      input: JSON.stringify(sources),
      maxBuffer: 10 * 1024 * 1024,
    });
  assert.equal(scan.status, 0, `Partner module parse failed: ${scan.stderr || scan.stdout}`);
  const requests = JSON.parse(scan.stdout);
  for (const [sourcePath, specifiers] of Object.entries(requests)) {
    for (const specifier of specifiers) {
      if (specifier.startsWith('./') || specifier.startsWith('../')) {
        const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(sourcePath), specifier));
        assert.ok(coveredPaths.has(resolved),
          `${sourcePath} import escapes the covered partner set: ${specifier}`);
      } else if (specifier.startsWith('node:')) {
        assert.ok(allowedBuiltins.has(specifier),
          `${sourcePath} imports an unreviewed Node builtin: ${specifier}`);
      } else {
        assert.ok(!specifier.includes(':') && allowedPackages.has(packageName(specifier)),
          `${sourcePath} imports an unlocked package: ${specifier}`);
      }
    }
  }
}

async function verifyCoveredFileKinds(root, entries) {
  for (const entry of entries) {
    const inCoveredDirectory = PARTNER_CONTRACT_DIRECTORIES.some(directory =>
      entry.path.startsWith(`${directory}/`));
    if (!inCoveredDirectory || entry.path.endsWith('.mjs')) continue;
    assert.ok(allowedCoveredDataFiles.has(entry.path),
      `${entry.path} has an unreviewed covered file type; only .mjs modules and the reviewed package JSON are allowed`);
    const packageJson = JSON.parse(await readFile(path.join(root, ...entry.path.split('/')), 'utf8'));
    assert.deepEqual(Object.keys(packageJson).sort(comparePortablePaths),
      ['exports', 'name', 'private', 'type', 'version'].sort(comparePortablePaths),
    `${entry.path} package fields changed`);
    assert.equal(packageJson.name, 'image-size');
    assert.equal(packageJson.private, true);
    assert.equal(packageJson.type, 'module');
    assert.equal(packageJson.exports, './index.mjs');
    assert.match(packageJson.version, /^3\.0\.0-arc-disabled\.\d+$/);
  }
}

export async function computePartnerContract(root = projectRoot) {
  const rootStat = await lstat(root);
  assert.equal(rootStat.isSymbolicLink(), false, 'Partner contract root must not be a symbolic link');
  assert.equal(rootStat.isDirectory(), true, 'Partner contract root must be a directory');
  for (const file of forbiddenNpmControlFiles) await assertAbsent(root, file);
  const entries = [];
  for (const directory of PARTNER_CONTRACT_DIRECTORIES) {
    entries.push(...await directoryEntries(root, directory));
  }
  for (const file of PARTNER_CONTRACT_FILES) entries.push(await regularFileEntry(root, file));
  entries.sort((left, right) => comparePortablePaths(left.path, right.path));
  assert.equal(new Set(entries.map(entry => entry.path)).size, entries.length,
    'Partner contract paths must be unique');
  await verifyCoveredFileKinds(root, entries);
  const allowedPackages = await verifyDependencyLockClosure(root);
  await verifyImportClosure(root, entries, allowedPackages);

  const payload = {
    schema: PARTNER_CONTRACT_SCHEMA,
    version: 1,
    directories: [...PARTNER_CONTRACT_DIRECTORIES],
    files: [...PARTNER_CONTRACT_FILES],
    entries,
  };
  const canonical = `${JSON.stringify(payload)}\n`;
  return { entry_count: entries.length, sha256: sha256(canonical) };
}

function manifestFor(bundle) {
  return {
    schema: 'arc-site-partner-contract-manifest-v1',
    version: 1,
    repository: 'arcwebhq-cpu/arc-site',
    bundle: {
      schema: PARTNER_CONTRACT_SCHEMA,
      version: 1,
      directories: [...PARTNER_CONTRACT_DIRECTORIES],
      files: [...PARTNER_CONTRACT_FILES],
      entry_count: bundle.entry_count,
      sha256: bundle.sha256,
    },
  };
}

export async function writePartnerContractManifest(root = projectRoot,
  expectedManifestPath = manifestPath) {
  const actual = await computePartnerContract(root);
  await writeFile(expectedManifestPath, `${JSON.stringify(manifestFor(actual), null, 2)}\n`);
  return actual;
}

export async function verifyPartnerContract(root = projectRoot, expectedManifestPath = manifestPath) {
  const relativeManifestPath = path.relative(root, expectedManifestPath).split(path.sep).join('/');
  assertPortablePath(relativeManifestPath);
  await assertNoSymlinkAncestors(root, relativeManifestPath);
  const manifestStat = await lstat(expectedManifestPath);
  assert.equal(manifestStat.isSymbolicLink(), false, 'Partner manifest must not be a symbolic link');
  assert.equal(manifestStat.isFile(), true, 'Partner manifest must be a regular file');
  const manifest = JSON.parse(await readFile(expectedManifestPath, 'utf8'));
  assert.deepEqual(Object.keys(manifest).sort(),
    ['bundle', 'repository', 'schema', 'version'].sort(), 'Partner manifest fields changed');
  assert.equal(manifest.schema, 'arc-site-partner-contract-manifest-v1');
  assert.equal(manifest.version, 1);
  assert.equal(manifest.repository, 'arcwebhq-cpu/arc-site');
  assert.deepEqual(Object.keys(manifest.bundle).sort(),
    ['directories', 'entry_count', 'files', 'schema', 'sha256', 'version'].sort(),
    'Partner manifest bundle fields changed');
  assert.equal(manifest.bundle.schema, PARTNER_CONTRACT_SCHEMA);
  assert.equal(manifest.bundle.version, 1);
  assert.deepEqual(manifest.bundle.directories, [...PARTNER_CONTRACT_DIRECTORIES]);
  assert.deepEqual(manifest.bundle.files, [...PARTNER_CONTRACT_FILES]);
  assert.match(manifest.bundle.sha256, /^[a-f0-9]{64}$/);

  const actual = await computePartnerContract(root);
  assert.deepEqual(actual, {
    entry_count: manifest.bundle.entry_count,
    sha256: manifest.bundle.sha256,
  }, 'ARC site partner contract changed; regenerate the reviewed manifest and preview binding');
  return actual;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  if (process.argv.includes('--write-manifest')) await writePartnerContractManifest();
  const result = await verifyPartnerContract();
  console.log(`ARC site partner contract passed (${result.entry_count} files; ${result.sha256}).`);
}
