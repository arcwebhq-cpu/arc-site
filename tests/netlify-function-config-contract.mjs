import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';

const functionDirectory = new URL('../netlify/functions/', import.meta.url);
const allowedMethods = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

function configObject(source, file) {
  const declaration = source.indexOf('export const config');
  if (declaration < 0) return null;
  const open = source.indexOf('{', declaration);
  assert.ok(open >= 0, `${file} has an invalid exported config declaration.`);

  let depth = 0;
  let quote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = open; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (lineComment) {
      if (character === '\n') lineComment = false;
      continue;
    }
    if (blockComment) {
      if (character === '*' && next === '/') { blockComment = false; index += 1; }
      continue;
    }
    if (quote) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === '/' && next === '/') { lineComment = true; index += 1; continue; }
    if (character === '/' && next === '*') { blockComment = true; index += 1; continue; }
    if (character === "'" || character === '"' || character === '`') { quote = character; continue; }
    if (character === '{') depth += 1;
    if (character === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(open, index + 1);
    }
  }
  assert.fail(`${file} has an unterminated exported config object.`);
}

function propertyValue(config, property) {
  const match = config.match(new RegExp(`\\b${property}\\s*:\\s*(\\[[^\\]]*\\]|[^,}\\n]+)`));
  return match?.[1].trim() || null;
}

function quotedLiteral(value) {
  if (value.length < 2 || !["'", '"'].includes(value[0]) || value.at(-1) !== value[0]) return null;
  let escaped = false;
  for (let index = 1; index < value.length - 1; index += 1) {
    if (escaped) { escaped = false; continue; }
    if (value[index] === '\\') { escaped = true; continue; }
    if (value[index] === value[0] || value[index] === '\n' || value[index] === '\r') return null;
  }
  if (escaped) return null;
  return value.slice(1, -1);
}

function literalValues(value, file, property) {
  const rawValues = value.startsWith('[')
    ? value.slice(1, -1).split(',').map(item => item.trim()).filter(Boolean)
    : [value];
  assert.ok(rawValues.length > 0, `${file} config.${property} must not be an empty array.`);
  return rawValues.map((raw) => {
    const literal = quotedLiteral(raw);
    assert.notEqual(literal, null,
      `${file} config.${property} must use an inline string literal so Netlify can extract it at build time.`);
    return literal;
  });
}

let routedFunctions = 0;
for (const file of (await readdir(functionDirectory)).filter(name => name.endsWith('.mjs')).sort()) {
  const source = await readFile(new URL(file, functionDirectory), 'utf8');
  const config = configObject(source, file);
  if (!config) continue;

  const pathValue = propertyValue(config, 'path');
  if (pathValue) {
    routedFunctions += 1;
    for (const route of literalValues(pathValue, file, 'path')) {
      assert.match(route, /^\//, `${file} config.path must be an absolute site path.`);
    }
  }

  const methodValue = propertyValue(config, 'method');
  if (methodValue) {
    for (const method of literalValues(methodValue, file, 'method')) {
      assert.ok(allowedMethods.has(method), `${file} uses an unsupported literal HTTP method: ${method}`);
    }
  }
}

assert.ok(routedFunctions >= 20, 'Expected the ARC production Function route surface to remain covered.');
console.log(`ARC Netlify Function config contract passed for ${routedFunctions} custom-routed functions.`);
