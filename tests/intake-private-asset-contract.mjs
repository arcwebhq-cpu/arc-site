import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import assetHandler, { config as assetConfig } from '../netlify/functions/intake-private-asset.mjs';
import {
  INTAKE_PRIVATE_ASSET_REQUEST_SCHEMA,
  createPrivateAssetGrants,
  privateAssetIndexEntries,
  resolvePrivateAssetEnvironment,
  retrievePrivateAsset,
} from '../netlify/lib/intake-private-asset-core.mjs';
import { BUDGET_CONFIRMATION, TERMS_CONFIRMATION, normalizeIntakeForm } from '../netlify/lib/intake-submission-core.mjs';
import { validateDecodableImageAsset, validateImageAsset } from '../netlify/lib/image-asset-validation.mjs';

const framedButUndecodableJpeg = Buffer.from([
  0xff,0xd8,
  0xff,0xc0,0x00,0x0b,0x08,0x00,0x01,0x00,0x01,0x01,0x01,0x11,0x00,
  0xff,0xda,0x00,0x08,0x01,0x01,0x00,0x00,0x3f,0x00,
  0x11,0xff,0x00,0x22,0xff,0xd9,
]);
const validJpegBytes = Buffer.from('/9j/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wAARCAACAAIDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAj/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFAEBAAAAAAAAAAAAAAAAAAAAAf/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AJXAIf/Z', 'base64');
const validWebpBytes = Buffer.from('UklGRiAAAABXRUJQVlA4TBQAAAAvAAAAAAdQgVQIIAAKmv7HiIj+Bw==', 'base64');
const jpegSegment = (marker, data) => Buffer.concat([Buffer.from([0xff, marker, 0, data.length + 2]), data]);
const jpegWithSegment = (marker, data) => Buffer.concat([framedButUndecodableJpeg.subarray(0, 2), jpegSegment(marker, data), framedButUndecodableJpeg.subarray(2)]);
const pngChunk = (type, data = Buffer.from('metadata')) => {
  const chunk = Buffer.alloc(12 + data.length); chunk.writeUInt32BE(data.length); chunk.write(type, 4, 4, 'ascii'); data.copy(chunk, 8); return chunk;
};
const webp = (type = 'VP8L', data = Buffer.from([0x2f, 0, 0, 0, 0])) => {
  const padded = data.length + (data.length & 1); const output = Buffer.alloc(20 + padded);
  output.write('RIFF'); output.writeUInt32LE(output.length - 8, 4); output.write('WEBP', 8); output.write(type, 12);
  output.writeUInt32LE(data.length, 16); data.copy(output, 20); return output;
};
const validPngBytes = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
const pngWithChunk = (type) => Buffer.concat([validPngBytes.subarray(0, -12), pngChunk(type), validPngBytes.subarray(-12)]);

for (const [bytes, type] of [[framedButUndecodableJpeg, 'image/jpeg'], [validPngBytes, 'image/png'], [webp(), 'image/webp']]) {
  assert.equal(validateImageAsset(bytes, type), true);
}
for (const [bytes, type] of [[validJpegBytes, 'image/jpeg'], [validPngBytes, 'image/png'], [validWebpBytes, 'image/webp']]) {
  assert.equal(await validateDecodableImageAsset(bytes, type), true);
}
for (const [bytes, type] of [
  [Buffer.from([0xff, 0xd8, 0xff, 0xd9]), 'image/jpeg'],
  [Buffer.concat([validPngBytes.subarray(0, 8), validPngBytes.subarray(-12)]), 'image/png'],
  [(() => { const shell = Buffer.alloc(20); shell.write('RIFF'); shell.writeUInt32LE(12, 4); shell.write('WEBP', 8); shell.write('VP8 ', 12); return shell; })(), 'image/webp'],
  [jpegWithSegment(0xe1, Buffer.from('Exif\0\0')), 'image/jpeg'],
  [jpegWithSegment(0xec, Buffer.from('vendor')), 'image/jpeg'],
  [Buffer.concat([framedButUndecodableJpeg.subarray(0, -2), jpegSegment(0xe1, Buffer.from('Exif\0\0')), framedButUndecodableJpeg.subarray(-2)]), 'image/jpeg'],
  [framedButUndecodableJpeg.subarray(0, -2), 'image/jpeg'],
  [pngWithChunk('tEXt'), 'image/png'], [pngWithChunk('tIME'), 'image/png'], [pngWithChunk('vpAg'), 'image/png'],
  [webp('XMP ', Buffer.from('xmp')), 'image/webp'], [webp('META', Buffer.from('vendor')), 'image/webp'],
  [webp('VP8 ', Buffer.from('<svg>')), 'image/webp'], [Buffer.from('not-an-image'), 'image/png'],
]) assert.throws(() => validateImageAsset(bytes, type), /Image asset is invalid/);

const corruptPngCrc = Buffer.from(validPngBytes);
corruptPngCrc[29] ^= 1;
assert.throws(() => validateImageAsset(corruptPngCrc, 'image/png'), /CRC/);
const webpDimensionBombData = Buffer.from([0x2f, 0xe0, 0x2e, 0, 0]);
assert.throws(() => validateImageAsset(webp('VP8L', webpDimensionBombData), 'image/webp'), /dimensions/);
const validStructureInvalidIdat = Buffer.from(validPngBytes);
validStructureInvalidIdat[43] ^= 0xff;
const idatOffset = validStructureInvalidIdat.indexOf(Buffer.from('IDAT'));
const idatLength = validStructureInvalidIdat.readUInt32BE(idatOffset - 4);
const crcTable = Array.from({ length: 256 }, (_, value) => { let current = value; for (let bit = 0; bit < 8; bit += 1) current = current & 1 ? 0xedb88320 ^ (current >>> 1) : current >>> 1; return current >>> 0; });
let crc = 0xffffffff;
for (const byte of validStructureInvalidIdat.subarray(idatOffset, idatOffset + 4 + idatLength)) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
validStructureInvalidIdat.writeUInt32BE((crc ^ 0xffffffff) >>> 0, idatOffset + 4 + idatLength);
assert.equal(validateImageAsset(validStructureInvalidIdat, 'image/png'), true, 'Fixture must retain valid PNG framing and CRCs.');
await assert.rejects(validateDecodableImageAsset(validStructureInvalidIdat, 'image/png'), /fully decode/);
await assert.rejects(validateDecodableImageAsset(framedButUndecodableJpeg, 'image/jpeg'), /fully decode/);
await assert.rejects(validateDecodableImageAsset(webp(), 'image/webp'), /fully decode/);

const undecodableForm = new FormData();
for (const [key, value] of Object.entries({
  intake_version: 'arc-intake-v7', name: 'Private Owner', email: 'private@example.test', business: 'Private Roofing',
  industry: 'Roofing', city: 'Everett, WA', main_services: 'Roofing', main_call_to_action: 'Contact',
  lead_form_needed: 'Yes', lead_notification_email: 'private@example.test', primary_style: 'Modern',
  budget_confirmed: BUDGET_CONFIRMATION, terms_accepted: TERMS_CONFIRMATION, asset_permission: 'Confirmed', 'bot-field': '',
})) undecodableForm.append(key, value);
undecodableForm.append('goals', 'More calls');
undecodableForm.append('lead_form_fields', 'Email');
undecodableForm.append('sections', 'Contact or quote form');
undecodableForm.append('assets', 'Logo');
undecodableForm.append('logo_file', new Blob([validStructureInvalidIdat], { type: 'image/png' }), 'corrupt.png');
let undecodableIdentityAllocations = 0;
await assert.rejects(normalizeIntakeForm(undecodableForm, new Date(), () => {
  undecodableIdentityAllocations += 1;
  return '11111111-1111-4111-8111-111111111111';
}), /fully decode/, 'Invalid compressed bytes must fail before a durable submission identity can be allocated.');
assert.equal(undecodableIdentityAllocations, 0, 'Invalid compressed bytes must cause zero pre-storage identity/state mutation.');

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; }
  async getWithMetadata(key) { const item = this.values.get(key); return item ? { data: structuredClone(item.data), etag: item.etag } : null; }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `e-${++this.sequence}`; this.values.set(key, { data: structuredClone(data), etag }); return { modified: true, etag };
  }
}
const form = new FormData();
for (const [key, value] of Object.entries({
  intake_version: 'arc-intake-v7', name: 'Private Owner', email: 'private@example.test', business: 'Private Roofing',
  industry: 'Roofing', city: 'Everett, WA', main_services: 'Roofing', main_call_to_action: 'Contact',
  lead_form_needed: 'Yes', lead_notification_email: 'private@example.test', primary_style: 'Modern',
  budget_confirmed: BUDGET_CONFIRMATION, terms_accepted: TERMS_CONFIRMATION, asset_permission: 'Confirmed',
  'bot-field': '',
})) form.append(key, value);
form.append('goals', 'More calls');
form.append('lead_form_fields', 'Email');
form.append('sections', 'Contact or quote form');
form.append('assets', 'Logo');
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
form.append('logo_file', new Blob([png], { type: 'image/png' }), 'logo.png');
const now = new Date('2026-08-13T20:00:00.000Z');
const submissionId = '11111111-1111-4111-8111-111111111111';
const normalized = await normalizeIntakeForm(form, now, () => submissionId);
const env = {
  ARC_INTAKE_ASSET_RETRIEVAL_ENABLED: 'true',
  ARC_INTAKE_ASSET_RETRIEVAL_SECRET: 'asset-retrieval-secret-unique-0123456789',
  ARC_INTAKE_ARC1_STATE_SECRET: 'state-secret-unique-0123456789-abcdefgh', URL: 'https://arcweb.onl',
};
const resolved = resolvePrivateAssetEnvironment(env);
const grants = createPrivateAssetGrants(normalized.record, resolved);
assert.deepEqual(grants.map(item => item.role), ['logo_file']);
assert.equal(JSON.stringify(grants).includes(png.toString('base64')), false);
const deliveryId = 'a'.repeat(64), evidenceSha256 = 'b'.repeat(64);
const store = new FakeStore(); await store.setJSON(normalized.key, normalized.record, { onlyIfNew: true });
for (const index of privateAssetIndexEntries(normalized.record, grants, {
  deliveryId, evidenceSha256, expiresAt: new Date(now.getTime() + 60_000).toISOString(),
})) await store.setJSON(index.key, index.value, { onlyIfNew: true });
for (const grant of grants) {
  const result = await retrievePrivateAsset({ schema: INTAKE_PRIVATE_ASSET_REQUEST_SCHEMA, asset_id: grant.asset_id, delivery_id: deliveryId, evidence_sha256: evidenceSha256 }, env, { store, now });
  assert.equal(createHash('sha256').update(result.bytes).digest('hex'), grant.sha256);
  assert.deepEqual(result.bytes, png);
}
const uploadGrant = grants.find(item => item.kind === 'UPLOAD');
await assert.rejects(retrievePrivateAsset({ schema: INTAKE_PRIVATE_ASSET_REQUEST_SCHEMA, asset_id: uploadGrant.asset_id, delivery_id: deliveryId, evidence_sha256: '0'.repeat(64) }, env, { store, now }), /NOT_FOUND/);
const source = store.values.get(normalized.key); source.data.assets.find(item => item.kind === 'UPLOAD').content_base64 = Buffer.from([1,2,3]).toString('base64');
await assert.rejects(retrievePrivateAsset({ schema: INTAKE_PRIVATE_ASSET_REQUEST_SCHEMA, asset_id: uploadGrant.asset_id, delivery_id: deliveryId, evidence_sha256: evidenceSha256 }, env, { store, now }), /BINDING_FAILED/);
source.data.assets.find(item => item.kind === 'UPLOAD').content_base64 = png.toString('base64'); source.data.data.asset_permission = '';
await assert.rejects(retrievePrivateAsset({ schema: INTAKE_PRIVATE_ASSET_REQUEST_SCHEMA, asset_id: uploadGrant.asset_id, delivery_id: deliveryId, evidence_sha256: evidenceSha256 }, env, { store, now }), /PERMISSION_REQUIRED/);

const saved = { ...process.env };
try {
  Object.assign(process.env, env);
  delete process.env.ARC_INTAKE_ASSET_RETRIEVAL_ENABLED;
  const request = () => new Request('https://arcweb.onl/internal/intake/arc1/assets/retrieve', { method: 'POST', headers: {
    authorization: `Bearer ${env.ARC_INTAKE_ASSET_RETRIEVAL_SECRET}`, 'content-type': 'application/json',
  }, body: JSON.stringify({ schema: INTAKE_PRIVATE_ASSET_REQUEST_SCHEMA, asset_id: uploadGrant.asset_id, delivery_id: deliveryId, evidence_sha256: evidenceSha256 }) });
  assert.equal((await assetHandler(request(), { get intakeStore() { throw new Error('Disabled asset endpoint must not touch storage.'); } })).status, 503);
  process.env.ARC_INTAKE_ASSET_RETRIEVAL_ENABLED = 'true';
  assert.equal((await assetHandler(new Request('https://arcweb.onl/internal/intake/arc1/assets/retrieve', { method: 'POST' }))).status, 401);
} finally { for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key]; Object.assign(process.env, saved); }
assert.equal(assetConfig.path, '/internal/intake/arc1/assets/retrieve');
assert.equal(assetConfig.method, 'POST');
console.log('ARC private content-addressed intake asset producer contract passed.');
