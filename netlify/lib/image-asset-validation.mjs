import sharp from 'sharp';

// Canonical fail-closed validation for customer image bytes. Only a narrow,
// metadata-free, structurally complete raster subset is accepted at every
// durable boundary.
const TYPES = Object.freeze({ png: 'image/png', jpg: 'image/jpeg', webp: 'image/webp' });
const MAX_DIMENSION = 12_000;
const MAX_PIXELS = 16_000_000;

function fail(message) {
  throw new TypeError(`Image asset is invalid: ${message}.`);
}

function dimensions(width, height, label) {
  if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1 ||
      width > MAX_DIMENSION || height > MAX_DIMENSION || width * height > MAX_PIXELS) fail(`${label} dimensions`);
}

function validateJpeg(bytes) {
  if (bytes.length < 30 || bytes[0] !== 0xff || bytes[1] !== 0xd8) fail('malformed JPEG');
  let offset = 2;
  let sawFrame = false;
  while (offset < bytes.length) {
    if (bytes[offset] !== 0xff) fail('JPEG marker alignment');
    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
    if (offset >= bytes.length) fail('malformed JPEG marker');
    const marker = bytes[offset++];
    if (marker === 0xd9) fail('JPEG missing scan');
    if (marker === 0 || marker === 1 || marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7)) fail('JPEG marker order');
    if (offset + 2 > bytes.length) fail('truncated JPEG segment');
    const length = bytes.readUInt16BE(offset);
    if (length < 2 || offset + length > bytes.length) fail('malformed JPEG segment');
    const data = bytes.subarray(offset + 2, offset + length);
    if (marker === 0xc0) {
      const components = data[5];
      if (sawFrame || data.length < 9 || data[0] !== 8 || components < 1 || components > 4 || length !== 8 + 3 * components) {
        fail('JPEG baseline frame');
      }
      dimensions(data.readUInt16BE(3), data.readUInt16BE(1), 'JPEG');
      sawFrame = true;
    } else if ((marker >= 0xc1 && marker <= 0xcf) && ![0xc4, 0xc8, 0xcc].includes(marker)) {
      fail('unsupported JPEG frame');
    }
    if (marker === 0xda) {
      const scanComponents = data[0];
      if (!sawFrame || scanComponents < 1 || scanComponents > 4 || length !== 6 + 2 * scanComponents) fail('JPEG scan header');
      let scanOffset = offset + length;
      let entropyBytes = 0;
      while (scanOffset < bytes.length) {
        if (bytes[scanOffset] !== 0xff) { entropyBytes += 1; scanOffset += 1; continue; }
        let markerOffset = scanOffset + 1;
        while (markerOffset < bytes.length && bytes[markerOffset] === 0xff) markerOffset += 1;
        if (markerOffset >= bytes.length) fail('truncated JPEG entropy');
        const scanMarker = bytes[markerOffset];
        if (scanMarker === 0) { entropyBytes += 1; scanOffset = markerOffset + 1; continue; }
        if (scanMarker >= 0xd0 && scanMarker <= 0xd7) { scanOffset = markerOffset + 1; continue; }
        if (scanMarker === 0xd9 && markerOffset + 1 === bytes.length && entropyBytes > 0) return;
        fail('JPEG metadata or multiple scans');
      }
      fail('missing JPEG end marker');
    }
    if (marker === 0xfe) fail('JPEG comments');
    if (marker >= 0xe0 && marker <= 0xef) {
      const jfif = marker === 0xe0 && data.length >= 14 && data.subarray(0, 5).toString('latin1') === 'JFIF\0' &&
        data[5] === 1 && data.length === 14 + (3 * data[12] * data[13]);
      const adobe = marker === 0xee && data.length === 12 && data.subarray(0, 5).toString('latin1') === 'Adobe';
      if (!jfif && !adobe) fail('JPEG APP metadata');
    }
    offset += length;
  }
  fail('malformed JPEG container');
}

const CRC_TABLE = Array.from({ length: 256 }, (_, value) => {
  let current = value;
  for (let bit = 0; bit < 8; bit += 1) current = current & 1 ? 0xedb88320 ^ (current >>> 1) : current >>> 1;
  return current >>> 0;
});
function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

function validatePng(bytes) {
  if (bytes.length < 57 || !bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) fail('malformed PNG');
  const forbidden = new Set(['eXIf', 'tEXt', 'zTXt', 'iTXt', 'iCCP', 'tIME']);
  const allowed = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'cHRM', 'gAMA', 'sBIT', 'sRGB', 'bKGD', 'hIST', 'tRNS', 'pHYs']);
  let offset = 8, chunkIndex = 0, dataBytes = 0, colorType = -1;
  let sawHeader = false, sawPalette = false, sawData = false, dataEnded = false;
  while (offset < bytes.length) {
    if (offset + 12 > bytes.length) fail('truncated PNG chunk');
    const length = bytes.readUInt32BE(offset);
    const type = bytes.subarray(offset + 4, offset + 8).toString('ascii');
    const dataStart = offset + 8, crcOffset = dataStart + length, next = crcOffset + 4;
    if (!/^[A-Za-z]{4}$/.test(type) || next > bytes.length || crc32(bytes.subarray(offset + 4, crcOffset)) !== bytes.readUInt32BE(crcOffset)) {
      fail('malformed PNG chunk or CRC');
    }
    if (forbidden.has(type) || (!allowed.has(type) && /^[a-z]/.test(type))) fail('PNG metadata');
    if (!allowed.has(type)) fail('unsupported critical PNG chunk');
    const data = bytes.subarray(dataStart, crcOffset);
    if (type === 'IHDR') {
      if (chunkIndex !== 0 || sawHeader || length !== 13) fail('PNG IHDR order');
      const width = data.readUInt32BE(0), height = data.readUInt32BE(4), bitDepth = data[8];
      colorType = data[9];
      const legalDepths = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
      dimensions(width, height, 'PNG');
      if (!legalDepths[colorType]?.includes(bitDepth) || data[10] !== 0 || data[11] !== 0 || ![0, 1].includes(data[12])) fail('PNG IHDR fields');
      sawHeader = true;
    } else if (!sawHeader) fail('PNG chunk before IHDR');
    if (type === 'PLTE') {
      if (sawPalette || sawData || length < 3 || length > 768 || length % 3) fail('PNG palette');
      sawPalette = true;
    } else if (type === 'IDAT') {
      if (dataEnded || length < 1) fail('PNG IDAT order');
      sawData = true;
      dataBytes += length;
    } else if (sawData && type !== 'IEND') dataEnded = true;
    if (type === 'IEND') {
      if (!sawData || dataBytes < 2 || length !== 0 || next !== bytes.length || (colorType === 3 && !sawPalette)) fail('PNG IEND or image data');
      return;
    }
    offset = next;
    chunkIndex += 1;
  }
  fail('malformed PNG container');
}

function uint24LE(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16);
}

function validateWebp(bytes) {
  if (bytes.length < 25 || bytes.subarray(0, 4).toString('ascii') !== 'RIFF' ||
      bytes.subarray(8, 12).toString('ascii') !== 'WEBP' || bytes.readUInt32LE(4) + 8 !== bytes.length) fail('malformed WebP');
  const allowed = new Set(['VP8 ', 'VP8L', 'VP8X', 'ALPH', 'ANIM', 'ANMF']);
  let offset = 12, first = true, extended = false, animated = false, sawPrimary = false;
  while (offset < bytes.length) {
    if (offset + 8 > bytes.length) fail('truncated WebP chunk');
    const type = bytes.subarray(offset, offset + 4).toString('ascii');
    const length = bytes.readUInt32LE(offset + 4), dataStart = offset + 8, next = dataStart + length + (length & 1);
    if (next > bytes.length || !allowed.has(type)) fail('WebP metadata or unknown chunk');
    const data = bytes.subarray(dataStart, dataStart + length);
    if (type === 'VP8X') {
      if (!first || extended || length !== 10 || (data[0] & 0xc1) !== 0) fail('WebP VP8X');
      extended = true; animated = Boolean(data[0] & 0x02);
      if (animated) fail('animated WebP is unsupported');
      dimensions(uint24LE(data, 4) + 1, uint24LE(data, 7) + 1, 'WebP');
    } else if (type === 'VP8 ') {
      if (sawPrimary || animated || length < 10 || data[3] !== 0x9d || data[4] !== 0x01 || data[5] !== 0x2a) fail('WebP VP8 payload');
      dimensions(data.readUInt16LE(6) & 0x3fff, data.readUInt16LE(8) & 0x3fff, 'WebP'); sawPrimary = true;
    } else if (type === 'VP8L') {
      if (sawPrimary || animated || length < 5 || data[0] !== 0x2f || (data[4] & 0xe0) !== 0) fail('WebP VP8L payload');
      const packed = data.readUInt32LE(1);
      dimensions((packed & 0x3fff) + 1, ((packed >>> 14) & 0x3fff) + 1, 'WebP'); sawPrimary = true;
    } else if (type === 'ANIM') {
      if (!extended || !animated || length !== 6 || sawPrimary) fail('WebP animation header');
    } else if (type === 'ANMF') {
      if (!extended || !animated || length < 16) fail('WebP animation frame');
      sawPrimary = true;
    } else if (type === 'ALPH' && (!extended || sawPrimary || length < 1)) fail('WebP alpha chunk');
    offset = next; first = false;
  }
  if (offset !== bytes.length || !sawPrimary) fail('malformed WebP container');
}

export function validateImageAsset(bytes, contentType) {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes || []);
  if (contentType === TYPES.png) validatePng(bytes);
  else if (contentType === TYPES.jpg) validateJpeg(bytes);
  else if (contentType === TYPES.webp) validateWebp(bytes);
  else fail('unsupported media type');
  const marker = bytes.toString('latin1').toLowerCase();
  if (/<(?:script|svg|html|iframe|object|embed)\b|javascript\s*:/.test(marker)) fail('active-content polyglot');
  return true;
}

// Structural parsing deliberately runs first so metadata-bearing or unusual
// containers never reach a native codec. A full bounded raster decode then
// proves that the compressed payload is real, not merely well-framed bytes.
export async function validateDecodableImageAsset(bytes, contentType) {
  validateImageAsset(bytes, contentType);
  const input = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes || []);
  try {
    const decoded = await sharp(input, {
      failOn: 'warning',
      limitInputPixels: MAX_PIXELS,
      sequentialRead: true,
    }).raw().toBuffer({ resolveWithObject: true });
    const { width, height, channels, depth, size } = decoded.info || {};
    dimensions(width, height, 'decoded image');
    if (!Number.isSafeInteger(channels) || channels < 1 || channels > 4 || depth !== 'uchar' ||
        !Number.isSafeInteger(size) || size !== width * height * channels || decoded.data.length !== size || size > MAX_PIXELS * 4) {
      fail('decoded raster shape');
    }
  } catch (error) {
    if (error instanceof TypeError && /^Image asset is invalid:/.test(error.message)) throw error;
    fail('compressed raster does not fully decode');
  }
  return true;
}

export function imageTypeForPath(path) {
  const extension = String(path).match(/\.([a-z]+)$/)?.[1] || '';
  return TYPES[extension] || '';
}
