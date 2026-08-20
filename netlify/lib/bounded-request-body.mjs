export class RequestBodyTooLargeError extends RangeError {
  constructor() {
    super('Request body is too large.');
    this.name = 'RequestBodyTooLargeError';
  }
}

export async function readBoundedRequestText(request, maximumBytes) {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
    throw new TypeError('Request body limit is invalid.');
  }
  const declared = request.headers.get('content-length');
  if (declared !== null) {
    if (!/^\d{1,10}$/.test(declared)) throw new TypeError('Content-Length is invalid.');
    if (Number(declared) > maximumBytes) throw new RequestBodyTooLargeError();
  }
  const reader = request.body?.getReader?.();
  if (!reader) throw new TypeError('Request body is unavailable.');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new TypeError('Request body chunk is invalid.');
      total += value.byteLength;
      if (total > maximumBytes) {
        try { await reader.cancel(); } catch {}
        throw new RequestBodyTooLargeError();
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  return Buffer.concat(chunks, total).toString('utf8');
}
