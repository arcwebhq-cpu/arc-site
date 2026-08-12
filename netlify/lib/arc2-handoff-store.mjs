import { validateExpectedBindings } from './arc2-handoff-core.mjs';

export async function readEntry(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  if (!entry) return null;
  return { record: validateExpectedBindings(entry.data), etag: entry.etag };
}

export async function createEntry(store, key, value) {
  const result = await store.setJSON(key, value, { onlyIfNew: true });
  if (!result?.modified || !result.etag) return null;
  return { record: value, etag: result.etag };
}

export async function replaceEntry(store, key, entry, value) {
  if (!entry?.etag) throw new TypeError('CAS entry must include an ETag.');
  const result = await store.setJSON(key, value, { onlyIfMatch: entry.etag });
  if (!result?.modified || !result.etag) throw new Error('ARC2_STATE_CONTENTION');
  return { record: value, etag: result.etag };
}

export async function createIndex(store, key, value) {
  const result = await store.setJSON(key, value, { onlyIfNew: true });
  if (!result?.modified || !result.etag) throw new Error('ARC2_INDEX_CONFLICT');
  return { record: value, etag: result.etag };
}

export async function readIndex(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  return entry?.data || null;
}
