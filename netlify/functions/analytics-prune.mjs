import { getStore } from '@netlify/blobs';
import { ANALYTICS_STORE, expirationTimestamp, isExpiredMetadata } from '../lib/analytics-core.mjs';

async function shouldDelete(store, key, metadata, now) {
  if (isExpiredMetadata(metadata, now)) return true;
  if (Number.isFinite(Number(metadata?.expires_at))) return false;
  const event = await store.get(key, { consistency: 'strong', type: 'json' });
  try {
    return event ? expirationTimestamp(event.received_at) <= now.getTime() : false;
  } catch {
    return false;
  }
}

export default async () => {
  if (process.env.ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED !== 'true') return;
  const store = getStore({ name: ANALYTICS_STORE, consistency: 'strong' });
  const { blobs } = await store.list({ prefix: 'events/' });
  const now = new Date();
  for (let index = 0; index < blobs.length; index += 25) {
    const batch = blobs.slice(index, index + 25);
    const metadata = await Promise.all(batch.map(({ key }) => store.getMetadata(key, { consistency: 'strong' })));
    const deletions = await Promise.all(batch.map(({ key }, itemIndex) => shouldDelete(store, key, metadata[itemIndex]?.metadata, now)));
    await Promise.all(batch.map(({ key }, itemIndex) => deletions[itemIndex] ? store.delete(key) : null));
  }
};
