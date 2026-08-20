import assert from 'node:assert/strict';
import { canonicalJson, hmacHex, sha256Hex, validateExpectedBindings } from '../netlify/lib/arc2-handoff-core.mjs';
import { createEntry, readEntry } from '../netlify/lib/arc2-handoff-store.mjs';
import {
  exchangeClaimBearer,
  getHandoffStatus,
  leadRouteReceiptContract,
  markClaimInvitationReady,
  renewClaimInvitation,
} from '../netlify/lib/arc2-handoff-service.mjs';

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; }
  async getWithMetadata(key) {
    const entry = this.values.get(key);
    return entry ? { data: structuredClone(entry.data), etag: entry.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    const etag = `e-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
}

const now = new Date('2026-08-12T20:00:00.000Z');
const handoffId = 'a'.repeat(64);
const env = {
  ARC_CLAIM_TOKEN_SECRET: 'claim-token-secret-unique-0123456789abcdef',
  ARC_LEAD_ROUTE_EVIDENCE_SECRET: 'route-evidence-secret-unique-0123456789abcdef',
  ARC_EMAIL_CLAIM_BINDING_SECRET: 'email-binding-secret-unique-0123456789abcdef',
  NETLIFY_OAUTH_CLIENT_ID: 'oauth-client-123',
  NETLIFY_OAUTH_CLIENT_SECRET: 'oauth-client-secret-unique-0123456789abcdef',
  NETLIFY_ADMIN_PAT: 'netlify-admin-pat-unique-0123456789abcdef',
  NETLIFY_TEAM_ACCOUNT_ID: 'source-account-123',
  NETLIFY_TEAM_SLUG: 'arc-team',
  ARC_PUBLIC_ORIGIN: 'https://arcweb.onl/',
};
const record = {
  schema: 'arc2-netlify-handoff-v1', handoff_id: handoffId, state: 'PRECLAIM_DEPLOY_READY', revision: 8,
  created_at: now.toISOString(), updated_at: now.toISOString(),
  payment_evidence_sha256: '1'.repeat(64), artifact_evidence_sha256: '2'.repeat(64), artifact_manifest_sha256: '3'.repeat(64),
  bundle_fingerprint: '4'.repeat(64), production_content_sha256: '5'.repeat(64), customer_email_sha256: '6'.repeat(64),
  lead_notification_email_sha256: sha256Hex('leads@example.test'), preview_folder: 'sample-roofing-a1b2c3d4',
  lead_route_recipient_hmac_sha256: hmacHex(env.ARC_LEAD_ROUTE_EVIDENCE_SECRET, 'arc-lead-route-recipient-v1\nleads@example.test'),
  artifacts: [{ path: '_headers', sha256: '7'.repeat(64), size: 10 }, { path: 'index.html', sha256: '8'.repeat(64), size: 20 }],
  form_name: 'sample-lead', netlify_session_id: '11111111-1111-4111-8111-111111111111',
  netlify_site_name: 'arc-lead-route-' + 'b'.repeat(24), netlify_source_account_id: 'source-account-123', netlify_site_id: 'c'.repeat(24),
  site_created_at: now.toISOString(), preclaim_deploy_id: 'd'.repeat(24), final_deploy_id: null,
  preclaim_deploy_attempted_at: now.toISOString(), preclaim_deploy_candidate_id: 'd'.repeat(24),
  final_deploy_attempted_at: null, final_deploy_candidate_id: null, email_hook_attempted_at: now.toISOString(),
  form_id: 'e'.repeat(24), hook_id: 'f'.repeat(24), destination_account_id: null,
  lead_route_receipt_sha256: null, claim_token_hmac_sha256: null, claim_token_consumed_hmac_sha256: null,
  claim_token_expires_at: null, claim_token_used_at: null, claim_wrapper_consumed_at: null,
  claim_jwt_issued_at: null, claim_invitation_ready_at: null, lead_route_provider_message_id_sha256: null,
  claim_callback_received_at: null, claimed_verified_at: null, final_deploy_ready_at: null, production_url: null,
  outbox_claim_status: null, outbox_claim_key_hmac_sha256: null,
  final_delivery_receipt_sha256: null, final_delivery_provider_message_id_sha256: null,
  final_delivery_receipt_issued_at: null, delivered_at: null,
};

const producerEvidenceValue = {
  version: leadRouteReceiptContract.producerVersion,
  scope: leadRouteReceiptContract.producerScope,
  preview_folder: record.preview_folder,
  production_content_sha256: record.production_content_sha256,
  artifact_manifest_sha256: record.artifact_manifest_sha256,
  handoff_artifact_evidence_sha256: record.artifact_evidence_sha256,
  bundle_fingerprint: record.bundle_fingerprint,
  netlify_account_id: record.netlify_source_account_id,
  staging_site_id: record.netlify_site_id,
  staging_site_url: `https://${record.netlify_site_name}.netlify.app/`,
  staging_deploy_id: record.preclaim_deploy_id,
  staging_deploy_url: `https://${record.preclaim_deploy_id}--${record.netlify_site_name}.netlify.app/`,
  deploy_file_manifest_sha256: sha256Hex('producer-deploy-file-manifest'),
  served_html_sha256: sha256Hex('producer-served-html'),
  staging_robots_header_sha256: sha256Hex('producer-staging-robots-header'),
  staging_form_id: record.form_id,
  notification_hook_id: record.hook_id,
  form_name: record.form_name,
  recipient_hmac_sha256: record.lead_route_recipient_hmac_sha256,
  synthetic_submission_id: '9'.repeat(24),
  synthetic_probe_sha256: sha256Hex('producer-synthetic-probe'),
  netlify_submission_timestamp: new Date(now.getTime() - 60_000).toISOString(),
  inbox_provider: 'gmail',
  inbox_account_hmac_sha256: sha256Hex('producer-inbox-account'),
  inbox_message_id_hmac_sha256: sha256Hex('producer-inbox-message'),
  inbox_received_timestamp: new Date(now.getTime() - 30_000).toISOString(),
  inbox_receipt_evidence_sha256: sha256Hex('producer-inbox-receipt-evidence'),
};
const signProducerEvidence = (raw) => hmacHex(
  env.ARC_LEAD_ROUTE_EVIDENCE_SECRET,
  `${leadRouteReceiptContract.producerSignaturePrefix}${raw}`,
);
const producerEvidence = JSON.stringify(producerEvidenceValue);
const producerSignature = signProducerEvidence(producerEvidence);

const legacyPreclaimRecord = {
  ...record,
  netlify_site_name: `arc-${'b'.repeat(24)}`,
};
delete legacyPreclaimRecord.lead_route_recipient_hmac_sha256;
const legacyPreclaimStore = new FakeStore();
await createEntry(legacyPreclaimStore, `handoffs/${handoffId}`, legacyPreclaimRecord);
const migratedLegacyPreclaim = await readEntry(legacyPreclaimStore, `handoffs/${handoffId}`);
assert.equal(migratedLegacyPreclaim.record.schema, 'arc2-netlify-handoff-v2');
assert.equal(migratedLegacyPreclaim.record.netlify_site_name, `arc-${'b'.repeat(24)}`);
assert.equal(migratedLegacyPreclaim.record.lead_route_recipient_hmac_sha256, null);
const legacyProducerEvidenceValue = {
  ...producerEvidenceValue,
  staging_site_url: `https://${legacyPreclaimRecord.netlify_site_name}.netlify.app/`,
  staging_deploy_url: `https://${record.preclaim_deploy_id}--${legacyPreclaimRecord.netlify_site_name}.netlify.app/`,
};
const legacyProducerEvidence = JSON.stringify(legacyProducerEvidenceValue);
const legacyPreclaimSnapshot = JSON.stringify([...legacyPreclaimStore.values.entries()]);
await assert.rejects(markClaimInvitationReady(
  handoffId,
  legacyProducerEvidence,
  signProducerEvidence(legacyProducerEvidence),
  env,
  { store: legacyPreclaimStore, clock: () => new Date(now) },
), /ARC2_LEGACY_SITE_NAMESPACE_QUARANTINED/,
'Even exact signed producer evidence must not advance an old-namespace pre-invitation record.');
await assert.rejects(markClaimInvitationReady(
  handoffId,
  'not-json',
  'not-a-signature',
  env,
  { store: legacyPreclaimStore, clock: () => new Date(now) },
), /ARC2_LEGACY_SITE_NAMESPACE_QUARANTINED/,
'Old-namespace quarantine must run before invitation evidence parsing or signature verification.');
assert.equal(JSON.stringify([...legacyPreclaimStore.values.entries()]), legacyPreclaimSnapshot,
  'Rejected invitation evidence must not mutate a quarantined legacy record or create an outbox.');

const producerStore = new FakeStore();
await createEntry(producerStore, `handoffs/${handoffId}`, record);
const producerIssued = await markClaimInvitationReady(handoffId, producerEvidence, producerSignature, env, {
  store: producerStore, clock: () => new Date(now),
});
assert.equal(producerIssued.record.state, 'INVITATION_READY');
assert.equal(producerIssued.record.lead_route_receipt_sha256, sha256Hex(producerEvidence), 'Receipt digest must bind the exact signed producer source.');
assert.equal(producerIssued.record.lead_route_provider_message_id_sha256, sha256Hex(producerEvidenceValue.inbox_message_id_hmac_sha256));
const producerReplay = await markClaimInvitationReady(handoffId, producerEvidence, producerSignature, env, {
  store: producerStore, clock: () => new Date(now.getTime() + 11 * 60_000),
});
assert.equal(producerReplay.claimBearer, producerIssued.claimBearer, 'Exact producer evidence must remain resumable after first-observation freshness.');

const staleProducerStore = new FakeStore();
await createEntry(staleProducerStore, `handoffs/${handoffId}`, record);
await assert.rejects(markClaimInvitationReady(handoffId, producerEvidence, producerSignature, env, {
  store: staleProducerStore, clock: () => new Date(now.getTime() + 11 * 60_000),
}), /stale or out of order/i, 'Stale producer evidence must not authorize a first invitation.');
const mismatchedProducerValue = { ...producerEvidenceValue, staging_form_id: 'a'.repeat(24) };
const mismatchedProducerEvidence = JSON.stringify(mismatchedProducerValue);
const mismatchedProducerStore = new FakeStore();
await createEntry(mismatchedProducerStore, `handoffs/${handoffId}`, record);
await assert.rejects(markClaimInvitationReady(handoffId, mismatchedProducerEvidence, signProducerEvidence(mismatchedProducerEvidence), env, {
  store: mismatchedProducerStore, clock: () => new Date(now),
}), /binding mismatch/i, 'A validly signed producer receipt for another form must fail its durable source binding.');
const badSignatureProducerStore = new FakeStore();
await createEntry(badSignatureProducerStore, `handoffs/${handoffId}`, record);
await assert.rejects(markClaimInvitationReady(handoffId, producerEvidence, '0'.repeat(64), env, {
  store: badSignatureProducerStore, clock: () => new Date(now),
}), /signature mismatch/i);
const reorderedProducerEvidence = canonicalJson(producerEvidenceValue);
const reorderedProducerStore = new FakeStore();
await createEntry(reorderedProducerStore, `handoffs/${handoffId}`, record);
await assert.rejects(markClaimInvitationReady(handoffId, reorderedProducerEvidence, signProducerEvidence(reorderedProducerEvidence), env, {
  store: reorderedProducerStore, clock: () => new Date(now),
}), /fields are invalid/i, 'Producer evidence must retain its exact signed field order and serialization.');
const outOfOrderProducerValue = {
  ...producerEvidenceValue,
  inbox_received_timestamp: new Date(now.getTime() - 90_000).toISOString(),
};
const outOfOrderProducerEvidence = JSON.stringify(outOfOrderProducerValue);
const outOfOrderProducerStore = new FakeStore();
await createEntry(outOfOrderProducerStore, `handoffs/${handoffId}`, record);
await assert.rejects(markClaimInvitationReady(handoffId, outOfOrderProducerEvidence, signProducerEvidence(outOfOrderProducerEvidence), env, {
  store: outOfOrderProducerStore, clock: () => new Date(now),
}), /stale or out of order/i, 'Inbox receipt time must not precede the Netlify submission.');

const store = new FakeStore();
await createEntry(store, `handoffs/${handoffId}`, record);

const evidenceValue = {
  version: leadRouteReceiptContract.version,
  scope: leadRouteReceiptContract.scope,
  handoff_id: handoffId,
  netlify_site_id_sha256: sha256Hex(record.netlify_site_id),
  form_id_sha256: sha256Hex(record.form_id),
  hook_id_sha256: sha256Hex(record.hook_id),
  recipient_email_sha256: record.lead_notification_email_sha256,
  provider_message_id_sha256: sha256Hex('provider-message'),
  inbox_receipt_id_sha256: sha256Hex('inbox-receipt'),
  received_at: new Date(now.getTime() - 30_000).toISOString(),
  issued_at: now.toISOString(),
};
const evidence = canonicalJson(evidenceValue);
const signature = hmacHex(env.ARC_LEAD_ROUTE_EVIDENCE_SECRET, `${leadRouteReceiptContract.signaturePrefix}${evidence}`);
const adapters = { store, clock: () => new Date(now) };
const issued = await markClaimInvitationReady(handoffId, evidence, signature, env, adapters);
assert.equal(issued.record.state, 'INVITATION_READY');
assert.equal(issued.record.revision, 9, 'Receipt binding and invitation readiness must be one atomic record transition.');
assert.match(issued.claimBearer, /^[A-Za-z0-9_-]{43}$/);
assert.equal(JSON.stringify([...store.values.values()]).includes(issued.claimBearer), false, 'Raw claim bearer must not be durable state.');
const replay = await markClaimInvitationReady(handoffId, evidence, signature, env, adapters);
assert.equal(replay.claimBearer, issued.claimBearer, 'Lost invitation response must recover the same bearer.');
const elevenMinuteReplay = await markClaimInvitationReady(handoffId, evidence, signature, env, {
  ...adapters, clock: () => new Date(now.getTime() + 11 * 60_000),
});
assert.equal(elevenMinuteReplay.claimBearer, issued.claimBearer, 'READY recovery must not re-apply receipt issuance freshness.');
const twentyNineMinuteReplay = await markClaimInvitationReady(handoffId, evidence, signature, env, {
  ...adapters, clock: () => new Date(now.getTime() + 29 * 60_000),
});
assert.equal(twentyNineMinuteReplay.claimBearer, issued.claimBearer, 'READY recovery must recover the original bearer through its TTL.');

const legacyInvitationStore = new FakeStore();
const legacyInvitationRecord = {
  ...issued.record,
  schema: 'arc2-netlify-handoff-v1',
  netlify_site_name: `arc-${'c'.repeat(24)}`,
};
delete legacyInvitationRecord.lead_route_recipient_hmac_sha256;
for (const field of [
  'final_delivery_receipt_sha256',
  'final_delivery_provider',
  'final_delivery_provider_account_hmac_sha256',
  'final_delivery_provider_event_id_hmac_sha256',
  'final_delivery_provider_message_id_hmac_sha256',
  'final_delivery_event_type',
  'final_delivery_status',
  'final_delivery_receipt_issued_at',
]) delete legacyInvitationRecord[field];
await createEntry(legacyInvitationStore, `handoffs/${handoffId}`, legacyInvitationRecord);
const legacyInvitationStatus = await getHandoffStatus(handoffId, env, {
  store: legacyInvitationStore,
  clock: () => new Date(now.getTime() + 60_000),
});
assert.equal(legacyInvitationStatus.claim_available, true,
  'An old-namespace record already at INVITATION_READY must remain available for downstream migration.');
const legacyExchanged = await exchangeClaimBearer(handoffId, issued.claimBearer, env, {
  store: legacyInvitationStore,
  clock: () => new Date(now.getTime() + 60_000),
});
assert.equal(legacyExchanged.record.state, 'CLAIM_WRAPPER_CONSUMED');
assert.equal(legacyExchanged.record.schema, 'arc2-netlify-handoff-v2');
assert.equal(legacyExchanged.record.netlify_site_name, `arc-${'c'.repeat(24)}`,
  'Downstream migration must preserve the already-created legacy Netlify site name.');

const renewalStore = new FakeStore();
renewalStore.values = new Map([...store.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
renewalStore.sequence = store.sequence;
const renewed = await markClaimInvitationReady(handoffId, evidence, signature, env, {
  store: renewalStore, clock: () => new Date(now.getTime() + 30 * 60_000),
});
assert.notEqual(renewed.claimBearer, issued.claimBearer, 'An expired unconsumed invitation must rotate to a new bearer.');
assert.equal(renewed.record.claim_invitation_generation, issued.record.claim_invitation_generation + 1);
await assert.rejects(exchangeClaimBearer(handoffId, issued.claimBearer, env, {
  store: renewalStore, clock: () => new Date(now.getTime() + 30 * 60_000 + 1000),
}), /BEARER_INVALID/, 'Invitation rotation must invalidate the superseded bearer.');
const renewedReplay = await markClaimInvitationReady(handoffId, evidence, signature, env, {
  store: renewalStore, clock: () => new Date(now.getTime() + 30 * 60_000 + 1000),
});
assert.equal(renewedReplay.claimBearer, renewed.claimBearer, 'Lost renewal response must recover the current generation.');
assert.equal((await getHandoffStatus(handoffId, env, adapters)).claim_available, true);

const exchanged = await exchangeClaimBearer(handoffId, issued.claimBearer, env, adapters);
assert.match(exchanged.claimUrl, /^https:\/\/app\.netlify\.com\/claim#[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
const exchangeReplay = await exchangeClaimBearer(handoffId, issued.claimBearer, env, adapters);
assert.equal(exchangeReplay.claimUrl, exchanged.claimUrl, 'Lost exchange response must recover the same official JWT fragment URL.');
await assert.rejects(exchangeClaimBearer(handoffId, 'z'.repeat(43), env, adapters), /BEARER_INVALID/);
const stored = await readEntry(store, `handoffs/${handoffId}`);
assert.equal(stored.record.state, 'CLAIM_WRAPPER_CONSUMED');
assert.equal(stored.record.claim_token_hmac_sha256, null);
assert.equal(JSON.stringify([...store.values.values()]).includes(issued.claimBearer), false);
assert.equal((await getHandoffStatus(handoffId, env, adapters)).claim_available, false);
const consumedReceiptReplay = await markClaimInvitationReady(handoffId, evidence, signature, env, {
  ...adapters, clock: () => new Date(now.getTime() + 11 * 60_000),
});
assert.equal(consumedReceiptReplay.alreadyConsumed, true, 'Exact receipt replay after exchange must remain stable without refreshing issuance.');
assert.equal(consumedReceiptReplay.claimBearer, null);
const consumedSnapshot = new Map([...store.values.entries()].map(([key, value]) => [key, structuredClone(value)]));
const sourceOwnedSiteResponse = () => new Response(JSON.stringify({
  id: record.netlify_site_id,
  name: record.netlify_site_name,
  session_id: record.netlify_session_id,
  account_id: record.netlify_source_account_id,
  account_slug: env.NETLIFY_TEAM_SLUG,
}), { headers: { 'content-type': 'application/json' } });
const abandonedStore = new FakeStore();
abandonedStore.values = new Map([...consumedSnapshot.entries()].map(([key, value]) => [key, structuredClone(value)]));
abandonedStore.sequence = store.sequence;
const renewalTime = new Date(Date.parse(issued.record.claim_token_expires_at) + 1);
const [abandonedRenewed, abandonedRaced] = await Promise.all([
  renewClaimInvitation(handoffId, env, { store: abandonedStore, clock: () => renewalTime, fetch: sourceOwnedSiteResponse }),
  renewClaimInvitation(handoffId, env, { store: abandonedStore, clock: () => renewalTime, fetch: sourceOwnedSiteResponse }),
]);
assert.equal(abandonedRenewed.claimBearer, abandonedRaced.claimBearer,
  'Concurrent abandoned-wrapper renewal must converge on one current generation.');
assert.equal(abandonedRenewed.record.state, 'INVITATION_READY');
assert.equal(abandonedRenewed.record.claim_invitation_generation, issued.record.claim_invitation_generation + 1);
await assert.rejects(exchangeClaimBearer(handoffId, issued.claimBearer, env, {
  store: abandonedStore, clock: () => new Date(renewalTime.getTime() + 1),
}), /BEARER_INVALID/, 'Abandoned-wrapper renewal must invalidate the prior bearer and JWT authority.');
const abandonedExchange = await exchangeClaimBearer(handoffId, abandonedRenewed.claimBearer, env, {
  store: abandonedStore, clock: () => new Date(renewalTime.getTime() + 1),
});
assert.equal(abandonedExchange.record.state, 'CLAIM_WRAPPER_CONSUMED');

const claimedProviderStore = new FakeStore();
claimedProviderStore.values = new Map([...consumedSnapshot.entries()].map(([key, value]) => [key, structuredClone(value)]));
claimedProviderStore.sequence = store.sequence;
const claimedSnapshot = JSON.stringify([...claimedProviderStore.values.entries()]);
await assert.rejects(renewClaimInvitation(handoffId, env, {
  store: claimedProviderStore,
  clock: () => renewalTime,
  fetch: async () => new Response(JSON.stringify({
    id: record.netlify_site_id,
    name: record.netlify_site_name,
    session_id: record.netlify_session_id,
    account_id: 'destination-account-456',
    account_slug: 'customer-team',
  }), { headers: { 'content-type': 'application/json' } }),
}), /SOURCE_ACCOUNT_MISMATCH/, 'A provider-claimed destination must never receive a replacement invitation.');
assert.equal(JSON.stringify([...claimedProviderStore.values.entries()]), claimedSnapshot,
  'Rejected post-claim renewal must not mutate state or invitation authority.');
const boundaryStore = new FakeStore();
await createEntry(boundaryStore, `handoffs/${handoffId}`, record);
const boundaryIssued = await markClaimInvitationReady(handoffId, evidence, signature, env, { store: boundaryStore, clock: () => new Date(now) });
await assert.rejects(exchangeClaimBearer(handoffId, boundaryIssued.claimBearer, env, {
  store: boundaryStore, clock: () => new Date(now.getTime() + 30 * 60_000 - 999),
}), /BEARER_INVALID/, 'Sub-second expiry boundary must fail before consuming state.');
assert.equal((await readEntry(boundaryStore, `handoffs/${handoffId}`)).record.state, 'INVITATION_READY');
assert.throws(() => validateExpectedBindings({ ...stored.record, claim_jwt_issued_at: 0 }), /claim_jwt_issued_at/);
assert.throws(() => validateExpectedBindings({ ...stored.record, destination_account_id: 'customer-account-123' }), /must be null/);
assert.throws(() => validateExpectedBindings({ ...stored.record, outbox_claim_status: 'CLAIMED' }), /outbox must be null/i);

console.log('ARC2 resumable claim service contract passed.');
