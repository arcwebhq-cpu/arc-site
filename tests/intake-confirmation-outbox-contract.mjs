import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import {
  config as claimConfig,
  createIntakeConfirmationClaimHandler,
} from '../netlify/functions/intake-confirmation-claim.mjs';
import {
  config as completeConfig,
  createIntakeConfirmationCompletionHandler,
} from '../netlify/functions/intake-confirmation-complete.mjs';
import {
  INTAKE_CONFIRMATION_CLAIM_REQUEST_SCHEMA,
  INTAKE_CONFIRMATION_COMPLETION_REQUEST_SCHEMA,
  claimIntakeConfirmationOutbox,
  completeIntakeConfirmationOutbox,
  intakeConfirmationRuntimeConfigured,
  reserveIntakeConfirmationOutbox,
  validateIntakeConfirmationOutbox,
} from '../netlify/lib/intake-confirmation-outbox-core.mjs';
import { canonicalJson } from '../netlify/lib/intake-arc1-bridge-core.mjs';
import { INTAKE_SUBMISSION_SCHEMA } from '../netlify/lib/intake-submission-core.mjs';
import { reserveIntakeEmailVerification } from '../netlify/lib/intake-email-verification-core.mjs';
import { testActivationAuthority } from './helpers/activation-authority.mjs';

const claimHandler = createIntakeConfirmationClaimHandler();
const completeHandler = createIntakeConfirmationCompletionHandler();

class FakeStore {
  constructor() { this.values = new Map(); this.sequence = 0; this.throwAfterWritePrefix = null; }
  async getWithMetadata(key) {
    const item = this.values.get(key);
    return item ? { data: structuredClone(item.data), etag: item.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && current?.etag !== options.onlyIfMatch) return { modified: false };
    if (options.onlyIfMatch && !current) return { modified: false };
    const etag = `etag-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    if (this.throwAfterWritePrefix && key.startsWith(this.throwAfterWritePrefix)) {
      this.throwAfterWritePrefix = null;
      throw new Error('synthetic ambiguous Blob write');
    }
    return { modified: true, etag };
  }
  async delete(key) { this.values.delete(key); }
}

const now = new Date();
const env = {
  ...testActivationAuthority(now),
  URL: 'https://arcweb.onl',
  ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED: 'true',
  ARC_INTAKE_CONFIRMATION_CONSUMER_ENABLED: 'true',
  ARC_INTAKE_CONFIRMATION_OUTBOX_SECRET: 'confirmation-outbox-secret-unique-0123456789',
  ARC_INTAKE_CONFIRMATION_CONSUMER_BEARER: 'confirmation-consumer-bearer-unique-01234567',
  ARC_INTAKE_CONFIRMATION_RECEIPT_SECRET: 'confirmation-receipt-secret-unique-012345678',
  ARC_INTAKE_EMAIL_VERIFICATION_ENABLED: 'true',
  ARC_INTAKE_EMAIL_VERIFICATION_STATE_SECRET: 'verification-state-secret-unique-0123456789',
  ARC_INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET: 'verification-token-secret-unique-0123456789',
  ARC_INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET: 'verification-recipient-secret-unique-012345',
  ARC_INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET: 'verification-release-secret-unique-01234567',
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY: 'ERERERERERERERERERERERERERERERERERERERERERE',
  ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET: 'confirmation-vault-hmac-secret-unique-012345',
};
assert.equal(intakeConfirmationRuntimeConfigured(env), true);
for (const credentialName of [
  'ARC_INTAKE_CONFIRMATION_OUTBOX_SECRET',
  'ARC_INTAKE_CONFIRMATION_CONSUMER_BEARER',
  'ARC_INTAKE_CONFIRMATION_RECEIPT_SECRET',
]) {
  assert.equal(intakeConfirmationRuntimeConfigured({
    ...env,
    ARC_ROTATED_CREDENTIAL_V2: env[credentialName],
  }), false, `An arbitrary alias must not reuse ${credentialName}.`);
}
const sourceRecord = {
  schema: INTAKE_SUBMISSION_SCHEMA,
  submission_id: '11111111-1111-4111-8111-111111111111',
  submission_data_sha256: createHash('sha256').update('immutable-intake').digest('hex'),
  data: { email: 'owner@example.test' },
};

const store = new FakeStore();
const intakeStore = new FakeStore();
const vaultStore = new FakeStore();
const verification = await reserveIntakeEmailVerification(sourceRecord, env, intakeStore, { clock: () => now });
const reserved = await reserveIntakeConfirmationOutbox(sourceRecord, env, store, {
  clock: () => now, vaultStore, verification,
});
assert.equal(reserved.created, true);
assert.equal(reserved.state, 'PENDING');
assert.match(reserved.outboxId, /^arcconfirm_[a-f0-9]{40}$/);
const outboxKey = [...store.values.keys()].find((key) => key.startsWith('outbox/'));
const pendingKey = [...store.values.keys()].find((key) => key.startsWith('pending/'));
assert.ok(outboxKey && pendingKey, 'The accepted reservation requires both durable outbox and recovery visibility.');
const initial = validateIntakeConfirmationOutbox(store.values.get(outboxKey).data);
assert.equal(JSON.stringify(initial).includes('owner@example.test'), false);
assert.equal(initial.recipient_identity_hmac_sha256, verification.recipient_identity_hmac_sha256);
assert.equal(initial.message.subject, 'Confirm your email to start your free preview');
assert.match(initial.message.text, /No payment is due unless you approve it/);
assert.equal(JSON.stringify(initial).includes('provider-message'), false);

const replay = await reserveIntakeConfirmationOutbox(sourceRecord, env, store, {
  clock: () => new Date(now.getTime() + 5_000), vaultStore, verification,
});
assert.deepEqual(replay, { ...reserved, created: false });
assert.equal([...store.values.keys()].filter((key) => key.startsWith('outbox/')).length, 1);

const ambiguousStore = new FakeStore();
ambiguousStore.throwAfterWritePrefix = 'outbox/';
const ambiguous = await reserveIntakeConfirmationOutbox(sourceRecord, env, ambiguousStore, {
  clock: () => now, vaultStore, verification,
});
assert.equal(ambiguous.state, 'PENDING', 'A strong read recovers an ambiguous create-only outbox write.');
assert.ok([...ambiguousStore.values.keys()].some((key) => key.startsWith('pending/')));

await assert.rejects(reserveIntakeConfirmationOutbox(sourceRecord, {
  ...env, ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED: 'false',
}, new Proxy({}, { get() { throw new Error('Disabled producer touched Blob state.'); } }), {
  vaultStore, verification,
}), /CONFIRMATION_DISABLED/);

const attemptId = `arcconfirmattempt_${'a'.repeat(40)}`;
const claimBody = canonicalJson({
  schema: INTAKE_CONFIRMATION_CLAIM_REQUEST_SCHEMA,
  submission_id: sourceRecord.submission_id,
  outbox_id: reserved.outboxId,
  consumer_attempt_id: attemptId,
});
const claimHeaders = {
  authorization: `Bearer ${env.ARC_INTAKE_CONFIRMATION_CONSUMER_BEARER}`,
  'content-type': 'application/json',
  'idempotency-key': `arcconfirmclaim_${createHash('sha256').update(claimBody).digest('hex').slice(0, 40)}`,
};
const claimRequest = () => new Request('https://arcweb.onl/internal/intake/confirmation/claim', {
  method: 'POST', headers: claimHeaders, body: claimBody,
});
const claim = await claimIntakeConfirmationOutbox(claimBody, claimRequest(), env, store, {
  clock: () => new Date(now.getTime() + 10_000),
});
assert.equal(claim.status, 'CLAIMED');
assert.equal(claim.idempotent_replay, false);
assert.equal(claim.provider_idempotency_key, reserved.outboxId);
assert.equal(JSON.stringify(claim).includes(sourceRecord.data.email), false);
assert.equal(claim.recipient_vault_hmac_sha256, initial.recipient_vault_hmac_sha256);
assert.doesNotMatch(JSON.stringify(store.values.get(outboxKey).data), new RegExp(claim.claim_token),
  'The provider claim token must never be stored in plaintext.');
const claimReplay = await claimIntakeConfirmationOutbox(claimBody, claimRequest(), env, store, {
  clock: () => new Date(now.getTime() + 20_000),
});
assert.deepEqual(claimReplay, { ...claim, idempotent_replay: true });

const competingBody = canonicalJson({ ...JSON.parse(claimBody), consumer_attempt_id: `arcconfirmattempt_${'b'.repeat(40)}` });
const competingRequest = new Request('https://arcweb.onl/internal/intake/confirmation/claim', {
  method: 'POST', headers: {
    ...claimHeaders,
    'idempotency-key': `arcconfirmclaim_${createHash('sha256').update(competingBody).digest('hex').slice(0, 40)}`,
  }, body: competingBody,
});
await assert.rejects(claimIntakeConfirmationOutbox(competingBody, competingRequest, env, store), /CLAIM_CONFLICT/);

const sentAt = new Date(now.getTime() + 30_000).toISOString();
const completionBody = canonicalJson({
  schema: INTAKE_CONFIRMATION_COMPLETION_REQUEST_SCHEMA,
  submission_id: sourceRecord.submission_id,
  outbox_id: reserved.outboxId,
  consumer_attempt_id: attemptId,
  claim_token: claim.claim_token,
  provider: 'provider_test',
  provider_message_id: 'provider-message-id-private',
  sent_at: sentAt,
});
const receiptSha = createHash('sha256').update(completionBody).digest('hex');
const receiptHmac = createHmac('sha256', env.ARC_INTAKE_CONFIRMATION_RECEIPT_SECRET)
  .update(`arc-intake-confirmation-completion-v1\n${completionBody}`).digest('hex');
const completionRequest = () => new Request('https://arcweb.onl/internal/intake/confirmation/complete', {
  method: 'POST', headers: {
    authorization: `Bearer ${env.ARC_INTAKE_CONFIRMATION_CONSUMER_BEARER}`,
    'content-type': 'application/json',
    'idempotency-key': `arcconfirmcomplete_${receiptSha.slice(0, 40)}`,
    'x-arc-intake-confirmation-receipt-hmac-sha256': receiptHmac,
  }, body: completionBody,
});
const completed = await completeIntakeConfirmationOutbox(completionBody, completionRequest(), env, store, {
  clock: () => new Date(now.getTime() + 31_000),
});
assert.equal(completed.status, 'PROVIDER_ACCEPTED');
assert.equal(completed.idempotent_replay, false);
assert.equal(store.values.has(pendingKey), false, 'Provider acceptance is the durable no-resend latch.');
const terminal = validateIntakeConfirmationOutbox(store.values.get(outboxKey).data);
assert.equal(terminal.provider, 'provider_test');
assert.equal(JSON.stringify(terminal).includes('provider-message-id-private'), false,
  'Only the provider message identity digest may be retained.');
assert.deepEqual(await completeIntakeConfirmationOutbox(completionBody, completionRequest(), env, store), {
  ...completed, idempotent_replay: true,
});

const staleStore = new FakeStore();
const staleIntakeStore = new FakeStore();
const staleVaultStore = new FakeStore();
const staleSource = {
  ...sourceRecord,
  submission_id: '22222222-2222-4222-8222-222222222222',
  submission_data_sha256: createHash('sha256').update('stale-intake').digest('hex'),
};
const staleVerification = await reserveIntakeEmailVerification(staleSource, env, staleIntakeStore, { clock: () => now });
const staleReserved = await reserveIntakeConfirmationOutbox(staleSource, env, staleStore, {
  clock: () => now, vaultStore: staleVaultStore, verification: staleVerification,
});
const staleBody = canonicalJson({
  schema: INTAKE_CONFIRMATION_CLAIM_REQUEST_SCHEMA,
  submission_id: staleSource.submission_id,
  outbox_id: staleReserved.outboxId,
  consumer_attempt_id: attemptId,
});
const staleRequest = () => new Request('https://arcweb.onl/internal/intake/confirmation/claim', {
  method: 'POST', headers: {
    ...claimHeaders,
    'idempotency-key': `arcconfirmclaim_${createHash('sha256').update(staleBody).digest('hex').slice(0, 40)}`,
  }, body: staleBody,
});
const staleClaim = await claimIntakeConfirmationOutbox(staleBody, staleRequest(), env, staleStore, {
  clock: () => new Date(now.getTime() + 40_000),
});
await assert.rejects(claimIntakeConfirmationOutbox(staleBody, staleRequest(), env, staleStore, {
  clock: () => new Date(Date.parse(staleClaim.claim_expires_at) + 1),
}), /REVIEW_REQUIRED/);
const staleOutbox = [...staleStore.values.values()].find((item) => item.data?.schema === 'arc-intake-confirmation-outbox-v1').data;
assert.equal(staleOutbox.status, 'REVIEW_REQUIRED');
assert.equal(staleOutbox.review_code, 'CLAIM_EXPIRED');
assert.equal([...staleStore.values.keys()].some((key) => key.startsWith('pending/')), false);

const savedEnvironment = { ...process.env };
try {
  Object.assign(process.env, env);
  process.env.ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED = 'false';
  assert.equal((await claimHandler(claimRequest(), {
    get confirmationStore() { throw new Error('Disabled claim touched Blob state.'); },
  })).status, 503);
  assert.equal((await completeHandler(completionRequest(), {
    get confirmationStore() { throw new Error('Disabled completion touched Blob state.'); },
  })).status, 503);
  process.env.ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED = 'true';
  assert.equal((await claimHandler(new Request('https://arcweb.onl/internal/intake/confirmation/claim', {
    method: 'POST', headers: { ...claimHeaders, authorization: 'Bearer wrong-but-long-enough-token-value' }, body: claimBody,
  }), { confirmationStore: store })).status, 401);
} finally {
  for (const key of Object.keys(process.env)) if (!(key in savedEnvironment)) delete process.env[key];
  Object.assign(process.env, savedEnvironment);
}

assert.equal(claimConfig.path, '/internal/intake/confirmation/claim');
assert.equal(claimConfig.method, 'POST');
assert.equal(completeConfig.path, '/internal/intake/confirmation/complete');
assert.equal(completeConfig.method, 'POST');

console.log('ARC intake confirmation durable provider-neutral outbox contract passed.');
