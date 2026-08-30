import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { createResendWebhookHandler, config as webhookConfig } from '../netlify/functions/resend-webhook.mjs';
import { config as workerConfig } from '../netlify/functions/transactional-email-worker.mjs';
import {
  emailSendAttemptConfiguration,
  markEmailProviderAccepted,
  readEmailSendAttempt,
  reconcileEmailProviderEvent,
  reserveEmailSendAttempt,
} from '../netlify/lib/email-send-attempt-core.mjs';
import {
  emailRecipientVaultConfiguration,
  openEmailRecipientCapsule,
  sealEmailRecipientCapsule,
} from '../netlify/lib/email-recipient-vault-core.mjs';
import {
  reserveIntakeConfirmationOutbox,
} from '../netlify/lib/intake-confirmation-outbox-core.mjs';
import { reserveIntakeEmailVerification } from '../netlify/lib/intake-email-verification-core.mjs';
import { INTAKE_SUBMISSION_SCHEMA } from '../netlify/lib/intake-submission-core.mjs';
import {
  RESEND_RECONCILED_EVENT_TYPES,
  RESEND_FROM_IDENTITY,
  RESEND_REQUIRED_WEBHOOK_EVENT_TYPES,
  RESEND_SENDING_DOMAIN,
  RESEND_WEBHOOK_PATH,
  resendProviderConfiguration,
  sendResendTransactionalEmail,
  verifyAndNormalizeResendWebhook,
} from '../netlify/lib/resend-transactional-provider-core.mjs';
import { processResendWebhook } from '../netlify/lib/resend-webhook-core.mjs';
import { renderTransactionalEmail } from '../netlify/lib/transactional-email-template-core.mjs';
import { runTransactionalEmailWorkerCycle } from '../netlify/lib/transactional-email-worker-core.mjs';
import { testActivationAuthority } from './helpers/activation-authority.mjs';

class FakeStore {
  constructor() {
    this.values = new Map(); this.sequence = 0; this.failCompletionOnce = false; this.failProviderIndexOnce = false;
  }
  async getWithMetadata(key) {
    const item = this.values.get(key);
    return item ? { data: structuredClone(item.data), etag: item.etag } : null;
  }
  async setJSON(key, data, options = {}) {
    const current = this.values.get(key);
    if (options.onlyIfNew && current) return { modified: false };
    if (options.onlyIfMatch && (!current || current.etag !== options.onlyIfMatch)) return { modified: false };
    if (this.failCompletionOnce && key.startsWith('outbox/') &&
        data?.schema === 'arc-intake-confirmation-outbox-v1' && data.status === 'PROVIDER_ACCEPTED') {
      this.failCompletionOnce = false;
      throw new Error('synthetic crash before intake completion');
    }
    if (this.failProviderIndexOnce && key.startsWith('provider-messages/')) {
      this.failProviderIndexOnce = false;
      throw new Error('synthetic crash before provider acceptance latch');
    }
    const etag = `etag-${++this.sequence}`;
    this.values.set(key, { data: structuredClone(data), etag });
    return { modified: true, etag };
  }
  async delete(key) { this.values.delete(key); }
  async list(options = {}) {
    return { blobs: [...this.values.keys()].filter((key) => key.startsWith(options.prefix || ''))
      .sort().map((key) => ({ key })) };
  }
}

const now = new Date();
const signingBytes = Buffer.alloc(32, 7);
const env = {
  ...testActivationAuthority(now),
  URL: 'https://arcweb.onl',
  ARC_TRANSACTIONAL_EMAIL_ENABLED: 'true',
  ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET: 'transactional-attempt-secret-unique-0123456789',
  ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'true',
  ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY: Buffer.alloc(32, 11).toString('base64url'),
  ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET: 'recipient-vault-hmac-secret-unique-0123456789',
  ARC_RESEND_SEND_ENABLED: 'true',
  ARC_RESEND_WEBHOOK_ENABLED: 'true',
  ARC_RESEND_API_KEY: 're_0123456789abcdefghijklmnopqrstuvwxyz',
  ARC_RESEND_WEBHOOK_SECRET: `whsec_${signingBytes.toString('base64')}`,
  ARC_RESEND_FROM: 'ARC <preview@send.arcweb.onl>',
  ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED: 'true',
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
};
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

assert.equal(RESEND_SENDING_DOMAIN, 'send.arcweb.onl');
assert.equal(RESEND_FROM_IDENTITY, 'ARC <preview@send.arcweb.onl>');
assert.equal(RESEND_WEBHOOK_PATH, '/api/webhooks/resend');
assert.deepEqual(RESEND_REQUIRED_WEBHOOK_EVENT_TYPES, [
  'email.delivered', 'email.bounced', 'email.complained', 'email.failed', 'email.suppressed',
]);
assert.ok(RESEND_REQUIRED_WEBHOOK_EVENT_TYPES.every((eventType) =>
  RESEND_RECONCILED_EVENT_TYPES.includes(eventType)));
for (const wrongSender of [
  'ARC Web <preview@send.arcweb.onl>',
  'ARC <previews@send.arcweb.onl>',
  'preview@send.arcweb.onl',
  'ARC <preview@arcweb.onl>',
  'arc <preview@send.arcweb.onl>',
]) {
  assert.equal(resendProviderConfiguration({
    ...env,
    ARC_RESEND_FROM: wrongSender,
  }).send_enabled, false, 'Only the exact staged ARC sender identity may be used.');
}
for (const [credentialName, disabled] of [
  ['ARC_RESEND_API_KEY', (configuration) => configuration.send_enabled === false && configuration.apiKey === null],
  ['ARC_RESEND_WEBHOOK_SECRET', (configuration) =>
    configuration.webhook_enabled === false && configuration.webhookSigningKey === null],
]) {
  const configuration = resendProviderConfiguration({
    ...env,
    ARC_ROTATED_CREDENTIAL_V2: env[credentialName],
  });
  assert.equal(disabled(configuration), true, `${credentialName} must reject an arbitrary configured alias.`);
}
for (const credentialName of [
  'ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY',
  'ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET',
]) {
  assert.equal(emailRecipientVaultConfiguration({
    ...env,
    ARC_ROTATED_CREDENTIAL_V2: env[credentialName],
  }).enabled, false, `${credentialName} must reject an arbitrary configured alias.`);
}
assert.equal(emailSendAttemptConfiguration({
  ...env,
  ARC_ROTATED_CREDENTIAL_V2: env.ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET,
}).enabled, false, 'Email attempt signing must reject an arbitrary configured alias.');
assert.equal(webhookConfig.path, RESEND_WEBHOOK_PATH);

async function reserveConfirmation(sourceRecord, confirmationStore, vaultStore) {
  const verification = await reserveIntakeEmailVerification(sourceRecord, env, new FakeStore(), { clock: () => now });
  return reserveIntakeConfirmationOutbox(sourceRecord, env, confirmationStore, {
    clock: () => now, vaultStore, verification,
  });
}

const confirmationTemplate = renderTransactionalEmail('intake_confirmation', {
  recipient_email: 'owner@example.test',
  verification_url: `https://arcweb.onl/verify/#arcv1.${'a'.repeat(43)}`,
});
assert.match(confirmationTemplate.subject, /free preview/i);
assert.match(confirmationTemplate.text, /Confirm your email/);
assert.match(confirmationTemplate.text, /No payment is due unless you approve it/);
assert.match(confirmationTemplate.html, /No reply is needed/);
assert.throws(() => renderTransactionalEmail('intake_confirmation', {
  recipient_email: 'owner@example.test',
  verification_url: `https://evil.example/verify/#arcv1.${'a'.repeat(43)}`,
}), /URL/);
const reviewTemplate = renderTransactionalEmail('preview_review', {
  recipient_email: 'owner@example.test',
  review_url: 'https://arcweb.onl/review/#invite=private-review-token-0123456789',
});
assert.match(reviewTemplate.text, /before you pay/i);
assert.doesNotMatch(reviewTemplate.text, /email ARC/i);
assert.throws(() => renderTransactionalEmail('preview_review', {
  recipient_email: 'owner@example.test', review_url: 'https://evil.example/review/',
}), /URL/);
assert.match(renderTransactionalEmail('claim_invitation', {
  recipient_email: 'owner@example.test', claim_url: 'https://arcweb.onl/claim/example-token-0123456789',
}).subject, /Claim your approved website/);
assert.match(renderTransactionalEmail('final_delivery', {
  recipient_email: 'owner@example.test', production_url: 'https://customer-site.netlify.app/',
}).subject, /website is live/);

const disabledStore = new Proxy({}, { get() { throw new Error('disabled path touched storage'); } });
await assert.rejects(sealEmailRecipientCapsule(disabledStore, {}, {
  ...env, ARC_EMAIL_RECIPIENT_VAULT_ENABLED: 'false',
}), /VAULT_DISABLED/);
let disabledFetch = false;
await assert.rejects(sendResendTransactionalEmail({}, 'key', { ...env, ARC_RESEND_SEND_ENABLED: 'false' }, {
  fetch: async () => { disabledFetch = true; },
}), /SEND_DISABLED/);
assert.equal(disabledFetch, false);
assert.deepEqual(await runTransactionalEmailWorkerCycle({ ...env, ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED: 'false' },
  new Proxy({}, { get() { throw new Error('disabled worker touched stores'); } })), {
  schema: 'arc-transactional-email-worker-result-v1', state: 'DISABLED', processed: 0,
});
assert.deepEqual(await runTransactionalEmailWorkerCycle({ ...env, ARC_RESEND_WEBHOOK_ENABLED: 'false' },
  new Proxy({}, { get() { throw new Error('webhook-disabled worker touched stores'); } })), {
  schema: 'arc-transactional-email-worker-result-v1', state: 'DISABLED', processed: 0,
});

const vault = new FakeStore();
const expiresAt = new Date(now.getTime() + 60_000).toISOString();
const sealed = await sealEmailRecipientCapsule(vault, {
  job_kind: 'preview_review',
  job_key: 'review_job_12345678',
  recipient_email: 'owner@example.test',
  private_payload: { invite_token: 'private-invite-token-0123456789' },
  expires_at: expiresAt,
}, env, { clock: () => now, randomBytes: () => Buffer.alloc(12, 5) });
assert.equal(sealed.created, true);
const durableVaultJson = JSON.stringify([...vault.values.values()].map((entry) => entry.data));
assert.doesNotMatch(durableVaultJson, /owner@example\.test|private-invite-token/);
const opened = await openEmailRecipientCapsule(vault, {
  job_kind: 'preview_review', job_key: 'review_job_12345678',
}, env, { clock: () => now });
assert.equal(opened.recipient_email, 'owner@example.test');
assert.equal(opened.private_payload.invite_token, 'private-invite-token-0123456789');
assert.equal((await sealEmailRecipientCapsule(vault, {
  job_kind: 'preview_review', job_key: 'review_job_12345678', recipient_email: 'owner@example.test',
  private_payload: { invite_token: 'private-invite-token-0123456789' }, expires_at: expiresAt,
}, env, { clock: () => now })).idempotent_replay, true);
await assert.rejects(sealEmailRecipientCapsule(vault, {
  job_kind: 'preview_review', job_key: 'review_job_12345678', recipient_email: 'other@example.test',
  private_payload: { invite_token: 'private-invite-token-0123456789' }, expires_at: expiresAt,
}, env, { clock: () => now }), /VAULT_CONFLICT/);

const attemptStore = new FakeStore();
const message = {
  to: 'owner@example.test', subject: 'Your free preview is ready', text: 'Review your preview.',
  html: '<p>Review your preview.</p>', tags: [{ name: 'arc_kind', value: 'preview_review' }],
};
const attemptInput = {
  job_kind: 'preview_review',
  job_key: 'review_outbox_12345678',
  provider_idempotency_key: 'arc_review_email_idempotency_123',
  recipient_email_sha256: sha256(message.to),
  sender_sha256: sha256(env.ARC_RESEND_FROM),
  message_sha256: sha256(JSON.stringify(message)),
};
const reservation = await reserveEmailSendAttempt(attemptStore, attemptInput, env, { clock: () => now });
assert.equal(reservation.decision, 'SEND_EXACT_IDEMPOTENT_REQUEST');
assert.equal((await reserveEmailSendAttempt(attemptStore, attemptInput, env, { clock: () => now })).created, false);
let capturedSend;
const providerId = '49a3999c-0ce1-4ea6-ab68-afcd6dc2e794';
const accepted = await sendResendTransactionalEmail(message, attemptInput.provider_idempotency_key, env, {
  clock: () => now,
  fetch: async (url, options) => {
    capturedSend = { url, options };
    return new Response(JSON.stringify({ id: providerId }), {
      status: 200, headers: { 'content-type': 'application/json' },
    });
  },
});
assert.equal(capturedSend.url, 'https://api.resend.com/emails');
assert.equal(capturedSend.options.redirect, 'error');
assert.equal(capturedSend.options.headers['Idempotency-Key'], attemptInput.provider_idempotency_key);
assert.match(capturedSend.options.headers.Authorization, /^Bearer re_/);
assert.deepEqual(JSON.parse(capturedSend.options.body).to, [message.to]);
const acceptance = await markEmailProviderAccepted(attemptStore, {
  attempt_hmac_sha256: reservation.attempt_hmac_sha256, provider_message_id: accepted.provider_message_id,
}, env, { clock: () => now });
assert.equal(acceptance.state, 'PROVIDER_ACCEPTED');
assert.equal(acceptance.unlock_delivery, false, 'Resend API acceptance must never unlock delivery.');
assert.equal((await markEmailProviderAccepted(attemptStore, {
  attempt_hmac_sha256: reservation.attempt_hmac_sha256, provider_message_id: accepted.provider_message_id,
}, env, { clock: () => now })).idempotent_replay, true);
assert.doesNotMatch(JSON.stringify([...attemptStore.values.values()]), /owner@example\.test|arc_review_email_idempotency_123/);

function signedWebhook(type, eventId, createdAt = now.toISOString()) {
  const raw = JSON.stringify({
    created_at: createdAt,
    data: { email_id: providerId, from: env.ARC_RESEND_FROM, to: [message.to], subject: message.subject },
    type,
  });
  const timestamp = String(Math.floor(now.getTime() / 1000));
  const signature = createHmac('sha256', signingBytes).update(`${eventId}.${timestamp}.`).update(raw).digest('base64');
  return { raw, headers: new Headers({
    'content-type': 'application/json', 'svix-id': eventId, 'svix-timestamp': timestamp,
    'svix-signature': `v1,${signature}`,
  }) };
}

const sentWebhook = signedWebhook('email.sent', 'msg_sent_123');
const normalizedSent = verifyAndNormalizeResendWebhook(Buffer.from(sentWebhook.raw), sentWebhook.headers, env, {
  clock: () => now,
});
assert.equal(normalizedSent.supported_event, true);
const sentResult = await reconcileEmailProviderEvent(attemptStore, {
  provider: normalizedSent.provider,
  provider_event_id: normalizedSent.provider_event_id,
  provider_message_id: normalizedSent.provider_message_id,
  event_type: normalizedSent.event_type,
  occurred_at: normalizedSent.occurred_at,
  payload_sha256: normalizedSent.payload_sha256,
}, env);
assert.equal(sentResult.state, 'IGNORED');
assert.equal(sentResult.unlock_delivery, false, '`email.sent` must never unlock delivery.');

let deliveredCallbacks = 0;
const deliveredWebhook = signedWebhook('email.delivered', 'msg_delivered_123');
const delivered = await processResendWebhook(Buffer.from(deliveredWebhook.raw), deliveredWebhook.headers,
  attemptStore, env, { clock: () => now, onDelivered: async () => { deliveredCallbacks += 1; } });
assert.equal(delivered.state, 'DELIVERED');
assert.equal(delivered.unlock_delivery, true);
assert.equal(deliveredCallbacks, 1);
const deliveryReplay = await processResendWebhook(Buffer.from(deliveredWebhook.raw), deliveredWebhook.headers,
  attemptStore, env, { clock: () => now, onDelivered: async () => { deliveredCallbacks += 1; } });
assert.equal(deliveryReplay.idempotent_replay, true);
assert.equal(deliveryReplay.unlock_delivery, true, 'Exact replay must retry an idempotent downstream delivery ack.');
assert.equal(deliveredCallbacks, 2);

const complaintWebhook = signedWebhook('email.complained', 'msg_complained_123');
const complained = await processResendWebhook(Buffer.from(complaintWebhook.raw), complaintWebhook.headers,
  attemptStore, env, { clock: () => now });
assert.equal(complained.state, 'COMPLAINED');
assert.equal(complained.unlock_delivery, false);
const lateDelivery = signedWebhook('email.delivered', 'msg_delivered_late_123');
assert.equal((await processResendWebhook(Buffer.from(lateDelivery.raw), lateDelivery.headers,
  attemptStore, env, { clock: () => now })).unlock_delivery, false,
'A lower-priority delivery event after complaint must not unlock.');
assert.equal((await readEmailSendAttempt(attemptStore, {
  job_kind: 'preview_review', job_key: 'review_outbox_12345678',
}, env)).state, 'COMPLAINED');

const invalidHeaders = new Headers(deliveredWebhook.headers);
invalidHeaders.set('svix-signature', `v1,${Buffer.alloc(32, 1).toString('base64')}`);
assert.throws(() => verifyAndNormalizeResendWebhook(deliveredWebhook.raw, invalidHeaders, env,
  { clock: () => now }), /SIGNATURE_INVALID/);

const intakeStore = new FakeStore();
const intakeAttemptStore = new FakeStore();
const intakeVaultStore = new FakeStore();
const source = {
  schema: INTAKE_SUBMISSION_SCHEMA,
  submission_id: '11111111-1111-4111-8111-111111111111',
  submission_data_sha256: sha256('intake-provider-integration'),
  data: { email: 'customer@example.test' },
};
await reserveConfirmation(source, intakeStore, intakeVaultStore);
let intakeSends = 0;
const intakeProviderId = '11111111-2222-4333-8444-555555555555';
const run = () => runTransactionalEmailWorkerCycle(env, {
  confirmation: intakeStore, attempt: intakeAttemptStore, vault: intakeVaultStore,
}, {
  clock: () => now,
  randomBytes: () => Buffer.alloc(12, 9),
  fetch: async () => {
    intakeSends += 1;
    return new Response(JSON.stringify({ id: intakeProviderId }), { status: 200 });
  },
});
assert.equal((await run()).state, 'PROVIDER_ACCEPTED');
assert.equal(intakeSends, 1);
assert.equal((await run()).state, 'IDLE');
assert.equal(intakeSends, 1, 'Terminal intake completion must prevent a second provider call.');

const crashIntakeStore = new FakeStore();
const crashAttemptStore = new FakeStore();
const crashVaultStore = new FakeStore();
await reserveConfirmation({
  ...source,
  submission_id: '22222222-2222-4222-8222-222222222222',
  submission_data_sha256: sha256('intake-provider-crash-recovery'),
}, crashIntakeStore, crashVaultStore);
crashIntakeStore.failCompletionOnce = true;
let crashSends = 0;
const crashRun = () => runTransactionalEmailWorkerCycle(env, {
  confirmation: crashIntakeStore, attempt: crashAttemptStore, vault: crashVaultStore,
}, {
  clock: () => now,
  randomBytes: () => Buffer.alloc(12, 4),
  fetch: async () => {
    crashSends += 1;
    return new Response(JSON.stringify({ id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' }), { status: 200 });
  },
});
await assert.rejects(crashRun(), /synthetic crash/);
assert.equal(crashSends, 1);
const recovered = await crashRun();
assert.equal(recovered.state, 'PROVIDER_ACCEPTED');
assert.equal(recovered.idempotent_replay, true);
assert.equal(crashSends, 1, 'Recovery must use the encrypted provider receipt without resending.');
assert.doesNotMatch(JSON.stringify([...crashVaultStore.values.values()]),
  /customer@example\.test|aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/);

const latchCrashIntake = new FakeStore();
const latchCrashAttempts = new FakeStore();
const latchCrashVault = new FakeStore();
await reserveConfirmation({
  ...source,
  submission_id: '33333333-3333-4333-8333-333333333333',
  submission_data_sha256: sha256('intake-provider-latch-crash'),
}, latchCrashIntake, latchCrashVault);
latchCrashAttempts.failProviderIndexOnce = true;
let latchCrashSends = 0;
const latchCrashRun = () => runTransactionalEmailWorkerCycle(env, {
  confirmation: latchCrashIntake, attempt: latchCrashAttempts, vault: latchCrashVault,
}, {
  clock: () => now,
  randomBytes: () => Buffer.alloc(12, 6),
  fetch: async () => {
    latchCrashSends += 1;
    return new Response(JSON.stringify({ id: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff' }), { status: 200 });
  },
});
await assert.rejects(latchCrashRun(), /MESSAGE_INDEX_UNAVAILABLE/);
assert.equal(latchCrashSends, 1);
const latchRecovered = await latchCrashRun();
assert.equal(latchRecovered.state, 'PROVIDER_ACCEPTED');
assert.equal(latchRecovered.idempotent_replay, true);
assert.equal(latchCrashSends, 1,
  'A persisted provider receipt must be recovered before any Resend retry when the acceptance latch crashed.');

const saved = { ...process.env };
try {
  Object.assign(process.env, env);
  const handler = createResendWebhookHandler();
  let invalidStoreTouched = false;
  const request = new Request('https://arcweb.onl/api/webhooks/resend', {
    method: 'POST', headers: invalidHeaders, body: deliveredWebhook.raw,
  });
  const response = await handler(request, {
    get attemptStore() { invalidStoreTouched = true; throw new Error('signature path touched store'); },
    clock: () => now,
  });
  assert.equal(response.status, 401);
  assert.equal(invalidStoreTouched, false, 'Signature verification must precede all durable state access.');
} finally {
  for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
  Object.assign(process.env, saved);
}

assert.equal(webhookConfig.path, '/api/webhooks/resend');
assert.equal(webhookConfig.method, 'POST');
assert.equal(workerConfig.schedule, '* * * * *');

const runbook = await readFile(new URL('../operations/transactional-email-resend.md', import.meta.url), 'utf8');
for (const required of ['Preview-review link | **BLOCKED**', 'Operations alert | **BLOCKED**',
  'Post-payment / final delivery | **BLOCKED**', 'Only an authenticated `email.delivered`']) {
  assert.match(runbook, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    `Transactional email runbook must retain activation gate: ${required}`);
}

console.log('ARC default-off Resend transactional provider, vault, worker, and signed delivery webhook contract passed.');
