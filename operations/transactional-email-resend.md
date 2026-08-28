# ARC transactional email / Resend activation gate

Status: **default OFF and not full-flow ready**. Repository tests are not proof
that a Resend account, sending domain, webhook, or customer inbox is configured.
Do not enable customer sending until the adult operator reviews a disabled
provider test and all four stage rows below are `READY`.

## Runtime switches

These switches must remain absent or `false` in the committed and deployed
baseline:

```dotenv
ARC_TRANSACTIONAL_EMAIL_ENABLED=false
ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED=false
ARC_EMAIL_RECIPIENT_VAULT_ENABLED=false
ARC_RESEND_SEND_ENABLED=false
ARC_RESEND_WEBHOOK_ENABLED=false
ARC_REVIEW_EMAIL_RESEND_CAPSULE_ENABLED=false
ARC_REVIEW_EMAIL_RESEND_WORKER_ENABLED=false
ARC_TRANSACTIONAL_EMAIL_RETENTION_ENABLED=false
ARC_OPERATIONS_ALERT_DELIVERY_ENABLED=false
```

Production-only Function secrets/configuration, never Git values:

- `ARC_TRANSACTIONAL_EMAIL_ATTEMPT_HMAC_SECRET`: 32–256 UTF-8 bytes.
- `ARC_EMAIL_RECIPIENT_VAULT_HMAC_SECRET`: a distinct 32–256 byte secret.
- `ARC_EMAIL_RECIPIENT_VAULT_ENCRYPTION_KEY`: 32 random bytes encoded as
  unpadded base64url.
- `ARC_RESEND_API_KEY`: a least-privilege `re_...` key.
- `ARC_RESEND_WEBHOOK_SECRET`: the endpoint's `whsec_...` signing secret.
- `ARC_RESEND_FROM`: one mailbox on the verified ARC sending subdomain.
- `ARC_RESEND_PROVIDER_ACCOUNT_ID`: the stable Resend account identity bound to
  native delivery receipts.
- `ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET`: a distinct 32–256 byte secret used
  only to bind that provider account identity.
- `ARC_TRANSACTIONAL_EMAIL_RETENTION_DAYS`: 7–365 when terminal-attempt pruning
  is explicitly enabled.

The one-minute `transactional-email-worker` schedule remains inert unless every
worker, ledger, vault, intake, Resend-send, and signed-webhook gate is valid.
`POST /api/webhooks/resend` verifies the exact raw bytes with `svix-id`,
`svix-timestamp`, and `svix-signature` before any Blob access.

## Stage gate

| Stage | Repository state | Activation requirement |
|---|---|---|
| Intake confirmation | Provider worker implemented | Disabled-provider send plus signed delivered, bounced, complained, failed, and suppressed webhook proofs |
| Preview-review link | **BLOCKED** | Code-complete encrypted producer capsule, create-only Resend attempt, signed delivered/bounce/complaint/failed/suppressed binding, and Checkout revocation; still requires disabled-provider and inbox E2E proof |
| Operations alert | **BLOCKED** | Durable `PROVIDER_ACCEPTED` no-resend state before its lease may be reclaimed, then signed delivery acknowledgement |
| Post-payment / final delivery | **BLOCKED** | Discoverable `FINAL_DEPLOY_READY` index, encrypted recipient/claim authority capsule, create-only send wiring, and native final-delivery receipt binding |

The provider API response and `email.sent` mean only that Resend accepted the
request. Neither may unlock review, checkout, operations resolution, or final
delivery. Only an authenticated `email.delivered` webhook may invoke an
idempotent downstream acknowledgement. Bounce, complaint, failed, and
suppressed events must keep delivery locked and route the flow to suppression or
manual review.

## Disabled-provider proof

1. Verify an ARC sending subdomain and record the domain/provider evidence
   outside Git. Do not use a free Gmail address for customer transactional mail.
2. Register the exact production webhook URL and subscribe to delivery,
   bounce, complaint, failed, and suppressed events.
3. Keep every runtime switch false. Use Resend's documented test recipients to
   prove each event class without contacting a customer.
4. Prove one create-only attempt before the network call, exact idempotency-key
   reuse after an ambiguous response, encrypted receipt recovery after each
   crash window, and no second send after provider acceptance.
5. Prove webhook exact replay and out-of-order handling. Only the delivered
   event may call the downstream acknowledgement; a later complaint must still
   suppress the recipient.
6. Add producer capsules and focused tests for every blocked row. Do not set the
   master worker or send switches true while any row is blocked.

Preview-review specifics: the authenticated prepare request seals the exact
recipient, invite token, and fragment-only review URL in the encrypted vault.
The durable review outbox, pending index, attempt ledger, and provider binding
contain only HMACs/digests. Resend API acceptance is a no-resend latch but never
unlocks review. The signed `email.delivered` webhook alone binds delivery;
`email.bounced`, `email.complained`, `email.failed`, and `email.suppressed`
revoke the invite and any bound Checkout. Terminal acknowledgement deletes both
review capsules. Active workers also prune expired capsules; terminal attempt
ledgers are pruned only after the configured 7–365 day retention window. The
bounded sweep consumes every provider page with an authenticated cursor,
quarantines stale nonterminal attempts, deletes terminal attempt/message/event
indexes as one cascade, and stores a signed PII-free completion receipt.

Official contracts:

- https://resend.com/docs/api-reference/emails/send-email
- https://resend.com/docs/dashboard/emails/idempotency-keys
- https://resend.com/docs/webhooks/verify-webhooks-requests
- https://resend.com/docs/webhooks/event-types
- https://resend.com/docs/knowledge-base/what-email-addresses-to-use-for-testing
