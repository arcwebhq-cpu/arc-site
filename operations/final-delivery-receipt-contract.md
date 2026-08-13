# ARC2 final delivery receipt contract

This endpoint records a final-handoff email that an independently configured
provider already delivered. It never sends email and never makes an outbox
actionable. The handoff must already be `FINAL_DEPLOY_READY`, with its exact
claimed outbox and verified final Netlify deployment.

## Trust boundary

The receipt signer is a provider adapter, not the email provider itself. Before
signing, that adapter must authenticate the provider's native webhook, bind it
to the configured provider account, and map only the provider's authoritative
delivered event to the exact values `event_type=message.delivered` and
`delivery_status=delivered`. Queued, accepted, sent, deferred, bounced,
complained, suppressed, or unauthenticated events must never produce a receipt.
This repository validates the adapter attestation; it does not contain or claim
to perform native provider-webhook verification.

The adapter and endpoint remain disabled until that external verification path
has been configured and tested against the chosen provider.

## Authentication and signature

- Version: `arc2-final-email-delivery-receipt-v1`
- Scope: `authoritative-final-email-provider-delivery`
- Signature prefix: `arc2-final-email-delivery-receipt-signature-v1\n`
- Receipt HMAC: SHA-256 with `ARC_FINAL_DELIVERY_RECEIPT_SECRET`
- Endpoint: `POST /internal/arc2/final-delivery-ack`
- Endpoint bearer: `ARC_FINAL_DELIVERY_ACK_SECRET`

Both secrets are required, 32–512 characters, and distinct from each other and
every other ARC/Netlify secret. They belong only in Netlify's encrypted
production Functions environment. The generic `ARC_HANDOFF_TRIGGER_SECRET`
cannot invoke this endpoint.

The request JSON has exactly these three string fields:

```json
{
  "handoff_id": "<64-lowercase-hex>",
  "delivery_receipt_evidence": "<canonical JSON string below>",
  "delivery_receipt_evidence_hmac_sha256": "<64-lowercase-hex HMAC>"
}
```

The embedded receipt is canonical JSON: no whitespace, lexicographically sorted
keys, and exactly these fields:

```json
{"delivered_at":"2026-08-13T06:00:00.000Z","delivery_status":"delivered","event_type":"message.delivered","handoff_id":"<64-lowercase-hex>","issued_at":"2026-08-13T06:00:30.000Z","netlify_deploy_id_sha256":"<64-lowercase-hex>","netlify_site_id_sha256":"<64-lowercase-hex>","outbox_claim_key_hmac_sha256":"<64-lowercase-hex>","production_url_sha256":"<64-lowercase-hex>","provider":"<lowercase-provider-key>","provider_account_hmac_sha256":"<64-lowercase-hex>","provider_event_id":"<native-provider-event-id>","provider_message_id":"<native-provider-message-id>","recipient_email_sha256":"<64-lowercase-hex>","scope":"authoritative-final-email-provider-delivery","version":"arc2-final-email-delivery-receipt-v1"}
```

The HMAC input is the exact signature prefix followed by the exact canonical
receipt string. The receipt binds to the stored handoff ID, outbox-claim HMAC,
customer-recipient hash, canonical production-URL hash, final Netlify deploy-ID
hash, and Netlify site-ID hash. It also binds the provider, provider-account
HMAC, native provider event/message identities, and exact delivered type/status.

On first observation, `issued_at` must be no more than ten minutes old or sixty
seconds in the future. `delivered_at` cannot precede final-deploy readiness,
cannot follow `issued_at`, and cannot be more than ten minutes before it.

Raw provider event/message IDs exist only in the signed request. Durable keys
and values use keyed, domain-separated HMACs:

- event: `arc2-final-delivery-provider-event-id-v1\n` plus canonical provider,
  provider-account HMAC, and event ID;
- message: `arc2-final-delivery-provider-message-id-v1\n` plus canonical
  provider, provider-account HMAC, and message ID.

Those event and message identities are independently reserved with create-only
global keys. Reuse in another handoff fails closed.

## Resumable persistence protocol

Netlify Blobs does not offer an atomic transaction across the handoff, outbox,
event-index, and message-index keys. The endpoint therefore uses this convergent
protocol:

1. Validate the exact signed receipt, stored handoff bindings, state, ordering,
   and first-observation freshness.
2. CAS the claimed outbox to `DELIVERY_ACK_PENDING`, binding one exact receipt.
   This is the receipt-intent lock and no-resend latch; a competing receipt
   cannot reserve identities for that handoff.
3. Create-only reserve the global provider event and message identities.
4. CAS the same outbox to terminal `DELIVERED`.
5. CAS the handoff to `DELIVERED` with only receipt hashes/bindings.

The endpoint returns success only after step 5. A crash after steps 2, 3, or 4
leaves enough exact durable evidence for a later identical retry to resume even
after the normal freshness window. A terminal outbox is never reopened or
rewritten on replay. Send workers must treat every state other than `CLAIMED` as
non-actionable.

The two global identity reservations are also separate keys. A receipt that
collides on only one identity can leave its other identity reserved before the
conflict is observed. This is an intentional fail-closed quarantine, not an
atomicity claim; it requires operator investigation and must never be silently
deleted or reassigned.

The outbox latch prevents new/retried workers from sending after acknowledgement
starts. It cannot cancel a provider request already in flight. The external
sender must additionally use a create-only send-attempt record and the outbox
claim HMAC as the provider idempotency key. That producer invariant is not
implemented by this acknowledgement endpoint and must be proven before email
automation is enabled.

## Legacy records

Stored `arc2-netlify-handoff-v1` records are normalized to v2 on read and retain
their original `arc-<24hex>` Netlify site name. Legacy records already marked
`DELIVERED` without authoritative receipt evidence are quarantined and rejected.
The committed lead-route producer supports only the
`arc-lead-route-<24hex>` namespace, so any `arc-<24hex>` record earlier than
`INVITATION_READY` is permanently quarantined from automated replay. The start
handler rejects it before index creation, binding repair, Netlify access, or any
other mutation; the invitation-ready handler rejects it before parsing or
verifying receipt evidence. An exact authenticated start replay cannot rename
the already-created site or repair this incompatibility. Resuming one of these
records requires a separately reviewed private migration, not a public endpoint
retry.

Legacy `arc-<24hex>` records that had already reached `INVITATION_READY` or a
later state remain readable and may continue through downstream claim and final
delivery migration. Their existing site name is preserved. This exception does
not authorize generating a new lead-route receipt for an earlier legacy state.
