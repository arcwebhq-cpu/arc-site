# ARC2 native transactional email foundation

This code is default-OFF. The private recipient continuity, fair shared worker,
signed Resend webhook bridge, and final-delivery acknowledgement are integrated
in the repository. Repository tests are not proof that Resend or Netlify is
configured, so every provider switch remains OFF until controlled E2E proof.

## Separate customer stages

| Stage | Discovery | Generic attempt job key | Private content derived at send time |
| --- | --- | --- | --- |
| `claim_invitation` | `invitation-ready-current/<handoff_id>` | Current invitation outbox digest | `https://arcweb.onl/claim/#arc2.<handoff>.<bearer>` |
| `final_delivery` | `outbox/<outbox_claim_key_hmac_sha256>` with exact `CLAIMED` state | `outbox_claim_key_hmac_sha256` | Freshly verified production URL |

The claim invitation transfers the approved Netlify site. It is not the final
delivery email. The final delivery email is authorized only after the customer
claim and exact final deployment have both been verified.

An expired claim link is never renewed on a timer. The claim page exposes one
explicit **Email me a fresh ownership link** action only after the exchange
returns an expired/invalid response. Its same-origin endpoint accepts the
expired bearer as proof of possession, allows at most two requests per IP and
site per hour, and rotates that exact generation once. The response contains no
new bearer or address. A successful rotation replaces the current generation,
invalidates the old bearer, and creates a distinct invitation outbox digest, so
the shared worker reserves a new Resend attempt instead of replaying the
already-delivered attempt.

Before rotation, recovery strong-readbacks the existing encrypted handoff
capsule, matches it to the paid recipient and source invite, checks global
review-recipient suppression, and checks the prior claim attempt for bounce,
complaint, failure, or suppression. Stripe payment and reversal authority is
freshly checked around the rotation; send-time authority checks it again. A
suppressed recipient never receives a recovery send.

## Recipient continuity

The paid ARC2 worker opens the encrypted `preview_review` capsule using the
review email outbox HMAC. It verifies the plaintext recipient against the paid
review binding. After `startReviewHandoff` returns a durable handoff, and before
the paid bridge is completed, it seals and strong-readbacks two capsules keyed
by the handoff ID:

- `claim_invitation + handoff_id`
- `final_delivery + handoff_id`

Each capsule contains the encrypted recipient and only the source review invite
HMAC. Claim URLs, production URLs, and provider events are never persisted in
these capsules or public discovery records. The deterministic capsule expiry is
the immutable handoff creation time plus 30 days, making crash recovery an exact
idempotent replay. A capsule failure leaves the paid bridge incomplete.

## Send authority and reconciliation

`getClaimInvitationEmailAuthority` accepts only `INVITATION_READY`, rotates an
expired generation under CAS, derives the claim bearer in memory, ensures the
current invitation outbox/index, and runs fresh Stripe reversal checks before
and after that work.

`getFinalDeliveryEmailAuthority` delegates to
`getHandoffStatus(..., { includePrivate: true })`. That path brackets exact
Netlify final-deploy readback with fresh Stripe reversal checks. A worker must
render and send immediately; the authority is limited to 60 seconds.

After the signed Resend webhook and generic attempt ledger authenticate an
`email.delivered` event for `final_delivery`, the webhook opens the encrypted
attempt context, refreshes the exact send authority, seals and strong-readbacks
the canonical receipt, then calls `acknowledgeFinalDelivery`. The sealed receipt
makes a crash or exact webhook replay converge on identical evidence. API
acceptance, `email.sent`, delay, bounce, suppression, failure, or complaint
never calls this adapter.

## Default-OFF environment

- `ARC_ARC2_CLAIM_INVITATION_EMAIL_ENABLED=false`
- `ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED=false`
- `ARC_ARC2_FINAL_DELIVERY_EMAIL_ENABLED=false`
- `ARC_TRANSACTIONAL_EMAIL_ENABLED=false`
- `ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED=false`
- `ARC_EMAIL_RECIPIENT_VAULT_ENABLED=false`
- `ARC_RESEND_SEND_ENABLED=false`
- `ARC_RESEND_WEBHOOK_ENABLED=false`

When either ARC2 stage is enabled, the transactional email master switch and
encrypted recipient vault must both be valid. The fail-closed negative-event
latch also requires a distinct `ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET`.
Final receipt production additionally requires:

- `ARC_RESEND_PROVIDER_ACCOUNT_ID`
- `ARC_RESEND_PROVIDER_BINDING_HMAC_SECRET`
- `ARC_FINAL_DELIVERY_RECEIPT_SECRET`

The provider binding secret must be distinct from the final receipt, generic
attempt, and recipient-vault HMAC secrets. Its exact derivation is:

`HMAC-SHA256(secret, "arc-resend-provider-account-binding-v1\n" + account_id)`

Keep all three ARC2 flags OFF until a controlled end-to-end
delivery/reversal/recovery test passes against the exact disabled production
configuration. The recovery proof must show that a delivered expired link can
queue exactly one new attempt, the old bearer is rejected, and complaint or
suppression blocks the new attempt.

## Integrated worker/webhook path

1. Paid worker: `openPaidPreviewRecipientCapsule`, then
   `sealArc2HandoffEmailCapsules` before `completePaymentArc2StartOutbox`.
2. The shared minute-based worker rotates intake, preview, claim, and final as
   first priority so one busy queue cannot starve another.
3. Claim worker: `discoverNextClaimInvitationEmail`, then
   `prepareClaimInvitationEmailJob`, then reserve the generic attempt with its
   returned `job_key`. It strong-readbacks an encrypted attempt context before
   the Resend request.
4. Final worker: `discoverNextFinalDeliveryEmail`, then
   `prepareFinalDeliveryEmailJob`, then reserve the generic attempt with its
   returned `job_key`, with the same pre-request context latch.
5. Verified delivered webhook: resolve the encrypted attempt context, seal the
   exact receipt capsule, then `acknowledgeFinalDelivery`.
6. Claim invitation delivery remains terminal only in the generic attempt
   ledger. It must not call the final-delivery acknowledgement.
7. Bounce, complaint, failure, or suppression stops retries and, when the
   stage is enabled, durably enters manual review, revokes its bearer and
   encrypted recipient capsules, and creates a local PII-free alert. A late
   delivery cannot clear that latch or advance the ARC2 handoff.
