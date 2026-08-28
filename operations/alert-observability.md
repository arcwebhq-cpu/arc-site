# ARC operational alert observability

Status: **durable detection and a reserve/ack protocol are implemented, but both
are disabled and trusted notification delivery is BLOCKED**.

The internal `/internal/operations/audit` endpoint performs a read-only scan of bounded first-party state and creates deduplicated, create-only `PENDING` alert records in `arc-operations-alerts`. It makes no email, Slack, Zapier, Stripe, or Netlify Admin API calls.

Detected conditions include:

- handoff records stalled for more than 60 minutes;
- expired claim invitation state and `READY` invitation outboxes;
- final-delivery outboxes still `CLAIMED` or `DELIVERY_ACK_PENDING` after 30 minutes;
- delivered handoffs without terminal delivery outboxes;
- every open Stripe reversal halt;
- verified Stripe reversal events whose PaymentIntent cannot be bound to a handoff;
- retention delete intents without receipts after 15 minutes;
- malformed/orphaned first-party control records.

Alert keys use a dedicated HMAC and contain no customer answers, addresses, email addresses, raw Stripe IDs, or provider bearer credentials. Exact scans deduplicate; alerts never close themselves and never claim a human was notified.

## Default-OFF environment contract

The committed and deployed baseline must keep both switches absent or exactly
`false`:

```dotenv
ARC_OPERATIONS_AUDIT_ENABLED=false
ARC_OPERATIONS_ALERT_DELIVERY_ENABLED=false
```

The reviewed production target is stricter: first-party retention cannot run
unless `ARC_OPERATIONS_AUDIT_ENABLED=true` and its signed queue secrets are
valid. This enables only durable PII-free queue writes. Notification delivery
stays `false` until its separate provider evidence gate is cleared.

All global-retention-fenced routes and freezers use that same queue for genuine
stale `WRITING` or `FROZEN` evidence. Queue delivery is synchronous and
fail-closed, including when an existing immutable fence alert must be retried;
ordinary live contention never creates an operations alert.

The reserve and acknowledgement routes share an authenticated worker bearer.
That protocol can coordinate an external sender, but a caller-supplied
`email.delivered` acknowledgement is not native provider evidence. Do not enable
`ARC_OPERATIONS_ALERT_DELIVERY_ENABLED` and do not attest
`failure_alert_verified=true` until the send attempt has a durable
provider-accepted no-resend latch and an exact Resend/Svix-signed delivery event
is bound to the alert before terminal acknowledgement.

Activation would additionally require:

- `ARC_OPERATIONS_AUDIT_ENABLED=true`
- `ARC_OPERATIONS_AUDIT_SECRET` — endpoint bearer
- `ARC_OPERATIONS_ALERT_HMAC_SECRET` — distinct durable alert identity secret
- `ARC_OPERATIONS_ALERT_DELIVERY_ENABLED=true`
- `ARC_OPERATIONS_ALERT_DELIVERY_HMAC_SECRET` — delivery-state signature secret
- `ARC_OPERATIONS_ALERT_DELIVERY_BEARER` — reserve/ack worker bearer
- `ARC_OPERATIONS_ALERT_RECIPIENT_EMAIL` — verified ARC operations recipient
- `ARC_OPERATIONS_ALERT_EMAIL_PROVIDER` and `ARC_OPERATIONS_ALERT_SENDER` — exact
  provider and verified sender bindings

The private audit endpoint processes at most 100 records and 20 provider pages
within one 8-second wall-clock budget. It persists each exact alert before
advancing and returns a signed `next_cursor` when work remains; operators must
resume until `AUDIT_COMPLETE`. The private ARC1 recovery endpoint likewise uses
signed cursor-resumable UUID shards, at most 20 dispatch attempts/100 reads per
call, and a shared 8-second deadline. The separate first-party ARC1 adapter
recovery endpoint uses signed cursor-resumable HMAC shards with the same bounded
attempt/read/deadline policy. A Zapier Catch Hook HTTP 200 is transport-only and
keeps the job pending. Recovery never reposts a hook-accepted packet: it monitors
the 15-minute awaiting-claim deadline and 30-minute active claim, moves stale
work to `REVIEW_REQUIRED`, creates a pseudonymous review index before pending
cleanup, and leaves resolution manual. Signed completion is the only ordinary
path to `COMPLETED`. No automatic claim reassignment exists in this release.

Before `failure_alert_verified` can be true, complete the native signed-webhook
binding described above, use create-only send attempts, verify the ARC recipient,
prove escalation/acknowledgement and retry limits, and run a synthetic stuck-state
test. Keep both audit and alert-delivery switches disabled until those receipts
are reviewed. Neither reserve nor acknowledgement has a schedule; no provider
sender currently consumes this protocol.
