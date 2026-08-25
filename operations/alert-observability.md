# ARC operational alert observability

Status: **durable detection implemented, disabled, notification delivery not implemented**.

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

## Environment contract

- `ARC_OPERATIONS_AUDIT_ENABLED=true`
- `ARC_OPERATIONS_AUDIT_SECRET` — endpoint bearer
- `ARC_OPERATIONS_ALERT_HMAC_SECRET` — distinct durable alert identity secret

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

Before `failure_alert_verified` can be true, build a separate alert consumer with create-only send attempts, a verified ARC recipient, provider delivery receipts, escalation/acknowledgement, retry limits, and a synthetic stuck-state test. Keep the audit endpoint disabled until its store bounds and recipient workflow are reviewed. Neither endpoint has a schedule, and alert delivery remains unimplemented.
