# ARC Stripe reversal control

Status: **code complete, disabled, and not connected to an ARC Stripe event destination**. This is not evidence that refunds or disputes are operationally monitored today.

## Safety properties

- The webhook accepts only the explicit reversal event allowlist in `stripe-reversal-core.mjs` and requires a valid Stripe `v1` signature over the untouched request body within a five-minute delivery tolerance.
- The endpoint requires Stripe API version `2026-06-24.dahlia`, the configured test/live mode, the expected ARC account hash, and a pre-registered Checkout Session → PaymentIntent → handoff binding.
- Each raw Stripe event ID, PaymentIntent ID, and reversal-object ID is converted to a domain-separated HMAC before durable storage. One create-only global event reservation prevents an event from being rebound to another handoff or other bytes.
- Any accepted refund attempt, refunded charge, or dispute creates a permanent fulfillment halt and manual-review requirement. Later favorable events can update the status but can never lower severity, clear the halt, or resume fulfillment.
- Before every controlled provider stage, ARC2 also requires a signed authoritative recheck issued within five minutes and bound to the exact handoff, Checkout Session, PaymentIntent, account, and mode. It must report `payment_intent_status=succeeded`, zero refunded amount, and no dispute. Rechecks are monotonic CAS records; older attestations cannot replace newer ones. The recheck producer must query Stripe's authoritative objects immediately before signing—webhook silence is never treated as proof of no reversal.
- Private final-email send authority is stricter: its recheck must not predate `FINAL_DEPLOY_READY` and must be issued no more than 60 seconds before authority issuance. ARC2 checks the halt and that exact freshness both before and after the final Netlify readback. The signed authority is actionable for at most 60 seconds after its `issued_at`; a sender must request a new authority and reject the send if that window closes before the provider request begins.
- The handler never calls Stripe, creates a refund, submits dispute evidence, sends email, or transfers a site. A refund remains an adult-operator decision under `refund-dispute-runbook.md`.
- ARC2 checks the binding, fresh recheck, and reversal halt before site creation, deploy, invitation readiness, claim exchange, post-claim verification, final fulfillment work, and release of private outbox/send evidence whenever the control is required.

Netlify Blobs cannot atomically lock a Stripe webhook key and a Netlify provider write. ARC2 rechecks immediately before each controlled stage, but a small cross-provider race remains. Every external email/outbox worker must independently enforce the 60-second signed-authority window immediately before sending and use its own durable send-attempt latch.

## Required external setup

1. Use only the verified ARC Stripe account. Create separate test and live webhook event destinations; never reuse their secrets.
2. Pin the event destination to API version `2026-06-24.dahlia` and select exactly:
   - `refund.created`, `refund.updated`, `refund.failed`
   - `charge.refunded`
   - `charge.dispute.created`, `charge.dispute.updated`, `charge.dispute.closed`
   - `charge.dispute.funds_withdrawn`, `charge.dispute.funds_reinstated`
3. Have the authoritative checkout-evidence producer register the exact Checkout Session, PaymentIntent, handoff, mode, and ARC account hash through `/internal/stripe/reversal-binding` before retrying ARC2 fulfillment.
4. Build the external recheck producer with a least-privilege Stripe restricted key. It must retrieve the exact PaymentIntent and related refund/dispute state from Stripe, fail closed on pagination or ambiguous state, then sign the exact recheck contract and submit it to `/internal/stripe/reversal-recheck`. A recheck expires after five minutes; each provider stage needs a fresh valid record.
5. Configure an infrastructure IP allowlist for Stripe webhook source ranges where supported. Rate limiting is defense in depth, not a substitute for signature verification.
6. Wire and receipt-test an alert sink for durable `arc-operations-alerts` records. The current code only records `PENDING` alerts.
7. Prove one partial refund, one completed refund, one failed refund, one open dispute, one favorable closure, one lost dispute, one duplicate delivery, one out-of-order delivery, one stale recheck, and one recheck/webhook race in Stripe test mode.

## Environment contract

All controls default to off. Secrets must be unique, 32–512 characters, and stored only in Netlify’s protected environment/secrets controls.

- `ARC_STRIPE_REVERSAL_CONTROL_REQUIRED=true`
- `ARC_STRIPE_REVERSAL_WEBHOOK_ENABLED=true`
- `ARC_STRIPE_REVERSAL_BINDING_ENABLED=true`
- `ARC_STRIPE_REVERSAL_RECHECK_ENABLED=true`
- `ARC_STRIPE_WEBHOOK_API_VERSION=2026-06-24.dahlia`

The first authenticated handoff-start call reserves immutable payment and
artifact state, then returns HTTP 202 with `handoff_id`,
`status: PAYMENT_VERIFIED`, and `reversal_control_ready: false`. It performs no
Netlify provider write. The private Stripe adapter must use that handoff ID to
register the exact Checkout Session→PaymentIntent binding, submit a fresh
no-reversal recheck, and replay the identical start request. Only that replay
may advance into provider work.

- `ARC_STRIPE_WEBHOOK_SIGNING_SECRET` — Stripe event-destination signing secret
- `ARC_STRIPE_REVERSAL_HMAC_SECRET` — durable identity HMAC secret
- `ARC_STRIPE_REVERSAL_BINDING_SECRET` — checkout-evidence producer signing secret
- `ARC_STRIPE_REVERSAL_BINDING_ENDPOINT_SECRET` — distinct endpoint bearer
- `ARC_STRIPE_REVERSAL_RECHECK_SECRET` — authoritative recheck producer signing secret
- `ARC_STRIPE_REVERSAL_RECHECK_ENDPOINT_SECRET` — distinct recheck endpoint bearer
- existing exact `ARC_HANDOFF_STATE_SECRET`, `ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256`, and `ARC_STRIPE_LIVE_MODE_ENABLED`

Keep `ARC_STRIPE_LIVE_MODE_ENABLED=false` and all three enable/required flags unset until the complete sandbox evidence and alert delivery are reviewed. Live refunds remain manual; no Stripe API key is needed or accepted by this control.
