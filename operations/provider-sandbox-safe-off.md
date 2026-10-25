# ARC V11 provider sandbox staging

Status: **SAFE_OFF_STAGED, not launch-ready**. The machine-readable source is
`operations/provider-sandbox-safe-off.json`. It contains public sandbox catalog
bindings and no credential values. Every local automation, customer email,
Checkout, webhook, intake, handoff, and analytics control remains exact `false`.

## Stripe sandbox

The V11 test catalog is bound to the one-time $5,000 USD product and price in
the JSON contract. Both are test-mode objects. No charge or customer mutation
is part of this staging step.

Two separate test-mode restricted keys are stored in the Netlify Deploy Preview
context without exposing their values:

- `ARC_STRIPE_REVIEW_SECRET_KEY`: Products Read, Prices Read, Checkout Sessions
  Write, and Tax Settings/Registrations Read.
- `ARC_STRIPE_ACCOUNT_VERIFICATION_KEY`: Events Read, Payment Intents Read, and
  Checkout Sessions Read.

Both values must start with `rk_test_`. A broad `sk_test_` key is not part of
the V11 sandbox plan. Store credentials only as protected runtime secrets. Do
not put them in Git, logs, readback receipts, or provider notes.

The current runtime also calls `GET /v1/account` with each restricted key, but
that capability is not present in the provider scope readback. The scope match
therefore remains blocked until an OFF-state provider capability test succeeds
or the keys are amended. The unified Stripe webhook remains not created and its
contract expects the corrected stable `2026-08-26.dahlia` API version; the
separate version remediation centralizes that runtime constant. Stripe Tax
registrations and head-office settings remain unchanged.

## Resend sandbox proof

The only accepted sending domain is `send.arcweb.onl`, and its DNS status is
verified. `ARC <preview@send.arcweb.onl>` and the domain-scoped sending key are
stored in the Netlify production context without exposing the key value.
Runtime configuration rejects every other display name, mailbox, bare address,
domain, or case variation even while the provider controls are OFF.

The native webhook URL is `https://arcweb.onl/api/webhooks/resend`. It is enabled
for sent, delivery-delayed, delivered, bounced, complained, failed, and
suppressed events. Delivered plus the four negative/suppression event classes
are the critical subset; sent and delivery-delayed never unlock delivery. Its
signing secret is stored in the Netlify production context without exposing it.

Run the deterministic no-network check with:

```sh
npm run preflight:providers
```

The executable preflight validates its actual `process.env`: every supplied ARC
automation/verification/required flag must be exact `false`, the supplied
Stripe version must equal the centralized stable version, and the supplied
sender must equal the staged identity. Unset flags remain runtime-fail-closed.
Any enabled, malformed, newly introduced, stale-version, or wrong-sender value
returns nonzero. The separate contract-only helper validates the checked-in
provider evidence without treating that fixture as deployed environment state.

A passing report means only that the public bindings, stored-scope evidence,
actual SAFE_OFF environment, and centralized version agree. It does not claim
the Stripe account-read scope is usable, claim provider E2E passed, or authorize
an email, Checkout Session, webhook mutation, public intake, handoff, charge,
or launch.
