# Review, email, Checkout, and payment-to-ARC2 activation environment

Status: **OFF by default**. This contract does not enable a Netlify Function,
Zap, Stripe destination, email integration, public form, pilot, or outreach
sequence. It defines the evidence required before an adult operator changes one
stage. The canonical machine-readable companion is
`operations/review-activation-environment.json`.

## One ordered activation path

Use only this order, one transition at a time:

`OFF -> EMAIL_SANDBOX -> CLAIM_SANDBOX -> LIVE_CHECKOUT -> PUBLIC_INTAKE -> PILOT -> OUTREACH`

The committed production profile is deliberately `PRODUCTION_BLOCKED` even
when every local value is internally consistent. Its machine-readable
`blocked_controls` remain authoritative until each named provider/cascade E2E
receipt is independently collected, reviewed, and the contract is updated.
Local booleans, self-attestation, or a synthetic readback cannot clear them.
The blockers explicitly name the unified Stripe event-destination receipt, the
selected Netlify handoff-credential readback, native operations-alert delivery,
provider retention cascades, and the complete live provider E2E.

The signed activation manifest in `operations/activation-manifest.md` remains
the runtime authority. This preflight is an additional provider/environment
binding check; neither one replaces the other. A candidate may advance only
after both checks pass, every provider control is independently read back, and
the bounded end-to-end receipt for that transition has been reviewed.

To avoid requiring the first email E2E receipt before that receipt can be
created, sandbox preflight accepts the deployment-bound `TEST_BOOTSTRAP`
authority described in `activation-manifest.md`. Its only scope is
the first `EMAIL_SANDBOX` receipt, its lifetime is at most 15 minutes, and live
Stripe, handoff, public intake, and analytics must remain off. Remove it after the native email
receipts are captured and replace it with a normal evidence-bearing
`EMAIL_SANDBOX` manifest. The regular sandbox preflight deliberately requires
only `EMAIL_SANDBOX`; ARC2 still requires `CLAIM_SANDBOX` before a sandbox
claim mutation. While the email `TEST_BOOTSTRAP` authority is active, only
`email.sandbox_delivery_receipt_sha256` may use the all-zero not-yet-collected
sentinel. Provider-account configuration plus native webhook and suppression
readbacks remain mandatory and nonzero.

The same circularity is closed once, separately, for the claim test. A
`CLAIM_SANDBOX` `TEST_BOOTSTRAP` must carry the completed email evidence,
remain in the exact test-only sandbox tuple, and expire within 15 minutes. The
ARC2 strong store atomically binds it to one deterministic paid review-session
handoff before mutation. The payment-link path, a second handoff, live mode,
and continuation without that binding are rejected. This exception does not
relax the paid Checkout ledger, reversal, recipient-continuity, suppression,
or post-claim provider checks. Replace it immediately with the normal
evidence-bearing `CLAIM_SANDBOX` manifest after reviewing the one bounded E2E
receipt.

| Transition | Minimum new proof |
| --- | --- |
| `OFF -> EMAIL_SANDBOX` | Native sandbox send, delivered event, bounce, complaint, and recipient-suppression receipts |
| `EMAIL_SANDBOX -> CLAIM_SANDBOX` | One-use review link, approval, two revision rounds, stale-link rejection, durable email outbox receipts, and bounce/complaint revocation of every open unpaid Checkout |
| `CLAIM_SANDBOX -> LIVE_CHECKOUT` | Stripe test Checkout, ledger webhook, tested `checkout.sessions.retrieve` and `checkout.sessions.expire` capabilities, payment-to-ARC2 sandbox claim-next/completion, reversal tests, adult/legal/tax approval, and live catalog readback without a charge |
| `LIVE_CHECKOUT -> PUBLIC_INTAKE` | Netlify deployed route/env readback, privacy/retention review, and public-intake provider E2E |
| `PUBLIC_INTAKE -> PILOT` | Bounded pilot acceptance and rollback evidence |
| `PILOT -> OUTREACH` | Separate outreach approval and final provider readback |

Any mismatch returns to `OFF`. Turn off the local flag, separately pause the
external provider control, remove the activation manifest, and retain only
redacted evidence digests.

## Exact mode split

The JSON contract is authoritative for every exact flag. Important invariants:

- sandbox uses `ARC_RUNTIME_ENVIRONMENT=sandbox`, test Stripe restricted keys,
  `ARC_STRIPE_LIVE_MODE_ENABLED=false`, test events allowed, no live handoff,
  and a non-required Checkout ledger;
- sandbox adult/business/tax/transactional-complete attestations and the
  reversal-required flag remain exact `false`; production requires them exact
  `true`;
- production uses `ARC_RUNTIME_ENVIRONMENT=production`, live Stripe restricted keys,
  `ARC_STRIPE_LIVE_MODE_ENABLED=true`, test events rejected, live handoff, and
  a required Checkout ledger;
- the review portal, durable email outbox, internal email API, revision outbox,
  review Checkout producer, Checkout revocation control, and payment bridge
  each have an independent exact boolean; and
- all booleans are absent or exact `false` in the committed/default state.

Use only `ARC_EXPECTED_PRODUCT_TAX_CODE`; the retired
`ARC_EXPECTED_STRIPE_PRODUCT_TAX_CODE` alias must be absent. Set exactly one of
`NETLIFY_ADMIN_PAT` or `NETLIFY_ACCESS_TOKEN`. Both-present is invalid even when
the values match, and the provider readback binds the single selected name.

Stripe uses one destination per mode at
`/internal/stripe/reversal-webhook` and one
`ARC_STRIPE_WEBHOOK_SIGNING_SECRET` for that destination. It must subscribe to
the exact JSON-contract union of four Checkout events and nine refund/dispute
events. A separate Checkout destination, an incomplete event selection, or a
readback for another endpoint remains blocked.

The native Resend path is one fail-closed unit: transactional attempt ledger,
encrypted recipient vault, Resend send, signed webhook, and worker must all be
exact `true` with valid distinct secrets. Preview-review Resend adds two exact
switches and a bound provider-account identity. Any partial tuple is invalid.
ARC2 claim-invitation, customer-requested claim-link renewal, and final-delivery
email stay off in sandbox and require three independent exact switches in
production; any requested stage also
requires the encrypted recipient vault and the shared provider-account HMAC
binding. Terminal email ledger retention is independently default-off and may
open only with an integer retention window from 7 through 365 days. Operations
alert delivery remains off in both profiles until its native delivery evidence
is separately reviewed.

The activation surface keeps the operations audit off in sandbox, requires its
signed queue in production whenever first-party retention is enabled, and keeps
alert delivery disabled until provider evidence exists. It names four distinct
audit/delivery secrets, sender/provider/recipient bindings, and all three
private routes. This is configuration surface only. While
`OPERATIONS_ALERT_PROVIDER_EVIDENCE` is blocked, `failure_alert_verified` stays
false and the native delivery receipt remains the all-zero not-yet-collected
sentinel. A reserve/ack call or email API acceptance is not provider proof.

Production also requires the default-off first-party cascade worker with
`ARC_FIRST_PARTY_RETENTION_ENABLED=true`, a distinct
`ARC_FIRST_PARTY_RETENTION_HMAC_SECRET`, exact unpaid/paid windows of 730/2555
days, and a current deployment-bound `ARC_FIRST_PARTY_RETENTION_RECEIPT`. That
receipt proves only the first-party Blob families were swept. It never clears
`RETENTION_PROVIDER_CASCADE_EVIDENCE`; Stripe, Resend, Netlify, and any other
provider deletion receipts remain separate external proof.

Every sandbox or production profile that can mutate retained first-party state
also requires `ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET`. The fence has no
enable flag: missing, malformed, or reused secret material keeps every gated
producer—including `intake-submit`—and the retention freezer fail-closed. Its
signed `OPEN`, `WRITING`, and `FROZEN` records coordinate those writers in the
dedicated
`arc-retention-control` store. This repository wiring is code evidence only;
there is no deployed fence intent, completion/finalize receipt, recovery alert,
or provider-cascade proof.

The production-only `POST /api/internal/retention/legal-hold` route accepts an
exact legal-hold input only from an operator holding the distinct
`ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER`, then persists a signed record. It
writes through the same global producer protocol; it must never be wrapped in a
second producer fence.

Do not copy a sandbox key, price, product, webhook destination, provider
account, Zap version, or Netlify site binding into production. The preflight
requires each mode's fresh readback to bind the deployed site, Stripe account,
catalog, checkout integration identifier, email provider, native webhook,
native suppression control, and exact Zap versions.

Production Checkout remains OFF unless the reversal-aware payment worker is
explicitly enabled and a fresh signed deployment readback proves the exact
`/internal/payment-arc2/start` contract. That route re-reads provider payment
authority, builds signed review-session payment evidence, calls
`startReviewHandoff`, and completes its outbox only from the durable signed ARC2
start receipt. Never set the reversal-required flag false to bypass it.

Native bounce/complaint acknowledgement now carries the same-recipient control
through `expireSuppressedRecipientReviewCheckouts` before suppression finishes.
It retrieves every indexed Session, expires only an open/unpaid bound Session,
retrieves it again, and halts fulfillment with a durable refund/manual-review
alert if the Session is already paid. Activation still requires the fresh
revocation-worker and provider-capability receipts; code presence alone is not
runtime proof.

## Secret ownership and separation

The JSON contract lists secret **environment names only**, their issuing
authority, and their minimum consumers. It contains no secret value. Generate
Netlify-owned secrets in the protected runtime secret store. Stripe-issued
keys remain in the matching test or live Stripe account. Give a Zap only the
single endpoint credential it needs.

Every listed secret must be 32–512 characters and byte-distinct from every
other listed secret. The review email API secret, revision worker bearer, and
payment worker bearer are three different credentials. The dedicated
`ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET` is required in both mutation
profiles and cannot reuse the retention-receipt HMAC, handoff-state, email,
Stripe, alert, bearer, API-key, or any other secret. The dedicated
`ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET` is distinct from all email, Stripe
reversal, Checkout, and payment bridge credentials. Test and live provider keys
and webhook signing secrets are different. Never put a value in Git, a URL, a
Zap field name, an activation receipt, a log, or CLI output.

ARC2 negative delivery state uses the separate
`ARC_ARC2_EMAIL_NEGATIVE_STATE_HMAC_SECRET`; it must not reuse a recipient-vault,
attempt-ledger, provider-binding, claim, or final-delivery secret.

## Email provider and Zapier boundary

The provider's native webhook must be the delivery/bounce/complaint source of
truth. The provider's native suppression control must be enabled and independently
read back. A Zapier email worker normalizes a verified native event and signs
the internal acknowledgement; it must never invent a delivery receipt from a
successful send API response.

The exact worker surfaces are:

| Worker | Claim/prepare | Complete/acknowledge |
| --- | --- | --- |
| Review email | `POST /api/internal/review-email/prepare`; `POST /api/internal/review-email/reserve` with exactly `{"claim_next":true}` | `POST /api/internal/review-email/ack` with a signed native provider receipt |
| Revision | `POST /api/internal/review-revision/claim` with exactly `{"cursor":null}` | `POST /api/internal/review-revision/complete` |
| Payment-to-ARC2 sandbox only | `POST /internal/payment-arc2/claim` with only a fresh random `claim_token` | `POST /internal/payment-arc2/complete` after a durable signed ARC2 start receipt |

Zapier must use one paused version per worker while preflight evidence is
collected. Each claim-next loop must be concurrency-one, retain its durable
idempotency binding, complete only after the downstream durable receipt, and
leave the record retryable after a timeout. Do not route transactional review
email through a personal Gmail mailbox.

## Fresh readback receipt

Set `ARC_REVIEW_ACTIVATION_READBACK_JSON` only from an access-controlled
operator process after independent API/dashboard reads. The exact schema is
enforced by `scripts/review-activation-preflight.mjs`. It contains only hashes,
non-secret route names, the provider slug, timestamps, and the deployed commit.
Sandbox requires it to be current: no older than 15 minutes and expiring within
15 minutes. In production it is a shape/binding bootstrap reference only; its
window must still be at most 15 minutes, but it may be historical. Production
currentness comes only from the separately signed durable runtime receipt.
Production additionally requires
`ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED=true`, a canonical HTTPS
`ARC_REVIEW_ACTIVATION_VERIFIER_URL`, and a pinned Ed25519 SPKI public key in
`ARC_REVIEW_ACTIVATION_VERIFIER_ED25519_PUBLIC_KEY`. The verifier refreshes a
durable signed runtime receipt; the static JSON value alone is never live
Checkout authority. The current deployment-bound, HMAC-signed activation
manifest's `live_checkout_readback` digest binds the canonical stable verifier
authority (deployed SHA, verifier URL/key fingerprints, provider bindings,
environment-name set, route matrix, and 900-second ceiling), not one mutable
receipt. Every runtime envelope must carry that authority digest and a valid
Ed25519 signature; a manifest naming another authority never opens Checkout.
See `operations/review-activation-runtime-readback.md`.

The receipt binds:

- Netlify site ID, deployed commit, Function-scoped environment-name set, the
  selected single handoff-credential name, exact route matrix, and live probes;
- Stripe account hash, price/product/integration identifiers, catalog and
  single webhook endpoint plus complete event-set readbacks, and executed
  `checkout.sessions.retrieve` and
  `checkout.sessions.expire` capability receipts;
- email provider account, sender identity, native webhook integration, native
  suppression integration, and a sandbox delivered-event receipt; and
- exact Zap workflow IDs/versions, an executed claim-next contract receipt, a
  provider-bound `/internal/payment-arc2/start` receipt, and a
  suppression-to-Checkout-expiry revocation worker receipt; and
- operations-alert audit/delivery state and the explicit absence of native
  failure-alert delivery proof while that control remains blocked.

`provider_controls_state` must still be `OFF`. Passing preflight means a
candidate is internally consistent; it is not permission to activate, proof
that a provider is live, or permission to charge, email, publish intake, or
start outreach.

Run the safe default check with:

```sh
npm run preflight:review
```

Sandbox and production candidate checks are intentionally explicit:

```sh
node scripts/review-activation-preflight.mjs --mode=sandbox
node scripts/review-activation-preflight.mjs --mode=production
```

The report emits only status, boolean checks, environment names, and blocker
codes. It never emits a secret, binding value, activation manifest, provider
receipt, or raw readback JSON. A sandbox or production command returns
`*_CONFIGURED` only when every exact binding, capability receipt, workflow
receipt, and fresh deployment readback is present and the profile has no
committed blocker. The current production profile therefore returns
`PRODUCTION_BLOCKED`; this is configuration evidence, not permission to
activate. OFF remains the committed default.
