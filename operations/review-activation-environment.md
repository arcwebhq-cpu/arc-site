# Review, email, Checkout, and payment-to-ARC2 activation environment

Status: **OFF by default**. This contract does not enable a Netlify Function,
Zap, Stripe destination, email integration, public form, pilot, or outreach
sequence. It defines the evidence required before an adult operator changes one
stage. The canonical machine-readable companion is
`operations/review-activation-environment.json`.

## One ordered activation path

Use only this order, one transition at a time:

`OFF -> EMAIL_SANDBOX -> CLAIM_SANDBOX -> LIVE_CHECKOUT -> PUBLIC_INTAKE -> PILOT -> OUTREACH`

The signed activation manifest in `operations/activation-manifest.md` remains
the runtime authority. This preflight is an additional provider/environment
binding check; neither one replaces the other. A candidate may advance only
after both checks pass, every provider control is independently read back, and
the bounded end-to-end receipt for that transition has been reviewed.

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

- sandbox uses `ARC_RUNTIME_ENVIRONMENT=sandbox`, test Stripe keys,
  `ARC_STRIPE_LIVE_MODE_ENABLED=false`, test events allowed, no live handoff,
  and a non-required Checkout ledger;
- production uses `ARC_RUNTIME_ENVIRONMENT=production`, live Stripe keys,
  `ARC_STRIPE_LIVE_MODE_ENABLED=true`, test events rejected, live handoff, and
  a required Checkout ledger;
- the review portal, durable email outbox, internal email API, revision outbox,
  review Checkout producer, Checkout revocation control, and payment bridge
  each have an independent exact boolean; and
- all booleans are absent or exact `false` in the committed/default state.

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
`ARC_STRIPE_REVIEW_REVOCATION_HMAC_SECRET` is distinct from all email, Stripe
reversal, Checkout, and payment bridge credentials. Test and live provider keys
and webhook signing secrets are different. Never put a value in Git, a URL, a
Zap field name, an activation receipt, a log, or CLI output.

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
It must be no older than 15 minutes and must expire within 15 minutes.
For production Checkout, the canonical JSON digest must also be the
`live_checkout_readback` evidence digest in the current deployment-bound,
HMAC-signed `LIVE_CHECKOUT` activation manifest. An unsigned environment value
or a valid manifest that names a different readback never opens Checkout.

The receipt binds:

- Netlify site ID, deployed commit, Function-scoped environment-name set, the
  exact route matrix, and live route probes;
- Stripe account hash, price/product/integration identifiers, catalog and
  webhook readbacks, and executed `checkout.sessions.retrieve` and
  `checkout.sessions.expire` capability receipts;
- email provider account, sender identity, native webhook integration, native
  suppression integration, and a sandbox delivered-event receipt; and
- exact Zap workflow IDs/versions, an executed claim-next contract receipt, a
  provider-bound `/internal/payment-arc2/start` receipt, and a
  suppression-to-Checkout-expiry revocation worker receipt.

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
receipt, and fresh deployment readback is present. This is configuration
evidence, not permission to activate; OFF remains the committed default.
