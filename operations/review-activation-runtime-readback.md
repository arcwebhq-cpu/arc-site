# Runtime provider readback

Status: **OFF by default**. This removes the operational dependency on a
15-minute JSON value frozen in Netlify environment configuration without
making provider evidence long-lived.

## Design

Production uses two independently checked layers:

1. The deployment-bound activation manifest's `live_checkout_readback`
   evidence digest binds a stable verifier authority: exact deployed SHA,
   verifier URL and Ed25519 public-key fingerprints, provider-binding digest,
   reviewed environment-name digest, route-matrix digest, and the 900-second
   freshness ceiling.
2. The verifier independently reads Netlify, Stripe, Resend, Zapier, and the
   operations-alert controls. It returns a new Ed25519-signed
   `arc-review-activation-runtime-readback-envelope-v1`. The receipt inside the
   envelope still expires within 15 minutes.

The scheduled Netlify Function polls the pinned HTTPS verifier every five
minutes, validates the signature and every provider/deploy binding, writes the
envelope to a deployment-and-authority-specific Netlify Blobs key using a
compare-and-set update, then strong-reads it. Older observations cannot replace
newer ones. Checkout strong-reads the same record on every request. If it is
missing or stale, Checkout attempts one signed refresh; any fetch, signature,
freshness, manifest, storage, deploy, provider, route, or binding failure closes
Checkout before acquiring recipient authority or contacting Stripe.

The verifier must generate receipts only from authenticated provider reads. It
must not copy a prior digest forward, convert a successful write response into
readback evidence, or sign a locally asserted value. Capability-test receipts
remain real retained evidence; volatile catalog/webhook/workflow/route digests
must reflect the current reads.

## Runtime configuration

Keep the switch `false` until the verifier has been independently deployed and
tested:

- `ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED=true`
- `ARC_REVIEW_ACTIVATION_VERIFIER_URL` — canonical HTTPS URL with no
  credentials, query, fragment, or non-default port
- `ARC_REVIEW_ACTIVATION_VERIFIER_ED25519_PUBLIC_KEY` — canonical base64 DER
  SPKI Ed25519 public key

The private signing key belongs only to the external verifier. Never put it in
Netlify. The public key and URL do not authorize Checkout by themselves: their
derived authority digest must be the current deployment-bound manifest's
`live_checkout_readback` evidence digest.

`ARC_REVIEW_ACTIVATION_READBACK_JSON` is retained only for the legacy sandbox
and operator/bootstrap inspection. Once the runtime switch is on, production
Checkout never falls back to that static value.

## Verifier response

Return `application/json` with no redirect and at most 32 KiB:

```json
{
  "schema": "arc-review-activation-runtime-readback-envelope-v1",
  "version": 1,
  "authority_sha256": "<derived authority digest>",
  "key_sha256": "<DER public-key digest>",
  "receipt": { "schema": "arc-review-activation-readback-v1" },
  "signature": "<canonical base64 Ed25519 signature>"
}
```

The signature input is UTF-8 bytes of the schema plus a newline plus canonical
sorted-key JSON of the envelope without `signature`. The receipt shape and all
required fields remain the exact contract in
`operations/review-activation-environment.json`.

## Preflight and rollback

Safe default:

```sh
npm run preflight:runtime-readback
```

For an access-controlled production check, place one freshly fetched signed
envelope in the temporary process variable
`ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_CANDIDATE_JSON`, use the exact deployed
build identity, and run the production mode of
`scripts/review-activation-runtime-readback-preflight.mjs`. The report emits
booleans/reason names only—not receipt contents, provider IDs, signatures, or
keys.

Rollback is fail-closed: set the runtime switch false together with the other
Checkout switches, remove both manifest slots, then independently disable the
external provider controls. Never switch production back to the static receipt
as a continuity shortcut.

This mechanism does not relax Stripe Tax. Immediately before creating every
live Checkout Session, the Checkout adapter still re-reads active Stripe Tax
settings and registrations and requires the configured Washington state sales
tax registration gate.
