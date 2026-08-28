# ARC ordered activation manifest

Status: **OFF by default**. No manifest, activation secret, provider receipt, or
enabled control is committed. A manifest is a short-lived local runtime
authority; it does not turn on Stripe, Netlify, email, Zapier, Apollo, or any
other external dashboard and it cannot turn those providers off. Provider
configuration and independent readback remain separate adult-operated gates.

## Ordered stages

Stages are ordered; higher stages require cumulative earlier evidence:

`OFF -> EMAIL_SANDBOX -> CLAIM_SANDBOX -> LIVE_CHECKOUT -> PUBLIC_INTAKE -> PILOT -> OUTREACH`

Each stage carries every earlier evidence kind in the exact order below.

| Stage | New evidence kind required at that transition |
| --- | --- |
| `OFF` | none |
| `EMAIL_SANDBOX` | `email_sandbox_e2e` |
| `CLAIM_SANDBOX` | `claim_sandbox_e2e` |
| `LIVE_CHECKOUT` | `adult_legal_tax_approval`, `checkout_test_e2e`, `live_checkout_readback` |
| `PUBLIC_INTAKE` | `public_intake_privacy_retention_review`, `public_intake_provider_e2e` |
| `PILOT` | `pilot_acceptance` |
| `OUTREACH` | `outreach_approval` |

The only pre-evidence exception is `TEST_BOOTSTRAP`, and it is limited to the
next single sandbox receipt. At `EMAIL_SANDBOX` it contains no evidence. At
`CLAIM_SANDBOX` it must still contain the reviewed `email_sandbox_e2e`
receipt; only the not-yet-created `claim_sandbox_e2e` receipt is omitted. Both
forms expire within 15 minutes and are accepted only for the explicit sandbox
tuple: test events on, live Stripe off, handoff off,
public-intake/build/analytics controls off, and any configured Stripe key in
test mode. Both are rejected for `LIVE_CHECKOUT` and `PUBLIC_INTAKE`, so they
cannot authorize a live charge or public form.

The claim bootstrap has one additional runtime fence. Before any handoff,
provider, or ARC2 state mutation, its manifest is atomically bound in the
strong ARC2 store to exactly one deterministic paid review-session handoff.
An exact retry of that handoff may continue while the same manifest remains
current; another handoff, the legacy payment-link start path, a missing
binding, or an expired/deployment-mismatched manifest fails closed. Every
ordinary paid-session, Stripe ledger, reversal, recipient-continuity,
suppression, and Netlify ownership check remains in force. Remove the
bootstrap after the bounded run and issue a normal `CLAIM_SANDBOX` manifest
whose `claim_sandbox_e2e` digest names the reviewed receipt.

The runtime minimums are deliberately narrower than the names imply:

- sandbox ARC2 configuration requires `CLAIM_SANDBOX`;
- production ARC2 mutations require `LIVE_CHECKOUT`;
- public intake and analytics collection require `PUBLIC_INTAKE`;
- analytics additionally requires exact prune automation to be enabled; and
- `preflight:live`, which includes public intake, requires `PUBLIC_INTAKE`.

A higher valid stage satisfies a lower minimum. A manifest alone never enables
a local boolean switch. Removing the manifest or its secret, letting it expire,
or turning the relevant local switches off closes the local path. Operators
must separately disable any external provider control when rolling back.

Every ARC1 background job, bridge delivery, adapter ingress/dispatch/recovery,
consumer claim/completion, legacy migration, and private-asset egress rechecks a
current `PUBLIC_INTAKE` authority at execution time before authentication-secret
parsing, Blob access, or network entry. A job queued while authority was valid
therefore fails closed if the manifest is missing, expired, deployment-mismatched,
or below `PUBLIC_INTAKE` when the queued invocation starts.

The public-asset readiness gate additionally requires the HMAC-signed ARC1
adapter attestation's `asset_producer_consumer_tests_sha256` to equal the
`public_intake_provider_e2e` digest in the current deployment-bound manifest.
Code presence or a mutable boolean can never satisfy that gate.

## Exact manifest contract

Keep these values only in the provider's encrypted, Function-scoped
environment:

- `ARC_ACTIVATION_MANIFEST` — the canonical signed JSON string;
- `ARC_ACTIVATION_MANIFEST_NEXT` — an optional, independently reviewed signed
  manifest used for an overlap rotation or a new deployment SHA; and
- `ARC_ACTIVATION_MANIFEST_HMAC_SECRET` — a dedicated 32–256 byte secret that
  is byte-distinct from every other secret, bearer, PAT, token, password,
  credential, or key.

`COMMIT_REF` is **not** runtime configuration. Netlify documents `COMMIT_REF`
as a [read-only build variable](https://docs.netlify.com/build/configure-builds/environment-variables/#read-only-variables).
`scripts/build-site.mjs` accepts only an exact 40-character
lowercase hexadecimal value and writes it into the non-secret generated
`netlify/lib/activation-build-identity.mjs` bundled with that deploy's
Functions. Runtime validation reads only that immutable module and never trusts
a runtime `COMMIT_REF`. An absent local build value generates `deployment_sha:
null`; a malformed value fails the build. Both cases prevent activation.

The unsigned object must contain these keys in this exact order and no others:

```json
{
  "schema": "arc-ordered-activation-manifest-v2",
  "version": 2,
  "stage": "EMAIL_SANDBOX",
  "authority_mode": "ROLLOUT",
  "issued_at": "2026-08-26T18:00:00.000Z",
  "expires_at": "2026-08-26T19:00:00.000Z",
  "deployment_sha": "0000000000000000000000000000000000000000",
  "evidence": [
    {
      "kind": "email_sandbox_e2e",
      "receipt_ref": "audit:0000000000000000",
      "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}
```

The zero values above are format examples, not evidence. `receipt_ref` must be
an internal pseudonymous reference in the form
`<3-32 lowercase label>:<16-64 lowercase hex>`. It must not contain a raw
provider ID, customer identity, email address, payment ID, or secret. `sha256`
is the digest of the reviewed, access-controlled receipt. Evidence remains
outside Git.

Use the repository helper, rather than hand-assembling an HMAC:

```js
import { signActivationManifest } from '../netlify/lib/activation-manifest-core.mjs';

const canonicalSignedJson = signActivationManifest(unsignedObject, dedicatedSecret);
```

The helper signs the canonical unsigned JSON with HMAC-SHA-256 using the domain
`arc-ordered-activation-manifest-v2\n`, appends the lowercase hexadecimal
`signature`, and returns the only accepted canonical serialization. Never log
the secret or place it on a command line. Store the returned string as
`ARC_ACTIVATION_MANIFEST` only after a second operator verifies the stage,
evidence digests, expiry, and deployed SHA.

`issued_at` and `expires_at` must be millisecond-precision UTC timestamps.
`TEST_BOOTSTRAP` authority may last at most 15 minutes and is valid only for
the exact sandbox constraints above. Its `EMAIL_SANDBOX` evidence array is
empty; its `CLAIM_SANDBOX` evidence array contains exactly the prior
`email_sandbox_e2e` receipt.
`ROLLOUT` authority may last at most 24 hours and is required through
`PUBLIC_INTAKE`. A `STEADY_STATE` authority is accepted only at `PILOT` or
`OUTREACH`, may last at most 90 days, and must append these exact reviewed
evidence receipts: `steady_state_dual_control_review`,
`steady_state_rotation_rehearsal`, and `steady_state_alert_route_e2e`. All
profiles allow at most 60 seconds of positive clock skew and fail closed at the
expiry boundary.

## Gap-free steady-state rotation

The 90-day ceiling avoids a daily operational hard stop without creating
permanent authority. Runtime results expose `rotation_due` during the final
seven days. Monitor a non-secret preflight result at least daily and alert both
independent reviewers at seven days, three days, and 24 hours; test that alert
route before every steady-state issuance and retain its digest as the required
receipt.

During the window, two reviewers create a replacement manifest before the old
one expires. Put it in `ARC_ACTIVATION_MANIFEST_NEXT` while leaving the current
slot intact. Both slots are validated independently against the build identity;
the runtime may use either valid sufficient candidate. For a code deployment,
the next manifest is signed for the new SHA, so the old deploy retains its
captured current authority while the new bundle selects only the matching next
authority. Verify the new deploy and preflight, promote NEXT to current, then
remove the old value. This overlap is the no-gap path; removal or expiry of all
matching candidates still fails closed. Secret rotation uses a separately
reviewed deploy because both overlap slots share the one dedicated HMAC secret.

## Activation and rollback check

1. Keep all local and provider controls off while collecting synthetic/test
   evidence for the next single stage.
2. Verify the deployed commit SHA and provider readbacks independently.
3. Create one short-lived manifest for exactly that SHA and stage.
4. Run safety, sandbox, or live preflight as applicable. Review only boolean
   results; the report intentionally emits no secret, signature, evidence, or
   deployment SHA.
5. Enable only the controls authorized for that stage, then re-run an external
   provider readback and a bounded synthetic test.
6. On any mismatch, turn local switches off, remove the manifest, and separately
   disable the relevant external dashboard control. Preserve only redacted
   incident evidence.

`OFF` needs no manifest and no activation secret. That is the committed and
safe operating baseline for this repository.
