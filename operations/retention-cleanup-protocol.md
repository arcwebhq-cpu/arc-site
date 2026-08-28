# ARC retention cleanup protocol

Status: **code complete for one first-party class, disabled, dry-run first, and not a provider-wide retention control**.

The cleanup endpoint can delete only exact `arc-intake-submissions` records that an adult-reviewed, signed manifest classifies as an unpaid preview, whose last interaction is at least 730 days old, and whose ARC1 delivery/dispatch history is absent or still pristine with zero attempts. Any claimed, acknowledged, failed, dead-lettered, or ambiguous delivery history is preserved for review. It deletes the embedded uploads with the record. It cannot delete ARC2 payment/tax/dispute/security records, Gmail, Zapier, GitHub, Stripe, Netlify sites, backups, or provider logs.

## Protocol

1. Inventory the record and confirm it is not linked to a payment, tax record, dispute, incident, legal hold, or active customer work.
2. Calculate the canonical record SHA-256 and create an exact one-target
   (one-subject) manifest using schema `arc-retention-manifest-v1`, policy
   `2026-08-13`, and mode `dry-run`. Multi-target legacy invocations fail
   before taking the global lock.
3. Sign the canonical manifest with the dedicated manifest secret and call `/internal/retention/cleanup` with the separate endpoint bearer.
4. Review the immutable dry-run completion. It must show the exact same sorted
   target-set digest, every target eligible, and zero missing, young, held, or
   deleted records. Dry-run never creates a deletion intent and never deletes
   data. Its gate-finalize evidence is explicitly domain-bound as
   non-destructive; only the mode-bearing legacy completion describes the
   dry-run result.
5. The endpoint validates the complete signed manifest outside the global
   generation lock, then CAS-freezes the exact observed OPEN generation. For
   apply, recheck legal holds, obtain accountable-adult approval, and set the
   apply attestations.
   Create a new signed `apply` manifest bound to the exact dry-run ID, dry-run
   manifest digest, and target set. Its `adult_approval_hmac_sha256` must be the
   dedicated adult-approval HMAC over those exact bindings and the apply run ID.
   A changed or partial target set cannot reuse the approval.
6. The function creates a durable delete intent, rechecks the legal-hold key,
   uses an ETag CAS to replace only the exact unchanged PII record with a
   non-PII terminal tombstone, reserves an immutable tombstone claim, strongly
   verifies the tombstone, and creates a PII-free receipt. It never follows the
   CAS with an unconditional physical delete. A signed global finalize receipt
   reopens the next generation only after strong output readback. A retry
   reconciles crashes at each step; a concurrent record update is preserved.
   A missing manifest target persists a signed missing-source anomaly and
   leaves FROZEN blocked rather than writing a completion.
7. Run the operations audit. An unresolved delete intent becomes a critical pending alert after 15 minutes.

Netlify Blobs cannot transact a legal-hold key with a deletion. The immediate recheck reduces but does not eliminate the race, so apply mode requires a provider-write freeze. Paid, disputed, legally required, unclassified, changed, young, malformed, missing-without-intent, and non-allowlisted records fail closed or are skipped.

## Environment contract

- `ARC_RETENTION_CLEANUP_ENABLED=true`
- `ARC_RETENTION_EXECUTION_MODE=dry-run` for the first run; `apply` only for an approved deletion window
- `ARC_RETENTION_CLEANUP_SECRET` — endpoint bearer
- `ARC_RETENTION_MANIFEST_SECRET` — signed-manifest HMAC secret
- `ARC_RETENTION_RECORD_HMAC_SECRET` — durable target identity HMAC secret
- `ARC_RETENTION_ADULT_APPROVAL_SECRET` — distinct HMAC secret for the exact adult-approved apply run
- `ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET` — distinct signed global generation-fence secret
- apply only: `ARC_RETENTION_ADULT_OPERATOR_VERIFIED=true`
- apply only: `ARC_RETENTION_LEGAL_HOLD_CHECK_VERIFIED=true`
- apply only: `ARC_RETENTION_DELETION_VERIFIED=true`

There is intentionally no schedule. The default is disabled, and deployment does not activate cleanup. Provider-by-provider deletion and backup exceptions in `data-retention.md` remain launch blockers until separately evidenced.
