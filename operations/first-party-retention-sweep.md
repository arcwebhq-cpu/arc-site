# ARC first-party retention sweep

Status: **implemented, default OFF, and not deployed or provider-verified**.

`first-party-retention-worker.mjs` is scheduled but returns `204` without
opening Blob stores unless every retention setting and distinct source-state
secret is valid. A production target uses:

- `ARC_FIRST_PARTY_RETENTION_ENABLED=true`
- `ARC_FIRST_PARTY_RETENTION_UNPAID_DAYS=730`
- `ARC_FIRST_PARTY_RETENTION_PAID_DAYS=2555`
- a dedicated `ARC_FIRST_PARTY_RETENTION_HMAC_SECRET`
- a separate 32–512-byte `ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET`,
  byte-distinct from every other runtime secret
- `ARC_OPERATIONS_AUDIT_ENABLED=true` with distinct
  `ARC_OPERATIONS_AUDIT_SECRET` and `ARC_OPERATIONS_ALERT_HMAC_SECRET`
- the same-deploy identity bundled in `activation-build-identity.mjs`

The global fence is always-on for any gated mutation, including intake
submission; there is deliberately no fence enable flag. Missing, malformed, or
reused fence material makes producers and the freezer return unavailable
without mutating customer state. Producers use `OPEN(N) -> WRITING(N)`,
deterministic operation identity, strong
source/tombstone rereads, strong output readback, and an immutable signed
completion receipt before `OPEN(N+1)`. A partial failure remains `WRITING`; an
exact retry resumes or validates that operation rather than releasing the lock.

Apply a production legal hold only through authenticated
`POST /api/internal/retention/legal-hold` with the dedicated
`ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER`. The route calls the legal-hold
producer fence directly, so a crash after the hold CAS leaves `WRITING` for the
same signed operation to resume; it does not release or nest the gate.

The retention worker reads `OPEN(N)`, builds a fully paginated signed
one-subject manifest outside the lock, and freezes only by CAS if the generation
is still N. Under `FROZEN` it rechecks legal holds, tombstones exact children and
the primary last, verifies readback, writes a signed finalize receipt, and then
reopens. Generation drift restarts manifest construction. Signed intents and
receipts govern stale `WRITING`/`FROZEN` recovery; ordinary contention retries
without a permanent alert, while a genuinely stale fence produces a critical
signed alert. A marked but missing source produces a signed anomaly and blocks
completion.

Every fenced producer and freezer, including the legal-hold writer and the
scheduled workers, validates each signed stale-fence alert and synchronously
enqueues a PII-free, deduplicated critical condition in
`arc-operations-alerts`. A queue configuration or write failure fails that
mutation route closed; immutable fence evidence remains blocked and exact
retries reattempt queue delivery. Ordinary live lock contention does not
enqueue an alert. Alert notification delivery remains a separately blocked
provider control.

The family sweep still processes a bounded page per call and creates a signed
PII-free completion receipt containing family counts and the deploy digest. The
`ARC_FIRST_PARTY_RETENTION_RECEIPT` activation binding must be that exact current
receipt; a boolean cannot substitute for it. The receipt HMAC and fence HMAC are
separate authorities.

Candidate evidence binds the exact source-record digest. Every destructive
child, index, and primary step strongly re-reads that source and revalidates its
signature, terminal state, current legal hold, and (for paid handoffs) exact
release immediately before mutation. A reopened, paid, replaced, or newly held
record is preserved with signed PII-free stale-candidate evidence.

## Rules

- Expired Turnstile replay, quota, non-legal suppression, and circuit records
  are deleted. `LEGAL` suppressions are preserved.
- Invalid or stale nonterminal records are preserved behind signed PII-free
  quarantine evidence. They are never guessed terminal.
- Review records are candidates only after the unpaid window and only when the
  state proves no active decision, or an approved, revoked, or superseded
  lineage whose Checkout binding is terminal and unpaid.
  Email outboxes, provider indexes, renewal state, revision work, Checkout
  bindings/indexes, pending entries, and unused recipient controls are removed
  before the invite primary.
- Revocable Checkout bindings delete only from `EXPIRED` or `CANCELLED` with
  no paid status. `REVIEW_REQUIRED`, open, creating, and expiry-pending rows are
  held or quarantined.
- Paid handoffs delete only from authoritative `DELIVERED`, after the paid
  window, with no negative-email control, no reversal review state, no legal
  hold, and a current signed release bound to the exact handoff record. The
  release must attest completed payment/tax/dispute retention review and
  verified Netlify transfer. Child indexes are removed before the primary.
- An unresolved duplicate-paid review uses its production
  `winning_handoff_id` binding and blocks the winning handoff cascade; it is
  quarantined for adult resolution, never deleted as an ordinary child.

## Honest activation boundary

A first-party completion receipt proves only these Netlify Blob cascades.
Stripe, Resend, Netlify account data/backups, Zapier, GitHub, Gmail, Apollo, and
other providers still need their own real deletion/readback evidence. Keep
`RETENTION_PROVIDER_CASCADE_EVIDENCE` blocked until that evidence exists.
No signed fence intent, producer completion, finalize receipt, missing-source
anomaly, stale-lock alert, deployed sweep receipt, or provider deletion proof
has been collected from a deployed runtime yet.
