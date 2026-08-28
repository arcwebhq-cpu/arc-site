# ARC data-retention control

Status: **not active across every provider**. This document is an operational requirement, not proof that cleanup has already run.

No analytics-prune schedule is registered. The handler is also an exact
default-off no-op unless an adult operator separately approves and sets
`ARC_ANALYTICS_PRUNE_AUTOMATION_ENABLED=true`. Keep it unset while the mandate
is to leave all automation OFF.

When separately activated, analytics pruning builds a signed, fully paginated,
bounded one-event manifest outside the global gate, verifies the same OPEN
generation, and freezes only that event. Under FROZEN it strongly rereads the
source, replaces it only by exact-ETag CAS with a signed PII-free terminal
tombstone, verifies readback, writes a signed finalize receipt, and reopens the
next generation. Exact crash retries resume the same manifest. A listed source
that disappears creates signed anomaly and critical-alert evidence and leaves
FROZEN blocked. It never issues an unconditional delete.

## Targets

- Unsubmitted browser drafts: never restored after 7 days; cleared on the next
  ARC visit after expiry, immediately after a confirmed successful request, or
  when the visitor clears site data. ARC cannot delete local browser storage
  while the site is closed.
- First-party aggregate analytics: delete after 90 days once the separately approved default-off prune control is activated.
- QA submissions, test emails, test uploads, and temporary test sites: delete within 14 days after the evidence bundle is recorded.
- Unpaid preview requests, submitted assets, generated previews, workflow state, and related email: delete or de-identify within 24 months after the last interaction, and sooner when no longer needed.
- Paid-project, payment, tax, dispute, and security records: retain only for the period the adult legal operator confirms is required.

## Activation evidence required

1. Name the accountable adult operator before live payment.
2. Inventory the exact first-party Netlify Function/Blobs intake records and
   uploads, including `arc-intake-submissions`,
   `arc-intake-confirmation-outbox`, `arc-email-recipient-vault`,
   `arc-transactional-email-attempts`, and
   `arc-operations-alert-delivery`; then inventory Resend transactional-email
   messages, events, and suppression state; Zapier Tables; GitHub previews and
   deliveries; Stripe; backups; and the separately controlled Gmail/Apollo
   outreach stores.
3. Configure automated deletion where the provider supports it.
4. Create a monthly deletion task for every remaining store, with an immutable completion record that contains counts but no customer data.
5. Run one synthetic expired-record test through each store and prove the intended record is deleted without deleting an in-scope record.
6. Record backup/provider exceptions and the actual expiration window.

An application-level `expires_at` that only blocks future reads is not deletion.
The confirmation outbox and mailbox-verification state retain only keyed
identifiers and delivery/state evidence; the raw recipient and fragment link are
sealed in the encrypted recipient vault. Vault and transactional-attempt sweeps
manually consume every provider page with authenticated continuation,
quarantine stale `INTENT`/`PROVIDER_ACCEPTED` attempts, delete terminal attempt
reverse/event indexes as one cascade, and persist a signed PII-free completion
receipt. The separate default-off first-party sweep covers abuse, review,
revocable Checkout, revision, and paid-handoff Blob families. Its CAS state
authenticates every continuation, bounded phases resume after a crash,
malformed or stale nonterminal rows are quarantined, and paid handoffs require
a short-lived adult/provider release. See `first-party-retention-sweep.md`.
These are code controls, not evidence that a deployed sweep or any
external-provider deletion has run.

All covered first-party mutation producers and the freezer share a signed
generation fence in `arc-retention-control`. Sandbox and production mutation
preflights require the dedicated
`ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET`; it must be 32–512 bytes and
byte-distinct from the retention-receipt HMAC and every other secret. There is
no bypass flag. Code defaults fail closed on missing configuration, partial
`WRITING`/`FROZEN` work, generation drift, or a missing marked source. No
deployed fence receipt, stale-recovery alert, sweep completion receipt, or
external-provider deletion proof currently exists.

Every production fenced mutation and retention freezer additionally requires
the signed operations alert queue for stale recovery. A genuine stale fence is
synchronously enqueued as a PII-free critical condition and deduplicated there;
any queue outage keeps the route fail-closed and exact retry reattempts queue
delivery. Normal generation contention retries without an alert. Notification
delivery is a separate provider-evidence gate.

| Store / provider | Required cascade or preservation rule | Release state |
| --- | --- | --- |
| `arc-intake-submissions` email-verification state/token indexes | Delete only with the exact expired unpaid source after proving no active ARC1 release | Provider-wide cleanup not verified |
| `arc-intake-confirmation-outbox` outbox/pending indexes | Delete only with that source and only when terminal or never claimed; ambiguous live claims quarantine | Provider-wide cleanup not verified |
| `arc-email-recipient-vault` | Cursor-sweep every expired encrypted capsule | Code complete; deployed completion receipt required |
| `arc-transactional-email-attempts` | Cursor-sweep terminal attempt, provider-message reverse index, and every provider-event index together; quarantine stale nonterminal attempts | Code complete; deployed completion receipt required |
| `arc-intake-abuse-control` | Authenticated expiry sweep for challenge replay, quota, suppression, and circuit-breaker records; `LEGAL` suppression remains held | Code complete, default OFF; deployed completion receipt required |
| `arc-preview-reviews` | Delete only expired unpaid terminal lineages after terminal email/revision/Checkout children and recipient indexes are cascaded; preserve active legal/incident holds | Code complete, default OFF; deployed completion receipt required |
| Stripe | Apply the accountable operator's payment, tax, dispute, refund, and legal-hold policy using provider controls | External evidence required |
| `arc2-handoffs` | Delete a delivered paid handoff only after the paid window, no negative/reversal review state, no legal hold, and a current signed adult/provider release bound to the exact record; delete child indexes before the primary | Code complete, default OFF; no provider release or deployed completion receipt exists |

Treat every raw address, ciphertext capsule, and keyed email identifier as
personal information until a tested delete path removes it from the primary
store and the provider's documented backup window expires.

Apollo must remain off and live checkout must remain blocked until this control is active and evidenced.
