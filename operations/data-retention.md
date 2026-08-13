# ARC data-retention control

Status: **not active across every provider**. This document is an operational requirement, not proof that cleanup has already run.

## Targets

- Unsubmitted browser drafts: automatic deletion after 7 days and after a successful request.
- First-party aggregate analytics: automatic deletion after 90 days.
- QA submissions, test emails, test uploads, and temporary test sites: delete within 14 days after the evidence bundle is recorded.
- Unpaid preview requests, submitted assets, generated previews, workflow state, and related email: delete or de-identify within 24 months after the last interaction, and sooner when no longer needed.
- Paid-project, payment, tax, dispute, and security records: retain only for the period the adult legal operator confirms is required.

## Activation evidence required

1. Name the accountable adult operator before live payment.
2. Inventory the exact first-party Netlify Function/Blobs intake records and uploads, Zapier Tables, Gmail, GitHub, Stripe, and backup locations.
3. Configure automated deletion where the provider supports it.
4. Create a monthly deletion task for every remaining store, with an immutable completion record that contains counts but no customer data.
5. Run one synthetic expired-record test through each store and prove the intended record is deleted without deleting an in-scope record.
6. Record backup/provider exceptions and the actual expiration window.

Apollo must remain off and live checkout must remain blocked until this control is active and evidenced.
