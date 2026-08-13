# ARC incident response

Status: operational template. The accountable adult operator and contact channel
must be filled and tested outside Git before launch.

## Stop conditions

Immediately disable checkout, ARC1/ARC2, customer email, Apollo, and claim
issuance when any of these occurs: wrong Stripe/Netlify account, duplicate or
uncertain payment fulfillment, exposed credential or claim bearer, unexpected
deploy, misrouted lead, unauthorized asset, lost audit state, privacy complaint,
provider compromise, or a failed readiness attestation.

## First hour

1. Preserve timestamps, immutable provider IDs, hashes, and non-sensitive logs.
   Do not copy secrets, full addresses, form answers, or card data into tickets.
2. Revoke or rotate the narrowest affected credential; do not rotate blindly if
   doing so would destroy evidence or interrupt containment.
3. Pause the affected provider automations and prevent new claims/charges/sends.
4. Identify affected customers, sites, deploys, submissions, and time window from
   authoritative provider records—not caller-supplied status fields.
5. Notify the accountable adult operator. Escalate payment issues to Stripe,
   hosting/claim issues to Netlify, and suspected crime to appropriate counsel or
   authorities. Never make public claims before facts are verified.

## Recovery

- Reconcile every ambiguous write by deterministic identity and exact content
  hash before retrying. Never create a second site, send a second invitation, or
  fulfill a second time merely because a response was lost.
- Restore only the exact reviewed deploy. Re-run payment, tax, recipient,
  ownership, lead-route, and final-byte verification.
- Customer communication must be plain, timely, scoped to verified facts, and
  approved by the accountable operator. Include protective action the recipient
  can take; never email bearer credentials or sensitive evidence.
- Reactivate one subsystem at a time after a synthetic test and independent
  review. Apollo returns last and only through its separate compliance gate.

## Closure record

Record incident ID, start/end, reporter, systems, root cause, affected count,
containment, credential rotations, customer/legal notifications, refunds, exact
recovery evidence, owner, and dated prevention tasks. Store the private record in
the approved incident system, not the public repositories.
