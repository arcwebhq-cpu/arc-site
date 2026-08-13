# ARC refund and dispute runbook

Status: operational template. Only the verified adult operator may authorize a
real refund. Never act in the currently connected non-ARC Stripe account.

1. Locate the exact ARC Checkout Session and PaymentIntent in the authoritative
   ARC Stripe account. Match account hash, mode, Payment Link, Price, customer,
   approved preview hash, subtotal, tax, total, and fulfillment record.
2. Confirm the published refund policy version accepted at checkout and whether
   claim/final delivery occurred. Preserve the customer's request and evidence.
3. Check for a prior refund, dispute, duplicate request, or pending asynchronous
   payment. A retry must read current Stripe state before any mutation.
4. The adult operator records the decision and amount. A full cancellation
   refund includes collected sales tax; partial refunds must use Stripe Tax's
   corresponding reversal/reporting treatment and accountant-approved records.
5. Submit one refund with an idempotency key bound to the PaymentIntent and
   decision record. Record Stripe's refund ID and final status outside Git.
6. Send one factual confirmation only after Stripe accepts the refund. Do not
   promise bank timing; state that card/bank processing varies.
7. For a dispute, stop duplicate refunds, preserve terms/consent/preview/delivery
   evidence, follow Stripe's deadline, and have the adult operator decide whether
   to accept or respond. Never fabricate evidence or contact the cardholder to
   pressure withdrawal.

Reconcile tax filings, revenue, and any customer-site access after the refund.
Refunding payment does not authorize deleting records that law or an active
dispute requires, and does not authorize retaining customer data indefinitely.
