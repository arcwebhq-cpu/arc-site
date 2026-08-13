# ARC customer email contract

These templates are the approved minimum copy for the proposed workflow. Dynamic
values must come from verified project state; email text must never unlock
publication or delivery by itself. The automatic claim workflow remains disabled
until resumable deployment, signed inbox-receipt evidence, replay-safe claim
exchange, customer-authorized post-claim verification, and the real email
provider are configured and tested. The claim service may reserve a durable
`READY` invitation outbox and bearer, but that means only “ready for the email
provider.” It must never be represented as sent. A separate provider receipt is
required before any workflow records email delivery. Claim-state evidence records
invitation readiness and successful claim-wrapper exchange, not email delivery.
Its issuance time is the immutable final-verification time; status reads must not
refresh it. The email gate rejects it after the freshness window.

## Preview ready

**Subject:** Your ARC website preview is ready

Hi {{customer_name}},

Your unlisted ARC preview for {{business_name}} passed our website checks:

{{preview_url}}

Two consolidated preview revision rounds are included before purchase. Reply to
this email with one complete revision list per round. If you approve the current
preview as-is, use the Stripe checkout inside the preview. The service subtotal is
$5,000 USD and applicable destination-based sales tax is added before payment.
The checkout must show subtotal, tax, and total. Payment confirms
approval of the then-current preview for production handoff.

ARC never needs your full card number by email.

## Checkout verification

**Subject:** ARC checkout verification in progress

Hi {{customer_name}},

ARC is verifying the Checkout Session, $5,000 service subtotal, applicable tax,
final total, purchaser destination, and consent directly with Stripe. This page or email is
not confirmation that payment succeeded and does not start production by itself.
If verification succeeds and all required content, routing, and account access are
complete, target delivery is within seven business days.

Status: {{payment_success_url}}

## Ownership claim invitation

**Subject:** Claim your ARC website in Netlify

Hi {{customer_name}},

ARC prepared an unlisted, noindex handoff deploy, sent an exact synthetic
submission through its rendered Netlify form, and verified receipt in the
authoritative lead inbox. Use the time-limited claim invitation below within the
stated window. Form and hook configuration alone never authorizes this email.
If the first redirect is interrupted, the same confidential invitation may be
retried until that window closes:

{{claim_invitation_url}}

The service-generated value must use exactly
`https://arcweb.onl/claim/#arc2.<64-lowercase-hex-handoff-id>.<43-character-base64url-bearer>`.
The bearer is permitted only in the URL fragment. It must never appear in a URL
path, query, server log, browser storage, DOM text, or analytics event. Opening
the wrapper immediately clears the fragment before a same-origin authenticated
POST and then redirects only to Netlify's validated official claim URL.

Treat this bearer invitation like a password. Do not forward it. Sending this
invitation does not prove ownership handoff or mean the site is launch-ready.

## Verified final handoff

**Subject:** Your ARC website ownership handoff is ready

Hi {{customer_name}},

Netlify destination-account control, the exact final deploy, and the durable
delivery outbox were independently verified:

{{production_url}}

This final email must not include a claim URL, OAuth credential, Netlify access
token, or other bearer secret.

Follow the handoff steps, connect the final domain, then submit one real lead-form
test before advertising the site. Your 30-day launch-bug support period begins
when the verified ownership handoff is completed. This is not a claim that the
site is fully launch-ready: the final domain, client-supplied privacy policy, real
lead inbox, and one real lead-form submission must still be confirmed.
