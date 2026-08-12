# ARC customer email contract

These templates are the approved minimum copy for the proposed workflow. Dynamic
values must come from verified project state; email text must never unlock
publication or delivery by itself. The automatic claim workflow remains disabled
until resumable deployment, signed inbox-receipt evidence, replay-safe claim
exchange, and customer-authorized post-claim verification are implemented and
tested. The future state model must separately record durable invitation issuance
and successful claim-wrapper exchange; those transitions are not implemented yet.

## Preview ready

**Subject:** Your ARC website preview is ready

Hi {{customer_name}},

Your unlisted ARC preview for {{business_name}} passed our website checks:

{{preview_url}}

Two consolidated preview revision rounds are included before purchase. Reply to
this email with one complete revision list per round. If you approve the current
preview as-is, use the $5,000 Stripe checkout inside the preview. Payment confirms
approval of the then-current preview for production handoff.

ARC never needs your full card number by email.

## Checkout verification

**Subject:** ARC checkout verification in progress

Hi {{customer_name}},

ARC is verifying the Checkout Session directly with Stripe. This page or email is
not confirmation that payment succeeded and does not start production by itself.
If verification succeeds and all required content, routing, and account access are
complete, target delivery is within seven business days.

Status: {{payment_success_url}}

## Ownership claim invitation

**Subject:** Claim your ARC website in Netlify

Hi {{customer_name}},

ARC prepared an unlisted, noindex handoff deploy, sent an exact synthetic
submission through its rendered Netlify form, and verified receipt in the
authoritative lead inbox. Use the one-time claim invitation below within the
stated window. Form and hook configuration alone never authorizes this email:

{{claim_invitation_url}}

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
