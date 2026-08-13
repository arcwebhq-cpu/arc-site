# ARC manual activation gate

Status: **nothing in this document is proof of readiness**. Live checkout,
customer email, Zapier, Apollo, and automatic Netlify claims must remain disabled
until every evidence item below is independently verified. Do not place identity
documents, tax records, bank data, API secrets, raw customer data, or account IDs
in Git, public URLs, email links, or chat.

The repository should leave only the following human/account-holder work.

## 1. Name the accountable business

- An adult representative must accept responsibility for the Stripe account and
  be authorized to bind the business. Stripe requires an adult representative
  when the user or representative is under 18.
- The operator must choose and form the legal structure, obtain any EIN needed,
  choose a real business and mailing address, designate the Washington registered
  agent if an entity is formed, and choose governing law/venue with counsel.
- Obtain the Washington business license, UBI/tax account, required city
  endorsement, and filing schedule. Custom website development has been subject
  to Washington retail sales tax and retailing B&O tax since October 1, 2025.
- Have a Washington-qualified accountant or lawyer confirm the contract, tax
  sourcing, refunds, record retention, and treatment of sales outside Washington.
- Clear the proposed legal name, trade name, and marks before filing or spending
  on branding. "ARC" is crowded in web/design services; a web search is not a
  trademark or Washington entity-name clearance.

Evidence kept outside Git: adult authority, entity/sole-proprietor decision, EIN
if applicable, UBI, active license/endorsements, registered/mailing address,
filing frequency, and dated professional review.

Official starting points:

- https://stripe.com/legal/ssa
- https://dor.wa.gov/open-business
- https://dor.wa.gov/taxes-rates/retail-sales-tax/services-newly-subject-retail-sales-tax/custom-website-development
- https://www.sos.wa.gov/corporations-charities/business-entities/online-filing-instructions/start-domestic-wa-limited-liability-company-llc-online
- https://www.irs.gov/businesses/small-businesses-self-employed/responsible-parties-and-nominees

## 2. Connect the real ARC Stripe account

The connected account observed during the August 12, 2026 audit was not an ARC
account. Do not create, edit, or charge anything there for ARC.

In the correct ARC account, the adult representative must complete verification,
bank/payout ownership, business/public details, support contact, statement
descriptor, terms/privacy/refund URLs, and Stripe Tax activation. Register with
Washington before creating or activating a Washington Stripe Tax registration.

Create separate test and live one-time Prices and Payment Links for a **$5,000
service subtotal plus applicable destination tax**. Require automatic tax,
billing address, terms consent, the adult-authority acknowledgement, business
name, and individual name. Keep promotion codes, optional items, adjustable
quantity, manual payment-method lists, subscriptions, invoice creation, and
phone collection off. Redirect only to the exact ARC success URL.

Store restricted keys and webhook secrets only in the provider secret vault.
Record only the expected account-ID hash, Payment Link ID, Price ID, and terms
version in runtime configuration. Run all five industry scenarios in Stripe test
mode. Do not use a real card as a production smoke test.

## 3. Connect the ARC Netlify handoff account

The adult account holder must supply the real ARC team slug/account ID, a
least-privilege deployment credential, an OAuth client ID/secret, approved
callback origin, and a separate destination test account. Secrets belong only in
Netlify's encrypted environment-variable store.

`ARC_HANDOFF_ENABLED` is the master kill switch and must remain absent or
`false` until every handoff attestation and disposable end-to-end test below is
verified. Set it to `true` only during the authorized claim-automation activation
step; never commit it.

Scope all handoff secrets to **Functions** and **Production** only in Netlify's
Secrets Controller. Set `ARC_EXPECTED_NETLIFY_SITE_ID` to the production ARC site
ID. Scope is the production-context boundary; at runtime the code additionally
requires exact `SITE_ID`, `SITE_NAME=arcsites`, and canonical `URL` origin equal
to `ARC_PUBLIC_ORIGIN`. Netlify does not expose build-only `CONTEXT` or
`DEPLOY_PRIME_URL` reliably to Functions, so they are not runtime identity gates.
Probe these runtime values on a disposable disabled deploy before activation.

Use a disposable synthetic site to prove: deterministic site recovery after an
ambiguous API response, exact ZIP deploy, Netlify form detection, one enabled
recipient hook, rendered-form submission, authoritative inbox receipt, claim
transfer, destination-account verification, exact final redeploy, and cleanup.
Confirm in writing whether the creator credential retains the API read/write
capability required after claim; an unsigned claim callback alone is not proof.

The current local service is disabled preparation, not activation-ready. Before
the master switch can change, engineering must also: unify the lead/inbox receipt
producer and consumer against the actual handoff site; reserve provider/inbox
receipt IDs globally; verify served bytes and zero snippets; split long work into
bounded resumable steps with fetch timeouts and crash tests; recheck Stripe
refund/dispute state before every irreversible transition; add provider delivery
acknowledgement; and make outbox claims non-actionable until authoritative final
state exists. Confirm the Netlify plan can enforce every configured rate-limit
rule (or consolidate to the plan limit) and inspect deploy processing logs.

Official implementation guide:
https://developers.netlify.com/guides/deploying-sites-from-ai-tools/

## 4. Activate public intake only after routing proof

The default production build strips Netlify form registration and the direct
POST method, so a visitor cannot bypass the paused UI and create unmonitored PII
submissions. Only after the real recipient, retention, notifications, provider
usage, and one controlled submission are verified may a reviewed deploy set
`ARC_BUILD_INTAKE_ENABLED=true`; the independent runtime variables
`ARC_INTAKE_ENABLED=true` and `ARC_LEAD_ROUTE_VERIFIED=true` are still required.
Before activation, inspect and delete any legacy retained test submissions under
the approved retention policy.

## 5. Connect private workflow state and transactional email

- Create the private Zapier Tables/state records and secret values named in
  `arc-previews/zapier/wiring-contract.json`.
- Wire ARC1 and ARC2 exactly in the documented order, with create-only claims,
  compare-and-set transitions, unique-submission rate limits, and durable
  PENDING/CLAIMED/SENT outboxes.
- Replace the currently connected non-ARC Gmail account with the intended ARC
  operations account. Use a branded-domain sender, not a free Gmail sender.
- Publish SPF, DKIM, and DMARC; verify the support inbox and the actual client lead
  inbox; prove unsubscribe/suppression handling before any marketing email.
- Keep the existing Apollo ARC sequence paused. It may not be activated until a
  valid postal address, accurate sender/subject, one-click unsubscribe,
  suppression, complaint handling, and an adult-approved outreach policy exist.
  Review and deliberately re-qualify every already-enrolled contact first; never
  let activation release a dormant backlog automatically.

CAN-SPAM source: https://www.ftc.gov/legal-library/browse/statutes/controlling-assault-non-solicited-pornography-marketing-act-2003-can-spam-act

## 6. Supply operational facts the software cannot invent

- Decide which historical/customer-like preview folders are authorized to remain
  in the public `arc-previews` repository. Approve a private migration and a
  separately reviewed history-redaction plan before any destructive purge.
- Verified lead-routing recipient and branded support sender.
- Client-supplied production domain and privacy-policy URL for each project.
- Content-addressed owned copies of uploaded and stock assets, plus license and
  attribution records. Remote hotlinks are not final-delivery evidence.
- Named retention owner, provider-by-provider deletion schedule, monthly deletion
  record, incident contact, refund/dispute owner, and bookkeeping owner.
- Real Safari, Firefox, iPhone, and Android acceptance results.

ARC currently has fictional concept work, not verified customer outcomes. Treat
the $5,000 positioning as unvalidated until real adult-operated sales discovery,
qualified conversations, and paid pilot results support it. Do not publish
invented testimonials, client logos, conversion claims, or guarantees.

## 7. Final activation sequence

1. Complete sections 1-6 without sending secrets or identity documents to Git.
2. Run the repository gates and five synthetic test purchases end to end.
3. Review the evidence bundle with the adult operator and tax/legal reviewer.
4. Enable transactional email only; verify one synthetic delivery and dedupe.
5. Enable Netlify claim automation only; verify one disposable transfer and
   cleanup.
6. Enable live Stripe last. Confirm account-ID hash, active tax registration,
   automatic tax, address collection, exact Price/Payment Link, and terms URLs
   immediately before activation.
7. Keep Apollo off until the separate outreach gate is complete.

Any failed, stale, missing, or mismatched check returns the system to disabled.

Operational companions: `incident-response.md`, `refund-dispute-runbook.md`,
`data-retention.md`, and `pilot-validation.md`.
