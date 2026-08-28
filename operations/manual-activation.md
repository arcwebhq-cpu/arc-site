# ARC manual activation gate

Status: **nothing in this document is proof of readiness**. Live checkout,
customer email, Zapier, Apollo, and automatic Netlify claims must remain disabled
until every evidence item below is independently verified. Do not place identity
documents, tax records, bank data, API secrets, raw customer data, or account IDs
in Git, public URLs, email links, or chat.

The runtime also requires the signed, expiring, deployment-bound ordered
authority in [`activation-manifest.md`](./activation-manifest.md). It is a local
fail-closed backstop, not evidence that an external dashboard is configured or
disabled. The current committed baseline is `OFF`; no activation manifest or
activation secret belongs in Git.

Operators must create the exact v2 unsigned object and sign it with
`signActivationManifest` as shown in that document; never hand-format JSON or
put the HMAC secret on a command line. `COMMIT_REF` is captured only during
`npm run build` into the Function bundle and is not a runtime variable. For
reviewed `PILOT`/`OUTREACH` steady state, use the documented current/NEXT
seven-day overlap procedure and independent dual review before the current
authority expires. This repository does not itself verify or disable external
provider dashboards.

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

The only connected context observed during the August 25, 2026 audit was the ARC
live Stripe account; no ARC test or sandbox context was available. Stripe
reported charges and payouts enabled, details submitted, and a representative
record present; the accessible fields did not verify legal age or contracting
authority. The public profile now identifies ARC, links
`https://arcweb.onl`, and has support contact details configured. Those
improvements are **not** launch proof. Stripe Tax remains pending because the
head office is missing, no tax registration exists in Stripe, automatic tax is
disabled on the observed live link, and no webhook endpoint is configured.

The active legacy website-build Payment Link is for the correct $5,000 USD
one-time amount, but it represents the superseded offer and must remain
undistributed and off the V11 path. It must not be repurposed for the fixed five-page service. It
has no successful payments, uses Stripe's hosted confirmation instead of the
verified ARC success handoff, does not require terms consent, and collects a
phone number. A stale active $100 Price has one successful live payment that
remains unrefunded. An active $500 monthly support offer has no subscriptions but
contradicts the published one-time, no-renewal scope. Do not distribute any live
link or enable live selling until the adult operator resolves and re-verifies
every mismatch, including the historical $100 payment.

In the correct ARC account, the adult representative must complete verification,
bank/payout ownership, business/public details, support contact, statement
descriptor, terms/privacy/refund URLs, and Stripe Tax activation. The adult
representative must confirm registration and tax obligations with qualified
advisers; any Stripe Tax registration must reflect a registration that is
already active with the relevant authority.

Create a fresh Product plus separate test and eventual live one-time Prices for
the **ARC fixed five-page website — $5,000 service subtotal plus applicable
destination tax**. V11 creates a private, approval-bound Checkout Session only
after the customer approves the exact preview; the returned Session must have
`payment_link=null`. Do not create or distribute a reusable Payment Link for
this offer. Bind offer contract
`arc-fixed-five-page-offer-v1`, terms version `2026-08-25`, and the exact approved
five-page artifact manifest. Require automatic tax only after the applicable
registration is active and verified, then require
billing address, terms consent, the adult-authority acknowledgement, business
name, and individual name. Keep promotion codes, optional items, adjustable
quantity, manual payment-method lists, subscriptions, invoice creation, and
phone collection off. Redirect only to the exact ARC success URL.

Store restricted keys and webhook secrets only in the provider secret vault.
Create one Stripe event destination per mode at
`/internal/stripe/reversal-webhook`, using one signing secret and the complete
Checkout plus refund/dispute event union in
`operations/review-activation-environment.json`; do not split those events
across two destinations. Record only the expected account-ID hash, Product ID,
Price ID, canonical Product tax code, Checkout integration identifier, and terms
version in runtime configuration. Run all five
industry scenarios in Stripe test mode. Do not use a real card as a production
smoke test. Any observed Payment Link belongs to the legacy-only inventory and
is not V11 activation evidence.

Use only the canonical product tax-code binding
`ARC_EXPECTED_PRODUCT_TAX_CODE`. The retired
`ARC_EXPECTED_STRIPE_PRODUCT_TAX_CODE` alias is not part of the V11 activation
environment and must be absent. A missing canonical binding or any retired
alias keeps Checkout and handoff disabled.

## 3. Connect the ARC Netlify handoff account

The August 25, 2026 deployment observation confirmed that both `arcweb.onl` and
`arcsites.netlify.app` served the exact reviewed index bytes from main commit
`5c4b853133e526f7ccbbf7d4e44a006a172f1fd0`; the reviewed build and both live
responses had SHA-256
`2811e658cd21ea93d025ee8c9802400a7f49b8835e9d2b81d574ce9a54b7d3ea`.
GitHub Actions run `32821861690` (`ARC site quality`) completed successfully,
and the public readiness endpoint still reported `intake_enabled=false`. This
proves the observed public build identity only. It does not prove access to the
production provider settings, Function-scoped environment values, webhook or
workflow routing, or any activation gate.

The production project remains on its legacy owner team, and a separate ARC-team
recovery mirror with no custom domain or environment variables must stay
disabled and must not be treated as the production identity. Obtain authorized
membership in the legacy owner team before editing production settings. Do not
recreate the live project, move the domain, or change Netlify DNS during this
access step.

Do not add a catch-all redirect from `arcsites.netlify.app` to `arcweb.onl` until
every provider callback, webhook, API, claim, and stored workflow URL using the
alias has been inventoried and migrated. Alias retirement is deliberately
deferred; an early redirect could break non-browser provider traffic.

The adult account holder must supply the real ARC team slug/account ID, a
least-privilege deployment credential, an OAuth client ID/secret, approved
callback origin, and a separate destination test account. Secrets belong only in
Netlify's encrypted environment-variable store.

The handoff runtime accepts the deployment credential as either
`NETLIFY_ADMIN_PAT` or the workflow-facing alias `NETLIFY_ACCESS_TOKEN`, but the
activation environment must contain **exactly one** of those names. Both-present
is invalid even when the values match; neither-present is also invalid. The
provider environment-name readback must identify the selected name without
exposing its value.

`ARC_HANDOFF_ENABLED` is the master kill switch and must remain absent or
`false` until every handoff attestation and disposable end-to-end test below is
verified. Set it to `true` only during the authorized claim-automation activation
step; never commit it.

Scope all handoff secrets to **Functions** and **Production** only in Netlify's
Secrets Controller. Set `ARC_EXPECTED_NETLIFY_SITE_ID` to the production ARC site
ID and set the explicit Function-scoped attestation
`ARC_RUNTIME_ENVIRONMENT=production`. Scope is the production-context boundary;
at runtime the code additionally
requires exact `SITE_ID`, `SITE_NAME=arcsites`, and canonical `URL` origin equal
to `ARC_PUBLIC_ORIGIN`. Netlify does not expose build-only `CONTEXT` or
`DEPLOY_PRIME_URL` reliably to Functions, so they are not runtime identity gates.
The disabled test deployment must instead use `ARC_RUNTIME_ENVIRONMENT=sandbox`
with the exact sandbox site identity. Probe these runtime values on a disposable
disabled deploy before activation.

Use a disposable synthetic site to prove: deterministic site recovery after an
ambiguous API response, exact ZIP deploy, Netlify form detection, one enabled
recipient hook, rendered-form submission, authoritative inbox receipt, claim
transfer, destination-account verification, exact final redeploy, and cleanup.
Every newly created handoff site uses the producer-compatible deterministic name
`arc-lead-route-<24 lowercase hex>`; the committed cross-repository contract
must pass against `ARC_PREVIEWS_DIR` before activation.
Inventory stored handoffs before activation. Any old `arc-<24 lowercase hex>`
record earlier than `INVITATION_READY` is deliberately quarantined: neither an
exact start replay nor an invitation receipt can make that namespace satisfy the
committed producer. Keep it untouched until a separately reviewed private
migration is approved. Old-namespace records already at `INVITATION_READY` or
later may continue through the downstream migration path without renaming their
existing Netlify site.
Confirm in writing whether the creator credential retains the API read/write
capability required after claim; an unsigned claim callback alone is not proof.
The customer invitation wrapper may remain available for 30 minutes, but each
irreversible Netlify claim JWT issued after a fresh reversal guard expires after
60 seconds. A reversal arriving after issuance cannot revoke an already issued
external JWT; the guarded post-transfer readback must halt delivery and route
the transferred site to adult review. Treat this narrow cross-provider window
as a documented residual until Netlify offers revocation.

The current local service is disabled preparation, not activation-ready. Before
the master switch can change, engineering must also: unify the lead/inbox receipt
producer and consumer against the actual handoff site; reserve all remaining
provider/inbox receipt IDs globally; verify served bytes and zero snippets;
split long work into bounded resumable steps with fetch timeouts and crash tests;
and recheck Stripe refund/dispute state before every irreversible transition.
The repository now has a default-off Resend send adapter, a create-only
idempotent attempt ledger, an encrypted recipient/recovery vault, and raw-body
Svix webhook verification. Those primitives are wired only to intake
confirmation. The preview-review producer still lacks a recoverable raw
recipient/token capsule, and ARC2 final delivery still lacks a discoverable
ready index plus a recoverable recipient/claim-URL capsule. Therefore the
existing final-delivery acknowledgement consumer is not a complete producer and
customer email must remain disabled. Configure `ARC_FINAL_DELIVERY_RECEIPT_SECRET`
and the distinct endpoint bearer `ARC_FINAL_DELIVERY_ACK_SECRET` only when that
producer and its signed delivery-webhook integration are ready. Confirm the
Netlify plan can enforce every configured rate-limit rule (or consolidate to the
plan limit) and inspect deploy processing logs.

Official implementation guide:
https://developers.netlify.com/guides/deploying-sites-from-ai-tools/

## 4. Activate public intake only after routing proof

ARC no longer deploys a native Netlify Forms registration. Native form handling
cannot be revoked at request time and therefore allowed direct POSTs around a
paused browser UI. An enabled build posts only to the first-party
`/api/intake/submit` Function, which rechecks readiness before a private Blob
write. The default build strips the POST method and endpoint, makes the form
inert, and visibly says requests are paused. After durable acceptance, an exact
same-origin HTML document navigation receives a `303 /thank-you/`; API requests
keep the JSON acceptance response. The redirect requires the exact allowed URL
origin plus same-origin Fetch Metadata and cannot be selected with `Accept`
alone. This preserves JavaScript and no-JavaScript form use without weakening
the runtime gate.

The repository and observed production commit now contain the **default-OFF**
first-party ARC1 adapter for `arc-intake-function-submission-v1`. Its presence in
the deployed commit is not provider activation: no provider invocation or exact
signed ACK has been verified. A normal Zapier Catch Hook is not the bridge
endpoint and cannot produce ARC's synchronous response. The reviewed endpoint is
`https://arcweb.onl/internal/intake/arc1/adapter`. Before its exact signed ACK,
the adapter re-creates and authenticates the canonical bridge envelope, reads
the source through strong Blob consistency, validates the actual stored image
bytes, requires every content-addressed private asset index, and atomically
creates an immutable ingress record, then creates its recovery index; no ACK is
returned until both writes succeed. The durable record
contains no raw answers or asset bytes, but it retains a pseudonymous source
submission pointer and is therefore still subject to the intake retention and
access policy.

Only after that durable claim exists does a separately gated background
Function submit a byte-bounded envelope (never inline asset bytes) to the exact
Catch Raw Hook. Its five-attempt state uses compare-and-set leases, signed
cursor/shard recovery, quarantine for corrupt indexes, and terminal dead-letter
alert fields. No consumer delivers those alerts yet. Exact HTTP 200 means only
**HOOK_ACCEPTED**. The adapter keeps the pending index after that response and
starts a 15-minute claim deadline. The signed v2 packet binds its exact claim and
completion endpoints, issue/expiry times, bridge identifiers, and complete
canonical payload with `ARC_INTAKE_ARC1_PACKET_SECRET`.

The unpublished consumer must then POST one canonical, bearer-authenticated
claim to `/internal/intake/arc1/adapter/claim`. A compare-and-set claim accepts
one stable `consumer_attempt_id`, returns a 30-minute lease token, stores only
its digest, returns an exact replay to the same attempt, and rejects a competing
attempt. A claim racing hook persistence receives retryable HTTP 425. There is
no automatic reassignment in this release: a missing or expired claim becomes
terminal `REVIEW_REQUIRED`. The repository now places the covered mutation
routes behind the signed generation-fence protocol, but no deployed intent,
completion/finalize receipt, or stale-recovery alert proves that runtime wiring.
Review evidence is create-only and durable before the pending index can be
removed.

After a durable downstream result exists, the same attempt must POST a canonical
receipt to `/internal/intake/arc1/adapter/complete`. The receipt is bound to the
delivery, full packet digest, attempt, lease token, completion time, and immutable
result digest, and authenticated with `ARC_INTAKE_ARC1_CONSUMER_RECEIPT_SECRET`.
Only its successful compare-and-set transition to **COMPLETED** clears ordinary
pending work. Exact completion replay self-heals an interrupted terminal-index
cleanup; altered receipt replay fails closed. None of this proves the external
Zap or generator has been configured or exercised.

All of these runtime switches must remain absent or `false` until the disabled
provider proof is reviewed: `ARC_INTAKE_ARC1_ADAPTER_ENABLED`,
`ARC_INTAKE_ARC1_BRIDGE_ENABLED`, `ARC_INTAKE_ARC1_DISPATCH_ENABLED`,
`ARC_INTAKE_ARC1_DOWNSTREAM_ENABLED`, and
`ARC_INTAKE_ASSET_RETRIEVAL_ENABLED`,
`ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED`, and
`ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED`,
`ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED`,
`ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED`, and
`ARC_INTAKE_CONFIRMATION_CONSUMER_ENABLED`, and
`ARC_INTAKE_EMAIL_VERIFICATION_ENABLED`. The required private values are
`ARC_INTAKE_ARC1_PACKET_SECRET`, `ARC_INTAKE_ARC1_CONSUMER_BEARER`, and
`ARC_INTAKE_ARC1_CONSUMER_RECEIPT_SECRET`, plus the distinct confirmation
outbox, consumer bearer, and receipt secrets and the four verification
state/token/recipient/release HMAC secrets. Every value must be 32–256 UTF-8
bytes and distinct from every other ARC authority. The v2 packet producer and paired
consumer are pinned to `https://arcweb.onl`; the Netlify alias may serve public
fallback pages but cannot originate this private protocol. The required adapter
attestation is valid
for at most 24 hours; no static value is an ongoing health proof, so its safe
rotation procedure is also a pre-activation requirement. The recovery endpoint
has no schedule and must be called with each authenticated `next_cursor` until
`RECOVERY_COMPLETE` during a disabled test.

The safe committed/runtime baseline is:

```dotenv
ARC_INTAKE_ARC1_ADAPTER_ENABLED=false
ARC_INTAKE_ARC1_BRIDGE_ENABLED=false
ARC_INTAKE_ARC1_DISPATCH_ENABLED=false
ARC_INTAKE_ARC1_DOWNSTREAM_ENABLED=false
ARC_INTAKE_ASSET_RETRIEVAL_ENABLED=false
ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED=false
ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED=false
ARC_INTAKE_ARC1_LEGACY_MIGRATION_ENABLED=false
ARC_INTAKE_ARC1_RECOVERY_AUTOMATION_ENABLED=false
ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED=false
ARC_INTAKE_CONFIRMATION_CONSUMER_ENABLED=false
ARC_INTAKE_EMAIL_VERIFICATION_ENABLED=false
ARC_TRANSACTIONAL_EMAIL_ENABLED=false
ARC_TRANSACTIONAL_EMAIL_WORKER_ENABLED=false
ARC_ARC2_CLAIM_LINK_RENEWAL_ENABLED=false
ARC_EMAIL_RECIPIENT_VAULT_ENABLED=false
ARC_RESEND_SEND_ENABLED=false
ARC_RESEND_WEBHOOK_ENABLED=false
```

When enabled by a reviewed build, `/api/intake/submit` first creates a 24-hour
mailbox challenge, seals the recipient and fragment verification URL in the
AES-GCM vault, and then creates one deterministic provider-neutral confirmation
outbox plus pending index before returning an accepted response. Exact retries
recover those same records. The outbox and consumer claim contain only keyed
recipient/vault identities, fixed template metadata, one lease token, and the
provider idempotency key. The one-minute worker opens the bound capsule and
sends “Confirm email to start your free preview.” API acceptance and
`email.sent` are no-resend evidence only. The one-time same-origin confirmation
must be consumed before foreground or recovery dispatch can release ARC1. See
`operations/intake-email-verification.md` for the exact state and signed-release
contract. A real disabled-provider test is still required, and review/final
delivery remain activation blockers.

The separate five-minute scheduled recovery runner is inert while its dedicated
switch is false. Once enabled, it persists each signed recovery cursor under a
compare-and-set lease. A crash resumes from the last committed cursor, and a
transient Blob read failure retains pending visibility instead of quarantining
availability failures as corruption.

Legacy unsigned v1 ingress records require the separate bounded
`/internal/intake/arc1/adapter/migrate-legacy` maintenance endpoint. It converts
them to `REVIEW_REQUIRED` and creates the review index; it never replays their
old hook. Its kill switch may be `true` only while every intake, dispatch,
downstream, asset, claim, and completion switch above is exactly `false`, and it
must be returned to `false` after every signed-cursor scan reaches
`MIGRATION_COMPLETE`.

Public intake remains disabled until the deployed adapter is exercised through a
provider-disabled test and its exact ACK, asset, retry, dedupe, secret-boundary,
completion-receipt, and alert paths are proven against the unpublished
downstream workflow. Only then may
`arc1_consumer_adapter_verified` change to `true` and a reviewed deploy set
`ARC_BUILD_INTAKE_ENABLED=true`. The build writes an immutable
`arc-intake-build-marker-v1` literal into the same Function bundle and compiles
the HTML from that same decision. The Function requires both that baked marker
and the separately scoped runtime flag on every request, so a mutable runtime
value cannot open a build compiled closed. It also checks the single
`ARC_INTAKE_READINESS_ATTESTATION` record below; this deliberately non-ready
example remains closed:

```json
{
  "schema": "arc-intake-readiness-attestation-v1",
  "version": 1,
  "intake_enabled": true,
  "route_verified": true,
  "recipient_verified": true,
  "dedupe_verified": true,
  "failure_alert_verified": false,
  "transactional_sender_verified": true,
  "adult_operator_verified": true,
  "legal_readiness_verified": true,
  "tax_readiness_verified": true,
  "payment_readiness_verified": true,
  "arc1_consumer_adapter_verified": false,
  "native_netlify_forms_disabled_verified": false,
  "retention_verified": false,
  "asset_pipeline_verified": false
}
```

The runtime rejects a missing, malformed, partial, oversized, wrong-version, or
unknown-field record. Every gate must be a JSON boolean and must be `true`, so
the example above cannot activate intake. Removing form attributes from HTML
does not prove a previously registered provider form stopped accepting direct
POSTs. In Netlify, disable form detection, deploy the updated form-free build,
then prove a controlled legacy `form-name=arc-preview` direct POST is rejected
and no Forms record or hook is created. If that cannot be proven on the current
site, migrate the production domain to a fresh project with Forms never enabled.
Only then may `native_netlify_forms_disabled_verified` become `true`.

The intake Function accepts at most 4,000,000 request bytes, 1,250,000 bytes per
image, 3,000,000 image bytes total, and 262,144 text bytes. At the request cap,
base64 transport is 5,333,336 bytes, leaving 666,664 bytes below Netlify's
6,000,000-byte buffered payload limit; max files plus max text also leave
737,856 raw request bytes for multipart framing. The browser enforces the same
1.25 MB per-file and 3 MB total limits. Folder-link imports are unavailable and
the server rejects that legacy field until a bounded, authenticated provider
adapter is implemented and verified. The Function also requires
`asset_permission` to equal exactly `Confirmed rights and no visible watermark v1` whenever a file is submitted. Earlier confirmation values are intentionally rejected so a submission cannot inherit the stronger v1 meaning without a fresh confirmation.
Client visibility or checkbox state is not authority.
Legacy `ARC_INTAKE_ENABLED` and `ARC_LEAD_ROUTE_VERIFIED` values do not open
public intake. Remove the record immediately when any evidence fails or becomes
stale. Before activation, inspect and delete any legacy retained test
submissions under the approved retention policy.

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
  attribution records. Remote hotlinks are not final-delivery evidence. The
  code contract now bundles receipt-bound uploaded images into the customer
  deploy, but its external ARC1-to-ARC2 wiring proof remains required and OFF.
- Named retention owner, provider-by-provider deletion schedule, monthly deletion
  record, incident contact, refund/dispute owner, and bookkeeping owner.
- Generate `ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET` separately from every
  other secret and import it only into the protected Netlify runtime. Both
  sandbox and production mutation preflights require 32–512 bytes and exact
  secret separation. Do not treat code presence, a local test, or a synthesized
  fence record as deployed retention or provider-deletion proof.
- Generate the production-only
  `ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_BEARER` separately and restrict it to the
  accountable operator calling `POST /api/internal/retention/legal-hold`.
- Before enabling first-party retention, set
  `ARC_OPERATIONS_AUDIT_ENABLED=true` with distinct audit and alert HMAC
  secrets. The retention worker must be able to persist its PII-free critical
  condition or it fails closed; alert email delivery remains separately gated.
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
   automatic tax, address collection, exact Product and Price, terms URLs, and
   the approval-bound private Checkout Session contract with `payment_link=null`
   immediately before activation. Keep every legacy Payment Link undistributed
   and off the V11 path.
7. Keep Apollo off until the separate outreach gate is complete.

Any failed, stale, missing, or mismatched check returns the system to disabled.

Operational companions: `incident-response.md`, `refund-dispute-runbook.md`,
`data-retention.md`, and `pilot-validation.md`.
