# Public intake abuse protection

Status: **OFF by default.** This control does not create a Cloudflare widget, secret, DNS record, or external account.

Public intake may open only when the build-scoped widget and the runtime verifier are both configured. The request path is deliberately ordered as follows:

1. Reject an unexpected method or exact `Origin` before reading the body.
2. Enforce the multipart byte limit.
3. Parse bounded multipart framing without decoding customer identity or uploaded images.
4. Send only the Turnstile token, request UUID, and trusted Netlify client IP (when available) to Cloudflare Siteverify.
5. Require `success: true`, exact hostname `arcweb.onl`, exact action `arc_intake_submit`, exact `cdata` request UUID, and a non-future challenge no older than the configured maximum (at most 300 seconds).
6. Consume a local HMAC-keyed replay guard, then normalize the recipient identity, check the signed circuit breaker and suppression records, and atomically reserve signed global, recipient-domain, and recipient quota slots.
7. Only then decode the remaining customer fields and images, persist the intake, reserve email verification/confirmation, and dispatch ARC1.

Any provider timeout, malformed response, configuration drift, replay, invalid signature, or ambiguous security-state read fails closed. Invalid challenges have zero intake, asset, vault, or email side effects.

## Build configuration

All four values are required to compile the public form open:

- `ARC_BUILD_INTAKE_ENABLED=true`
- `ARC_BUILD_TURNSTILE_ENABLED=true`
- `ARC_TURNSTILE_SITE_KEY=<public site key>`
- `ARC_TURNSTILE_EXPECTED_ACTION=arc_intake_submit`

If any widget value is missing or malformed, the build emits the paused form, the Function marker remains closed, and no Cloudflare script or widget enters `dist/`.

Create a managed Turnstile widget restricted to the exact production hostname. Do not proxy or cache Cloudflare's `api.js`. The checked-in CSP permits only Cloudflare's documented `https://challenges.cloudflare.com` script and frame origin.

## Runtime configuration

The runtime requires these exact controls:

- `ARC_INTAKE_ABUSE_PROTECTION_ENABLED=true`
- `ARC_TURNSTILE_SECRET_KEY=<runtime secret>`
- `ARC_TURNSTILE_EXPECTED_HOSTNAME=arcweb.onl`
- `ARC_TURNSTILE_EXPECTED_ACTION=arc_intake_submit`
- `ARC_TURNSTILE_MAX_AGE_SECONDS=300`
- `ARC_INTAKE_ABUSE_HMAC_SECRET=<independent 32+ byte secret>`
- `ARC_INTAKE_ABUSE_RECIPIENT_LIMIT` and `ARC_INTAKE_ABUSE_RECIPIENT_WINDOW_SECONDS`
- `ARC_INTAKE_ABUSE_DOMAIN_LIMIT` and `ARC_INTAKE_ABUSE_DOMAIN_WINDOW_SECONDS`
- `ARC_INTAKE_ABUSE_GLOBAL_LIMIT` and `ARC_INTAKE_ABUSE_GLOBAL_WINDOW_SECONDS`

Initial conservative limits for a controlled pilot are 2 requests per recipient per 86,400 seconds, 10 per recipient domain per 3,600 seconds, and 100 globally per 3,600 seconds. Raise limits only from observed legitimate traffic. The global limit opens a signed circuit breaker through the end of its current window.

The HMAC and Turnstile secrets must be unique and must not match any other ARC secret, token, bearer, API key, or PAT. The Turnstile secret is runtime-only; never inject it into HTML or build logs.

## Private abuse state

The `arc-intake-abuse-control` Blob store contains only HMAC-keyed identities and bounded control metadata:

- `challenge-replay/` — one-time provider token digests;
- `quota/global/`, `quota/domain/`, and `quota/recipient/` — create-only window slots;
- `suppression/domain/` and `suppression/recipient/` — signed, expiring records;
- `circuit-breaker/current-v1` — signed, expiring global breaker.

No record or key may contain a raw email address, raw email domain, Turnstile token, IP address, uploaded file, or provider secret. `buildIntakeAbuseSuppressionRecord` is the only supported record constructor; permitted reasons are `DELIVERY_COMPLAINT`, `LEGAL`, `MANUAL_ABUSE`, and `SECURITY`. Write suppression records only from authenticated operator tooling, never a public route.

Retention cleanup must delete expired replay, quota, suppression, and circuit-breaker records. A failed cleanup keeps intake closed if the required retention attestation is not current.

## Verification before activation

Run `node tests/intake-abuse-protection-contract.mjs`, then the full `npm test`. The contract covers forged origins; invalid, expired, future, mismatched, and replayed challenges; distributed-IP attempts against one recipient; rollback of partial quota reservations; PII-free suppression state; and zero image/persistence/email work on challenge rejection.

Cloudflare references: [server-side validation](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/), [client rendering](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/), and [CSP](https://developers.cloudflare.com/turnstile/reference/content-security-policy/).
