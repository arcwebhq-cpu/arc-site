# Intake mailbox ownership gate

Status: **implemented, default OFF, not provider-verified**.

Public intake must not release an ARC1 preview from an unverified mailbox. The
accepted intake reserves a 24-hour challenge before the confirmation outbox is
made discoverable. The confirmation recipient and fragment verification URL are
sealed only in the AES-256-GCM email recipient vault. Verification state and
indexes contain no plaintext email address or bearer token.

The email links to `https://arcweb.onl/verify/#arcv1.<opaque bearer>`. URL
fragments are not sent in HTTP requests. The first-party page removes the
fragment with `history.replaceState` before POSTing the bearer in a bounded JSON
body to `/api/intake/verify`. The endpoint requires exact same-origin browser
headers, uses `Cache-Control: no-store` and `Referrer-Policy: no-referrer`, and
returns the same rejection for invalid, expired, and replayed links.

The durable state machine is:

`PENDING -> VERIFIED -> ARC1_RELEASED`

An expired pending challenge becomes `EXPIRED`. The browser bearer is consumed
once with a compare-and-set transition. Foreground and recovery dispatch both
return `AWAITING_EMAIL_VERIFICATION` while the state is pending. The ARC1
delivery boundary consumes `VERIFIED` into `ARC1_RELEASED` and produces a
separately HMAC-signed, source-digest-bound 24-hour release receipt before it may
create evidence, mutate delivery state, or enter network I/O. Exact retries can
replay only that same signed receipt; a different submission or source digest
cannot reuse it.

Required default-OFF controls:

```text
ARC_INTAKE_EMAIL_VERIFICATION_ENABLED=false
ARC_INTAKE_EMAIL_VERIFICATION_STATE_SECRET=<distinct 32-256 byte secret>
ARC_INTAKE_EMAIL_VERIFICATION_TOKEN_SECRET=<distinct 32-256 byte secret>
ARC_INTAKE_EMAIL_VERIFICATION_RECIPIENT_SECRET=<distinct 32-256 byte secret>
ARC_INTAKE_EMAIL_VERIFICATION_ARC1_RELEASE_SECRET=<distinct 32-256 byte secret>
```

Every value is independent of all ARC bridge, outbox, vault, provider, manifest,
and webhook authorities. The email recipient vault, native transactional worker,
verified Resend sender/domain, and signed Resend webhook must also be ready.

Do not activate public intake until a controlled end-to-end test proves:

1. submission stores the challenge and encrypted confirmation capsule before ACK;
2. no ARC1 request occurs before the mailbox link is consumed;
3. a valid click releases exactly one ARC1 job and receives the preview email;
4. invalid, expired, replayed, copied, and cross-origin requests never release ARC1;
5. logs, state exports, provider metadata, analytics, and URLs observed by the
   server contain no raw recipient or verification bearer; and
6. disabled-mode tests prove zero Blob, email-provider, ARC1, and network access.
