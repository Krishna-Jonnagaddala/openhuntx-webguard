# Transactional Email (Slice 17)

## 1. What this is

Slice 16 built the identity system's need for email (verification,
password reset, invitation) against a narrow `MailProvider` interface,
but the only implementations were `LoggingMailProvider` (writes to the
application log) and `InMemoryMailProvider` (test-only). No real
message ever left the process. This slice completes that: a real
provider (`ProductionMailProvider`, backed by Postmark) sends real
mail, while `service.py`'s identity-domain code remains completely
unaware of Postmark or any vendor -- it still only ever calls
`self.mail_provider.send(to=..., subject=..., body=..., category=...)`.

## 2. Provider choice: Postmark

`docs/production/PROVIDER_EVALUATION.md`'s Email section already
recommended Postmark over AWS SES specifically for a security-tool
vendor, where deliverability reputation (not landing in spam) matters
disproportionately, and where Postmark's transactional-only sending
posture (no marketing-blast reputation risk) is a better fit than
SES's general-purpose one. This slice implements that recommendation
directly rather than re-evaluating it, per the brief's own instruction
to prefer the already-evaluated provider absent new evidence.

## 3. Architecture: three layers, matching the KMS/Secrets-Manager pattern

```
service.py (identity domain logic)
    │  .send(to, subject, body, category)
    ▼
MailProvider (Protocol -- DevelopmentMailProvider | InMemoryMailProvider | ProductionMailProvider)
    │
    ▼  (ProductionMailProvider only)
PostmarkClientProtocol (Protocol)
    │
    ▼
PostmarkHttpClient (real HTTPS, stdlib http.client only)
```

This mirrors `secret_provider.py`'s `SecretsManagerClientProtocol` and
`signing.py`'s `KmsClientProtocol` exactly: `ProductionMailProvider`
depends on `PostmarkClientProtocol` (a Protocol whose only method is
`send_email(payload) -> dict`), never on Postmark's own SDK or on
`PostmarkHttpClient` concretely. Unlike the KMS/Secrets-Manager case,
there is no vendor SDK to avoid importing -- Postmark's API is a single
`POST /email` with a JSON body, so `PostmarkHttpClient` is built
entirely on `http.client`/`json` (the standard library), matching
`webguard_scanner.safe_http`'s own established stdlib-only convention
for outbound HTTP in this codebase. No new dependency was added to
`requirements-ci.lock` for this.

`mail_transport` is an injectable parameter of
`build_production_components()` (mirroring `kms_client`/`s3_client`)
specifically so a test harness can fake the Postmark network boundary
while still exercising `ProductionMailProvider`'s real payload/retry/
classification logic -- see `tests/integration/webguard_production_harness.py`'s
`FakePostmarkTransport`.

## 4. What gets sent

| Category | Trigger | Link |
|---|---|---|
| `email_verification` | Registration; `POST /v1/auth/email/verify/request` (resend) | `{web_app_base_url}/verify-email?token=...` |
| `password_reset` | `POST /v1/auth/password/reset/request` | `{web_app_base_url}/reset-password?token=...` |
| `invitation` | `POST /v1/team/invitations` | `{web_app_base_url}/accept-invitation?token=...` |
| `password_changed` | In-session password change; password-reset completion | No link -- a plain notification, with a forgot-password link only in the change-notification case |

`password_changed` is the "optional if already supported cleanly"
security notification the brief named -- added because the mail
infrastructure it needs already exists, and notifying an account
holder that their password just changed is a standard, low-cost
security practice (a victim of account takeover gets a signal even if
they didn't initiate the change). Scan-result notifications are
explicitly **not** sent this slice, per requirement 2's own
instruction -- the notification model (what a customer wants notified
about, at what frequency, with what opt-out) is not yet defined, and
building delivery for it before that model exists would be guessing.

Every link's `{web_app_base_url}` comes from `ProductionServiceConfig.web_app_base_url`
(required, fail-closed in production) or `WEBGUARD_WEB_APP_BASE_URL`
(optional, defaults to the local Vite dev port) outside production --
`service.py` never hardcodes a frontend origin.

## 5. Email security (requirement 3)

- **Never in a mail payload**: passwords, session secrets, API tokens,
  authentication-context secrets. Every `_send_mail_best_effort` call
  site in `service.py` was reviewed; only the corresponding short-lived
  identity token (verification/reset/invitation) is ever embedded, and
  only in a URL, never as a bearer credential of any other kind.
- **Logs never contain those tokens**: `ProductionMailProvider` logs
  only non-sensitive delivery metadata (category, Postmark's own
  `MessageID`, outcome/failure category) -- never the message body,
  and therefore never the token embedded in it. This is a real,
  deliberate difference from `DevelopmentMailProvider`, which *does*
  log the full body (including the token) -- a local/dev console is
  not a production log-aggregation exposure surface, matching every
  other local-vs-production distinction already drawn in this project
  (e.g. `secure_cookies`, `hsts_enabled`).
- Postmark's own `Tag` field carries the `category` (a legitimate,
  vendor-native categorization mechanism, not a WebGuard-specific
  header) -- satisfying part of requirement 5's "template/event type"
  ask without inventing new payload structure.

## 6. Anti-enumeration under delivery failure (requirement 4)

`request_password_reset()` already returned an identical generic
response regardless of account existence (Slice 16). This slice adds a
new way that guarantee could have broken: a delivery failure happening
*after* a real account was matched must not produce a different,
distinguishable response than a delivery failure (or non-failure) for
a non-existent account. `_send_mail_best_effort()` (service.py) is the
single choke point every mail-send call goes through: it catches
`MailDeliveryError` and never re-raises it, so **no caller's HTTP
response ever differs based on whether the underlying send succeeded**.
The failure is only ever visible server-side, via a log line.

This is a deliberate, uniform policy across every mail-send call site
(registration, password reset, resend verification, invitation), not
just the anti-enumeration-sensitive one -- a downstream Postmark outage
should never take down account creation, password reset, or team
invitations; a customer can always retry the mail-dependent step
separately (resend verification, request another reset) once the
provider recovers.

## 7. Failure classification and retry (requirement 6)

`MailDeliveryError.category` is one of:

| Category | Meaning | Retried? |
|---|---|---|
| `temporary` | 5xx from Postmark, an unrecognized response shape, or a transport-level connection failure | Yes, once |
| `timeout` | The HTTPS request itself timed out | Yes, once |
| `rate_limited` | HTTP 429 | No |
| `permanent` | A 4xx business-logic rejection (e.g. Postmark `ErrorCode 406`, inactive/bounced recipient) | No |
| `configuration` | HTTP 401/403, or Postmark `ErrorCode 10` (bad API token) | No |

Classification is driven primarily by the HTTP status code (a contract
this module trusts completely) and secondarily by a small set of
stable, long-documented Postmark `ErrorCode` values -- never by
free-text vendor messages, which are logged for operator debugging but
never used for branching logic or exposed to a caller.

**Retry safety**: `ProductionMailProvider.send()` builds the Postmark
payload (including the embedded one-time token) exactly once, before
any retry loop begins. A retry re-sends the *identical* payload object
-- it never re-derives the token, and it never calls back into
`service.py` to mint a new one. This is what makes "one-time tokens
must not accidentally be regenerated on every transport retry"
structurally true rather than merely tested: the token simply is not
in scope of anything that runs more than once. `test_mail_provider.py`'s
`test_temporary_failure_is_retried_once_with_the_identical_payload`
asserts the two attempts' payloads are byte-identical.

## 8. What this document is not

It does not cover the identity-token lifecycle itself (TTLs, single-use
enforcement, hashing) -- see
`docs/security/BROWSER_SESSION_SECURITY.md` and
`docs/product/CUSTOMER_AUTH_ARCHITECTURE.md` §4/§7 for that, unchanged
this slice except for the links now embedded in the mail body.
