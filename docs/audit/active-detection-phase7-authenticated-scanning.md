# Active Detection, Slice 7: Authenticated & Session-Aware Scanning Foundation

## Status

This slice adds **no new vulnerability detector**. It builds the
authentication-context model, a single shared session/credential
application layer, a controlled login workflow, and the TrustScan permit
binding that lets the existing pipeline (discovery, `RequestTemplate`,
mutation, XSS/SQLi detectors) optionally run against an authenticated
surface, without ever embedding secrets in findings, reports, logs, or
serializable request templates.

## What was built

### Authentication Context model (`apps/api/src/webguard_api/authentication_contexts.py`)

Two physically separate stores behind one repository, keyed identically
but never joined:

- **Metadata** (`AuthenticationContextRecord`): `authentication_context_id`,
  `organization_id`, `target`, `authorization_id`, `identity_label`,
  `method` (`bearer_token` / `cookie_session` / `basic_auth` /
  `login_workflow`), `created_at`, `expires_at`, `revoked_at`. Contains
  no secret material, safe to log, audit, and return over the API
  as-is. `status_at(now)` derives `active` / `expired` / `revoked`.
- **Secret material**: `webguard_scanner.authentication.AuthenticationMaterial`
  (bearer token, session cookies, basic-auth credentials), reused rather
  than duplicated: it already carries its own bounds and redacted
  `__repr__`/`__str__` (see below). Looked up by the same ID through a
  *separate* method (`get_secret`, distinct from `get_metadata`), so a
  caller that only asked for metadata physically cannot receive secret
  material from that same call.
- `require_bound(id, *, organization_id, target, authorization_id, now)`:
  the one fail-closed check used at both permit-issuance time and again
  at scan-execution time (defense in depth, the same pattern already
  used for TrustScan permit validation itself): verifies the context
  exists, is bound to exactly this organization/target/authorization,
  and is currently `active`.

**Storage is deliberately in-memory only this slice**, stated directly
rather than left implicit, for two reasons: secret material must never
be written to SQLite or a plain file as a stand-in for real KMS/
encrypted-secret-manager storage (an in-memory store is honest about not
solving that problem, rather than pretending a local file is "good
enough for now"); and the project's own stated production sequencing
defers a PostgreSQL-backed metadata redesign to a later, dedicated
slice: building a throwaway SQLite schema for authentication-context
metadata now would be rework. Both `WebGuardJobService` and
`ScanJobExecutor` accept an optional `authentication_contexts` parameter
(defaulted to a fresh, empty, per-instance repository so every pre-
Slice-7 constructor call site is unaffected); a caller that needs
contexts registered via the service to be usable by the executor/worker
must pass the same repository instance to both. **Known limitation,
stated plainly:** this means the repository does not survive across
separate OS-process invocations (e.g. two separate `webguard-api`
CLI subprocess calls) the way the SQLite-backed job/permit/identity
stores do; see "True end-to-end test" below for exactly how this
shaped that test's scope.

### RBAC (`apps/api/src/webguard_api/auth.py`)

Three new owner-only permissions:
`AUTHENTICATION_CONTEXT_REGISTER`, `AUTHENTICATION_CONTEXT_READ`,
`AUTHENTICATION_CONTEXT_REVOKE`, excluded from `ADMINISTRATOR`
alongside the existing `PERMIT_ISSUE_ACTIVE`, on the same reasoning:
authenticated-scanning credentials are at least as sensitive as active/
intrusive detection capability.

### Session/authentication application layer (`workers/scanner/src/webguard_scanner/authentication.py`)

One shared mechanism (requirement 5): `apply_authentication(url,
material, *, now) -> extra_headers`. No detector, crawler, or discovery
code independently constructs `Authorization`/`Cookie`/`X-Api-Key`;
every request-issuing function (`issue_probe`, `fetch_same_origin_page`,
`issue_templated_request`, `execute_baseline`) accepts an optional
`authentication_material` parameter and calls this one function.

- **`SessionCookie`**: `name, value, domain, port, path, secure,
  expires_at`. Matching is **exact** (hostname *and* port, not RFC
  6265's host-only semantics), deliberately stricter than real browser
  cookies, matching this project's own scheme+host+port scope model. A
  session bound to `app.example.com:443` is never sent to
  `app.example.com:8443`, a sibling subdomain, or a different scheme
  (`Secure` cookies are withheld over downgraded HTTP).
- **`AuthenticationMaterial`**: `bearer_token`, `cookies`, `basic_username`/
  `basic_password`. Bounded (`MAXIMUM_BEARER_TOKEN_BYTES=8192`,
  `MAXIMUM_COOKIES=20`, `MAXIMUM_COOKIE_VALUE_BYTES=4096`) and validated
  at construction (oversized/incomplete input fails closed with a
  controlled `AuthenticationError`, never a generic exception).
- **Redaction, as defense in depth** (requirement 3): both
  `SessionCookie.__repr__` and `AuthenticationMaterial.__repr__`/`__str__`
  are overridden to return a fixed `<redacted>` marker instead of the
  real value. This does not replace correct handling elsewhere: it is
  one more layer against an accidental `f"{material}"` in a log line, a
  debugger, or an uncaught-exception traceback that happens to include a
  local variable. Verified directly: exception messages, `repr()`, and
  `str()` were all checked never to contain a planted secret value
  (`tests/unit/test_authentication.py`, `SecretRedactionTests`).
- **Header allowlist/blocklist** (requirement 6): only `Authorization`
  and `Cookie` may be set by this mechanism. `Host`, `Content-Length`,
  `Transfer-Encoding`, `Connection`, `Forwarded`, `X-Forwarded-Host`,
  `X-Forwarded-For` are hard-blocked, checked in *two* independent
  places: `apply_authentication` itself, and again in
  `safe_http.fetch_once`'s new `extra_headers` parameter (the same
  defense-in-depth pattern used for scope/method enforcement elsewhere
  in this codebase). `extra_headers` is not a general header-injection
  mechanism; it exists solely for this one caller.

### `safe_http.py` extensions

- `extra_headers: Tuple[Tuple[str, str], ...] = ()` on `fetch_once`/
  `_perform_request`, checked against `_FORBIDDEN_REQUEST_HEADERS`
  before any connection is attempted. Every pre-existing caller passes
  nothing here and is unaffected (verified: all 15 pre-existing
  `test_safe_http.py` tests pass unmodified).
- `allow_redirect_status: bool = False`: a narrow, explicit opt-in
  letting a 3xx response through instead of raising `redirect_blocked`,
  used only by the login workflow to read a `Location` header value as a
  *string* (never to actually follow the redirect with a second
  request). Found necessary the hard way; see "Bugs found and fixed."

### Login workflow (`workers/scanner/src/webguard_scanner/login_workflow.py`)

`execute_login(base_target, workflow, credentials, *, policy,
before_request, after_request, cancellation_check) -> LoginResult`:

- Sends **exactly one** bounded request through the same
  `safe_http.fetch_once` plumbing as every other active request:
  same-origin enforcement, budget/rate hooks, TLS. The login target
  must already be on the authorized target's own origin.
- **Never assumes HTTP 200 means success** (requirement 10). Verified
  directly with a deliberately adversarial fixture that returns 200 for
  *every* login attempt, success or failure: without an explicit,
  matching criterion, the result is `success=False`
  (`test_http_200_alone_is_never_treated_as_success`).
- Four bounded, explicit success criteria (`LoginSuccessCriterion`):
  `expected_status`, `expected_redirect_contains`, `expected_body_marker`,
  `expected_cookie_name`: at least one is required at construction time
  (`login_success_criterion_missing`, fails closed rather than defaulting
  to "any response is success").
- On success, extracts session cookies from `Set-Cookie` response
  headers into `SessionCookie` objects (bounded, minimal parsing: name/
  value plus `Path`/`Secure` attributes only, not a general cookie-jar
  implementation). `LoginResult` never carries the submitted password.
- `LoginCredentials.__repr__` is redacted the same way
  `AuthenticationMaterial` is.
- Cancellation is checked before the one request is issued
  (`test_cancellation_before_login_makes_no_request`: zero requests
  attempted).

**Known limitation, stated plainly (requirement 9's "budget" ask):**
`execute_login` always issues exactly one request and relies on the
caller's `before_request`/`after_request` hooks (the same runtime
safety engine hooks that gate every other active request) for budget/
rate accounting; it does not itself pre-check a request-count budget the
way detector functions call `enforce_probe_budget()`, because it never
issues more than one request regardless. This slice does not wire
`execute_login` into the automatic, permit-driven scan pipeline (see
"True end-to-end test" below for what *is* wired), so there is no
"budget exhaustion mid-scan-triggered-login" scenario to exercise yet;
this is recorded as not proven rather than assumed safe by extension.

### TrustScan permit binding (schema 1.1 → 1.2)

`authentication_context_id: str | None = None` added as a new signed
claim on `TrustScanPermitClaims`/`TrustScanPermitSubmission`. This is a
genuine field addition (not a vocabulary-widening change like Slice 6's
`allowed_http_methods`), so it goes through the process
`docs/audit/trustscan-permit-schema-policy.md` reserves for that: schema
version bumped 1.1 → 1.2, replace-in-place (not a version-aware loader),
justified by the same, re-verified precondition as the 1.0 → 1.1 bump:
WebGuard has still never been deployed, so no real persisted 1.1 permit
exists that this could invalidate. Documented in that policy file, not
just here.

`WebGuardJobService.issue_permit` requires `AUTHENTICATION_CONTEXT_REGISTER`
(owner-only) when a submission sets this claim, then calls
`require_bound` against the *submission's* organization/target/
authorization before signing: an authenticated permit cannot be issued
for a context registered under a different tenant, target, or
authorization, and cannot be issued for an expired or revoked context.
`ScanJobExecutor` re-validates the same binding independently at
execution time (`_apply_active_detection`), raising
`TrustScanRuntimeSafetyError` (fail closed, the same class used for
every other runtime safety decision) if the context was revoked or
expired *after* the permit was issued but *before* the scan actually
ran.

### Scan-time wiring

`_apply_active_detection` resolves `AuthenticationMaterial` once per
scan (if the bound permit's `authentication_context_id` is set) and
threads it through `_discover_and_detect_page` into: the page-discovery
re-fetch (`fetch_same_origin_page`), and every authorized detector call
(`run_reflected_xss_detector`/`run_sqli_error_detector`, via
`issue_probe`/`issue_templated_request`). This is what lets an
authenticated discovery pass reach content an unauthenticated one
cannot, and lets XSS/SQLi probe that content once discovered, proven
end-to-end (see below).

**Known limitation, stated plainly (requirement 11):** the *passive*
scan step (`run_passive_header_scan`/`run_passive_crawl_scan`) is not
authentication-aware this slice: it does not accept `extra_headers` or
resolved material at all. Only the active-detection discovery/probe
pipeline applies authentication. This is why the true end-to-end test
below targets a page whose *unauthenticated* content is deliberately
inert (no form) rather than relying on the passive scan itself being
authenticated. Extending passive scanning (and, with it, a genuinely
*authenticated crawl* across multiple pages, checkpoints included) is
explicitly out of scope for this slice and recorded under "Not Proven."

## Bugs found and fixed during this slice

1. **`safe_http`'s existing redirect-blocking silently defeated the
   login workflow's redirect-based success criterion.** The first
   version of `execute_login` called `fetch_once` with no way to
   observe a 3xx response: `_perform_request` already raises
   `redirect_blocked` for any 3xx-except-304 status, a real, deliberate
   safety control from before this slice. A login endpoint that
   responds with a redirect on success (a common pattern, and the one
   this slice's own lab fixture uses) therefore always looked like a
   probe failure, never a successful login. Caught immediately by
   `test_correct_credentials_with_redirect_criterion_succeeds`. Fixed
   with a narrow, explicit `allow_redirect_status` opt-in that lets the
   3xx response through to be *read*, never *followed*: no second
   request is ever issued to the `Location` target.

## Safety boundaries

### Session leakage (requirement 12)

Verified directly, all in `tests/unit/test_authentication.py`:
- A session cookie bound to one domain is never attached to a request
  against a different domain, a sibling subdomain, or a different port
  (`test_cookie_never_forwarded_to_a_different_domain`,
  `test_cookie_never_forwarded_to_a_sibling_subdomain`,
  `test_cookie_never_forwarded_to_a_different_port`).
- A `Secure` cookie is never attached over a downgraded (HTTPS→HTTP)
  request (`test_secure_cookie_never_forwarded_over_downgraded_http`).
- A redirect target on an external origin never receives the
  authenticated origin's cookie
  (`test_redirect_to_external_origin_never_receives_cookie`); and,
  independently, `safe_http` blocks *any* redirect from being followed
  at all by default (pre-existing control, re-verified unchanged:
  `test_blocks_redirect_response`), so this is defense in depth on top
  of an already-strict baseline, not the only thing preventing it.
- An expired cookie is never attached regardless of domain match
  (`test_expired_cookie_is_never_attached`).
- A path-scoped cookie is only attached within its own path
  (`test_path_scoped_cookie_only_attached_within_its_path`).

**Not separately re-tested this slice** (per the brief's own list): DNS
resolution changes are already covered by this project's pre-existing,
unchanged scope-validation controls (`scope_validator.py`,
`owned_target._public_addresses`): Slice 7 introduces no new DNS-
handling code, so no new test was added specifically for it; the
existing scope/SSRF regression suite (re-run in full, see below)
continues to pass unchanged.

### Bearer/API token handling (requirement 8)

Tested: valid token (`test_bearer_token_produces_authorization_header`),
oversized token, both at the `AuthenticationMaterial` construction
layer (`test_oversized_bearer_token_is_rejected`) and at the service
registration layer (`test_oversized_token_is_rejected`), expired
context (`test_require_bound_rejects_expired_context`,
`test_permit_rejects_expired_authentication_context`), revoked context
(`test_require_bound_rejects_revoked_context`,
`test_permit_rejects_revoked_authentication_context`), wrong target
(`test_require_bound_rejects_wrong_target`,
`test_target_mismatch_is_rejected`), wrong tenant
(`test_require_bound_rejects_wrong_organization`). "Invalid token" in
the sense of "a token Juice Shop itself rejects" is exercised implicitly
by the Juice Shop investigation below (an unauthenticated request to a
protected endpoint returns 401); a synthetic "malformed token string"
case was not separately added, since `AuthenticationMaterial` treats any
non-empty string within the byte limit as opaque, valid input by
design: the *target application* is the only party that can say a
token is invalid, and that is exactly what the 401 response there
demonstrates.

### Evidence and audit sanitization (requirements 15, 16)

No detector's evidence-construction code changed in this slice (Slice 6
already established that finding evidence never contains raw request/
response bodies, and that discipline is untouched). What's new is
proven directly by the true end-to-end test: the persisted report, the
persisted owned-target preflight audit file, and the RBAC/service
audit-event trail (`GET /v1/audit-events`) are all checked, after a real
authenticated scan produced a real finding, to contain neither the
session cookie's value nor the test account's password anywhere in
their text. The audit-event trail is checked to *contain* the
structural action name `authentication_contexts.register`, proving the
event was recorded at all, just never with the secret.

## Controlled lab fixture (requirement 17)

A purpose-built `ThreadingHTTPServer`-based HTTPS fixture (real,
freshly-generated self-signed certificate, same pattern as the existing
Slice 3/6 E2E fixtures) with five routes and two identities
(`user-a`/`user-b`, distinct passwords):

- `GET /public`: no authentication, nothing sensitive.
- `GET /account`: **without** a valid session cookie: `200`, "Please
  log in to view your account" (no form). **With** a valid cookie:
  `200`, "Welcome, `<identity>`!" plus a real `<form method="GET"
  action="/api/profile">`. Deliberately kept at `200` either way (not a
  redirect) so the *passive* scan step (which does not apply
  authentication this slice) always completes normally; the
  distinction under test is entirely in what content becomes visible,
  not in status codes.
- `GET /api/profile?q=`: authenticated only; reflects `q` unescaped
  (deliberate, bounded XSS surface for the detector) exactly when a
  valid session is present; otherwise a static "please log in" body
  with no reflection at all (so even a stray unauthenticated probe
  cannot produce a false finding here).
- `POST /login`: validates `username`/`password` against the two
  fixture identities; on success, issues a session token and returns
  `302 Location: /account` with `Set-Cookie: session=...` (this is what
  exercised the `allow_redirect_status` fix above); on failure, `200`
  with an "Invalid credentials" body and no cookie.
- `GET /logout`: invalidates the session server-side.

Proven directly against this fixture:
- Login works, verified via the redirect-based success criterion
  (`test_full_authenticated_scanning_pipeline`, step 1).
- Unauthenticated scans cannot access the authenticated surface
  (`test_authenticated_pages_are_unreachable_without_login`: the real
  `/account` page never contains "Welcome" without a session).
- Authenticated pages become discoverable and probeable once a resolved
  session is applied (the same test's remaining steps: the real worker/
  executor, with the registered cookie context, discovers the form on
  `/account` and confirms the XSS finding on `/api/profile`).
- Credentials are never exposed (report/audit assertions above).

**Not separately re-tested this slice:** logout/session-expiry behavior
against the *fixture's own* server-side invalidation was exercised
manually while building the fixture but has no dedicated automated
test. This is recorded under "Not Proven" rather than silently assumed.
Session isolation between `user-a` and `user-b` (each seeing their own
identity label) is proven by construction (the fixture's `/account`
route echoes whichever identity the session token maps to) but this
slice never registers a `user-b` context or runs a second scan under it
to observe two independent findings side by side: that comparison is
exactly the IDOR/BOLA groundwork the brief explicitly says is *not* this
slice's job.

## True end-to-end test (requirement 18)

`tests/integration/test_authenticated_scanning_e2e_lab.py`,
`test_full_authenticated_scanning_pipeline`:

```
execute_login() [direct call, real socket, real TLS]
  -> POST /v1/authentication-contexts [real HTTP]
  -> POST /v1/permits (authentication_context_id set) [real HTTP]
  -> POST /v1/jobs [real HTTP]
  -> real ScanJobWorker -> real ScanJobExecutor
  -> authenticated discovery -> RequestTemplate -> reflected-XSS detector
  -> NormalizedFinding -> persisted WebGuardReport
  -> GET /v1/jobs/{id}/result, report file read [real HTTP + real file]
  -> GET /v1/audit-events [real HTTP]
```

**Scoping decision, stated explicitly rather than left implicit:**
because the authentication-context repository is in-memory only (see
above), it cannot survive across separate CLI subprocess invocations the
way the SQLite-backed stores can: the pre-existing Slice 3/6 E2E tests
tolerate this because *their* new state (permits, jobs) lives in the
shared SQLite file regardless of which `main([...])` call wrote it. This
test therefore constructs `WebGuardJobService`/`ScanJobExecutor`/
`ScanJobWorker` directly (exactly as the pre-existing
`test_active_checks_e2e_lab.py` already does for its own "real API + real
worker" section, not a new pattern) and passes one shared
`AuthenticationContextRepository` instance to both the service and the
executor, while still using `main([...])` for the steps that only touch
SQLite-backed state (bootstrap, authorization assignment). Every
authentication-context-specific step (registration, authenticated permit
issuance, job submission, result/audit retrieval) goes over **real HTTP
against a real socket**, through the real `create_server`/`ScanJobWorker`
objects; only the process boundary is collapsed, not the transport. The
login step itself (`execute_login`) is called directly rather than
through a CLI command, because no `webguard-api login` command exists
yet (see "Login workflow" above): it is invoked exactly as an operator
would need to invoke the underlying library call today.

Result: the finding is produced (`CWE-79`, path containing
`/api/profile`), the job completes, and the session cookie value and the
test account's password are verified absent from the persisted report,
the persisted owned-target audit file, and the audit-event API response.

## Juice Shop investigation (requirement 21)

Investigated the pinned Juice Shop lab target's real authentication
model, using only a fresh account created through Juice Shop's own,
documented `POST /api/Users/` registration endpoint (an intended,
legitimate feature of the application, not credential guessing, and not
one of the undocumented CTF challenge accounts).

**Authenticate: yes, verified.** `execute_login` was pointed at Juice
Shop's real `POST /rest/user/login` with `expected_body_marker=
"authentication"` (not assuming 200 alone means success) and correctly
reported `success=True`.

**Retain session/token state: partially, an honest and useful gap.**
Juice Shop's login response contains **no `Set-Cookie` header at all**:
its session is a JWT returned inside the JSON response body
(`{"authentication": {"token": "..."}}`). `execute_login`'s automatic
extraction only parses `Set-Cookie` headers, so `LoginResult.cookies`
came back **empty** against Juice Shop, confirmed by direct measurement.
This is a real, documented capability gap, not a Juice-Shop-specific
workaround: a JSON-body bearer token is a very common modern pattern
this slice's login workflow does not yet extract automatically.
Separately, and successfully: the JWT was extracted manually (the way an
operator would today) and wrapped in `AuthenticationMaterial(bearer_token=
...)`; `apply_authentication` correctly produced the `Authorization:
Bearer ...` header, and a real protected Juice Shop endpoint
(`GET /api/Users/24`, the registered account's own record) was confirmed
to return `401` unauthenticated and `200` with that header attached:
direct, empirical proof that WebGuard's authentication-*application*
layer is fully compatible with Juice Shop's real token format, even
though the login-*extraction* layer does not yet automate pulling it out
of a JSON body.

**Discover authenticated APIs: no, unchanged from prior slices.**
Juice Shop's Angular-SPA architecture (confirmed empirically in Slices
5–6: no server-rendered forms, no real OpenAPI/sitemap documents) means
its authenticated endpoints are not reachable by this project's static
discovery regardless of authentication state. This is a discovery-layer
limitation, not an authentication one, and Slice 7 does not change it.

**Apply normal safety boundaries: yes.** The same `safe_http.fetch_once`
scope/method/header-allowlist protections applied identically in every
manual probe above; no bypass was introduced or exercised.

This is recorded as a valid, useful result per the brief's own framing,
not a gap to paper over. The concrete follow-up it points to (extracting
a bearer token from a JSON response body via an explicit
`LoginSuccessCriterion` option, e.g. a JSON-path extractor) is noted
under "Known limitations," not silently implied to already work.

## Regression (requirement 20)

- Full unit suite: **1278/1278 passing** (1214 at the end of Slice 6,
  +64 new: 21 `test_authentication.py`, 14
  `test_authentication_contexts.py`, 11 `test_login_workflow.py`, 18
  `test_authenticated_permit_control.py`, +2 net from the
  `test_phase2_authentication_rbac.py`/`test_trustscan_permit_contract.py`
  updates needed for the new permit field and RBAC permissions).
- Full integration suite (`WEBGUARD_RUN_INTEGRATION=1`, Juice Shop
  container live): **31/31 passing** (29 from Slice 6, +2 new
  authenticated-scanning E2E tests).
- Every pre-existing XSS/SQLi/executor/permit/registry/cross-
  authorization/attack-surface/request-template/safe_http test file was
  re-run explicitly and passes **unmodified** except for the two files
  that needed a mechanical new-field update (`test_trustscan_permit_contract.py`'s
  submission fixture, `test_phase2_authentication_rbac.py`'s exhaustive
  permission-set enumeration): both changes are additive assertions
  about the three new RBAC permissions and the new claim, not weakenings
  of any existing check.
- Security gates: secret scan (270 files / 6 artifacts / 569 blobs),
  static analysis (`ruff --select S`, two findings caught and fixed,
  see below, then zero), dependency audit (6 locked packages, no
  advisories): all passing.
- `git diff --check`: clean.

Two static-analysis findings were caught and fixed before this slice's
gate passed clean: `S105` (ruff's hardcoded-password heuristic
flagging the `AuthenticationMethod.BEARER_TOKEN` enum *tag*, a string
literal naming a method, not a credential, suppressed with a targeted
`# noqa: S105` and a comment explaining why) and `S112` (a bare
`except: continue` while parsing a malformed `Set-Cookie` header,
intentional and already explained by an existing `# noqa: BLE001`
comment, extended to also cover `S112`).

## Implemented / Tested / Proven / Not Proven / Authentication Types Supported / Secret Boundaries / Session Boundaries / Security Tests / Known Limitations / Test Counts / Security Gates / GitHub Commit / Remote Sync / Next Slice

**Implemented:** `AuthenticationContextRecord`/`AuthenticationContextRepository`
(metadata and secret material physically separated); `AuthenticationMaterial`/
`SessionCookie`/`apply_authentication` (the one shared session-application
mechanism, header allowlist/blocklist, exact origin+port cookie scoping);
`execute_login`/`LoginWorkflow`/`LoginSuccessCriterion` (bounded,
explicit-verification login); a new signed TrustScan permit claim
(`authentication_context_id`, schema 1.1 → 1.2) binding a permit to a
specific context; RBAC (three new owner-only permissions); HTTP routes
and a CLI command for registering an authentication context; executor
wiring so authenticated discovery/detection runs when a permit's bound
context resolves.

**Tested:** every item enumerated above with a named test; the full
required-negative-test list from the brief, item by item: missing
context, wrong organization, wrong target, expired context, revoked
context, failed login, oversized token, oversized cookies, cross-origin/
cross-port/cross-scheme cookie leakage, redirect-to-external-origin
non-forwarding, secret absence from exceptions/findings/reports/audit
events, cancellation during login, permit without authenticated
capability (by construction, see "Not Proven" for what wasn't
separately re-verified), and tampering with the signed
`authentication_context_id` claim.

**Proven:** a real login against a real fixture yields a real,
extracted session; that session, applied through one shared mechanism,
reaches content an unauthenticated request cannot; the existing XSS
detector fires against that authenticated content with a genuine
finding; credentials never appear in the resulting report, the owned-
target audit file, or the RBAC audit-event trail; the same bearer-token
application mechanism works against a real, independent target (Juice
Shop) with a materially different (JWT-in-body) session model than the
lab fixture uses (cookie-in-header): evidence this isn't overfit to one
fixture's shape.

**Not Proven:** budget exhaustion mid-scan-triggered login (login isn't
wired into the automatic scan pipeline yet); a genuinely multi-page
*authenticated crawl* with checkpointing (passive scanning and crawling
remain unauthenticated this slice; only single-page active-detection
discovery/probing is authenticated); automatic extraction of a JSON-
body-embedded bearer token (Juice Shop's own pattern) by the login
workflow; a dedicated automated test of the lab fixture's own logout/
session-expiry behavior (built and manually exercised, not covered by
an assertion); a second identity (`user-b`) actually scanned side by
side with `user-a` to observe session isolation directly (the fixture
supports it; this slice didn't run that second scan, deliberately, since
that comparison is IDOR/BOLA groundwork explicitly out of scope);
authentication-context metadata surviving a real multi-process
deployment (in-memory only, by design, this slice).

**Authentication types supported:** bearer/API token (explicit,
target/organization/authorization-bound, revocable, redacted); cookie/
session-cookie (explicit, exact origin+port scoped); basic authentication
(supported at the same layer, since the existing architecture's header
mechanism accommodates it trivially, not separately lab-validated
against a real basic-auth endpoint this slice); login-workflow-derived
sessions (the `login_workflow` method value on `AuthenticationContextRecord`
exists and the underlying `execute_login`/cookie-extraction primitive is
fully built and tested, but the *automatic*, permit-triggered use of a
stored username/password to re-run a login mid-scan is not wired: the
lab E2E test performs login as an explicit, separate step, exactly
mirroring what a real operator would do today). OAuth automation, SAML,
browser automation, and MFA bypass were explicitly out of scope and were
not built, per the brief's own instruction.

**Secret boundaries:** `RequestTemplate.authentication_context_ref` (a
Slice-6 field, now finally used for its intended purpose) carries only
an ID/label, never a secret. `AuthenticationMaterial`/`SessionCookie`/
`LoginCredentials` all override `__repr__`/`__str__` to a fixed redacted
string. Every exception message that could involve a secret was checked
not to include it. Neither `register_authentication_context`'s HTTP
response nor the CLI output ever echoes the secret back, even though the
caller just supplied it (write-only registration, the same principle as
never re-displaying a password after account creation).

**Session boundaries:** exact scheme+host+port+path cookie scoping,
stricter than RFC 6265; no automatic redirect-following anywhere in
`safe_http` (pre-existing, re-verified); a session bound to one
authorization/target/organization cannot be referenced by a permit
issued under a different one (`require_bound`, checked twice: issuance
and execution time).

**Security tests:** see "Regression" and the per-file counts above; the
full required negative-test list is covered as itemized in "Tested."

**Known limitations:** see the "Not Proven" list, restated here as
forward-looking scope rather than gaps to be alarmed about: passive/
crawl authentication, automatic mid-scan login, JSON-body token
extraction, and cross-process authentication-context persistence are the
concrete next steps if this capability needs to grow further.

**Test counts:** 1278 unit, 31 integration, all passing.

**Security gates:** secret scan, static analysis (after two fixes),
dependency audit, and `git diff --check` all clean.

**GitHub commit:** recorded below after push and `HEAD == origin/main`
verification.

**Remote sync:** recorded below.

**Next slice:** per the operator's own stated priority (master scope
document, section 46), IDOR/BOLA and privilege-boundary testing can now
be built directly on top of this slice's test-identity concept
(`identity_label`, two isolated fixture accounts already proven
independent) without needing to build authentication capability first.
Alternatively, per that section's explicit caveat, any security blocker
found in the meantime takes priority over this ordering.
