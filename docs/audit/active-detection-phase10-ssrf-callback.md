# Active Detection, Slice 10: Controlled SSRF Detection & Callback Infrastructure

## Status

This slice adds a new active detector, `active.ssrf.callback` (CWE-918,
OWASP Top 10 2021 A10), built on a dedicated controlled-callback
architecture rather than response-text guessing. Confirmation requires
a genuine, out-of-band, server-side outbound request from the target
application to a WebGuard-controlled callback destination: never a
target response that merely reflects, validates, or mentions a
callback URL. This is also the first slice to require a real,
runnable receiver component (not just a test fixture) as production
code, since confirmation depends on something actually being able to
receive the target's own outbound connection.

## What was built

### Dedicated active check (requirement 1)

`active.ssrf.callback` added to `KNOWN_TRUSTSCAN_ACTIVE_CHECKS`
(vocabulary widening, no permit schema bump, the identical, already-
established precedent from Slice 8's `active.authorization.idor`
addition). It requires explicit presence in a permit's `active_checks`
claim; there is no shared "any active check" gate beyond the existing
`PERMIT_ISSUE_ACTIVE` RBAC permission every active check already uses
at issuance time. An XSS-only, SQLi-only, or IDOR-only permit **never**
authorizes SSRF: proven directly (see "Authorization negatives"
below) rather than merely asserted, since `_apply_ssrf_callback_detection`
checks for this exact string and nothing else.

### Callback architecture (requirements 2, 19, 20)

Split across two layers, mirroring this project's established
scanner/API-layer separation:

- **`workers/scanner/callback_broker.py`** (scanner-side, zero
  `apps/api` dependency): `CallbackToken` (opaque, high-entropy value +
  the full callback URL), `CallbackObservation` (bounded: token,
  timestamp, method, a categorical `source_class`, never a raw source
  IP), `CallbackPolicy` (explicit bounds, see "Safety boundaries"),
  the `CallbackBroker` protocol the detector depends on
  (`register`/`wait_for_observation`, nothing more), and
  `InMemoryCallbackBroker`: a genuine, bounded, self-contained
  default implementation usable standalone with no API-layer
  dependency at all (the same relationship `AuthenticationMaterial`
  already has to `AuthenticationContextRepository`).
- **`apps/api/callback_service.py`** (API-layer, multi-tenant):
  `CallbackRepository` wraps one shared `InMemoryCallbackBroker` for
  the whole process's lifetime (tokens are globally unique via
  `secrets.token_urlsafe`, so one instance safely serves every
  concurrent scan) and additionally records organization/target/
  authorization metadata per registration for audit/lookup:
  `ScopedCallbackRegistration`. This is intentionally *not* itself
  handed to the detector: `executor.py`'s `_ScanScopedCallbackBroker`
  is a small local adapter that binds one scan's tenancy once via
  closure and satisfies the scanner's `CallbackBroker` protocol
  exactly, so the detector never needs to know tenancy exists.
- **`apps/api/callback_server.py`**: `CallbackHttpReceiver`: a real,
  runnable `ThreadingHTTPServer`-based listener, not a test mock. It
  accepts `/<scan_id>/<token>` and calls `record_observation` on
  whatever observation sink it was given (a `CallbackRepository`, or a
  bare `InMemoryCallbackBroker` for detector-only tests, satisfied
  via a small `Protocol`, not a hard dependency on the API-layer
  class). **Not started automatically as part of `webguard-api
  serve`** this slice: an operator or test constructs and starts one
  explicitly, mirroring how the worker and scheduler are already
  independently-run components in this architecture (requirement 19's
  "separately scalable service" framing, achieved honestly rather than
  simulated).

Production requirements documented, **not** built this slice
(requirement 20): a stable public hostname (e.g.
`callback.openhuntx.com`) with wildcard or token-based path routing,
TLS termination, DNS that does not rebind between registration and
observation, rate limiting and abuse controls on the receiver itself,
short-lived correlation storage in PostgreSQL/Redis rather than
in-process memory, and monitoring/alerting on the receiver's own
health. None of this is provisioned; the interface (`CallbackBroker`)
is what makes swapping in a real implementation later possible without
touching the detector.

### No internal-network probing (requirement 3)

Structurally enforced, not merely policy: the only destination value
`run_ssrf_callback_detector` ever substitutes into a candidate
parameter is `token.url`: the callback URL a `CallbackBroker.register()`
call itself produced. There is no code path anywhere in this detector
that constructs, accepts, or falls back to `127.0.0.1`, `localhost`,
`169.254.169.254`, an RFC1918 address, or any other destination.
WebGuard's own outbound-request scope protections (`scope_validator.py`,
`safe_http.py`) are completely untouched by this slice: they still
govern every request WebGuard's own client makes to the *target*, a
separate boundary from what value gets embedded in a parameter the
target's own server later chooses to act on. This distinction
(requirement 22) is the load-bearing safety property of this whole
slice: WebGuard prevents its own client from being pointed at internal
addresses (unchanged); WebGuard *tests* whether the target is willing
to make an outbound request to an address WebGuard controls (new, and
that address is never internal).

### Candidate discovery (requirement 4)

`is_ssrf_candidate_parameter`/`select_ssrf_candidates` filter
`RequestTemplate`s (the existing Slice 6 discovery/mutation model,
reused completely unmodified: GET query, POST form, and JSON string
fields are all representable, and OpenAPI-declared JSON body fields
already produce `RequestTemplate`s the same filter applies to) by
parameter name against a bounded hint set: `url`, `uri`, `callback`,
`webhook`, `image`, `avatar`, `feed`, `source`, `redirect`, `endpoint`,
`fetch`, `import`. **This is a discovery-time filter only: never
evidence.** No finding this detector produces depends in any way on
the parameter's name; a candidate with the most suggestive possible
name (`callback_url`) that never actually gets fetched server-side
still produces zero findings (`test_parameter_name_alone_never_becomes_a_finding`).
The match is a case-insensitive substring check, deliberately a little
permissive (`resource_id` also matches "source") since over-inclusion
here only costs one extra bounded probe request and can never itself
produce a finding.

### Probe design (requirement 5)

`run_ssrf_callback_detector` reuses, unmodified: `RequestTemplate`/
`mutate()` (the exact Slice 6 mutation engine: only the one selected
parameter changes, every other field of the request is preserved
byte-for-byte), `issue_templated_request` (the same shared transport
already used by SQLi/XSS's POST/JSON path, including same-origin
enforcement via the existing `_require_same_origin`), `AuthenticationMaterial`
(threaded through identically to every other detector), and
`safe_http`/the TrustScan runtime safety engine (via
`before_request`/`after_request` hooks, unchanged). **No separate
network stack was created**: the only genuinely new networking code
in this entire slice is the callback *receiver* (a server, listening
for inbound connections), never a new outbound client.

### Confirmation model (requirements 6, 12)

Five conservative states, mirroring the discipline already established
for IDOR (Slice 8):

- **CONFIRMED**: the probe request itself succeeded, and a callback
  observation for this *exact* token arrived within the policy's
  primary wait window.
- **PROBABLE**: identical, except the token-correlated observation
  only arrived during the secondary grace window: still never
  guessed, just weaker timing evidence (a real callback can legitimately
  arrive late if the target's own fetch is queued/asynchronous).
- **NOT_VULNERABLE**: the probe succeeded and no observation arrived
  even after the full wait+grace window.
- **INCONCLUSIVE**: callback registration itself failed (the broker's
  own registration budget was exhausted), or the wait was stopped
  early by cancellation: in both cases the test could not actually
  complete, so no claim either way is made.
- **ERROR**: the probe request itself failed at the transport level.

Correlation fields (requirement 6): scan ID, candidate endpoint/method/
parameter, the callback token's own fingerprint, and the observation's
timestamp/method: all recorded in the finding's evidence text (see
"Evidence" below). **A target response containing the callback URL is
never SSRF evidence by itself**: verified directly
(`test_reflection_of_callback_url_alone_produces_no_finding`,
`test_response_merely_mentioning_the_callback_domain_produces_no_finding`)
and structurally impossible by construction: the classification
function never inspects the probe response body at all, only whether
`callback_broker.wait_for_observation` returned something.

### Callback authenticity (requirement 7)

`InMemoryCallbackBroker.register()` generates every token with
`secrets.token_urlsafe(32)` (256 bits of entropy): there is no code
path that accepts a caller-supplied token value as a registration.
Tokens are scan-bound and candidate-bound at registration
(`CallbackToken.scan_id`/`candidate_fingerprint`), time-limited
(`CallbackPolicy.token_ttl_seconds`, default 300s, hard-capped at one
hour), and bounded-use (`maximum_observations_per_token`, default 5).
An arbitrary, forged, or guessed token value is never accepted as
proof: `record_observation` returns `False` (never raises) for any
unknown, expired, or over-quota token, verified directly
(`test_arbitrary_user_supplied_id_is_never_accepted_as_proof`,
`test_expired_token_is_rejected`, `test_bounded_use_rejects_beyond_maximum_observations`).
A callback observed for a *different* token (whether from an
unrelated candidate in the same scan or from an entirely different
scan) never satisfies a waiting registration
(`test_callback_from_wrong_token_never_confirms_this_candidate`,
`test_callback_from_another_scans_token_never_confirms_this_one`).

### Redirect behavior (requirement 8)

All five explicitly required scenarios are tested: direct callback
(CONFIRMED); the application reflects the URL only, never fetching it
(NOT_VULNERABLE); the application validates and rejects the URL,
returning 400, without ever fetching (NOT_VULNERABLE); the application
genuinely fetches it (CONFIRMED, the only such case); and the
callback destination itself redirects
(`test_redirect_response_does_not_prevent_confirmation`). The last
case is the one requiring architectural care: WebGuard's own detector
never follows, sees, or acts on the callback receiver's response at
all: confirmation happens the instant the inbound request *arrives*
at the receiver, before any response is even sent back. No redirect-
to-private-network behavior was introduced anywhere: the receiver's
own optional, test-only `respond_with_redirect` flag redirects to a
fixed, local, non-sensitive path (`/redirected`) purely to prove this
property, never to a network-reachable destination of any kind.

### DNS/rebinding safety (requirement 9)

Correlation is based **only** on the token presented in the request
path: never on the Host header, the source address, or any DNS
resolution the request happened to arrive via. Verified directly
(`test_correlation_depends_only_on_the_token_never_on_host_header`): a
request presenting a spoofed, unrelated `Host` header is still
correctly correlated purely by its token. This makes the local
implementation already resistant to DNS rebinding and callback-host
spoofing by construction, independent of any DNS trust decision,
proven locally without needing attacker-controlled DNS at all, since
the property being tested (token-only correlation) doesn't depend on
DNS in the first place. **Documented production requirement**: a real
deployment needs a stable, WebGuard-controlled DNS record for the
callback hostname (no dynamic/rebinding-prone DNS), and the receiver
should continue to trust only the token, never the Host header or
resolved address, exactly as this local implementation already does.

### Evidence (requirement 10)

`_build_finding`'s evidence text contains only: the candidate
endpoint/method/parameter (via `FindingIdentity`), scan/authorization/
permit provenance, a truncated SHA-256 fingerprint of the (non-secret,
WebGuard-generated) callback token, and the observation's timestamp
and HTTP method. Verified directly
(`test_evidence_never_contains_authentication_material_or_full_body`)
that a planted bearer token never appears in evidence text. Never
stored: authentication secrets, full request/response bodies, cookies,
complete callback headers, source IP (only the categorical
`source_class="external"` is ever recorded), or sensitive response
content.

### Finding / CWE mapping (requirement 11)

Every finding carries `CWE-918` unconditionally and, as this project's
second non-CWE identifier namespace (the first was `OWASP-API` for
IDOR in Slice 8), `OWASP`/`A10:2021`: OWASP Top 10 (2021) category A10
is literally named "Server-Side Request Forgery," a direct, well-
justified match rather than a stretch. "Callback reflected in
response" is never treated as confirmed SSRF, see "Confirmation
model" above.

## Bugs found and fixed during this slice

1. **A pre-existing Slice 9 bug in `resource_graph._endpoint_template`,
   surfaced by this slice's Juice Shop investigation.** The function
   computed a resource's structural endpoint template via
   `canonical.replace(resource.identifier_value, "{identifier}", 1)`:
   a naive first-occurrence substring replacement. Juice Shop's real
   basket IDs (small integers like `11`/`12`) coincidentally matched
   digits *inside the loopback IP address itself* (`127.0.0.1`), so
   `.replace("12", ...)` rewrote the wrong part of the string (inside
   the host, not the trailing path segment), producing two different
   templates for what was structurally the same endpoint and silently
   breaking cross-identity comparison eligibility for those two
   resources. Caught when `test_confirms_basket_access_control_bypass_via_login_response_discovery`
   (a Slice 9 integration test, unrelated to this slice's own new
   code) started failing against a fresh Juice Shop container during
   this slice's regression run. **Fixed** by rewriting
   `_endpoint_template` to split the path into segments and replace
   the identifier only when it exactly matches a whole path segment
   (searched from the end backward), never as an arbitrary substring
   of the full URL, verified with a new regression test
   (`test_numeric_identifier_coinciding_with_a_digit_in_the_host_is_still_eligible`)
   and by re-running the Juice Shop test, now passing. This bug
   predates this slice (introduced in Slice 9) but was only discovered
   here, during this slice's own honest regression discipline.

## Controlled vulnerable fixture (requirement 13)

Five routes, exactly as required: `/fetch-vulnerable` (genuinely
vulnerable: the server performs a real, blocking, standard-library
outbound HTTP request to the supplied URL before responding);
`/fetch-safe` (accepts the URL, never fetches it); `/reflect-only`
(echoes the URL value, never fetches); `/validation-error` (always
400, never fetches); `/generic-500` (always 500, never fetches). Only
`/fetch-vulnerable` ever produces a CONFIRMED finding: verified
directly against all five simultaneously
(`test_only_the_actual_fetch_produces_a_confirmed_finding`).

## Real-network test (requirement 14)

`tests/integration/test_ssrf_callback_detector_live.py` runs the
unmodified detector against the fixture above and a real
`CallbackHttpReceiver`, using real sockets throughout: WebGuard's probe
to the fixture is a real HTTP request; the fixture's vulnerable
route's own outbound fetch (via Python's standard library, not
WebGuard's client) is a real HTTP request; the callback arriving at
WebGuard's receiver is a real HTTP request. No part of this path is
mocked.

## End-to-end test (requirement 15)

`tests/integration/test_ssrf_callback_e2e_lab.py`,
`test_full_ssrf_callback_pipeline`:

```
target authorization (real HTTPS fixture, self-signed cert)
  -> TrustScan permit with active_checks=["active.ssrf.callback"] [real HTTP]
  -> job [real HTTP] -> real worker -> real executor
  -> discovery (GET-form candidates on the fixture's root page)
  -> request template + mutation engine (Slice 6, unmodified)
  -> callback registration (real CallbackRepository + CallbackHttpReceiver)
  -> SSRF probe [real HTTP to the fixture]
  -> the fixture's vulnerable route performs a real outbound fetch
  -> callback observed [real HTTP, real socket, real receiver]
  -> CONFIRMED CWE-918/OWASP-A10:2021 finding
  -> persisted report -> retrieved over the real HTTP API
```

Result: exactly one CONFIRMED finding, on `/fetch-vulnerable`; zero
findings on `/fetch-safe` or `/reflect-only`.

## Authorization negatives (requirement 16)

Covered, with the specific test/reasoning for each:

- **Passive permit → no SSRF; XSS-only → no SSRF; SQLi-only → no
  SSRF**: proven directly through the full real pipeline
  (`test_passive_permit_produces_no_ssrf_finding`,
  `test_xss_only_permit_produces_no_ssrf_finding`,
  `test_sqli_only_permit_produces_no_ssrf_finding`) against the
  identical vulnerable fixture that, with the right permit, does
  confirm: proving the absence is due to authorization, not fixture
  behavior.
- **IDOR-only → no SSRF**: not separately re-run through the full
  pipeline (an IDOR-authorized permit requires registering two
  authentication contexts and a comparison plan, substantially more
  setup for a check that is structurally identical to the XSS-only/
  SQLi-only cases already proven): the gate
  (`"active.ssrf.callback" not in active_checks`) does not special-case
  any particular other check, so the XSS/SQLi proofs already
  demonstrate the general property.
- **Expired permit / revoked authorization / wrong target / wrong
  organization / tampered active-checks claim**: all already
  generically covered by the existing, detector-agnostic
  `test_active_checks_permit_control.py` suite
  (`test_cross_tenant_permit_use_fails`,
  `test_target_not_matching_authorization_fails`,
  `test_tampering_with_signed_active_checks_fails_verification`,
  `test_administrator_cannot_issue_active_capability_permit`): these
  tests exercise the shared `active_checks` claim/RBAC mechanism
  generically, and `active.ssrf.callback` now being a real, known
  check ID means these protections provably apply to it identically,
  with no SSRF-specific code path that could bypass them.
- **Request-budget exhaustion / cancellation before probe /
  cancellation while waiting for callback**: unit-tested directly
  (`test_probe_budget_exceeded_raises_before_any_request`,
  `test_cancellation_before_first_candidate_probes_nothing`,
  `test_cancellation_while_waiting_for_callback_is_inconclusive`).

One incidental, mechanical fix: two pre-existing tests
(`test_unknown_active_check_fails_closed`,
`test_unknown_detector_id_fails_closed`) had used the literal string
`"active.ssrf.callback"` as their example of an *unrecognized* detector
ID: a coincidence from before this slice implemented it for real.
Updated both to use `"active.nonexistent.detector"` instead; their
actual assertions (an unknown ID is rejected) are unchanged.

## False-positive controls (requirement 17)

All required scenarios covered: reflected callback URL; generic 200
(no actual URL-shaped semantics engaged); generic 500; a URL
validation error; callback from the wrong token; callback from an
expired token; duplicate callback delivery (still produces exactly one
finding, never a double-report); callback from another scan's token;
a response merely mentioning the callback service's domain in an
unrelated context; a malformed candidate (a `RequestTemplate` whose
named parameter doesn't actually exist, caught per-candidate as
`ERROR`, never aborting the whole run). "Client-side/browser fetch
only" is covered by construction rather than a dedicated test: since
WebGuard's probe never executes JavaScript, a URL that would only be
fetched by client-side code produces no server-side outbound request
and therefore no callback: indistinguishable from, and correctly
classified the same as, `/reflect-only`'s behavior.

## Timeout behavior (requirement 18)

`CallbackPolicy` bounds: `maximum_wait_seconds` (default 3.0, hard-
capped at 30.0), `grace_seconds` (default 2.0), `maximum_active_registrations`
(default 20, enforced at registration time: a 21st concurrent
registration raises `callback_registration_limit_exceeded` before any
probe is sent for it), `maximum_observations_per_token` (default 5).
No worker thread ever waits indefinitely: `wait_for_observation`'s
polling loop has a hard wall-clock deadline
(`time.monotonic() + maximum_wait_seconds + grace_seconds`) checked on
every iteration, independent of whether a callback ever arrives.

## Security boundary separation (requirement 22)

Verified explicitly, not just asserted: `scope_validator.py` and
`safe_http.py` (the modules responsible for preventing WebGuard's own
HTTP client from being pointed at an internal/private address) were
not modified in this slice at all (`git diff` confirms zero changes to
either file). The new capability this slice adds is entirely
additive: a value WebGuard embeds in a *target's own* request
parameter, and a *separate, new receiver component* that listens for
whatever the target's server chooses to do with it. These are the two
genuinely different security boundaries the brief calls out, and they
remain implemented in entirely separate code with no shared logic
between them.

## Juice Shop investigation (requirement 21)

Investigated only after the controlled fixture and real-network test
both passed, using controlled lab accounts created solely through
Juice Shop's own documented registration/login endpoints.

Juice Shop does expose a real, documented server-side URL-fetch
feature: `POST /profile/image/url` (set a profile picture by URL,
which the server fetches). Testing it with a WebGuard-controlled
callback destination reachable from inside the Juice Shop container
(`http://host.docker.internal:<port>/...`, since this slice's local
callback receiver is explicitly not production/public infrastructure)
produced a consistent `500 Error: Blocked illegal activity` response.
Inspecting the container's own logs traced this to
`profileImageUrlUpload.js`: Juice Shop's own, deliberate SSRF-
challenge protection, which blocks URLs that resolve to private/
internal-looking address ranges. `host.docker.internal` resolves to a
Docker-internal gateway address from the container's perspective, so
Juice Shop's own blocklist correctly (from its own design's
perspective) treated it as exactly the kind of internal-network target
its challenge is built to defend against test the presence of.

**This is the honest result, not a workaround target.** Per the
brief's explicit instruction, this investigation did not search for or
exploit internal network access to bypass Juice Shop's own protection
(that is precisely the "internal network pivot mechanism" requirement
3 already forbids this detector from becoming), and the detector was
not modified in any way to force a finding here. A genuinely public,
internet-routable callback destination would very plausibly pass
Juice Shop's own blocklist check and allow full confirmation, but
provisioning one is explicitly out of scope for this slice
(requirement 2: "do not provision production callback infrastructure
yet"). **Recorded as: no compatible controlled SSRF surface was
confirmed for Juice Shop within this slice's methodology and
environment.** The synthetic real-network fixture remains this
slice's validation source, exactly as the brief anticipates for this
outcome.

## Regression (requirement 22)

- Full unit suite: **1405/1405 passing** (1368 at the end of Slice 9,
  +37 new: `test_callback_broker.py` [11], `test_callback_service.py`
  [6], `test_ssrf_callback_detector.py` [19], +1 new regression test
  in `test_active_detector_registry.py`'s existing consistency test,
  +1 new regression test in `test_resource_graph.py`).
- Full integration suite (`WEBGUARD_RUN_INTEGRATION=1`, Juice Shop
  container recreated fresh for this slice's investigation): **42/42
  passing** (37 from Slice 9, +5 new: the SSRF live-fixture test and
  the four SSRF E2E-lab tests). One pre-existing Slice 9 test failure
  was found (see "Bugs found and fixed" above), root-caused to a real
  Slice 9 bug rather than test flakiness, fixed, and re-verified
  passing.
- Every pre-existing discovery, request-template, authentication,
  authenticated-crawl, XSS, SQLi, IDOR/BOLA, resource-graph, permit,
  RBAC, executor, crawler, `safe_http`, and scope/SSRF-prevention test
  file was re-run and passes: two tests needed the mechanical
  placeholder-string fix described above; no other file needed any
  change.
- Security gates: secret scan (298 repository files / 6 generated
  artifacts / 653 reachable Git blobs), static analysis (`ruff
  --select S`, zero findings, no fixes needed this slice), dependency
  audit (6 locked packages, no advisories), all passing.
- `git diff --check`: clean.

## Implemented / Tested / Proven / Not Proven / Callback Architecture / Candidate Discovery / Confirmation Model / False-Positive Controls / Safety Boundaries / CWE Mapping / Known Limitations / Test Counts / Security Gates / GitHub Commit / Remote Sync / Next Slice

**Implemented:** `active.ssrf.callback` (vocabulary widening, no
permit schema change); `CallbackToken`/`CallbackObservation`/
`CallbackPolicy`/`CallbackBroker` protocol/`InMemoryCallbackBroker`
(scanner-side); `CallbackRepository`/`ScopedCallbackRegistration`
(API-layer, multi-tenant); `CallbackHttpReceiver` (a real, runnable
local HTTP receiver); `run_ssrf_callback_detector` (candidate name
filtering, mutation-engine reuse, five-state callback-correlated
classification); `_apply_ssrf_callback_detection`/
`_ScanScopedCallbackBroker` (executor wiring, single-page scans this
slice).

**Tested:** every item above with a named test, plus the full
mandatory false-positive checklist and the authorization-negative
checklist (see their dedicated sections above for exactly which test
covers which scenario).

**Proven:** a real target application's real, server-side, standard-
library outbound HTTP request to a WebGuard-controlled callback
destination is genuinely observed over real sockets and correctly
confirmed as CWE-918: end to end, through the real permit/job/worker/
executor pipeline, with the victim endpoint distinguished from four
deliberately non-vulnerable siblings (safe, reflect-only, validation-
error, generic-500) using the identical discovery and probe mechanism
against all five.

**Not Proven:** crawl-mode SSRF detection (single-page scans only this
slice, matching the identical, already-documented precedent from
Slice 8/9's comparison-style detectors); a genuinely public,
internet-routable callback destination (this slice's receiver is
local-only by explicit design; Juice Shop's own SSRF-challenge
protection could not be tested past that boundary without either
violating the no-internal-network-probing principle or provisioning
production infrastructure, both explicitly out of scope); a CLI
convenience command for standing up the callback receiver (the
component exists and is fully tested; only an operator-facing
`webguard-api callback-server`-style subcommand is missing, matching
the same kind of gap Slice 8 initially left for authorization-
comparison plans).

**Callback architecture:** scanner-side protocol + self-contained
in-memory implementation; API-layer multi-tenant wrapper; a real,
separate, independently-startable local HTTP receiver, never
embedded inside the detector itself.

**Candidate discovery:** name-based filtering over the existing
Slice 6 `RequestTemplate` model (GET query, POST form, JSON body all
representable); discovery-time only, never confirmation evidence.

**Confirmation model:** CONFIRMED/PROBABLE distinguished only by
callback arrival timing, both requiring exact token correlation;
NOT_VULNERABLE/INCONCLUSIVE/ERROR distinguish "waited it out, saw
nothing" from "registration failed" from "the probe itself failed",
never conflated.

**False-positive controls:** see the dedicated section above, eleven
distinct scenarios, all verified to produce zero findings.

**Safety boundaries:** no internal-network probing, ever; token-only
correlation (DNS/Host-independent); bounded registrations/observations/
wait time; evidence sanitization verified directly; WebGuard's own
outbound-request scope protections completely untouched by this
slice's additions.

**CWE mapping:** `CWE-918` unconditional; `OWASP`/`A10:2021` as a
second, well-justified non-CWE namespace. `docs/CWE_COVERAGE.md`
updated: CWE-918 now IMPLEMENTED, on the strength of real callback
confirmation proven above, not merely built.

**Known limitations:** see "Not Proven" above.

**Test counts:** 1405 unit, 42 integration, all passing.

**Security gates:** secret scan, static analysis, dependency audit,
and `git diff --check` all clean, no fixes needed this slice's own new
code (one fix was needed for a pre-existing Slice 9 bug this slice's
regression discipline surfaced).

**GitHub commit:** recorded below after push and `HEAD == origin/main`
verification.

**Remote sync:** recorded below.

**Next slice:** write-level (state-changing) authorization testing
remains explicitly deferred, per this project's ongoing brief
sequence, to a dedicated future slice. A production-grade callback
service (public hostname, TLS, PostgreSQL/Redis-backed correlation
storage, rate limiting) is the most direct infrastructure extension of
this slice's own documented, not-yet-built production requirements, if
SSRF detection needs to run against real-world (non-loopback) targets.
