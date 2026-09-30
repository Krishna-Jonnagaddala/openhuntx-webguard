# Active Detection, Slice 8: Multi-Identity Authorization Differential Engine + IDOR/BOLA

## Status

This slice adds one new active detector, `active.authorization.idor`
(CWE-639, OWASP API Security Top 10, API1:2023 Broken Object Level
Authorization), built as a genuine **authorization comparison engine**
across two controlled test identities, not a parameter fuzzer, not a
sequential-ID brute-forcer, and not a reinterpretation of Slice 7's
single-identity `authentication_context_id` claim. It is the first
detector in this project confirmed against a live, real-world
application (OWASP Juice Shop) in addition to a controlled synthetic
fixture.

## What was built

### Resource model (`workers/scanner/src/webguard_scanner/authorization_resource.py`)

`AuthorizationResource`: `resource_type`, `endpoint`, `method`,
`identifier_location` (`path`/`query`/`none`), `identifier_name`,
`identifier_value`, `owning_test_identity`, `source`, `content_type`,
`expected_access`, `owner_marker`. `resource_id` is computed in
`__post_init__` as a SHA-256 digest of **structural fields only**
(canonical endpoint, method, identifier location/name/value), never
response content, mirroring the `candidate_id`/`RequestTemplate`
fingerprinting pattern already established in Slices 5–6.

`ResourceSource`: `EXPLICIT_TEST_RESOURCE`, `EXPLICIT_FIXTURE`,
`CREATED_BY_IDENTITY`, `OBSERVED_RESPONSE`, `CONTROLLED_LAB_API`: the
requirement that a resource identifier must originate from one of
these controlled sources is enforced **structurally**, not just in
documentation: `AuthorizationResource` requires a `source` value from
this enum at construction, and there is no code path anywhere in this
module, the detector, or the executor wiring that generates, mutates,
or enumerates an `identifier_value`: every one is either read
directly from an operator-supplied `ResourcePairSpec`, or (in the
Juice Shop investigation below) extracted from an identity's own
authenticated JWT.

`ResourceOwnership`: `PRIVATE_TO_OWNER`, `SHARED`, `PUBLIC`, `UNKNOWN`,
the expected-access model requirement 16 calls for. A resource
classified `SHARED` or `PUBLIC` is unreportable by construction (see
"Confirmation logic" below), independent of what HTTP status either
identity receives.

### Detector (`workers/scanner/src/webguard_scanner/idor_authorization_detector.py`)

`run_idor_authorization_detector(target, resource_pairs, context, *,
primary_identity_label, primary_material, secondary_identity_label,
secondary_material, policy, before_request, after_request,
cancellation_check) -> IdorDetectorRunResult`.

For each `AuthorizationResourcePair` (a primary resource + a secondary
resource, both structurally paired, never generated), issues exactly
four requests: baseline A→A, baseline B→B, cross A→B, cross B→A, each
resolved through `apply_authentication()`, Slice 7's one shared
session/credential-application mechanism. **No detector code in this
slice constructs an `Authorization`/`Cookie` header directly.**

**Confirmation logic** (`_classify`), five states:

- **INCONCLUSIVE**: either identity's own baseline did not succeed or
  did not return HTTP 200, **or** the resource pair's
  `expected_access` is `SHARED`/`PUBLIC` (checked first, before any
  other evaluation; a shared resource is never reachable by any
  branch that could produce CONFIRMED or PROBABLE).
- **ERROR**: the cross-identity request itself failed at the
  transport level (timeout, connection refused, etc.), distinct from
  a successful HTTP response that happens to deny access.
- **NOT_VULNERABLE**: cross-identity request returned a non-200
  status (403/404/etc.), or returned 200 but its content fingerprint
  does not match the victim's own baseline fingerprint (a generic 200
  page, an unrelated public response) and no marker was configured or
  matched.
- **CONFIRMED**: cross-identity request returned 200 **and** its
  content fingerprint exactly matches the victim's own baseline
  fingerprint (SHA-256 of the response body). This is the
  requirement-8 distinction made real in code: the detector does not
  merely observe 200, it establishes that the object returned is
  actually the other identity's controlled resource.
- **PROBABLE**: reachable **only** when an operator has explicitly
  configured `AuthorizationResource.owner_marker` (default: no marker
  configured) and that exact marker string is present in the
  cross-identity response body, without an exact fingerprint match.
  Never inferred from response length, timing, or any other weak
  structural coincidence; see "Bugs found and fixed" below for why
  this exists.

Both directions of every pair are classified independently
(`outcome_primary` for A→B, `outcome_secondary` for B→A), each
producing its own `IdorComparisonRecord` and, only for
`CONFIRMED`/`PROBABLE`, its own `NormalizedFinding`.

**CWE/OWASP mapping**: every finding this detector produces carries
exactly `ExternalIdentifier("CWE", "CWE-639")` and
`ExternalIdentifier("OWASP-API", "API1:2023")`, unconditionally.
`CWE-862` (Missing Authorization) is **never** attached automatically.
The detector's own evidence establishes a specific object-level bypass
(a user-controlled key granting access to a specific other identity's
resource), not a general absence-of-authorization-check condition;
attaching the broader CWE would overclaim what was actually observed.
`OWASP-API` is a new identifier namespace for this project (confirmed
via inspection of `ExternalIdentifier` that `namespace` carries no
allow-list restriction), the first non-CWE taxonomy this project's
findings use, since Broken Object Level Authorization is an
API-specific classification with no equally precise single CWE
equivalent.

**Evidence sanitization**: finding evidence (`Evidence(summary=...)`)
contains only the detector ID/version, scan/authorization/permit IDs,
the two identity *labels* (never secrets), the expected-vs-observed
authorization outcome, and the classification outcome, never a
bearer token, cookie, password, session ID, or resource content.
Verified directly (`EvidenceSanitizationTests` in the unit suite, and
again against a real persisted report in the true end-to-end test).

**Safety budgets**: `_REQUESTS_PER_RESOURCE_PAIR = 4`; total request
cost (`len(resource_pairs) * 4`) is checked against
`policy.maximum_probe_requests` **before any request is issued**,
raising the existing `ActiveDetectionError("candidate_budget_exceeded",
...)`, reusing Slice 5/6's error class rather than inventing a new
one. `cancellation_check`, if supplied, is polled before every
resource pair; once it returns `True`, no further pairs are compared.
For this initial implementation, two identities and a bounded,
operator-supplied resource-pair list are the entire scope: there is
no N×N cross-user comparison, and no code path that would produce one.

### Identity isolation

Proven directly (`IdentityIsolationTests`): fetching identity A's own
baseline never sends identity B's token, and vice versa, by inspecting
which bearer token was actually attached to which request path in a
fake connection that records `sent_tokens_by_path`. Context switching
happens in exactly one place: the two independent
`apply_authentication()` calls inside `_fetch_resource`, parameterized
by whichever `AuthenticationMaterial` the caller passed for that
specific fetch, never by mutating shared state.

### Comparison-plan model and repository (`apps/api/src/webguard_api/authorization_comparison.py`)

**Design decision (requirement 4):** the existing permit architecture
was inspected first, per the brief's explicit instruction, before
building anything. Reinterpreting the existing singular
`authentication_context_id` claim as "a list of two" was rejected:
that claim's entire validation path (single `require_bound` call,
single resolved `AuthenticationMaterial` per scan) is built around
exactly one identity, and overloading it would either break that path
or require threading a type-ambiguous value through it. Instead: a new,
independent, versioned permit claim,
`authorization_comparison_plan_id`, referencing a new record type
(`AuthorizationComparisonPlanRecord`) that itself references, never
embeds, the two `authentication_context_id`s it compares. Two
independent signed references, two independent responsibilities,
exactly the "smallest clean mechanism" the brief asked for.

`AuthorizationComparisonPlanRecord`: `comparison_plan_id`,
`organization_id`, `target`, `authorization_id`, `primary_context_id`,
`secondary_context_id`, `permitted_active_check` (always
`"active.authorization.idor"`, this plan type has exactly one
purpose), `allowed_http_methods`, `resource_scope` (a tuple of
`ResourcePairSpec`), `maximum_resources`, `maximum_comparisons`,
`created_at`, `expires_at`, `revoked_at`. **Contains references only:
no cookie, password, bearer token, or API key ever appears on this
record or its `to_public_dict()`.**

`AuthorizationComparisonPlanRepository.create()` enforces, in code, not
merely in documentation:

- **Two distinct identities** (requirement 3): raises
  `authorization_comparison_identities_not_distinct` if
  `primary_context_id == secondary_context_id`.
- Non-empty resource scope, and both a resource-pair count bound
  (`MAXIMUM_RESOURCE_PAIRS_PER_PLAN = 10`) and a total-comparison bound
  (`MAXIMUM_COMPARISONS_PER_PLAN = 20`, i.e. `len(resource_scope) * 2`),
  requirement 12's safety budgets, enforced at plan-registration
  time, independent of the detector's own per-run request budget.
- `expires_at` must be strictly in the future relative to `now`.

Storage is in-memory only, for the same two reasons Slice 7's
`AuthenticationContextRepository` is: the plan references but never
contains secrets, and building a throwaway SQLite schema now would be
rework given this project's planned PostgreSQL migration sequencing.
**Known limitation, stated plainly (requirement 20):** this repository
does not survive across separate OS-process invocations; see "True
end-to-end test" below for how this shaped that test's scope, exactly
mirroring Slice 7's identical scoping decision for
`AuthenticationContextRepository`. No raw authentication secret is
ever written to SQLite to work around this.

### RBAC (`apps/api/src/webguard_api/auth.py`)

Three new owner-only permissions:
`AUTHORIZATION_COMPARISON_REGISTER`, `AUTHORIZATION_COMPARISON_READ`,
`AUTHORIZATION_COMPARISON_REVOKE`, excluded from `ADMINISTRATOR`,
alongside the Slice 7 authentication-context permissions and
`PERMIT_ISSUE_ACTIVE`, on the same reasoning: registering or revoking
an authorization-comparison plan is at least as sensitive as issuing
an active-detection-capable permit.

### TrustScan permit binding (schema 1.2 → 1.3)

`authorization_comparison_plan_id: str | None = None` added as a new
signed claim on `TrustScanPermitClaims`/`TrustScanPermitSubmission`:
a genuine field addition, following the same process
`docs/audit/trustscan-permit-schema-policy.md` already reserves for
that: schema version bumped 1.2 → 1.3, replace-in-place, justified by
the same, re-verified precondition as the 1.0→1.1 and 1.1→1.2 bumps:
WebGuard has still never been deployed, so no real persisted 1.2
permit exists that this could invalidate. `active.authorization.idor`
was also added to `KNOWN_TRUSTSCAN_ACTIVE_CHECKS`'s vocabulary: a
widening change, not requiring its own version bump (same precedent as
Slice 6's `allowed_http_methods` vocabulary growth). Documented in the
schema policy file itself, not just here.

`WebGuardJobService.issue_permit` requires
`AUTHORIZATION_COMPARISON_REGISTER` (owner-only) when a submission sets
this claim, then:

1. Calls `authorization_comparison_plans.require_bound(...)` against
   the submission's own organization/target/authorization: a
   comparison plan registered under a different tenant, target, or
   authorization cannot be bound to this permit, and cannot be bound
   if expired or revoked.
2. Additionally requires that `comparison_plan.permitted_active_check`
   (always `"active.authorization.idor"`) is present in the
   submission's own `active_checks`: **referencing a comparison plan
   without also explicitly requesting the check it exists to run is
   rejected** (`authorization_comparison_check_not_requested`), and
   the reverse holds too: requesting `active.authorization.idor`
   without a bound comparison plan means the executor's own
   `_apply_authorization_comparison` no-ops (see below), so the
   detector never actually runs: the check can be *authorized*
   without a plan, but never *executed* without one.

`ScanJobExecutor._apply_authorization_comparison` re-validates the
identical binding (plan **and** both underlying contexts) independently
at execution time, raising `TrustScanRuntimeSafetyError` (fail closed,
same class used for every other runtime safety decision) if anything
was revoked or expired after permit issuance but before the scan ran.

### Operator-facing surface

- `POST /v1/authorization-comparisons` (register), `POST
  /v1/authorization-comparisons/{id}/revoke`: mirror the existing
  authentication-context HTTP routes exactly (`http_api.py`).
- `webguard-api permit issue --authorization-comparison-plan-id`
  (`cli.py`): the permit-issuance CLI path was extended; a dedicated
  `authorization-comparison register` CLI subcommand was **not**
  built this slice (see "Known limitations"). Plan registration is
  fully exercised through the real HTTP API in the true end-to-end
  test below, exactly the path an HTTP-based integration (not the CLI)
  would use.

### Scan-time wiring (`executor.py`)

`_apply_authorization_comparison`: no-ops immediately (returns the
report unchanged) unless `active.authorization.idor` is in
`active_checks` **and** a `comparison_plan_id` claim is present: an
XSS-only or SQLi-only permit's report is never touched by this
function, proven directly by the permit-issuance rejection above (such
a permit cannot legally carry a comparison-plan reference in the first
place) and by construction (the two guard conditions are checked
before anything else in the function body). Also no-ops for crawl-mode
reports (`hasattr(report, "pages")`), deferred, see "Known
limitations." Resolves both contexts' secret material and identity
labels through the same `AuthenticationContextRepository` Slice 7
introduced, builds `AuthorizationResourcePair`s from the plan's
`resource_scope` via `_resource_pair_from_spec`, and calls
`run_idor_authorization_detector`, appending any findings to the
report.

## Bugs found and fixed during this slice

1. **A length-based PROBABLE fallback produced a false positive.** The
   first version of `_classify` fell back to comparing
   `cross_primary_to_secondary.response_length ==
   baseline_secondary.response_length` when fingerprints didn't match
   exactly, to assign PROBABLE. A deliberately constructed test
   scenario (a real 35-byte order JSON body versus a completely
   unrelated 35-byte generic HTML page) triggered a false PROBABLE
   finding purely from the coincidental byte-length match, directly
   violating "generic HTTP 200 alone must not be sufficient" (caught
   by `test_generic_200_response_is_not_a_finding`). **Fixed** by
   removing the length-based fallback entirely and replacing it with
   the explicit, opt-in `owner_marker` mechanism described above.
   PROBABLE is now unreachable by any inferred structural coincidence.
2. **Baseline HTTP failure (not just transport failure) fell through
   to NOT_VULNERABLE instead of INCONCLUSIVE.** The original
   `_classify` checked `.succeeded` (transport-level success) on both
   baselines but never checked their HTTP `status`, so a baseline that
   transported successfully but returned a genuine `500` was
   incorrectly treated as a valid baseline and fell through to a
   NOT_VULNERABLE verdict on the cross-access check, rather than
   INCONCLUSIVE (caught by
   `test_failed_baseline_is_inconclusive_not_vulnerable`). **Fixed**
   by adding explicit `baseline_primary.status != 200` and
   `baseline_secondary.status != 200` checks before any cross-access
   evaluation.

Both bugs were caught by tests written as part of this slice's own
test-development process, before any commit, not found afterward or
reported by a user.

## False-positive controls (requirement 15)

Verified directly in `tests/unit/test_idor_authorization_detector.py`:
secure-endpoint cross-access denial (403/404) never produces a
finding; a generic 200 response with an unrelated body never produces
a finding (the bug-#1 regression test); a nonexistent object (404)
never produces a finding; a `SHARED` resource never produces a finding
**even when both identities receive an identical 200** (the exact
scenario requirement 16 calls out); a failed/500 baseline is
INCONCLUSIVE, never NOT_VULNERABLE and never a finding (bug #2); no
marker configured plus no exact fingerprint match safely defaults to
NOT_VULNERABLE rather than any positive classification. The true
end-to-end test (below) independently proves the same for the secure
and shared endpoints in the full pipeline, not just the detector
function in isolation.

## Safety boundaries

### Two-identity requirement (requirement 3)

Enforced at three independent layers: the repository
(`authorization_comparison_identities_not_distinct`), re-verified at
the service layer with a dedicated test
(`test_one_identity_only_cannot_register_a_plan`), and structurally
impossible to bypass at the detector layer since
`run_idor_authorization_detector` requires two separately-supplied
`primary_material`/`secondary_material` arguments with no default that
would let a caller supply the same value once.

### Cross-organization / cross-target / expired / revoked binding (requirements 13, 23)

All independently tested at the service layer
(`tests/unit/test_idor_permit_control.py`): a context registered under
a different organization is rejected
(`authentication_context_organization_mismatch`); a context bound to a
different target is rejected
(`authentication_context_target_mismatch`); an expired context is
rejected (`authentication_context_expired`); a revoked context is
rejected (`authentication_context_revoked`); a revoked comparison plan
is rejected at permit-issuance time
(`authorization_comparison_plan_revoked`); an unknown comparison plan
is rejected (`authorization_comparison_plan_not_found`); a permit
whose `active_checks` doesn't include `active.authorization.idor`
cannot bind a comparison plan
(`authorization_comparison_check_not_requested`, independently proven
for the empty-list, XSS-only, and SQLi-only cases).

### Tampering (requirement 23)

`test_tampering_with_signed_comparison_plan_id_fails_verification`:
rebinding a signed permit's `authorization_comparison_plan_id` claim
to a different value (here, `None`) without re-signing invalidates the
Ed25519 signature exactly like tampering with any other claim already
does: the claim is fully covered by the existing signature, not a
side-channel value.

### Secrets absent from errors, reports, and audit (requirement 17)

`test_secrets_never_appear_in_service_errors` plants a real bearer
token, revokes its context, and asserts the resulting
`ApiServiceError.message` never contains it. The true end-to-end test
below independently verifies both test accounts' real bearer tokens
are absent from the entire persisted report text after a genuine
finding was produced, the strongest form of this check, since it
inspects the actual artifact an operator would read. Audit calls
throughout `service.py`'s new methods pass only structural
`detail_code` strings (e.g. `resource_pairs_3`); no code path threads
a resource_scope value or secret into an audit call.

## Controlled vulnerable fixture (requirement 14)

A purpose-built `ThreadingHTTPServer`-based HTTPS fixture
(`tests/integration/test_idor_authorization_e2e_lab.py`) with two
bearer-token identities (`user-a`, `user-b`) and:

- `GET /api/orders/{id}`, **secure**: ownership is actually checked;
  returns the real order body only when the requesting identity owns
  it, `403` otherwise, `404` for a nonexistent order.
- `GET /api/orders-vuln/{id}`, **deliberately vulnerable**: identical
  underlying data, but any authenticated identity receives the real
  content regardless of ownership, no ownership check at all.
- `GET /api/shared/team-document`: a resource intentionally
  accessible by both identities, configured with
  `expected_access=SHARED` in the comparison plan's `resource_scope`.
- `GET /api/public/info`: unauthenticated, identical for everyone
  (not exercised by the comparison plan itself, but present as a
  reachable false-positive control for the fixture's own consistency).

Proven directly against this fixture (see the true end-to-end test
below): the secure endpoint never produces a finding; the vulnerable
endpoint produces a genuine CONFIRMED/CWE-639 finding in both
directions (A can read B's real order, and B can read A's real order,
the fixture's vulnerability is symmetric by construction); the shared
endpoint never produces a finding despite both identities legitimately
receiving 200.

## True end-to-end test (requirement 22)

`tests/integration/test_idor_authorization_e2e_lab.py`,
`test_full_idor_comparison_pipeline`:

```
register authentication-context A [real HTTP]
register authentication-context B [real HTTP]
  -> register authorization-comparison plan (resource_scope: secure +
     vulnerable + shared endpoints, explicitly supplied) [real HTTP]
  -> POST /v1/permits (active_checks=[active.authorization.idor],
     authorization_comparison_plan_id set) [real HTTP]
  -> POST /v1/jobs [real HTTP]
  -> real ScanJobWorker -> real ScanJobExecutor
  -> _apply_authorization_comparison -> run_idor_authorization_detector
  -> CONFIRMED CWE-639/OWASP-API finding on the vulnerable endpoint
  -> persisted WebGuardReport
  -> GET /v1/jobs/{id}/result, report file read [real HTTP + real file]
```

**Scoping decision (requirement 20), stated explicitly:** because both
`AuthenticationContextRepository` and
`AuthorizationComparisonPlanRepository` are in-memory only, this test
constructs `WebGuardJobService`/`ScanJobExecutor`/`ScanJobWorker`
directly and shares one instance of each repository between the
service and the executor, exactly Slice 7's identical scoping
decision for its own authenticated-scanning E2E test, applied here for
the same reason. Every step that references either repository (context
registration ×2, comparison-plan registration, permit issuance with
the comparison claim, job submission, result retrieval) goes over
**real HTTP against a real socket**, through the real
`create_server`/`ScanJobWorker` objects; only the process boundary is
collapsed, not the transport.

Result: exactly one CONFIRMED finding is produced per direction on the
vulnerable endpoint (both `orders-vuln/A-001` and `orders-vuln/B-001`
paths), each carrying `CWE-639` and an `OWASP-API` identifier; the
secure endpoint and the shared endpoint produce **no** findings at
all; both test accounts' bearer tokens are verified absent from the
full persisted report text.

## Juice Shop investigation (requirement 21)

Unlike Slices 1, 4, and 6's reflected-XSS and SQL-injection
detectors, each of which found **no reachable surface** on Juice
Shop for their respective methodologies (Angular SPA, no
server-rendered forms), this detector's methodology (compare
GET-accessible, per-user object responses across two identities) maps
directly onto a real, well-known, publicly documented Juice Shop
weakness: **viewing another user's shopping basket by ID.**

Two lab accounts were created using **only** Juice Shop's own
documented `POST /api/Users` registration endpoint and
`POST /rest/user/login` login endpoint: no enumeration, no
brute-force, no privilege escalation, and no data alteration of any
kind. Each account's own shopping-basket ID (the JWT's `bid` claim)
was obtained **only from that account's own authenticated login
response**, never guessed, generated, or enumerated, matching the
brief's "controlled lab API response" resource-identifier source
exactly.

Manual verification (read-only GETs only) confirmed: account A's own
basket (`GET /rest/basket/{A's own bid}` with A's token) returns 200
with A's real basket; account B's own basket likewise; **account A's
token against B's basket ID, and account B's token against A's basket
ID, both return 200 with the other account's real basket content**,
a genuine, live, reachable authorization bypass.

`tests/integration/test_idor_authorization_juice_shop_lab.py` then ran
the actual, unmodified `run_idor_authorization_detector` function
against this live target over a real HTTP connection, using each
identity's real bearer token. **Result: CONFIRMED, CWE-639, exactly as
manual verification predicted**: the detector's own content-
fingerprint-based classification (not a weakened or Juice-Shop-specific
code path, the identical function used against the synthetic fixture
and in the unit tests) independently reproduced the same conclusion a
human tester would reach manually. The detector was not altered in any
way to force this result; it was pointed at a real target with a real,
independently-verifiable vulnerability and it worked.

This is a materially different, and stronger, result than every prior
slice's Juice Shop investigation could report, recorded here
honestly, and not overclaimed as evidence the detector is
"generally accurate": one confirmed true positive against one known
vulnerability on one application says the classification logic *can*
correctly fire on real-world data, not that its false-positive rate
against arbitrary real applications has been measured.

## Regression (requirement 24)

- Full unit suite: **1318/1318 passing** (1278 at the end of Slice 7,
  +40 new: `test_authorization_comparison.py` [10],
  `test_idor_authorization_detector.py` [12], and
  `test_idor_permit_control.py` [18]; every other modified file's test
  count is unchanged or was itself the mechanical schema-1.3 fixture
  fix described below).
- Full integration suite (`WEBGUARD_RUN_INTEGRATION=1`, Juice Shop
  container live): **33/33 passing** (31 from Slice 7, +2 new: the
  IDOR true end-to-end lab test and the Juice Shop live-confirmation
  test).
- One pre-existing integration test required a mechanical fix for
  schema 1.3:
  `tests/integration/test_authenticated_scanning_e2e_lab.py` built its
  own raw permit-submission JSON body and needed
  `"authorization_comparison_plan_id": None` added, the same kind of
  additive, non-weakening fix Slice 7 itself needed when *its* new
  field was introduced. No other pre-existing test file needed
  modification for the schema bump. The CLI's own `_permit_issue_command`
  was fixed once, at the source, during development.
- Every pre-existing authentication, attack-surface, request-template,
  XSS, SQLi, permit, RBAC, executor, `safe_http`, crawler, and
  scope/SSRF test file was re-run and passes **unmodified**, except the
  one mechanical fixture fix above.
- Security gates: secret scan (278 repository files / 6 generated
  artifacts / 601 reachable Git blobs), static analysis (`ruff --select
  S`, zero findings), dependency audit (6 locked packages, no
  advisories), all passing, no fixes needed this slice.
- `git diff --check`: clean.

## Implemented / Tested / Proven / Not Proven / Identity Model / Resource Model / Authorization Differential / False-Positive Controls / Safety Boundaries / CWE/OWASP Mapping / Known Limitations / Test Counts / Security Gates / GitHub Commit / Remote Sync / Next Slice

**Implemented:** `AuthorizationResource`/`AuthorizationResourcePair`
(structural, content-independent fingerprinting);
`run_idor_authorization_detector` (four-request-per-pair differential
comparison, five-state classification, marker-gated PROBABLE tier,
budget/cancellation enforcement); `AuthorizationComparisonPlanRecord`/
`AuthorizationComparisonPlanRepository` (two-distinct-identity
enforcement, resource/comparison bounds, in-memory); a new,
independent signed TrustScan permit claim
(`authorization_comparison_plan_id`, schema 1.2 → 1.3); RBAC (three
new owner-only permissions); HTTP routes for plan registration/
revocation; permit-issuance and executor-time double-binding
validation; executor wiring (`_apply_authorization_comparison`,
crawl-mode deferred).

**Tested:** every item above with a named test, plus the full
mandatory-negative-test list from requirement 23: one identity only
cannot register a plan; different-organization context rejected;
different-target context rejected; expired context rejected; revoked
context rejected; revoked comparison plan rejected at permit issuance;
unknown comparison plan rejected; IDOR-not-in-active_checks rejected;
XSS-only and SQLi-only permits independently proven unable to carry a
comparison plan; request budget enforced before any request is sent;
cancellation stops remaining comparisons; tampering with the signed
`authorization_comparison_plan_id` claim invalidates the permit
signature; secrets absent from service errors and from the full
persisted end-to-end report.

**Proven:** the detector correctly distinguishes a secure,
ownership-checked endpoint (no finding) from a structurally identical
but unprotected endpoint (CONFIRMED finding) using real HTTP requests
issued through the real permit/executor/worker pipeline; a shared
resource is never reported despite both identities receiving 200; the
same unmodified detector function independently reproduces a real,
publicly known Juice Shop broken-access-control vulnerability
(viewing another user's basket) using resource identifiers obtained
only from each account's own authenticated session, the first
detector in this project validated against a live application rather
than only a synthetic fixture.

**Not Proven:** authenticated crawl-mode IDOR scanning (this slice
covers single-page scans only; crawl-mode reports pass through
`_apply_authorization_comparison` unchanged, deferred exactly as
Slices 5–6 deferred site-level discovery expansion in crawl mode);
write-level (POST/PUT/DELETE) authorization testing (explicitly out of
scope per the brief: read-only GET/idempotent methods only this
slice); a dedicated `authorization-comparison register` CLI
subcommand (the HTTP route and service method exist and are fully
tested; only the CLI convenience wrapper is missing); cross-process
persistence of comparison plans (in-memory only, by design, same
limitation as Slice 7's authentication contexts); PROBABLE-tier
detection against a real application (the marker mechanism was only
exercised against the synthetic fixture in unit tests; Juice Shop's
basket vulnerability was strong enough to hit CONFIRMED directly, so
the marker path was not separately live-validated).

**Identity model:** exactly two, explicitly registered, distinct
`AuthenticationContext`s per comparison plan, reusing Slice 7's model
unchanged, referenced by ID from a new, independent plan record. No
N-identity generalization was built or attempted this slice, per the
brief's own explicit scope limit.

**Resource model:** `AuthorizationResource`, structurally fingerprinted
(SHA-256 of endpoint/method/identifier-location/name/value, never
content), sourced exclusively from one of five controlled origins
(`ResourceSource`), carrying an explicit expected-access classification
(`ResourceOwnership`: private/shared/public/unknown) that gates
reportability independent of observed HTTP status.

**Authorization differential:** baseline-then-cross-access comparison
across both identities and both directions per resource pair;
classification requires an exact content-fingerprint match to the
victim's own baseline for CONFIRMED, or an explicit, operator-configured
marker match for PROBABLE: a bare HTTP 200, or any weaker structural
coincidence (response length was tried and rejected), is never
sufficient.

**False-positive controls:** secure-endpoint denial, generic/unrelated
200 responses, nonexistent objects, shared/public resources (even with
identical 200 for both identities), and failed baselines (transport or
HTTP-level) all independently verified to never produce a finding.

**Safety boundaries:** two-distinct-identity requirement enforced at
the repository and service layers; resource-pair and total-comparison
count bounds enforced at plan-registration time; per-run request
budget enforced before any request is sent; cancellation checked
before every resource pair; double binding validation (plan and both
contexts) at both permit-issuance and execution time; signature
coverage over the new claim verified by a tampering test; secrets
verified absent from errors, the persisted report, and (implicitly, by
construction: no secret is ever passed to an audit call) the audit
trail.

**CWE/OWASP mapping:** `CWE-639` (Authorization Bypass Through
User-Controlled Key) attached unconditionally; `OWASP-API`/`API1:2023`
(Broken Object Level Authorization) attached alongside it as this
project's first non-CWE identifier namespace; `CWE-862` deliberately
never attached automatically. `docs/CWE_COVERAGE.md` updated
accordingly.

**Known limitations:** see "Not Proven", restated here as
forward-looking scope: authenticated crawl-mode IDOR, write-level
authorization testing, a CLI registration subcommand, cross-process
plan persistence, and live PROBABLE-tier validation are the concrete
next steps if this capability needs to grow further.

**Test counts:** 1318 unit, 33 integration, all passing.

**Security gates:** secret scan, static analysis, dependency audit,
and `git diff --check` all clean, no fixes needed this slice.

**GitHub commit:** recorded below after push and `HEAD == origin/main`
verification.

**Remote sync:** recorded below.

**Next slice:** write-level (state-changing) authorization testing was
explicitly deferred by this slice's own brief ("Write-level testing …
designed separately later") and is the most direct extension of this
slice's identity/resource model. Authenticated crawl-mode expansion
(making IDOR reachable across a full multi-page scan, not just a
single page) is the other concrete candidate, building on the same
"not yet proven" gap Slice 7 already flagged and this slice
deliberately left unresolved rather than rushed.
