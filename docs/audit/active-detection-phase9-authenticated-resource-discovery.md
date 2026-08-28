# Active Detection — Slice 9: Authenticated Crawl & Authorization Resource Discovery

## Status

This slice adds **no new active detector and no new CWE**. It removes
Slice 8's central limitation -- that IDOR/BOLA comparison resources had
to be explicitly supplied by the operator -- by teaching WebGuard to
*discover* authorization-sensitive resources while authenticated as
each controlled test identity, and feeding those discoveries into the
existing, unchanged `active.authorization.idor` detector. Discovery is
strictly additive: every Slice 8 code path (explicit `resource_scope`,
classification logic, safety budgets, CWE/OWASP mapping) is untouched
and independently re-verified passing.

## What was built

### Authenticated crawling (`crawler.py`, `crawl_scan.py`)

Slice 7's authentication mechanism is now threaded through the
crawler, closing the one major fetch path in this codebase that Slice
7 did not update. `crawl_same_origin` and `run_passive_crawl_scan` both
gained an `authentication_material: AuthenticationMaterial | None =
None` parameter (default `None`, every pre-existing caller unaffected
and unauthenticated exactly as before). The one place a header is
attached is unchanged: `_fetch_with_retry` calls
`authentication.apply_authentication(url, material, now=...)` and
passes the result as `fetch_once`'s `extra_headers` -- the identical
mechanism `active_detection.issue_probe`/`fetch_same_origin_page`
already used. **No detector-specific authentication handling was
introduced anywhere in this module**, satisfying requirement 2
directly.

Every existing crawler control is preserved unchanged, because nothing
about the control-flow, budgets, or scope enforcement was touched:
authorization/permit-derived policy, `CrawlPolicy`'s
page/depth/link/rate/time/attempt bounds, same-origin restriction
(`_canonical_candidate`), DNS/IP validation (via the target's own
already-resolved `ValidatedTarget`), cancellation
(`CrawlCancellationToken`), checkpointing (`CrawlResumeState`/
`on_checkpoint`), and response limits (`FetchPolicy`).

**Credential isolation** (requirement 3) is structural, not just
tested: `authentication_material` is a plain function parameter with
no shared mutable state anywhere in the call chain, so two crawls for
two identities cannot cross-contaminate by construction. Proven
directly (`tests/unit/test_authenticated_crawl.py`,
`CredentialIsolationTests`): identity A's crawl never sends B's token
and vice versa, an unauthenticated crawl sends no authentication header
at all, and a *resumed* crawl still applies the correct material after
resume.

### Resource-discovery stage (`authorization_resource_discovery.py`)

A new, reusable, stateful stage (`ResourceDiscoverySink`, requirement
4) visited once per crawled page (`visit_page(target, response)`),
alongside the crawl's existing passive analyzers (wired into
`crawl_scan.py`'s `analyze_page` closure via a new, optional
`resource_discovery` parameter on `run_passive_crawl_scan` --
`CrawlScanResult`'s own schema is completely untouched by this).

- **HTML links**: `_discover_html_link_resources` parses `<a href>`
  values, resolves them against the page URL, and recognizes a
  same-origin two-segment path (`/orders/A-001`) as a candidate object
  resource -- `resource_type` from the second-to-last segment,
  `identifier_value` from the last. Off-origin links, and structural
  non-identifiers (`login`, `static`, `assets`, file extensions),
  are rejected before ever becoming a resource.
- **JSON fields**: `_discover_json_field_resources` walks a parsed
  JSON body (bounded depth/field count) looking for keys matching a
  configurable `field_patterns` set (default: `id`, `user_id`,
  `order_id`, `document_id`, `basket_id`, `resource_id` --
  requirement 7's suggested list, explicitly documented as
  configurable rather than exhaustive). A matching field only becomes
  **PATH-addressable** (and therefore comparison-eligible) when its
  value is *self-referential* -- it matches the URL's own trailing path
  segment, structural proof the endpoint is parameterized by exactly
  this value, discovered without ever fetching or guessing anything
  new. A non-self-referential match (e.g. a `UserId` field naming who
  owns a resource, not the resource itself) is still recorded, but with
  `identifier_location=NONE`, which the eligibility rules below make
  permanently uncomparable -- directly satisfying requirement 18's
  "API returning another user's ID only as non-sensitive metadata"
  false-positive control.
- **`endpoint_templates`** (requirement 7's "explicit configuration"
  signal): an optional, operator-supplied `{field_name:
  "relative/template/{value}"}` mapping for the case where an
  identifier is legitimately revealed on one endpoint (e.g. a login
  response) but addresses a *different*, separately-known endpoint.
  The *value* still comes only from an observed field; the *endpoint*
  comes only from explicit configuration, never inference. Every
  resulting endpoint is still independently same-origin-checked before
  becoming a resource. This is what made the Juice Shop investigation
  below possible (see "Juice Shop investigation").
- **`IdentifierProvenance`** (requirement 5, `authorization_resource.py`):
  a new, closed enum -- `HTML_LINK`, `API_RESPONSE`, `JSON_FIELD`,
  `FORM_VALUE`, `OPENAPI_DECLARATION`, `EXPLICIT_OPERATOR_INPUT`,
  `CONTROLLED_FIXTURE` -- added as a new field on `AuthorizationResource`
  (default `EXPLICIT_OPERATOR_INPUT`, so every Slice 8 resource
  remains correctly and honestly labeled without touching a single
  Slice 8 call site). Every member names a legitimate, non-generative
  observation mechanism; there is no member for a generated,
  sequential, or brute-forced value, and there must never be one --
  the enum itself **is** the enforcement, the same discipline
  `ResourceSource` already established in Slice 8.
- **Bounds** (`ResourceDiscoveryBudget`): maximum resources per page,
  maximum total resources per crawl, maximum JSON depth/field count
  examined, maximum response bytes considered, maximum identifier
  value length -- an explicit sub-budget independent of both the
  crawl's own `CrawlPolicy` and the detector's own comparison-request
  budget (requirement 17).
- **No complete response body is ever retained** -- only the bounded
  set of recognized `AuthorizationResource` values.

### Login-page / expired-session detection (requirement 11, 12)

`AuthenticationHealthCriterion` (`login_page_marker`,
`authenticated_marker`, `unauthenticated_statuses`) reuses Slice 7's
own principle -- HTTP 200 alone is never sufficient evidence of
anything -- applied here to the crawl phase. `classify(response)`
distinguishes an explicit denial (`401`/`403` ->
`authentication_failed`) from a `200` that looks like a login page or
is missing an expected authenticated marker (`authentication_expired`).
`ResourceDiscoverySink.visit_page` checks this **before** any
discovery logic runs: an unhealthy page contributes zero resources, is
recorded in `pages_with_authentication_failure`, and cancels the
crawl's own `CrawlCancellationToken` -- reusing the crawler's existing
cooperative-cancellation mechanism (checked between page fetches, the
same granularity every other cancellation check in this codebase
already uses) rather than inventing new control flow to abort
mid-crawl. The result's `status` field is exactly
`AuthenticatedCrawlStatus.AUTHENTICATION_EXPIRED`/`AUTHENTICATION_FAILED`
in that case, never silently `SUCCEEDED`.

### Resource graph and comparison eligibility (`resource_graph.py`, requirements 8, 9, 14)

`AuthorizationResourceGraph`: resources keyed by owning identity label,
deduplicated by structural `resource_id`, holding references only --
no authentication material anywhere in this type.

`is_eligible_for_comparison(primary, secondary)` -- the deterministic
eligibility rules requirement 9 asks for, **all** of which must hold:
distinct owning identities; same `resource_type`; same HTTP method,
and that method must be read-only (`GET`/`HEAD`); same
`identifier_location` (and never `NONE` -- a resource with no
structural endpoint template can never be compared); a
`PRIVATE_TO_OWNER` expected-access on **both** sides (`SHARED`,
`PUBLIC`, and `UNKNOWN` are permanently excluded, regardless of
observed HTTP status); an approved identifier provenance on both sides
(`APPROVED_COMPARISON_PROVENANCE` -- currently every `IdentifierProvenance`
member, since the enum itself excludes generated values, but checked
explicitly as a real gate rather than assumed); a compatible endpoint
*template* (the endpoint with its own identifier value structurally
removed); and distinct identifier values. That last rule has a
valuable emergent property, verified directly in the end-to-end test:
a genuinely **shared** resource discovered identically by both
identities (same URL, same identifier value, because it is literally
the same object) is automatically excluded by the identical-value
check alone -- no separate "is this shared" classification signal was
needed for discovered resources to get this right.

`build_comparison_pairs(graph, primary_identity, secondary_identity,
maximum_pairs=20)`: pairs up eligible resources one-to-one (each
resource used in at most one pair), bounded, in discovery order.

**Integration with the existing detector (requirement 14): the Slice 8
classification logic was not touched.** `build_comparison_pairs`
produces `AuthorizationResourcePair` tuples -- the exact type
`run_idor_authorization_detector` already consumed -- and
`_apply_authorization_comparison` in `executor.py` simply extends its
existing `resource_pairs` list (built from the plan's explicit
`resource_scope`, unchanged) with any additional discovery-derived
pairs before making the same, single, unmodified detector call. CONFIRMED
rules, PROBABLE marker rules, shared/public exclusions, structural
fingerprinting, and request bounds are all Slice 8 code, byte-for-byte
unchanged.

### Comparison-plan extension (`authorization_comparison.py`, `service.py`)

`AuthorizationComparisonPlanRecord` gained two new fields:
`enable_discovery: bool = False` and `discovery_login_page_marker: str
= ""`. This is an **API-layer** repository field, not a TrustScan
permit claim -- it required no permit schema bump (still 1.3). The
existing "empty resource_scope is rejected" rule
(`authorization_comparison_resource_scope_empty`) is relaxed to allow
an empty scope **only** when `enable_discovery=True` -- a plan must
still specify at least one resource pair or explicitly opt into
discovery; it can never specify neither. `register_authorization_comparison_plan`
accepts both fields from the request body (defaulting to `False`/`""`,
so every Slice 8 registration call is unaffected).

### Executor wiring (`executor.py`)

`_apply_authorization_comparison` gained one additive block, gated on
`plan.enable_discovery`: for each identity, it calls the new
`run_authenticated_resource_discovery_crawl` with a fixed, conservative
sub-budget (`_DISCOVERY_CRAWL_POLICY`: `maximum_pages=5,
maximum_depth=1, maximum_request_attempts=20` -- deliberately not
operator-configurable this slice, see "Known limitations"), the
already-resolved `AuthenticationMaterial` for that identity (the same
material Slice 8 resolves via `authentication_contexts.get_secret`
after `require_bound` succeeds -- no new secret-resolution path was
added), and the executor's own `safety.before_request`/
`safety.after_request` runtime-safety hooks -- meaning **every
discovery request still counts toward the overall TrustScan runtime
safety engine's budget and rate limits** (requirement 17). Discovered
resources are added to a fresh `AuthorizationResourceGraph`, paired via
`build_comparison_pairs`, and merged (deduplicated by resource-ID pair)
into the same `resource_pairs` list Slice 8's explicit `resource_scope`
already populates, before the single, unchanged
`run_idor_authorization_detector` call.

A discovery-phase authentication failure for one identity does not
raise -- it simply means that identity contributes no discovered
resources this run (fail closed on *data*, an expired session is never
silently treated as "this identity legitimately has no resources", but
also never aborts the whole scan merely because discovery for one
identity was unhealthy).

### Checkpoint/resume with re-validated binding (requirement 10)

**Proven at the crawl-engine level, not yet wired into persisted,
cross-process job checkpointing** -- stated plainly rather than
overclaimed. `crawl_same_origin`'s existing `CrawlResumeState`/
`on_checkpoint`/`resume_state` mechanism (built in Slice 5, unchanged)
already supports resuming a partial crawl; this slice proves directly
(`AuthenticatedCrawlCheckpointResumeTests`) that a resumed crawl still
correctly re-applies the supplied `AuthenticationMaterial` to every
subsequent request.

Separately, and more importantly for requirement 10's actual safety
concern ("if any binding changed: fail closed, do not silently resume
with another session"): **this is already structurally guaranteed by
the existing Slice 7/8 double-binding-validation pattern**, not a new
mechanism. Every single execution of `_apply_authorization_comparison`
-- whether it is a scan's first attempt or a retried/resumed one --
calls `authentication_contexts.require_bound(...)` fresh, for both
identities, before ever resolving secret material. There is no
persisted "old" material anywhere that a resumed execution could
accidentally reuse: if a context was revoked or expired between
attempts, `require_bound` raises immediately and the entire
authorization-comparison step (discovery included) fails closed via
`TrustScanRuntimeSafetyError`, exactly as Slice 8 already proved for
the explicit-resource-scope path.

**Known limitation, stated plainly:** the discovery sub-crawl itself
does not persist its own mid-flight checkpoint to survive a worker
process crash mid-discovery -- consistent with every other
active-detection phase in this executor (XSS, SQLi, and Slice 8's own
IDOR comparison), none of which checkpoint mid-phase either. Given the
discovery sub-crawl is deliberately small and bounded (5 pages, depth
1, 20 requests), a crash mid-discovery simply means the job's normal
retry/failure handling re-runs the whole (cheap) discovery pass from
scratch on the next attempt -- not a correctness or security gap, a
resource-efficiency one, and out of proportion to build out this slice
given how bounded the cost already is.

## Bugs found and fixed during this slice

1. **The discovery crawl's root target didn't match the fixture's
   authenticated content location.** The first version of the
   end-to-end lab fixture put per-identity dashboard content at
   `/account/A`/`/account/B` while the scan's own authorized target was
   the site root `/`, which had no route at all -- discovery correctly
   found nothing, an honest failure that was actually a fixture design
   mismatch, not a code bug. **Fixed** by having the fixture's root `/`
   serve the same per-identity dashboard content (matching how many
   real authenticated applications behave -- a logged-in dashboard at
   or redirecting to `/`), while keeping `/account/A`/`/account/B` as
   explicit routes for the dedicated login-page-detection test. This
   is recorded as a fixture bug, not a discovery-engine bug -- the
   engine behaved correctly (it discovered nothing because there was
   genuinely nothing to discover at the URL it was told to start from).
2. **Two `except Exception: continue` blocks** in
   `authorization_resource_discovery.py` (around `AuthorizationResource`
   construction in both the HTML-link and JSON-field discovery
   functions) were flagged by static analysis (`ruff` `S112`) as
   overly broad. **Fixed** by narrowing both to
   `except AuthorizationResourceError` -- the only exception type
   `AuthorizationResource.__post_init__` actually raises, and one that
   is already structurally unreachable given the checks performed
   immediately before construction; kept as explicit defense in depth
   rather than removed.

## False-positive controls (requirement 18)

Verified directly, `tests/unit/test_authorization_resource_discovery.py`
and the end-to-end lab test: a public object and a shared object
(identical value for both identities, per the eligibility rule above);
an oversized response (skipped by budget, never partially parsed); a
redirect response (no HTML/JSON body to extract from); an inaccessible
(404) object; malformed JSON (caught, zero resources, no crash); an
unrelated ID field not matching configured patterns; a duplicate
resource reference on the same page (deduplicated by the sink); an
"API returning another user's ID only as non-sensitive metadata"
(`UserId` alongside `id` -- recorded but never PATH-addressable,
therefore never comparison-eligible); a resource with an unknown access
policy (excluded by the same `PRIVATE_TO_OWNER`-on-both-sides rule as
`SHARED`/`PUBLIC`). A login page returned as HTTP 200 is verified
separately (see "Login-page/expired-session detection" above) to
contribute zero resources and to be classified `AUTHENTICATION_EXPIRED`,
never mistaken for ordinary content.

## Scope controls (requirement 19)

Authenticated discovery never expands scope. Two independent layers:
(1) `crawl_same_origin` itself never follows an off-origin link to
begin with -- discovery only ever runs against pages the crawler's own,
unchanged scope enforcement already agreed to fetch; (2)
`_discover_html_link_resources` independently re-checks same-origin on
every extracted `<a href>` value before it can become a resource, so
even an off-origin URL appearing as literal text/markup within an
already-fetched, in-scope page's HTML is rejected a second time. Proven
directly: the end-to-end lab fixture's account page includes a literal
`<a href="https://evil-external.test/orders/999">` link, and the graph
never contains a resource pointing at that host.

## Operator-facing CLI (requirement 20)

`webguard-api authorization-comparison register|revoke` closes the gap
the phase 8 audit doc flagged explicitly. Both subcommands call the
exact same `WebGuardJobService` methods
(`register_authorization_comparison_plan`/
`revoke_authorization_comparison_plan`) the HTTP route already uses --
CLI and API share identical validation/service logic by construction,
not by keeping two implementations manually in sync. `register`
accepts `--resource-scope-json` (a JSON array, may be `"[]"`),
`--enable-discovery`, and `--discovery-login-page-marker`.

**Scope note, consistent with Slice 7's own precedent:** like
`authentication-context register`, this CLI command operates on an
in-memory repository freshly constructed and discarded within one
process invocation -- it cannot be round-tripped across two separate
CLI invocations the way SQLite-backed state can (see "Persistence
boundary" below). `tests/unit/test_authorization_comparison_cli.py`
therefore proves argument parsing, RBAC enforcement, and fail-closed
error propagation within one process boundary; the true multi-identity
happy path is proven over real HTTP in the end-to-end lab test instead.

## Persistence boundary (requirement 21)

Both `AuthenticationContextRepository` and
`AuthorizationComparisonPlanRepository` remain in-memory only, for the
same reasons Slice 7/8 gave: neither is safe to persist to SQLite as a
stand-in for real KMS-backed secret storage, and a throwaway schema now
would be rework once the project's planned PostgreSQL migration
happens. **No raw authentication secret was written to SQLite to make
cross-process testing convenient this slice, or any prior one.**
Cross-process persistence remains a documented production-
infrastructure gap, unresolved by design, exactly as Slice 7 and 8
already recorded it.

## Controlled fixture (requirement 13)

`tests/integration/test_authenticated_resource_discovery_e2e_lab.py`'s
`_DiscoveryFixtureHandler` expands the Slice 7/8 lab pattern with two
identities and, per identity: an authenticated dashboard (HTML links,
including a **duplicate** reference to the same order and one
deliberately **out-of-scope external link**), a **vulnerable**
`/orders/{id}` (JSON, no ownership check), a **secure**
`/documents/{id}` (JSON, ownership-checked, with a **nested,
unrelated** `metadata.tracking_ref` field that must never surface as a
resource identifier), a **shared** `/shared/team-doc` (identical for
both identities), a **public** `/public/info` (unauthenticated,
identical for everyone), and a dedicated `/account/expired` route that
always returns a login-page marker regardless of credentials.

## True end-to-end test (requirement 15)

`tests/integration/test_authenticated_resource_discovery_e2e_lab.py`,
`test_full_discovery_and_comparison_pipeline`:

```
register authentication-context A [real HTTP]
register authentication-context B [real HTTP]
  -> register authorization-comparison plan (resource_scope=[],
     enable_discovery=true) [real HTTP]
  -> POST /v1/permits (active_checks=[active.authorization.idor],
     authorization_comparison_plan_id set) [real HTTP]
  -> POST /v1/jobs [real HTTP]
  -> real ScanJobWorker -> real ScanJobExecutor
  -> authenticated crawl A -> resource discovery A
  -> authenticated crawl B -> resource discovery B
  -> resource graph construction -> comparison eligibility
  -> run_idor_authorization_detector (unmodified Slice 8 code)
  -> CONFIRMED CWE-639 finding on the vulnerable /orders/ endpoint
  -> persisted WebGuardReport
  -> GET /v1/jobs/{id}/result, report file read [real HTTP + real file]
```

**The test never supplies a resource identifier to the comparison plan
or the detector directly** -- `resource_scope` is an empty list; every
compared identifier is discovered only from a page fetched while
legitimately authenticated as that identity. Result: a CONFIRMED
CWE-639/OWASP-API finding on the vulnerable orders endpoint; **zero**
findings for the secure documents endpoint, the shared document, or
the public endpoint; both accounts' bearer tokens and the unrelated
`XJ99912` tracking reference verified absent from the entire persisted
report text.

The dedicated `test_expired_session_page_is_never_treated_as_ordinary_content`
test proves the fixture's `/account/expired` route, fetched directly
with a real `AuthenticationHealthCriterion`, is correctly classified
`AUTHENTICATION_EXPIRED` with zero resources -- the requirement-13
fixture checklist item exercised at the engine level, independent of
the full job pipeline.

## Juice Shop investigation (requirement 16)

Two fresh lab accounts were created for this run (the container is
ephemeral; no hardcoded historical account state was relied upon),
using only Juice Shop's own documented `POST /api/Users` and
`POST /rest/user/login` endpoints.

**Path one -- a genuine, unmodified authenticated crawl of Juice
Shop's own root page: finds nothing, honestly reported.** Juice Shop
v20.1.1 is an Angular single-page application with no server-rendered
HTML links and no JSON API surface reachable from the root URL itself
-- the identical structural limitation already documented for the
reflected-XSS and SQL-injection detectors across Slices 1, 4, and 6.
This is not a discovery-engine bug; `run_authenticated_resource_discovery_crawl`
was not modified or weakened to force a result here.

**Path two -- targeted discovery against a legitimately-received JSON
response: succeeds, and confirms the real vulnerability.** Direct
inspection of Juice Shop's real `POST /rest/user/login` response body
confirmed it contains a plaintext `bid` (basket ID) field alongside the
JWT (`{"authentication": {"token": "...", "bid": 6, "umail": "..."}}`)
-- a JSON field an authenticated identity legitimately receives while
logging in. Running `ResourceDiscoverySink` directly against this
response body, with `field_patterns={"bid"}` and the requirement-7
"explicit configuration" mechanism
(`endpoint_templates={"bid": "rest/basket/{value}"}`), correctly
discovers each account's own basket resource -- the *value* still
comes only from a field WebGuard actually observed, never guessed; only
the endpoint template was operator-configured. Feeding the two
discovered resources into the **unmodified** `run_idor_authorization_detector`
correctly reproduces Juice Shop's real, publicly documented "view
another user's basket" broken access control weakness: **CONFIRMED,
CWE-639** -- the same conclusion Slice 8's direct-JWT-decode
investigation reached, now reached via legitimate discovery instead.

This slice does not overclaim from one result: a single confirmed true
positive against one known vulnerability, using one explicitly
configured field/endpoint mapping, demonstrates the *mechanism* works
against a real application -- it is not evidence that discovery would
automatically find an arbitrary, unconfigured vulnerability on an
arbitrary target.

## Regression (requirement 22)

- Full unit suite: **1368/1368 passing** (1318 at the end of Slice 8,
  +50 new: `test_authenticated_crawl.py` [8], `test_resource_graph.py`
  [16], `test_authorization_resource_discovery.py` [19],
  `test_authorization_comparison_cli.py` [5], plus 2 new tests added to
  `test_authorization_comparison.py` for the `enable_discovery` field).
- Full integration suite (`WEBGUARD_RUN_INTEGRATION=1`, Juice Shop
  container recreated fresh for this run): **37/37 passing** (33 from
  Slice 8, +4 new: the discovery end-to-end lab's two tests and the
  Juice Shop discovery-investigation file's two tests). One transient
  failure was observed during a full-suite run under heavy concurrent
  load (a pre-existing Slice 3 test, unrelated to this slice's code)
  and confirmed non-reproducible in isolation and on a clean re-run of
  the full suite -- recorded here rather than silently ignored.
- Every pre-existing authentication, attack-surface, request-template,
  XSS, SQLi, IDOR (Slice 8), permit, RBAC, executor, `safe_http`,
  crawler, checkpoint, and scope/SSRF test file was re-run and passes
  **unmodified** -- no Slice 8 test file needed any change for this
  slice's additions.
- Security gates: secret scan (288 repository files / 6 generated
  artifacts / 632 reachable Git blobs), static analysis (two `S112`
  findings caught and fixed -- see "Bugs found and fixed" -- then
  zero), dependency audit (6 locked packages, no advisories) -- all
  passing.
- `git diff --check`: clean.

## Implemented / Tested / Proven / Not Proven / Authenticated Crawl / Resource Discovery / Resource Provenance / Resource Graph / IDOR Integration / Juice Shop Result / Safety Boundaries / Known Limitations / Test Counts / Security Gates / GitHub Commit / Remote Sync / Next Slice

**Implemented:** authentication threaded through `crawl_same_origin`/
`run_passive_crawl_scan`; `ResourceDiscoverySink`/
`AuthenticationHealthCriterion` (HTML-link and JSON-field discovery,
bounded, provenance-tagged, endpoint-template configuration);
`AuthorizationResourceGraph`/`is_eligible_for_comparison`/
`build_comparison_pairs` (deterministic cross-identity eligibility);
`run_authenticated_resource_discovery_crawl` (the dedicated,
checkpoint/cancellation-capable orchestration function); two new
`AuthorizationComparisonPlanRecord` fields (`enable_discovery`,
`discovery_login_page_marker`, API-layer only, no permit schema
change); executor wiring merging discovery-derived pairs into the
existing, unmodified `run_idor_authorization_detector` call; CLI
`authorization-comparison register|revoke`.

**Tested:** credential isolation across two identities and across a
checkpoint resume; HTML-link and JSON-field discovery including
provenance tagging, self-referential vs. non-self-referential PATH
addressing, and the `endpoint_templates` mechanism; every eligibility
rule in requirement 9 individually; the full false-positive checklist
in requirement 18; scope enforcement against an off-origin link
embedded in in-scope HTML; login-page/expired-session detection
distinguishing explicit denial from a 200-status login page; CLI
argument parsing, RBAC, and fail-closed error propagation.

**Proven:** a real permit -> job -> worker -> executor pipeline
performs two independent authenticated crawls, discovers each
identity's own resources with no identifier ever injected directly by
the test, builds a correct two-identity resource graph, correctly
excludes a shared and a public resource via the identical-value rule
alone, and produces a genuine CONFIRMED CWE-639 finding on the
vulnerable endpoint using the unmodified Slice 8 detector; the same
discovery mechanism (not the detector) is what changed, and it works
against a live application (Juice Shop) as well as the synthetic
fixture.

**Not Proven:** persisted, cross-process checkpointing of a mid-flight
discovery sub-crawl (the crawl-engine-level resume/re-authentication
mechanism is proven; wiring it into the job store's own checkpoint
persistence is deferred, matching every other active-detection phase's
identical non-checkpointed status); operator-configurable discovery
crawl budgets (currently fixed and conservative); automatic
expected-access classification for discovered resources beyond the
identical-value emergent property (there is no explicit
`SHARED`/`PUBLIC` inference for discovered resources -- it is not
needed for the cases this slice tested, but a shared resource with a
*different* identifier value per identity, if one existed, would not
yet be automatically recognized as shared); JSON discovery from deeply
nested list items beyond the bounded scan limits.

**Authenticated crawl:** Slice 7's shared authentication-application
mechanism, unchanged, now reachable from the crawler; all pre-existing
crawl safety controls preserved unchanged; credential isolation
structural and directly tested; checkpoint/resume proven with
authentication re-applied.

**Resource discovery:** HTML-link and JSON-field extraction, bounded,
provenance-tagged, never enumerating or guessing an identifier;
`endpoint_templates` as an explicit, bounded escape hatch for
identifiers observed on one endpoint but addressing another.

**Resource provenance:** `IdentifierProvenance` (7 closed members, no
generative member, ever) recorded on every `AuthorizationResource`;
`APPROVED_COMPARISON_PROVENANCE` checked explicitly at the eligibility
gate rather than assumed.

**Resource graph:** identity-keyed, deduplicated by structural
resource ID, references only, no credentials.

**IDOR integration:** discovery-derived pairs merge into, and are
processed by, the exact same, unmodified `run_idor_authorization_detector`
call Slice 8 built -- zero changes to CONFIRMED/PROBABLE/shared-
exclusion/fingerprinting/budget logic.

**Juice Shop result:** generic authenticated-crawl discovery finds
nothing (Angular SPA, honestly reported, consistent with prior
slices); targeted, explicitly-configured discovery against a
legitimately-received login response succeeds and reproduces the real
basket-access vulnerability, CONFIRMED/CWE-639.

**Safety boundaries:** credential isolation; discovery-phase
authentication failure fails closed on data without aborting the whole
scan; scope never expands (off-origin links rejected twice,
independently); discovery requests count toward the same runtime
safety budget as every other request; existing double-binding
(context + plan) re-validation, unchanged from Slice 8, already
satisfies the "fail closed on stale binding" half of requirement 10.

**Known limitations:** see "Not Proven" above.

**Test counts:** 1368 unit, 37 integration -- all passing.

**Security gates:** secret scan, static analysis (after two fixes),
dependency audit, and `git diff --check` all clean.

**GitHub commit:** recorded below after push and `HEAD == origin/main`
verification.

**Remote sync:** recorded below.

**Next slice:** write-level (state-changing) authorization testing
remains explicitly deferred, per this slice's own brief, to a
dedicated future slice. Automatic expected-access inference for
discovered resources (recognizing a resource as `SHARED` even when its
identifier value legitimately differs per identity) is the most direct
extension of this slice's own resource graph if broader real-world
coverage is needed later.
