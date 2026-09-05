# Active Detection, Slice 6: Request Template & Safe Mutation Engine

## Status

This slice adds **no new detector**. It builds a common request-template
and parameter-mutation layer between attack-surface discovery and the two
existing detectors (reflected-XSS, error-based SQLi), then extends both
detectors to consume it: SQLi across all three supported transports
(GET query, POST form, JSON body), XSS across two (GET query/form, POST
form; JSON deliberately excluded, see below).

## What was built

### The request-template contract (`workers/scanner/src/webguard_scanner/request_template.py`)

- `RequestTemplate`: a plain, serializable description of one request
  shape: endpoint, method, content type, the one parameter this
  template exists to test, and its baseline query/form/JSON values.
  Carries no secrets: `authentication_context_ref` is an opaque
  reference for a future protected runtime context to resolve, never a
  credential value, so this model is safe to log or persist as-is.
- `build_request_template(candidate: AttackSurfaceCandidate) ->
  RequestTemplate`: the one-to-one projection from a Slice-5 discovery
  candidate. Safety classification is carried through unchanged, never
  re-decided here.
- `request_template_from_detection_candidate`: a bridge from the
  pre-Slice-6 GET-only `DetectionCandidate` contract, used internally by
  both detectors' legacy code path.
- `to_request_templates(result, *, allow_post=False, allow_json=False)`:
  the authorization-aware projection used by the executor. Always
  projects `SAFE_TO_PROBE` GET candidates; projects
  `REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION` POST-form/JSON candidates only
  when the caller's own already-established authorization says so.
  `POTENTIALLY_STATE_CHANGING` and `UNSUPPORTED` candidates are **never**
  projected here, regardless of the flags (see "Safety boundaries"
  below).

### Supported request types

| Location | Slice 5 (discovery) | Slice 6 (representable) | Slice 6 (probeable by a detector) |
|---|---|---|---|
| GET query parameter | yes | yes | yes (XSS, SQLi) |
| GET form field | yes | yes | yes (XSS, SQLi) |
| POST form field | yes (classified, not probed) | yes | yes (XSS, SQLi) |
| JSON body field (dotted/indexed path) | new this slice | yes | yes (SQLi only) |
| Path parameter | no | field exists, unpopulated | no |
| Multipart form | no | no | no |
| GraphQL variables | indicator only | no | no |
| XML body | no | no | no |

Path parameters, multipart forms, GraphQL variables, and XML bodies are
explicitly designed-for (the `RequestTemplate.path_parameters` field
exists) but not implemented, consistent with the brief's "design for,
do not necessarily implement yet."

### Parameter mutation (`mutate(template, parameter, replacement)`)

One shared mechanism for all three transports:

- **GET query**: `dict(template.query_parameters)`, overwrite one key,
  re-encode. Every other query parameter is preserved unchanged.
- **POST form**: `dict(template.form_parameters)`, overwrite one key,
  re-urlencode. Every other field is preserved unchanged.
- **JSON body**: parse the baseline document (bounded, see below), deep
  copy it, replace the value at exactly one dotted/indexed path (e.g.
  `email`, `user.email`, `items[0].name`), preserving every sibling field
  untouched (verified directly: mutating `email` in `{"email": ...,
  "password": "baseline"}` never alters `password`, per
  `test_json_mutation_preserves_unrelated_fields` and
  `test_nested_json_mutation_preserves_siblings`).

Mutating a parameter that doesn't exist on the template fails closed
(`RequestTemplateError`) rather than silently creating a new field or
no-oping.

### Deterministic candidate identity

`AttackSurfaceCandidate.candidate_id` (Slice 5) now also incorporates
`content_type`, per this slice's explicit identity fields (origin, path,
method, content type, parameter location, parameter name, never a
volatile probe value). This changes computed hash values but not
semantics: the two-part invariant (same identity for the same
endpoint+method+content-type+location+parameter regardless of discovery
order or incidental query/fragment noise; different identity for
anything else) is unchanged and re-verified
(`test_candidate_identity_is_deterministic_regardless_of_discovery_order`,
`test_candidate_identity_ignores_query_string_and_fragment_variation`,
both still passing).

### Bounded JSON handling

- `load_bounded_json_document`: rejects a document over
  `JsonMutationBudget.maximum_document_bytes` **before** calling
  `json.loads` (never parses an oversized document to find out it's too
  big), and rejects malformed JSON (catching `JSONDecodeError` and
  `RecursionError`, the latter guarding an extremely deeply nested but
  small document) as `RequestTemplateError`, never an uncaught exception.
- `_validate_json_depth`: rejects a document whose structural nesting
  exceeds `maximum_depth`, checked recursively but bounded by the same
  depth limit, so it cannot itself recurse unboundedly.
- `enumerate_json_parameter_paths`: deterministic, bounded leaf-path
  enumeration (`maximum_parameter_paths`, `maximum_array_index`,
  `maximum_depth`), verified to cap output on a document with 100 flat
  fields, a document with 50 array elements, and a wide-and-deep
  (50 groups × 20 fields) document that would otherwise enumerate 1,000
  candidates (`test_does_not_recursively_explode_on_a_large_document`).
  Only `str`/`int`/`float`/`bool` leaves are addressable; `null` and any
  other type are skipped, never guessed at.
- `parse_json_parameter_path`: a small explicit state machine (not a
  single regex) for `"email"`, `"user.email"`, `"items[0].name"`. A
  regex-based first attempt had a real bug where the `.` separator
  between segments wasn't itself consumed, silently producing a
  malformed-path false-negative; caught by
  `test_nested_json_mutation_preserves_siblings` before this reached any
  detector, fixed by rewriting as an explicit character-by-character
  parser (see "Bugs found and fixed" below).

### Baseline execution as a first-class primitive

`execute_baseline(base_target, template, *, policy, before_request,
after_request) -> BaselineObservation | None`: issues one request using a
template's own unmutated values and records `status`, `response_length`,
a small allowlisted header subset (`content-type`, `server`,
`cache-control`), a SHA-256 `content_fingerprint`, and
`elapsed_milliseconds`. Never stores a complete response body. Returns
`None` on any request failure: a missing baseline is recorded as "no
observation," never fabricated.

This is built, tested, and exported as reusable infrastructure per the
brief's explicit ask, but the SQLi detector's own baseline/diagnostic
comparison does **not** call it internally: that comparison needs the
full response text to search for a database-error signature, which a
fingerprint-based observation cannot provide. `execute_baseline` is
available for a future detector whose methodology only needs to know
"did the response change," not "what did it say." This is a deliberate
scoping decision, not an oversight, documented here rather than forcing
an awkward fit.

## Extending the existing detectors

### Design: additive dispatch, not a rewrite

Both detectors keep their entire pre-Slice-6 code path for
`DetectionCandidate` items **byte-for-byte unchanged**, in its own
function (`_issue_legacy_baseline_and_diagnostic` /
`_issue_legacy_probe`). A new, separate function
(`_issue_templated_baseline_and_diagnostic` / `_issue_templated_probe`)
handles `RequestTemplate` items via `mutate` +
`issue_templated_request`. The main loop dispatches on `isinstance`,
then shares the same classification, recording, and finding-construction
code for both: that code was already transport-agnostic (it only ever
looked at response text/status), so no duplication was needed there.

This design was chosen specifically so every one of the 16 pre-existing
SQLi unit tests and 14 pre-existing XSS unit tests could be re-run
**unmodified** as a regression guard, rather than needing to be
re-validated against a rewritten implementation. All 30 pass unchanged.

### SQLi (`sqli_error_detector.py`): one detector, three transports

Per the brief's explicit instruction, this is one detector consuming
three input transports, not three detectors
(`sqli_get_detector`/`sqli_post_detector`/`sqli_json_detector`). The
baseline-then-single-apostrophe-diagnostic methodology and the
database-error-signature classification (`_classify`, `_find_signature`)
are completely unchanged from Slice 4; only how the two requests are
constructed and sent differs by transport.

`_build_finding` and `SqliDetectorRunRecord` were changed to take an
explicit `parameter`/`method` pair instead of assuming
`candidate.parameter`/`"GET"`: a mechanical signature change with
identical output for the GET case, since the legacy path still passes
exactly `candidate.parameter` and `"GET"`.

### XSS (`xss_reflected_detector.py`): two transports, not three

POST-form candidates are supported identically to SQLi. JSON bodies are
explicitly **not** supported:
`_issue_templated_probe` raises `RequestTemplateError("xss_json_body_not_supported", ...)`
for any JSON-content-type template, recorded as a probe error, never
silently skipped or crashed on. Rationale, stated directly in code and
here: reflected-XSS's evidence (attacker-controlled markup echoed
unescaped into an HTML response) only means what it claims to mean when
a browser would render that HTML. A JSON API response containing
attacker input back is a different, unproven claim (it would require
showing that response is later rendered somewhere as HTML, a DOM-XSS-
adjacent question this detector's methodology does not investigate).
Feature parity with SQLi was explicitly not a goal by itself. This
slice's own brief says so, and this is the concrete instance of it.

## Safety boundaries

### Representable is not probeable (requirement 5)

`RequestTemplate`/`mutate` answer "can this request be built and
mutated", a pure, static question about shape. `to_request_templates`
is the only place that additionally asks "does the caller assert
authorization for this," and even there, `POTENTIALLY_STATE_CHANGING`
and `UNSUPPORTED` candidates are never projected regardless of any flag.
There is no code path in this slice that turns representability alone
into a probe.

### POST safety and the keyword classifier (requirement 6)

Reused and extended Slice 5's `_classify_safety`: added `transfer`,
`change-password`, `reset-password`, `register`, `create-user` to the
state-changing keyword list. One deliberate refinement made during this
slice: the bare keyword `"password"` (present since Slice 5) was
**removed**, keeping only the more specific `"change-password"` /
`"reset-password"`. Reason, found empirically while investigating a
synthetic OpenAPI login endpoint: a bare `"password"` keyword matched
every ordinary login form's password field, permanently classifying
login endpoints (a common and legitimate SQLi/XSS target) as
`POTENTIALLY_STATE_CHANGING`, which this slice's own design makes
un-unlockable by any permit. Login (authenticating with a password) and
password-change (mutating a password) are different actions; only the
latter is genuinely state-changing. This is documented here as a
deliberate correction, not silently changed.

Classification remains deterministic (same inputs always produce the
same classification) and conservative (a method other than GET defaults
to `REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION`, never `SAFE_TO_PROBE`,
regardless of keyword match).

### JSON safety (requirement 7)

Covered above under "Bounded JSON handling." Every one of excessive
nesting, huge arrays, oversized strings, malformed JSON, and unsupported
data types has an explicit test (see "Testing" below). Duplicate JSON
object keys are a `json.loads` standard-library behavior (last key wins)
and are not separately handled: no ambiguity exists at the parsed-object
level this module operates on.

### Authorization and HTTP methods (requirements 12, 13)

Being able to represent a POST/JSON request does not bypass any existing
control:

- **`active_checks`**: unchanged: the executor's detector-registry
  lookup (`ACTIVE_DETECTOR_REGISTRY[check_id]`) still only runs a
  detector the permit's `active_checks` claim names, regardless of
  transport. Proven directly:
  `test_post_candidate_not_probed_when_only_xss_authorized`.
- **HTTP method authorization**: `TRUSTSCAN_ALLOWED_HTTP_METHODS`
  (`packages/contracts/python/src/webguard_contracts/scan_permits.py`)
  was widened from `("GET", "HEAD")` to `("GET", "HEAD", "POST")`, an
  additive vocabulary extension to an existing field's accepted value
  set, not a schema-shape change (the wire field is still `tuple[str,
  ...]`); every existing GET/HEAD-only permit remains valid unchanged.
  This is the same class of change as `KNOWN_TRUSTSCAN_ACTIVE_CHECKS`
  growing in Slices 3–4, and does not require the version-aware-loader
  process `docs/audit/trustscan-permit-schema-policy.md` reserves for
  actual field additions/removals. This enables, but does not by itself
  grant, POST authorization: an operator must still explicitly request
  it via `--allowed-http-method POST` at permit-issuance time.
  Two enforcement layers already existed and needed no new code: `safe_http.fetch_once`
  rejects any method not in `policy.allowed_methods` (itself derived
  from the permit's `allowed_http_methods` claim in
  `ScanJobExecutor._policies`), and
  `TrustScanRuntimeSafetyEngine.before_request` independently re-checks
  the same claim before any request begins. Proven directly:
  `test_post_candidate_blocked_under_get_only_permit` (POST candidate
  discovered and representable, permit allows only GET/HEAD → zero POST
  requests ever attempted, zero findings) and
  `test_post_candidate_executes_when_permit_allows_post_and_sqli`
  (same candidate, permit allows POST and authorizes `active.sqli.error`
  → the vulnerable endpoint is confirmed).
- **Request budget, rate limits, concurrency, cancellation**: unchanged.
  `ActiveDetectionPolicy.maximum_probe_requests`,
  `TrustScanRuntimeSafetyEngine`'s in-flight/rate accounting, and
  `cancellation_check` all apply identically to a `RequestTemplate`
  probe as to a `DetectionCandidate` one: they operate on the same
  `before_request`/`after_request` hooks and the same policy object,
  which `issue_templated_request` calls exactly like `issue_probe` does.
- **Target scope**: `issue_templated_request` calls the same
  `_require_same_origin`/`_build_probe_target` as `issue_probe`: an
  off-origin mutated request is rejected before any connection is
  attempted (`test_off_origin_mutated_request_is_rejected_fail_closed`).

### Evidence sanitization (requirement 14)

Neither detector's `_build_finding` was changed in what it puts into
`Evidence.summary`: still scan/authorization/permit IDs, a matched-
signature *category* (never the signature text) or a marker, and the
outcome. `FindingIdentity.parameter` legitimately carries a parameter
*name or path* (e.g. `"user.email"`), which is allowed evidence per the
brief; the JSON *value* of that path, the full request body, and any
other field on the document are never included. Verified directly:
`test_finding_evidence_never_contains_raw_json_body_or_payload` sends a
JSON body containing a password and a token value alongside the tested
`id` field and confirms neither value, nor the literal `{` character
(i.e. no serialized JSON at all), appears anywhere in the finding's
evidence.

## Bugs found and fixed during this slice

1. **JSON path parser dropped separators.** The first implementation of
   `parse_json_parameter_path` used a single regex with `finditer`,
   which silently skipped over the `.` characters between segments
   rather than treating them as syntax. `"user.email"` parsed to two
   matches at positions that didn't abut, which the position-tracking
   check correctly flagged as malformed, meaning every nested JSON path
   failed to parse at all. Caught immediately by
   `test_nested_json_mutation_preserves_siblings` before touching any
   detector. Fixed by rewriting as an explicit character-by-character
   state machine (see `parse_json_parameter_path`'s docstring).
2. **Site-level discovery dropped the target's port.** While wiring
   `discover_site_attack_surface` (Slice 5 code, exercised again by this
   slice's true-E2E tests) against a target on a non-default port (the
   normal shape for every TLS lab fixture in this repository), the
   auxiliary-resource URL builder used
   `f"{target.scheme}://{target.hostname}/"`, omitting the port. Against
   a same-host-different-port target this fails
   `_require_same_origin`'s port check and raises, uncaught, to the
   worker's generic exception handler as `worker_internal_error`. Caught
   by both true end-to-end tests
   (`test_active_checks_e2e_lab.py`, `test_sqli_checks_e2e_lab.py`)
   before merge. Fixed with an `_origin_base_url()` helper. (This bug and
   fix were already reported in the Slice 5 audit doc; repeated here only
   because this slice's SQLi/XSS extension work depends on the same
   function being correct.)
3. **A malformed `RequestTemplate` crashed the whole detector run, not
   just one candidate.** The first version of
   `_issue_templated_baseline_and_diagnostic` only caught
   `RequestTemplateError` around the narrow
   `get_template_parameter_value` lookup, not around `mutate()` itself.
   A template with unparseable JSON therefore raised out of
   `run_sqli_error_detector` entirely, discarding every other
   candidate's results in the same run: a real, if narrow, availability
   bug (one bad candidate should never take down the whole batch, the
   same principle `ActiveDetectionError` handling in the executor already
   establishes for detector-level failures). Caught by
   `test_malformed_json_template_is_recorded_as_probe_error_not_a_crash`.
   Fixed by wrapping the whole per-candidate dispatch call in the main
   loop with a `try/except RequestTemplateError`, recording it as a
   normal probe error and continuing.
4. **The bare `"password"` safety keyword over-classified login
   endpoints.** Covered above under "POST safety and the keyword
   classifier."

## Juice Shop investigation (requirement 15)

Re-investigated the pinned Juice Shop lab target (`bkimminich/juice-
shop:v20.1.1@sha256:cd58d79c…`, loopback-only) with this slice's
completed mutation engine and expanded discovery available, to determine
whether its real login endpoint is now representable and/or discoverable.

**Confirmed by direct inspection:** `POST /rest/user/login` with
`Content-Type: application/json` and a body like `{"email": ...,
"password": ...}` is Juice Shop's real login endpoint (`401 Invalid
email or password` for a wrong credential, confirming it is live and
JSON-based).

**Discovered? No.** Re-ran `discover_page_attack_surface` +
`discover_site_attack_surface` (unchanged Slice 5 logic, now also
carrying Slice 6's OpenAPI `requestBody`-example extraction) against the
live container:

- Page-level: 0 candidates (confirmed again: the root page is a pure
  Angular SPA shell: `polyfills.js`/`scripts.js`/`main.js` external
  bundles only, zero inline `<script>` content, zero server-rendered
  `<form>`/parameterised `<a href>`).
- Site-level: `robots.txt` yields one genuine, real (non-SPA-routed)
  entry (`Disallow: /ftp`, recorded `UNSUPPORTED`, never probed).
  `sitemap.xml`, `/openapi.json`, `/swagger.json`, `/v2/api-docs` all
  return HTTP 200 with the same Angular `index.html` (an SPA catch-all
  route), which contains no `<loc>` tags and fails JSON parsing,
  correctly recorded as `malformed_openapi_document`/no candidates, not
  fabricated into false data.
- Combined: `to_request_templates(..., allow_post=True,
  allow_json=True)` on the merged result yields **0 templates**. The
  login surface is not discoverable by this project's static/API-
  description-based discovery, full stop. This has not changed since
  Slice 5, and this slice's expanded discovery (POST forms, real JSON
  body extraction from OpenAPI) does not change the outcome, because
  Juice Shop simply never exposes it through anything this discovery
  reads.

**Representable? Yes, verified by direct construction.** A
`RequestTemplate` was manually constructed (not discovered) for `POST
/rest/user/login`, `application/json`, body `{"email": "a@b.com",
"password": "x"}`, `parameter="email"`. This is a legitimate exercise of
the representability question independent of discovery, per the brief's
own framing.

**Authorized? Mechanically available, not exercised as a full
CLI→API→worker E2E**, since discovery would never route this candidate
there anyway, running the full stack against it would only prove the
existing method/active_checks gates again (already proven against the
synthetic fixture), not anything new about Juice Shop.

**Detectable using the current, unmodified methodology? No, verified
empirically, without inventing or attempting any authentication-bypass
payload.** `run_sqli_error_detector` was run, completely unmodified,
against the manually-constructed template. It sent exactly the same two
requests it always sends: a baseline, then one single unescaped
apostrophe as the `email` field's value, nothing else. Result:
`SqliDetectionOutcome.INCONCLUSIVE`, zero findings, zero probe errors.
This is the expected, honest outcome: Juice Shop's actual login "SQL
injection" challenge is a boolean/logic bypass (a crafted value that
makes the query's `WHERE` clause always true), which produces a *valid,
different* successful response, not a database error, structurally
outside what an error-signature-based detector can see, by design of the
detector's own conservative methodology (Slice 4's explicit choice to
exclude boolean-differential and bypass techniques). No new or different
payload was attempted to try to make this turn green.

**Summary, exactly in the terms requirement 15 asks for:** discovered:
no. representable: yes. authorized: mechanically available via the
existing permit model, not separately re-proven end-to-end since
discovery never surfaces this candidate. detectable using current SQLi
methodology: no, confirmed empirically. This is recorded as a valid
result, not a gap to paper over.

## Testing

New test files/additions, each traced to a required item from the brief:

- `tests/unit/test_request_template.py` (29 tests): JSON path parsing
  (simple/nested/array/malformed), JSON parameter enumeration
  (nested paths, array indices, null-skipping, depth budget, parameter-
  count budget, array-index budget, large-document non-explosion),
  bounded JSON loading (malformed, oversized, excessive depth), mutation
  (GET query preserves other params, POST form preserves unrelated
  fields, JSON preserves unrelated fields, nested JSON preserves
  siblings, malformed-template failure, unknown-parameter failure ×3
  transports, maximum-depth enforcement during mutation), and issuance
  (POST JSON body/content-type correctness, POST form body correctness,
  off-origin rejection, baseline execution recording + preserving
  baseline values + returning None on failure).
- `tests/unit/test_sqli_error_detector.py` (+9 tests): genuine vulnerable
  POST form (confirmed) and its safe-parameterised control, POST form
  mutation preserving unrelated fields, genuine vulnerable JSON body
  (confirmed) and its safe control, JSON mutation preserving unrelated
  fields, malformed-JSON-template resilience (probe error, not a crash),
  a mixed legacy-GET + templated-JSON single run (cross-transport
  regression guard), and evidence sanitization (no password/token/raw
  JSON in evidence).
- `tests/unit/test_active_xss_reflected.py` (+4 tests): POST form
  confirmed/no-finding, JSON body candidate never probed (asserts the
  underlying connection is never even opened), mixed legacy-GET +
  templated-POST single run.
- `tests/unit/test_active_checks_http_method_authorization.py` (3 new
  tests, new file): GET-only permit blocks a discovered POST candidate
  entirely (zero POST requests attempted); a permit allowing POST and
  authorizing `active.sqli.error` executes and confirms the vulnerable
  POST-form endpoint; the same POST-permitted permit authorizing only
  `active.xss.reflected` never triggers SQLi against the same candidate.
- `tests/integration/test_sqli_error_detector_live.py` (+4 tests, real
  sockets, real SQLite): genuine vulnerable POST-form and JSON endpoints
  confirmed; their parameterised-safe counterparts produce no finding,
  extending the existing four-endpoint real-database fixture to all
  three transports.
- `tests/unit/test_trustscan_permit_contract.py`: the one existing test
  that encoded "POST is unsafe" (`test_submission_rejects_unsafe_http_method`)
  was updated to test `DELETE` instead: POST is now a legitimately
  issuable method, and the test's actual intent (unknown/unsafe methods
  are still rejected) is preserved with a still-genuinely-unsupported
  method. One new test added confirming POST is now accepted.

Every item from the brief's required-coverage list (GET mutation, POST
form mutation, JSON mutation, nested JSON, malformed JSON, maximum JSON
depth, parameter-count budget, state-changing classification, GET-only
permit blocking POST, POST method authorization, SQLi-only authorization,
XSS-only authorization, budget exhaustion, cancellation, off-origin
rejection, duplicate candidate normalization, evidence sanitization,
baseline preservation, genuine vulnerable POST-form SQLi, genuine
vulnerable JSON SQLi, safe controls) is covered above or was already
covered by Slice 5's `test_attack_surface_discovery.py` (budget
exhaustion, cancellation, duplicate candidate normalization, unchanged
by this slice and re-run as regression).

## Regression

- Full unit suite: **1214/1214 passing** (1147 at the end of Slice 5,
  +21 Slice-5 attack-surface tests already counted there, +29 new
  request-template tests, +9 new SQLi tests, +4 new XSS tests, +3 new
  HTTP-method-authorization tests, +1 permit-contract test net after the
  one rewritten test; see exact arithmetic in each test file above).
- Full integration suite (`WEBGUARD_RUN_INTEGRATION=1`, Juice Shop
  container live): **29/29 passing** (25 from Slice 5, +4 new real-socket
  POST-form/JSON SQLi tests), including both true end-to-end tests.
- All pre-existing detector/permit/executor/registry/cross-authorization
  test files re-run explicitly and pass unchanged: `test_active_xss_reflected.py`
  (18, 14 unchanged + 4 new), `test_sqli_error_detector.py` (25, 16
  unchanged + 9 new), `test_active_checks_permit_control.py`,
  `test_active_checks_cli.py`, `test_job_executor_active_detection.py`,
  `test_active_detector_registry.py`,
  `test_active_checks_cross_detector_authorization.py`,
  `test_active_checks_permit_lifecycle.py`, `test_attack_surface_discovery.py`
  (21, unchanged), `test_safe_http.py` (15, unchanged).
- Security gates: secret scan (261 files / 6 artifacts / 551 blobs),
  static analysis (`ruff --select S`, zero findings), dependency audit
  (6 locked packages, no advisories), all passing.
- `git diff --check`: clean.

## Implemented / Tested / Proven / Not Proven / Supported Request Types / Safety Boundaries / False-Positive Controls / Known Limitations / Test Counts / Security Gates / GitHub Commit / Remote Sync / Next Slice

**Implemented:** a `RequestTemplate`/mutation/issuance/baseline-observation
layer (`request_template.py`) sitting between attack-surface discovery
and active detectors; SQLi extended to GET query, POST form, and JSON
body transports through it (one detector, not three); XSS extended to
GET query/form and POST form (JSON deliberately excluded); the TrustScan
permit's `allowed_http_methods` vocabulary widened to include POST as an
issuable method; OpenAPI `requestBody` example/schema extraction
producing genuine JSON body candidates with real baseline documents.

**Tested:** every item on the brief's required-coverage list (see
"Testing" above); 3 real bugs found and fixed before merge (JSON path
parser, malformed-template crash propagation, over-broad state-changing
keyword), each with a regression test that would have caught it.

**Proven:** mutation never alters an unrelated field, across all three
transports; a discovered POST candidate is genuinely unexecutable under
a GET-only permit and genuinely executable once the permit explicitly
allows POST and authorizes the specific detector; SQLi and XSS
authorization remain provably independent under POST transport exactly
as they already were under GET; a real, purpose-built vulnerable fixture
is correctly confirmed and its safe/control counterparts correctly
produce no finding, across all three transports, over real sockets and a
real database engine; evidence never contains a raw JSON body, password,
or token value.

**Not Proven:** that any newly-representable request shape (POST form,
JSON body) has been exercised against a genuine, independently-discovered
real-world vulnerability: the only real-world lab target available
(Juice Shop) is empirically confirmed to expose its actual vulnerable
endpoint through neither this nor any prior slice's discovery, for a
documented, verified reason (SPA architecture, no static description of
its API).

**Supported request types:** see the table under "Supported request
types" above.

**Safety boundaries:** representability and probeability remain distinct
questions with no code path collapsing them; POST/JSON authorization
requires both the permit's `active_checks` claim (which detector) and
its `allowed_http_methods` claim (which methods), proven independently
gated; `POTENTIALLY_STATE_CHANGING`/`UNSUPPORTED` candidates are never
projected to a probeable template under any authorization; every
existing safety control (scope, budget, rate, concurrency, cancellation)
applies unchanged to the new transports because they share the same
hook-calling code path as the original GET-only one.

**False-positive controls:** unchanged detection methodology (same
signature list, same classification function) reused verbatim across all
three transports; three transports × vulnerable/safe pairs plus the two
Slice-4 generic-error/database-looking-text controls, none of which
produced a false finding.

**Known limitations:** path parameters, multipart forms, GraphQL
variables, and XML bodies remain unimplemented (designed for, not built);
JSON support for reflected-XSS is intentionally absent; JSON body
candidate discovery depends entirely on an OpenAPI document providing a
concrete example or schema: an endpoint with neither is discovered at
the endpoint/method level only, never at the field level; site-level
discovery (where the OpenAPI/JSON-body extraction lives) still does not
run in crawl mode, a Slice-5 limitation unchanged by this slice.

**Test counts:** 1214 unit, 29 integration (all passing).

**Security gates:** secret scan, static analysis, and dependency audit
all passing; `git diff --check` clean.

**GitHub commit:** recorded below after push and `HEAD == origin/main`
verification.

**Remote sync:** recorded below.

**Next slice:** per the operator's own stated priority (master scope
document, section 46, item 5, "add next high-value detector classes"),
a new detector class can now be built directly on top of this transport-
agnostic candidate/template/mutation model from the start, rather than
needing its own GET-only special case first. Alternatively, per that same
section's explicit caveat, any security blocker found in the meantime
takes priority over this ordering.
