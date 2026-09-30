# Active Detection, Slice 1: Reflected XSS

## Status

Detector implemented and tested. **Not yet integrated** into scan job orchestration, the API, or TrustScan permits: this slice is the detector and its safety plumbing only, standalone-invokable, not reachable through `webguard scan` or the job/permit pipeline yet. That integration is explicitly out of scope for this slice and is listed under Remaining Risks below.

This is the first of the active-detection classes prioritized in the brief (SQL injection, reflected XSS, auth/authz, IDOR, SSRF). Per the brief's own instruction to "implement only detectors for which the project can establish a reliable and safe testing methodology," this slice implements **one** class only, reflected XSS, chosen because it has the cleanest, lowest-risk confirmation signal (string-match on a response already fetched; no code execution, no data modification) of the five candidates.

## Phase A: Architecture

Two new modules in `workers/scanner/src/webguard_scanner/`:

- `active_detection.py`: shared contract and safety plumbing for all future active detectors: `DetectionCandidate`, `ActiveDetectionPolicy`, `ActiveDetectionContext`, `issue_probe`.
- `xss_reflected_detector.py`: the reflected-XSS detector itself.

Design decisions and why:

- **Every probe request goes through the existing `safe_http.fetch_once`.** A probe is built as a `ValidatedTarget` that reuses the caller's already-validated `hostname`/`port`/`scheme`/`resolved_addresses` unchanged: no new DNS resolution, no new address, so no new SSRF surface. It inherits SSRF-validated addresses, TLS enforcement, redirect blocking (confirmed by test: a redirect response during a probe is recorded as a `redirect_blocked` probe error, never misread as a finding), and response-size limits without any changes to `safe_http.py`.
- **Same-origin enforcement is fail-closed and checked before any request is built.** `issue_probe` rejects a candidate whose URL scheme, hostname, or port differs from the authorized target's origin (`candidate_origin_mismatch`), tested explicitly (`test_off_origin_candidate_is_rejected_fail_closed`, and again over a real socket in the live-fixture suite).
- **Candidates are never auto-discovered.** `DetectionCandidate` is an explicit, caller-supplied `(url, parameter, method)` triple. Automatic discovery of candidate parameters from crawled forms/links is not implemented in this slice (see Remaining Risks): this keeps the blast radius of the first slice small and avoids conflating "what could be tested" with "what was tested."
- **Only GET is supported.** `DetectionCandidate.__post_init__` rejects any other method outright rather than silently coercing it.
- **Rate limiting and permit revalidation are inherited via hooks, not reimplemented.** `issue_probe` accepts the same `BeforeRequestHook`/`AfterRequestHook` types already used by `passive_scan.run_passive_header_scan`. When wired into the real executor, whatever rate-limiting/circuit-breaking/permit-revalidation logic the executor already applies to passive requests applies identically to active probes: this slice does not duplicate or approximate that logic.
- **`ActiveDetectionPolicy` bounds every run**: `maximum_probe_requests` (1–25, fail-closed via `enforce_probe_budget` before any request is sent, verified with a 3-candidate list against a policy of 2, confirming zero requests were made) and `minimum_delay_seconds` (0–30, enforced between probes).
- **`ActiveDetectionContext` records authorization/permit provenance** (`scan_id`, `authorization_id`, `permit_id`, `permit_fingerprint`) into every finding's evidence text. These fields are honest about what is not yet true: they are optional because no caller currently derives them from a real TrustScan permit (that wiring doesn't exist yet), and their absence is recorded as `"not recorded"` rather than silently omitted.

## Phase B: Detection contract

Findings use the **existing** `webguard_contracts.NormalizedFinding` contract unchanged: no new finding schema was introduced. `source="webguard-active"` distinguishes these from `source="webguard-passive"` findings.

The brief asked for five confirmation levels (confirmed / probable / suspected / informational / inconclusive); the existing shared `Confidence` enum only has four values (low/medium/high/confirmed) and is used across every other analyzer, persistence path, and report renderer in the codebase. Rather than widen a shared, heavily-depended-on enum for one detector, this slice defines its own richer `DetectionOutcome` enum (`active_xss_reflected_detector.DetectionOutcome`) for the detector's internal confirmation logic, and maps it onto the existing `Confidence`/`Severity` values when constructing the `NormalizedFinding`:

| DetectionOutcome | Finding produced? | Severity | Confidence | CWE-79 attached? |
|---|---|---|---|---|
| CONFIRMED | yes | High | Confirmed | yes |
| PROBABLE | yes | High | High | yes |
| SUSPECTED | yes | Medium | Medium | yes |
| INFORMATIONAL | yes | Informational | Confirmed | **no**: this is evidence of correct encoding, not a weakness |
| INCONCLUSIVE | **no** | N/A | N/A | N/A |

The exact `DetectionOutcome` value is preserved verbatim as a finding tag (`outcome-<value>`) and in the evidence text, so the distinction is never lost even though it collapses onto four `Confidence` values downstream.

"Do not claim a vulnerability merely because a payload produced an unusual response" is enforced structurally: `_classify_reflection` only produces CONFIRMED/PROBABLE/SUSPECTED from an exact substring match of a unique, randomly generated 21-character marker (`wgxss<16 hex chars>`): never from response-length deltas, timing, or status-code changes, none of which this detector uses at all.

## Phase C: Lab validation

### What was checked against Juice Shop, and what was found

The pinned lab target (`bkimminich/juice-shop:v20.1.1`) was investigated for a genuine server-side-reflected injection point:

| Endpoint | Result |
|---|---|
| `GET /rest/products/search?q=<marker>` | Marker not reflected in the JSON response body |
| `GET /<nonexistent-path>` (404 fallback) | Falls back to the Angular SPA's `index.html`, no reflection |
| `GET /api/Feedbacks?comment=<marker>` | Unrecognized query parameter, ignored, no reflection |
| `GET /rest/user/change-password?...new=<marker>...` | `401` (requires auth), no reflection |
| `GET /rest/captcha?<marker>` | Unrelated JSON captcha response, no reflection |
| `GET /redirect?to=<marker>` | `406 Not Acceptable` (the redirect challenge requires an allowlisted URL) |

**No genuine server-side raw-HTML reflection point was found in this Juice Shop version.** This is not a gap in the investigation: Juice Shop v20.1.1 is an Angular single-page application. Its documented reflected/DOM XSS challenge (the search bar) is rendered **client-side** by Angular after the JSON API response is fetched: the vulnerable rendering happens in the browser, not in the server's raw HTTP response. WebGuard does not execute JavaScript (a deliberate, previously documented safety and scope decision), so this class of finding is structurally out of reach for a raw-response detector, regardless of how well the detector's string-matching logic works.

**This is the honestly-reported Phase C result for Juice Shop: absence of a reachable vulnerability, not detector failure, and not a Juice Shop finding of any kind.** Per the brief's explicit instruction, this is documented rather than worked around, substituted with a weaker test, or silently dropped from the report.

### What was validated instead: real-socket fixture

`tests/integration/test_active_xss_reflected_live.py` stands up a minimal, purpose-built HTTP server bound to `127.0.0.1` only (never Juice Shop, never any real site) with three routes: `/reflect` (echoes `?q=` unescaped), `/safe` (HTML-escapes it), `/noecho` (ignores it). This exercises the detector over a **real TCP socket and real HTTP response parsing** (not a mocked connection) while keeping the "vulnerable" behavior fully understood and controlled, unlike relying on an unconfirmed third-party app.

Results, all passing:

- `/reflect` → `CONFIRMED`, CWE-79 attached, High/Confirmed.
- `/safe` → `INFORMATIONAL`, no CWE attached (correctly recognizes safe encoding as not a weakness).
- `/noecho` → `INCONCLUSIVE`, no finding, but recorded in the run's audit trail (not silently absent).
- Off-origin candidate → rejected before any request (`ActiveDetectionError: candidate_origin_mismatch`), confirmed over the real setup, not just the mocked unit test.

### What was validated with mocked connections (`tests/unit/test_active_xss_reflected.py`, 14 tests)

- All five `DetectionOutcome` classifications, including both "partial" cases (only the left or only the right angle bracket survives unescaped → PROBABLE) and the case where the marker text survives but both brackets are stripped entirely → SUSPECTED, distinct from full HTML-entity-encoding → INFORMATIONAL.
- False-positive resistance: `INFORMATIONAL` (safely encoded) never attaches CWE-79 or gets conflated with a real finding.
- Malformed/unexpected response handling: a probe that receives a redirect response is recorded as a `redirect_blocked` probe error, never misclassified as a finding (this reuses `safe_http`'s existing redirect-blocking, not new logic).
- Budget enforcement: an oversized candidate list is rejected before any network request is made (`connection.requested_paths == []`, i.e. zero requests actually sent).
- Rate/hook wiring: `before_request`/`after_request` are invoked exactly once per successful probe with the correct arguments.
- Distinct markers per candidate (no correlation/leakage between probes in a multi-candidate run).
- Policy bounds validation (probe count and delay both rejected outside their allowed ranges).
- Method restriction (`POST` candidate rejected at construction).

### What was explicitly NOT validated

- No genuine third-party vulnerable application's reflected-XSS was reproduced end-to-end (see above, none was found in the current lab target).
- POST-body or header-based injection points are out of scope (GET-query only, by design, this slice).
- Candidate discovery from crawled HTML forms is not implemented or tested (candidates are caller-supplied).
- DOM-based / client-rendered XSS is categorically out of reach (no JavaScript execution).
- Timeout behavior during a probe was not separately tested in this slice: it already reuses `safe_http`'s existing, separately-tested timeout handling (`connection_timeout`), but a dedicated slow-server fixture test was not added here.

## Phase D: Safety boundaries (verified)

| Requirement | How it's enforced | Verified by |
|---|---|---|
| Explicit target/origin binding | `issue_probe` rejects any candidate off the validated target's origin | Unit + live-fixture test |
| Bounded request count | `ActiveDetectionPolicy.maximum_probe_requests` (1–25), enforced before any request | Unit test (budget exceeded → zero requests sent) |
| Rate limiting | `minimum_delay_seconds` (0–30) enforced between probes; `before_request`/`after_request` hooks let the executor apply its own throttling identically to passive requests | Unit test (hook invocation) |
| SSRF-safe requests | Reuses `safe_http.fetch_once` unmodified; no new DNS resolution | Design (no new code path bypasses `scope_validator`) |
| No arbitrary file access / shell execution | Detector only constructs URLs and reads HTTP response bytes; no filesystem or subprocess calls anywhere in either new module | Code inspection (grep confirms no `os.system`/`subprocess`/`open()` calls) |
| Fail-closed on invalid policy | Out-of-range `maximum_probe_requests`/`minimum_delay_seconds` raise at construction | Unit test |
| Only GET is permitted | `DetectionCandidate.__post_init__` rejects non-GET | Unit test |

## Phase E: Regression suite

- `tests/unit/test_active_xss_reflected.py`: 14 tests (mocked connections, no network).
- `tests/integration/test_active_xss_reflected_live.py`: 4 tests (real loopback sockets, opt-in via `WEBGUARD_RUN_INTEGRATION=1`).
- Full repository regression: **1095/1095 unit tests, 18/18 integration tests** (14 pre-existing Juice Shop + 4 new live-fixture) passed after this slice.
- Security gates (secret scan, static analysis, dependency audit): passed.

## Phase F: CWE coverage impact

`docs/CWE_COVERAGE.md` updated: CWE-79 moves from **Planned** to a new **Implemented (active, standalone)** status, implemented and tested, explicitly distinguished from the 18 passive CWEs that already run automatically as part of every scan. CWE-79 does not run as part of `webguard scan` yet.

## Remaining risks / explicitly not done

- **Not integrated into the job/permit pipeline.** `run_reflected_xss_detector` cannot currently be invoked through the API, a scan job, a TrustScan permit, or the CLI. `ActiveDetectionContext`'s `authorization_id`/`permit_id`/`permit_fingerprint` fields exist but nothing populates them from a real permit yet. Wiring this in is a distinct, separate piece of work (touching the executor, `permitted_modes`, and likely the API contract) and was deliberately not attempted in this slice to keep it reviewable.
- **No candidate discovery.** Nothing today produces `DetectionCandidate` values automatically from a crawl. An operator (or future orchestration code) must supply them explicitly.
- **No genuine third-party reflected-XSS was reproduced.** The lab validation is real-network but synthetic; see Phase C.
- **SQL injection, auth/authz, IDOR, and SSRF detectors do not exist.** Only reflected XSS was built in this slice, per the brief's own instruction to start narrow.
- **DOM-based XSS is categorically undetectable** by this or any future raw-HTTP-response detector in this architecture, unless a future architectural decision adds JavaScript execution (with its own, much larger safety-review requirements).
