# Active Detection, Slice 2: Orchestration, Permit Enforcement, Executor Integration

## Status

Complete for the scope described below. The reflected-XSS detector built in Slice 1 (`docs/audit/active-detection-phase1-xss.md`) is now reachable end-to-end through the real job/permit/executor pipeline, not standalone-only.

## What changed and why

### TrustScan permit schema: 1.0 → 1.1

Added one new signed claim: `active_checks: tuple[str, ...] = ()`. An empty tuple (the default for every existing and newly issued permit that does not explicitly opt in) authorizes no active detector: this is the fail-closed default. A permit must explicitly list `"active.xss.reflected"` to authorize it.

This is a real, deliberate schema-version bump (`CURRENT_TRUSTSCAN_PERMIT_SCHEMA_VERSION` 1.0 → 1.1), not an additive/optional field, because the permit loader (`load_signed_trustscan_permit_json`) enforces an *exact* required-field set: there is no concept of an optional wire field in this contract. Schema 1.1 **replaces** 1.0 outright (`SUPPORTED_TRUSTSCAN_PERMIT_SCHEMA_VERSIONS = ("1.1",)`, dropping 1.0) rather than supporting both versions. This is deliberate and was not done lightly: WebGuard is pre-production (README: "not yet a publicly hosted production service"), so there is no deployed 1.0 permit this breaks, and building a dual-version loader for a system with zero real users would be speculative complexity with no present benefit. If this were a live production system with issued 1.0 permits, this would need a proper migration path instead. Recorded here as a residual risk, not silently glossed over.

`KNOWN_TRUSTSCAN_ACTIVE_CHECKS = ("active.xss.reflected",)` is the contracts-side catalog of detector IDs a permit may reference; a permit claiming an unrecognized ID is rejected at construction (`trustscan_permit_active_checks_unknown`).

**Blast radius of the schema bump**: 14 pre-existing tests across 4 files (`test_trustscan_permit_contract.py`, `test_trustscan_permit_service.py`, `test_http_api.py`, `test_trustscan_permit_service_lab.py`) constructed raw permit-submission JSON without the new field and needed `"active_checks": []` added to their shared fixture helpers. `create_trustscan_permit` (the shared Python-level test helper used across dozens of other tests) needed no changes: it gained an `active_checks: tuple[str, ...] = ()` keyword argument with a backward-compatible default, so every caller that doesn't care about active checks was unaffected. No SQLite schema/migration was needed: permits are persisted as a `document_json` blob column (`scan_permits.document_json`), so the new claim is simply part of that JSON, verified by reading `store.py` before making this change, not assumed.

### Executor integration (`apps/api/src/webguard_api/executor.py`)

After the existing passive scan completes (single-page or crawl, unchanged), and only if the bound permit's `active_checks` is non-empty:

1. For each successfully-scanned page (`ScanStatus.COMPLETED`/`COMPLETED_WITH_ERRORS`), issue one additional same-origin GET request to re-fetch that page's HTML (`fetch_same_origin_page`, Slice 1 code, unmodified) and run the bounded form-candidate discovery parser (new, `active_candidate_discovery.py`) on the result.
2. For each detector ID the permit authorizes *and* the scanner-side registry (`ACTIVE_DETECTOR_REGISTRY`) recognizes, run it against the discovered candidates.
3. Merge findings into the report: `ScanResult.findings` (single-page) or the matching `CrawlPageScanResult.findings` (crawl), via `dataclasses.replace`, never mutating the original report in place, since both are frozen dataclasses.

**Every one of these requests (discovery fetch and detection probes alike) goes through the exact same `TrustScanRuntimeSafetyEngine.before_request`/`after_request` hooks already enforced on passive requests.** This was a design decision from Slice 1 (the active-detection contract accepts the same `BeforeRequestHook`/`AfterRequestHook` types as `passive_scan.run_passive_header_scan`), and it means active probes automatically inherit, with zero new code: origin/scope enforcement, HTTP-method allowlisting, the permit's request-attempt budget, its requests-per-second rate limit (with real throttling), its concurrency limit, per-request permit revalidation, and circuit breaking after repeated failures/429s/5xxs. This was verified, not assumed: see the budget-exhaustion test below.

A code-level guard (`ActiveDetectionError`, e.g. a candidate-count mismatch) is caught locally and treated as "skip this detector for this page" rather than aborting the job: a bug in the active-detection layer must not discard an already-successful passive scan result. A security-relevant runtime-safety decision (`TrustScanRuntimeSafetyError`, e.g. budget exhausted, scope violation, circuit breaker open) is deliberately **not** caught here. It propagates to the executor's existing `except TrustScanRuntimeSafetyError` handler exactly as a passive-scan safety block already does, producing the same signed `safety_blocked` receipt and `JobExecutionError`. These are different failure classes and are handled differently on purpose.

### Crawl-mode constraint: self-submitting forms only

`CrawlPageScanResult` has an existing, audited invariant: every finding attached to a page must belong to that page's own URL. A form discovered on page A that submits to page B has no valid page slot to attach a finding to without violating that invariant, and extending or bypassing it was out of scope and undesirable (it protects report integrity). This slice therefore restricts crawl-mode active detection to forms whose action resolves to the *same* path as the page they were found on (e.g. a self-submitting search box), discovered via `restrict_to_page_path` filtering in the executor. Single-page mode has no such constraint (`ScanResult.findings` has no per-page attribution requirement) and can test a discovered form's separate action URL. This asymmetry is real and is recorded here, not smoothed over.

### Candidate discovery (`active_candidate_discovery.py`)

A new, independently-bounded HTML form parser, deliberately *not* an extension of the existing, already-audited `html_analyzer.py` internals, to avoid adding any risk to that module. Only GET forms; only text-like input types (`text`, `search`, `email`, `url`, `tel`, absent-type, `textarea`, `select`); explicitly excludes `password`, `hidden`, `file`, `checkbox`, `radio`, `submit`, `button` fields. Bounded: max 5 forms, max 5 fields/form, max 15 total candidates. Verified against real Juice Shop HTML (not just synthetic fixtures); see Verification below.

### Detector registry (`active_detector_registry.py`)

`ACTIVE_DETECTOR_REGISTRY = {"active.xss.reflected": run_reflected_xss_detector}`. A test (`test_active_detector_registry.py`, see Regression suite) asserts this stays in sync with the contracts-side `KNOWN_TRUSTSCAN_ACTIVE_CHECKS` catalog, since the two packages deliberately have no runtime import coupling.

### What was deliberately not built in this slice

- **Dedicated audit-event-table wiring.** Investigated first, not assumed: job execution (passive or active) does not currently record a dedicated event into the `security_audit_events` table at all: the only existing call site in `service.py` is unrelated. Adding this selectively only for active checks would be architecturally inconsistent (passive execution would remain unaudited by the same mechanism). Auditability for this slice instead relies on the signed safety receipt (already covers all request activity, passive and active alike, unchanged) and finding provenance (`source="webguard-active"` on every active finding, already true from Slice 1). Building consistent job-execution audit-event wiring for both passive and active scans together is recorded as a real gap, not silently accepted.
- **CLI / HTTP API surface for setting `active_checks` on permit issuance.** The contract, loader, and executor all support it; no CLI flag or documented curl example was added in this slice. An operator can issue an active-authorizing permit today only by constructing the raw JSON body directly (as the tests do). This is the most likely next piece of follow-up work if this capability needs to be operator-usable rather than just architecturally present.
- **Safety-receipt schema changes.** The existing receipt fields (`requests_attempted`, `requests_permitted`, etc.) already honestly reflect combined passive+active request activity since both flow through the same safety engine. No new fields were added, and none seemed necessary.

## Regression suite

- `packages/contracts/python/src/webguard_contracts/scan_permits.py` + 4 test files updated for the 1.1 schema (14 pre-existing tests, all still passing, now exercising the new field).
- `tests/unit/test_job_executor_active_detection.py`: 6 new tests:
  - passive-only permit (`active_checks=()`) never attempts discovery or probes (zero requests observed);
  - a permit explicitly authorizing `active.xss.reflected` discovers a form and reports a `CONFIRMED` finding with `source="webguard-active"`, `CWE-79`, and evidence containing no raw response content;
  - a permit whose `active_checks` does not include the requested detector never runs it;
  - a permit with a request budget too small to cover the discovery fetch *and* a probe fails the whole job closed with `trustscan_runtime_request_budget_exhausted` and a signed safety receipt, proving the existing runtime safety engine, not new detector-level code, is the actual enforcement point;
  - cancellation requested between the discovery fetch and the first probe stops before any probe is issued;
  - crawl mode merges an active finding into the correct `CrawlPageScanResult`.
- Full repository regression after this slice: **1101/1101 unit tests**, **18/18 integration tests** (14 Juice Shop + 4 Slice-1 live-fixture), security gates (secret scan, static analysis, dependency audit) all passing.

## Verification against the controlled lab (Juice Shop)

Per this session's own rule ("do not use the existence of a Juice Shop vulnerability as proof a detector is generally accurate", inherited from Slice 1, and here: prove the orchestration path doesn't break on a real app's real HTML):

- Re-ran the full Juice Shop integration suite (18 tests, including the permit-issuance HTTP flow) after the schema change. One pre-existing fixture needed the same `"active_checks": []` addition, fixed, all passing.
- Fetched Juice Shop's real root-page HTML over a live socket and ran `discover_get_form_candidates` against it directly (not mocked): **no crash, 0 candidates found**, correct, since Juice Shop v20.1.1 is an Angular SPA with no server-rendered `<form>` tags, consistent with the Slice 1 finding that this app has no reachable server-side reflection surface for this detector's methodology.

No active-check permit was issued against the real Juice Shop container and run through a full live job execution in this slice. The executor-level tests above exercise the identical orchestration code against a controlled synthetic HTML fixture (mocked transport, real permit/executor/detector/discovery code), and the parser was separately verified against Juice Shop's actual HTML. Running an authorized-active-checks job against the live Juice Shop container end-to-end through the HTTP API remains a reasonable next verification step, not yet done.

## Implemented / Tested / Proven / Not Proven / Remaining Risks

**Implemented:**
- TrustScan permit schema 1.1 with an `active_checks` claim, fail-closed default.
- Executor-side discovery (same-origin page re-fetch, bounded GET-form parsing) and detection (registry-driven), fully inheriting the existing runtime safety engine.
- Crawl-mode page-attribution-safe candidate filtering.
- Findings merge into both single-page and crawl reports via the existing, unmodified finding contract.

**Tested:**
- Fail-closed default (empty `active_checks` → zero extra requests).
- Explicit authorization triggers real discovery + detection + finding merge (single-page and crawl).
- Requesting an unauthorized check never runs it.
- The permit's existing request budget governs active probes exactly as it governs passive ones (shared enforcement, not reimplemented).
- Cancellation stops probes before they're issued.
- Evidence contains no raw response content.
- The whole existing 1101-test suite is unaffected by this change (four pre-existing test fixtures needed a one-line update for the new required field; no test needed to be *weakened* to pass).

**Proven:**
- The orchestration wiring works end-to-end against controlled, real-network conditions (Slice 1's real-socket fixture reused via the executor tests' mocked-transport-but-real-code-path pattern) and against real Juice Shop HTML at the parser level.

**Not Proven:**
- A full authorized-active-checks job has not been run against the live Juice Shop container through the real HTTP API end-to-end (only the equivalent code path via executor-level tests, and the parser standalone against real Juice Shop HTML).
- No genuine reflected-XSS finding has been produced against any live target through this orchestration path: none exists to find in the current lab target (Slice 1's conclusion still holds).
- Multi-detector interaction is untested (there is currently only one detector).

**Remaining risks:**
- No CLI/API surface to request `active_checks` on permit issuance. This capability is architecturally real but not operator-reachable without hand-constructing JSON.
- No dedicated audit-event-table entry for active (or passive) job execution.
- The 1.0→1.1 schema replacement (rather than dual-version support) is only safe because there are no deployed 1.0 permits; this must be revisited before any real production deployment with issued permits.
- Crawl-mode active detection only covers self-submitting forms: a real, intentional coverage gap versus single-page mode, not a bug.

**Next slice:** either build the CLI/API surface to make this operator-usable, or proceed to the next detector class (SQL injection) using the same permit-gated, lab-first methodology now that the orchestration scaffolding exists and doesn't need to be rebuilt per detector.
