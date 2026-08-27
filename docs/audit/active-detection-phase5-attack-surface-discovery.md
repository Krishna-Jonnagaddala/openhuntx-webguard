# Active Detection — Slice 5: Attack Surface & Candidate Discovery Expansion

## Status

This slice adds **no new detector**. Per the operator's own instruction ("Do not add another detector yet"), it replaces detector-specific, single-source candidate discovery (GET forms only, discovered by `active_candidate_discovery.py`) with a generalized, reusable attack-surface model that both existing detectors (reflected-XSS, error-based SQLi) now consume through the executor's orchestration layer, without either detector's own code or tests changing.

## What was built

### The candidate/attack-surface contract (`workers/scanner/src/webguard_scanner/attack_surface.py`)

- `AttackSurfaceCandidate`: endpoint URL, method, `InputLocation` (query/path/form/json_body/header), parameter name, baseline value, content type, source page, `DiscoveryMethod`, `SafetyClassification`, and a deterministic `candidate_id` (SHA-256 of canonicalized endpoint + method + input location + parameter — query strings and fragments on the endpoint itself are stripped before hashing, so re-discovering the same endpoint from a different page, a different link, or with different tracking-parameter noise on the *action* URL still resolves to the same identity).
- `SafetyClassification`: `SAFE_TO_PROBE`, `REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION`, `POTENTIALLY_STATE_CHANGING`, `UNSUPPORTED`. Every non-GET candidate is classified `POTENTIALLY_STATE_CHANGING` if its path or field names match a fixed keyword list (`delete`, `remove`, `purchase`, `buy`, `checkout`, `payment`, `pay`, `password`, `logout`/`signout`, `upload`, `admin`, `destroy`, `cancel`, `unsubscribe`); otherwise it defaults to `REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION` — there is no heuristic path to `SAFE_TO_PROBE` for a non-GET candidate. GET is always `SAFE_TO_PROBE`.
- `AttackSurfaceBudget`: independent limits for discovery itself — `maximum_endpoints`, `maximum_parameters_per_endpoint`, `maximum_forms`, `maximum_api_definitions`, `maximum_script_resources`, `maximum_response_bytes`, `maximum_links` — separate from any detector's own probe budget (`ActiveDetectionPolicy.maximum_probe_requests`).
- `AttackSurfaceDiscoveryResult`: `candidates`, `skipped` (a `SkippedSurfaceItem(reason, detail)` tuple — every exclusion is recorded, not silently dropped), `truncated`.
- `to_detection_candidates()`: the one-way projection from the rich model down to the existing, narrower `active_detection.DetectionCandidate` (GET, query/form parameter only) that `xss_reflected_detector.py` and `sqli_error_detector.py` already understand. Only `SAFE_TO_PROBE` GET candidates with a named query/form parameter project through. POST forms, JSON-body candidates, and anything state-changing or unsupported are discovered, classified, and reported on in `AttackSurfaceDiscoveryResult`, but never handed to a detector — no detector exists yet that can represent those shapes safely, and this slice does not invent one to fill that gap.

### Discovery sources implemented

| Source | Function | Notes |
|---|---|---|
| GET forms | `discover_page_attack_surface` | Text-like inputs and `<textarea>`/`<select>`, same field-type exclusions as the original GET-only parser. |
| POST forms | `discover_page_attack_surface` | Classified `POTENTIALLY_STATE_CHANGING` or `REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION`; never projected. |
| Query parameters on links | `discover_page_attack_surface` | `<a href="...?x=1">`, same-origin only, classified `SAFE_TO_PROBE`. |
| Script-embedded endpoint literals | `discover_page_attack_surface` | Bounded regex extraction of quoted `/api/…`, `/rest/…`, `/graphql` string literals from **inline** `<script>` text only — no JavaScript is parsed or executed. Recorded `UNSUPPORTED` (a literal alone doesn't establish a safe parameter shape). |
| GraphQL indicators | `discover_page_attack_surface` | A `/graphql`-containing literal is tagged with `DiscoveryMethod.GRAPHQL_INDICATOR` rather than treated as an ordinary API path; recorded, never probed. |
| OpenAPI/Swagger documents | `discover_site_attack_surface` | Bounded fetch of `/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/swagger/v1/swagger.json`, `/api-docs` (budget: `maximum_api_definitions`, default 3); `paths`/method entries become candidates, safety-classified per method the same way as forms. |
| sitemap.xml | `discover_site_attack_surface` | `<loc>` entries with query strings become `SAFE_TO_PROBE` GET candidates. |
| robots.txt | `discover_site_attack_surface` | `Disallow`/`Allow` paths become `UNSUPPORTED` candidates (paths worth knowing about) — **never** treated as vulnerability evidence, and never projected to a probeable candidate, exactly as instructed. |
| Crawl-discovered pages | executor wiring | `discover_page_attack_surface` already runs once per crawled page in `_discover_and_detect_page`; no new code needed since the crawler already supplies `page_url` per page. |

### Not implemented this slice (explicitly deferred, not silently dropped)

- **URL query parameters as a distinct top-level source** beyond link-embedded ones — the brief's "URL query parameters" and "links containing parameters" collapsed into one implementation (`LINK_PARAMETER`) since a query parameter not reachable via some link or form is not discoverable from static HTML at all without a browser runtime, which this slice explicitly avoids introducing.
- **Common API description formats beyond OpenAPI** (e.g. Postman collections, RAML) — OpenAPI/Swagger's well-known paths were the only ones implemented; no evidence in this codebase's existing lab targets justified more.
- **Site-level discovery in crawl mode.** `discover_site_attack_surface` only runs for single-page scans. Crawl-mode findings must be attributable to one specific crawled page's own URL (`CrawlPageScanResult`'s existing, audited invariant, enforced via `restrict_to_page_path`); sitemap/robots/OpenAPI candidates aren't tied to any one crawled page, so folding them in would either violate that invariant or require inventing a new attribution rule this slice does not define. This is a known, documented limitation, not an oversight.

### Deduplication

`candidate_id` (canonicalized endpoint + method + input location + parameter) is the sole identity used for deduplication, both within one discovery pass (`discover_page_attack_surface`, `discover_site_attack_surface`) and across passes (`merge_attack_surface_results`). Every duplicate collapse is recorded as a `SkippedSurfaceItem("duplicate", …)`, never silently absorbed. Verified deterministic regardless of discovery order (`test_candidate_identity_is_deterministic_regardless_of_discovery_order`) and regardless of incidental query-string/fragment noise on a form's own `action` URL (`test_candidate_identity_ignores_query_string_and_fragment_variation`).

### Scope enforcement

Every URL this module ever turns into a candidate — from a form action, a link `href`, a script literal, a sitemap `<loc>`, or an OpenAPI `paths` key — is checked against the target's own origin (scheme + hostname + port) via `_same_origin` before being added. An off-origin URL is recorded as `SkippedSurfaceItem("off_origin", url)` and never becomes a candidate, regardless of source. Verified explicitly: a form whose `action` points at `https://third-party.example/...`, and a sitemap `<loc>` pointing at a different origin, are both excluded (`test_external_out_of_scope_endpoint_is_excluded_not_authorized`, `test_sitemap_off_origin_url_is_excluded`). Discovery never expands the authorized scope of a scan.

### Budgets

`AttackSurfaceBudget` bounds endpoints, parameters-per-endpoint, forms, API definitions fetched, script resources inspected, and response bytes. Exhausting any of them sets `truncated=True` and records the specific reason (`max_endpoints_reached`, `max_api_definitions_reached`, `response_too_large`) rather than failing the scan. `discover_site_attack_surface` also accepts a `cancellation_check` polled before each of its (up to five) auxiliary fetches — a cancellation mid-discovery stops issuing further requests and returns whatever was already collected, recorded as `SkippedSurfaceItem("cancelled", …)`. Wired through from the executor's existing `cancellation_token`.

### Executor integration (`apps/api/src/webguard_api/executor.py`)

- `_discover_and_detect_page` now calls `discover_page_attack_surface` + `to_detection_candidates` instead of `discover_get_form_candidates` directly. The `restrict_to_page_path` crawl-mode filter and the `maximum_probe_requests` truncation are unchanged — only the discovery step underneath changed.
- `_apply_active_detection`'s single-page branch additionally runs `discover_site_attack_surface` once per scan and merges its `SAFE_TO_PROBE` GET candidates in via a new `extra_candidates` parameter on `_discover_and_detect_page`, deduplicated against page-level candidates by `(url, parameter)`.
- `discover_get_form_candidates` (`active_candidate_discovery.py`) is left in place, unmodified, and no longer called by the executor — kept rather than deleted since deleting working, tested code that nothing currently imports is out of scope for this slice and not something the brief asked for.

## Safety boundaries verified

- **No new probing capability was introduced.** The only thing either existing detector can act on — a GET query/form parameter on the target's own origin — is unchanged; `to_detection_candidates` is a strict subset filter, never an expansion.
- **A discovered POST/JSON/state-changing candidate is never auto-probed.** Verified directly: a POST comment form, a POST `/account/delete` form, and OpenAPI-declared POST/PUT/DELETE operations are all discovered and safety-classified, but none of them appear in `to_detection_candidates`'s output (`test_post_form_requires_explicit_authorization_and_is_not_projected`, `test_likely_state_changing_post_form_is_classified_accordingly`, `test_json_post_api_and_safe_get_api_from_openapi_document`).
- **robots.txt is discovery input, never findings.** Every robots.txt-derived path is `UNSUPPORTED` and never projected (`test_robots_txt_paths_are_discovery_input_not_findings`).
- **Off-origin discovery never expands authorization.** Confirmed for both page-level (forms, links) and site-level (sitemap) sources.
- **No browser or JavaScript runtime was introduced.** Script-literal extraction is a bounded regex over already-fetched inline `<script>` text; nothing is parsed as JavaScript or executed. External bundle files (`<script src="…">`) are not fetched or inspected by this module.

## A real bug this slice caught before it reached production data

While wiring `discover_site_attack_surface` into the true end-to-end lab test (a real target on a non-default TLS port, exactly the shape every hosted/production target will have), both true E2E tests (`test_active_checks_e2e_lab.py`, `test_sqli_checks_e2e_lab.py`) failed with `worker_internal_error`. Root cause: the initial implementation built auxiliary-resource URLs (`/sitemap.xml`, `/robots.txt`, the OpenAPI well-known paths) as `f"{target.scheme}://{target.hostname}/"`, silently dropping a non-default port. Against a target actually listening on a non-default port, that malformed URL failed `_require_same_origin`'s port check and raised `ActiveDetectionError`, uncaught, all the way to the worker's generic exception handler — a functional bug, not a security one (the fail-closed same-origin check did exactly what it should when given a wrong URL), but one that would have made site-level discovery *silently non-functional* on almost every real deployment, since almost no production HTTPS target runs on port 443 behind a bare hostname in this project's own lab-testing pattern. Fixed with a small `_origin_base_url()` helper that only omits the port when it matches the scheme's default. Caught by the pre-existing true-E2E tests exactly as intended — this is why those tests patch only TLS trust and target validation, and run the real executor otherwise.

## Real-network validation and Juice Shop investigation

Re-ran discovery against the pinned Juice Shop lab target (`bkimminich/juice-shop:v20.1.1@sha256:cd58d79c…`, loopback-only) to **measure**, not force, whether previously-missed surfaces are now discoverable.

**Page-level discovery against the root page:** 0 candidates, 0 skipped. Confirmed by direct inspection: the served page is an Angular SPA shell (`<script src="polyfills.js">`, `scripts.js`, `main.js` — all external bundle files, zero inline `<script>` content, zero server-rendered `<form>` or parameterised `<a href>` elements). Consistent with, not a new finding beyond, the phase 1 and phase 4 investigations.

**Site-level discovery:**
- `robots.txt` — real, Express-served (not SPA-routed): `Disallow: /ftp`. Discovered and recorded as one `UNSUPPORTED` candidate (`http://127.0.0.1:3000/ftp`), never probed, matching the explicit instruction that robots.txt is discovery input only.
- `sitemap.xml`, `/openapi.json`, `/swagger.json`, `/v2/api-docs` — **all four return HTTP 200 with Juice Shop's Angular `index.html`**, not sitemap XML or an OpenAPI document. This is an Angular catch-all route serving the SPA shell for any unmatched path. `sitemap.xml`'s HTML contains no `<loc>` tags (zero candidates, zero false positives). The three OpenAPI-shaped paths fail JSON parsing and are correctly recorded as `SkippedSurfaceItem("malformed_openapi_document", …)` rather than crashing or fabricating a candidate from HTML. `/swagger/v1/swagger.json` was never attempted — the `maximum_api_definitions` budget (3) was already exhausted, recorded as `SkippedSurfaceItem("max_api_definitions_reached", …)`.
- **Accepted candidates:** 1 (`/ftp`, `UNSUPPORTED`, never probed).
- **Skipped candidates with reasons:** 3× `malformed_openapi_document`, 1× `max_api_definitions_reached`.
- **Projected, probeable candidates (`to_detection_candidates`):** 0.

**Conclusion, honestly stated:** Juice Shop's actual REST API surface (`/rest/...`, `/api/...`, including its well-known SQLi login challenge) remains **not discoverable** by this slice's static/API-description-based discovery. It is loaded exclusively by client-side JavaScript in bundle files this slice deliberately does not fetch, parse, or execute, per the explicit constraint against introducing a browser/JS runtime "unless there is a strong architectural justification" — none was found. This is the expected, foreshadowed outcome of exhausting safe static discovery first: it was insufficient for Juice Shop's specific SPA architecture, and that insufficiency is itself the honest result being reported, not a defect to paper over. No candidate was fabricated and no detector was altered to force a finding.

## Regression

- New test file `tests/unit/test_attack_surface_discovery.py`: **21/21 passing.** Covers all 13 required fixtures (GET form, POST form, query parameter, JSON POST API, safe API endpoint, likely state-changing endpoint, duplicate endpoints, external/out-of-scope endpoint, malformed HTML, malformed JSON/OpenAPI, very large input, cancellation, budget exhaustion) plus two candidate-identity/determinism tests and two merge/dedup tests.
- Full unit suite: **1168/1168 passing** (1147 pre-existing + 21 new), zero regressions.
- Full integration suite (`WEBGUARD_RUN_INTEGRATION=1`, Juice Shop container live): **25/25 passing**, including both true end-to-end tests (`test_active_checks_e2e_lab.py`, `test_sqli_checks_e2e_lab.py`) and all 14 Juice Shop-dependent lab tests.
- The complete pre-existing active-detection suite (66 tests: XSS classification/safety, SQLi classification/safety, permit control, CLI, executor, registry, cross-detector authorization, permit lifecycle) was re-run explicitly against the new discovery pipeline and passes unchanged — neither detector's behavior, findings, or test expectations were touched by this slice.
- Security gates (secret scan, static analysis, dependency audit) and `git diff --check`: run after this document; commit recorded below only after they pass.

## Implemented / Tested / Proven / Not Proven / Security Boundaries Verified / False-Positive Controls / Known Limitations / Remaining Risks / Test Counts / Security Gate Status / GitHub Commit / Remote Sync Status / Next Slice

**Implemented:** a generalized `AttackSurfaceCandidate` model with safety classification, deterministic deduplication, independent discovery budgets, and eight discovery sources (GET forms, POST forms, link query parameters, script-embedded endpoint literals, GraphQL indicators, OpenAPI/Swagger documents, sitemap.xml, robots.txt), wired into the executor for both single-page and crawl scans; both existing detectors now consume it through a one-way, safety-filtering projection.

**Tested:** all 13 brief-specified fixture types, candidate-identity determinism under reordering and under incidental URL noise, cross-source deduplication, discovery-budget exhaustion (page-level and merge-level), cancellation mid-discovery, and off-origin exclusion at both page and site level.

**Proven:** the new discovery pipeline produces identical detector-visible candidates to the old GET-form-only pipeline for the cases the old pipeline already handled (both true E2E tests and the full 66-test active-detection suite pass unchanged); POST/JSON/state-changing candidates are discovered and classified but structurally cannot reach either detector; a real port-handling bug in the new site-level discovery code was caught by the existing true-E2E tests before merge, not after.

**Not Proven:** that any of the newly added discovery sources (OpenAPI, sitemap, robots.txt, script literals) surface a genuinely new, previously-unreachable vulnerability on any real target — Juice Shop's SPA architecture happens to defeat all of them, so this remains unproven pending a lab or authorized target with server-rendered API documentation or a classic (non-SPA) page structure.

**Security boundaries verified:** no new probing capability; POST/JSON/state-changing candidates never auto-probed; robots.txt never treated as evidence; off-origin candidates always excluded regardless of source; no browser/JS runtime introduced; discovery budgets and cancellation enforced with explicit skip/termination recording.

**False-positive controls:** not directly applicable to this slice (no new detection logic) — the relevant control is that a discovered candidate is never mistaken for a finding; discovery only ever produces candidates or explicit skip records, never a security finding on its own.

**Known limitations:** site-level discovery does not run in crawl mode (page-attribution invariant, documented above, not fixed this slice); JavaScript bundle files are never fetched or parsed, so any SPA whose API surface is not also described by robots.txt/sitemap/OpenAPI remains undiscoverable by this slice; the state-changing safety heuristic is a fixed keyword list, not a semantic analysis, and can both under- and over-classify an unusually named endpoint.

**Remaining risks:** the keyword-based `POTENTIALLY_STATE_CHANGING` classifier could mislabel a genuinely safe POST endpoint as merely `REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION` (not itself dangerous, since neither classification is auto-probed) or, more importantly, could fail to recognize a destructive endpoint that doesn't match any of its keywords, defaulting it to `REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION` rather than `POTENTIALLY_STATE_CHANGING` — both outcomes currently have the identical effect (never auto-probed), so this is a labeling-accuracy risk today, not a safety gap, but would become a safety gap if a future detector ever probes `REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION` candidates without also checking the keyword classification independently.

**Test counts:** 1168 unit (1147 existing + 21 new), 25 integration (all passing with the Juice Shop lab container live).

**Security gate status:** recorded below after `scripts/run-security-gates.sh` completes.

**GitHub commit:** recorded below after push and `HEAD == origin/main` verification.

**Remote sync status:** recorded below.

**Next slice:** per the operator's own stated priority (master scope document, section 46), the next high-value detector class can now be built on top of this richer candidate model from the start — most naturally one that can actually consume a POST/form or JSON-body candidate (this slice deliberately built the discovery and classification for that surface without yet building a detector that can safely act on it). Alternatively, per the same section's explicit caveat, any security blocker found in the meantime takes priority over this ordering.
