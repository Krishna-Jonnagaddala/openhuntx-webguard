# Active Detection — Slice 4: SQL Injection (CWE-89)

## Status

Complete. A second active detector — conservative, error-based SQL injection detection — is implemented, tested, real-network validated against a purpose-built vulnerable fixture, and end-to-end verified through the full CLI → API → worker → executor → registry → detector → report chain, reusing the orchestration/candidate-discovery/permit infrastructure built for reflected XSS (Slices 1–3) without modifying it in any way that weakens existing behavior.

## What was built

### Detector (`workers/scanner/src/webguard_scanner/sqli_error_detector.py`)

Per-candidate methodology: exactly two bounded GET requests — a **baseline** (the candidate's original value, or `"1"` if empty) and a **diagnostic** (a single unescaped apostrophe `'`, the minimal SQL metacharacter that breaks a string-literal query fragment without executing an alternate statement, extracting data, or modifying anything). No UNION extraction, no stacked statements, no time delays, no boolean-differential technique in this slice — all explicitly out of scope per the brief.

A finding is produced **only** when a specific, database-engine-attributable error signature appears in the diagnostic response and is **absent** from the baseline. Sixteen signatures spanning PostgreSQL, MySQL/MariaDB, Microsoft SQL Server, and SQLite — each a multi-token, engine-specific phrase (e.g. `"you have an error in your sql syntax"`, `"unclosed quotation mark after the character string"`, `"unrecognized token:"`), never a bare word like `"SQL"`, `"error"`, or a product name alone. A generic status-code change with no attributable signature produces **no finding at all**, not even a low-confidence one — this is the core anti-false-positive property this slice's brief specifically demanded, and it is real-network verified below, not just asserted.

Three outcomes (deliberately fewer than reflected-XSS's five — see the module docstring for why: this technique's evidence doesn't support more granularity than "specific signature newly appeared" vs. "nothing attributable happened"):

| Outcome | Condition | Finding? | Severity / Confidence |
|---|---|---|---|
| CONFIRMED | new signature in diagnostic, absent from baseline, **and** status code changed | yes | High / Confirmed |
| PROBABLE | new signature in diagnostic, absent from baseline, status code unchanged | yes | High / High |
| INCONCLUSIVE | everything else (no signature, probe failure, signature already in baseline, generic error, reflection without interpretation) | **no** | — |

### Shared-infrastructure extension: multi-request budget accounting

`active_detection.enforce_probe_budget` gained an optional `requests_per_candidate` parameter (default `1`, preserving reflected-XSS's existing behavior exactly) so a detector issuing more than one request per candidate can declare its real request cost. SQLi passes `requests_per_candidate=2`. This is the only change to shared code in this slice, and it is additive/backward-compatible — verified by the full existing XSS test suite passing unchanged.

### Registry and contracts catalog

`ACTIVE_DETECTOR_REGISTRY["active.sqli.error"] = run_sqli_error_detector`. `webguard_contracts.KNOWN_TRUSTSCAN_ACTIVE_CHECKS` extended to `("active.sqli.error", "active.xss.reflected")` — this is an addition to an existing whitelist tuple, not a claims-schema change, so **no permit schema version bump was needed** (unlike Slice 2's 1.0→1.1 bump, which changed the claims *shape*; this only widens the set of values one existing field may contain).

### Candidate discovery: reused unmodified

`discover_get_form_candidates` (built for XSS in Slice 2) is used exactly as-is. The executor already discovers candidates once per page and runs every authorized+registered detector against the same set — this was already detector-agnostic before this slice, confirmed by reading the code rather than assumed, and this slice's tests exercise that shared path directly (`test_active_checks_cross_detector_authorization.py`).

## False-positive controls

The brief listed eleven specific negative scenarios; all are covered by dedicated tests (unit, mocked-connection: `test_sqli_error_detector.py`; real-network: `test_sqli_error_detector_live.py`):

| Scenario | Mechanism that prevents a false positive | Verified |
|---|---|---|
| Genuine SQL error | (positive control) | mocked + real |
| Generic HTTP 500 | no attributable signature → INCONCLUSIVE | mocked + real |
| Application validation error | no signature → INCONCLUSIVE | mocked |
| Ordinary apostrophes in legitimate content | signature matching is specific multi-token phrases, never bare punctuation | mocked |
| Reflected probe string, no SQL interpretation | reflection alone isn't a signature | mocked |
| Database-looking text already in baseline | signature present in *both* baseline and diagnostic → treated as pre-existing, INCONCLUSIVE | mocked + real |
| Changed response, no database evidence | status change alone is never sufficient | mocked |
| Redirects | `safe_http`'s existing redirect-blocking surfaces as a probe error, never a finding | mocked |
| Connection failures | surfaced as a probe error, never a finding | mocked |
| Malformed responses | `errors="replace"` decoding, no crash | implicit in all tests (never raised) |
| Multiple parameters | classified fully independently per candidate | mocked + real |
| Probe-budget exhaustion | `enforce_probe_budget` with `requests_per_candidate=2` rejects before any request is sent | mocked |

## Safety boundaries

Identical to reflected-XSS's, inherited unmodified:

- Same-origin enforcement (`issue_probe`'s existing fail-closed origin check) — reused, not reimplemented.
- Only GET candidates (`DetectionCandidate` already rejects non-GET at construction).
- Every probe goes through the same `TrustScanRuntimeSafetyEngine.before_request`/`after_request` hooks as passive requests and reflected-XSS probes — budget, rate, concurrency, revalidation, circuit-breaking all apply identically, with zero new enforcement code for SQLi.
- **Independent authorization**: proven, not assumed. `test_active_checks_cross_detector_authorization.py` runs a single field genuinely vulnerable to *both* XSS and SQLi under three permit configurations (XSS-only, SQLi-only, both) and asserts the unauthorized detector never fires in either direction — this specifically rules out the possibility that "any active check" implicitly enables every registered detector.
- Permit lifecycle gates (expiry, revocation, wrong target/authorization) evaluated identically regardless of which detector IDs `active_checks` contains — `test_active_checks_permit_lifecycle.py` reconfirms this explicitly for SQLi-bearing permits rather than relying solely on the pre-existing, detector-agnostic Phase 2/4 coverage.
- Tampering: the existing `test_tampering_with_signed_active_checks_fails_verification` test (Slice 3) already proves mutating *any* content of the signed `active_checks` claim invalidates the Ed25519 signature — this is a property of the claims/signing mechanism, not per-detector, so it was not duplicated for SQLi specifically; re-asserting an already-proven general property under a new name would not add evidence.
- Cross-tenant permit access: likewise an existing, general, already-tested tenant-isolation property (Phase 2/4, reconfirmed for `active_checks`-bearing permits in Slice 3) — not re-derived here.
- Evidence sanitization: findings carry only a fixed provenance string (`Detector <id> vX.Y. Scan: ... Matched signature category: database-engine error output (signature text not retained).`) — the actual matched phrase, the response body, and any query results are never included. No credentials, cookies, or authorization headers pass through this detector at any point (it only ever sends GET requests with a single benign or diagnostic query-parameter value).

## Real-network validation

`tests/integration/test_sqli_error_detector_live.py` — a real in-memory SQLite database behind four HTTP endpoints served over real loopback sockets (not mocked): `/vulnerable` (string-concatenated SQL, genuinely broken by `'`), `/safe` (parameterised query, `'` is just a literal value), `/broken` (always a generic 500, no SQL involved), `/about` (static 200 page whose copy happens to contain a database-shaped phrase, identically every time). **5/5 tests pass**: the detector fires (CONFIRMED) only on `/vulnerable`; the other three endpoints — each representing one of the brief's required negative controls — produce no finding, run individually and together in one detector invocation.

The actual SQLite exception text was verified empirically before writing signatures, not assumed from documentation: `unrecognized token: "'"` for this exact injection, confirmed by direct interpreter testing.

## True end-to-end test

`tests/integration/test_sqli_checks_e2e_lab.py` — the identical chain proven for XSS in Slice 3 (CLI bootstrap → CLI authorization assignment → CLI permit issuance with `--active-check active.sqli.error` → real HTTP API job submission → real worker → real `ScanJobExecutor` → real registry lookup → real `run_sqli_error_detector` → a `CWE-89` finding in the persisted report → retrieved through the HTTP API's job-result endpoint), against a purpose-built local fixture (self-submitting form wrapping a real, genuinely vulnerable SQLite query), over a freshly generated self-signed TLS certificate, using the same three narrowly-scoped, individually-justified mocks Slice 3 already established and documented (loopback scope validation, the owned-target preflight's independent public-address re-check, and the TLS trust anchor). **1/1 test passes.**

## Juice Shop investigation

Investigated, not assumed. Checked empirically:

- `GET /rest/products/search?q='` → clean `{"status":"success","data":[]}`, no error, no signature.
- Root page (`curl` fetch, not a rendered browser) → **zero** `<form>` elements, confirmed via `grep`.
- `discover_get_form_candidates` run directly against the real fetched root-page HTML → zero candidates, matching the CWE-79 investigation's identical finding.
- The actual documented Juice Shop SQLi challenge is `POST /rest/user/login` with a JSON body (confirmed: `GET` on that path returns a generic 500 unrelated to the challenge; `POST` with JSON returns 401 for bad credentials) — a POST JSON endpoint, structurally outside this detector's GET-form-only candidate discovery.

**Conclusion: this detector's deliberately conservative methodology cannot be validated against the pinned Juice Shop version, for the same structural reason as reflected-XSS** — no reachable server-rendered GET-form surface exists on this app at all. The detector was not altered to manufacture a finding here, per the brief's explicit instruction.

## Regression

Full suite run after this slice: **1147/1147 unit tests**, **25/25 integration tests** (14 Juice Shop + 4 XSS live-fixture + 5 SQLi live-fixture + 1 XSS true-E2E + 1 SQLi true-E2E), all three security gates (secret scan: 254 files / 6 artifacts / 530 blobs; static analysis; dependency audit) passing, `git diff --check` clean. The complete reflected-XSS test suite (43 tests across `test_active_xss_reflected.py`, `test_active_checks_permit_control.py`, `test_active_checks_cli.py`, `test_job_executor_active_detection.py`, `test_active_detector_registry.py`) was re-run explicitly and passes unchanged — XSS behavior is unaffected by this slice.

## Implemented / Tested / Proven / Not Proven / Remaining Risks

**Implemented:** error-based SQLi detector (CWE-89), independently permit-gated (`active.sqli.error`), registered, candidate-discovery-integrated, evidence-sanitized.

**Tested:** all eleven brief-specified negative scenarios plus the two positive ones (mocked + real-network); all eleven brief-specified authorization scenarios (passive-only, XSS-only, SQLi-only-doesn't-grant-XSS, unknown-ID, expired, revoked, wrong-target, cross-tenant [existing coverage], tampering [existing coverage], cancellation, budget exhaustion).

**Proven:** the detector correctly identifies a genuinely vulnerable endpoint and correctly abstains on three realistic near-miss endpoints, over a real database engine and real sockets; the full CLI-to-report chain works end-to-end; SQLi and XSS authorization are provably independent even against a target vulnerable to both.

**Not Proven:** no genuine, independently-discovered real-world SQL injection has been found by this detector — the fixture is a controlled, known-vulnerable synthetic page, and the one available real-world lab target (Juice Shop) has no reachable surface for this detector's methodology, honestly documented rather than worked around.

**Remaining risks:**
- Detection is limited to GET-form-discovered parameters with error-based evidence only; no boolean-differential technique exists yet (explicitly deferred by the brief), so a SQLi vulnerability that fails silently (no distinguishable error output) would not be found.
- No POST-body or JSON-body candidate discovery exists (shared limitation with reflected-XSS, not new to this slice) — this is precisely why Juice Shop's actual SQLi challenge is unreachable.
- The 16-signature list, while deliberately specific, is not exhaustive; a database engine or driver whose error text doesn't match any of these sixteen phrases would produce a false negative, not a false positive — consistent with this slice's stated priority (accuracy over count; ambiguous evidence yields no finding rather than a guess).

**GitHub commit(s):** recorded below after push and `HEAD == origin/main` verification.

**Next slice:** per the original instruction, further active-detection classes (e.g. IDOR/access-control, or SSRF with a controlled callback architecture) can now reuse this same registry/candidate-discovery/permit/CLI/RBAC scaffolding without rebuilding it — or, alternatively, the production-readiness sweep (PostgreSQL/Redis/deployment) remains open per the earlier gap matrix, per the operator's stated "not yet" on infrastructure.
