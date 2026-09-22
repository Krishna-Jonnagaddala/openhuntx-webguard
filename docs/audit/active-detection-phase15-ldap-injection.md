# Active Detection, Slice 15: LDAP Injection (CWE-90)

## Status

Complete for this detector's own scope, with one disclosed dependency caveat. A ninth active detector (error-based LDAP injection detection) is implemented, unit-tested (mocked connection, no real network), registered/permit-gated through the exact same infrastructure the SQLi/path-traversal/command-injection/open-redirect detectors already use, (Slice 18) real-network validated using a real LDAP client library's own filter compiler, and (Slice 19) taken through a true end-to-end CLI → API → worker → executor → report test. Both the real-network and true-end-to-end proofs depend on the optional `ldap3` package (dev-only, not wired into this project's CI), so they run for real on any machine with it installed and skip cleanly everywhere else, including this project's own CI. **Not yet run against any live/public target.** Added after the same Slice 11 feature freeze the four prior post-freeze slices were added after, at the user's continued request; see `docs/CWE_COVERAGE.md`'s Slice 15 note. Unlike CWE-601/611/78/22, CWE-90 was never previously named in this project's own "Planned" list: it is new scope added directly, not a promotion from a pre-existing entry.

## Pre-implementation verification

This detector's architecture (two bounded requests, baseline-vs-diagnostic comparison, a specific signature must be new to count as evidence, CONFIRMED/PROBABLE/INCONCLUSIVE tiers) is a direct, deliberate reuse of `sqli_error_detector.py`'s own already-shipped, already-proven design. The only genuinely new judgment calls were the diagnostic payload and the error-signature list, so verification focused there rather than re-litigating an architecture this codebase already trusts.

Before writing any code, a drafted signature list (9 entries) and payload were fact-checked and stress-tested by three independent lenses: a signature fact-checker, a false-positive hunter, and a payload-reliability/false-negative hunter. All three verified claims against real client-library source code and real production incident reports rather than reasoning from memory or assumption.

**All 9 originally-drafted signatures checked out as real and accurate**, including resolving the one thing the drafter was explicitly unsure of: whether PHP 8's `ext/ldap` had moved its filter-error warning to an exception. It has not; current `php-src` master still calls `php_error_docref(NULL, E_WARNING, "Search: %s", ldap_err2string(...))` unconditionally from the one C helper (`php_ldap_do_search`) that `ldap_search()`, `ldap_read()`, and `ldap_list()` all share, confirmed directly against source and cross-checked against real, dated (2024-2025) bug reports in GLPI, Snipe-IT, and Nextcloud showing the exact literal text.

**4 more signatures were added** to close real, verified coverage gaps the draft had missed entirely:
- `ldap.filter_error` (Python's python-ldap, confirmed via real GitHub issues)
- `ldap3.core.exceptions.ldapinvalidfiltererror` (Python's ldap3, confirmed via ldap3 issues #680 and #1115, and a real injection scenario in jupyterhub/ldapauthenticator#225)
- `org.apache.directory.api.ldap.model.exception.ldapinvalidsearchfilterexception` (Apache Directory LDAP API / ApacheDS / Spring-LDAP, confirmed via Apache JIRA DIRSERVER-1864)
- `unbalanced parentheses at matchparen` (Node.js's ldapjs, confirmed verbatim across four real ldapjs GitHub issues)

One signature the reviewers proposed, the bare JNDI exception *message* text ("unbalanced parenthesis", as opposed to the already-included fully-qualified class name), was deliberately **not** added: unlike the other proposed additions, it lacks any implementation-attributable token and is generic enough that it could plausibly appear in an unrelated code-syntax-checking tool's own output. The existing `javax.naming.directory.invalidsearchfilterexception` class-name signature already covers the case where an app renders a full exception trace; an app that renders only `exception.getMessage()` without the qualified type is a real, accepted coverage gap, not closed by adding a phrase this detector's own discipline (never a bare word) would otherwise reject.

**One real design ambiguity was caught before it became a bug.** The draft's own prose said the diagnostic payload should be the baseline value with a closing parenthesis appended, but the sibling detector it was modeled on (`sqli_error_detector.py`) actually substitutes a bare module-level constant for the whole value, never appending to a baseline. A reviewer flagged that reflexively copying the SQLi *code pattern* while the *prose* specified append would send a bare `)` instead of `<baseline>)`. The shipped detector explicitly appends (`_diagnostic_payload(baseline_value) -> f"{baseline_value})"`), resolving the ambiguity in code, not just prose, and a dedicated test (`test_diagnostic_payload_appends_to_baseline_not_replaces_it`) pins the exact diagnostic value sent.

**The payload's core mechanism was independently stress-tested and held up.** Two reviewers worked through the paren-arithmetic by hand for simple, wildcard-wrapped, and compound/nested filter templates and found that string concatenation is additive: it can only ever increase the close-paren-vs-open-paren imbalance an injected `)` creates, never cancel it out, regardless of how the surrounding filter is shaped. This was corroborated by real production incident reports (Atlassian Crowd/Jira KB articles, OpenLiberty issue #10462) of ordinary directory values containing a stray parenthesis breaking arbitrary, unknown-shaped production LDAP filters.

**One real, disclosed-not-mitigated safety consideration was surfaced, materially different in kind from anything this project has shipped before.** On a target built with the Node.js `ldapjs` library, this exact payload can, per multiple documented library issues, throw a synchronous, uncaught exception in that library's own filter parser and crash the target's entire process, not merely produce an error response for one request. Every other active detector's diagnostic payload in this project, including this one's own SQLi/path-traversal siblings, can at most produce an unusual HTTP response; none of them can crash the target process outright. This is inherent to the paren-imbalance technique against that specific library, not something this detector can engineer around while still testing for this weakness. It is named plainly in the module's own docstring rather than softened, matching this project's own rule that a safety claim states the actual mechanism, never a hedged wrapper.

## What was built

### Detector (`workers/scanner/src/webguard_scanner/ldap_injection_detector.py`)

Per-candidate methodology: exactly two bounded requests, a **baseline** (the candidate's original value, or `"1"` if empty) and a **diagnostic** (`<baseline>)`, the baseline value with a single unescaped closing parenthesis appended). Classification requires a specific, implementation-attributable signature (a function name, or a fully-qualified exception class name, never a bare generic word) to appear in the diagnostic response and be absent from the baseline, with the status-code-change distinction giving CONFIRMED vs. PROBABLE, mirroring `sqli_error_detector.py`'s `_classify` exactly.

### Registry and contracts catalog

`ACTIVE_DETECTOR_REGISTRY["active.ldapi.error"] = run_ldap_injection_detector`. `webguard_contracts.KNOWN_TRUSTSCAN_ACTIVE_CHECKS` extended to a 9-tuple. `test_active_detector_registry.py`'s sync assertions pass unmodified against the six-entry generic registry.

### Candidate discovery and transports: reused unmodified

Same dual-path shape (legacy `DetectionCandidate` GET, `RequestTemplate` POST/JSON) as every other detector in the registry, built on the identical shared primitives. No new candidate-discovery code, no parameter-name filtering (every discovered candidate is tried, matching SQLi/XSS/path-traversal/command-injection's precedent).

## False-positive controls

Covered by `tests/unit/test_ldap_injection_detector.py` (mocked connection, no real network):

| Scenario | Mechanism that prevents a false positive | Verified |
|---|---|---|
| Genuine filter error, status change | (positive control) | mocked |
| Directory error present but status unchanged | classified PROBABLE, still requires a real signature | mocked |
| Generic 500, no signature | INCONCLUSIVE | mocked |
| Reflection of the raw payload into an error message with no directory-error signature | INCONCLUSIVE (no attributable text present) | mocked |
| Signature already present in baseline (e.g. documentation text) | INCONCLUSIVE, not attributable to the probe | mocked |
| Each of the 13 documented signatures | independently confirmed to be matched | mocked |
| Multiple candidates | classified independently | mocked |
| Probe-budget exhaustion | `enforce_probe_budget` with `requests_per_candidate=2` rejects before any request is sent | mocked |

## Safety boundaries

Identical to the other GET/POST/JSON detectors', inherited unmodified: same-origin enforcement, GET-only legacy candidates rejected at construction, shared `before_request`/`after_request` hooks, redirect/connection-failure handling as probe errors, cancellation checked before every candidate. Evidence sanitization: the matched signature text is never retained in the finding's provenance string (`test_finding_evidence_never_contains_raw_signature_text`). Fingerprint determinism: `test_finding_fingerprint_determinism.py::LdapInjectionFingerprintDeterminismTests` proves the fingerprint is stable across two runs against the same candidate and differs for a different endpoint.

Cross-detector authorization independence has not been re-proven with a dedicated test for this specific detector, the same open gap every post-freeze detector's own audit doc records, relying on the shared, already-tested `active_checks` claim-matching mechanism.

**Non-destructiveness, and the one place this claim cannot be made as cleanly as for this project's other detectors:** the payload itself never touches a file, never executes a command, and never causes a second request anywhere. But unlike every prior active detector here, this project cannot claim the payload is guaranteed non-disruptive to the target process itself: on an ldapjs-backed Node.js target, the documented uncaught-exception behavior means this specific diagnostic can crash the target's service. This is named here plainly, not minimized, and is the one detector in this project's active-detection suite that carries this specific risk class.

## v1 scope

Stated directly in the module's own docstring, repeated here:

- Filter-syntax-error induction only, via one payload shape (a single appended closing parenthesis).
- No DN-injection variant (a different LDAP injection sub-technique using different metacharacters, `,`, `+`, `"`, `\`, `<`, `>`, `;`, to corrupt a distinguished name rather than a search filter).
- No boolean-based blind detection (comparing an always-true vs. an always-false filter injection) and no time-based detection.
- One signature, `"bad search filter"`, is the sole bare, non-attributable entry in the list; kept because no false-positive evidence was found against it in the wild, but named as the first suspect if one is ever reported.
- Several fully-qualified exception-class-name signatures match on *any* error of that class, not specifically a filter-syntax one, the identical structural exposure `sqli_error_detector.py`'s own signature list already carries, inherited rather than newly introduced.
- Real, unmitigated risk: on ldapjs-backed Node.js targets, this payload can crash the target process rather than merely error one request. Stated plainly, not hidden or softened.

## Real-network validation

Done (Slice 18), closing the gap named above without a real LDAP server or real TCP LDAP port. `tests/integration/test_ldap_injection_detector_live.py` uses the pure-Python `ldap3` library's `MOCK_SYNC` client strategy: a real `ldap3.Connection` object backed by an in-memory fake directory, reached over the fixture's real TCP socket. `MOCK_SYNC` only fakes the network transport, not ldap3's own client-side filter compiler, which parses every search filter before any request would reach a real or mocked directory. Confirmed empirically before the fixture was built: a malformed filter (the detector's own diagnostic value, one closing parenthesis appended to the baseline) genuinely raises `ldap3.core.exceptions.LDAPInvalidFilterError`, one of this detector's own 13 signatures, actually exercised here rather than only asserted to exist in the wild. The fixture's vulnerable route interpolates the raw value into the filter unescaped; the safe route escapes it first with ldap3's own real `escape_filter_chars`, which keeps the filter balanced and produces no exception.

`ldap3` is installed dev-only into the local venv for this one test and is not added to any `requirements*.lock` file or CI configuration. The test's own import guard skips it gracefully (rather than erroring) wherever `ldap3` is absent, including this project's current CI, which does not install it; this is a real, disclosed limit on where this specific validation currently runs, not a claim that it runs everywhere.

## True end-to-end test

Done (Slice 19), with the same `ldap3` dependency caveat as the real-network validation above. `tests/integration/test_ldap_injection_checks_e2e_lab.py` mirrors SQLi's own `test_sqli_checks_e2e_lab.py` exactly: real CLI bootstrap, real permit issuance with `--active-check active.ldapi.error`, a real HTTP job submission claimed by a real worker, the real `ScanJobExecutor`, against a fixture reusing the identical `ldap3` `MOCK_SYNC` mechanism the Slice 18 real-network test already proved works. The persisted report's finding carries exactly `CWE-90` and a `rule_id` starting with `active.ldapi.error`.

## Live-target investigation

**Not attempted this slice.**

## Regression

`tests/unit/test_ldap_injection_detector.py`: 16/16 pass. `tests/unit/test_finding_fingerprint_determinism.py`: pass, including 2 new tests for this detector's own fingerprint determinism. `tests/unit/test_active_detector_registry.py`: 3/3 pass unchanged. Full `tests/unit` discover run: clean, no regressions in any pre-existing detector's own test file. `tests/contract`: 99/99 pass (63 skipped, PostgreSQL-backed). `ruff check --select S --ignore S101` against `packages/contracts/python/src`, `workers/scanner/src`, `apps/api/src` (the exact scope `scripts/run-security-gates.sh` checks): clean. `scripts/scan-secrets.py`: clean.

**Slice 18 addendum:** `tests/integration/test_ldap_injection_detector_live.py`: 4/4 pass with `WEBGUARD_RUN_INTEGRATION=1` and `ldap3` installed; skips cleanly (4 skipped) with either missing. Re-ran the full `tests/unit` suite (2031/2031 pass) and the full security-gates script (secret scan, ruff, dependency audit) at the same time as the other four Slice 18 additions; see `docs/CWE_COVERAGE.md`'s own Slice 18 section for the combined run.

**Slice 19 addendum:** `tests/integration/test_ldap_injection_checks_e2e_lab.py`: 1/1 pass with `WEBGUARD_RUN_INTEGRATION=1` and `ldap3` installed; skips cleanly with either missing. Re-ran the full `tests/unit` suite (2031/2031 pass), the full `tests/integration` suite (312/312 pass, 243 skipped), and the full security-gates script (secret scan, ruff, dependency audit) at the same time as the other four Slice 19 additions; see `docs/CWE_COVERAGE.md`'s own Slice 19 section for the combined run.

## Implemented / Tested / Proven / Not Proven / Remaining Risks

**Implemented:** error-based LDAP injection detector (CWE-90), independently permit-gated (`active.ldapi.error`), registered in `ACTIVE_DETECTOR_REGISTRY`, candidate-discovery-integrated, evidence-sanitized.

**Tested:** classification logic, the append-not-replace payload construction, every one of the 13 documented signatures individually confirmed to be matched, evidence sanitization, fingerprint determinism, and the full same-origin/budget/redirect/connection-failure/cancellation/hook safety-boundary suite. All against a fake connection.

**Proven:** the payload's structural reliability (an injected, unmatched closing parenthesis can only ever increase a filter's paren imbalance, never be absorbed by any surrounding template shape) was independently verified by hand-worked arithmetic across simple, wildcard-wrapped, and compound filter shapes and corroborated by real production incident reports, not merely asserted by analogy to SQLi; all 13 signatures are real, currently-accurate strings/class names from named, real libraries and servers, fact-checked against source and real bug reports before this detector was written, not assumed. As of Slice 18, one of those 13 signatures (`ldap3.core.exceptions.ldapinvalidfiltererror`) is also proven by actually triggering it: a real `ldap3` client genuinely raises it on the detector's own diagnostic filter, not merely cited as existing in the wild. As of Slice 19, also proven to survive the full, real CLI → HTTP API → worker → executor → report pipeline unmodified, on any machine with `ldap3` installed.

**Not Proven:** that this detector correctly fires against a real, genuinely vulnerable directory-backed HTTP server beyond this project's own `ldap3`-backed fixture, or correctly abstains against a real, properly-escaping target in the wild; that any real-world target is actually detectable by it; that the other 12 signatures behave as documented against their own real libraries (only the `ldap3` one has been actually triggered so far).

**Remaining risks:**
- On an ldapjs-backed Node.js target, this detector's own diagnostic payload can crash the target process, a materially different and larger risk than any other active detector in this project carries. An operator should be aware of this before authorizing this specific check against a target that might be running that library. Still not exercised under test; the Slice 18/19 fixtures use `ldap3`, not ldapjs, and do not attempt to reproduce the crash.
- Detection is limited to the single closing-parenthesis payload and filter-syntax-error induction; a target vulnerable only through DN injection, boolean-blind, or time-based techniques produces a false negative.
- Both the real-network validation and the true end-to-end test depend on the optional `ldap3` package, installed dev-only and not wired into this project's CI; unlike the other four Slice 18/19 additions, neither currently runs for real anywhere but a machine with `ldap3` installed by hand.
- Cross-detector authorization independence for this specific detector is inferred, not independently reconfirmed.

**Next steps:** live/public-target investigation, the same next step now recorded for every detector besides CWE-639 and CWE-306; separately, a decision on whether to add `ldap3` to this project's locked CI dependencies so both of this detector's Slice 18/19 additions run in CI like the other four do, and whether a simulated ldapjs-shaped crash-on-malformed-filter behavior is worth building to exercise the crash risk under test rather than only reasoning about it.
