# Active Detection, Slice 14: Open Redirect (CWE-601)

## Status

Complete for this detector's own scope. An eighth active detector (single-request Location-header confirmation) is implemented, unit-tested (mocked connection, no real network), registered/permit-gated, (Slice 18) real-network validated against a purpose-built local fixture that genuinely redirects, and (Slice 19) taken through a true end-to-end CLI → API → worker → executor → report test. Unlike XXE, it fits `ACTIVE_DETECTOR_REGISTRY`'s generic synchronous calling convention exactly, the same shape SQLi/XSS/path traversal/command injection already use. **Not yet run against any live/public target.** Added after the same Slice 11 feature freeze the three prior post-freeze slices were added after, at the user's continued request; see `docs/CWE_COVERAGE.md`'s Slice 14 note.

## Pre-implementation adversarial review

Before writing any code, a fully-specified classification design (exact payload, exact pseudocode, the specific transport change needed) was reviewed by three independent lenses, each explicitly instructed to try to break it rather than restate it: a false-positive hunter, an in-scope false-negative hunter grounded in this codebase's actual discovery pipeline, and a code-level correctness reviewer with deep `urllib.parse`/HTTP knowledge. All three actually read the relevant source (`safe_http.py`, `active_detection.py`, `request_template.py`, `attack_surface.py`, `executor.py`) and ran real Python to verify claims empirically rather than reasoning abstractly.

None of the three found a way to produce a false CONFIRMED against a genuinely safe target, despite deliberately trying: the userinfo-prefix trick (`https://target.com@evil.invalid/`), protocol-relative Location values, a safe app that redirects to itself while echoing the payload only in its own query string, case variation, trailing-dot FQDN canonicalization, and a malformed IPv6-bracket Location value. The core primitive, exact hostname comparison via `urlsplit(...).hostname` against a fresh, unique, RFC 2606 `.invalid`-TLD marker, held up under all of it.

Three concrete, verified bugs were found and fixed before any implementation code existed:

1. **Duplicate `Location` headers.** The naive design (`next(...)`, pick the first match) would have made the outcome depend on wire order, an ambiguity a reverse-proxy/WAF layer adding its own `Location` header on top of the origin's own can genuinely produce. Verified directly by feeding a synthetic two-`Location`-header HTTP response through `http.client.HTTPResponse` and confirming `getheaders()` preserves both. Fixed: require exactly one `Location` value; zero or more than one is `NOT_VULNERABLE`, never a guess.
2. **Trailing-dot FQDN normalization.** `urlsplit('https://x.invalid./').hostname` preserves the trailing dot (verified directly), so a target that canonicalizes its own redirect host to an absolute FQDN form would have been missed. Fixed: `.rstrip('.')` on both sides before comparing.
3. **Status-code scope.** The naive design mirrored `fetch_once`'s own 300-399 redirect-blocking range. 300 (Multiple Choices) and 305 (Use Proxy, removed from RFC 7231) are not in the WHATWG Fetch spec's "redirect status" set that governs what a browser actually auto-follows; classifying them as CONFIRMED overclaimed the "silent redirect to attacker site" severity story this detector's own MEDIUM rating is based on. Fixed: narrowed to exactly `{301, 302, 303, 307, 308}`.

The reviewers also surfaced several real gaps that were deliberately **not** fixed in code, either because the fix would require changing shared, cross-cutting infrastructure used by every active detector (out of scope for adding one new detector), or because closing them would meaningfully expand this slice's own scope beyond the single technique it commits to. Both categories are named directly in the module's own docstring rather than left implicit; see "v1 scope" below.

## What was built

### Transport addition: `allow_redirect_status` threaded up one layer

`fetch_once` (`safe_http.py`) already accepted `allow_redirect_status: bool = False`, added in an earlier slice so `login_workflow.py` could read a login-success redirect's `Location` header without following it. Neither `issue_probe` (`active_detection.py`) nor `issue_templated_request` (`request_template.py`) exposed this to their own callers; both always left it False, which converts any 3xx response into a `redirect_blocked` `SafeRequestError` before a caller ever sees its status or headers. Both functions now accept the identical `allow_redirect_status: bool = False` keyword-only argument, passed straight through to their own `fetch_once` call. Every existing caller (SQLi, XSS, path traversal, command injection) leaves it False and is completely unaffected; `open_redirect_detector.py` is the first candidate-based detector to pass True.

### Detector (`workers/scanner/src/webguard_scanner/open_redirect_detector.py`)

One diagnostic request per candidate, no baseline: the parameter's value is replaced with `https://{marker}.invalid/` where `marker = uuid4().hex[:16]` (fresh, unique per candidate, mirroring `_new_marker()` in `command_injection_detector.py`). `.invalid` is the RFC 2606 reserved TLD guaranteed never to resolve; nothing ever connects to it, since `allow_redirect_status=True` means the transport never follows the redirect, it only returns the target's own 3xx response with the `Location` header value as a string.

Classification requires all three of: a status in `{301, 302, 303, 307, 308}`; exactly one `Location` header; and that header's value, parsed with `urlsplit`, resolving (via `.hostname`, never substring matching) to the exact marker host, case-insensitively and with a trailing "." stripped from each side. `urlsplit` itself can raise `ValueError` on some malformed values (an unterminated IPv6 literal); this is caught and folded into `NOT_VULNERABLE`, never allowed to crash the run over one candidate's malformed response.

Outcomes are `CONFIRMED`, `NOT_VULNERABLE`, `ERROR` only, no `PROBABLE` tier: the check is structural (a fresh marker host either is or is not the resolved redirect destination), not a content signature with a weaker/stronger reading the way path traversal's status-code-change signal is.

### Registry and contracts catalog

`ACTIVE_DETECTOR_REGISTRY["active.openredirect.location"] = run_open_redirect_detector`. `webguard_contracts.KNOWN_TRUSTSCAN_ACTIVE_CHECKS` extended to an 8-tuple. `test_active_detector_registry.py`'s sync assertions pass unmodified against the five-entry generic registry.

### Candidate discovery and transports: reused unmodified, deliberately unfiltered

Same dual-path shape (legacy `DetectionCandidate` GET, `RequestTemplate` POST/JSON) as every other generic-registry detector. Unlike SSRF/XXE, no parameter-name-based discovery filter is applied: every discovered GET/POST/JSON candidate is tried, matching SQLi/XSS/path-traversal/command-injection's own "try everything, let structural evidence decide" precedent, justified because this probe costs only one request per candidate and is not structurally limited to URL-sounding field names.

## False-positive controls

Covered by `tests/unit/test_open_redirect_detector.py` (mocked connection, no real network):

| Scenario | Mechanism that prevents a false positive | Verified |
|---|---|---|
| Genuine redirect to the injected host, each of the 5 auto-followed statuses | (positive control) | mocked |
| Userinfo-prefix trick (`https://target.com@<marker>.invalid/`) | `.hostname` resolves the real destination, not the string that appears first | mocked |
| Safe self-redirect echoing the payload only in a query string | `.hostname` resolves the app's own domain, not a substring match on the marker | mocked |
| Status 300/305/306 with a matching Location | excluded from the accepted status set | mocked |
| Relative or missing `Location` on a 3xx | no host to resolve -> NOT_VULNERABLE | mocked |
| Duplicate `Location` headers | ambiguity treated as NOT_VULNERABLE, never a coin-flip pick | mocked |
| Malformed IPv6-bracket `Location` | `ValueError` caught, folded into NOT_VULNERABLE, no crash | mocked |
| Case variation / trailing-dot FQDN in a genuinely vulnerable response | still resolves and still confirms (these are false-negative controls, not positive controls, but pinned the same way) | mocked |
| Probe-budget exhaustion | `enforce_probe_budget` with `requests_per_candidate=1` rejects before any request is sent | mocked |

## Safety boundaries

Identical to the other generic-registry detectors', inherited unmodified: same-origin enforcement, GET-only legacy candidates rejected at construction, shared `before_request`/`after_request` hooks, connection-failure handling as a probe error, cancellation checked before every candidate. Evidence sanitization: the finding's provenance string never includes the probe's own `.invalid` marker host (`test_finding_evidence_never_contains_the_probe_host`). Fingerprint determinism: `test_finding_fingerprint_determinism.py::OpenRedirectFingerprintDeterminismTests` proves the fingerprint ignores the fresh per-candidate marker entirely.

Cross-detector authorization independence has not been re-proven with a dedicated test for this specific detector, the same open gap every post-freeze detector's own audit doc records, relying on the shared, already-tested `active_checks` claim-matching mechanism.

**Non-destructiveness:** the diagnostic never causes a real second request anywhere. `allow_redirect_status=True` means the transport reads the target's 3xx response and stops; it never dereferences the `Location` value, and the value it injects (`https://{marker}.invalid/`) points at a TLD reserved by RFC 2606 to never resolve, so even a hypothetical bug that did follow it would fail closed against nothing.

## v1 scope

Stated directly in the module's own docstring, repeated here:

- Exactly one payload shape (a bare absolute `https://` URL). Protocol-relative input, backslash tricks, double-encoding, and whitespace/control-character bypass encodings are not attempted.
- Only the HTTP `Location` header on a 3xx response is checked. The legacy HTTP `Refresh` response header (a second, real, non-JavaScript redirect mechanism, distinct from the HTML `<meta http-equiv="refresh">` tag) is not checked. Client-side JavaScript redirects are out of scope entirely (no JS execution).
- Single request only, no follow-up action: a "store now, redirect later" pattern (the common post-login/post-SSO redirect, where the payload is captured on one request and only used on a later, separate one) is not observable and is reported NOT_VULNERABLE even when the application is genuinely vulnerable. This is a real, common shape for this exact weakness, not a rare corner case.
- Severity is a flat MEDIUM for every CONFIRMED finding regardless of the parameter's role; an OAuth `redirect_uri`/SSO callback parameter is not distinguished from a cosmetic share link.
- The diagnostic response's body is still read and bounded by `fetch_once` even though classification never inspects it, the same tradeoff `login_workflow.py`'s own `allow_redirect_status=True` use already accepts. An oversized redirect-interstitial page body can push a genuinely vulnerable candidate into a probe ERROR instead of CONFIRMED.
- No cache-busting beyond the marker's own uniqueness: a CDN/cache keyed on path alone could in principle serve one candidate's cached diagnostic response to a different candidate probing the same endpoint path, a false negative, never a false positive.
- Candidate reach is inherited unchanged from this codebase's existing discovery pipeline, which costs open redirect specifically more than the other value-substitution detectors: crawl-mode's per-page `restrict_to_page_path` filter drops a redirect-controlling parameter discovered via a link to a *different* endpoint (the classic `<a href="/logout?redirect_to=...">` shape); `attack_surface.py`'s in-page-only discovery never turns the entry URL's own query string into a candidate (the classic bookmarked `?next=` shape); and the shared `_STATE_CHANGING_KEYWORDS` safety classification (a deliberate safety boundary for every active detector, not a bug) keeps POST-based logout/payment-callback redirect fields, both classic real-world CWE-601 targets, out of reach entirely. None of these are fixed in this slice: each is a shared, pre-existing property of the discovery architecture, and changing it would be a larger, separately-justified change affecting every other active detector, not something scoped to adding one new one.

## Real-network validation

Done (Slice 18). `tests/integration/test_open_redirect_detector_live.py` runs the unmodified detector against a real `ThreadingHTTPServer` with three routes: `/vulnerable` unconditionally answers 302 with the client-supplied value copied straight into `Location`, a genuine, unvalidated open redirect; `/safe` unconditionally answers 302 with `Location: /`, the fixture's own root, never referencing the client value at all; `/safe-echoes-in-body` answers a plain 200 whose body renders the marker host as ordinary page text next to a fixed, unrelated link, with no `Location` header at all, proving the detector's CONFIRMED verdict tracks a real status code and header, never a body-text coincidence.

## True end-to-end test

Done (Slice 19). `tests/integration/test_open_redirect_checks_e2e_lab.py` mirrors SQLi's own `test_sqli_checks_e2e_lab.py` exactly: real CLI bootstrap, real permit issuance with `--active-check active.openredirect.location`, a real HTTP job submission claimed by a real worker, the real `ScanJobExecutor`, against a fixture reusing the identical unconditional-redirect mechanism the Slice 18 real-network test already proved works. The persisted report's finding carries exactly `CWE-601` and a `rule_id` starting with `active.openredirect.location`, reaching CONFIRMED directly (this detector has no PROBABLE tier).

## Live-target investigation

**Not attempted this slice.**

## Regression

`tests/unit/test_open_redirect_detector.py`: 21/21 pass. `tests/unit/test_finding_fingerprint_determinism.py`: 19/19 pass (17 pre-existing + 2 new, including this detector's own). `tests/unit/test_active_detector_registry.py`: 3/3 pass unchanged. Full `tests/unit` discover run and `tests/contract` suite: clean, no regressions in any pre-existing detector's own test file, including SQLi/XSS/path-traversal/command-injection whose `issue_probe`/`issue_templated_request` call sites are unaffected by the new `allow_redirect_status` keyword-only argument (every existing call site already passes only keyword arguments, none positional). `ruff check --select S --ignore S101` against `packages/contracts/python/src`, `workers/scanner/src`, `apps/api/src` (the exact scope `scripts/run-security-gates.sh` checks): clean. `scripts/scan-secrets.py`: clean.

**Slice 18 addendum:** `tests/integration/test_open_redirect_detector_live.py`: 3/3 pass with `WEBGUARD_RUN_INTEGRATION=1`; skips cleanly without it. Re-ran the full `tests/unit` suite (2031/2031 pass) and the full security-gates script (secret scan, ruff, dependency audit) at the same time as the other four Slice 18 additions; see `docs/CWE_COVERAGE.md`'s own Slice 18 section for the combined run.

**Slice 19 addendum:** `tests/integration/test_open_redirect_checks_e2e_lab.py`: 1/1 pass with `WEBGUARD_RUN_INTEGRATION=1`; skips cleanly without it. Re-ran the full `tests/unit` suite (2031/2031 pass), the full `tests/integration` suite (312/312 pass, 243 skipped), and the full security-gates script (secret scan, ruff, dependency audit) at the same time as the other four Slice 19 additions; see `docs/CWE_COVERAGE.md`'s own Slice 19 section for the combined run.

## Implemented / Tested / Proven / Not Proven / Remaining Risks

**Implemented:** open redirect detector (CWE-601), independently permit-gated (`active.openredirect.location`), registered in `ACTIVE_DETECTOR_REGISTRY`, evidence-sanitized. One new shared-transport capability (`allow_redirect_status` on `issue_probe`/`issue_templated_request`), additive and backward-compatible.

**Tested:** classification logic including every false-positive scenario the adversarial review specifically constructed (userinfo trick, safe query-string echo, duplicate headers, malformed IPv6, excluded status codes), evidence sanitization, fingerprint determinism, and the same-origin/budget/cancellation/hook safety-boundary suite. All against a fake connection.

**Proven:** the structural hostname-comparison approach is sound against every false-positive scenario three independent, code-grounded adversarial reviews could construct, not merely against the scenarios the detector's own author thought of; the three real bugs those reviews found (duplicate headers, trailing-dot FQDN, status scope) were fixed before implementation, not discovered after shipping. As of Slice 19, also proven to survive the full, real CLI → HTTP API → worker → executor → report pipeline unmodified.

**Not Proven:** that this detector correctly fires against a real, genuinely vulnerable HTTP server beyond this project's own fixture, or correctly abstains against a real, hardened target in the wild; that any real-world target is actually detectable by it given the disclosed discovery-reach gaps.

**Remaining risks:**
- The single-request, no-follow-up-action methodology cannot detect the common post-login/post-SSO redirect pattern, arguably the highest-impact real-world shape of this exact weakness; this is a real, disclosed false-negative class, not a rare corner case.
- Candidate reach is capped by shared discovery-pipeline restrictions (crawl-mode path filtering, state-changing-keyword classification) that cost this technique specifically more than the others; closing them is a separately-justified, cross-cutting change, not something attempted here.
- Cross-detector authorization independence for this specific detector is inferred, not independently reconfirmed.

**Next steps:** live/public-target investigation, the same next step now recorded for every detector besides CWE-639 and CWE-306; separately, whether to extend discovery to surface the entry URL's own query string as candidates (which would benefit every GET-based detector, not just this one) is worth its own, dedicated design discussion rather than being folded into this slice.
