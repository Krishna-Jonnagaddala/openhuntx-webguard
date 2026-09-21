# Scanner v1 Capability Matrix

## Status

This is the authoritative, audited inventory of what OpenHuntX WebGuard's scanner engine actually does, as of Slice 11 (the Scanner v1 feature freeze). It was compiled by cross-checking the actual registries (`ACTIVE_DETECTOR_REGISTRY`, `KNOWN_TRUSTSCAN_ACTIVE_CHECKS`, `DEFAULT_PASSIVE_ANALYZERS`), the actual detector/analyzer source code, and the actual test suite, not derived from prior documentation or roadmap intent. Every "PROVEN" claim below traces to a named, currently-passing test. Nothing here is marked proven on the strength of documentation alone.

**Slice 12 addendum:** two more active detectors were added after this freeze, at the user's explicit request (sections 13-14 below). They follow the identical registry/permit architecture sections 6-9 describe, but are marked PARTIAL rather than PROVEN for the end-to-end and live-target claims sections 6-9 carry, since that verification has not been done for them yet. Sections 1-12 below describe the state as of Slice 11 and are unchanged by Slice 12 except where a section explicitly says otherwise.

**Slice 13 addendum:** a third post-freeze active detector, XXE (section 15 below), was added the same way. Unlike sections 13-14, it does not use `ACTIVE_DETECTOR_REGISTRY` at all: like SSRF, it needs a `CallbackBroker` wait, so it lives in `CALLBACK_ACTIVE_CHECK_IDS` and its own executor function instead.

**Slice 14 addendum:** a fourth post-freeze active detector, open redirect (section 16 below), was added the same way. Unlike section 15's XXE, it fits `ACTIVE_DETECTOR_REGISTRY`'s generic calling convention exactly, the same as sections 13-14.

**PROVEN** means a named unit test, integration test, or real-network/E2E test currently passes and exercises exactly that claim. **PARTIAL** means some real capability exists but with a stated, real restriction. **NOT SUPPORTED** means the capability does not exist in code at all, not merely undocumented.

## 1. Target authorization & scope safety

| Capability | Status | Evidence |
|---|---|---|
| Owned-target authorization documents (self-attested, JSON, filesystem-backed) | PROVEN | `packages/contracts/python/src/webguard_contracts/owned_targets.py`; `tests/unit/test_owned_target.py` |
| HTTPS-only for non-lab targets | PROVEN | `canonicalize_owned_target_url` rejects non-HTTPS unconditionally; `tests/unit/test_owned_target.py` |
| Loopback/private-IP rejection (commercial mode) | PROVEN | `tests/unit/test_scope_validator.py::test_rejects_loopback_in_commercial_mode`, `test_rejects_private_address_in_commercial_mode` |
| Cloud metadata address rejection | PROVEN | `test_rejects_cloud_metadata_address` |
| Mixed public/private DNS answer rejection | PROVEN | `test_rejects_mixed_public_and_private_dns_results` |
| IPv4-mapped loopback rejection | PROVEN | `test_rejects_ipv4_mapped_loopback` |
| IPv6 link-local/multicast/reserved rejection | PROVEN (by construction) | `scope_validator.py` classifies via Python's `ipaddress.is_link_local`/`is_multicast`/`is_reserved`: these correctly cover IPv6 ranges; **no dedicated named test for an IPv6 link-local literal exists**, so this is PROVEN by code inspection of a general-purpose stdlib classification, not by a target-specific regression test. See Known Limitations. |
| Alternative IP representations (octal/decimal/hex) | PROVEN (by construction, not a dedicated test) | `ipaddress.ip_address()` is strict RFC-4291/dotted-decimal only: it raises on octal/decimal/hex forms rather than silently accepting them, so these forms fail closed as unparseable hostnames requiring DNS resolution rather than being misclassified as a "safe" literal. No dedicated regression test exercises this explicitly. |
| DNS-rebinding independence (resolve-once, pin, connect-to-pinned-address) | PROVEN (Slice 11) | `tests/unit/test_stabilization_audit_boundaries.py::DnsRebindingIndependenceTests`: proves `fetch_once` never performs its own DNS resolution and always connects to `target.resolved_addresses`, even across two requests against the same target |
| Redirect-following (any redirect at all) | NOT SUPPORTED (deliberate) | `safe_http.py` blocks every 3xx response by default (`redirect_blocked`); `tests/unit/test_safe_http.py::test_blocks_redirect_response`. A narrow, explicit `allow_redirect_status` opt-in exists only for the login workflow reading a `Location` header value as a string, never for following it. |
| Lab-mode explicit allowlist (loopback/private targets for authorized local labs) | PROVEN | `tests/unit/test_scope_validator.py::test_accepts_allowlisted_loopback_lab_target`, `test_accepts_allowlisted_private_docker_target`, `test_rejects_unallowlisted_lab_hostname`, `test_rejects_public_address_in_lab_mode` |
| Query string / fragment / embedded-credential rejection on the registered target URL itself | PROVEN | `test_rejects_query_string`, `test_rejects_fragment`, `test_rejects_embedded_credentials` |

## 2. TrustScan permits & tenant/RBAC boundaries

| Capability | Status | Evidence |
|---|---|---|
| Signed (Ed25519), tenant/target/authorization-bound permits | PROVEN | `packages/contracts/python/src/webguard_contracts/scan_permits.py`; `tests/unit/test_trustscan_permit_contract.py` |
| Permit schema versioning (1.0→1.3, replace-in-place) | PROVEN | `docs/audit/trustscan-permit-schema-policy.md`; current `CURRENT_TRUSTSCAN_PERMIT_SCHEMA_VERSION = "1.3"` |
| Owner-only RBAC gate for any active check | PROVEN | `ApiPermission.PERMIT_ISSUE_ACTIVE`; `tests/unit/test_active_checks_permit_control.py::test_administrator_cannot_issue_active_capability_permit` |
| Cross-tenant permit read/revoke/use fails closed (matches "unknown", never leaks existence) | PROVEN | `tests/unit/test_phase2_cross_tenant_permits.py` |
| Cross-tenant job get/cancel/result fails closed | PROVEN | `tests/unit/test_phase2_cross_tenant_jobs.py` |
| Cross-tenant authorization scope (real authorization, unassigned tenant) | PROVEN (Slice 11, was a gap) | `tests/unit/test_cross_tenant_authorization_scope.py` |
| Cross-tenant authentication-context / comparison-plan isolation | PROVEN | `test_authentication_contexts.py::test_require_bound_rejects_wrong_organization`; `test_authorization_comparison.py::test_require_bound_rejects_wrong_organization` |
| Cross-tenant schedule isolation | PROVEN | `tests/unit/test_phase2_cross_tenant_schedules.py` |
| Cross-tenant audit-cursor isolation | PROVEN | `tests/unit/test_phase2_cursor_tenant_isolation.py` |
| Callback-registration tenant scoping | PARTIAL | `CallbackRepository.registration_for(token_value)` has no organization parameter at all: isolation rests on token secrecy/entropy, not an explicit org-scoped check. No operator-facing API exposes this method today, so there is no current exploitable path, but the invariant itself is untested and structurally different from every other resource type's `<resource>_scoped(id, organization_id)` pattern. See Known Limitations. |
| Tampered signed-claim detection (active_checks, authentication_context_id, authorization_comparison_plan_id) | PROVEN | `test_active_checks_permit_control.py::test_tampering_with_signed_active_checks_fails_verification`; equivalent tests in `test_authenticated_permit_control.py`, `test_idor_permit_control.py` |

## 3. Safe HTTP transport

| Capability | Status | Evidence |
|---|---|---|
| Bounded timeout/body/header size enforcement | PROVEN | `tests/unit/test_safe_http.py` |
| TLS certificate validation, no downgrade | PROVEN | same file; `tests/unit/test_tls_analyzer.py` |
| Forbidden request-header blocklist (`Host`, `Content-Length`, etc.) | PROVEN | `test_safe_http.py` |
| Single choke point for every outbound scanner request | PROVEN (Slice 11 audit) | Every network call site (crawler, sitemap/robots/OpenAPI discovery, login, authenticated crawl, XSS/SQLi/IDOR/SSRF probes) routes through `safe_http.fetch_once` exclusively: confirmed by full-codebase grep during this slice's audit; no bypass found |
| Truncated/short-read HTTP response handling | PARTIAL | No dedicated code path distinguishes a truncated body from EOF; whatever the stdlib's `http.client` does (short body, or `IncompleteRead` mapping to the generic `http_protocol_error`) is what happens, untested either way. See Known Limitations. |

## 4. Crawling & attack-surface discovery

| Capability | Status | Evidence |
|---|---|---|
| Bounded breadth-first same-origin crawl | PROVEN | `tests/unit/test_crawler.py`; hard ceiling `MAXIMUM_CRAWL_PAGES = 50`, `MAXIMUM_CRAWL_DEPTH = 3` |
| Crawl checkpoint/resume with tamper/corruption rejection | PROVEN | `tests/unit/test_crawl_checkpoints.py` |
| GET-form / query-parameter / link-parameter discovery | PROVEN | `tests/unit/test_attack_surface*.py` |
| POST-form discovery (representable, requires explicit active authorization to probe) | PROVEN | `request_template.py::to_request_templates(allow_post=True)`; `tests/unit/test_sqli_error_detector.py` POST tests |
| JSON-body discovery (OpenAPI-derived) | PROVEN | `attack_surface.py`'s OpenAPI JSON-body candidate extraction; `tests/unit/test_sqli_error_detector.py` JSON tests |
| Sitemap/robots.txt/well-known-OpenAPI-path discovery | PROVEN | `attack_surface.py::discover_site_attack_surface` |
| GraphQL/XML/multipart candidate discovery | NOT SUPPORTED | No code anywhere parses GraphQL variables, XML bodies, or multipart form parts as mutable candidates |
| Bounded candidate explosion under large forms / many query params | PROVEN | `AttackSurfaceBudget.maximum_parameters_per_endpoint` caps extraction at 10 fields regardless of how many exist on the page (measured this slice: 200-field form → exactly 10 candidates, ~0.5ms) |

## 5. Passive security checks (18 CWEs)

All PROVEN, unit-tested, unchanged in scope this slice. See `docs/CWE_COVERAGE.md` for the complete per-CWE table. Analyzer modules: `header_analyzer.py`, `cookie_analyzer.py`, `cors_analyzer.py`, `disclosure_analyzer.py`, `html_analyzer.py`, `tls_analyzer.py`. One check family, `web.html.meta_refresh.*`, carries no CWE identifier at all (a real, minor gap noted during this slice's registry audit, the finding is still produced, just without a CWE tag).

## 6. Reflected XSS (`active.xss.reflected`, CWE-79)

```
Reflected XSS
├── GET query        PROVEN   (unit + real-socket "_live" + E2E lab)
├── GET form         PROVEN   (same evidence)
├── POST form        PROVEN   (Slice 6 mutation engine; unit + E2E lab)
├── JSON body         NOT SUPPORTED  (explicit RequestTemplateError("xss_json_body_not_supported") -- HTML-reflection evidence doesn't mean the same thing for a JSON response, deliberately not attempted)
├── DOM XSS           NOT SUPPORTED  (no JavaScript execution anywhere in this scanner)
└── Stored XSS         NOT SUPPORTED  (requires a second, unrelated observation point this scanner has no model for)
```

Authentication support: full, with `authentication_material` threaded through every probe. Authorization requirement: `active.xss.reflected` explicit in permit `active_checks`, gated by owner-only `PERMIT_ISSUE_ACTIVE`. Evidence: bounded provenance string (detector id/version, scan/authorization/permit ids, a fresh non-secret marker, outcome): now proven secret-free by a dedicated test as of this slice (`test_active_xss_reflected.py::EvidenceSanitizationTests`, closing a gap this audit found: XSS previously had no such test while IDOR/SQLi/SSRF did). Fingerprint determinism: PROVEN through the real detector path (`test_finding_fingerprint_determinism.py::XssFingerprintDeterminismTests`).

## 7. SQL injection (`active.sqli.error`, CWE-89)

```
SQL Injection (error-based only)
├── GET query         PROVEN
├── POST form         PROVEN   (Slice 6)
├── JSON body         PROVEN   (Slice 6 -- the only detector with full JSON support)
├── Boolean-blind      NOT SUPPORTED
├── Time-based blind   NOT SUPPORTED
├── UNION-based        NOT SUPPORTED
├── Stacked queries    NOT SUPPORTED
└── Data extraction    NOT SUPPORTED  (deliberately: this detector proves injection exists, never reads or exfiltrates real data)
```

Confirmation requires a database-engine-attributable error signature present in the diagnostic response and absent from the baseline: never a generic status-code change alone. Authentication support: full. Evidence sanitization: PROVEN, and deliberately discards the matched signature text itself ("signature text not retained"). Fingerprint determinism: PROVEN.

## 8. IDOR/BOLA (`active.authorization.idor`, CWE-639 + OWASP-API API1:2023)

```
IDOR/BOLA
├── Explicit operator-supplied resource pairs   PROVEN
├── Authenticated resource discovery (Slice 9)  PROVEN  (HTML-link + JSON-field, provenance-tagged)
├── Read-only (GET/HEAD) comparison             PROVEN
├── Write-level (state-changing) comparison     NOT SUPPORTED (explicitly deferred by design across three slices)
├── Multi-identity (>2) comparison              NOT SUPPORTED (2 identities only, by design)
└── Crawl-mode findings                          NOT SUPPORTED (single-page scans only -- a crawled page's findings must be attributable to that one page's own URL; comparison resources are scan-wide, not page-scoped)
```

Never guesses, enumerates, or brute-forces an identifier: every resource identifier originates from an operator-supplied test resource or a legitimate authenticated observation. CONFIRMED requires an exact SHA-256 content-fingerprint match to the victim's own baseline. Uniquely among this project's detectors, confirmed against a live, real-world target (OWASP Juice Shop's basket-access weakness), both via direct JWT inspection (Slice 8) and via legitimate discovery (Slice 9), not only a synthetic fixture. Note (Slice 11 registry audit): this detector has no `test_idor_*_live.py`-named file, breaking the naming convention the other three active detectors follow: its live-network coverage is delivered instead through `test_idor_authorization_juice_shop_lab.py`/`test_authenticated_discovery_juice_shop_lab.py`, which is equivalent or stronger evidence, just differently named. Fingerprint determinism: PROVEN.

## 9. SSRF (`active.ssrf.callback`, CWE-918 + OWASP A10:2021)

```
SSRF (callback-confirmed only)
├── GET query callback probe    PROVEN
├── POST form callback probe    PROVEN  (via the shared RequestTemplate/mutation engine)
├── JSON body callback probe    PROVEN  (same engine, when permitted)
├── Internal-network pivoting   NOT SUPPORTED, and structurally prohibited (the only destination ever used is a callback URL WebGuard itself issued)
├── Blind (non-callback) SSRF   NOT SUPPORTED (no timing-based or DNS-exfiltration-based confirmation exists)
└── Public callback service     NOT SUPPORTED yet (local-only receiver this slice; see docs/production/INFRASTRUCTURE_REQUIREMENTS.md)
```

Confirmation requires an actual out-of-band callback observation correlated to a `secrets.token_urlsafe`-generated, scan-bound, time-limited, bounded-use token: never response-text guessing. Real-network proven (real outbound fetch from a vulnerable fixture, real socket, real receiver) and full E2E proven. Investigated against Juice Shop's real profile-image-URL feature; blocked by Juice Shop's own SSRF-challenge protection given this slice's local-only callback destination, honestly recorded as no compatible surface confirmed there, not worked around. Fingerprint determinism: PROVEN.

## 10. Authentication contexts, sessions & authenticated crawling

| Capability | Status | Evidence |
|---|---|---|
| Bearer token, cookie-session, basic-auth material | PROVEN | `tests/unit/test_authentication.py` |
| Login workflow (explicit success criteria, never assumes 2xx) | PROVEN | `tests/unit/test_login_workflow.py` |
| Cookie exact-origin scoping (domain+port+path+scheme) | PROVEN | `test_authentication.py::test_cookie_never_forwarded_to_a_different_domain` etc. |
| Bearer-token off-origin non-transmission | PROVEN (Slice 11, closed a gap) | `test_stabilization_audit_boundaries.py::BearerTokenNeverSentOffOriginTests`: proven through the real call chain (`issue_probe`/`fetch_same_origin_page`), since `apply_authentication` itself performs no origin check by design (that's the caller's job, always discharged before authentication is applied) |
| Authentication context revocation/expiry enforcement | PROVEN, at repository and permit-issuance layers | `test_authentication_contexts.py`, `test_authenticated_permit_control.py`. Execution-time re-validation exists (`executor.py`) but has no dedicated test proving revocation *between* issuance and execution specifically triggers it end-to-end. See Known Limitations. |
| No credentials in crawl checkpoints | PROVEN (Slice 11, was untested) | `test_stabilization_audit_boundaries.py::CheckpointCredentialAbsenceTests` |
| No credentials in persisted reports | PROVEN (via E2E tests) | Every authenticated E2E test (Slices 7-10) asserts the planted bearer token is absent from the full persisted report text |
| Authenticated crawl (Slice 7 mechanism reused, Slice 9 threaded through crawler) | PROVEN | `test_authenticated_crawl.py` |
| Authorization resource discovery (HTML-link, JSON-field, provenance-tagged) | PROVEN | `test_authorization_resource_discovery.py`, `test_resource_graph.py` |
| MFA, OAuth, SAML, browser automation | NOT SUPPORTED | No code exists for any of these |

## 11. Findings, evidence, reports

See `docs/audit/scanner-v1-security-review.md` for the full finding-schema and fingerprint audit. Summary: `NormalizedFinding` has no `finding_id`, no `first_seen`/`last_seen`, no `scanner_version`/`detector_version` as structured per-finding fields, and no CVSS field at all (by design, no fake precision has been introduced). Fingerprint is deterministic (rule_id/asset/path/method/parameter only) and now proven so through real detector runs for all four active detectors, not only the contract-layer synthetic tests. Evidence sanitization is proven for IDOR/SQLi/SSRF/XSS (XSS closed this slice).

## 12. Jobs, workers, scheduling

| Capability | Status | Evidence |
|---|---|---|
| SQLite-backed job queue, lease/heartbeat/crash-recovery | PROVEN | `tests/unit/test_worker_leases.py`, `test_phase4_lock_crash_recovery.py` |
| Scheduling | PROVEN | `tests/unit/test_phase2_cross_tenant_schedules.py` and the scheduler test suite |
| Unexpected detector/executor exception never crashes the worker | PROVEN, generically | `test_job_worker.py::test_unexpected_exception_is_redacted`: proven via a fake executor raising, not via a real detector raising through the full call chain. See Known Limitations. |
| Redis/message-queue-backed dispatch | NOT SUPPORTED | SQLite-backed leases/polling only |

## 13. Path traversal (`active.pathtraversal.disclosure`, CWE-22, Slice 12, post-freeze)

```
Path Traversal
├── GET query          PARTIAL   (unit-tested against a mocked connection only)
├── GET form           PARTIAL   (same evidence)
├── POST form          PARTIAL   (Slice 6 mutation engine, same evidence)
├── JSON body          PARTIAL   (same evidence)
├── Windows targets     NOT SUPPORTED  (Unix/Linux /etc/passwd only this slice)
├── Alternate depths    NOT SUPPORTED  (one fixed six-level payload only)
└── Encoding bypasses   NOT SUPPORTED  (no URL-encoding/null-byte/absolute-path variants attempted)
```

Confirmation requires an `/etc/passwd` root-entry-line signature present in the diagnostic response and absent from the baseline: never a generic status-code change alone. Authentication support: full, reuses the identical `authentication_material` threading every other detector uses. Evidence sanitization and fingerprint determinism: PROVEN (`test_path_traversal_detector.py`, `test_finding_fingerprint_determinism.py::PathTraversalFingerprintDeterminismTests`). Real-network validation and true end-to-end test: NOT DONE. See `docs/audit/active-detection-phase11-path-traversal.md`.

## 14. OS command injection (`active.cmdi.marker`, CWE-78, Slice 12, post-freeze)

```
OS Command Injection
├── GET query               PARTIAL   (unit-tested against a mocked connection only)
├── GET form                PARTIAL   (same evidence)
├── POST form               PARTIAL   (Slice 6 mutation engine, same evidence)
├── JSON body                PARTIAL   (same evidence)
├── Other separators (| && ` $())  NOT SUPPORTED  (";"-plus-"#" POSIX chaining only)
├── Windows cmd.exe/PowerShell      NOT SUPPORTED
└── Quote-breaking injection contexts  NOT SUPPORTED
```

Confirmation requires a fresh, unique marker to appear in the diagnostic response *and* the full raw diagnostic payload to be absent, specifically to rule out a target reflecting the unexecuted payload verbatim (a real false positive found and fixed during this slice, not caught later). Severity is CRITICAL, the highest this project assigns, for a technique proven so far only against a scripted fake connection, not a real shell. Authentication support: full. Evidence sanitization and fingerprint determinism: PROVEN (`test_command_injection_detector.py`, `test_finding_fingerprint_determinism.py::CommandInjectionFingerprintDeterminismTests`). Real-network validation and true end-to-end test: NOT DONE. See `docs/audit/active-detection-phase12-command-injection.md`.

## 15. XXE (`active.xxe.callback`, CWE-611, Slice 13, post-freeze)

```
XML External Entity injection (out-of-band/blind only)
├── POST form endpoint, whole-body XML override   PARTIAL  (unit-tested against a mocked connection and the real in-memory CallbackBroker only)
├── JSON body endpoint, whole-body XML override    PARTIAL  (same evidence)
├── GET-only endpoints                              NOT SUPPORTED  (no body to replace; never selected)
├── In-band file disclosure (reflected entity value) NOT SUPPORTED  (see the module's own docstring for why this was ruled out, not just deferred)
├── In-band error-signature detection                NOT SUPPORTED  (ruled out: a hardened parser's own safe-rejection error often uses the same vocabulary a vulnerable parser's failure could)
├── Parameter-entity two-stage exfiltration           NOT SUPPORTED  (would require inducing the target to actually read and transmit its own file, the exact risk this detector is built to avoid)
└── DNS-only out-of-band channel                      NOT SUPPORTED  (only a completed inbound HTTP request at WebGuard's receiver counts as proof)
```

Unlike path traversal and command injection, this detector does not fit `ACTIVE_DETECTOR_REGISTRY`'s generic synchronous calling convention: like SSRF, it requires a `CallbackBroker` registration and a bounded wait for an out-of-band observation, so it lives in `CALLBACK_ACTIVE_CHECK_IDS` and its own `executor._apply_xxe_callback_detection`, a close mirror of `_apply_ssrf_callback_detection`. Confirmation requires a genuine callback observation correlated to a token embedded in the probe's SYSTEM identifier, exactly SSRF's own confirmation logic; response text is never inspected, so there is no in-band signature for a hardened parser's own rejection message to be misread as. Candidate selection dedupes by (endpoint, method) rather than by parameter, since the crafted document replaces the whole request body regardless of which field discovered the endpoint. Authentication support: full, reuses the identical `authentication_material` threading every other detector uses. Evidence sanitization and fingerprint determinism: PROVEN (`test_xxe_callback_detector.py`, `test_finding_fingerprint_determinism.py::XxeFingerprintDeterminismTests`). Real-network validation and true end-to-end test: NOT DONE. See `docs/audit/active-detection-phase13-xxe-callback.md`.

## 16. Open redirect (`active.openredirect.location`, CWE-601, Slice 14, post-freeze)

```
Open Redirect (Location header only)
├── GET query                                PARTIAL   (unit-tested against a mocked connection only)
├── GET form                                 PARTIAL   (same evidence)
├── POST form                                PARTIAL   (Slice 6 mutation engine, same evidence)
├── JSON body                                PARTIAL   (same evidence)
├── HTTP Refresh response header             NOT SUPPORTED  (a second, real, non-JS redirect mechanism; only Location on a 3xx is checked)
├── HTML meta-refresh tag                    NOT SUPPORTED  (pre-existing html_analyzer.py gap, not this detector's to close)
├── Client-side JS redirect                  NOT SUPPORTED  (black-box HTTP scanner, no JS execution)
├── Store-now-redirect-later (post-login/SSO) NOT SUPPORTED  (single request per candidate, no follow-up action; a real, common shape for this weakness, not a rare corner case)
└── Alternate payload encodings               NOT SUPPORTED  (protocol-relative input, backslash tricks, double-encoding not attempted)
```

Fits `ACTIVE_DETECTOR_REGISTRY`'s generic synchronous calling convention exactly, unlike SSRF/XXE: one request per candidate, no `CallbackBroker`, no wait. Confirmation requires the diagnostic response's status to be one of the five codes browsers actually auto-follow (301/302/303/307/308) with exactly one `Location` header resolving, via `urlsplit(...).hostname`, to this probe's own fresh marker host; response body is never inspected. A drafted classification design was adversarially reviewed by three independent lenses before implementation, finding no false-positive path but three real bugs fixed before any code was written: duplicate-`Location`-header ambiguity, trailing-dot FQDN normalization, and narrowing the accepted status set to the browser-auto-followed five. Candidate reach inherits this codebase's existing discovery-pipeline restrictions (crawl-mode's per-page path filter, the shared state-changing-keyword safety classification) in a way that costs this technique specifically more than the others, since redirect-controlling parameters are classically discovered via a link to a different endpoint or present only in the entry URL's own query string; both are named directly in the detector module's own docstring. This slice also threads a new `allow_redirect_status` keyword-only argument (defaulted False) through `issue_probe` and `issue_templated_request`, so a 3xx response can be read intact instead of becoming a `redirect_blocked` error; every existing caller is unaffected. Authentication support: full. Evidence sanitization and fingerprint determinism: PROVEN (`test_open_redirect_detector.py`, `test_finding_fingerprint_determinism.py::OpenRedirectFingerprintDeterminismTests`). Real-network validation and true end-to-end test: NOT DONE. See `docs/audit/active-detection-phase14-open-redirect.md`.

## Cross-references

- CWE-by-CWE audit trail: `docs/CWE_COVERAGE.md`
- Lab/fixture regression coverage: `docs/lab/SCANNER_V1_REGRESSION_MATRIX.md`
- False-positive discipline review: `docs/audit/scanner-v1-false-positive-review.md`
- Full known-limitations list: `docs/scanner/SCANNER_V1_LIMITATIONS.md`
- Overall readiness verdict: `docs/audit/scanner-v1-security-review.md`
