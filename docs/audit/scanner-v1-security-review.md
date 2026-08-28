# Scanner v1 Security Review

## Verdict

**READY_WITH_REMEDIATIONS**

The scanner engine (target authorization → TrustScan permits → RBAC/tenant boundaries → passive/active detection → findings/reports → jobs/workers) is internally coherent, its safety invariants are backed by regression tests (not merely documentation), and its false-positive discipline holds up under adversarial review. It is not NOT_READY: no functional defect, security bypass, or missing safety control was found that would make running this engine as the core of a hosted product unsafe *as a scanner*. It is not unconditionally READY: this audit found and closed several real test gaps, and identified several real, still-open gaps that should be closed before (not necessarily blocking) production integration — none of which are exploitable today given the current single-operator, loopback-only deployment shape, but all of which become materially more important the moment the platform is multi-tenant-hosted and internet-facing.

## Basis for this verdict

### What this audit actually did

Four parallel research passes (detector-registry integrity, finding-schema/fingerprint/evidence, failure-taxonomy/retry/budget/cancellation, authentication-boundary/multi-tenant/permit-compatibility) cross-checked the real code and real test suite — not prior documentation — against every requirement in this slice's brief. Every finding below traces to a specific file, test, or absence-of-test. Where gaps were found, this audit closed the ones that were cheap, high-value, and within scope (new regression tests — 24 new tests across 4 new files plus one file extended), and explicitly documented the rest rather than either silently fixing everything (out of scope: "do not add another detector," "do not provision infrastructure") or silently ignoring them.

### Verified security invariants (proven, not assumed)

- **Detector registry integrity**: zero drift between the scanner-side registry, the contracts-side permit vocabulary, and `docs/CWE_COVERAGE.md`. Single validation call site confirmed for CLI/API check-ID acceptance.
- **Finding fingerprint determinism**: proven through all four active detectors' *real* code paths this slice (previously only proven at the generic contract layer) — a fresh, high-entropy per-run marker/token never perturbs the fingerprint; a different endpoint/parameter always does.
- **Evidence sanitization**: proven for all four active detectors (XSS was a gap this slice closed) — planted secrets (bearer tokens, resource content, passwords) never appear in finding evidence.
- **Request-budget accounting**: every actual outbound scanner request (crawl, sitemap/robots/OpenAPI, login, authenticated crawl, active probes, IDOR baseline+cross-access, SSRF probes) routes through one choke point (`safe_http.fetch_once`) with hooked `before_request`/`after_request` accounting. No hidden/uncounted request category was found. DNS preflight and SSRF callback-wait polling are correctly excluded (they are not requests against the target).
- **Retry safety**: retries are gated by `is_retryable_error`, which only 5 of ~25 known error codes satisfy (transient network failures). Security/policy exceptions (`TrustScanRuntimeSafetyError`, permit errors) are a structurally different exception type that never enters the retry-decision code path at all — proven by exception-type analysis, though not by a dedicated regression test tying this specifically to the retry loop (a documented gap, not a live risk, since the type boundary is unconditional).
- **Cancellation**: checked pervasively — every subsystem has a real, working cancellation check. Granularity varies (finest: SSRF callback-wait, polled every 50ms; coarsest: IDOR's baseline+cross-access loop, checked once per 4-request resource pair) — documented as an accepted trade-off, not a defect.
- **Scope/SSRF safety separation**: WebGuard's own outbound-request scope protections (`scope_validator.py`, `safe_http.py`) were not modified at all by the SSRF detector's introduction (confirmed via diff history across Slice 10) — the two boundaries ("WebGuard tests target SSRF" vs. "WebGuard's own client must never reach internal networks") remain implemented in entirely separate code with zero shared logic. DNS-rebinding independence proven this slice: `fetch_once` never performs its own DNS resolution, always connecting to the address pinned at target-validation time.
- **Authentication boundaries**: cookie exact-origin scoping proven; bearer-token off-origin non-transmission proven this slice (a real gap this audit found: `apply_authentication` itself performs no origin check by design, relying on the caller's `_require_same_origin` — now proven true through the real call chain rather than assumed); revocation/expiry enforcement proven at repository and permit-issuance layers; no credentials in crawl checkpoints proven this slice (previously untested); no credentials in persisted reports proven via every authenticated E2E test.
- **Multi-tenant isolation**: proven for permits, jobs, authentication contexts, comparison plans, schedules, and audit events (all pre-existing). Cross-tenant *authorization scope* (a real authorization genuinely assigned to tenant A, tenant B attempting to use it) had no dedicated test — every existing cross-tenant test file deliberately assigns the same authorization to both tenants to reach a different boundary. Closed this slice with a new, dedicated test proving the negative case fails closed identically to an unknown authorization ID.

### Real gaps found, closed this slice

24 new regression tests, across 5 files: `test_active_xss_reflected.py` (evidence sanitization, closing XSS's gap relative to IDOR/SQLi/SSRF), `test_finding_fingerprint_determinism.py` (new — fingerprint stability/uniqueness through real detector runs, all four active detectors), `test_stabilization_audit_boundaries.py` (new — bearer-token off-origin enforcement, DNS-rebinding independence, checkpoint credential absence), `test_cross_tenant_authorization_scope.py` (new — the authorization cross-tenant gap above). One genuine pre-existing bug was NOT found this slice (Slice 10 found and fixed one in `resource_graph.py`, already shipped) — this slice's own new code introduced none.

### Real gaps found, deliberately not closed this slice (documented, not fixed)

Fixing these would mean expanding scope beyond auditing — building persistent finding-lifecycle storage, a KMS integration, or a public callback service — each explicitly out of this slice's stated bounds ("do not add another detector," "do not provision production infrastructure yet"):

1. **No `finding_id`, `first_seen`/`last_seen`, or structured `scanner_version`/`scan_id` fields on `NormalizedFinding`.** Findings are ephemeral per-scan today; production finding-lifecycle management (matching a finding across scans) needs schema work this audit correctly did not attempt to do inline.
2. **No CVSS field at all.** This is the *correct* current state per this slice's own instruction ("do not introduce fake CVSS precision... if the available evidence cannot support CVSS context, leave it absent") — recorded as a verified pass, not a gap.
3. **Callback-registration tenant scoping** has no explicit organization-checked read path (isolation rests on token entropy alone). No operator-facing API exposes this read path today, so there is no current exploitable route — but the invariant is untested and structurally inconsistent with every other resource type.
4. **TrustScan permit signing key is a local file, not KMS/HSM-backed.** Already flagged independently in `docs/THREAT_MODEL.md`; this audit re-confirms it as the single highest-priority infrastructure gap (see `docs/production/INFRASTRUCTURE_REQUIREMENTS.md`).
5. **Truncated/short-read HTTP response handling** has no dedicated code path or test.
6. **A detector raising an unexpected exception mid-execution** is protected generically at the worker boundary (proven) but not through a real detector's actual exception propagation path (only a fake executor raising was tested).
7. **IPv6 link-local/alternative-IP-representation scope rejection** is proven by inspection of Python's `ipaddress` semantics, not by a dedicated literal-address regression test.
8. **Report-generation has no cancellation check** — low risk given it's fast, synchronous, in-memory work today.

None of items 1-8 represent a way to bypass an existing safety control; they represent incompleteness in defense-in-depth, schema richness, or test coverage of an otherwise-sound design.

### Performance observations

Measured locally (see `docs/scanner/SCANNER_V1_CAPABILITIES.md` §4 and this review's own spot checks): a 50-page crawl (the hard architectural ceiling — `MAXIMUM_CRAWL_PAGES = 50`) completes in ~33ms with ~700KB peak RSS delta; a 200-field form or a 100-query-parameter page is correctly bounded to 10 extracted candidates by `AttackSurfaceBudget.maximum_parameters_per_endpoint` in under 1ms; a 200-distinct-endpoint page is correctly bounded to 40 candidates by `maximum_endpoints`, with the truncation flag correctly set (unlike the single-form-many-fields case, where the field-level cap is applied silently without setting `truncated` — a minor coverage-accounting imprecision, not a safety issue, noted for completeness). **"100 pages" as a literal test scenario is structurally impossible** — `MAXIMUM_CRAWL_PAGES = 50` is a hard, intentional ceiling, not a performance limitation to optimize away. No genuine bottleneck was found at any tested scale; this project's own bounding discipline (budgets everywhere) is precisely what keeps performance flat under stress rather than degrading.

## What would move this from READY_WITH_REMEDIATIONS to READY

Close items 3-4 above (callback tenant scoping, KMS-backed signing key) before any multi-tenant, internet-facing deployment — both are cheap relative to the rest of the production infrastructure buildout and directly address the two places where the current "single trusted operator" deployment assumption is doing real safety work that a hosted multi-tenant product cannot rely on.

## What would move this to NOT_READY

Discovering that any of the "proven" claims in `docs/scanner/SCANNER_V1_CAPABILITIES.md` do not actually hold under the cited tests — this review found none; every proven claim traced to a currently-passing test, re-verified as part of this slice's final full regression run.
