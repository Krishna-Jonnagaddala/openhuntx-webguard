# Active Detection, Slice 17: Missing Authentication for Critical Function (CWE-306)

## Status

Complete for v1 scope. A tenth active detector (missing-authentication-for-critical-function detection) is implemented, unit-tested (mocked connection, no real network), contract-tested at the permit-claim layer, registered/permit-gated through a new dedicated dispatch category, and taken through a true end-to-end CLI → HTTP API → worker → executor → report pipeline against a real, purpose-built local HTTPS fixture. Added after the same Slice 11 feature freeze the six prior post-freeze slices were added after, at the user's continued request ("do broken authentication next"). Unlike every other post-freeze slice, this one could not stay self-contained inside the scanner package: it required a signed-permit schema change, so the user was asked directly (via a scoping question, not assumed) whether to do the full build or a narrower alternative, and chose the full build.

**Investigated (Slice 20) against a live Juice Shop container: no genuine, unambiguous candidate for this detector's specific claim exists there.** Every other claim in this doc that a prior post-freeze slice left undone (end-to-end pipeline, real-network fixture validation) is done here.

## CWE precision: why CWE-306, not CWE-287

The user's request named "broken authentication," which is CWE-287 (Improper Authentication) in the CWE catalog. CWE-287 itself has no safe active-detector shape in this project: proving a target incorrectly *accepts* invalid credentials requires actually attempting a login with those credentials, which is password-attack territory, and `ROADMAP.md` states plainly that "password attacks... are not part of the current initial release scope." Read directly, `attack_surface.py`'s own `_classify_safety` confirms this exclusion is about what the *technique* requires (an active login attempt), not about which endpoints discovery happens to reach.

CWE-306 (Missing Authentication for Critical Function) is CWE-287's precise, safely-testable child: an operator asserts that a specific URL should require a specific authenticated identity, and the detector checks whether it is reachable with no authentication at all. This needs no password guessing, no session forgery, and no state change: a single anonymous GET, the same non-destructive shape every other active detector's diagnostic probe already uses. This is the identical precision discipline this project already applies to CWE-639-not-862 for `active.authorization.idor`: the most specific CWE that matches exactly what was proven, stated plainly in the coverage registry rather than silently substituted. CWE-287 remains in `docs/CWE_COVERAGE.md`'s own Planned table; this slice does not close it.

## Pre-implementation architecture decisions

**Permit claim, not a separate plan/repository.** A research pass first confirmed there was no existing ad-hoc channel for submitting an arbitrary URL list to a scan (`ScanJobSubmission` accepts only `target`/`authorization_id`/`confirm_authorization`/`mode`). It then compared this detector's needs against `active.authorization.idor`'s own heavyweight `AuthorizationComparisonPlan`/`AuthorizationComparisonPlanRepository` pattern (a separately registered, independently revocable plan referencing two distinct identities' secret material) and found that pattern exists specifically because of IDOR's two-identity/two-secrets need, not because of any general project convention. This detector needs one identity (already referenced by the permit's own `authentication_context_id`) and a list holding no secrets at all (plain URLs plus an optional non-secret marker string). Per `authorization_comparison.py`'s own stated design philosophy ("the smallest clean mechanism"), a direct, bounded claim on the permit itself is the correct fit; a plan/repository would have been unnecessary added surface for a claim with no independent revocation need.

**Schema bump, not dual support.** `CURRENT_TRUSTSCAN_PERMIT_SCHEMA_VERSION` moved `1.3` → `1.4`. `_strict_mapping`'s exact-key-match means adding any new claim field, regardless of whether it is expressed as a direct claim or a plan-ID reference, forces a version bump either way; there is no way to add an optional field without one. Replaced outright rather than dual-supported, the same precedent the `1.0`→`1.1` bump set, justified the same way: this project is "not yet a publicly hosted production service," so there is no deployed old-schema permit to keep compatible.

**A new, distinctly-named dispatch category.** `COMPARISON_ACTIVE_CHECK_IDS`'s own docstring defines "comparison" specifically as IDOR's two-identity, resource-*pair* correlation (four requests, two baselines, cross-checked), a property this detector completely lacks (one real identity vs. no identity, flat endpoints, never pairs, two requests not four). Reusing that name would mislead a future reader. `FIXED_ENDPOINT_ACTIVE_CHECK_IDS` was added instead, with its own docstring naming the real differentiator: candidates are sourced from a signed permit claim, never from page discovery.

## Pre-implementation adversarial verification

Before any detector code was written, the drafted design (marker-less CONFIRMED via bare fingerprint match, an assumed-clean redirect classification, a batch-level try/except, IDOR's crawl-mode skip reused as-is) was reviewed by two independent agents working from the actual code, not the design's own prose. Findings, all resolved before implementation:

- **Blocking.** Both lenses independently flagged that a bare exact-SHA-256-fingerprint match promoted straight to CONFIRMED has no negative control: unlike IDOR, which always has a second identity's own baseline to rule out "this endpoint returns the same thing to everyone," this detector has none. A legitimately public/identical page (a CDN-cached static asset, an unpersonalized SPA shell whose real per-account data loads via an API call the operator never listed) would false-positive as CONFIRMED. **Resolution**: reuse IDOR's own opt-in `owner_marker` mechanism. CONFIRMED now requires *both* an exact fingerprint match *and* the configured marker present in the anonymous response; either signal alone is PROBABLE.
- **Should-fix.** Per-request dynamic content (a CSRF token, a timestamp) on an otherwise fully-leaking page would make the authenticated and anonymous bodies differ byte-for-byte, producing a false NOT_VULNERABLE with zero fallback. The same marker mechanism fixes this: a marker match on a non-identical 200 response is PROBABLE, not dropped.
- **Should-fix.** The drafted design assumed a 3xx redirect to a login page would classify cleanly as NOT_VULNERABLE, but `fetch_once` (and everything built on it) raises `SafeRequestError('redirect_blocked', ...)` for any 3xx unless the caller explicitly passes `allow_redirect_status=True`, which the design had not accounted for. Without it, the single most common correctly-gated pattern (redirect to login) would surface as ERROR, not NOT_VULNERABLE. **Resolution**: both the baseline and the probe pass `allow_redirect_status=True` explicitly; any 3xx is classified from its status alone, before the response body is ever read.
- **Should-fix.** `active.authorization.idor`'s own executor wrapper (`_apply_authorization_comparison`) wraps its entire per-resource-pair loop in one blanket `except ActiveDetectionError: return report`, so a single bad or malformed resource anywhere in the batch silently discards every other pair's results, a pre-existing, unfixed, untested gap in that detector's own code. **Resolution**: this detector does not repeat it. Each endpoint's same-origin check and fetch is wrapped in its own local try/except, isolating a bad entry (a typo, an off-origin URL) to that one endpoint's ERROR outcome and letting the loop continue.
- **Should-fix.** `active.authorization.idor`/`active.ssrf.callback`/`active.xxe.callback` all skip crawl-mode scans in the executor, each citing candidate discovery/page attribution as the reason. Investigation for this slice found that reasoning does not transfer here (this detector's candidates are never discovered from a page at all), but a *different*, more fundamental reason applies just as strongly: `webguard_contracts.CrawlScanResult` (a crawl scan's own report type) has no scan-wide `findings` field at all, unlike `ScanResult`. A crawl report's findings exist only inside each individual page in its own `pages` tuple. This detector's candidates were never page-specific to begin with, so there is not even a plausible single page to attribute a crawl-mode finding to. This is stated explicitly in the detector module's own docstring, not left as an unexplained copy of the existing pattern, and the executor function's own docstring cross-references it.
- **Not a problem, confirmed by direct code reading.** No stale-cookie-leak risk exists: `safe_http.py`'s `fetch_once`/`_make_connection` open a brand-new connection per call with `Connection: close`, no cookie jar, no session object anywhere; `apply_authentication(url, None, now=...)` returns `()`. An anonymous probe issued with `authentication_material=None` cannot structurally inherit anything from the prior authenticated call in the same run.
- **Not a problem, but resolved with a stronger design.** Whether the permit-claim's bidirectional binding rule (endpoints non-empty ⟺ check present, and check present requires `authentication_context_id` set) needed a live-repository lookup to enforce. It does not: it is fully, self-containedly enforced inside `TrustScanPermitClaims.__post_init__`/`TrustScanPermitSubmission.__post_init__` from the claims alone, which is actually stronger than IDOR's own analogous cross-check (only enforced once, at issuance time, against a live plan-repository lookup, and only in the forward direction: a permit can be issued today with `active_checks=["active.authorization.idor"]` and `authorization_comparison_plan_id=None`, an unenforced no-op at execution time).

## What was built

### Contracts (`packages/contracts/python/src/webguard_contracts/scan_permits.py`)

`CURRENT_TRUSTSCAN_PERMIT_SCHEMA_VERSION` moved `1.3` → `1.4`. `KNOWN_TRUSTSCAN_ACTIVE_CHECKS` extended to a 10-tuple with `active.authentication.missing`. New frozen dataclass `MissingAuthenticationEndpoint` (`endpoint`, `method="GET"` enforced, `owner_marker=""` optional), a new field `missing_authentication_endpoints: tuple[MissingAuthenticationEndpoint, ...] = ()` on both `TrustScanPermitSubmission` and `TrustScanPermitClaims`, a bound of `MAXIMUM_MISSING_AUTHENTICATION_ENDPOINTS = 10`, and the bidirectional binding rule described above. Both JSON loaders (`load_trustscan_permit_submission_json`, `load_signed_trustscan_permit_json`) updated to require and parse the new key.

### CLI and service (`apps/api/src/webguard_api/cli.py`, `service.py`)

Two new repeatable flags, `--missing-auth-endpoint` and `--missing-auth-marker` (paired by position; markers past the first endpoint or a skipped middle marker require the HTTP API's JSON submission directly, since the CLI's positional pairing cannot address a gap). `service.issue_permit` passes `submission.missing_authentication_endpoints` straight through to the claims and adds an audit-detail-code suffix (`missing_authentication_scope_authorized`, or appended to an existing suffix) when the list is non-empty. No new RBAC gate needed: the existing generic `active_checks`-non-empty gate already requires `PERMIT_ISSUE_ACTIVE`, and `active.authentication.missing` being present in `active_checks` already triggers it.

### Detector (`workers/scanner/src/webguard_scanner/missing_authentication_detector.py`)

Per-endpoint methodology: exactly two bounded GET requests, an authenticated **baseline** and a fully anonymous **probe** (no Authorization/Cookie header at all), both with `allow_redirect_status=True`. Classification: baseline must succeed with 200 or the endpoint is INCONCLUSIVE; a probe transport failure is ERROR; a non-200 probe (including any 3xx) is NOT_VULNERABLE, classified from status alone; a 200 probe reaches CONFIRMED only when both the exact fingerprint match and the configured marker hold, PROBABLE when exactly one holds, NOT_VULNERABLE otherwise.

### Registry (`workers/scanner/src/webguard_scanner/active_detector_registry.py`)

New `FIXED_ENDPOINT_ACTIVE_CHECK_IDS = frozenset({"active.authentication.missing"})`, unioned into `KNOWN_ACTIVE_DETECTOR_IDS`. `test_active_detector_registry.py`'s sync test extended to check pairwise disjointness across all four categories, not just the original three.

### Executor (`apps/api/src/webguard_api/executor.py`)

`_apply_missing_authentication_detection`, mirroring `_apply_ssrf_callback_detection`'s single-identity resolution pattern (resolve `authentication_context_id` once, up front, outside any per-endpoint loop; let `AuthenticationContextError` propagate as `TrustScanRuntimeSafetyError`, terminating the whole scan with a signed safety receipt rather than being caught per-endpoint). Fails closed on three conditions together: the check ID absent from `active_checks`, an empty endpoint list, or no `authentication_context_id` set (each already prevented from occurring independently by the permit contract's own binding rule; re-checked here as defense in depth, the same posture `_apply_authorization_comparison` takes toward its own already-validated `comparison_plan_id`). Restricted to single-page scans (`hasattr(report, "pages")`) for the `CrawlScanResult`-has-no-scan-wide-findings-field reason described above, not a candidate-discovery one.

## False-positive and false-negative controls

Covered by `tests/unit/test_missing_authentication_detector.py` (mocked connection, no real network):

| Scenario | Mechanism | Verified |
|---|---|---|
| Exact match with no marker configured | PROBABLE, not CONFIRMED (the blocking false-positive fix) | mocked |
| Marker match on non-identical content (dynamic per-request data) | PROBABLE, not NOT_VULNERABLE (the false-negative fix) | mocked |
| Exact match and marker both present | CONFIRMED | mocked |
| Anonymous probe denied (401/403) | NOT_VULNERABLE | mocked |
| Anonymous probe redirected to login (302) | NOT_VULNERABLE, not ERROR; body never fingerprinted | mocked |
| Anonymous 200 with unrelated content (public shell) | NOT_VULNERABLE | mocked |
| Authenticated baseline itself fails | INCONCLUSIVE | mocked |
| One off-origin/bad endpoint among several | ERROR for that endpoint only; others unaffected | mocked |
| Anonymous probe | proven to carry no bearer token at all | mocked |
| Probe-budget exhaustion | budget check (2 requests/endpoint) rejects before any request is sent | mocked |
| Cancellation before first endpoint | nothing probed | mocked |

Contract-layer validation (`tests/unit/test_trustscan_permit_contract.py`, 17 new tests): the `MissingAuthenticationEndpoint` dataclass's own validation (empty endpoint, non-GET method, method case-normalization, `from_dict` error paths), the maximum-10 bound (both sides), all three directions of the bidirectional binding rule, the valid-combination success path, `to_dict` serialization, JSON submission round-tripping, and fingerprint sensitivity to the new field.

## Safety boundaries

Same-origin enforcement, shared `before_request`/`after_request` hooks, cancellation checked before every endpoint: inherited unmodified from `active_detection.py`. Evidence sanitization and fingerprint determinism: PROVEN (`test_missing_authentication_detector.py::EvidenceSanitizationTests`, `test_finding_fingerprint_determinism.py::MissingAuthenticationFingerprintDeterminismTests`).

**Non-destructiveness.** GET only, enforced twice independently: the permit-claim's own `MissingAuthenticationEndpoint.__post_init__` rejects any method but GET, and the detector never sends anything else regardless. The anonymous probe can only ever read; it can never change state on the target, whether or not the target turns out to be vulnerable.

## v1 scope

Stated directly in the module's own docstring, repeated here:

- GET only.
- Single-page scans only, for the `CrawlScanResult`-schema reason described above; extending `CrawlScanResult` with a scan-wide findings field is tracked as follow-up work, not attempted here.
- No client-side (JavaScript-gated) SPA detection: if access control lives entirely in client-side routing with the server serving an identical shell to every visitor, this detector cannot distinguish that from a genuine server-side failure unless a marker specific to genuinely protected content is configured. A marker-less match is capped at PROBABLE for exactly this reason, a named structural limit, not an oversight.
- Up to 10 endpoints per permit (`MAXIMUM_MISSING_AUTHENTICATION_ENDPOINTS`).
- CWE-287 (credential-guessing / login-bypass confirmation) is explicitly not attempted; see the precision section above.

## Real-network validation

Done this slice, via a purpose-built local HTTPS fixture (`tests/integration/test_missing_authentication_e2e_lab.py`, self-signed certificate, real sockets, the same TLS pattern `test_active_checks_e2e_lab.py`/`test_ssrf_callback_e2e_lab.py` already established): `/vulnerable` returns identical marked content to any caller, with or without a bearer token; `/secure` returns protected content only to the correct token, a 401 with unrelated content otherwise.

## True end-to-end test

Done this slice. `tests/integration/test_missing_authentication_e2e_lab.py`:

```
target authorization (real HTTPS fixture, self-signed cert)
  -> authentication context registration [real HTTP]
  -> TrustScan permit with active_checks=["active.authentication.missing"]
     plus missing_authentication_endpoints [real HTTP, schema 1.4]
  -> job [real HTTP] -> real worker -> real executor
  -> authenticated baseline request [real HTTP to the fixture]
  -> anonymous probe request, no credentials at all [real HTTP]
  -> CONFIRMED CWE-306 finding
  -> persisted report -> retrieved over the real HTTP API
```

Result: exactly one CONFIRMED finding on `/vulnerable`; zero findings on `/secure` against the same permit; zero findings when `active_checks` is empty (the permit contract's own binding rule means an inactive permit cannot even carry a non-empty endpoint list, proving the negative from the contract level, not only the executor gate).

## Authorization negatives

- **Passive permit → no finding**: `test_passive_permit_produces_no_missing_auth_finding`, proven through the full real pipeline against the identical vulnerable fixture endpoint that, with the right permit, does confirm.
- **Properly-gated endpoint → no finding, even when the check is active**: `test_secure_endpoint_produces_no_finding`, proving the detector does not simply flag every listed endpoint.
- **Expired permit / revoked authorization / wrong target / wrong organization / tampered `active_checks` claim**: already generically covered by the existing, detector-agnostic `test_active_checks_permit_control.py` suite; `active.authentication.missing` now being a real, known check ID means these protections provably apply to it identically, with no detector-specific code path that could bypass them.
- **An XSS-only or SQLi-only permit cannot trigger this detector**: not separately re-run through the full pipeline (structurally identical to the passive-permit proof already run: the gate `"active.authentication.missing" not in active_checks` does not special-case any other check), inferred from the shared mechanism rather than independently re-proven, the same posture SSRF's own audit doc took toward IDOR.

## Live-target investigation

Done (Slice 20). Investigated against the pinned Juice Shop lab container (v20.1.1) both by probing live and by reading the actual server route table inside the running container (`docker exec ... node -e`, listing every `app.use`/`app.get`/etc. registration and cross-referencing which ones attach `security.isAuthorized()`). **No genuine, unambiguous CWE-306 candidate was found**: every endpoint reachable with zero authentication is either intentionally public by the application's own design, or exposes a real problem of a different CWE shape.

Checked directly:
- `GET /api/Users` (the admin user-listing endpoint the "Admin Section" challenge's own page depends on) correctly returns `401 Unauthorized` with no token. Properly gated.
- `GET /rest/user/authentication-details` and `GET /rest/admin/application-config` both correctly return `401`. Properly gated (the latter's 500 on a broken query string is an unrelated server error, not an auth bypass).
- `GET /rest/memories` (the public photo-wall feed) succeeds with zero authentication and returns every user's memory records, each embedding that user's full nested `User` object, including password hash and `deluxeToken`. This is real, but it is CWE-200 (sensitive data exposure via a legitimately-public endpoint over-sharing fields it should have filtered out of its response), not CWE-306: the endpoint itself is intentionally public by design (it is literally the "Photo Wall" gallery feature), so there is no operator-defensible claim that it "should require authentication to access at all," only that it should redact certain fields once it responds. This project's own passive `disclosure_analyzer.py`/`html_analyzer.py` checks, not this detector, are the right tool for that shape of finding.
- `GET /rest/track-order/:id` and `POST /api/Feedbacks` both succeed anonymously by the application's own explicit design (public order tracking and public review submission are ordinary storefront features, not oversights).
- `POST /file-upload` (the complaint-file-upload route that Slice 20's XXE investigation, see `docs/audit/active-detection-phase13-xxe-callback.md`, already found has no `security.isAuthorized()` middleware at all) is the closest candidate, but its intent is genuinely ambiguous: a public complaint-submission form is a defensible design choice (comparable to a contact form), and Juice Shop's own challenge catalog frames this route's real, intended weakness as the deprecated-XML-upload/XXE angle, never as a missing-authentication one. Using it as a CWE-306 example would be asserting an operator intent this project has no actual basis to assert.

This detector's own contract requires an operator to assert "this specific URL should require my authenticated identity," a judgment call about intent that source-reading and probing alone cannot make on someone else's behalf. No confirmable example exists in this lab target under that standard.

## Regression

`tests/unit/test_missing_authentication_detector.py`: 12/12 pass. `tests/unit/test_trustscan_permit_contract.py`: 26/26 pass (17 new). `tests/unit/test_finding_fingerprint_determinism.py`: pass, including 2 new tests for this detector. `tests/unit/test_active_detector_registry.py`: pass, extended for the fourth category. Full `tests/unit` discover run: 2031/2031 pass, no regressions in any pre-existing detector's own test file (the ~13-file permit-schema-fixture ripple from the `1.3`→`1.4` bump was mechanical: every raw JSON permit submission fixture across unit and integration tests needed `"missing_authentication_endpoints"` added, the same kind of ripple the CSRF slice's check-count shift caused, now fixed). `tests/integration/test_missing_authentication_e2e_lab.py`: 3/3 pass (`WEBGUARD_RUN_INTEGRATION=1`).

**Slice 20 addendum:** live-target investigation against Juice Shop is done; see the "Live-target investigation" section above. No code or test changes this slice, investigation only.

## Implemented / Tested / Proven / Not Proven / Remaining Risks

**Implemented:** missing-authentication-for-critical-function detector (CWE-306), independently permit-gated (`active.authentication.missing`), a new signed-permit claim (`missing_authentication_endpoints`, schema `1.4`), CLI/service/executor wiring, a new dedicated dispatch category (`FIXED_ENDPOINT_ACTIVE_CHECK_IDS`).

**Tested:** classification logic (all five outcomes, including both false-positive and false-negative controls the pre-implementation review surfaced), per-endpoint error isolation, anonymous-probe identity isolation, evidence sanitization, fingerprint determinism, budget/cancellation, and the full permit-contract binding rule (all directions).

**Proven:** the detector correctly reaches CONFIRMED against a real, genuinely vulnerable HTTP endpoint and correctly abstains against a real, properly-gated one, over real sockets and real TLS, through the complete CLI → HTTP API → worker → executor → report pipeline, not only against a mocked connection.

**Not Proven:** that this detector correctly fires against, or correctly abstains against, any real-world third-party target; that the marker-based CONFIRMED/PROBABLE tiering behaves as intended against a genuinely diverse set of real applications (only the two fixture shapes, exactly-identical and denied, were exercised end-to-end; the dynamic-content/marker-only PROBABLE path is proven only at the unit level). As of Slice 20, it is now known that the one live target investigated (Juice Shop) presents no genuine, unambiguous example of this detector's specific claim, so no finding there was ever expected once that was established, not a gap in the detector.

**Remaining risks:**
- Detection is capped at PROBABLE, never CONFIRMED, for any endpoint whose operator did not configure an `owner_marker`, an explicit, named ceiling of comparing one identity against no identity at all, not a bug.
- Single-page scans only; a crawl-mode scan silently never runs this check today (consistent with, not worse than, IDOR/SSRF/XXE's identical existing restriction), pending a `CrawlScanResult` schema change to add a scan-wide findings field.
- Up to 10 endpoints per permit; an operator with more than 10 critical endpoints to check must issue multiple permits.
- This detector's own contract needs an operator's genuine intent ("this URL should require auth") to test meaningfully; a lab environment with no such documented intent behind any of its anonymously-reachable endpoints cannot supply a confirmable positive, a structural limit on what live-target investigation alone can establish for this specific CWE, not something a different target would necessarily fix.

**Next steps:** a `CrawlScanResult` scan-wide findings field, if crawl-mode support for this detector is ever prioritized; separately, a live target with a *documented* missing-authentication weakness (rather than one inferred from source reading) would be needed to move this claim further.
