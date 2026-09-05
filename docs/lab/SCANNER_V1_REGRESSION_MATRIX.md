# Scanner v1 Lab Regression Matrix

## Status

For every controlled lab fixture and the one real-world lab target (OWASP Juice Shop) this project uses, this matrix records exactly what is expected to fire, what is expected not to fire, and what is executed vs. skipped vs. structurally unsupported. Compiled by cross-checking each fixture's own test file against its own handler routes, not by assumption.

## 1. Synthetic passive fixture (header/cookie/CORS/disclosure/HTML/TLS)

Fixtures: purpose-built `ThreadingHTTPServer` handlers per analyzer, in each analyzer's own unit test file, plus the shared Juice Shop passive pass below.

| Expected finding | Check family |
|---|---|
| Missing HSTS | `web.headers.hsts` |
| Missing CSP | `web.headers.csp` |
| Missing X-Content-Type-Options | `web.headers.x_content_type_options` |
| Missing frame protection | `web.headers.frame_protection` |
| Missing/permissive referrer policy | `web.headers.referrer_policy` |
| Insecure/missing cookie flags | `web.cookies.*` (7 families) |
| Permissive CORS | `web.cors.*` (5 families) |
| Server/framework version disclosure | `web.disclosure.*` (6 families) |
| Directory listing, mixed content, password over HTTP, sensitive HTML comments | `web.html.*` (9 families, one of which, `meta_refresh`, carries no CWE tag) |
| TLS certificate/chain/cipher/protocol weaknesses | `web.tls.*` (7 families) |

**Executed checks**: all `DEFAULT_PASSIVE_ANALYZERS`, every scan. **Skipped checks**: TLS checks skip cleanly for HTTP-only targets (`test_tls_analyzer_lab.py::test_http_juice_shop_skips_https_only_tls_checks`), recorded as skipped-with-reason, not silently absent. **Unsupported**: none within this fixture's own scope.

## 2. Reflected-XSS fixture

Fixture: `tests/integration/test_active_checks_e2e_lab.py`'s `_ReflectedXssFixtureHandler` (self-submitting `?q=` search form) plus `tests/integration/test_active_xss_reflected_live.py`'s dedicated confirm/encode/off-origin fixture.

| Route/scenario | Expected outcome |
|---|---|
| Unescaped reflection | CONFIRMED, CWE-79 |
| HTML-encoded reflection | NOT a finding (informational, no CWE) |
| No reflection at all | No finding, recorded as tested |
| Off-origin candidate | Rejected before any request (`candidate_origin_mismatch`) |
| POST-form variant | CONFIRMED (Slice 6 mutation path) |
| JSON-body candidate | Never probed at all (unsupported by design) |

**Executed**: `active.xss.reflected` only. **Skipped**: SQLi/IDOR/SSRF (not authorized by this fixture's permit). **Unsupported**: DOM/stored XSS (no code path exists).

## 3. SQLi fixture

Fixture: `tests/integration/test_sqli_error_detector_live.py`, real in-memory SQLite behind 8 routes across 3 transports (GET/POST-form/JSON) × (vulnerable/safe) + `/broken` (generic 500) + `/about` (static database-shaped text).

| Route | Expected outcome |
|---|---|
| `/vulnerable*` (all 3 transports) | CONFIRMED, CWE-89 |
| `/safe*` (all 3 transports, parameterized query) | No finding |
| `/broken` (generic 500, no SQL involved) | INCONCLUSIVE, no finding |
| `/about` (static text mentioning a DB error phrase, unconditionally) | INCONCLUSIVE, no finding (the same phrase appears whether or not the probe was sent) |

**Executed**: `active.sqli.error` only. **Skipped**: XSS/IDOR/SSRF. **Unsupported**: boolean-blind/time-based/UNION/data-extraction techniques: no code path exists for any of them.

## 4. Authenticated fixture

Fixture: `tests/integration/test_authenticated_scanning_e2e_lab.py`, two identities, `/public`, `/account` (login-gated), `/api/profile?q=` (authenticated-only reflection point), `/login`, `/logout`.

| Scenario | Expected outcome |
|---|---|
| Unauthenticated `/account` | Generic "please log in" body, no form, no reflection surface |
| Authenticated `/account` | Real dashboard with a reflectable form |
| Authenticated `/api/profile?q=` | CONFIRMED reflected-XSS (CWE-79), the same detector unmodified |
| Login with correct credentials | Session extracted (redirect-based success criterion) |
| Login with wrong credentials | `success=False`, no session, never assumes 2xx means success |

**Executed**: authenticated crawl/discovery + `active.xss.reflected`. **Skipped**: SQLi/IDOR/SSRF (not authorized). **Unsupported**: MFA, OAuth, browser-based login.

## 5. IDOR fixture

Fixtures: `tests/integration/test_idor_authorization_e2e_lab.py` (explicit resource_scope) and `tests/integration/test_authenticated_resource_discovery_e2e_lab.py` (discovery-based), two identities, secure `/documents/{id}` (ownership-checked), vulnerable `/orders/{id}` (no ownership check), `/shared/team-doc`, `/public/info`, an out-of-scope external link, a duplicate resource reference, `/account/expired`.

| Route/scenario | Expected outcome |
|---|---|
| `/orders/{own-id}` (baseline, either identity) | 200, own content |
| `/orders/{other-identity's-id}` (cross-access) | CONFIRMED, CWE-639 + OWASP-API API1:2023 (the vulnerable endpoint) |
| `/documents/{other-identity's-id}` (cross-access) | 403, no finding (the secure endpoint) |
| `/shared/team-doc` (both identities) | No finding (identical value for both, excluded by the distinct-identifier-value eligibility rule alone) |
| `/public/info` | No finding (public, unauthenticated) |
| Out-of-scope external link in authenticated HTML | Never becomes a resource (rejected twice: crawler never follows it; discovery independently re-checks origin) |
| Duplicate resource reference on one page | Deduplicated by structural resource ID, not double-reported |
| `/account/expired` | Classified `AUTHENTICATION_EXPIRED`, zero resources contributed |

**Executed**: authenticated crawl/discovery + `active.authorization.idor`. **Skipped**: XSS/SQLi/SSRF. **Unsupported**: write-level comparison, >2 identities, crawl-mode findings.

## 6. SSRF callback fixture

Fixture: `tests/integration/test_ssrf_callback_detector_live.py` / `test_ssrf_callback_e2e_lab.py`, `/fetch-vulnerable` (real outbound fetch), `/fetch-safe`, `/reflect-only`, `/validation-error`, `/generic-500`.

| Route | Expected outcome |
|---|---|
| `/fetch-vulnerable` | CONFIRMED, CWE-918 + OWASP A10:2021 (real callback observed over a real socket) |
| `/fetch-safe` | No finding (accepts the URL, never fetches) |
| `/reflect-only` | No finding (echoes the URL, never fetches; the core false-positive control) |
| `/validation-error` | No finding (400, never fetches) |
| `/generic-500` | No finding (500, never fetches) |

**Executed**: `active.ssrf.callback` only, proven independently not authorized by passive/XSS-only/SQLi-only permits against this identical fixture. **Skipped**: IDOR-only (not separately re-run through the full pipeline: the gate is structurally identical to the XSS/SQLi cases already proven; see `docs/audit/active-detection-phase10-ssrf-callback.md`). **Unsupported**: internal-network destinations (structurally impossible), blind/timing-based SSRF, a public callback service.

## 7. OWASP Juice Shop (real-world lab target)

Investigated across Slices 1, 4, 6, 8, 9, 10, using only Juice Shop's own documented registration/login endpoints, never enumeration/brute-force/privilege-escalation/data-alteration.

| Detection class | Result | Why |
|---|---|---|
| Reflected XSS | No compatible surface found | Angular SPA: the documented reflected/DOM-XSS challenge renders client-side; no server-side raw-HTML reflection point exists for this detector's methodology |
| SQL injection | No compatible surface found | The real login-bypass challenge is a silent boolean/auth-bypass, not an error condition, and is a POST-JSON endpoint with no discoverable server-rendered form |
| IDOR/BOLA | **CONFIRMED against the real basket-access weakness** | Both via direct JWT-payload inspection (Slice 8) and via legitimate discovery from the login response's own `bid` field (Slice 9) |
| SSRF | No compatible surface confirmed | The real profile-image-URL-fetch feature exists and does perform a server-side fetch, but Juice Shop's own SSRF-challenge protection blocks this project's local-only (non-public) callback destination; testing past that boundary would require either internal-network probing (forbidden by design) or production callback infrastructure (out of scope this slice) |

Juice Shop is the only target where this project has ever confirmed a genuine finding against a real, independently-known vulnerability rather than a fixture this project built and controls. That is a materially stronger validation signal than any synthetic fixture alone, precisely because two of the four active detectors found nothing there (an honestly-reported absence, not a detector failure).
