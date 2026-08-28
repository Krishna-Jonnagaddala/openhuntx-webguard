# OpenHuntX WebGuard CWE Coverage

## Status language

This registry follows the same discipline as [`ROADMAP.md`](ROADMAP.md): it separates what is implemented and tested today from what is planned. It is not a claim that WebGuard detects every weakness listed, and it is not a transcription of the full CWE catalog.

## Scope discipline

WebGuard does not claim to scan for every CWE. The CWE catalog (including the reference view consulted while scoping this registry) covers roughly a thousand entries spanning memory safety, language-specific misuse, hardware, and internal software-development defects that are not observable by an external, black-box web assessment tool. Those entries are out of scope by construction and are not enumerated here as "not applicable" noise.

This registry instead tracks only CWE classes that are:

- web- or API-relevant, and
- externally observable (or detectable with explicit, authorised authenticated access) without source-code review.

Each tracked CWE has one status:

- **IMPLEMENTED** — detection logic exists in a scanner analyzer, runs as part of a normal scan, and is covered by tests.
- **IMPLEMENTED (active, permit-gated)** — detector code exists, is tested, and is reachable end-to-end through the API job/executor pipeline when a TrustScan permit explicitly authorizes it (`active_checks` claim). Not reachable through the standalone `webguard scan` CLI, which does not use TrustScan permits at all. See the linked audit doc for exactly what was and wasn't validated.
- **PARTIAL** — some indicators can be detected, but exploitability cannot always be established from the outside.
- **PLANNED** — defined as in-scope, not yet implemented.
- **NOT APPLICABLE** — cannot reasonably be tested externally; intentionally excluded.

## Implemented

Detected today by the passive analyzers (`workers/scanner/src/webguard_scanner/`), each with dedicated tests:

| CWE | Name | Detected by |
|---|---|---|
| CWE-16 | Configuration | `cors_analyzer.py`, `header_analyzer.py`, `cookie_analyzer.py` |
| CWE-20 | Improper Input Validation | `cookie_analyzer.py` |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | `header_analyzer.py`, `html_analyzer.py`, `disclosure_analyzer.py` |
| CWE-209 | Generation of Error Message Containing Sensitive Information | `html_analyzer.py` |
| CWE-295 | Improper Certificate Validation | `tls_analyzer.py` |
| CWE-319 | Cleartext Transmission of Sensitive Information | `header_analyzer.py`, `html_analyzer.py`, `cookie_analyzer.py` |
| CWE-324 | Use of a Key Past its Expiration Date | `tls_analyzer.py` |
| CWE-326 | Inadequate Encryption Strength | `tls_analyzer.py` |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | `tls_analyzer.py` |
| CWE-548 | Exposure of Information Through Directory Listing | `html_analyzer.py` |
| CWE-598 | Use of GET Request Method With Sensitive Query Strings | `html_analyzer.py` |
| CWE-614 | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | `cookie_analyzer.py` |
| CWE-615 | Sensitive Information in Source Comments | `html_analyzer.py` |
| CWE-693 | Protection Mechanism Failure | `header_analyzer.py` |
| CWE-942 | Overly Permissive Cross-domain Whitelist | `cors_analyzer.py` |
| CWE-1004 | Sensitive Cookie Without 'HttpOnly' Flag | `cookie_analyzer.py` |
| CWE-1021 | Improper Restriction of Rendered UI Layers or Frames | `header_analyzer.py` |
| CWE-1275 | Sensitive Cookie with Improper SameSite Attribute | `cookie_analyzer.py` |

**18 CWEs implemented**, all passive (no active/intrusive requests), all covered by unit tests.

## Implemented (active, permit-gated, operator-reachable)

| CWE | Name | Detector | Notes |
|---|---|---|---|
| CWE-79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | `xss_reflected_detector.py` | **Operator-reachable + authorization-controlled + end-to-end verified.** Reflected-XSS over GET query/form parameters and, as of Slice 6, POST-form parameters (via the shared request-template/mutation engine, gated by the permit's `allowed_http_methods` claim). JSON bodies are deliberately not supported — this detector's evidence (unescaped markup echoed into an HTML response) doesn't mean the same thing for a JSON API response. Issuable via `webguard-api permit issue --active-check active.xss.reflected`, gated by a stricter owner-only RBAC permission (`PERMIT_ISSUE_ACTIVE`) beyond ordinary permit issuance, and audited (detector ID recorded, never payload/evidence). Runs end-to-end through the job executor when the bound TrustScan permit's `active_checks` claim authorizes it; every existing and default-issued permit has an empty `active_checks` claim and therefore never triggers it — fail-closed by default. A true end-to-end test (CLI → HTTP API → worker → executor → registry → detector → report) is verified against a local synthetic fixture, over real TLS, real permit/RBAC enforcement, and the real runtime safety engine. Not reachable through the standalone `webguard scan` CLI (no permit concept there). See `docs/audit/active-detection-phase1-xss.md` (detector validation), `docs/audit/active-detection-phase2-orchestration.md` (orchestration wiring), `docs/audit/active-detection-phase3-operator-surface.md` (CLI/RBAC/audit surface + the end-to-end test), and `docs/audit/active-detection-phase6-request-mutation.md` (POST-form support) for exactly what was validated at each layer. |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | `sqli_error_detector.py` | **Operator-reachable + authorization-controlled + end-to-end verified.** Conservative, error-based detection only (baseline request + one bounded apostrophe diagnostic per candidate; no boolean-differential, time-based, UNION, or stacked-query techniques) — unchanged since Slice 4. As of Slice 6, this same methodology runs over three input transports through the shared request-template/mutation engine: GET query parameter, POST form parameter, and JSON body parameter (dotted/indexed path, e.g. `user.email`), each independently gated by the permit's `allowed_http_methods` claim in addition to `active_checks`. A finding requires a specific, database-engine-attributable error signature present in the diagnostic response and absent from the baseline, regardless of transport — a generic status-code change alone never produces a finding. Issuable via `webguard-api permit issue --active-check active.sqli.error`, independently authorized from `active.xss.reflected` (proven for both GET and POST transports: an XSS-only permit cannot trigger SQLi and vice versa, even against a field genuinely vulnerable to both). Verified over a real, purpose-built, deliberately vulnerable local SQLite-backed fixture (real sockets, real database engine) with three transports × vulnerable/safe pairs plus a generic-500 and a database-looking-static-text negative control, none of which produced a false finding. A true end-to-end test (CLI → HTTP API → worker → executor → registry → detector → report) is verified the same way as CWE-79. Investigated against the pinned Juice Shop lab target: **still could not be validated there, for a documented reason that changed with this slice.** Juice Shop's real login endpoint (`POST /rest/user/login`, JSON body) is now representable and, if manually supplied, was empirically confirmed to be correctly classified INCONCLUSIVE by this detector's unmodified error-based methodology (no error signature — Juice Shop's login bypass is a silent boolean/auth-bypass condition, not an error condition). It remains undiscovered by static discovery (no HTML form, no real OpenAPI/sitemap/robots reference — Juice Shop is an Angular SPA whose API surface loads via JS bundles this project deliberately does not parse). See `docs/audit/active-detection-phase4-sqli.md` (GET, phase 4) and `docs/audit/active-detection-phase6-request-mutation.md` (POST/JSON, phase 6) for exactly what was and wasn't validated. |
| CWE-639 | Authorization Bypass Through User-Controlled Key (IDOR/BOLA) | `idor_authorization_detector.py` | **Operator-reachable + authorization-controlled + end-to-end verified — and, uniquely among this project's active detectors so far, confirmed against a live, real-world lab target, not only a synthetic fixture.** A genuine multi-identity authorization-comparison engine, not a parameter fuzzer: requires two explicitly registered, distinct `AuthenticationContext`s (`AuthorizationComparisonPlan`, a separate signed permit claim from the single-identity `authentication_context_id`) and an explicit, operator-supplied `resource_scope` of controlled resource pairs — this detector never guesses, enumerates, or brute-forces an identifier; every resource identifier must originate from a resource created by a test identity, an explicitly configured fixture/test resource, or a controlled lab API response legitimately obtained while authenticated as that identity. Read-only (GET) object access only this slice. CONFIRMED requires an exact SHA-256 content-fingerprint match between the cross-identity response and the victim's own baseline response — a generic HTTP 200, or a coincidental response-length match, is never sufficient (a length-based fallback was tried, found to produce a real false positive in testing, and removed). A `SHARED`/`PUBLIC` expected-access classification on a resource makes it permanently unreportable regardless of what status both identities receive, so intentionally shared resources are never misreported as IDOR. Issuable via a permit whose `active_checks` includes `active.authorization.idor` **and** whose `authorization_comparison_plan_id` claim references a plan bound to this exact organization/target/authorization — referencing the plan without also requesting the check (or vice versa) is rejected; an XSS-only or SQLi-only permit cannot trigger it. Every finding carries both `CWE-639` and, as this project's first non-CWE identifier namespace, `OWASP-API` (`API1:2023`, Broken Object Level Authorization) — `CWE-862` is deliberately never attached automatically, since this detector's evidence establishes a specific object-level bypass, not a general missing-authorization condition. Verified over a real, purpose-built fixture with two identities, a secure ownership-checked endpoint, a deliberately vulnerable parallel endpoint with no ownership check, and a shared-resource endpoint — the secure and shared endpoints never produce a finding. **Independently confirmed against a live OWASP Juice Shop container** using two accounts created only through Juice Shop's own documented registration/login endpoints and each account's own shopping-basket ID (obtained from that account's own JWT, never guessed) — Juice Shop's real, publicly documented "view another user's basket" broken access control weakness was genuinely reproduced and correctly classified CONFIRMED/CWE-639 by this detector's unmodified methodology. A true end-to-end test (two contexts → comparison plan → permit → job → worker → executor → detector → report) is verified against the local synthetic fixture, over real TLS, real permit/RBAC enforcement, and the real runtime safety engine. See `docs/audit/active-detection-phase8-idor-bola.md` for exactly what was and wasn't validated. |

**3 CWEs implemented as permit-gated, operator-reachable, end-to-end-verified active detectors.**

## Planned

The remaining active-detection target set (see `ROADMAP.md` — coverage growth), gated behind a valid TrustScan permit and the `SecurityCheck` interface described there. Not yet implemented.

| CWE | Name | Category |
|---|---|---|
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | Injection |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | File & path security |
| CWE-611 | Improper Restriction of XML External Entity Reference | Injection |
| CWE-502 | Deserialization of Untrusted Data | Injection |
| CWE-918 | Server-Side Request Forgery (SSRF) | Network / SSRF |
| CWE-352 | Cross-Site Request Forgery (CSRF) | CSRF |
| CWE-287 | Improper Authentication | Authentication |
| CWE-862 | Missing Authorization | Authorization |
| CWE-601 | URL Redirection to Untrusted Site ('Open Redirect') | Configuration |

**9 CWEs planned.**

## Not yet classified

Every other CWE, including the full breadth of the reference catalog consulted while scoping this list, is treated as **NOT APPLICABLE to external black-box assessment** unless a specific, evidence-backed detection approach is proposed and reviewed. This registry will only grow by adding rows with real detection logic and tests attached (see `docs/ROADMAP.md`, "Detection architecture and CWE coverage" — no CWE is added to this file on the basis of intent alone).

## Coverage summary

```
18 Implemented (passive, in orchestration)
 3 Implemented (active, permit-gated, integrated into orchestration)
 0 Partial
 9 Planned
```

## Non-CWE identifiers

As of Slice 8, findings may also carry an `OWASP-API` identifier alongside their primary CWE — the OWASP API Security Top 10 (2023) classifies authorization-bypass findings (e.g. `API1:2023`, Broken Object Level Authorization) more specifically for API-shaped resources than any single CWE does. This is additive: every such finding still carries a CWE as its primary identifier, and `OWASP-API` is never a substitute for one.
