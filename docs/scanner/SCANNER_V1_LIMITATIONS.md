# Scanner v1 Known Limitations

## Status

Explicit, honest documentation of what OpenHuntX WebGuard's scanner does **not** do, as of the Scanner v1 feature freeze (Slice 11). Every item below is a deliberate scope boundary or a genuine, currently-real gap, not a bug to silently work around. Honest limitations are what make the capability claims in `docs/scanner/SCANNER_V1_CAPABILITIES.md` and the CWE coverage in `docs/CWE_COVERAGE.md` trustworthy.

## Detection breadth limitations

- **DOM-based XSS**: not supported. This scanner never executes JavaScript; DOM XSS requires a browser engine to observe, which this project has explicitly never built (no headless browser, no JS interpreter anywhere in the codebase).
- **Stored XSS**: not supported. Confirmation would require a second, unrelated observation point (submit on page A, observe reflection on page B, possibly as a different identity) that this scanner has no model for yet.
- **JSON-body reflected XSS**: not supported, deliberately. HTML-reflection evidence (unescaped markup echoed into an HTML response) doesn't mean the same thing for a JSON API response; this detector explicitly rejects JSON-body candidates rather than producing misleading findings.
- **Boolean-blind, time-based, UNION-based, and stacked-query SQL injection**: not supported. Only conservative, error-signature-based detection exists (one bounded diagnostic request per candidate).
- **SQL injection data extraction**: not supported, deliberately. This detector proves that injection is possible; it never reads or exfiltrates real database contents.
- **Write-level (state-changing) authorization testing**: not supported. IDOR/BOLA detection is read-only (GET/HEAD) only, across three consecutive slices of explicit deferral.
- **Multi-identity (>2) authorization comparison**: not supported. Exactly two controlled identities, by design: no N×N cross-user comparison exists or is planned for v1.
- **Unrestricted resource enumeration**: not supported, and structurally prohibited. No code path anywhere in this codebase generates, enumerates, or brute-forces a resource identifier; every IDOR candidate originates from an operator-supplied test resource or a legitimate authenticated observation.
- **Internal-network SSRF pivoting**: not supported, and structurally prohibited. The SSRF detector's only ever destination is a callback URL WebGuard itself issued: never 127.0.0.1, RFC1918, or cloud metadata addresses, even to "prove" the vulnerability exists.
- **Blind (non-callback) SSRF**: not supported. No timing-based or DNS-exfiltration-based confirmation technique exists; confirmation requires an actual observed callback.
- **Arbitrary brute force** (credentials, tokens, session IDs, resource IDs): not supported anywhere in this codebase, by design: this is a load-bearing safety property, not an oversight.
- **Browser automation**: not supported. No Selenium/Playwright/headless-Chrome integration exists; every request is issued through this project's own bounded `safe_http` client.
- **Multipart form active mutation**: not supported. Only `application/x-www-form-urlencoded` and `application/json` bodies are mutable candidates; multipart (file-upload-shaped) forms are not parsed into mutable candidates at all.
- **GraphQL-variable active mutation**: not supported. `attack_surface.py` recognizes a GraphQL indicator as a discovery signal only; it does not parse or mutate GraphQL query variables.
- **XML active mutation**: not supported. No XML body parsing or mutation exists (and, correspondingly, no XXE detection).
- **CSRF, open redirect, path traversal, command injection, XXE, insecure deserialization**: none of these detector classes exist yet. They remain in `docs/CWE_COVERAGE.md`'s Planned table, not implemented.
- **Crawl-mode IDOR/SSRF findings**: not supported. Both detectors operate on single-page scans only this slice: a crawled page's findings must be attributable to that one page's own URL, and both detectors' resources/candidates are scan-wide rather than page-scoped.

## Finding schema limitations

- **No CVSS score or vector**: absent by design, not partially faked. No detector's evidence currently supports the environmental/temporal context CVSS scoring requires, so no CVSS field exists on `NormalizedFinding` at all: never a fabricated or default-guessed score.
- **No per-finding `finding_id`, `first_seen`/`last_seen`, or structured `scanner_version`/`detector_version`/`scan_id` fields**: findings are currently ephemeral, produced fresh per scan and written into that scan's own report: there is no persisted finding-lifecycle/deduplication store. `scan_id` and detector-version information exist only as free text inside a finding's evidence, not as structured, independently-queryable fields. Building real finding-lifecycle management (matching a finding across scans, tracking its first/last observation) is explicitly a production-phase requirement, not a v1 scanner feature, see `docs/production/INFRASTRUCTURE_REQUIREMENTS.md`.

## Infrastructure/environment limitations

- **Local-only callback receiver**: the SSRF callback receiver (`CallbackHttpReceiver`) binds to a local address only; there is no public, internet-routable callback hostname. This is why SSRF detection could not be fully validated against Juice Shop's own SSRF-challenge protection, which specifically blocks private/internal-looking destinations.
- **No CLI convenience command for the callback receiver**: the component exists and is fully tested, but standing it up currently requires constructing it directly in code (as the E2E tests do), not a `webguard-api callback-server`-style subcommand.
- **In-memory-only authentication contexts, comparison plans, and callback registrations**: none of these survive a process restart or are shared across separate CLI/worker invocations. This is an explicit, repeatedly-reaffirmed design decision (never store raw secrets in SQLite as a stand-in for real KMS-backed storage), not an oversight.
- **SQLite-backed job queue, not a message queue**: worker dispatch uses SQLite leases/polling, not Redis/Celery/RabbitMQ. Functionally complete (lease renewal, crash recovery, cancellation are all implemented and tested) but not the technology a multi-worker, horizontally-scaled production deployment would eventually want.
- **No PostgreSQL, object storage, or KMS integration**: every persistent store is local SQLite or the local filesystem. See `docs/production/INFRASTRUCTURE_REQUIREMENTS.md`.

## Audit-identified gaps (real, not yet closed)

These are genuine gaps this slice's stabilization audit found and did not fix, because fixing them would mean expanding scope beyond auditing (adding a persistent finding store, a version-aware permit loader, a public callback service): each is recorded here explicitly rather than silently left implicit:

- **IPv6 link-local / alternative-IP-representation scope rejection** is proven only by inspection of Python's `ipaddress` module semantics, not by a dedicated named regression test using a literal `fe80::`/octal/decimal address.
- **Truncated/short-read HTTP response handling** has no dedicated error code or test; behavior depends on whatever the standard library's `http.client` does on a dropped connection mid-body.
- **Callback-registration tenant scoping** has no explicit `organization_id`-checked read path (isolation currently rests on token secrecy alone); no operator-facing API exposes a read path today, so this is not currently exploitable, but the invariant itself is untested and inconsistent with every other resource type's scoping pattern.
- **Detector-exception-crashes-the-worker protection** is proven generically (a fake executor raising a raw exception is redacted correctly) but not specifically through a real detector raising mid-execution via the full `_apply_active_detection` → `execute()` call chain.
- **Authentication-context revocation/expiry between permit issuance and job execution**: the executor-level re-validation code exists and is documented, but no test drives a context through exactly that timing window end-to-end.
- **Report-generation/serialization has no cancellation check**: acceptable today since serialization is fast, synchronous, in-memory work, but worth revisiting if report size grows substantially.
- **The IDOR baseline+cross-access loop checks cancellation once per resource pair (4 requests), not once per request**: coarser than every other active detector's per-candidate/per-probe cancellation granularity. A cancellation signal can be "in flight" for up to 4 HTTP requests before it's observed.
