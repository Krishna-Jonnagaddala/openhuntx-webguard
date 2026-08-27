# InternStack — First Production-Style Validation Scan

## Status

Complete. This is OpenHuntX WebGuard's first real-world scan against a live, externally-owned target, performed as the intended end-to-end validation of the authorization → permit-equivalent → scan → report pipeline described in `docs/ROADMAP.md` and `docs/PRODUCT_CHARTER.md`.

This scan used the standalone `webguard` CLI path (self-attested owned-target authorization, ADR-0019), not the full hosted API/TrustScan-permit path (ADR-0021/0026) — the CLI is the currently-implemented mechanism for a single operator running an authorized scan against their own target; the hosted multi-tenant permit system remains the production path described elsewhere in the roadmap.

## Authorization

- **Target (as authorized by the operator):** `https://www.internstack.in/`
- **Canonical target actually scanned:** `https://internstack.in/` — `www.internstack.in` returns an HTTP 308 permanent redirect to the bare apex domain, and WebGuard's safe HTTP client deliberately does not follow redirects (see README, "External execution currently performs no: ... redirect following"). The authorization was re-issued against the canonical apex URL, with `www.internstack.in` recorded as an additional explicitly-authorized host on the same document.
- **Organization:** OpenHuntX / InternStack
- **Authorized by:** Krishna Prasad (operator, in-conversation confirmation: "This is our own website and must be treated as an explicitly authorized target")
- **Authorization ID:** `308dd035-94fb-4aab-87ab-ab86f3014f35`
- **Authorization SHA-256:** `91f4745e72e8e84aba31fbe943f4b5fb2eeaef04f36bfb45b5bb0a233518f5e0`
- **Authorization document:** `authorizations/internstack.json` (not committed — private runtime material per `README.md` "Data handling")
- **Validity:** 2026-08-27T13:37:36Z to 2026-09-26T13:37:36Z (30 days)
- **Scope:** passive-only (`passive_only: true`), no form submission, no JavaScript execution, no active payload injection, no credential attacks, no denial-of-service testing — matching the operator's explicit constraints for this scan.

This authorization is a **locally generated, self-attested document**. Per README ("Safety and authorisation"): it records operator approval and scan limits; it does not independently prove legal ownership of the domain. The operator's affirmative statement in this conversation is the basis for treating this target as authorized. Independent domain-ownership verification (DNS/file-based) is documented as future work in `docs/ROADMAP.md` ("Permission and identity maturity") and was not performed here.

## Scan configuration

| Parameter | Value |
|---|---|
| Engine | `webguard-native` 0.1.0 |
| Modes run | single-page passive, then same-origin passive crawl |
| Crawl limits | max 10 pages, max depth 1, max 50 links/page, ≥1.0s delay between requests |
| Request limits | 10s timeout, 1 attempt (no retries), 1,048,576 byte body cap, 65,536 byte header cap, 100 header count cap |
| Stop conditions | scope/DNS validation failure, redirect response, TLS verification failure, request-attempt budget, execution-time budget, root-request failure, operator interrupt |
| Resolved address | `204.69.207.1` (single public IPv4; validated by `scope_validator.py` as globally routable, non-private/loopback/link-local/multicast/reserved before any request was sent) |

Preflight (`--preflight-only`, zero HTTP requests sent) was run first and returned `approved` before any live traffic occurred.

## Timeline

| Step | Scan ID | Timestamp (UTC) | Result |
|---|---|---|---|
| Preflight-only dry run | — | 2026-08-27T13:37 | Approved, no request sent |
| Single-page passive scan | `c4fba42d-32df-4484-98fc-8d98eba42573` | 2026-08-27T13:37 | Completed, 6 findings |
| Same-origin crawl (max 10 pages) | `211b67c9-d275-4f40-a19f-63aa95626ea7` | 2026-08-27T13:37–13:38 | Completed, 6 findings |

## Coverage

- **Pages discovered / scanned:** 1 of 1 attempted (crawl found 0 same-origin `<a>` links to follow from the root page — WebGuard does not execute JavaScript, so client-side-rendered navigation is not discovered; this is a known, documented limitation, not a scan failure).
- **Requests attempted / succeeded:** 1 / 1 (single-page); 1 / 1 (crawl root page).
- **HTTP status observed:** 200.
- **Checks executed:** 40 of 40 planned (100% coverage) — cookies (8 checks), CORS (5), disclosure (6), security headers (5), HTML security (8), TLS/certificate (8).
- **Errors:** 0 in the completed scans (the first attempt against `www.internstack.in` produced 1 controlled `redirect_blocked` error, by design — see Authorization section above).

## Findings

All 6 findings are passive, evidence-backed, and reproducible from the response headers alone. Independent corroboration via a single manual `curl -I` request against both `https://www.internstack.in/` and `https://internstack.in/` confirmed every finding against the raw HTTP response.

| # | Title | Severity | Confidence | CWE | Informal OWASP Top 10 (2021) mapping* |
|---|---|---|---|---|---|
| 1 | X-Content-Type-Options header missing | Low | Confirmed | CWE-16 | A05:2021 – Security Misconfiguration |
| 2 | Content-Security-Policy header missing | Medium | Confirmed | CWE-693 | A05:2021 – Security Misconfiguration |
| 3 | Clickjacking frame protection missing | Medium | Confirmed | CWE-1021 | A05:2021 – Security Misconfiguration |
| 4 | Referrer-Policy header missing | Low | Confirmed | CWE-200 | A05:2021 – Security Misconfiguration |
| 5 | Cookie Domain attribute broadens host scope | Low | Confirmed | CWE-16 | A05:2021 – Security Misconfiguration |
| 6 | Server header exposes implementation information | Informational | Confirmed | CWE-200 | A05:2021 – Security Misconfiguration |

\* WebGuard does not yet implement OWASP mapping as a first-class, machine-verified finding attribute (tracked in `docs/ROADMAP.md`, "Detection architecture and CWE coverage"). The mapping above was added manually for this report and should not be read as a scanner-generated claim.

### 1–4. Missing security headers (Low/Medium)

**Evidence:** no `X-Content-Type-Options`, `Content-Security-Policy`, `X-Frame-Options`/CSP `frame-ancestors`, or `Referrer-Policy` header was present on the `200` response to `GET https://internstack.in/`. Verified independently: the raw `curl -I` response headers contain none of these four headers.

**Remediation:** add `X-Content-Type-Options: nosniff`; deploy a tested `Content-Security-Policy` (start report-only); add a `frame-ancestors` directive (or `X-Frame-Options` as legacy fallback); set `Referrer-Policy: strict-origin-when-cross-origin` or stricter.

**Not a false positive.** All four are real, currently-missing, low-cost-to-fix hardening headers.

### 5. Cookie Domain attribute broadens host scope (Low)

**Evidence:** the `__cf_bm` cookie is set with `Domain=internstack.in`, converting it from host-only to domain scope (shared with subdomains).

**Attribution note (not a false positive, but not directly application-controlled):** `__cf_bm` is Cloudflare's own bot-management cookie, set by the edge proxy, not by application code. The scanner's observation is technically accurate — the header genuinely broadens cookie scope — but remediation, if desired, is a Cloudflare dashboard/configuration change rather than an application code change. This distinction is recorded here because the finding's remediation text ("Remove the Domain attribute unless deliberately shared") does not by itself convey who controls that decision.

### 6. Server header exposes implementation information (Informational)

**Evidence:** `Server: cloudflare`.

**Assessment:** this discloses only "fronted by Cloudflare," which is extremely common and low information value — it does not reveal application framework, language, or version. Severity is correctly rated Informational. **Effectively not actionable by the operator** for the same reason as finding 5: this header is set by Cloudflare's edge, not the origin application.

### Ancillary manual observation (not a scanner finding)

An `X-Site-Id` response header (a UUID) was observed during independent corroboration. WebGuard's disclosure analyzer does not currently pattern-match this header, so it was not raised as a finding. It is noted here for completeness only — it is a low-confidence, low-severity possible platform fingerprint (looks like a website-builder/hosting-platform identifier) and is explicitly **not confirmed as a security-relevant finding by passive scanning**.

### Positive observations

- TLS/certificate checks (8 of 8) produced no findings: certificate validity, hostname match, chain, cipher, and protocol all passed WebGuard's checks.
- `Strict-Transport-Security: max-age=2628000` is present (no `includeSubDomains` or `preload`, but WebGuard's current HSTS check does not flag partial HSTS configuration as a finding — this is a scanner coverage gap, not a false negative claim; recorded under Limitations below).
- No CORS misconfiguration, HTML-security, or information-disclosure findings beyond the Server header.

## False-positive review

All 6 findings were reviewed against the raw response captured independently via `curl -I`. **Zero false positives** — every finding corresponds to a header genuinely absent or a cookie attribute genuinely present in the live response. Two findings (5 and 6) carry an attribution caveat (Cloudflare-controlled, not application-controlled) rather than being incorrect.

## Limitations

- **No JavaScript execution.** If `internstack.in` is a client-rendered SPA, only the initial server-rendered HTML was analyzed; client-side routes/links were not discovered.
- **No active testing.** No injection, authentication, SSRF, CSRF, or other active checks were run — WebGuard's active-detection engine does not exist yet (see `docs/CWE_COVERAGE.md`, "Planned"). This scan validates the **passive** engine only.
- **Partial HSTS not flagged.** WebGuard currently only checks for HSTS presence, not `includeSubDomains`/`preload` completeness — a coverage gap, not a finding suppressed.
- **Single page reached.** Crawl mode discovered 0 same-origin links from the root page in this run, so coverage is effectively single-page despite crawl mode being used.
- **Self-attested authorization only.** No independent domain-ownership proof (DNS TXT, well-known file) was performed; see Authorization section.

## Conclusion

This is a genuine, reproducible end-to-end validation: authorization → preflight → scoped/DNS-validated request → passive analysis → evidence-backed findings → rendered report, all against a live external target, with zero false positives on manual review. The scanner behaved exactly as designed, including correctly refusing to follow the `www` → apex redirect rather than silently working around its own safety control.

Artifacts (not committed — see `README.md` "Data handling"):
- `authorizations/internstack.json`
- `scan-results/internstack-single-page.json`, `scan-results/internstack-single-page-audit.json`
- `scan-results/internstack-crawl.json`, `scan-results/internstack-crawl-audit.json`
- `scan-results/internstack-report.html`
