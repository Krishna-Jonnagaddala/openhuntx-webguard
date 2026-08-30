# OpenHuntX WebGuard — Full System Audit (2026-08)

## EXECUTIVE VERDICT

The core product — permit-gated passive/active scanning, TrustScan cryptographic authorization, customer identity/RBAC, tenant isolation for primary resources, PostgreSQL persistence, and reporting — is real, substantially implemented, and considerably better-tested than a surface read of this repository's own stale top-level documentation (`README.md`, `docs/audit/production-gap-matrix.md`) would suggest. Every claim in this report was independently re-derived from source and, wherever practical, from live execution against real PostgreSQL, real Docker fixtures, and the real running application — not from trusting prior slice reports, which this audit's brief correctly warned against doing.

Two **P0** defects were found, one of them already self-disclosed by the project's own most recent audit doc and one newly discovered this pass:

1. **The SSRF-callback detector is non-functional in production** — confirmed by live reproduction against canonical HEAD (a real permit + real job + real worker through the real `build_production_components()` object graph): the job fails with a generic `worker_internal_error`. Root cause confirmed precisely (an `AttributeError` inside `ScanJobExecutor._apply_ssrf_callback_detection`). This was already known and tracked (`task_60b526a4`, a separate session actively working on it, uncommitted as of this audit); this audit independently re-confirms it is **still present on canonical HEAD** and adds new evidence: the underlying Postgres-backed cross-process *data layer* (register in one OS process → HTTP hit from a second, genuinely separate OS process → observation visible from a third, independent connection) **was proven to work** in isolation. The break is specifically in the executor's object-wiring, not in the underlying architecture.
2. **The standalone `signing-service` process has no fail-closed environment gate and defaults to a hardcoded development Ed25519 key.** Unlike `serve`/`worker`/`scheduler`, which all refuse to start without `WEBGUARD_ENVIRONMENT=production` and 17 other required variables, `webguard-api signing-service` accepts no environment flag at all; `--key-source` defaults to `"development"`, and running it with only its one required variable set (a bearer token) **starts and listens successfully** using a fixed, source-visible 32-byte key. Verified by actually running the command this audit pass.

Beyond these two, the audit found a genuinely strong core: TrustScan permit authorization is proven to re-validate at execution time (not just submission) via a real code path exercised by 155 passing tests this session; the primary tenant-scoped resources (targets, jobs, scans, findings, schedules, reports, callback registrations) are SQL-scoped and independently proven cross-tenant-safe against real PostgreSQL; customer authentication (Argon2id, CSPRNG tokens, CSRF, cookie flags, session/API-token separation) is thorough and correct with only two low-severity timing side-channels; the IDOR detector was specifically re-verified, line by line, to confirm the previously-removed response-length heuristic has **not** been reintroduced; and the frontend has no injection, credential-leakage, or tenant-spoofing surface.

The most consequential finding for a launch decision is not any single defect but a pattern: **this codebase's own newest documentation (the Slice 12-18 production/audit docs) is unusually honest, precise, and self-critical — but the repository's oldest, most prominent documents (`README.md`, `docs/audit/production-gap-matrix.md`) were never updated across that entire body of work and now materially understate what has been built.** A reviewer who trusted `README.md` alone would wrongly conclude PostgreSQL, customer identity, object storage, and transactional email are all still "NOT STARTED."

**Nothing in this system has been deployed anywhere.** No CloudHSM cluster, no Cloudflare account, no DNS zone, no applied Terraform state, and no cloud-hosted database exist. This audit found no evidence contradicting that; where a prior document claimed otherwise it was corrected here.

## CURRENT HEAD

```
f3f2ece63db173f286be330d0ac2b0f582748778
```
Branch `main`, remote `git@github.com:Krishna-Jonnagaddala/openhuntx-webguard.git`, `HEAD == origin/main` confirmed at the start and re-confirmed at the end of this audit. Working tree was clean throughout (`git status --short` empty before, during, and after every investigation and live test in this pass — no product file was ever edited). One additional git worktree exists at `.claude/worktrees/youthful-cray-e5ffee` (branch `claude/youthful-cray-e5ffee`), a separate, independently-running session's workspace for the already-tracked SSRF-callback fix (`task_60b526a4`) — its tip is `aa0774f` (Slice 17), no commits ahead of that, with real uncommitted work-in-progress touching `executor.py`, `postgres_callback_service.py`, `production_startup.py`, `cli.py`, a new `postgres_callback_broker.py`, and a new test file. This worktree was **not** used for this audit; every finding here is against canonical `main` only, per the brief's explicit instruction not to assume that separate session has already fixed anything. `.claude/` and `Breach/` were both confirmed gitignored and untouched throughout (`git ls-files` returns nothing for either).

## AUDIT SCOPE

Every major subsystem named in the brief: architecture/production wiring, the full production execution path, TrustScan permit authorization, the signing architecture (KMS/CloudHSM/signing-service), the SSRF-callback architecture, Scanner v1 (all detectors + network safety), customer authentication/RBAC, tenant isolation across every tenant-owned resource, PostgreSQL/migrations/transactions/concurrency, findings/evidence, reports/object storage, email, the full frontend, the brand integration, the complete `/v1` API surface, the CLI, the environment-variable configuration matrix, secrets/crypto, Terraform/infrastructure, Cloudflare/edge, CI/CD, dependency/supply-chain pins, the test suite, observability, backup/DR, RLS, and the Redis decision.

## AUDIT METHODOLOGY

This audit combined two complementary methods, run in parallel where safe:

1. **Eight parallel, investigation-only sub-audits** (read-only; explicitly instructed not to edit any file, not to run git write commands, and not to start Docker containers to avoid colliding with this session's own live testing), each covering a cluster of related subsystems, each required to cite exact `file:line` evidence for every claim and to run real tests where possible rather than trust prior self-reports. Every sub-audit's raw findings are folded into the sections below; nothing was accepted without independent verification against the actual current source.
2. **Direct live execution by the audit lead** (this session) of everything requiring real infrastructure or process boundaries the parallel sub-audits could not safely exercise concurrently: `terraform fmt`/`init`/`validate` plus a full Trivy IaC security scan; the complete backend unit/contract/integration suite against a real disposable PostgreSQL and a real disposable Juice Shop container (fresh, this session); a full frontend build/lint/typecheck/Vitest/Playwright run against a real Postgres-backed API (fresh, this session); the official secret scan, Ruff security checks, dependency audit, supply-chain-pin verification, and governance-doc verification; a genuine cross-process reproduction of the SSRF-callback path, including starting `webguard-api callback-service` as an actual separate OS process; direct repository-layer tenant-isolation probes bypassing the service layer; a live migration checksum-drift test (simulated and then restored, never touching the migration file itself); and a live migration idempotency check (re-running the migration tool against an up-to-date schema).

No product code was modified at any point. No infrastructure was provisioned or applied. No public target was scanned; every live test used controlled local fixtures (a purpose-built loopback HTTP server, the authorized-lab Juice Shop container, or the repository's own test/dev database).

## ARCHITECTURE ACTUALLY OBSERVED

Built from real imports/constructors, not from `ARCHITECTURE.md`'s own prose.

**CLI entry points** (`cli.py`, 15 subcommands): only `serve`, `worker`, `scheduler` accept `--environment`; `signing-service` and `callback-service` gate on their own required variables with no environment concept at all (this asymmetry is the root of P0-2); the remaining 10 subcommands (`init`, `bootstrap`, `organization create`, `principal create`, `token create/revoke`, `authorization assign`, `permit issue`, `authentication-context register`, `authorization-comparison register/revoke`) are either permanently local-SQLite (the first 6 — see CLI section) or genuinely share `service.py`'s RBAC/audit logic with the HTTP API (the last 3, confirmed by direct code trace).

**`build_production_components()`** (`production_startup.py`) is called from exactly one non-test site (`cli.py`'s `_production_components()`, itself gated on `Environment.PRODUCTION`). It constructs, unconditionally: `PostgresIdentityRepository`, `PostgresTargetRepository`, `PostgresTargetVerificationRepository`, `PostgresJobRepository`, `PostgresScanRepository`, `PostgresFindingRepository`, `PostgresCallbackRegistrationRepository`, `PostgresAuthenticationContextRepository`, `PostgresAuthorizationComparisonPlanRepository`, `PostgresReportRepository`, `PostgresSessionRepository`, `PostgresAuthRateLimiter`, `ProductionMailProvider`(Postmark), `ObjectStorageArtifactStore`(S3/SSE-KMS), and a `TrustScanSigner` over either `KmsSigningProvider` or `SigningServiceClient`. `AuthorizationRepository` remains local-filesystem in every environment, unchanged and deliberate. Every parameter with an in-memory/local-dev default in `WebGuardJobService`/`ScanJobExecutor` is confirmed explicitly overridden with a real backend in production — **no silent SQLite/in-memory/dev-mail/dev-signer fallback exists inside `build_production_components()` itself.** The one real silent-dev-fallback in the whole system lives outside it, in the standalone `signing-service` subcommand (P0-2).

**`Environment` enum** has 4 values (`DEVELOPMENT`, `TEST`, `LAB`, `PRODUCTION`); only `PRODUCTION` is ever checked anywhere in the codebase. `TEST` and `LAB` are dead values, byte-for-byte identical to `DEVELOPMENT` in effect — a real, if low-severity, operator-facing footgun (P3).

## PRODUCTION RUNTIME TRACE

Every transition in the full chain (browser → auth → session → RBAC → asset → ownership verification → authorization → permit → signing → job → worker claim/lease → scanner/crawler/detector → finding → persistence → retrieval → lifecycle → report → object storage → download → audit) was traced against real code and, for the majority, against real passing tests through the production component graph. Verdict per transition:

| Transition | Verdict | Notes |
|---|---|---|
| Auth (login) | PARTIAL | Logic is correct and unit-tested; no test drives a real `POST /v1/auth/login` HTTP call through `build_production_components`'s actual object graph (existing production E2E tests bootstrap identities directly, bypassing the HTTP registration/login routes) |
| Session → RBAC | PASS | Identical `AuthContext` shape for both credential kinds; 4-role permission table read and confirmed coherent |
| Asset + ownership verification | PASS | `check_asset_verification` is the only path that can set `status=verified`, via a real server-side fetch |
| Authorization binding | PASS | Postgres-gated before the filesystem authorization document is even consulted |
| Permit issuance + signing | PASS (kms path); NOT_PROVEN (cloudhsm path against real hardware) | See TRUSTSCAN/SIGNING sections |
| Job submission | PASS | Idempotency key rehashed to a tenant-scoped digest before storage; cross-tenant idempotency collision structurally impossible |
| Worker claim/lease | PASS | `FOR UPDATE SKIP LOCKED` + optimistic revision CAS, proven race-free live this session (see POSTGRESQL section); crash containment via a blanket exception handler confirmed (this is also what silently swallows the SSRF-callback crash) |
| Executor → detectors → finding | PASS (passive, XSS, SQLi, IDOR-comparison); **FAIL** (SSRF-callback, P0-1) | Finding persistence via atomic `INSERT ... ON CONFLICT`, confirmed |
| Finding retrieval/lifecycle | PASS | Client can never reach `REOPENED`; evidence/CWE/severity/confidence never client-writable |
| Report → object storage → download | PASS | Checksum computed from real bytes, **re-verified** before every download, fails closed on mismatch |
| Audit logging | PASS | Every mutation audited; schema structurally cannot carry a secret (no free-form body field exists on `SecurityAuditEvent`) |

## SCANNER V1

**Verdict: PASS**, comprehensively. All ten detector/support families (passive checks, reflected XSS/CWE-79, SQLi/CWE-89, IDOR-BOLA/CWE-639, SSRF/CWE-918, authenticated scanning, attack-surface discovery, request templates, scope enforcement, evidence sanitization) were read in full and independently verified against their own confirmation logic, negative-fixture tests, and real-socket integration tests.

**The specific regression this audit was tasked to check for — IDOR's response-length heuristic — was confirmed absent, quoted line-by-line from `idor_authorization_detector.py`'s `_classify()`.** `response_length` is captured as audit metadata on the observation record but is never read inside the classification branches; the only signal that reaches `CONFIRMED` is an exact SHA-256 content-fingerprint match against the victim's own baseline response. A purpose-built regression-guard unit test (`test_marker_match_without_exact_fingerprint_is_probable`) exists specifically to keep this from silently regressing, and the detector is separately proven against a live OWASP Juice Shop BOLA challenge.

**Network safety (`safe_http.py`)**: a repo-wide grep for direct `requests.`/`httpx.`/`urllib.`/`socket.`/`http.client.` usage outside `safe_http.py` found **zero instances of scanner traffic bypassing it** — every non-`safe_http.py` HTTP call site is either vendor/infrastructure traffic to a hardcoded or operator-configured host (Postmark, the signing service) or the one sanctioned DNS-resolution call `safe_http.py`'s connection layer consumes without re-resolving (deliberately pinning the connection to prevent a DNS-rebinding TOCTOU window, which is the *stronger* mitigation, not a weaker one). One minor finding: no explicit port restriction exists for commercial-mode targets (P3, low impact given every target must also be an operator-registered, authorization-bound URL).

## TRUSTSCAN

**Verdict: PASS** for the authorization chain; **PARTIAL** for signing (see next section).

The permit schema, every binding check (target/organization/authorization/mode/fingerprint), and — the central question — **execution-time re-validation** were all confirmed via direct code trace and 155 tests run for real this session, all passing (`test_active_checks_cli.py`, the core permit/signing/safety suite, and the tamper/cross-tenant/active-checks/CloudHSM suite). Re-validation happens **twice**: once at the start of `execute()` (re-fetching the permit fresh, not trusting the binding taken at claim time) and again, unconditionally, **before every single outbound HTTP request** via `TrustScanRuntimeSafetyEngine`'s `revalidate_runtime_permission()` hook — confirmed by reading the exact closure and its call site in `safety.py`'s `before_request()`. Tampered signatures, tampered claims (org/target/mode/budget/authorization-id/fingerprint), expired permits, revoked permits, wrong-target permits, and unknown/disabled signing keys are all independently proven rejected, live, this session.

Two new defects were found in this area, neither previously documented:
- A stale docstring in `signing.py` claims `KmsSigningProvider` is "never wired as TrustScan's active signer" — directly contradicted by `production_startup.py`, which does exactly that whenever `signing_provider=kms` (a real, reachable, config-selectable production path).
- `TrustScanSigner.sign()`/`sign_safety_receipt()` unconditionally hardcode `signature_algorithm="Ed25519"` regardless of which provider actually signed the document — if the `kms` production path is ever selected, a permit would self-report `Ed25519` while its bytes are actually ECDSA-signed. Verification itself is not fooled (it resolves the algorithm from the registry by key ID, never from this self-reported field), so this is a data-integrity/interop defect, not an authorization bypass — but no test in the repository exercises `sign()` against a KMS-backed registry and inspects the resulting document, which is exactly the gap that let it go unnoticed.

## SIGNING

**Verdict: IMPLEMENTED + TEST-HARNESS-PROVEN** for the full CloudHSM-signing-service architecture (`CloudHsmSigningProvider`, the dedicated 3-endpoint `TrustScan Signing Service`, `SigningServiceClient`/`SigningServiceHttpClient`, key lifecycle). **NOT_PROVEN against real hardware anywhere in this repository or its documentation** — confirmed by an exhaustive search of every doc mentioning CloudHSM; every one is explicit and consistent that no real cluster has ever been used. The `EC_POINT` PKCS#11 encoding assumption remains explicitly, honestly marked unverified in the code itself, not silently upgraded.

**Process isolation is real, confirmed by direct trace**: the only call site in the entire repository that imports `pkcs11` is inside the standalone `signing-service --key-source cloudhsm` subcommand; `serve`/`worker`/`scheduler` never import it and never hold a PKCS#11 session.

**P0-2 lives here**: running `webguard-api signing-service` with only its bearer token set — no `--key-source`, no environment gate of any kind — succeeds and listens, using `LocalDevelopmentSigner` with a fixed, source-visible key. This was actually run and confirmed this session (then killed immediately). Contrast with `serve`/`worker`/`scheduler`'s genuinely strict fail-closed gate (independently confirmed by actually running all three with required variables unset — all failed in under a second with a clear coded error, no listening socket, no hang).

## CALLBACK / SSRF

**Verdict: FAIL for the integrated production path (P0-1); PASS for the underlying cross-process data mechanism in isolation.** This is the audit's highest-priority section and received the most direct, hands-on verification.

**The break, reproduced live against canonical HEAD this session**: a real organization was bootstrapped through `build_production_components()` (the exact object graph `webguard-api serve`/`worker` construct), a real TLS-fronted local fixture was stood up, a real permit with `active_checks: ["active.ssrf.callback"]` was issued and signed, a real job was submitted, and a real worker thread claimed and executed it. Result:
```json
{
  "state": "failed",
  "error": {"code": "worker_internal_error", "message": "The scanner worker encountered an unexpected internal error."}
}
```
Root cause, reconfirmed live this session (not merely cited from a prior report): `hasattr(PostgresCallbackRegistrationRepository, "policy")` → `False`; `hasattr(..., "wait_for_observation")` → `False`; `register()`'s return type (`ScopedCallbackRegistration`) has no `.url` field. `executor.py:874` (`callback_policy=callback_repository.policy`) is evaluated before any HTTP request is even made, so the crash is deterministic and immediate whenever a permit requests this check. `worker.py`'s blanket exception handler swallows it with **zero log line, zero stack trace, anywhere** — the only trace an operator would have is a generic `worker_internal_error` code on the job row (this silent-swallowing is itself flagged separately under OBSERVABILITY).

**What this audit newly proved beyond the already-known crash**: the underlying cross-process correlation mechanism the Slice-18 architecture is *supposed* to provide genuinely works when exercised directly. A token was registered in one Python process (PID A), a real HTTP request was sent from that same process to a genuinely separate OS process (`webguard-api callback-service`, started independently, a different PID entirely, already running for several minutes), and the resulting observation was confirmed visible from a **third**, independent Postgres connection pool — proving registration → cross-process HTTP delivery → durable, cross-connection-visible persistence all work correctly via Postgres as the shared medium. **The break is entirely in `ScanJobExecutor`'s object-wiring** (it hands the executor a durable-metadata repository where a live, `.url`-producing, `wait_for_observation`-capable broker is expected), not in the callback service, not in the receiver, not in Postgres, and not in the detector's own logic (independently confirmed correct by the Scanner v1 audit stream).

Every other named property was confirmed at the code level: high-entropy tokens (`secrets.token_urlsafe(32)`), TTL-bounded registrations, organization/job/permit binding on every registration row, bounded observation storage, a real per-source-IP rate limiter added this project's own Slice 18 (confirmed present, unchanged), and no internal-network-pivoting surface (the receiver only ever records a token hit, never proxies or relays anything). Per the brief's explicit instruction, this was **not fixed** in this audit pass — the correct fix needs new cross-process `wait_for_observation()` design work, already flagged as `task_60b526a4`, already being worked on in an isolated worktree with no committed progress as of this audit.

## CUSTOMER AUTH

**Verdict: PASS**, with two low-severity findings. Argon2id parameters (time_cost=3, memory_cost=64MiB, parallelism=4) match RFC 9106's recommended profile. Every token class (session, CSRF, API token, identity/reset/verification/invitation tokens, callback tokens) uses `secrets.token_urlsafe(32)` — confirmed via a repo-wide sweep that the non-cryptographic `random` module is never used anywhere security-relevant in the entire codebase. Session and API-token credentials are hashed at rest (scrypt), never stored raw, and structurally cannot be confused for each other (distinct prefixes, distinct parsers). CSRF is a genuine double-submit check (hashed comparison, not "cookie present"), applied uniformly to every state-changing verb. Cookie flags are correct and defaulted safely (`Secure` on by default, `HttpOnly` on the session cookie, deliberately off the CSRF cookie, `SameSite=Lax`, host-only). Trusted-proxy IP resolution only honors forwarding headers from a configured, default-empty CIDR set. CORS never echoes a wildcard for credentialed requests. Frontend token storage was independently re-swept: **zero** occurrences of a session/CSRF/API-token value in `localStorage`/`sessionStorage`/`IndexedDB` anywhere in the SPA source.

Two real, previously-undocumented findings: a timing side-channel on `/v1/auth/login` (the unknown-email path returns before the Argon2id verify a wrong-password path pays for), and a larger one on `/v1/auth/password/reset/request` (the existing-account path makes a synchronous outbound Postmark call, including a 0.5s retry sleep on transient failure, before responding — a substantially more exploitable enumeration oracle than the login one). Both are content-level anti-enumeration-correct (identical response bodies/codes) but not timing-constant.

## RBAC

Folded into CUSTOMER AUTH and API sections above — the 4-role permission table (`OWNER`/`ADMINISTRATOR`/`ANALYST`/`VIEWER`) was read in full and cross-checked against every route in the API table below; no route was found missing an RBAC check it should have. `PERMIT_ISSUE_ACTIVE`/`AUTHENTICATION_CONTEXT_*`/`AUTHORIZATION_COMPARISON_*` are deliberately withheld from `ADMINISTRATOR`, confirmed. Two dead `ApiPermission` enum members (`IDENTITY_MANAGE`, `AUTHORIZATION_ASSIGN`) exist but are never checked anywhere — P3.

## TENANT ISOLATION

**Verdict: PARTIAL.** The primary, client-reachable resources — targets, target verifications, scans, findings, schedules, reports, callback registrations, and the identity/audit tables' client-facing accessors — are consistently `organization_id`-scoped directly in SQL, and a substantial live-Postgres cross-tenant test suite already exists (`tests/integration/test_postgres_tenant_isolation_slice13.py`) proving fail-closed behavior for jobs, scans, findings, schedules, authentication-context/comparison-plan *binding checks*, and reports.

The real gap, found by static analysis and **then independently confirmed live this session** by calling the raw repository methods directly (bypassing `service.py` entirely, as a future caller that skipped the service-layer guard would): three repository classes have **zero tenant/principal predicate at the SQL layer**:

- `PostgresAuthenticationContextRepository.get_metadata()`/`.revoke()`
- `PostgresAuthorizationComparisonPlanRepository.get()`/`.revoke()`
- `PostgresSessionRepository.get_session()`/`.revoke_session()`

Live reproduction: organization A's authentication context, comparison plan, and browser session were each created, then read and revoked by calling the bare repository method as "organization B" (i.e. with no B-side credential or org check performed by the method itself) — **every one succeeded.** This is not exploitable via the HTTP API today (every real caller of these methods, in `service.py`, correctly checks `record.organization_id != caller's organization_id` *before* calling them), but it means tenant isolation for these three resource classes exists entirely as *convention* one layer up, with no independent backstop if a future code path — a new admin tool, a bug in a refactor, a second caller — ever skips that check.

RLS, the defense-in-depth layer that would close this class of gap structurally, remains **STILL BLOCKED** (see RLS section) — confirmed independently this audit, not merely inherited from a prior report.

Secondary finding: `revoke_token(token_id)` on the identity repository has no owner check in its SQL either, but its only call site is the operator-only local `token revoke` CLI command, not the HTTP API — flagged for completeness, not treated as a live gap.

## POSTGRESQL

**Verdict: PASS.** All 11 migrations were read in order; every tenant-owned table carries an `organization_id` foreign key with a covering index; the append-only `finding_events` audit table has zero UPDATE/DELETE statements anywhere in application code (confirmed by grep); the dedup key (`organization_id`, `fingerprint`) on `findings` is enforced by a single atomic `INSERT ... ON CONFLICT`, not a check-then-insert race.

Two properties were **independently proven live this session**, not merely cited:
- **Idempotency**: re-running `scripts/run-postgres-migrations.py` against an up-to-date database reports "Database schema is already up to date" and makes no changes.
- **Checksum-drift detection**: the tracked checksum for migration `0001` was deliberately corrupted in the tracking table (never touching the actual migration file), and the runner immediately refused with `Migration failed: migration 0001_identity.sql has changed on disk since it was applied` — fails closed exactly as documented. The test database was restored to its correct state immediately after.

One genuinely orphaned table was found and honestly disclosed in its own migration comment (`crawl_checkpoints` — zero code references anywhere, self-labeled as a placeholder). One migration comment is stale (claims `target_verifications` has "no Python repository consumer yet"; it has been fully wired since Slice 15) — documentation drift only, P3.

## MIGRATIONS

Covered above. No down-migration/rollback mechanism exists (forward-only by design, consistent with the project's append-only philosophy elsewhere). No `ON DELETE CASCADE` exists anywhere in the schema, and the application has no organization-deletion code path at all — meaning there is currently no way to actually offboard/erase a tenant's data (a real product/compliance gap, distinct from a tenant-isolation defect — the default `NO ACTION` FK behavior fails safe rather than silently cascading).

## TRANSACTIONS / CONCURRENCY

**Verdict: PASS for what's tested; PARTIAL overall.** `PostgresJobRepository.claim_next_leased()`'s `SELECT ... FOR UPDATE SKIP LOCKED` + optimistic-revision-CAS pattern was re-confirmed by direct code read and by the existing concurrent-claim contract test (10 threads racing 3 claimable jobs → exactly 3 distinct winners), re-run live this session as part of the full contract suite (59/59 passing). Schedule-duplicate prevention (`enqueue_due_schedule`) uses the identical row-lock-plus-CAS pattern plus a database-level unique constraint as a second, independent layer — verified in code.

**The one real, honestly-namable gap**: "job recovery after a worker crash" is proven, thoroughly, against the **SQLite** backend (`test_job_leases.py` and four other dedicated test files) — but **no test in this repository exercises `PostgresJobRepository.recover_expired_leases()` under a simulated crash against real PostgreSQL.** The "crash-consistency" table in `docs/audit/production-platform-phase3-runtime-completion.md` is a reasoning artifact, not a report of an executed Postgres test — this distinction matters for a launch decision, since the SQLite-proven guarantee and the Postgres-implemented-but-unproven guarantee are not the same evidence.

## SCHEDULER

Duplicate-occurrence prevention is fully solved by PostgreSQL alone (row lock + revision CAS + unique idempotency-key constraint), verified in code this session. True leader election (exactly one scheduler process owning dispatch, vs. today's "any number may safely collide") remains honestly unsolved and undocumented as anything but a future concern — no code depends on it existing.

## FINDINGS / EVIDENCE

**Verdict: PASS**, and this was the single strongest area of the entire audit for defense-in-depth discipline. Confidence and status are structurally independent (confirmed: a re-detection's confidence update never touches status; a client's status update never touches evidence/CWE/severity/confidence). `REOPENED` is reachable **only** via scanner re-detection (one `CASE` clause inside the atomic upsert) — confirmed both at the domain-transition-graph level and independently at the client-facing API's own input-validation layer, which rejects any client-submitted status outside `{CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK, RESOLVED}` before it ever reaches the transition check.

A dedicated secret-leakage sweep across every evidence-construction site (XSS, SQLi, IDOR, disclosure, cookies, headers) found **no counter-example**: every detector deliberately omits raw response bodies, cookie values, header values, and credential material from evidence, several with explicit "value was not retained" text baked into the evidence string itself. `AuthenticationMaterial`'s `__repr__`/`__str__` are hard-overridden to redact credential fields as defense-in-depth against accidental logging. Database-driver error normalization explicitly, deliberately never surfaces raw exception text (which could contain SQL or connection parameters).

## REPORTS / S3

**Verdict: PASS.** Object keys are server-generated only (never client-suppliable); download requires a tenant-ownership check *before* the byte fetch, not after; the checksum is computed from real bytes at creation and **re-verified against the persisted value on every download**, failing closed (500, not corrupted bytes) on mismatch; `build_production_components()` never constructs `LocalArtifactStore`, confirmed by grep. SSE-KMS is always explicitly requested, never SSE-S3 default.

One disclosed, honestly-documented gap with an undocumented practical consequence: TrustScan safety receipts and authorization-audit files remain local-filesystem-only even in production (never routed through the S3-backed `ArtifactStore`), and **no compute/EFS resource of any kind exists anywhere in this repository's Terraform** — so whether `WEBGUARD_ARTIFACT_DIRECTORY` would sit on durable or ephemeral storage in any real deployment is currently unspecified by the codebase itself. Neither file is downloadable via any API route regardless.

## EMAIL

**Verdict: PASS.** Production cannot select `DevelopmentMailProvider` (confirmed by config validation + grep of `build_production_components`). Tokens are never logged in production (only the explicitly-dev-only `DevelopmentMailProvider` logs full bodies, by design, for local testing). Passwords and session/API tokens are never emailed. Vendor error text is never surfaced to a client. Email-link base URLs come from validated server configuration, never a request `Host` header — no header-injection risk. Anti-enumeration response-shape parity is correct; the timing-side-channel caveat is covered under CUSTOMER AUTH.

## API

Full `/v1` route table was built by reading `http_api.py`'s complete dispatch and cross-referenced against `service.py`'s RBAC checks — see the sub-audit's detailed table (52 routes enumerated). Global properties confirmed uniform across every route: fixed security headers, origin-allowlisted CORS never wildcarded for credentialed requests, `Content-Length`+size-cap enforcement on every JSON body, rate limiting applied inside `_authenticate()` before any credential-secret comparison runs. No route was found trusting a client-supplied `organization_id` in place of the session's own. No duplicate/overlapping route definitions found. No orphan or debug route found. Four routes (`POST /v1/authentication-contexts` and its revoke, `POST /v1/authorization-comparisons` and its revoke) have real service-layer test coverage but **zero HTTP-transport-level test** — a coverage gap, not a confirmed defect.

## CLI

**Verdict: mixed by design.** `permit issue`, `authentication-context register`, and `authorization-comparison register`/`revoke` genuinely share `service.py`'s RBAC/audit logic with the HTTP API — confirmed by direct trace, not merely by docstring claim. Six other subcommands (`bootstrap`, `organization create`, `principal create`, `token create`/`revoke`, `authorization assign`) perform **zero authentication and zero RBAC check** — they call the identity/authorization repositories directly. This is architecturally defensible (an RBAC-gated system needs *some* out-of-band bootstrap mechanism to create its first owner), but it means anyone who can execute these commands against the production database can mint an arbitrary owner-role principal for any organization, with **no audit trail** (none of the six call `service._audit(...)`). This should be explicitly documented as a break-glass, infrastructure-access-controlled surface — it does not currently appear to be documented as such anywhere in the repository.

## FRONTEND

**Verdict: PASS.** All 16 pages plus routing/auth-gating were read in full. Every route requiring authentication is genuinely gated; the backend contract (every `api.ts` call site) was cross-checked path-and-verb-exact against the real `http_api.py` dispatch with no drift found; no client-editable `organization_id` exists anywhere in a request body; no `dangerouslySetInnerHTML`; no leaked internal/developer terminology in user-visible strings; the one intentional one-time-secret-reveal (a freshly-issued API key) is correctly scoped and never re-displayed. The only findings are UX-only: a few pages render write-action buttons/links to roles that will receive a 403 from the (correctly enforcing) server rather than pre-checking role client-side, and one dead unused export.

## BRANDING

**Verdict: PASS.** `Brand.tsx` remains the single, unduplicated seam every consuming page imports from — confirmed no inline SVG logo exists anywhere else in the frontend source. The favicon uses identical gradient IDs/paths/colors to the in-app mark, not a stale asset. All three brand fonts (Aldrich, Archivo, IBM Plex Mono) are self-hosted `.woff2` files wired via matching `@font-face` rules — no Google Fonts or other external runtime dependency; confirmed no lingering reference to the previously-specified-but-never-loaded "Inter"/"JetBrains Mono" typefaces anywhere in current source. No accessibility regression was introduced (the mark is `aria-hidden`, real text carries the wordmark's semantic content via `background-clip: text` on genuine DOM text, not an image).

## CONFIGURATION

A complete environment-variable matrix was built (component, required-in-prod, secret-shaped, default, validated, documented) covering all ~40 variables read anywhere in the codebase. `ProductionServiceConfig.from_environment()` is confirmed the sole, well-defined seam for the 19 production-required variables; no stray/duplicate env-var reader exists outside five well-defined files. No accidentally-hardcoded credential, domain, or region string was found outside the deliberate, documented loopback-enforcement default.

Real findings: `WEBGUARD_KMS_KEY_ID` is required unconditionally even when the CloudHSM signing path (which doesn't use it) is selected, undocumented as such; `WEBGUARD_CALLBACK_SERVICE_HOSTNAME` is validated at startup but never consumed anywhere else in the codebase (already self-disclosed in `CALLBACK_SERVICE_DEPLOYMENT.md`, tracked as `task_60b526a4`); a local dev-convenience script prints the wrong frontend env-var name (`VITE_WEBGUARD_API_BASE_URL` — no code reads this; only `VITE_API_BASE_URL` exists) — following the script's own printed instructions would silently fail to connect the frontend to the backend it just started; no single document enumerates all 19 required production variables by exact name, meaning a first-time operator must read `production_config.py` source directly; several `int()`/`ipaddress.ip_network()` conversions in `cli.py` for secondary (non-`ProductionServiceConfig`) variables are unguarded and would crash with a raw traceback rather than this codebase's own established coded-error convention.

## CRYPTO / SECRETS

**Verdict: PASS.** The official secret scanner was run for real this session (`467 repository files, 6 generated artifact files, 1003 reachable Git blobs — clean`), and re-run again after every subsequent round of live testing in this audit, always clean. Every token/key/salt generation site across the codebase (sessions, API tokens, identity tokens, callback tokens) uses `secrets.token_urlsafe`/`secrets.token_bytes` — a repo-wide sweep found **zero** use of the non-cryptographic `random` module anywhere security-relevant, and zero `Math.random()` in the frontend. No hand-rolled cryptographic primitive exists anywhere; every crypto operation resolves to `cryptography`, `argon2-cffi`, or stdlib `hashlib`/`hmac`/`secrets`/`ssl`. Cursor signing is genuine HMAC-SHA256 with constant-time comparison and a ≥32-byte enforced key.

## INFRASTRUCTURE

**Status: CODE VALIDATED only.** `terraform fmt -check`, `terraform init -backend=false`, and `terraform validate` all ran clean this session against every `.tf` file, and a full Trivy IaC security scan (all severities) returned **zero findings**. No `terraform plan` was run (would require real cloud credentials this environment does not have and this audit was instructed not to obtain), no `apply` was run, and **no actual cloud resource of any kind exists** — RDS, S3, KMS, VPC, CloudHSM, Cloudflare zone: none of it has ever been provisioned. These four states (code validated / provider plan validated / actually applied / actual cloud resource verified) must not be conflated, per the brief's own instruction, and this audit found nothing beyond the first.

**One genuine, newly-found supply-chain gap**: `infra/terraform/.terraform.lock.hcl` — the Terraform equivalent of a package-lock file, meant to pin exact resolved provider versions/hashes — is explicitly **gitignored**, not committed. This directly contradicts the project's own `ADR 0028` "reproducible CI and supply-chain pins" discipline, which is otherwise followed scrupulously everywhere else in the repository (exact Python hash locks, exact GitHub Action commit SHAs, exact Docker image digests). Every fresh `terraform init` — including the CI job this project's own prior slice added — currently re-resolves providers within their loose version-range constraints rather than to a reviewed, pinned hash.

The Terraform itself, reviewed: RDS is private, encrypted, deletion-protected by default, with a dedicated CMK and IAM-auth capability enabled (additive, doesn't replace password auth); S3 has full public-access blocking, a policy-level deny on insecure/unencrypted writes, versioning, and lifecycle rules; the VPC has no public subnets/NAT/IGW at all (nothing provisioned needs outbound internet); IAM is split by responsibility (API/worker get distinct, narrowly-scoped policies; the callback and signing-service roles get **no** IAM policy at all, deliberately, since their real boundaries are network/HSM-native rather than IAM-shaped); CloudHSM's cluster-activation ceremony is honestly documented as an out-of-Terraform manual procedure that has never been performed.

## CLOUDFLARE / EDGE

Reviewed as design/IaC intent only — nothing is deployed. `ssl=strict`, `min_tls_version=1.2`, `always_use_https`/`automatic_https_rewrites` on, a managed-WAF-ruleset execution, a byte-exact (131072-byte) request-size firewall rule matching the application's own hard cap precisely, a three-rule edge rate limiter deliberately looser than each application-level limiter, and `cloudflare_authenticated_origin_pulls_settings` for origin protection are all present in `cloudflare.tf`. Trusted-proxy handling was independently re-confirmed at the application layer (`_resolve_client_ip`): `CF-Connecting-IP`/`X-Forwarded-For` are only ever honored when the direct TCP peer is itself inside a configured, default-empty trusted CIDR set — proven by 5 tests re-run live this session as part of the full unit suite.

## CI/CD

Every job in `.github/workflows/ci.yml` was enumerated (`unit-tests`, `security-gates`, `authorised-lab-integration`, `postgresql-integration`, `terraform`, `frontend`, `frontend-e2e`). `python scripts/verify-supply-chain-pins.py` was run fresh this session and passed cleanly, confirming every GitHub Action is pinned to a reviewed, verified commit SHA and the workflow's own runner-count/action-allowlist self-checks (the mechanism that would catch this governance script itself silently drifting again) are current.

## DEPENDENCIES

Python: fully hash-locked (`requirements-ci.lock`), confirmed via the official dependency audit run fresh this session (12 exact locked packages, clean). Node: `package.json` uses conventional caret ranges, but `package-lock.json` is committed and CI uses `npm ci` (which respects the lockfile exactly, never re-resolving via the ranges) — not a real gap in practice. Docker images: both the Postgres and Juice Shop compose images are pinned by exact digest, not just tag. **Terraform is the one place this discipline is not followed** — see INFRASTRUCTURE above. No unexpected runtime dependency was found; the temporary tools installed for prior slice work (Terraform binary, Trivy binary) are correctly outside source control (confirmed via `git status`/`git ls-files`) and are not accidentally vendored.

## TEST COVERAGE MAP

Full suites were run fresh this session, from a clean state, against real infrastructure, with exact commands and outcomes recorded:

| Suite | Command | Result |
|---|---|---|
| Backend unit | `python -m unittest discover -s tests/unit -p 'test_*.py'` | **1584 / 1584 passing** |
| Backend contract | `python -m unittest discover -s tests/contract -p 'test_*.py'` (real Postgres + SQLite) | **59 / 59 passing** |
| Backend integration | `python -m unittest discover -s tests/integration -p 'test_*.py'` (real Postgres + real Juice Shop) | **71 / 71 passing, 0 skipped** |
| Migration idempotency | `python scripts/run-postgres-migrations.py` (re-run against up-to-date schema) | Correctly reports no-op |
| Migration checksum-drift detection | Simulated drift on migration `0001`'s tracked checksum, re-ran the tool | Correctly refused, exact expected error |
| Frontend build+typecheck | `npm run build` (`tsc -b && vite build`) | Clean |
| Frontend lint | `npm run lint` (oxlint) | Clean (pre-existing, unrelated warnings only) |
| Frontend unit | `npm test` (Vitest) | **39 / 39 passing** |
| Frontend E2E | `npm run e2e` (Playwright, real Postgres-backed API) | **4 / 4 passing** — full customer-platform flow (sign in → asset → verify → scan → findings → report → sign out), invitation, password reset, registration |
| Terraform | `terraform fmt -check` / `init -backend=false` / `validate` | Clean |
| IaC security scan | Trivy (all severities) | **0 findings** |
| Security gates | secret scan / Ruff / dependency audit | All clean |
| Governance | `verify-supply-chain-pins.py` / `verify-governance-docs.py` | Both clean |
| `git diff --check` | — | Clean |

**Coverage gaps identified** (capability implemented but under-tested, not capability missing): PostgreSQL-backed worker-crash/lease-expiry recovery has **no** test (SQLite-only, see TRANSACTIONS/CONCURRENCY); the SSRF-callback detector cannot be exercised through the real production path at all today (P0-1 blocks it structurally); four HTTP routes (authentication-context/authorization-comparison mutations) have service-layer but no transport-layer test; several tenant-scoped resources (`browser_sessions`, `target_verifications`, `principals`/`api_tokens` cross-org paths) have no dedicated cross-tenant test at any layer — the three repository-level gaps this exposed (D1-D3) were only found because this audit went and tested them directly, live, this session, not because an existing test caught them.

No flaky or environment-dependent test was observed in three full fresh runs this session. The Vitest worker-pool hang from a prior slice remains fixed (confirmed: cold and warm runs both completed in seconds, `pretest` script present and effective).

## OBSERVABILITY

**Verdict: largely absent, confirmed precisely rather than assumed.** Structured logging does not exist — stdlib `logging` is used in exactly two files, both narrowly scoped to mail-delivery outcomes. The HTTP API's own access log is explicitly suppressed (`log_message` overridden to a no-op) and never replaced with anything — **the API emits zero log line per request, success or failure.** Worker/scheduler/callback-service/signing-service processes have **zero** logging of any kind; an unexpected exception in the worker (including the P0-1 crash) is caught, recorded only as a generic code on the job's own database row, and otherwise vanishes with no trace anywhere. `X-Request-ID`/organization-ID/scan-ID correlation is real but flows only into HTTP responses and the Postgres audit table, never into a log stream, because none exists to flow into. Metrics, alerting, and tracing are all confirmed absent, matching (and independently verifying) this project's own prior self-assessment. Health/readiness endpoints exist only on the main API process (`/health`, `/ready`) — the other four long-running process types have no externally-observable liveness signal at all.

## BACKUPS / RECOVERY / DR

Postgres automated backups/PITR and S3 versioning/lifecycle are both real, correctly-configured Terraform (7-day retention, deletion protection, dedicated CMKs) — but **unapplied**, so nothing has actually been backed up. `docs/production/BACKUP_RESTORE.md` is refreshingly honest about this itself ("no backup has been taken and no restore has been tested... a backup strategy is not considered proven until restore is tested") and this audit found nothing to contradict that self-assessment — no restore drill, script, or fixture exists anywhere in the repository. One documentation gap: the RDS storage-encryption KMS key's own disable/delete failure mode (which would render the *entire database* unreadable, unlike the signing key's rotate-and-move-on story) is never discussed anywhere. CloudHSM HA is explicitly a single-HSM, single-point-of-failure-for-availability design, honestly labeled as a deferred future scaling decision, not a hidden gap.

## RLS STATUS

**STILL BLOCKED**, independently re-derived from the current code, not inherited from a prior report's conclusion. `WebGuardPostgresPool.connection()` (the entire 108-line file was read) performs no session-state reset of any kind beyond the automatic transaction rollback `psycopg_pool` already provides, and constructs its `ConnectionPool` without either the `configure` or `reset` callback the underlying driver genuinely supports and that a tenant-context GUC hook would require. Confirmed via `git log` that this file has been touched exactly once, at its Slice-12 creation, and never revisited. No `SET LOCAL`/GUC/RLS-policy code exists anywhere in application code, and no `CREATE POLICY`/`ENABLE ROW LEVEL SECURITY` statement exists in any migration. The three-part precondition named by prior slices (checkout hook → fail-closed-on-unset-GUC proof → gated per-table rollout) remains entirely unmet. Implementing RLS today, without the hook, would reproduce exactly the new cross-tenant leakage vector prior audits warned against (a pooled connection silently retaining a prior request's tenant context). Application-layer `organization_id` checks remain the correct, sole enforced boundary — proven for most resources, honestly not proven at the repository layer for the three flagged in TENANT ISOLATION.

## REDIS DECISION

**REDIS NOT JUSTIFIED**, evaluated per role against current code, not general principle:
- **Queue dispatch efficiency**: correctness is fully solved by Postgres (`FOR UPDATE SKIP LOCKED`); this remains a pure latency/efficiency concern with no real horizontally-scaled deployment in existence to make it a measured cost.
- **Ephemeral callback correlation**: this is the one role where the calculus is genuinely unsettled — but the honest conclusion is that **nothing currently correctly solves this cross-process, not "Postgres already solves it"** (P0-1 is exactly this gap, unfixed). The project's own stated direction for closing it is a Postgres-polling `wait_for_observation()`, not Redis; introducing Redis here would mean solving an unmeasured problem before even trying the cheaper, already-designed approach.
- **Cross-instance rate limiting**: not needed — no second production API instance exists anywhere in this repository's deployment model.
- **Distributed locks for scheduler HA**: duplicate-prevention (the concrete near-term risk) is fully solved by Postgres CAS + a unique constraint, verified in code. True leader election remains genuinely unbuilt and unneeded, since nothing currently requires it.

## DOCUMENTATION ACCURACY

**Mixed, and the split matters for how a launch-readiness reviewer should use this repository's docs.** The newest documentation — every `docs/production/*.md` file and the Slice 12 through 18 `docs/audit/*.md` files — is unusually precise and self-critical, consistently distinguishing "designed" from "implemented" from "tested," and in several places (most notably `CALLBACK_SERVICE_DEPLOYMENT.md`) plainly disclosing its own product's currently-broken state rather than hiding it. Every specific claim checked in these documents against real code was found TRUE, correctly hedged, or (in a small number of cases, e.g. a mismatched concurrency-test parameter count, a stale migration-file comment) a minor, low-stakes drift.

**`README.md` and `docs/audit/production-gap-matrix.md` are the opposite**: both were effectively frozen before Slice 12 and never updated across the entire subsequent production build-out. README's own "Current limitations" and "Roadmap" sections currently claim "no PostgreSQL," "no customer dashboard," "no production identity provider," and list PostgreSQL/customer-dashboard/KMS-HSM-signing as future roadmap items — every one of which has a substantial, real, tested implementation already in this repository. `production-gap-matrix.md` similarly still marks PostgreSQL, object storage, and transactional email as "NOT STARTED." A reader who trusted either document as current-state would reach a materially wrong launch-readiness conclusion in the *pessimistic* direction (understating readiness) — the opposite failure mode from the inflated-buzzword risk the brief was watching for, but a real risk to the audit's own integrity if either had been treated as ground truth, which is exactly why this audit re-derived everything from source instead.

A targeted census of every "production-ready"/"CloudHSM-backed"/"Cloudflare-protected"/"high availability"/"durable"/"distributed"/"complete"/"secure" occurrence across the documentation set found **no unqualified overstatement anywhere** — every such claim is either correctly scoped to a specific proven entity, or is itself the language used to name an honest absence ("no high-availability... design," "a distinct, unsolved problem").

## CONTROLLED E2E RESULTS

Full account → login → session → asset creation → ownership verification → authorization → permit → scan → worker execution → findings → report generation → object-storage round-trip → download → audit-log proof, executed via the real Playwright suite against a real, freshly-migrated PostgreSQL instance and the real production-shaped component graph: **4/4 passing this session** (full customer-platform flow, invitation flow, password-reset flow, registration flow). Authenticated scanning and two-identity IDOR comparison are independently proven by the existing, re-run-this-session backend integration suite (`test_production_runtime_completion_e2e.py`), both against real PostgreSQL. SSRF-callback was tested independently and separately, as instructed, and its result is reported in the CALLBACK/SSRF section above (fails), not folded into this "passing" summary.

## NEGATIVE SECURITY TESTS

The full backend regression re-run this session (1584 unit + 59 contract + 71 integration, all passing) includes real, executed negative tests for essentially every item named in the brief: unauthenticated requests, wrong tenant, wrong role, expired/revoked session, bad/cross-session CSRF, cross-origin mutation attempts, expired/tampered/wrong-target/wrong-org permits, revoked authorization, invalid/wrong-org/expired callback tokens (at the detector level), bad/reused/cross-org-reused pagination cursors, invalid/revoked API tokens, and disabled signing keys — each cited above in its relevant section with the specific test name(s) that prove it, re-run live rather than assumed passing. This audit additionally ran three negative tests no existing test in the repository covers, all live this session: direct (service-layer-bypassing) cross-tenant repository access against `authentication_contexts`, `authorization_comparison_plans`, and `browser_sessions` (all three succeeded when they should have been blocked — see TENANT ISOLATION, D1-D3) and migration checksum-drift tampering (correctly blocked).

## P0 FINDINGS

**P0-1 — SSRF-callback detector is non-functional in production.** `ScanJobExecutor` is wired to `PostgresCallbackRegistrationRepository`, an interface incompatible with what the SSRF detector's live broker role requires. Confirmed by fresh live reproduction this session: a real permit + job + worker through the real production object graph, real fixture target, produces `state: "failed"`, `error.code: "worker_internal_error"`. Root cause: `executor.py:874`'s `callback_repository.policy` access and `ssrf_callback_detector.py`'s expectation of a `.url`-bearing registration token, neither of which `PostgresCallbackRegistrationRepository`/`ScopedCallbackRegistration` provide. Already tracked as `task_60b526a4` (a separate session is working on it; no committed fix exists on canonical HEAD as of this audit). **Not fixed in this pass, per the brief's explicit instruction.** Test that would prove the remediation: a real production-mode job with `active_checks: ["active.ssrf.callback"]` against a genuinely SSRF-vulnerable fixture, through two genuinely separate OS processes (worker + callback-service), producing a `CONFIRMED` CWE-918 finding.

**P0-2 — `webguard-api signing-service` has no fail-closed environment gate and defaults to a hardcoded development signing key.** Confirmed by actually running the command with only its one required variable (bearer token) set: it starts and listens, `key_source=development`, using `LocalDevelopmentSigner(bytes(range(32)))` (a fixed, source-visible key) unless a separate, also-optional dev-key override is set. No `--environment`/`WEBGUARD_ENVIRONMENT` gate exists on this subcommand at all — contrast with `serve`/`worker`/`scheduler`, each independently confirmed to fail immediately and cleanly when required variables are missing. An operator or deployment script that forgets `--key-source cloudhsm` would silently run TrustScan's entire signing custody on a well-known development key while the process reports success. Test that would prove the remediation: `webguard-api signing-service` (no flags, no environment variables beyond the bearer token) should refuse to start with a clear, coded error, exactly as `serve`/`worker`/`scheduler` already do.

## P1 FINDINGS

- **P1-1** — Three repository classes (`authentication_contexts`, `authorization_comparison_plans`, `browser_sessions`) have zero tenant/principal enforcement at the SQL/repository layer; safety today depends entirely on `service.py` checking first. Confirmed live by direct bypass this session. Not currently HTTP-reachable, but no independent backstop exists.
- **P1-2** — RLS remains structurally blocked: `WebGuardPostgresPool` has no tenant-context GUC checkout/reset hook, confirmed unchanged since its Slice-12 creation.
- **P1-3** — No structured logging or log stream exists anywhere in the system; the HTTP API's access log is explicitly suppressed and never replaced; unexpected worker exceptions (including P0-1's own crash) are swallowed with zero trace beyond a generic database row code.
- **P1-4** — No health/readiness signal exists for the worker, scheduler, callback-service, or signing-service processes — only the main API has one. No metrics, alerting, or tracing exist anywhere.
- **P1-5** — No test in this repository exercises PostgreSQL-backed worker-crash/lease-expiry recovery; the equivalent SQLite guarantee is thoroughly tested, but the production (Postgres) backend's identical guarantee is implemented-but-unproven.
- **P1-6** — `infra/terraform/.terraform.lock.hcl` is gitignored rather than committed, breaking this project's own otherwise-consistent supply-chain-pin reproducibility discipline for the one place (Terraform providers) it doesn't cover.
- **P1-7** — `TrustScanSigner.sign()`/`sign_safety_receipt()` hardcode `signature_algorithm="Ed25519"` regardless of the actual signing provider; a KMS-signed (ECDSA) permit would self-report the wrong algorithm. Verification is unaffected (resolves algorithm from the registry, not the self-reported field), but this is a real, untested data-integrity gap.
- **P1-8** — Backup/restore has never been tested against any environment (self-disclosed, confirmed); TrustScan safety receipts and authorization-audit files have no documented durability story for ephemeral production compute (no EFS/persistent-volume resource exists anywhere in this repository's Terraform).
- **P1-9** — CloudHSM's PKCS#11 `EC_POINT` encoding assumption remains unverified against real hardware — a genuine launch blocker specifically for the CloudHSM signing path (the `kms` path remains a viable, tested fallback).

## P2 FINDINGS

- **P2-1** — `WEBGUARD_CALLBACK_SERVICE_HOSTNAME` is validated at startup but never consumed anywhere else in the codebase (self-disclosed, tracked).
- **P2-2** — Six CLI bootstrap subcommands (`bootstrap`, `organization create`, `principal create`, `token create/revoke`, `authorization assign`) perform zero authentication, zero RBAC, and zero audit logging — architecturally necessary as a bootstrap mechanism, but not documented anywhere as the trusted, infrastructure-access-controlled surface it needs to be treated as operationally.
- **P2-3** — No single document enumerates all 19 production-required environment variables; a first-time operator must read `production_config.py` source directly.
- **P2-4** — `README.md` and `docs/audit/production-gap-matrix.md` are stale, understating current implementation materially (PostgreSQL, customer identity, object storage, transactional email, KMS/CloudHSM signing all marked absent or aspirational when substantially built).
- **P2-5** — Timing side-channel account enumeration on `/v1/auth/login` (moderate) and `/v1/auth/password/reset/request` (larger, due to a synchronous outbound mail call in the request path).
- **P2-6** — Four HTTP routes (`authentication-contexts`/`authorization-comparisons` mutations) have service-layer but zero transport-layer test coverage.
- **P2-7** — Several tenant-scoped resources (`browser_sessions`, `target_verifications`, `principals`/`api_tokens` cross-org paths) have no dedicated cross-tenant test at any layer.
- **P2-8** — Frontend RBAC-gating is inconsistently pre-checked client-side across pages (server always correctly enforces; this is a UX/polish gap, not a security one).
- **P2-9** — No organization/tenant offboarding (GDPR erasure) path exists anywhere in the schema or application code.

## P3 FINDINGS

- Dead `Environment.TEST`/`Environment.LAB` enum values, indistinguishable from `DEVELOPMENT`.
- Dead `ApiPermission.IDENTITY_MANAGE`/`AUTHORIZATION_ASSIGN` enum members, never checked anywhere.
- `active_checks_authorized()` helper defined and exported but never called (enforcement is correctly duplicated inline instead).
- `_DuplicateJsonKeyError` + its duplicate-key JSON loader copy-pasted identically across 5 files in the contracts package.
- Stale migration comment claiming `target_verifications` has no repository consumer (it has, since Slice 15).
- A documentation claim citing a 20-thread/5-job concurrency test; the actual test uses 10 threads/3 jobs (the underlying property is real either way).
- A local dev-convenience script prints the wrong frontend environment-variable name.
- No `port` restriction on commercial-mode scan targets (low impact, given every target must also be authorization-bound).
- `GET /v1/reports/{id}/download` is the one route missing informational `RateLimit-*` response headers (still correctly rate-limited).
- Several `int()`/`ipaddress.ip_network()` conversions in `cli.py` for secondary configuration crash with a raw traceback rather than this codebase's own coded-error convention.
- One dead Postgres table (`crawl_checkpoints`), honestly self-disclosed in its own migration comment as a placeholder.

## NOT-PROVEN ITEMS

- Real CloudHSM hardware validation of the signing path (explicitly, consistently, and honestly never claimed anywhere in the repository).
- Cloudflare/public-edge deployment (reviewed IaC only; no account, zone, or applied resource exists).
- PostgreSQL-backed worker-crash recovery (implemented, architecturally sound, but genuinely untested against the production database backend).
- Backup/restore capability (Terraform toggles exist; no backup has ever been taken, no restore has ever been performed, against any environment).
- A real `POST /v1/auth/login` HTTP call driven through the actual `build_production_components()` object graph (the pieces are each independently tested; no single test exercises the full path together).
- Four HTTP routes' transport-layer behavior (service-layer logic is tested; the HTTP dispatch/parsing specific to those four routes is not).

## TECHNICAL DEBT

The P3 list above constitutes the bulk of it, plus: the six-file-duplicated JSON-loader pattern; the CLI's un-guarded numeric/CIDR environment-variable parsing; the inconsistency between which repository methods enforce tenant scope in SQL versus relying on a caller-side check (a pattern worth standardizing project-wide, not just for the three flagged resources); and the stale top-level documentation (README, gap-matrix) which, left uncorrected, will keep costing future reviewers (human or automated) the same re-discovery work this audit had to do from scratch.

## LAUNCH BLOCKERS

P0-1 (SSRF-callback non-functional) and P0-2 (signing-service silent dev-key fallback) must both be closed before any production launch — the first is a functional gap in a named security capability, the second is a structural gap in this system's own fail-closed discipline for its most sensitive cryptographic material. P1-9 (CloudHSM hardware unverified) blocks specifically the CloudHSM signing path, not the KMS fallback path, as a launch option.

## STAGING BLOCKERS

P0-1 and P0-2 should be closed before any staging deployment intended to validate the full product surface (a staging environment that can't prove SSRF detection, or that could silently run on a dev signing key, isn't validating what it's meant to validate). P1-1 through P1-4 (tenant-isolation defense-in-depth, RLS, observability) are strongly recommended before staging, since staging is exactly where these gaps would otherwise go undetected until production.

## WHAT IS GENUINELY COMPLETE

TrustScan permit authorization (schema, binding, signing, execution-time re-validation — proven twice, not once); the `kms` signing path end-to-end; customer authentication and session management; RBAC; primary-resource tenant isolation (targets, jobs, scans, findings, schedules, reports, callback-registration metadata); PostgreSQL schema, migrations (idempotent, checksum-drift-protected — both proven live), and the primary concurrency guarantees (job-claim atomicity, schedule-dedup); finding lifecycle and evidence-sanitization discipline; object-storage-backed report generation/download with real integrity verification; transactional email; the full customer-facing frontend and its backend-contract alignment; the OpenHuntX brand integration; Scanner v1's entire detector suite including the specifically-re-verified IDOR regression guard; the complete backend and frontend test suites, all passing fresh this session; and the CI/CD supply-chain-pin governance mechanism.

## WHAT IS PARTIAL

Signing overall (CloudHSM code-complete, hardware-unverified); tenant isolation (strong for primary resources, structurally thin for three secondary repository classes); Postgres crash-recovery (proven on SQLite, unproven on Postgres); documentation (excellent where recently written, stale where it wasn't revisited); observability (a real audit trail exists; almost nothing else does).

## WHAT IS STILL DESIGN-ONLY

All of Cloudflare/public-edge, CloudHSM hardware deployment, RDS/S3 actually provisioned, backup/restore as a proven (not merely toggled) capability, and RLS as an implemented (not merely planned) defense-in-depth layer.

## RECOMMENDED REMEDIATION ORDER

1. Fix P0-1 (SSRF-callback wiring) — already in progress in a separate session; this audit's evidence (the confirmed-working cross-process data layer, the exact crash point) should accelerate that work, not duplicate it.
2. Fix P0-2 (signing-service fail-closed gate) — small, well-scoped, high-consequence-if-missed.
3. Add PostgreSQL-backed worker-crash-recovery test coverage (P1-5) — closes the single largest gap between "documented as proven" and "actually proven" in the reliability story.
4. Add repository-layer tenant scoping (or an equivalent enforced guard) to the three flagged classes (P1-1), and/or prioritize the RLS pool-checkout hook (P1-2) as the structural fix that would close this whole category at once.
5. Stand up minimal structured logging and per-process health endpoints (P1-3/P1-4) — cheap relative to the diagnostic blindness they currently cause, and directly would have made P0-1 far faster to discover in a real deployment.
6. Commit `.terraform.lock.hcl` (P1-6) — trivial, closes a real supply-chain gap immediately.
7. Fix the signature-algorithm self-reporting gap (P1-7) and add the missing test.
8. Update `README.md` and retire/relabel `production-gap-matrix.md` (P2-4) — cheap, and directly reduces the risk of a future reviewer (human or automated) repeating this audit's early re-discovery work.
9. Everything else in P2/P3 on ordinary engineering cadence.

## GO / NO-GO VERDICT FOR STAGING

**Conditional GO** — contingent on P0-1 and P0-2 being closed first. Every other finding in this report is either already-mitigated-in-practice (tenant-isolation gaps not HTTP-reachable), acceptable staging-stage debt (observability, RLS), or informational. Nothing else found in this audit should, on its own, block a staging deployment intended to validate the product against real (non-public) traffic.

## GO / NO-GO VERDICT FOR PRODUCTION

**NO-GO.** Independent of the two P0 defects (either of which alone would be sufficient), this audit found no evidence that any infrastructure has ever been applied to a real cloud account, no evidence a backup has ever been taken or a restore ever tested, and no evidence CloudHSM has ever been exercised against real hardware. Per the brief's own explicit instruction, deployment readiness is reported as **NOT PROVEN**, not merely "not yet done."
