# Production Gap Matrix

## Purpose

Inventories the current repository against the architecture described in the "OpenHuntX / WebGuard — Claude Production Integration Guide" (supplied 2026-08-27), per that guide's own recommended step 2: "inventory current implementation against this document and create a gap matrix." Status is verified against actual code, not assumed from prior documentation.

## Status legend

- **DONE** — implemented, tested, verified this session or a prior audited phase.
- **PARTIAL** — some real implementation exists but does not meet the guide's full requirement.
- **NOT STARTED** — no implementation exists.
- **BLOCKED ON EXTERNAL DECISION** — cannot be started without the user choosing a provider/account/credential; not something to pick unilaterally.

## §3 — Required connectors and infrastructure

| Item | Guide priority | Status | Evidence |
|---|---|---|---|
| GitHub | Essential | DONE | Repo is on GitHub (`git@github.com:Krishna-Jonnagaddala/openhuntx-webguard.git`), used as source of truth all session (branches off `main`, commits, pushes, HEAD verified against `origin/main` each slice). No PR/CI-gated merge workflow used yet — commits go straight to `main`. |
| PostgreSQL | Essential | NOT STARTED | `apps/api/src/webguard_api/store.py`: `"""SQLite-backed persistent scan-job queue."""`. Single-file SQLite throughout (API job store, identity store, service secrets). No PostgreSQL driver, schema, or migration path exists. |
| Redis / job queue | Essential | NOT STARTED | No Redis, Celery, or RabbitMQ dependency anywhere in `requirements-*.lock` or source. Async job dispatch is implemented via SQLite-backed leases/polling (`store.py`), not a message queue. |
| Object storage | Essential | NOT STARTED | Reports/checkpoints/artifacts are local filesystem paths (`scan-results/`, `authorizations/`) with strong local-filesystem hardening (Phase 5: ownership checks, atomic writes, no-symlink). No S3/GCS/Azure Blob integration. |
| Cloud hosting | Essential | NOT STARTED | Nothing deployed; `webguard-api serve` binds to `127.0.0.1` only (README: "must not be exposed directly to the public internet"). |
| DNS / domain | Live required | NOT STARTED | No domain owned by this project; target-ownership verification is self-attested only (README, "Safety and authorisation"). |
| Transactional email | Production | NOT STARTED | No email-sending code or provider integration. |
| Monitoring | Production | PARTIAL | In-process counters exist (Milestone 1.32: "observed counters for attempted, permitted, and blocked requests..."), but nothing exports to an external metrics/tracing/alerting system. |

**All seven infrastructure items other than GitHub are genuinely unstarted, not just under-documented.** Every one of them (§3–§7, PostgreSQL/Redis/object storage/cloud hosting/DNS) requires the user to choose a provider and supply an account/credentials — this is explicitly flagged as **BLOCKED ON EXTERNAL DECISION** below, not something to provision unilaterally.

## §5 — Production data layer

| Suggested entity | Status |
|---|---|
| organisations, principals (users), API tokens, authorizations, jobs, schedules, TrustScan permits, audit events | DONE, but on SQLite, not PostgreSQL. Tenant isolation, RBAC, hashed-token storage, signed cursors already implemented and audited (Phase 2/4 checkpoints). |
| findings, finding_occurrences, finding_status_history | NOT STARTED — no finding-lifecycle/dedup persistence exists; findings are currently ephemeral (produced per-scan, written to a report file, not stored as first-class queryable rows). |
| service_credentials_metadata | PARTIAL — external service-secret files exist (Phase 5) but aren't modeled as a PostgreSQL-tracked entity. |

## §6 — Queue and worker architecture

DONE in spirit, NOT in the guide's specified technology: worker leases, heartbeat renewal, crash recovery, stale-worker fencing, and cancellation are all implemented and tested (Phase 4 audit, `test_job_leases.py`, `test_phase4_lock_crash_recovery.py`) — but on a SQLite-backed lease table, not Redis. The guide's own architecture diagram treats this as acceptable evolution ("PostgreSQL should replace development-only persistence **where appropriate**"), so this is a real design decision, not obviously a defect — flagged for explicit discussion, not silently kept or silently replaced.

## §8–9 — Identity, authN/authZ, target ownership

| Item | Status |
|---|---|
| Server-side tenant/role checks | DONE (Phase 2/4 audited, adversarially tested for cross-tenant access) |
| Mature identity provider / MFA | NOT STARTED — current auth is a bespoke Bearer-token + scrypt-hash model (deliberately reviewed and hardened, but not an off-the-shelf IdP, and no MFA) |
| Domain/DNS ownership verification | NOT STARTED — README is explicit: authorization is "a locally generated authorisation document" that "does not independently prove legal ownership"; this is a known, previously-documented limitation, not new information |
| SSRF/scope-escape protection on the scanner itself | DONE and independently re-verified this session (`scope_validator.py`, 19/19 tests, fail-closed on mixed public/private DNS answers) |

## §10–13 — Detection model, passive/active detection, lab validation

| Item | Status |
|---|---|
| Finding schema (rule ID, severity, confidence, CWE, evidence, remediation, fingerprint) | DONE — `webguard_contracts.NormalizedFinding`, existed before this session, unmodified |
| OWASP / CAPEC / CVSS fields on findings | NOT STARTED — no first-class fields; the InternStack report used a manually-added OWASP note, explicitly disclaimed as non-automated |
| Coverage matrix with explicit skip/unsupported accounting | DONE — `docs/CWE_COVERAGE.md`, plus per-scan coverage accounting (`executed_checks`/`skipped_checks` with stated reasons, verified against real Juice Shop/InternStack scans) |
| Passive detection (headers, cookies, TLS, CORS, disclosure) | DONE — 18 CWEs, lab- and real-site-validated this session |
| Active detection | PARTIAL — exactly one class (reflected XSS) implemented, lab-investigated, real-socket tested; not wired into orchestration; SQLi/IDOR/SSRF/auth/API checks from §12 do not exist |
| Controlled vulnerable labs | PARTIAL — Juice Shop wired and used (14 integration + ad hoc CLI validation this session); DVWA, WebGoat, dedicated SSRF/IDOR/auth fixtures do not exist |

## §14 — Security development toolchain

| Item | Status |
|---|---|
| Repository/history secret scanner | DONE, adversarially tested (Phase 5, P5-009) |
| SAST (Ruff security rules) | DONE, in `scripts/run-security-gates.sh` |
| Dependency advisory scanning | DONE (`scripts/audit-dependencies.py`) |
| Dependabot / equivalent | NOT STARTED |
| Container image scanning (Trivy) | NOT STARTED — no container is built for the app itself; only the Juice Shop lab image is pulled (pinned by digest) |
| SBOM generation | NOT STARTED |
| Hash-locked dependencies | DONE (`requirements-*.lock`, `--require-hashes` used in install scripts) |

## §15–16 — Monitoring, notifications, email

All **NOT STARTED**. In-process counters exist; nothing external.

## §18 — Owned website validation workflow

PARTIAL, honestly: one passive scan of `internstack.in` was completed this session under the operator's explicit chat authorization (`docs/audit/internstack-first-production-scan.md`) — self-attested, not DNS-verified, consistent with the current authorization model's known limitation. No active checks, no test accounts, no authenticated testing has been done against any real site — correctly gated, per this guide's own §21, behind the user explicitly supplying that material.

## §19 — Documentation

| Doc | Status |
|---|---|
| Threat model | DONE — `docs/THREAT_MODEL.md` (pre-existing) |
| Repository/development workflow | PARTIAL — README covers CLI/API usage; no formal contributor workflow doc |
| Scanner coverage matrix | DONE — `docs/CWE_COVERAGE.md` |
| CWE/OWASP/CAPEC catalogue | PARTIAL — CWE only; no OWASP/CAPEC catalogue exists yet |
| Lab validation reports | DONE — `docs/audit/lab-validation-juiceshop.md`, `docs/audit/active-detection-phase1-xss.md` |
| Production deployment guide | NOT STARTED |
| Target authorization/scope model | DONE — README + `docs/AUTHORIZATION_MODEL.md` |
| Data retention / evidence handling | PARTIAL — `docs/DATA_CLASSIFICATION.md` exists; no retention/deletion automation |
| Secrets/key-management model | DONE — Phase 5 audit checkpoint |
| Incident/rollback procedures | NOT STARTED |
| API documentation | PARTIAL — README documents the full curl-based workflow; no generated OpenAPI spec |
| Finding schema / severity methodology | DONE — `webguard_contracts/findings.py`, documented in CWE_COVERAGE.md |
| Known limitations | DONE — stated explicitly in every audit doc produced this session |
| Release notes / migration notes | PARTIAL — ROADMAP tracks milestones; no formal changelog |

## What this means for the recommended execution order (§22)

Steps 1–4 (verify repo, gap matrix, finish audit findings, stabilise scanner contracts) are the state this session has been operating in and are substantially complete. **Steps 5–10 (PostgreSQL, Redis, object storage, identity/RBAC-as-a-service, target-authorization-as-a-service, production API + web UI) are all genuinely unstarted and every one of them requires the user to choose and supply access to a real external provider** — I cannot pick an AWS/GCP/Azure account, register a domain, or provision a managed Postgres/Redis instance unilaterally; those are exactly the kind of consequential, costly, externally-visible decisions that need your explicit choice, not my default.

Steps 11–12 (expand passive coverage, add active detection classes lab-first) are directly continuable right now with no new infrastructure or decisions needed — this is the same track the last two slices (P6-001, reflected-XSS) were already on.
