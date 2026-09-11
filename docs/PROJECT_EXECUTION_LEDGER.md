# Project Execution Ledger

Durable, requirement-level tracking for OpenHuntX WebGuard engineering work, per the Claude Master Completion Mandate (2026-09-11). This is a coordination document, not the authoritative vulnerability record — that remains `docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md` and `docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md` (immutable). This ledger links to that evidence rather than duplicating it.

Status values: NOT_STARTED, IN_PROGRESS, IMPLEMENTED_UNVERIFIED, VERIFIED, BLOCKED_EXTERNAL, DEFERRED_WITH_REASON.

## Canonical baseline

```
Commit: da5da852919bcde2f8773c6cf6eae4d393734c71
Verified: 2026-09-11, by direct git fetch + rev-parse, not trusted from a prior report.
origin/main == this commit: YES
Open P1 total: 6 (P1-2, P1-6, P1-7, P1-8, P1-9, P1-12-R1) -- verified against
  docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md's own "CURRENT P1
  ACCOUNTING" section directly, not the mandate's paraphrase of it.
```

## Requirement rows

| ID | Source | Intended behavior | Status | Code/contracts | Tests/evidence | Dependency | Milestone | Acceptance condition |
|---|---|---|---|---|---|---|---|---|
| A-G | Baseline audit P1-2 | Tenant-context plumbing through dormant RLS policies | VERIFIED | `infra/postgres/bootstrap/tenant_isolation_*.sql` | 129/129 combined Postgres suite, CI run 34506680942 | none | Phase A-G | Reconfirmed live at `da5da85`; see final P1-C2-G report in session transcript |
| P1-6 | Baseline audit | Commit `.terraform.lock.hcl`, stop gitignoring it | IN_PROGRESS | `.gitignore`, `infra/terraform/.terraform.lock.hcl` | `terraform fmt`/`validate`/Trivy/secret-scan all pass locally; PR CI pending | none | opportunistic fix | PR #17 merged, CI green |
| P1-2 | Baseline audit | RLS structurally blocked: no tenant-context GUC checkout/reset hook at runtime | IN_PROGRESS (policies defined, runtime not converted) | A-G bootstrap SQL exists; `postgres_pool.py`'s tenant-context helper exists (Phase B) but ordinary repository callers don't yet set it before every query | Dormant-state proven (29/29 Phase G); runtime conversion (Phase H) not started | Phase H completion | Real runtime paths set tenant context; enforced isolation survives adversarial test; RLS+FORCE activated in a real (non-disposable) environment with evidence |
| P1-7 | Baseline audit | `TrustScanSigner.sign()`/`sign_safety_receipt()` hardcode `signature_algorithm="Ed25519"` regardless of actual provider | NOT_STARTED | `apps/api/src/webguard_api/signing.py` | none yet | none | independent fix | Algorithm field is provider-derived; local + KMS paths both tested; verification stays bound to key/algorithm |
| P1-8 | Baseline audit | Backup/restore never tested against any environment | NOT_STARTED | Terraform toggles exist; no EFS/persistent-volume resource | none | requires an actual applied environment | deferred to staging | Real backup/restore exercise, integrity verified, RTO/RPO measured |
| P1-9 | Baseline audit | CloudHSM PKCS#11 `EC_POINT` encoding unverified against real hardware | BLOCKED_EXTERNAL | `kms` path is the tested fallback; CloudHSM code exists, unexercised | none against real hardware | real CloudHSM module/hardware access | N/A until hardware available | Genuine hardware validation of key extraction, identity, signing, independent verification |
| P1-12-R1 | Post-audit residual | Sustained callback-service PostgreSQL outage can lose durable SSRF evidence (proven: yields false NOT_VULNERABLE, not INCONCLUSIVE) | DEFERRED_WITH_REASON | `callback_server.py`, `postgres_callback_service.py` | Proven residual: `test_no_fabricated_confirmation_when_persistence_never_recovers` | requires an explicit secondary-durability architecture decision (not a bug fix) | future architecture slice | Durable secondary store or documented, accepted, explicitly-surfaced limitation |
| Phase H | Mandate §7 | Convert ordinary PostgreSQL repository callers to set tenant context before query; classify pre-auth/cross-tenant/callback paths separately | IN_PROGRESS (inventory started) | 13 `postgres_*.py` repository files, ~90 public methods enumerated 2026-09-11 (see below) | none yet — classification and conversion not started | P1-2 closure depends on this | multi-session | Every ordinary tenant-data method sets context before query; adversarial cross-tenant test passes under real runtime credentials |

## Phase H: repository inventory (discovery, 2026-09-11)

Structural pass only — file, class, and public method names, extracted directly from source. Per-method classification (tenant source, principal source, current pool/role, desired capability, transaction boundary, control-function need, error semantics, test coverage) is the next pass and is NOT yet done; do not treat the presence of a method here as evidence its tenant scoping has been reviewed.

| File | Class | Public method count |
|---|---|---|
| `postgres_authentication_contexts.py` | `PostgresAuthenticationContextRepository` | 6 |
| `postgres_authorization_comparison.py` | `PostgresAuthorizationComparisonPlanRepository` | 6 |
| `postgres_callback_broker.py` | `PostgresCallbackBroker` | 5 |
| `postgres_callback_service.py` | `PostgresCallbackRegistrationRepository` | 4 |
| `postgres_findings.py` | `PostgresFindingRepository` | 5 |
| `postgres_identity.py` | `PostgresIdentityRepository` | 25 |
| `postgres_jobs.py` | `PostgresJobRepository` | 30 |
| `postgres_reports.py` | `PostgresReportRepository` | 3 |
| `postgres_scans.py` | `PostgresScanRepository` | 5 |
| `postgres_schedules.py` | `PostgresScheduleRepository` | 10 |
| `postgres_sessions.py` | `PostgresSessionRepository` | 6 |
| `postgres_target_verification.py` | `PostgresTargetVerificationRepository` | 4 |
| `postgres_targets.py` | `PostgresTargetRepository` | 6 |

13 repository files, ~115 public methods total (note: `postgres_jobs.py` re-exposes several schedule methods as thin delegates to `postgres_schedules.py` — actual distinct implementations are fewer; this will be resolved in the classification pass, not double-counted in Phase H's own completion metric).

## Milestone history (reconstructed from Git + tracker, not fabricated)

| Milestone | Evidence |
|---|---|
| 1.25 | Reporting hotfix (referenced in mandate; not independently re-verified this session) |
| 1.26 | Service queue (referenced in mandate; not independently re-verified this session) |
| 1.27 | Organizations/RBAC (referenced in mandate and old README; superseded by later identity work) |
| 1.31 | TrustScan Scan Permit v1 |
| 1.32 | Runtime safety enforcement, Safety Receipt v1 |
| P0 remediation | `a26b99a`, `0114d56`, disabled-key fix `d94b96c`, closure `c13ccb9` |
| P1-A | `ccf05d1` (A1), `ee3c2c2` (A2, closes P1-5) |
| P1-1 closure | `fa94d7c`, audit record `b412e8b` |
| P1-3 closure | `a2f385b` |
| P1-4 closure | `2ba35a1`, tracking `38ee4b4` |
| P1-10/P1-11 closure, P1-12 partial | tracked in `WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md`, commit `b5d3bb9` |
| Phase A-G (tenant isolation) | `af5cb58` through `da5da85`, this session |
| P1-6 fix | PR #17, branch `fix/p1-6-terraform-lockfile`, commit `43da1c7` |

1.25/1.26/1.27 milestone claims are carried forward from the mandate as-supplied; this session did not independently re-derive their exact commits. Flagged here rather than silently treated as verified.
