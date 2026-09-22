# WebGuard-only release checklist

Product decision (2026-09-22): ship OpenHuntX's first release with WebGuard as the
available product. SOC and Compliance continue as separate development tracks and are
not release blockers for WebGuard; see "Deferred, not blocking" and
`docs/production/WEBGUARD_RELEASE_CHECKLIST.md`'s own SOC/Compliance rows below for
what keeps them out of the critical path without pretending they do not exist in the
codebase.

This is the one finite checklist for that release. It supersedes no other document's
own evidence: `docs/RELEASE_READINESS.md` still holds the six-gate verdict framework
and `docs/PROJECT_EXECUTION_LEDGER.md` still holds the full P1-N mandate history. This
file exists because neither is structured as a closeable list with an acceptance
criterion and a remaining dependency per row, which a release decision needs and an
open-ended narrative does not give.

Status values used below: **DONE** (evidence exists, acceptance criterion met),
**PARTIAL** (some of the requirement is met; the gap is named), **OPEN** (not met),
**OWNER DECISION** (the code/evidence exists on both sides of a choice; a person, not
more engineering, closes this row).

## Mandatory release blockers

| # | Requirement | Status | Evidence / implementing PR | Acceptance criterion | Remaining dependency |
|---|---|---|---|---|---|
| M1 | Register, verify email, sign in | DONE | `service.py` `register_account`/`login`/email-verify flow; `apps/web/e2e/registration.spec.ts` | Real account created and verified through the actual HTTP/UI path | None |
| M2 | Create an organization; join one | PARTIAL | `register_account` (create); invite/accept flow (join) | Create is DONE. "Join" exists only via invite, never self-service by domain | OWNER DECISION: accept invite-only join as the shipped v1 behavior (recommended; self-service join-by-domain is new scope) |
| M3 | Manage team roles | DONE | `auth.py` `_ROLE_PERMISSIONS`; `invite_team_member`/`update_team_member`/`remove_team_member`; `TeamPage.tsx` | Four real roles, server-enforced, self-modification blocked, role change revokes sessions | None |
| M4 | Register assets, verify ownership | DONE | `check_dns_txt_token`/`check_well_known_token` in `check_asset_verification`; `AssetDetailPage.tsx` | Real DNS TXT / well-known HTTP check, server-generated token, no client-settable verified flag | None |
| M5 | Configure authorized assessments | PARTIAL | `issue_permit`; `StartScanPanel` in `AssetDetailPage.tsx`; `cli.py --active-check` | Permit issuance is DONE end to end. The web UI only ever issues passive-only permits (`api.ts` hardcodes `active_checks: []`); active-check selection is CLI/API-only, never customer-facing | OWNER DECISION: ship passive-only as the customer-facing v1 scope (recommended for this release; active-check UI is new scope), state it in release notes |
| M6 | View status, coverage limitations, findings, evidence | DONE | `ScanDetailPage.tsx`; `AssetDetailPage.tsx` `CoveragePanel` ("Coverage Truth Map") | Coverage gaps are shown to the customer, not confined to internal docs | None |
| M7 | Download reports | DONE | `ReportsPage.tsx` `downloadReport`; `/v1/reports/{id}/download` | Report downloads after scan completion | None |
| M8 | Manage finding status and remediation verification | DONE | `update_finding_status`; `finding_store.py`'s RESOLVED→REOPENED re-detection transition; `FindingDetailPage.tsx` | A re-scan that still finds a "resolved" issue reopens it automatically | None |
| M9 | Account settings, sessions, API keys | PARTIAL | `ApiKeysPage.tsx`/`create_api_key`/`revoke_api_key` (DONE); `logout_all_sessions`/`SettingsPage.tsx` (bulk sign-out only) | API keys fully real. Sessions: only bulk "sign out everywhere," no list/revoke of one session | OWNER DECISION: accept bulk-only session management for v1 (recommended; per-session UI is new scope) |
| M10 | Customer-visible audit history | DONE | `AuditLogPage.tsx`; `/v1/audit-events`; `identity.list_audit_events_page` (hard `organization_id` filter) | Every read is org-scoped; no cross-tenant audit visibility | None |
| M11 | `set_password_hash` and sibling methods under forced RLS | DONE | PR #72 (merged, `1b9bf22`); independently re-run this session: `test_postgres_password_hash_tenant_context.py` 7/7, full CI Postgres suite 169/169, both live against a real Postgres 16.10 instance | Registration/login/password-change/reset/invitation succeed under forced RLS; a mismatched `organization_id` is rejected by RLS itself, not application logic | None |
| M12 | SECURITY DEFINER function boundary review | DONE | PR #72; `docs/audit/p1-2-phase-h-security-definer-boundary-review-2026-09.md`; independently spot-verified this session (call-site grep, both proof tests re-run) | Every named function's real trust boundary (possession-of-ID vs. Python call-site discipline) stated and tested, not asserted | None |
| M13 | `callback_receiver` effective privileges | DONE | PR #72; `test_callback_receiver_has_exactly_one_privilege_anywhere`, re-run this session | Proven by adversarial catalog query (ACL sweep + role-membership sweep), not by reading the GRANT statement alone | None |
| M14 | Tenant isolation / RLS policy correctness (code and test level) | DONE | PR #72; `test_postgres_rls_policies.py`'s `TwoTenantIsolationTests`, 22/22, re-run this session under real ENABLE+FORCE RLS in a disposable database | Policy model isolates tenants under forced RLS, proven against disposable databases | None (see M18 for activation in a persistent environment) |
| M15 | Pooled-connection cleanup (no role/tenant-context leak) | DONE | `test_postgres_phase_h_gap_closure.py::test_pooled_connection_does_not_leak_role_or_tenant_context`, re-run this session | A connection checked out under one role/tenant and released reverts to the pool default before the next borrower | None |
| M16 | Fresh-install and upgrade compatibility | DONE | PR #72; `test_postgres_schema_upgrade_compatibility.py`, 2/2, re-run this session live | Both a fresh bootstrap and an upgrade from the pre-Phase-H state succeed, old-shaped reads byte-identical after upgrade | None |
| M17 | Public-repository exposure review | DONE | This session: 3-agent audit (workflow trust boundaries, full git-history secret scan, repo settings/CI-log scan) | No `pull_request_target`, no shell-injection via untrusted `${{ }}`, all third-party actions SHA-pinned, zero `secrets.*` in workflows, no credential found across 274 commits / 3752 objects, 5 recent CI runs' logs clean | None |
| M18 | RLS `ENABLE`/`FORCE` activation in a persistent (staging/production) environment | OPEN | `docs/production/RLS_STAGING_ACTIVATION.md` (procedure, written); PR #71 (staging plan, open, gated on owner go-ahead) | RLS is actually forced on a real, non-disposable database, not only proven in disposable test databases | OWNER DECISION: approve PR #71's cost estimate (~$2.30/one-day window) and Terraform state backend choice, then execute the documented, separately-approved activation step |
| M19 | GitHub Actions / repository protections | OPEN | This session's audit: `main` has no branch protection and no rulesets (404/empty); repo-level Actions settings allow any action (`allowed_actions: "all"`, `sha_pinning_required: false`) | Either accept current single-collaborator risk explicitly, or add branch protection (required reviews/status checks) and restrict allowed Actions | OWNER DECISION: a repository-settings change, not a code change |
| M20 | SOC/Compliance unreachable server-side in this release | DONE | PR #75 (open): deployment-wide `enabled_modules` gate, defaults to `webguard`-only, blocks all 4 SOC/Compliance read routes, the 1 write route, and the entitlement toggle itself, independent of per-org entitlement | An owner cannot enable SOC/Compliance via the API in a WebGuard-only deployment; unauthenticated/low-privilege callers get the identical 404 a genuinely-absent route would | Merge PR #75 |
| M21 | Evidence handling during sustained callback-persistence outages (P1-12-R1) | PARTIAL (fails safe) | `callback_server.py`'s `_record_observation_with_bounded_retry`: bounded retry (2 attempts, 0.1s backoff), then logs `callback_observation_persistence_exhausted` and drops, never fabricates a confirmation | Current behavior never produces a false CONFIRMED; a full secondary-durability fix (queue/WAL) is undesigned | Design + implement a secondary durability mechanism, or explicitly accept "an outage loses the observation, never lies about it" as v1's stated limitation |
| M22 | Object-storage / secret-provider tenant isolation (P1-13) | OPEN | `docs/PROJECT_EXECUTION_LEDGER.md` P1-13 row: traced, Medium severity, 2026-09-15; no code change since; no regression test exists | Either add a second, independent isolation layer at the storage/secrets boundary, or explicitly accept application-layer-only isolation as v1's stated limitation, with a named test proving what the current layer does catch | Architecture decision (undesigned as of this checklist), then implementation |
| M23 | Production signing configuration selected and provable | PARTIAL | `signing.py`: `LocalDevelopmentSigner` (structurally excluded from production by `production_config.py`), `KmsSigningProvider` (tested, never run against real AWS), `CloudHsmSigningProvider` (needs unapplied `cloudhsm.tf` + real hardware) | `kms` is the only hardware-free, already-tested production path, but wiring it as the actually-active signer needs a reviewed Ed25519→ECDSA_SHA_256 schema/verification change (`docs/production/TRUSTSCAN_PRODUCTION_SIGNING.md` "Option C"), not yet done | Scope and implement the KMS signing cutover, or accept CloudHSM's hardware-procurement timeline instead |
| M24 | Deployment path: reverse proxy / TLS in front of the loopback-only API | OPEN | `docs/production/PUBLIC_EDGE_SECURITY.md` covers edge TLS/WAF; explicitly states the host-local reverse-proxy sidecar "does not exist in this repository" | A real nginx/Caddy/Envoy config exists and is validated in staging | Write and validate the sidecar config; do not remove the loopback restriction (`http_api.py`/`production_config.py`'s two independent checks) until it exists |
| M25 | Deploy rollback procedure (bad application release, not RLS or DB backup) | OPEN | `docs/audit/production-gap-matrix.md`, row "Incident/rollback procedures": NOT STARTED | A written, testable procedure for rolling back a bad WebGuard release exists | Write the procedure (pure documentation, no infra needed) |

## Deferred, not blocking this release

| Item | Why it does not block | Tracking |
|---|---|---|
| P1-8: real AWS RDS snapshot-restore timing | Backup/restore *mechanics* are proven locally (33 tables, 696 rows, byte-identical restore, 99/99 contract tests); only the real-AWS timing/PITR exercise is missing, and that needs an applied environment this release does not require | `docs/production/BACKUP_RESTORE.md` |
| P1-9: CloudHSM hardware validation | `kms` is the tested, hardware-free fallback (see M23); CloudHSM itself needs physical hardware procurement out of scope for a first release | `docs/production/TRUSTSCAN_SIGNING_SERVICE.md` |
| Individual session list/revoke UI | Bulk "sign out everywhere" already covers the security-relevant case (M9); per-session UI is a UX improvement, not a missing control | N/A |
| Self-service org-join-by-domain | Invite-based joining already covers the customer journey (M2); domain-based self-join is new scope | N/A |
| Alerting/paging integration | Health checks and structured logs exist; external alerting (PagerDuty/Opsgenie/etc.) is operational maturity, not a release blocker | `docs/production/INFRASTRUCTURE_REQUIREMENTS.md` |
| SBOM / build provenance generation | Dependencies are locked and audited (`requirements*.lock`, `scripts/audit-dependencies.py`); SBOM/provenance is supply-chain hardening beyond what a first release needs | N/A |
| SOC module (live connector integrations) | Zero live HTTP clients exist by design this release; blocked server-side by M20 | `docs/PLATFORM_SCOPE.md` |
| Compliance module (framework content, live evaluation) | Framework catalog is reference-only (0 controls loaded); blocked server-side by M20 | `docs/PLATFORM_SCOPE.md` |

## Newly found during this checklist's own verification, not yet fixed

- A freshly-registered organization through the real `webguard-api serve --environment lab` path ended up with zero module-entitlement rows (`GET /v1/module-entitlements` returned `{"entitlements":[]}`), contradicting `register_account`'s own guarded grant call and its passing unit test. Root cause not yet diagnosed; flagged as its own follow-up task, tracked outside this checklist since it is unrelated to the WebGuard-only release gate (PR #75) that surfaced it.

## How to use this checklist

Every mandatory row needs to reach DONE, or an explicit OWNER DECISION needs to be recorded against it, before this release's go/no-go is called. "Deferred, not blocking" rows are not silently dropped: each one names the tracking document that still owns it. This file should be updated in place (not superseded by a new file) as rows close; each closure should cite the commit/PR that closed it, matching the discipline `docs/PROJECT_EXECUTION_LEDGER.md` already uses.
