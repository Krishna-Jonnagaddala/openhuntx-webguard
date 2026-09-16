# Release Evidence

Per-capability implementation/test/deployment state across all three modules, using the state vocabulary `docs/audit/OPENHUNTX_THREE_MODULE_PLATFORM_HANDOFF_2026-09.md` section 19 specifies: `proposed`, `designed`, `implemented`, `locally_tested`, `integration_tested`, `staging_validated`, `production_deployed`, `externally_verified`. Do not compress every row into a single "done."

This file tracks capability-level release evidence. Requirement-level status (what's implemented, what's a documented gap and why) stays in `docs/PROJECT_EXECUTION_LEDGER.md`; this file adds the deployment-stage dimension on top.

## WebGuard

| Capability | State | Evidence |
|---|---|---|
| Ten-pillar core (permit, safety receipt, scanner, reporting) | `integration_tested` | Baseline audit + full regression suite, `docs/PRODUCT_VISION_TRACEABILITY.md` |
| Phase A-H tenant-isolation runtime conversion | `integration_tested` | PRs #30-47, proven against real disposable Postgres and CI's own fresh Postgres job |
| RLS+FORCE enforcement | `designed` | Policies defined (`infra/postgres/bootstrap/tenant_isolation_rls_policies.sql`) for all 29 tenant-owned tables with a current ACL grantee, including `coverage_records`/`module_entitlements`/`scoped_control_implementations` (added 2026-09-15, this audit's own Phase 3 correction) and `technical_assertion_collections` (added 2026-09-15, Phase 5) — never enabled; P1-2 stays open on this basis |
| Coverage Truth Map v1 | `integration_tested` | PRs #49-50, real end-to-end production-pipeline assertion in `test_production_mode_e2e.py` |
| Coverage Truth Map v1 read API (`GET /v1/assets/{id}/coverage`) | `integration_tested` | Phase 4, 2026-09-15: tenant-scoped, paginated, HTTP-level unit tests plus a real disposable-Postgres contract suite; rendered on the existing `AssetDetailPage.tsx` |

## SOC

| Capability | State | Evidence |
|---|---|---|
| Connector manifests (Entra, Defender XDR, Sentinel) | `implemented`, unit-tested | `apps/api/src/webguard_api/soc_connectors.py`, PRs #53/#55/#57; every permission/RBAC role verified against Microsoft's current documentation; `docs/CONNECTOR_CAPABILITIES.md` |
| Live connector clients | `proposed` | Zero HTTP clients exist by design; no Microsoft tenant credentials available to this project |
| Everything else in section 9 of the handoff (telemetry normalization, detection engineering, ProofLoop, cases/investigations, AI-assisted analysis, Response Guard) | `proposed` | No design or code exists |

## Compliance

| Capability | State | Evidence |
|---|---|---|
| Framework/master-control catalog | `integration_tested` | Migration 0015, PR #54; 5 seeded placeholder frameworks, zero real control content, proven against real disposable Postgres |
| Scoped control implementation (applicability) | `integration_tested` | Migration 0016, PR #56; the first of section 10.2's seven status dimensions, tenant-scoped, proven against real disposable Postgres |
| Technical assertion catalog | `locally_tested` | `apps/api/src/webguard_api/technical_assertions.py`, PR #58; 5 assertions (3 Entra-sourced, 2 Sentinel-sourced), cross-validated against connector manifests at construction time; no schema change, no database table, nothing executed |
| Technical assertion collection and evaluation (`assertion_collections.py`, first executed assertion `entra_conditional_access_policy_mode`) | `locally_tested` | Phase 5, 2026-09-15: fixture- and manually-supplied evidence paths, tenant-scoped, real disposable-Postgres contract suite (5 tests) plus pure evaluation-logic unit tests (11 tests). No live vendor connector: evidence is always labeled `fixture` or `manual`, never presented as a live read. No service/HTTP/CLI surface yet, matching this stage's own established Compliance pattern. This is the "collection/test-execution/assertion-outcome" dimension the row below used to list as entirely `proposed` — one assertion of five now has real evaluation logic, the other four remain unimplemented |
| Control-assessment/treatment/assurance-review dimensions; evidence records; governance/privacy/vendor/audit workflows | `proposed` | Not designed or built |

## Platform-shared

| Capability | State | Evidence |
|---|---|---|
| Module entitlement | `integration_tested` | Migration 0014, PR #52; wired into organization creation, proven against real disposable Postgres |
| Shared evidence envelope (handoff section 11) | `proposed` | Not started; Coverage Truth Map's own `coverage_records` table is the closest existing precedent for the shape a generalized envelope needs |

## Known risks carried into this expansion

- Every SOC connector needs real Microsoft tenant credentials this project does not have; nothing SOC-related can reach `integration_tested` or later until that access exists.
- Compliance framework packs need authoritative legal-text verification (GDPR/UK GDPR commencement text specifically could not be fully retrieved by the source handoff's own research pass) before any legal claim in a released pack.
- RLS+FORCE activation needs a real, non-disposable environment this session has no standing authorization to provision.
- No code path anywhere connects a WebGuard finding to a SOC or Compliance record, or the reverse. The three modules currently share only `organization_id` as a common key; the flagship cross-module workflow (handoff §14) has not been attempted.

No rollout/rollback plan exists for any SOC/Compliance capability yet, since none has reached a stage where one is needed. This section will gain real rollout/rollback evidence as capabilities reach `staging_validated`.

This file was last reconciled against actual repository state on 2026-09-15 (previously last updated 2026-09-12, before PRs #52-58 shipped). See the OpenHuntX Scope & Progress Audit, 2026-09-14, for the evidence-backed review this reconciliation is based on.
