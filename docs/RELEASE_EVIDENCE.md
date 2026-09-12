# Release Evidence

Per-capability implementation/test/deployment state across all three modules, using the state vocabulary `docs/audit/OPENHUNTX_THREE_MODULE_PLATFORM_HANDOFF_2026-09.md` section 19 specifies: `proposed`, `designed`, `implemented`, `locally_tested`, `integration_tested`, `staging_validated`, `production_deployed`, `externally_verified`. Do not compress every row into a single "done."

This file tracks capability-level release evidence. Requirement-level status (what's implemented, what's a documented gap and why) stays in `docs/PROJECT_EXECUTION_LEDGER.md`; this file adds the deployment-stage dimension on top.

## WebGuard

| Capability | State | Evidence |
|---|---|---|
| Ten-pillar core (permit, safety receipt, scanner, reporting) | `integration_tested` | Baseline audit + full regression suite, `docs/PRODUCT_VISION_TRACEABILITY.md` |
| Phase A-H tenant-isolation runtime conversion | `integration_tested` | PRs #30-47, proven against real disposable Postgres and CI's own fresh Postgres job |
| RLS+FORCE enforcement | `designed` | Policies defined (`infra/postgres/bootstrap/tenant_isolation_rls_policies.sql`), never enabled; P1-2 stays open on this basis |
| Coverage Truth Map v1 | `integration_tested` | PRs #49-50, real end-to-end production-pipeline assertion in `test_production_mode_e2e.py` |

## SOC

| Capability | State | Evidence |
|---|---|---|
| Everything in section 9 of the handoff | `proposed` | No design or code exists yet beyond this repository-evidence scaffold |

## Compliance

| Capability | State | Evidence |
|---|---|---|
| Everything in section 10 of the handoff | `proposed` | No design or code exists yet beyond this repository-evidence scaffold |

## Platform-shared

| Capability | State | Evidence |
|---|---|---|
| Module entitlement | `designed` | See `docs/adr/0033-platform-expansion-module-boundaries.md`; implementation tracked in `docs/PROJECT_EXECUTION_LEDGER.md` |
| Shared evidence envelope (handoff section 11) | `proposed` | Not started; Coverage Truth Map's own `coverage_records` table is the closest existing precedent for the shape a generalized envelope needs |

## Known risks carried into this expansion

- Every SOC connector needs real Microsoft tenant credentials this project does not have; nothing SOC-related can reach `integration_tested` or later until that access exists.
- Compliance framework packs need authoritative legal-text verification (GDPR/UK GDPR commencement text specifically could not be fully retrieved by the source handoff's own research pass) before any legal claim in a released pack.
- RLS+FORCE activation needs a real, non-disposable environment this session has no standing authorization to provision.

No rollout/rollback plan exists for any SOC/Compliance capability yet, since none has reached a stage where one is needed. This section will gain real rollout/rollback evidence as capabilities reach `staging_validated`.
