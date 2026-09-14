# Product Vision Traceability

Maps each of the ten OpenHuntX vision pillars (per the Claude Master Completion Mandate, 2026-09-11) to actual verified implementation state. Status values: NOT_STARTED, IN_PROGRESS, IMPLEMENTED_UNVERIFIED, VERIFIED, BLOCKED_EXTERNAL, DEFERRED_WITH_REASON.

This document reflects code found by direct repository inspection at commit `9df82b0498f5ffda35b9c43d81ea5750e5aea294`, not the mandate's own summary of it. Update it when a pillar's real status changes; do not let it drift back into aspiration.

## 1. Cryptographic Scan Permit

**Status: VERIFIED (core), IN_PROGRESS (schema evolution)**

`apps/api/src/webguard_api/permits.py`, `signing.py`. TrustScan Scan Permit v1 is Ed25519-signed, immutably bound to a job, with runtime re-validation at execution time (baseline audit: "TrustScan permit authorization (schema, binding, signing, execution-time re-validation — proven twice, not once)"). KMS signing path is complete and tested; CloudHSM path is code-complete but hardware-unverified (P1-9, open).

Not yet done: versioned schema evolution for amendments-as-new-revisions (mandate §12), explicit delegated-authority modeling distinct from domain-control verification.

## 2. Per-action authorization enforcement

**Status: IMPLEMENTED_UNVERIFIED (runtime boundary and data-layer wiring)**

`safety.py` is the network-boundary gate all execution paths pass through today. The A-G PostgreSQL work (tenant roles, ACLs, function-owner capabilities, dormant RLS policies) defines the data-layer half of this pillar; Phase H (see `docs/PROJECT_EXECUTION_LEDGER.md`) wires it into the live request/worker/scheduler/callback paths and is now complete across all 13 repository files, proven against a real disposable Postgres. The remaining gap is RLS itself: policies are defined but not `FORCE`-enabled in any real, non-disposable environment, so this pillar is not yet VERIFIED end to end.

## 3. Scanner execution attestation

**Status: NOT_STARTED**

No `attestation` symbol, no build-provenance binding of scanner version/binary digest/rule pack/policy to an execution record. Confirmed by repository search, not assumed.

## 4. Runtime Safety Receipt

**Status: IMPLEMENTED_UNVERIFIED**

`safety.py` produces a Safety Receipt bound to permit/job with observed limits, throttling, and termination reasons. Circuit-breaker threshold and persistence-schema variants disagree across archived ADR 0027 copies (mandate §3) — current code/tests are the source of truth, not yet reconciled against the ADR text in this pass.

## 5. Coverage Truth Map

**Status: IMPLEMENTED_UNVERIFIED (v1)**

`coverage_records` (migration 0013), `postgres_coverage.py`, wired into `executor.py`, shipped PRs #49-50. Populates three of the vision's six states (completed, blocked, unreachable) for the base passive/analyzer check plan, keyed by (organization_id, asset, path, http_method, identity_label, check_id). `discovered` and `authorized` are not populated: no current signal distinguishes them without either guessing or building new tracking (individual discovered-URL tracking, a resolved per-operation authorization boundary) that doesn't exist yet. `identity_label` is always "unauthenticated": active-detection, authorization-comparison, and SSRF-callback findings carry no identity field to attribute coverage to. No API/report surface yet, by confirmed scope decision. See `docs/PROJECT_EXECUTION_LEDGER.md`'s "Coverage Truth Map" sections for the full discovery and implementation record.

## 6. Tamper-evident Assessment Ledger

**Status: NOT_STARTED**

No append-only event ledger linking permit issuance/amendment/revocation → execution → findings → remediation → retest. Zero matching symbols in the repository.

## 7. Verifiable remediation evidence

**Status: NOT_STARTED**

No signed remediation record, no retest-comparability model (verified-fixed / still-reproducible / not-reproducible-under-changed-conditions / mitigated / accepted-risk / inconclusive). Existing finding lifecycle (`postgres_findings.py`) has status transitions but not this evidentiary binding.

## 8. Standards-based assessment exports

**Status: NOT_STARTED (OSCAL/SARIF/CycloneDX-VEX), IMPLEMENTED_UNVERIFIED (native reports)**

Native JSON/HTML/PDF reporting exists (`reporting.py`, `report_loader.py`, baseline audit: "object-storage-backed report generation/download with real integrity verification"). No OSCAL, SARIF, GitHub/GitLab/Jira issue export, or CycloneDX-VEX exporter found.

## 9. Versioned cloud rules-of-engagement policy packs/compiler

**Status: NOT_STARTED**

Zero matching symbols (`policy_pack`, rules-of-engagement modeling, provider-specific permission compiler). Roadmap-only today (`docs/ROADMAP.md`'s "Coverage growth" section gestures at this without a design).

## 10. Data-sovereignty controls and customer-hosted execution

**Status: NOT_STARTED**

Zero matching symbols (region binding, regional key custody, customer-hosted runner enrollment). Roadmap-only ("Control-plane and runner separation" section).

## Summary table

| Pillar | Status |
|---|---|
| 1. Cryptographic Scan Permit | VERIFIED (core) / IN_PROGRESS (schema evolution) |
| 2. Per-action authorization enforcement | IMPLEMENTED_UNVERIFIED (Phase H wiring complete; RLS+FORCE not yet real-environment activated) |
| 3. Scanner execution attestation | NOT_STARTED |
| 4. Runtime Safety Receipt | IMPLEMENTED_UNVERIFIED |
| 5. Coverage Truth Map | IMPLEMENTED_UNVERIFIED (v1: 3 of 6 states, unauthenticated only, no API surface) |
| 6. Tamper-evident Assessment Ledger | NOT_STARTED |
| 7. Verifiable remediation evidence | NOT_STARTED |
| 8. Standards-based assessment exports | NOT_STARTED (interop) / IMPLEMENTED_UNVERIFIED (native) |
| 9. Rules-of-engagement policy packs | NOT_STARTED |
| 10. Data-sovereignty / customer-hosted execution | NOT_STARTED |

Full-vision completion requires all ten at VERIFIED. A release candidate does not require this; see `docs/RELEASE_READINESS.md` for the separate release-scope gate.

## Platform expansion: SOC and Compliance (added 2026-09-12)

The ten pillars above remain WebGuard's own vision and are unaffected by this expansion. OpenHuntX is now a three-module platform (WebGuard, SOC, Compliance); see `docs/PLATFORM_SCOPE.md` for the module contract and `docs/audit/OPENHUNTX_THREE_MODULE_PLATFORM_HANDOFF_2026-09.md` for the full supplied design document, including its complete source disposition register (every numbered SOC and Compliance source section, S-01 through S-53 and C-01 through C-84, with a retain/revise/defer/integrate disposition and a binding recommendation). That register is not duplicated here; this file tracks implementation status as SOC/Compliance work actually lands, the handoff tracks the original design intent.

**SOC (handoff section 9): IN_PROGRESS.** Two of three Microsoft-first connector manifests are contract-designed (Entra, Defender XDR; see `docs/CONNECTOR_CAPABILITIES.md`), each with permissions verified against Microsoft's own current documentation. Sentinel's manifest, any live HTTP client, query and detection engineering, ProofLoop scenario validation, AI-assisted investigation, and Response Guard governed actions remain not designed or built.

**Compliance (handoff section 10): IN_PROGRESS.** The framework/master-control catalog is built (5 seeded placeholder frameworks, zero real control content, `docs/adr/0034-compliance-catalog-is-global-reference-data.md`), and the first of section 10.2's status dimensions, applicability, is built as the first tenant-scoped Compliance record (`webguard_contracts.compliance_scope.ScopedControlImplementation`). The other six status dimensions (collection, test execution, assertion, control assessment, treatment, assurance review), the initial ~40-60 technical assertion catalogue, and governance/privacy/vendor/audit workflows remain not designed or built.

**Platform-shared (handoff section 7): module entitlement designed** (`docs/adr/0033-platform-expansion-module-boundaries.md`); the generalized evidence envelope, assurance-relationship graph, and cross-module event bus remain proposed.

Neither module may be marketed, badged, or reported as available, in beta, or in any deployed state until its own row here says otherwise. `docs/RELEASE_EVIDENCE.md` tracks the deployment-stage dimension for each capability as it's built.
