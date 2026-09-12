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

**Status: NOT_STARTED**

No coverage model separating discovered/authorized/attempted/completed/blocked/unreachable per (asset, operation, identity, test class, version). `crawl_scans.py`/`reporting.py` track scan-level progress, not this. This is the mandate's own recommended first differentiator (Competitive Research §"Three priorities") and is unbuilt.

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
| 5. Coverage Truth Map | NOT_STARTED |
| 6. Tamper-evident Assessment Ledger | NOT_STARTED |
| 7. Verifiable remediation evidence | NOT_STARTED |
| 8. Standards-based assessment exports | NOT_STARTED (interop) / IMPLEMENTED_UNVERIFIED (native) |
| 9. Rules-of-engagement policy packs | NOT_STARTED |
| 10. Data-sovereignty / customer-hosted execution | NOT_STARTED |

Full-vision completion requires all ten at VERIFIED. A release candidate does not require this; see `docs/RELEASE_READINESS.md` for the separate release-scope gate.
