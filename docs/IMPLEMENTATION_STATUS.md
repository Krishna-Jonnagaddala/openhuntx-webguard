# Implementation Status

Snapshot of the four product layers (mandate §2 scope contract), as of commit `9df82b0498f5ffda35b9c43d81ea5750e5aea294`, 2026-09-12. Cross-references `docs/PRODUCT_VISION_TRACEABILITY.md` (pillar-level) and `docs/PROJECT_EXECUTION_LEDGER.md` (requirement-level). Do not duplicate detail already tracked there; this file is the layer-level rollup.

## WebGuard scanner

Transport safety, discovery, crawling, passive analysis (headers/cookies/CORS/disclosure/HTML/TLS), and bounded active checks (per `docs/CWE_COVERAGE.md`) are implemented per the accepted baseline audit ("WHAT IS GENUINELY COMPLETE": Scanner v1's detector suite, IDOR regression guard). Active-detection phases 1-10 have dedicated audit records (`docs/audit/active-detection-phase*.md`) not re-read in this pass — treat as historical evidence pending reconciliation, not re-verified here.

Not yet built: standardized `SecurityCheck` interface, common evidence model, check/scanner-engine versioning for reproducibility (`docs/ROADMAP.md`'s "Detection architecture and CWE coverage" section — planned, not built).

## TrustScan

Permit (Ed25519, KMS path), runtime safety boundary, and Safety Receipt v1 are implemented and tested (baseline audit, `docs/PRODUCT_VISION_TRACEABILITY.md` pillars 1/2/4). CloudHSM path is code-complete, hardware-unverified (P1-9, `BLOCKED_EXTERNAL`). Signature-algorithm self-reporting gap closed (P1-7, `VERIFIED`): the algorithm field is now derived from the active provider, not a hardcoded literal.

## Assessment assurance

**Correction, 2026-09-15**: this section's "Coverage Truth Map... NOT_STARTED" line above is stale; it was already wrong before this correction (Coverage Truth Map v1 shipped in PRs #49-50, per `docs/PROJECT_EXECUTION_LEDGER.md`'s own "Coverage Truth Map" sections and `docs/PRODUCT_VISION_TRACEABILITY.md` pillar 5), and is now further out of date: Phase 4 (2026-09-15) added a tenant-scoped, paginated read API (`GET /v1/assets/{id}/coverage`) and a minimal frontend view. Tamper-evident Assessment Ledger, verifiable remediation evidence, and standards-interop exports (OSCAL/SARIF/CycloneDX-VEX) remain `NOT_STARTED`. Native JSON/HTML/PDF reporting exists.

## Compliance (added 2026-09-15, was previously not its own section here)

Framework/master-control catalog, scoped control implementation (applicability), and the technical assertion catalog exist and are Postgres-integration-tested (PRs #54/#56/#58). Phase 5 (2026-09-15) added the first genuinely *executed* Compliance signal: `technical_assertion_collections`, a tenant-scoped collection-attempt-and-evaluation record, with real evaluation logic for one assertion (`entra_conditional_access_policy_mode`) against fixture or manually-supplied evidence, never a live vendor read. No service/HTTP/CLI surface yet, matching this stage's own established Compliance pattern (`module_entitlements`/`compliance_scope` have none either). See `docs/PROJECT_EXECUTION_LEDGER.md`'s own Phase 4/5 sections for the full record.

This is the layer with the largest gap between vision and code. Per the Competitive Research document's own recommendation, this is also the highest-leverage differentiation work now that Phase H's runtime conversion is complete: coverage/evidence claims about a system whose tenant isolation isn't runtime-enforced would have been premature before; RLS itself still isn't `FORCE`-enabled in any real environment, so this work can proceed in parallel with that separate, infrastructure-gated activation, not blocked by it.

## Enterprise control plane

Identity, organizations, RBAC, scoped API tokens, PostgreSQL schema/migrations, job queue, worker leases, scheduler, callback registration are implemented (baseline audit "WHAT IS GENUINELY COMPLETE"). Tenant-isolation data-layer plumbing (Phase A-G) is `VERIFIED` at the dormant-policy level; runtime conversion (Phase H) is `IMPLEMENTED_UNVERIFIED`: all 13 `postgres_*.py` repository files converted and proven against a real disposable Postgres (PRs #30-#47), 9 documented gaps remaining where no correct role/grant exists yet, RLS+`FORCE` activation in a real environment not started. Frontend exists and is described as complete for current backend-supported workflows per prior audit passes, not independently re-verified pixel-by-pixel in this session.

## Open P1 findings (all layers)

See `docs/PROJECT_EXECUTION_LEDGER.md` for the authoritative row-level status of P1-2, P1-8, P1-9, P1-12-R1. Total open: 4, verified against the mutable tracker directly. P1-6 and P1-7 closed this session.

## What this document is not

Not a replacement for `docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md` (authoritative vulnerability status) or `docs/ROADMAP.md` (product-facing planned-vs-implemented language). This is an internal engineering rollup for continuation across sessions.
