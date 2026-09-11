# Implementation Status

Snapshot of the four product layers (mandate §2 scope contract), as of commit `da5da852919bcde2f8773c6cf6eae4d393734c71`, 2026-09-11. Cross-references `docs/PRODUCT_VISION_TRACEABILITY.md` (pillar-level) and `docs/PROJECT_EXECUTION_LEDGER.md` (requirement-level). Do not duplicate detail already tracked there; this file is the layer-level rollup.

## WebGuard scanner

Transport safety, discovery, crawling, passive analysis (headers/cookies/CORS/disclosure/HTML/TLS), and bounded active checks (per `docs/CWE_COVERAGE.md`) are implemented per the accepted baseline audit ("WHAT IS GENUINELY COMPLETE": Scanner v1's detector suite, IDOR regression guard). Active-detection phases 1-10 have dedicated audit records (`docs/audit/active-detection-phase*.md`) not re-read in this pass — treat as historical evidence pending reconciliation, not re-verified here.

Not yet built: standardized `SecurityCheck` interface, common evidence model, check/scanner-engine versioning for reproducibility (`docs/ROADMAP.md`'s "Detection architecture and CWE coverage" section — planned, not built).

## TrustScan

Permit (Ed25519, KMS path), runtime safety boundary, and Safety Receipt v1 are implemented and tested (baseline audit, `docs/PRODUCT_VISION_TRACEABILITY.md` pillars 1/2/4). CloudHSM path is code-complete, hardware-unverified (P1-9, `BLOCKED_EXTERNAL`). Signature-algorithm self-reporting gap open (P1-7, `NOT_STARTED`).

## Assessment assurance

Coverage Truth Map, tamper-evident Assessment Ledger, verifiable remediation evidence, and standards exports (OSCAL/SARIF/CycloneDX-VEX) are all `NOT_STARTED` (confirmed by repository search, `docs/PRODUCT_VISION_TRACEABILITY.md` pillars 5-8). Native JSON/HTML/PDF reporting exists.

This is the layer with the largest gap between vision and code. Per the Competitive Research document's own recommendation, this is also the highest-leverage differentiation work once Phase H/P1-2 close — not before, since coverage/evidence claims about a system whose tenant isolation isn't runtime-enforced would be premature.

## Enterprise control plane

Identity, organizations, RBAC, scoped API tokens, PostgreSQL schema/migrations, job queue, worker leases, scheduler, callback registration are implemented (baseline audit "WHAT IS GENUINELY COMPLETE"). Tenant-isolation data-layer plumbing (Phase A-G) is `VERIFIED` at the dormant-policy level; runtime conversion (Phase H) is `IN_PROGRESS` (inventory only, see ledger). Frontend exists and is described as complete for current backend-supported workflows per prior audit passes — not independently re-verified pixel-by-pixel in this session.

## Open P1 findings (all layers)

See `docs/PROJECT_EXECUTION_LEDGER.md` for the authoritative row-level status of P1-2, P1-6, P1-7, P1-8, P1-9, P1-12-R1. Total open: 6, verified against the mutable tracker directly.

## What this document is not

Not a replacement for `docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md` (authoritative vulnerability status) or `docs/ROADMAP.md` (product-facing planned-vs-implemented language). This is an internal engineering rollup for continuation across sessions.
