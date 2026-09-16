# Implementation Status

Snapshot of the four product layers (mandate §2 scope contract), reconciled against actual repository state at commit `ac82ea38d6e1be9fe882a4a2fba854442cfde10d`, 2026-09-15 (previously snapshotted 2026-09-12, before PRs #52-58 shipped). Cross-references `docs/PRODUCT_VISION_TRACEABILITY.md` (pillar-level) and `docs/PROJECT_EXECUTION_LEDGER.md` (requirement-level). Do not duplicate detail already tracked there; this file is the layer-level rollup.

## WebGuard scanner

Transport safety, discovery, crawling, passive analysis (headers/cookies/CORS/disclosure/HTML/TLS), and bounded active checks (per `docs/CWE_COVERAGE.md`) are implemented per the accepted baseline audit ("WHAT IS GENUINELY COMPLETE": Scanner v1's detector suite, IDOR regression guard). Active-detection phases 1-10 have dedicated audit records (`docs/audit/active-detection-phase*.md`) not re-read in this pass — treat as historical evidence pending reconciliation, not re-verified here.

Not yet built: standardized `SecurityCheck` interface, common evidence model, check/scanner-engine versioning for reproducibility (`docs/ROADMAP.md`'s "Detection architecture and CWE coverage" section — planned, not built).

## TrustScan

Permit (Ed25519, KMS path), runtime safety boundary, and Safety Receipt v1 are implemented and tested (baseline audit, `docs/PRODUCT_VISION_TRACEABILITY.md` pillars 1/2/4). CloudHSM path is code-complete, hardware-unverified (P1-9, `BLOCKED_EXTERNAL`). Signature-algorithm self-reporting gap closed (P1-7, `VERIFIED`): the algorithm field is now derived from the active provider, not a hardcoded literal.

## Assessment assurance

Coverage Truth Map v1 shipped (PRs #49-50): `coverage_records` (migration 0013), `postgres_coverage.py`, wired into `executor.py`, populating 3 of its own 6 vision states (completed/blocked/unreachable; `discovered`/`authorized` need signal that doesn't exist yet). `identity_label` is always `"unauthenticated"` today, an honest reflection of what the executor can currently attribute, not a defect. No API or report surface exists: the table is written on every scan and read by nothing. Tamper-evident Assessment Ledger, verifiable remediation evidence, and standards-interop exports (OSCAL/SARIF/CycloneDX-VEX) remain `NOT_STARTED` (confirmed by repository search, `docs/PRODUCT_VISION_TRACEABILITY.md` pillars 6-8). Native JSON/HTML/PDF reporting exists.

This is still the layer with the largest gap between vision and code, even after Coverage Truth Map v1. Per the OpenHuntX Scope & Progress Audit (2026-09-14), exposing Coverage Truth Map's already-built, already-tested data through a read API and a minimal frontend view is the recommended next slice: no new infrastructure, no new authorization, and it converts an existing backend capability into something a user could actually see.

## Enterprise control plane

Identity, organizations, RBAC, scoped API tokens, PostgreSQL schema/migrations, job queue, worker leases, scheduler, callback registration are implemented (baseline audit "WHAT IS GENUINELY COMPLETE"). Tenant-isolation data-layer plumbing (Phase A-G) is `VERIFIED` at the dormant-policy level; runtime conversion (Phase H) is `IMPLEMENTED_UNVERIFIED`: all 13 `postgres_*.py` repository files converted and proven against a real disposable Postgres (PRs #30-#47), 9 documented gaps remaining where no correct role/grant exists yet, RLS+`FORCE` activation in a real environment not started. Frontend exists and is described as complete for current backend-supported workflows per prior audit passes, not independently re-verified pixel-by-pixel in this session.

## Open P1 findings (all layers)

See `docs/PROJECT_EXECUTION_LEDGER.md` for the authoritative row-level status of P1-2, P1-8, P1-9, P1-12-R1, and P1-13. Total open: **5**, verified against the mutable tracker directly. P1-6 and P1-7 closed earlier. P1-13 (object storage's own tenant-isolation posture, distinct from the P1-1/P1-2 Postgres findings) was newly identified by the OpenHuntX Scope & Progress Audit (2026-09-14), independent of the original August baseline; it is not a residual of any existing finding, so it takes a fresh ID rather than an `-R` suffix.

## Enterprise expansion (SOC and Compliance)

Not one of the mandate's original four layers, added by the 2026-09-12 platform expansion decision (`docs/PLATFORM_SCOPE.md`). Module entitlement is implemented and tested (migration 0014). SOC has three contract-designed connector manifests (Entra, Defender XDR, Sentinel; zero live HTTP clients by design, blocked on real Microsoft tenant credentials). Compliance has a framework/master-control catalog (5 seeded placeholder frameworks, zero real control content), the first of seven status dimensions built (applicability, as a tenant-scoped record), and a technical assertion catalog (5 assertions, code-level, nothing executed against any of them yet). No code path connects either module to WebGuard's own findings/scans in either direction. See `docs/RELEASE_EVIDENCE.md` for per-capability deployment-stage detail.

## What this document is not

Not a replacement for `docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md` (authoritative vulnerability status) or `docs/ROADMAP.md` (product-facing planned-vs-implemented language). This is an internal engineering rollup for continuation across sessions.
