# Architecture Decisions

This project records architecture decisions as individual, numbered files in `docs/adr/` (one file per decision, e.g. `docs/adr/0026-trustscan-cryptographic-scan-permit-v1.md`), not as a single consolidated log. This file exists only because the platform-expansion handoff (`docs/audit/OPENHUNTX_THREE_MODULE_PLATFORM_HANDOFF_2026-09.md`) names `ARCHITECTURE_DECISIONS.md` as an expected record; it is an index into the existing convention, not a competing one.

## Decisions relevant to the SOC/Compliance platform expansion

- [ADR 0033: Platform Expansion Module Boundaries](adr/0033-platform-expansion-module-boundaries.md): shared contracts stay in `webguard_contracts`, operational database stays PostgreSQL with the existing tenant-isolation model, module entitlement is the first shared-contract slice, new tenant tables get the same ACL/role/RLS review WebGuard tables already have, and domain objects (finding/incident/risk/audit finding) stay distinct types linked through one shared relationship graph rather than collapsed into a generic status enum.

See `docs/adr/` for the full numbered history, including the WebGuard-era decisions this expansion builds on (identity and RBAC, tenant isolation phases, TrustScan permit and safety-receipt design, CI security gates, and others).
