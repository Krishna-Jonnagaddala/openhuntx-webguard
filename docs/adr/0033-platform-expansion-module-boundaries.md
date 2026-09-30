# ADR 0033: Platform Expansion Module Boundaries

- Status: Accepted
- Date: 2026-09-12
- Source: `docs/audit/OPENHUNTX_THREE_MODULE_PLATFORM_HANDOFF_2026-09.md`

## Context

The owner approved expanding OpenHuntX from WebGuard alone into three modules: WebGuard, SOC, and Compliance (`docs/PLATFORM_SCOPE.md`). The supplied handoff document specifies a shared architecture (its own section 7): one shared entity identity and evidence system, separate domain views and permissions per module, no forcing high-volume SOC telemetry into the operational PostgreSQL tables, and no graph database, Kafka, or microservices adopted merely because the brief uses the word "enterprise."

Several concrete implementation choices need a decision before any SOC- or Compliance-specific code is written, since getting them wrong early is expensive to unwind across many future PRs.

## Decisions

### Shared contracts stay in `webguard_contracts` for now

New cross-module entities (module entitlement, and later shared evidence/authority types) are added to the existing `packages/contracts/python/src/webguard_contracts` package rather than a new `openhuntx_contracts` package. Renaming the package is a pure mechanical refactor touching every import across the codebase, with zero functional benefit on its own and real risk of merge conflicts against ongoing WebGuard work. Nothing in the handoff mandates a package rename; it specifies domain-level module boundaries, not a Python package boundary. Revisit this once SOC/Compliance-specific contracts genuinely outnumber WebGuard ones, since at that point the package name would actively mislead a new reader.

### Operational database stays PostgreSQL; no new infrastructure yet

WebGuard's existing tenant-scoped PostgreSQL schema, role-based tenant isolation (Phase A-H), and worker-pool execution model extend to SOC and Compliance control-plane entities. High-volume SOC telemetry (raw security events at SIEM scale) does not belong in these operational tables; a separately selected telemetry query/storage engine is deferred until measured scale, retention, and query patterns justify a specific choice, per the handoff's own explicit instruction against speculative infrastructure. Nothing beyond ordinary PostgreSQL tables, the existing worker-pool pattern, and object storage (already used for WebGuard reports) is introduced by this decision.

### Module entitlement is the first shared-contract slice

Before any SOC- or Compliance-specific feature table exists, an organization needs a durable record of which modules it has access to (`module_entitlements`, `apps/api/src/webguard_api/postgres_module_entitlements.py`). This is deliberately small and connector-independent: it needs no external credentials, blocks nothing else architecturally, and both SOC and Compliance depend on it for navigation and data-access gating (handoff section 13: "Module entitlement is separate from data permission"). Every existing organization is backfilled with WebGuard enabled at migration time, since WebGuard access must not silently change for any current tenant; SOC and Compliance start disabled for every organization and require an explicit grant.

### New tenant tables get the same tenant-isolation treatment WebGuard tables already have

Every new SOC/Compliance table needs its own reviewed ACL grants, its own role-scoping decision (which of `api_tenant_data`/`worker_tenant_data`/`scheduler_tenant_data`, or new module-specific roles if the access pattern genuinely differs), and its own RLS policy once Phase H's own runtime-conversion methodology reaches it, mirroring exactly the process `docs/PROJECT_EXECUTION_LEDGER.md`'s Phase H sections document for WebGuard's own 13 repository files. The historical count of 94 RLS policies is not a target; it is what existed for WebGuard's own tables before this expansion, and SOC/Compliance tables need their own count, decided by their own actual schema, not by matching that number.

### Domain objects stay distinct; only relationships are shared

A vulnerability, an incident, a risk, and an audit finding remain four separate domain object types with their own state machines, even though they all participate in one shared assurance-relationship graph (handoff section 7: "typed, dated links between claims, observations, assets, findings, incidents, controls and remediation"). No shared code should ever collapse these into one generic "item" or "status" table; that would make it impossible to express, for example, that a scanner finding is not automatically an incident, and an incident is not automatically a failed legal requirement, both explicit acceptance requirements from the handoff.

## Consequences

Every future SOC/Compliance PR in this arc should be checked against this ADR before adding a new table, a new package, or a new piece of infrastructure: does it belong in the existing PostgreSQL schema under the existing tenant-isolation model, using the existing `webguard_contracts` package, linked into the shared assurance-relationship graph rather than a bespoke status enum? If a genuine reason exists to deviate (a real measured need for a different storage engine, a real need for a second contracts package), that deviation gets its own ADR, not a silent departure from this one.
