# ADR 0034: Compliance Catalog Is Global Reference Data

- Status: Accepted
- Date: 2026-09-12
- Source: `docs/audit/OPENHUNTX_THREE_MODULE_PLATFORM_HANDOFF_2026-09.md` section 10.1

## Context

Every table this project has ever had is tenant-scoped: an `organization_id` column, a tenant-isolation role, an eventual RLS policy, following the pattern Phase A-H built and proved. Building the Compliance framework/control catalog (handoff section 10.1: "versioned framework requirements, master controls, scoped implementations, assertions/tests, evidence and mappings") needed a decision before any schema could be written: is a framework's own definition (its name, version, and controls) tenant data, or something else?

## Decision

`frameworks` and `master_controls` are global reference data, not tenant data. A framework's own requirements (what SOC 2's Trust Services Criteria say, what ISO/IEC 27001:2022's Annex A controls are) are identical for every organization; there is nothing to isolate per tenant at this layer. This mirrors how `docs/CWE_COVERAGE.md`'s CWE registry, or MITRE ATT&CK's own technique catalog, are shared reference data a finding or a detection cites, not something copied per customer.

This is the first table in this schema with no `organization_id` at all. Consequences follow directly:

- No tenant-isolation role (`api_tenant_data`/`worker_tenant_data`/`scheduler_tenant_data`) applies in the usual sense, since there is no tenant context to set. Reads run under `api_tenant_data` via `role_scoped_connection` (role-only, no GUC), the same "no tenant to scope by" treatment `postgres_identity.py`'s `get_principal` and similar no-organization-id methods already use, chosen over inventing a new role category for a single read-only table.
- Writes (adding a framework or a control to the catalog) are an OpenHuntX-operator concern, not a customer-facing one: no organization ever creates or edits a framework definition. Writes stay on the unrestricted connection, mirroring `postgres_identity.py`'s `assign_authorization`/`revoke_token` precedent for CLI/operator-only methods with no live API-serve-process caller.
- No RLS policy is needed or will be added for these two tables. RLS exists to enforce tenant isolation; there is no tenant boundary here to enforce.

The distinct, tenant-scoped concept, "how is this specific organization doing against this control" (an implementation record, an assertion result, linked evidence), is explicitly not built in this slice. That is real tenant data and will need the full Phase-H-style tenant-isolation treatment when it is built, unlike the catalog itself.

## Content policy

No framework's real, legally-reviewed control content ships in this slice. `docs/PLATFORM_SCOPE.md` records legal-text verification as an open blocker for every framework pack (SOC 2, ISO/IEC 27001:2022 plus its 2024 amendment, HIPAA, GDPR, UK GDPR). `FrameworkStatus.PLACEHOLDER` lets a framework's own row exist, named and cited to its authoritative source, with zero `master_controls` rows under it: an honest "we intend to support this, we have not loaded reviewed content yet" rather than either no row at all or fabricated control text standing in for real legal review.

ISO/IEC 27001:2022's 2024 amendment is modeled as part of the same framework row's own `version` field (e.g. "2022 plus 2024 amendment"), not a second `framework_id`, per the handoff's own explicit instruction against duplicate counting. A real overlay/delta mechanism (tracking which specific controls the amendment changed) is deferred to whenever real ISO content is actually loaded, since that mechanism cannot be designed honestly without the real amendment text in hand.

## Consequences

A future PR building tenant-scoped control implementations/assertions/evidence must not retrofit `organization_id` onto `frameworks`/`master_controls` themselves; it adds new, separate, tenant-scoped tables that reference these by `framework_id`/`control_id`, the same "distinct linked domain objects" principle ADR 0033 already established for findings/incidents/risks. If a genuine need for organization-specific framework customization ever appears (a customer wanting to redefine a control's own text), that is a new, explicit decision requiring its own ADR, not a silent column addition here.
