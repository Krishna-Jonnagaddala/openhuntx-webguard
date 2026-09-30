-- Module entitlement (product platform expansion, docs/PLATFORM_SCOPE.md
-- and docs/adr/0033-platform-expansion-module-boundaries.md): which of
-- WebGuard, SOC, and Compliance an organization has access to. Module
-- entitlement is separate from data permission (RBAC/ABAC on records
-- inside a module); this table only says whether a module is
-- available to the organization at all.
--
-- One row per (organization_id, module), and every organization is
-- meant to carry exactly three rows at all times, one per module:
-- create_organization inserts all three going forward (webguard
-- enabled, soc and compliance disabled), and this migration backfills
-- the same three rows for every organization that already existed.
-- A missing row is a defect to fail closed against, not a state
-- application code is meant to rely on meaning "disabled": explicit
-- rows for every module keep "no decision made yet" indistinguishable
-- from nothing (it cannot happen) and "explicitly disabled" (a real,
-- recorded row) from being silently conflated.
CREATE TABLE module_entitlements (
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    module TEXT NOT NULL
        CHECK (module IN ('webguard', 'soc', 'compliance')),
    status TEXT NOT NULL
        CHECK (status IN ('enabled', 'disabled', 'trial')),
    updated_at TIMESTAMPTZ NOT NULL,
    enabled_at TIMESTAMPTZ,
    enabled_by UUID REFERENCES principals(principal_id),
    disabled_at TIMESTAMPTZ,
    disabled_by UUID REFERENCES principals(principal_id),
    PRIMARY KEY (organization_id, module)
);

CREATE INDEX idx_module_entitlements_organization
    ON module_entitlements (organization_id);

-- Backfill: WebGuard access must not silently change for any
-- organization that existed before module entitlement did, and every
-- organization gets explicit soc/compliance rows too so no later
-- reader has to guess what a missing row would have meant.
INSERT INTO module_entitlements (organization_id, module, status, updated_at, enabled_at)
SELECT organization_id, 'webguard', 'enabled', created_at, created_at
FROM organizations;

INSERT INTO module_entitlements (organization_id, module, status, updated_at)
SELECT organization_id, 'soc', 'disabled', created_at
FROM organizations;

INSERT INTO module_entitlements (organization_id, module, status, updated_at)
SELECT organization_id, 'compliance', 'disabled', created_at
FROM organizations;
