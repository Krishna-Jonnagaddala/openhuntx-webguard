-- Compliance's first tenant-scoped table (platform expansion,
-- docs/PLATFORM_SCOPE.md, handoff section 10.1-10.2). frameworks and
-- master_controls (0015) are global reference data shared by every
-- organization; this table is the opposite: one row per organization
-- per control, recording that specific tenant's own applicability
-- decision. See webguard_contracts.compliance_scope's module
-- docstring for why applicability is modeled as three distinct
-- states rather than a boolean, and why two of them require an
-- attributed human decision.
--
-- framework_id is deliberately NOT a column here: control_id already
-- uniquely determines its framework via master_controls' own FK, and
-- storing a second, independent copy of that fact would let this
-- table silently disagree with the catalog it depends on. A reader
-- that needs framework_id joins to master_controls; see
-- postgres_compliance_scope.py.
CREATE TABLE scoped_control_implementations (
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    control_id TEXT NOT NULL REFERENCES master_controls(control_id),
    applicability_status TEXT NOT NULL
        CHECK (applicability_status IN ('applicable', 'not_applicable_with_rationale', 'unresolved')),
    rationale TEXT,
    decided_by UUID REFERENCES principals(principal_id),
    decided_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, control_id),
    CONSTRAINT scoped_control_implementations_unresolved_is_undecided CHECK (
        (applicability_status = 'unresolved' AND rationale IS NULL AND decided_by IS NULL AND decided_at IS NULL)
        OR (applicability_status <> 'unresolved' AND decided_by IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CONSTRAINT scoped_control_implementations_not_applicable_has_rationale CHECK (
        applicability_status <> 'not_applicable_with_rationale' OR rationale IS NOT NULL
    )
);

CREATE INDEX idx_scoped_control_implementations_organization
    ON scoped_control_implementations (organization_id);
