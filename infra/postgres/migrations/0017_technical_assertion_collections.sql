-- Technical assertion collection and evaluation (platform expansion,
-- handoff sections 10.1-10.3; Phase 5 of the 2026-09-14 scope audit's
-- recommended next work: the first genuinely executed Compliance
-- signal, not just a catalog of what could be checked).
--
-- This is genuinely tenant data (organization_id present), unlike
-- frameworks/master_controls/technical_assertions (all global
-- reference data or code-level registries with no table of their
-- own). One row per collection attempt, not one row per (organization,
-- assertion): an organization can and will re-collect the same
-- assertion over time, and each attempt's own evidence, status, and
-- outcome must stay distinct and queryable, the same "history, not a
-- single mutable current-state row" reasoning finding_events already
-- established for findings.
--
-- assertion_id is validated against TECHNICAL_ASSERTION_REGISTRY in
-- application code (assertion_collections.py), not an FK: the
-- registry is a static, code-level catalog with no table of its own,
-- the same shape SOC_CONNECTOR_REGISTRY/ACTIVE_DETECTOR_REGISTRY
-- already use. assertion_version is captured at collection time and
-- never updated afterward, even if the registry's own assertion later
-- changes version: a collection row is evidence of what was true when
-- it ran, under the assertion logic that existed then, not a live
-- view that silently reinterprets old evidence under new logic.
--
-- collection_status='failed' rows carry collection_error and no
-- evidence/outcome at all (collection failed, so there is nothing to
-- evaluate). collection_status='succeeded' rows always carry
-- raw_evidence, outcome, and evaluated_at together: evaluation is
-- synchronous with collection in this version (see
-- assertion_collections.py's own collect_and_evaluate docstring).
CREATE TABLE technical_assertion_collections (
    collection_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    assertion_id TEXT NOT NULL,
    assertion_version TEXT NOT NULL,
    evidence_source TEXT NOT NULL
        CHECK (evidence_source IN ('fixture', 'manual')),
    evidence_provenance TEXT NOT NULL,
    collection_status TEXT NOT NULL
        CHECK (collection_status IN ('succeeded', 'failed')),
    collection_error TEXT,
    raw_evidence JSONB,
    outcome TEXT
        CHECK (outcome IN ('satisfied', 'violated', 'indeterminate', 'not_tested')),
    outcome_detail TEXT,
    collected_by UUID NOT NULL REFERENCES principals(principal_id),
    collected_at TIMESTAMPTZ NOT NULL,
    evaluated_at TIMESTAMPTZ,
    CONSTRAINT technical_assertion_collections_failed_has_no_evidence CHECK (
        (collection_status = 'failed' AND raw_evidence IS NULL AND outcome IS NULL AND evaluated_at IS NULL)
        OR (collection_status = 'succeeded' AND raw_evidence IS NOT NULL AND outcome IS NOT NULL AND evaluated_at IS NOT NULL)
    ),
    CONSTRAINT technical_assertion_collections_failed_has_error CHECK (
        (collection_status = 'failed' AND collection_error IS NOT NULL)
        OR (collection_status = 'succeeded' AND collection_error IS NULL)
    )
);

CREATE INDEX idx_technical_assertion_collections_org_assertion
    ON technical_assertion_collections (organization_id, assertion_id, collected_at DESC);
