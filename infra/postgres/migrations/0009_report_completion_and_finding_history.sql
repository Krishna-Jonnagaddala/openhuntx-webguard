-- Slice 14 requirement 5: report metadata gains a completion timestamp
-- distinct from creation -- a report can be created in a "generating"
-- state and complete later, mirroring how scan_records separates
-- started_at from completed_at.
ALTER TABLE reports
    ADD COLUMN completed_at TIMESTAMPTZ;

-- Slice 14 requirement 10: append-only finding lifecycle history. The
-- `findings` row itself (Slice 13) carries only the *current* status;
-- this table is the only place "when," "by whom," and "why" a
-- transition happened are preserved. Rows are never updated or
-- deleted by application code -- an incorrect entry is corrected by
-- appending a new one, never by rewriting history.
CREATE TABLE finding_events (
    event_id UUID PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES findings(finding_id),
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    previous_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    reason TEXT,
    changed_by UUID REFERENCES principals(principal_id),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_finding_events_finding
    ON finding_events (finding_id, created_at);

CREATE INDEX idx_finding_events_organization
    ON finding_events (organization_id, created_at DESC);
