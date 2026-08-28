-- Slice 12 requirement 4/10: full production schema for the remaining
-- entities the brief lists "at minimum" -- jobs, schedules, scan
-- records, findings, reports metadata, authentication contexts,
-- authorization-comparison plans, and crawl checkpoints. This slice
-- deliberately builds schema only, no Python repository classes: see
-- docs/audit/production-platform-phase1-postgres-kms-tenancy.md
-- "Known limitations" for why (requirement 17's "do not create an
-- enormous infrastructure stack in one change", applied to schema
-- breadth vs. repository depth rather than to the schema itself,
-- which is cheap to design fully now and expensive to redesign later
-- once real data depends on it).
--
-- Every table still carries organization_id directly per requirement
-- 5, even though nothing queries it yet, so the day a repository is
-- built for one of these tables it does not also require a schema
-- migration to add the tenant-ownership column it should have had
-- from the start.

CREATE TABLE scan_jobs (
    job_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    submitted_by UUID NOT NULL REFERENCES principals(principal_id),
    target TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    cancellation_requested BOOLEAN NOT NULL DEFAULT FALSE,
    submitted_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    scan_id TEXT,
    result_status TEXT,
    report_ref TEXT,
    audit_ref TEXT,
    error_code TEXT,
    error_message TEXT
);

CREATE INDEX idx_scan_jobs_organization
    ON scan_jobs (organization_id, submitted_at DESC);
CREATE INDEX idx_scan_jobs_queue
    ON scan_jobs (state, submitted_at, job_id);

CREATE TABLE scan_schedules (
    schedule_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    created_by UUID NOT NULL REFERENCES principals(principal_id),
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    next_run_at TIMESTAMPTZ NOT NULL,
    last_enqueued_at TIMESTAMPTZ,
    last_job_id UUID,
    last_error_code TEXT,
    last_error_at TIMESTAMPTZ
);

CREATE INDEX idx_scan_schedules_organization
    ON scan_schedules (organization_id, next_run_at);

-- One row per completed/failed scan (crawl or single-page). The
-- report body itself (pages, per-endpoint results) is not modeled
-- relationally here -- it stays a filesystem/object-storage artifact
-- referenced by `report_ref`, matching the existing filesystem-report
-- design; this row is the durable index/summary over those artifacts,
-- which is what a Scans list page actually queries.
CREATE TABLE scan_records (
    scan_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    job_id UUID REFERENCES scan_jobs(job_id),
    target TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    report_ref TEXT
);

CREATE INDEX idx_scan_records_organization
    ON scan_records (organization_id, started_at DESC);

-- Findings carry only what the scanner itself already proves true
-- (fingerprint, CWE/OWASP mapping, evidence) -- no CVSS column exists
-- because no CVSS value is computed anywhere in this codebase
-- (docs/scanner/SCANNER_V1_CAPABILITIES.md is explicit that inventing
-- one would be false precision); adding a column for a value nothing
-- populates would misrepresent the schema's own honesty about what
-- data actually backs it.
CREATE TABLE findings (
    finding_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    scan_id UUID REFERENCES scan_records(scan_id),
    fingerprint TEXT NOT NULL,
    check_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    cwe_id TEXT,
    owasp_category TEXT,
    asset TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    http_method TEXT NOT NULL,
    parameter TEXT,
    scanner_version TEXT NOT NULL,
    check_version TEXT,
    evidence TEXT,
    -- Deliberately no lifecycle UI this slice (requirement 19), but the
    -- status enum is fixed now so future work only ever adds a status
    -- transition, never a column-shape migration for one.
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'confirmed', 'false_positive', 'accepted_risk', 'resolved', 'reopened')),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_findings_organization
    ON findings (organization_id, last_seen_at DESC);
CREATE UNIQUE INDEX idx_findings_fingerprint
    ON findings (organization_id, fingerprint);

CREATE TABLE reports (
    report_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    scan_id UUID REFERENCES scan_records(scan_id),
    title TEXT NOT NULL,
    prepared_by TEXT NOT NULL,
    classification TEXT,
    report_ref TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_reports_organization
    ON reports (organization_id, created_at DESC);

-- Metadata only, matching AuthenticationContextRecord exactly. No
-- credential/secret column exists here on purpose: the in-memory
-- AuthenticationContextRepository already separates secret material
-- from metadata for its own stated reasons (never log/audit/persist a
-- raw credential) -- this table preserves that boundary rather than
-- undoing it just because Postgres exists. When authentication-context
-- secrets do need to survive a restart, they belong in a KMS/secret-
-- manager-adjacent store, not a column on this table.
CREATE TABLE authentication_contexts (
    authentication_context_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    target TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    identity_label TEXT NOT NULL,
    method TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_authentication_contexts_organization
    ON authentication_contexts (organization_id, expires_at);

CREATE TABLE authorization_comparison_plans (
    comparison_plan_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    target TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    primary_context_id UUID NOT NULL,
    secondary_context_id UUID NOT NULL,
    permitted_active_check TEXT NOT NULL,
    allowed_http_methods TEXT[] NOT NULL,
    resource_scope JSONB NOT NULL,
    maximum_resources INTEGER NOT NULL,
    maximum_comparisons INTEGER NOT NULL,
    enable_discovery BOOLEAN NOT NULL DEFAULT FALSE,
    discovery_login_page_marker TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_authorization_comparison_plans_organization
    ON authorization_comparison_plans (organization_id, expires_at);

-- Crawl checkpoints today are filesystem JSON
-- (webguard_contracts.crawl_checkpoints), written for crash/resume
-- recovery of a single in-flight crawl. This table is a placeholder
-- for a future durable-checkpoint story if crawl execution ever moves
-- off a single worker host's local filesystem; nothing writes to it
-- yet, so the column shape is intentionally minimal rather than a
-- full translation of CrawlCheckpoint's much larger in-progress state.
CREATE TABLE crawl_checkpoints (
    checkpoint_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    job_id UUID REFERENCES scan_jobs(job_id),
    checkpoint_ref TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_crawl_checkpoints_job
    ON crawl_checkpoints (job_id, created_at DESC);
