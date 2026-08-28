-- Slice 13: promotes the deferred `scan_jobs` and `scan_records`
-- schema (Slice 12, schema-only) to full parity with the SQLite
-- `ScanJobStore`'s real lifecycle -- optimistic-concurrency `revision`
-- counter, fenced worker leases (worker_id + lease_token +
-- lease_expires_at), idempotent submission, and TrustScan permit
-- binding. This is an ALTER, not a rewrite: nothing depended on the
-- Slice 12 schema-only shape (no Python repository ever wrote to it),
-- so widening it here is safe.

ALTER TABLE scan_jobs
    ADD COLUMN idempotency_key TEXT,
    ADD COLUMN request_fingerprint TEXT,
    ADD COLUMN authorization_sha256 TEXT,
    ADD COLUMN worker_id TEXT,
    ADD COLUMN lease_token TEXT,
    ADD COLUMN lease_expires_at TIMESTAMPTZ,
    ADD COLUMN heartbeat_at TIMESTAMPTZ,
    ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;

-- Idempotent submission (requirement 14): a retried submission with
-- the same idempotency key must return the original job, never create
-- a second one. NULL keys are permitted to coexist (a job submitted
-- without an idempotency key), matching Postgres's standard "NULLs
-- are distinct" unique-index behavior.
CREATE UNIQUE INDEX idx_scan_jobs_idempotency_key
    ON scan_jobs (idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- The lease-recovery scan (requirement 4: "lease expires -> second
-- worker attempts claim") filters on exactly this predicate.
CREATE INDEX idx_scan_jobs_lease_expiry
    ON scan_jobs (state, lease_expires_at)
    WHERE state = 'running';

-- The claim query (requirement 3) filters on exactly this predicate,
-- ordered oldest-first.
CREATE INDEX idx_scan_jobs_claimable
    ON scan_jobs (submitted_at, job_id)
    WHERE state = 'queued';

-- TrustScan permits (requirement 2: "permit identity/reference" on
-- scans, without duplicating raw signature material beyond what the
-- permit itself already is -- this table stores the permit exactly
-- once; jobs/scans reference it by ID + fingerprint, never re-embed
-- its signed document).
CREATE TABLE scan_permits (
    permit_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    authorization_id TEXT NOT NULL,
    authorization_sha256 TEXT NOT NULL,
    target TEXT NOT NULL,
    issued_by UUID NOT NULL REFERENCES principals(principal_id),
    issued_at TIMESTAMPTZ NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    permit_sha256 TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    document_json JSONB NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES principals(principal_id)
);

CREATE INDEX idx_scan_permits_organization
    ON scan_permits (organization_id, issued_at DESC);

CREATE TABLE job_permits (
    job_id UUID PRIMARY KEY REFERENCES scan_jobs(job_id),
    permit_id UUID NOT NULL REFERENCES scan_permits(permit_id),
    permit_sha256 TEXT NOT NULL
);

CREATE TABLE schedule_permits (
    schedule_id UUID PRIMARY KEY REFERENCES scan_schedules(schedule_id),
    permit_id UUID NOT NULL REFERENCES scan_permits(permit_id),
    permit_sha256 TEXT NOT NULL
);

-- Safety receipts are signed artifacts written to the filesystem/
-- object storage, exactly like SQLite's `job_safety_receipts` table
-- -- this stores only the reference and digest, never the receipt
-- body itself.
CREATE TABLE job_safety_receipts (
    job_id UUID PRIMARY KEY REFERENCES scan_jobs(job_id),
    receipt_ref TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- Promotes `scan_records` (Slice 12, schema-only) with the remaining
-- requirement-2 columns: permit reference, requested checks, a
-- distinct created_at (vs. started_at -- a scan can be created before
-- it actually starts executing), cancellation metadata, and summary/
-- count metadata.
ALTER TABLE scan_records
    ADD COLUMN permit_id UUID REFERENCES scan_permits(permit_id),
    ADD COLUMN permit_fingerprint TEXT,
    ADD COLUMN requested_checks JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN created_at TIMESTAMPTZ,
    ADD COLUMN cancellation_requested BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN cancelled_at TIMESTAMPTZ,
    ADD COLUMN finding_count INTEGER NOT NULL DEFAULT 0;

-- Findings (requirement 6): title/remediation/references were not
-- part of Slice 12's schema-only design; adding them now that a real
-- repository will populate this table.
ALTER TABLE findings
    ADD COLUMN title TEXT,
    ADD COLUMN remediation TEXT,
    ADD COLUMN references_list JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Authentication contexts (requirement 9): metadata only. This column
-- is a *reference* to wherever the actual secret lives (a future KMS/
-- secrets-manager key name) -- never the secret itself. No such
-- production secret store exists yet (documented as deferred in this
-- slice's audit doc), so this column is currently always NULL in
-- practice; the column exists so the day one does, no migration is
-- needed to start populating it.
ALTER TABLE authentication_contexts
    ADD COLUMN secret_reference_id TEXT;

-- Report metadata (requirement 12): format/state/checksum, matching
-- what a report's own lifecycle actually needs. The report body
-- itself stays a filesystem/object-storage artifact referenced by
-- report_ref, unchanged from Slice 12's design.
ALTER TABLE reports
    ADD COLUMN format TEXT NOT NULL DEFAULT 'html',
    ADD COLUMN state TEXT NOT NULL DEFAULT 'generated',
    ADD COLUMN checksum TEXT;
