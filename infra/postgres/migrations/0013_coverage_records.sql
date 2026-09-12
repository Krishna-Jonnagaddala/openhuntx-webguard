-- Coverage Truth Map v1 (product vision pillar 5,
-- docs/PROJECT_EXECUTION_LEDGER.md's "Coverage Truth Map: discovery"
-- section). One row per (organization_id, asset, path, http_method,
-- identity_label, check_id): the durable, queryable record
-- ScanCoverage/CrawlScanCoverage (webguard_contracts.scans) already
-- compute on every scan today but never persist anywhere.
--
-- v1 scope, decided with the user before this migration was written:
-- exact URL/method, not a normalized route pattern (no route-
-- templating exists anywhere in this codebase yet); an explicit
-- 'unauthenticated' identity_label rather than a nullable column,
-- since NULL in a uniqueness-bearing key has its own well-known
-- Postgres footguns; forward-only population (no backfill from
-- existing scan/finding history, since historical scans never
-- persisted their own planned-checks set, so a backfill could only
-- reconstruct the "attempted and found something" slice and would
-- silently misrepresent everything else as never-attempted).
--
-- status is deliberately three values, not the vision's full six-state
-- lattice. See coverage_store.py's own module docstring for exactly
-- why discovered/authorized/attempted are not populated in v1: no
-- current signal in this codebase distinguishes them from the other
-- three without either guessing or building a genuinely new tracking
-- mechanism (individual discovered-URL tracking, a resolved
-- authorization boundary per operation) that does not exist today.
CREATE TABLE coverage_records (
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    asset TEXT NOT NULL,
    path TEXT NOT NULL,
    http_method TEXT NOT NULL,
    identity_label TEXT NOT NULL,
    check_id TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('completed', 'blocked', 'unreachable')),
    scanner_version TEXT NOT NULL,
    check_version TEXT,
    last_scan_id UUID REFERENCES scan_records(scan_id),
    last_finding_id UUID REFERENCES findings(finding_id),
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, asset, path, http_method, identity_label, check_id)
);

CREATE INDEX idx_coverage_records_organization
    ON coverage_records (organization_id, asset);
