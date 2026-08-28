-- Slice 13: `reports.title`/`prepared_by` were NOT NULL in the
-- Slice 12 schema-only design, but requirement 12's actual field list
-- for report metadata (report_id, organization_id, scan_id, format,
-- state, artifact reference, checksum, created_at) does not include
-- either -- relaxing them to nullable rather than writing placeholder
-- empty strings into every row `PostgresReportRepository` creates.
ALTER TABLE reports
    ALTER COLUMN title DROP NOT NULL,
    ALTER COLUMN prepared_by DROP NOT NULL;
