-- Slice 13: `scan_schedules` was missing `authorization_sha256`,
-- which `ScanScheduleRecord` (webguard_contracts) requires -- found
-- while implementing `PostgresScheduleRepository` against the
-- Slice 12 schema-only table.
ALTER TABLE scan_schedules
    ADD COLUMN authorization_sha256 TEXT NOT NULL DEFAULT '';

ALTER TABLE scan_schedules
    ALTER COLUMN authorization_sha256 DROP DEFAULT;
