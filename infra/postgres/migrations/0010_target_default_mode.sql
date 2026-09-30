-- Slice 15 requirement 2: a per-asset scan-profile default. A
-- requested mode only -- never a standing scan authorization; the
-- existing authorization/TrustScan boundaries remain the sole thing
-- that actually permits a scan to run.
ALTER TABLE targets
    ADD COLUMN default_mode TEXT;
