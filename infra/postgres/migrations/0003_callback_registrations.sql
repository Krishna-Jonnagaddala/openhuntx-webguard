-- Slice 12: durable callback registrations/observations.
--
-- Production analogue of the in-memory `CallbackRepository`
-- (apps/api/src/webguard_api/callback_service.py) introduced in
-- Slice 10 and tenant-isolation-remediated in Slice 12. Local/unit/lab
-- keeps the in-memory backend unchanged -- this table exists only for
-- the production repository implementation
-- (`PostgresCallbackRegistrationRepository`), which satisfies the
-- identical `CallbackRegistrationRepository` protocol.
--
-- Column shape mirrors `ScopedCallbackRegistration` exactly (token
-- value, scan/job/permit/authorization/organization binding,
-- candidate fingerprint, timestamps, revocation) -- this is the one
-- migration in this slice with a direct existing Python dataclass to
-- stay faithful to, so it intentionally is a close translation rather
-- than a schema improvised from scratch.

CREATE TABLE callback_registrations (
    token_value TEXT PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    scan_id TEXT NOT NULL,
    job_id TEXT,
    permit_id TEXT,
    target TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    candidate_fingerprint TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

-- The tenant-ownership index this slice's own remediation exists to
-- guarantee is actually checked: every lookup in
-- `PostgresCallbackRegistrationRepository` filters by
-- (token_value, organization_id) together, never token_value alone.
CREATE INDEX idx_callback_registrations_organization
    ON callback_registrations (organization_id, created_at DESC);

CREATE TABLE callback_observations (
    observation_id UUID PRIMARY KEY,
    token_value TEXT NOT NULL REFERENCES callback_registrations(token_value),
    method TEXT NOT NULL,
    source_class TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_callback_observations_token
    ON callback_observations (token_value, observed_at);
