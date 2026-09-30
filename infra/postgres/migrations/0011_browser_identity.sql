-- Slice 16: browser-user identity, password credentials, verification/
-- reset/invitation tokens, and browser sessions. `principals` remains
-- the account: email/verification/last-login live directly on it
-- rather than a second, unrelated user table, matching how this
-- project already treats a principal as the org-scoped identity.

-- security_audit_events.token_id previously always named a real
-- api_tokens row. It now also holds a browser_sessions.session_id for
-- session-authenticated actions, or a fresh, otherwise-unused UUID for
-- identity events that happen before a session exists or after one has
-- already been consumed (login failure/success, password reset
-- completion, email verification, invitation acceptance). A foreign
-- key naming one specific credential table is no longer correct.
ALTER TABLE security_audit_events
    DROP CONSTRAINT security_audit_events_token_id_fkey;

ALTER TABLE principals
    ADD COLUMN email TEXT,
    ADD COLUMN email_verified_at TIMESTAMPTZ,
    ADD COLUMN last_login_at TIMESTAMPTZ;

CREATE UNIQUE INDEX idx_principals_email
    ON principals ((lower(email)))
    WHERE email IS NOT NULL;

CREATE TABLE password_credentials (
    principal_id UUID PRIMARY KEY REFERENCES principals(principal_id),
    algorithm TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Email verification / password reset / invitation tokens share one
-- lifecycle shape (high-entropy, hashed at rest, single-purpose,
-- expiry-bounded, single-use, principal/org bound), so one table with
-- a `purpose` discriminator replaces three near-identical ones.
CREATE TABLE identity_tokens (
    token_id UUID PRIMARY KEY,
    principal_id UUID NOT NULL REFERENCES principals(principal_id),
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    purpose TEXT NOT NULL CHECK (purpose IN ('email_verification', 'password_reset', 'invitation')),
    secret_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE INDEX idx_identity_tokens_principal
    ON identity_tokens (principal_id, purpose, used_at);

-- The session's own bearer secret is never persisted -- only its hash
-- (`secret_hash`), matching api_tokens' existing pattern. `csrf_hash`
-- is the hash of the separate, non-HttpOnly CSRF cookie value this
-- same session issues; comparing the caller-supplied X-CSRF-Token
-- header against it is this API's CSRF defense for cookie-authenticated
-- requests (requirement 7 -- SameSite is defense in depth, not the
-- whole model).
CREATE TABLE browser_sessions (
    session_id UUID PRIMARY KEY,
    principal_id UUID NOT NULL REFERENCES principals(principal_id),
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    secret_hash TEXT NOT NULL,
    csrf_hash TEXT NOT NULL,
    assurance_level TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    user_agent TEXT,
    ip_address TEXT
);

CREATE INDEX idx_browser_sessions_principal
    ON browser_sessions (principal_id, revoked_at);

-- Postgres-backed counters for pre-authentication rate limiting
-- (login attempts, password-reset requests, verification resends,
-- invitation acceptance) -- process-local in-memory limiting (the
-- existing FixedWindowRateLimiter) is insufficient once more than one
-- API process/host can serve these routes, since each process would
-- otherwise enforce its own independent quota. One row per attempt,
-- counted over a trailing window, is simpler and less racy than a
-- read-modify-write counter row.
CREATE TABLE auth_rate_limit_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    bucket_key TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_auth_rate_limit_bucket_time
    ON auth_rate_limit_events (bucket_key, occurred_at DESC);
