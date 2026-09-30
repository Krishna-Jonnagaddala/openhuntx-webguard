-- Slice 12: identity, RBAC, and audit foundation.
--
-- Deliberately not a mechanical translation of identity.py's SQLite
-- schema: UUID columns instead of TEXT, TIMESTAMPTZ instead of ISO
-- strings, explicit CHECK constraints instead of Python-side
-- validation as the last line of defense, and a genuinely new
-- `memberships` table (see below) rather than reusing SQLite's
-- denormalized-only "role lives on the principal row" model.
--
-- Every tenant-owned table below carries organization_id directly, so
-- no query needs more than one join to establish tenant ownership.

CREATE TABLE organizations (
    organization_id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT organizations_name_key_unique UNIQUE (name_key)
);

CREATE TABLE principals (
    principal_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    display_name TEXT NOT NULL,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('user', 'service_account')),
    role TEXT NOT NULL CHECK (role IN ('owner', 'administrator', 'analyst', 'viewer')),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_principals_organization
    ON principals (organization_id, active, role);

-- Append-only role-assignment history. `principals.role` remains the
-- fast-read current value (mirroring SQLite); every assignment or
-- change of that value is additionally recorded here so "who had what
-- role, when, granted by whom" survives independently of the mutable
-- current value -- something SQLite's schema has never tracked and
-- which the production audit/Team-page surface genuinely needs. This
-- is the only intentional schema divergence from SQLite's identity
-- model in this migration; it does not change principal/role
-- semantics (still exactly one active role per principal today), only
-- adds a durable history of how that value got there.
CREATE TABLE memberships (
    membership_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    principal_id UUID NOT NULL REFERENCES principals(principal_id),
    role TEXT NOT NULL CHECK (role IN ('owner', 'administrator', 'analyst', 'viewer')),
    assigned_by UUID NOT NULL REFERENCES principals(principal_id),
    assigned_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_memberships_principal
    ON memberships (principal_id, assigned_at DESC);
CREATE INDEX idx_memberships_organization
    ON memberships (organization_id, assigned_at DESC);

CREATE TABLE api_tokens (
    token_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    principal_id UUID NOT NULL REFERENCES principals(principal_id),
    label TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_api_tokens_principal
    ON api_tokens (principal_id, revoked_at, expires_at);
CREATE INDEX idx_api_tokens_organization
    ON api_tokens (organization_id);

-- Assignment of a filesystem-resident owned-target authorization
-- document to an organization. The authorization *content* (a
-- self-attested ownership-proof JSON document, see
-- AuthorizationRepository) stays filesystem-based in every backend --
-- this table only records the tenant-ownership binding, exactly
-- mirroring SQLite's `organization_authorizations` table.
CREATE TABLE organization_authorizations (
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    authorization_id TEXT NOT NULL,
    assigned_by UUID NOT NULL REFERENCES principals(principal_id),
    assigned_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, authorization_id)
);

CREATE TABLE security_audit_events (
    event_id UUID PRIMARY KEY,
    request_id TEXT NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    principal_id UUID NOT NULL REFERENCES principals(principal_id),
    token_id UUID NOT NULL REFERENCES api_tokens(token_id),
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'denied', 'failed')),
    occurred_at TIMESTAMPTZ NOT NULL,
    detail_code TEXT
);

-- Audit records are immutable once written -- no UPDATE/DELETE path is
-- exposed anywhere in this schema's Python repository layer; this
-- index only serves the read/pagination path.
CREATE INDEX idx_security_audit_org_time
    ON security_audit_events (organization_id, occurred_at DESC, event_id DESC);
