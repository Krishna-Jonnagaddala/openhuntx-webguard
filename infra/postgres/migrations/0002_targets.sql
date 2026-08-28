-- Slice 12: targets/assets and target verification metadata.
--
-- No SQLite equivalent exists to translate: today a scan "target" is
-- just a URL string field embedded in a permit/authorization, with no
-- standing asset record and no domain-ownership verification
-- (see docs/production/INFRASTRUCTURE_REQUIREMENTS.md, "no DNS/
-- domain-ownership verification exists"). This is genuinely new
-- schema, introduced ahead of the future web app's Assets page
-- (requirement 19) and ahead of any real verification mechanism being
-- built -- `target_verifications` intentionally has no Python
-- repository consumer yet; it exists so the column shape does not
-- have to be guessed at again when verification is actually built.

CREATE TABLE targets (
    target_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    url TEXT NOT NULL,
    label TEXT,
    created_by UUID NOT NULL REFERENCES principals(principal_id),
    created_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ,
    CONSTRAINT targets_organization_url_unique UNIQUE (organization_id, url)
);

CREATE INDEX idx_targets_organization
    ON targets (organization_id, archived_at);

-- Forward-looking only (requirement 19): no verification mechanism is
-- implemented this slice, and no code writes to this table yet. The
-- shape anticipates a DNS-TXT-record or well-known-file ownership
-- check, matching the pattern OwnedTargetAuthorization documents
-- already use for authorization (self-attested evidence plus a
-- recorded verification decision), without inventing the verification
-- logic itself ahead of a real design for it.
CREATE TABLE target_verifications (
    verification_id UUID PRIMARY KEY,
    target_id UUID NOT NULL REFERENCES targets(target_id),
    organization_id UUID NOT NULL REFERENCES organizations(organization_id),
    method TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'verified', 'failed', 'expired')),
    evidence TEXT,
    checked_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_target_verifications_target
    ON target_verifications (target_id, checked_at DESC);
