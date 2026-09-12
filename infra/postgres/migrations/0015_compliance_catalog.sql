-- Compliance framework/master-control catalog (platform expansion,
-- docs/PLATFORM_SCOPE.md, docs/adr/0034-compliance-catalog-is-global-reference-data.md).
--
-- Deliberately the first tables in this schema with no
-- organization_id column: a framework's own requirements are
-- identical for every tenant, so there is no tenant boundary to
-- enforce here. See the ADR for the full reasoning and for why
-- reads/writes use a different access pattern than every other table
-- in this schema.
CREATE TABLE frameworks (
    framework_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('placeholder', 'current', 'proposed', 'future_readiness', 'superseded')),
    source_reference TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE master_controls (
    control_id TEXT PRIMARY KEY,
    framework_id TEXT NOT NULL REFERENCES frameworks(framework_id),
    control_number TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT master_controls_framework_number_unique UNIQUE (framework_id, control_number)
);

CREATE INDEX idx_master_controls_framework
    ON master_controls (framework_id);

-- Seed the five initial profiles the handoff names (section 10.1), as
-- placeholders only: named, cited to their own authoritative source,
-- zero master_controls under any of them. No control text is invented
-- here; loading real content is a separate, later PR gated on the
-- legal-text verification docs/PLATFORM_SCOPE.md already records as
-- an open blocker. ISO/IEC 27001:2022's 2024 amendment is folded into
-- that one row's own version string, not a second framework_id, per
-- the handoff's own instruction against duplicate counting.
INSERT INTO frameworks (framework_id, name, version, status, source_reference, created_at, updated_at)
VALUES
    (
        'soc2',
        'SOC 2',
        '2017 Trust Services Criteria',
        'placeholder',
        'https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services',
        now(),
        now()
    ),
    (
        'iso_27001',
        'ISO/IEC 27001',
        '2022 plus 2024 amendment',
        'placeholder',
        'https://www.iso.org/standard/27001',
        now(),
        now()
    ),
    (
        'hipaa_security_rule',
        'HIPAA Security Rule',
        'current (2024 update proposed, not in force)',
        'placeholder',
        'https://www.hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/index.html',
        now(),
        now()
    ),
    (
        'eu_gdpr',
        'EU General Data Protection Regulation',
        'Regulation (EU) 2016/679',
        'placeholder',
        'https://eur-lex.europa.eu/eli/reg/2016/679/oj',
        now(),
        now()
    ),
    (
        'uk_gdpr',
        'UK General Data Protection Regulation',
        'as retained and amended in UK law',
        'placeholder',
        'https://www.legislation.gov.uk/eur/2016/679',
        now(),
        now()
    );
