"""In-memory Compliance framework/master-control catalog for local,
unit, and lab use (platform expansion, docs/PLATFORM_SCOPE.md).

Production uses :class:`webguard_api.postgres_compliance_catalog.PostgresComplianceCatalogRepository`,
reading the same catalog seeded by ``infra/postgres/migrations/0015_compliance_catalog.sql``.
This module carries the identical five placeholder frameworks that
migration seeds (same ids, names, versions, source references), so
local/lab mode shows the real catalog rather than an empty one, the
same "local demos populate real data" precedent
``coverage_store.InMemoryCoverageRepository`` already established.
Zero ``MasterControl`` rows exist here, matching production exactly:
no framework's real, legally-reviewed control content has shipped yet
(``docs/PLATFORM_SCOPE.md``'s own open blocker), so there is nothing to
fabricate and nothing this in-memory catalog could get wrong by being
"more complete" than the real one.
"""

from __future__ import annotations

from datetime import datetime, timezone

from webguard_contracts import Framework, FrameworkStatus, MasterControl

_SEEDED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)

PLACEHOLDER_FRAMEWORKS: tuple[Framework, ...] = (
    Framework(
        framework_id="soc2",
        name="SOC 2",
        version="2017 Trust Services Criteria",
        status=FrameworkStatus.PLACEHOLDER,
        source_reference="https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
        created_at=_SEEDED_AT,
        updated_at=_SEEDED_AT,
    ),
    Framework(
        framework_id="iso_27001",
        name="ISO/IEC 27001",
        version="2022 plus 2024 amendment",
        status=FrameworkStatus.PLACEHOLDER,
        source_reference="https://www.iso.org/standard/27001",
        created_at=_SEEDED_AT,
        updated_at=_SEEDED_AT,
    ),
    Framework(
        framework_id="hipaa_security_rule",
        name="HIPAA Security Rule",
        version="current (2024 update proposed, not in force)",
        status=FrameworkStatus.PLACEHOLDER,
        source_reference="https://www.hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/index.html",
        created_at=_SEEDED_AT,
        updated_at=_SEEDED_AT,
    ),
    Framework(
        framework_id="eu_gdpr",
        name="EU General Data Protection Regulation",
        version="Regulation (EU) 2016/679",
        status=FrameworkStatus.PLACEHOLDER,
        source_reference="https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        created_at=_SEEDED_AT,
        updated_at=_SEEDED_AT,
    ),
    Framework(
        framework_id="uk_gdpr",
        name="UK General Data Protection Regulation",
        version="as retained and amended in UK law",
        status=FrameworkStatus.PLACEHOLDER,
        source_reference="https://www.legislation.gov.uk/eur/2016/679",
        created_at=_SEEDED_AT,
        updated_at=_SEEDED_AT,
    ),
)


class ComplianceCatalogError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class InMemoryComplianceCatalogRepository:
    """Read-only, matching
    :class:`webguard_api.postgres_compliance_catalog.PostgresComplianceCatalogRepository`'s
    method surface. No ``create_framework``/``create_master_control``
    here: this catalog is loaded by migration, not by application
    code, in every environment."""

    def list_frameworks(self) -> tuple[Framework, ...]:
        return PLACEHOLDER_FRAMEWORKS

    def get_framework(self, framework_id: str) -> Framework:
        for framework in PLACEHOLDER_FRAMEWORKS:
            if framework.framework_id == framework_id:
                return framework
        raise ComplianceCatalogError(
            "compliance_framework_not_found", f"No framework {framework_id!r} exists."
        )

    def list_master_controls(self, framework_id: str) -> tuple[MasterControl, ...]:
        self.get_framework(framework_id)
        return ()


__all__ = [
    "PLACEHOLDER_FRAMEWORKS",
    "ComplianceCatalogError",
    "InMemoryComplianceCatalogRepository",
]
