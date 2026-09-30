"""PostgreSQL-backed technical assertion collection repository
(platform expansion, handoff sections 10.1-10.3, Phase 5 of the
2026-09-14 scope audit). See assertion_collections.py's own module
docstring for what a collection attempt is and why collection and
evaluation are kept as two distinct timestamped facts on one record.

api_tenant_data only, matching module_entitlements/
scoped_control_implementations' own precedent: collection and
evaluation both run synchronously inside one API request in this
version, so no worker/scheduler path ever touches this table.
"""

from __future__ import annotations

import json
from datetime import timezone

from .assertion_collections import (
    AssertionCollectionRecord,
    CollectionStatus,
    EvidenceSource,
)
from .postgres_pool import API_TENANT_DATA_ROLE, WebGuardPostgresPool
from .technical_assertions import AssertionOutcome

_COLUMNS = (
    "collection_id, organization_id, assertion_id, assertion_version, evidence_source, "
    "evidence_provenance, collection_status, collection_error, raw_evidence, outcome, "
    "outcome_detail, collected_by, collected_at, evaluated_at"
)


def _record_from_row(row: tuple) -> AssertionCollectionRecord:
    (
        collection_id, organization_id, assertion_id, assertion_version, evidence_source,
        evidence_provenance, collection_status, collection_error, raw_evidence, outcome,
        outcome_detail, collected_by, collected_at, evaluated_at,
    ) = row
    return AssertionCollectionRecord(
        collection_id=str(collection_id),
        organization_id=str(organization_id),
        assertion_id=assertion_id,
        assertion_version=assertion_version,
        evidence_source=EvidenceSource(evidence_source),
        evidence_provenance=evidence_provenance,
        collection_status=CollectionStatus(collection_status),
        collection_error=collection_error,
        raw_evidence=raw_evidence,
        outcome=AssertionOutcome(outcome) if outcome is not None else None,
        outcome_detail=outcome_detail,
        collected_by=str(collected_by),
        collected_at=collected_at.astimezone(timezone.utc),
        evaluated_at=evaluated_at.astimezone(timezone.utc) if evaluated_at is not None else None,
    )


class PostgresAssertionCollectionRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    def record(self, record: AssertionCollectionRecord) -> AssertionCollectionRecord:
        with self._pool.tenant_connection(record.organization_id, role=API_TENANT_DATA_ROLE) as connection:
            row = connection.execute(
                f"""
                INSERT INTO technical_assertion_collections (
                    collection_id, organization_id, assertion_id, assertion_version,
                    evidence_source, evidence_provenance, collection_status, collection_error,
                    raw_evidence, outcome, outcome_detail, collected_by, collected_at, evaluated_at
                ) VALUES (
                    %(collection_id)s, %(organization_id)s, %(assertion_id)s, %(assertion_version)s,
                    %(evidence_source)s, %(evidence_provenance)s, %(collection_status)s, %(collection_error)s,
                    %(raw_evidence)s, %(outcome)s, %(outcome_detail)s, %(collected_by)s, %(collected_at)s,
                    %(evaluated_at)s
                )
                RETURNING {_COLUMNS}
                """,  # noqa: S608
                {
                    "collection_id": record.collection_id,
                    "organization_id": record.organization_id,
                    "assertion_id": record.assertion_id,
                    "assertion_version": record.assertion_version,
                    "evidence_source": record.evidence_source.value,
                    "evidence_provenance": record.evidence_provenance,
                    "collection_status": record.collection_status.value,
                    "collection_error": record.collection_error,
                    "raw_evidence": json.dumps(record.raw_evidence) if record.raw_evidence is not None else None,
                    "outcome": record.outcome.value if record.outcome is not None else None,
                    "outcome_detail": record.outcome_detail,
                    "collected_by": record.collected_by,
                    "collected_at": record.collected_at,
                    "evaluated_at": record.evaluated_at,
                },
            ).fetchone()
        return _record_from_row(row)

    def list_for_assertion(
        self, organization_id: str, assertion_id: str
    ) -> tuple[AssertionCollectionRecord, ...]:
        with self._pool.tenant_connection(organization_id, role=API_TENANT_DATA_ROLE) as connection:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM technical_assertion_collections "  # noqa: S608
                "WHERE organization_id = %s AND assertion_id = %s "
                "ORDER BY collected_at DESC",
                (organization_id, assertion_id),
            ).fetchall()
        return tuple(_record_from_row(row) for row in rows)


__all__ = ["PostgresAssertionCollectionRepository"]
