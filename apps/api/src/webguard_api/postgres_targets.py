"""PostgreSQL-backed target/asset repository (Slice 12 requirement
4/9). Satisfies the same ``TargetRepository`` protocol, and the same
``TargetRecord``/``TargetRepositoryError`` types, as
``targets.InMemoryTargetRepository`` -- see that module's docstring
for the production-boundary rationale.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from .db_errors import DatabaseIntegrityError
from .postgres_pool import WebGuardPostgresPool
from .targets import TargetRecord, TargetRepositoryError


class PostgresTargetRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    def create_target(
        self,
        organization_id: str,
        url: str,
        *,
        created_by: str,
        now: datetime,
        label: str | None = None,
        target_id: str | None = None,
    ) -> TargetRecord:
        record = TargetRecord(
            target_id=str(uuid4()) if target_id is None else target_id,
            organization_id=organization_id,
            url=url,
            created_by=created_by,
            created_at=now,
            label=label,
        )
        try:
            with self._pool.connection() as connection:
                connection.execute(
                    """
                    INSERT INTO targets (target_id, organization_id, url, label, created_by, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        record.target_id,
                        record.organization_id,
                        record.url,
                        record.label,
                        record.created_by,
                        record.created_at,
                    ),
                )
        except DatabaseIntegrityError as exc:
            raise TargetRepositoryError(
                "target_conflict",
                "A target with that URL already exists for this organization.",
            ) from exc
        return record

    def get_target(self, target_id: str, *, organization_id: str) -> TargetRecord:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT target_id, organization_id, url, label, created_by, created_at, archived_at
                FROM targets WHERE target_id = %s AND organization_id = %s
                """,
                (target_id, organization_id),
            ).fetchone()
        if row is None:
            raise TargetRepositoryError("target_not_found", "Target was not found.")
        return self._record_from_row(row)

    def list_targets(
        self, organization_id: str, *, include_archived: bool = False
    ) -> tuple[TargetRecord, ...]:
        clause = "" if include_archived else "AND archived_at IS NULL"
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"""
                SELECT target_id, organization_id, url, label, created_by, created_at, archived_at
                FROM targets
                WHERE organization_id = %s {clause}
                ORDER BY created_at ASC
                """,  # noqa: S608
                (organization_id,),
            ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    def archive_target(
        self, target_id: str, *, organization_id: str, now: datetime
    ) -> TargetRecord:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                UPDATE targets SET archived_at = COALESCE(archived_at, %s)
                WHERE target_id = %s AND organization_id = %s
                RETURNING target_id, organization_id, url, label, created_by, created_at, archived_at
                """,
                (now, target_id, organization_id),
            ).fetchone()
        if row is None:
            raise TargetRepositoryError("target_not_found", "Target was not found.")
        return self._record_from_row(row)

    @staticmethod
    def _record_from_row(row: tuple) -> TargetRecord:
        return TargetRecord(
            target_id=str(row[0]),
            organization_id=str(row[1]),
            url=row[2],
            label=row[3],
            created_by=str(row[4]),
            created_at=row[5].astimezone(timezone.utc),
            archived_at=row[6].astimezone(timezone.utc) if row[6] else None,
        )


__all__ = ["PostgresTargetRepository"]
