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

    _COLUMNS = (
        "target_id, organization_id, url, label, created_by, created_at, archived_at, default_mode"
    )

    def create_target(
        self,
        organization_id: str,
        url: str,
        *,
        created_by: str,
        now: datetime,
        label: str | None = None,
        target_id: str | None = None,
        default_mode: str | None = None,
    ) -> TargetRecord:
        record = TargetRecord(
            target_id=str(uuid4()) if target_id is None else target_id,
            organization_id=organization_id,
            url=url,
            created_by=created_by,
            created_at=now,
            label=label,
            default_mode=default_mode,
        )
        try:
            with self._pool.connection() as connection:
                connection.execute(
                    """
                    INSERT INTO targets (target_id, organization_id, url, label, created_by, created_at, default_mode)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        record.target_id,
                        record.organization_id,
                        record.url,
                        record.label,
                        record.created_by,
                        record.created_at,
                        record.default_mode,
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
                f"SELECT {self._COLUMNS} FROM targets WHERE target_id = %s AND organization_id = %s",  # noqa: S608
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
                SELECT {self._COLUMNS} FROM targets
                WHERE organization_id = %s {clause}
                ORDER BY created_at ASC
                """,  # noqa: S608
                (organization_id,),
            ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    def list_targets_scoped_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        include_archived: bool = False,
    ) -> tuple[tuple[TargetRecord, ...], bool]:
        clauses = ["organization_id = %s"]
        parameters: list[object] = [organization_id]
        if not include_archived:
            clauses.append("archived_at IS NULL")
        if after is not None:
            clauses.append("(created_at < %s OR (created_at = %s AND target_id::text < %s))")
            parameters.extend((after[0], after[0], after[1]))
        parameters.append(limit + 1)
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"""
                SELECT {self._COLUMNS} FROM targets
                WHERE {' AND '.join(clauses)}
                ORDER BY created_at DESC, target_id DESC
                LIMIT %s
                """,  # noqa: S608
                tuple(parameters),
            ).fetchall()
        has_more = len(rows) > limit
        return tuple(self._record_from_row(row) for row in rows[:limit]), has_more

    def update_target(
        self,
        target_id: str,
        *,
        organization_id: str,
        label: str | None = ...,
        default_mode: str | None = ...,
    ) -> TargetRecord:
        assignments = []
        parameters: list[object] = []
        if label is not ...:
            assignments.append("label = %s")
            parameters.append(label)
        if default_mode is not ...:
            assignments.append("default_mode = %s")
            parameters.append(default_mode)
        if not assignments:
            return self.get_target(target_id, organization_id=organization_id)
        parameters.extend((target_id, organization_id))
        with self._pool.connection() as connection:
            row = connection.execute(
                f"""
                UPDATE targets SET {', '.join(assignments)}
                WHERE target_id = %s AND organization_id = %s
                RETURNING {self._COLUMNS}
                """,  # noqa: S608
                tuple(parameters),
            ).fetchone()
        if row is None:
            raise TargetRepositoryError("target_not_found", "Target was not found.")
        return self._record_from_row(row)

    def archive_target(
        self, target_id: str, *, organization_id: str, now: datetime
    ) -> TargetRecord:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"""
                UPDATE targets SET archived_at = COALESCE(archived_at, %s)
                WHERE target_id = %s AND organization_id = %s
                RETURNING {self._COLUMNS}
                """,  # noqa: S608
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
            default_mode=row[7],
        )


__all__ = ["PostgresTargetRepository"]
