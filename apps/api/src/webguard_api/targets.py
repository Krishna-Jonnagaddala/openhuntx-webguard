"""Target/asset registry (Slice 12 requirement 4/19): a genuinely new
entity with no prior SQLite table to preserve. Local/unit/lab uses
:class:`InMemoryTargetRepository`; production uses
:class:`PostgresTargetRepository` (in ``postgres_targets.py``) --
mirroring the production-boundary split this slice already uses for
callback registrations, both satisfying the identical
``TargetRepository`` protocol in ``repository_contracts.py``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4


class TargetRepositoryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class TargetRecord:
    target_id: str
    organization_id: str
    url: str
    created_by: str
    created_at: datetime
    label: str | None = None
    archived_at: datetime | None = None


class InMemoryTargetRepository:
    """Local/unit/lab backend. Matches
    :class:`webguard_api.postgres_targets.PostgresTargetRepository`'s
    behavior and error codes exactly, so contract tests exercise both
    with the same test bodies."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._targets: dict[str, TargetRecord] = {}

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
        with self._lock:
            for existing in self._targets.values():
                if existing.organization_id == organization_id and existing.url == url:
                    raise TargetRepositoryError(
                        "target_conflict",
                        "A target with that URL already exists for this organization.",
                    )
            record = TargetRecord(
                target_id=str(uuid4()) if target_id is None else target_id,
                organization_id=organization_id,
                url=url,
                created_by=created_by,
                created_at=now,
                label=label,
            )
            self._targets[record.target_id] = record
        return record

    def get_target(self, target_id: str, *, organization_id: str) -> TargetRecord:
        with self._lock:
            record = self._targets.get(target_id)
        if record is None or record.organization_id != organization_id:
            raise TargetRepositoryError("target_not_found", "Target was not found.")
        return record

    def list_targets(
        self, organization_id: str, *, include_archived: bool = False
    ) -> tuple[TargetRecord, ...]:
        with self._lock:
            values = [
                record
                for record in self._targets.values()
                if record.organization_id == organization_id
                and (include_archived or record.archived_at is None)
            ]
        return tuple(sorted(values, key=lambda record: record.created_at))

    def archive_target(
        self, target_id: str, *, organization_id: str, now: datetime
    ) -> TargetRecord:
        with self._lock:
            record = self._targets.get(target_id)
            if record is None or record.organization_id != organization_id:
                raise TargetRepositoryError("target_not_found", "Target was not found.")
            if record.archived_at is None:
                record = TargetRecord(
                    target_id=record.target_id,
                    organization_id=record.organization_id,
                    url=record.url,
                    created_by=record.created_by,
                    created_at=record.created_at,
                    label=record.label,
                    archived_at=now.astimezone(timezone.utc),
                )
                self._targets[target_id] = record
        return record


__all__ = ["InMemoryTargetRepository", "TargetRecord", "TargetRepositoryError"]
