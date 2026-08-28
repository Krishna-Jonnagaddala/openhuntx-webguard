"""PostgreSQL-backed finding repository (Slice 13 requirements 6-8).
Satisfies the same surface as ``finding_store.InMemoryFindingRepository``
-- see that module's docstring for the dedup/lifecycle rules this
implementation enforces identically, atomically, via
``INSERT ... ON CONFLICT (organization_id, fingerprint)``.

The tenant-scoped uniqueness constraint
(``idx_findings_fingerprint`` on ``(organization_id, fingerprint)``,
from Slice 12's schema) is what makes this atomic: a concurrent insert
of the same (org, fingerprint) pair from two scans running at once
resolves to one winning row and one conflicting upsert, never a
duplicate finding and never a lost update -- proven under real
concurrent transactions in
``tests/integration/test_postgres_finding_concurrency.py``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from .db_errors import DatabaseIntegrityError
from .finding_store import FindingRecord, FindingStatus, FindingStoreError, assert_valid_transition
from .postgres_pool import WebGuardPostgresPool

_COLUMNS = (
    "finding_id, organization_id, scan_id, fingerprint, check_id, scanner_version, "
    "title, severity, confidence, asset, endpoint, http_method, status, "
    "first_seen_at, last_seen_at, parameter, check_version, cwe_id, owasp_category, "
    "evidence, remediation, references_list"
)


class PostgresFindingRepository:
    def __init__(self, pool: WebGuardPostgresPool) -> None:
        self._pool = pool

    @staticmethod
    def _record_from_row(row: tuple) -> FindingRecord:
        (
            finding_id, organization_id, scan_id, fingerprint, check_id, scanner_version,
            title, severity, confidence, asset, endpoint, http_method, status,
            first_seen_at, last_seen_at, parameter, check_version, cwe_id, owasp_category,
            evidence, remediation, references_list,
        ) = row
        return FindingRecord(
            finding_id=str(finding_id),
            organization_id=str(organization_id),
            scan_id=str(scan_id) if scan_id else "",
            fingerprint=fingerprint,
            check_id=check_id,
            scanner_version=scanner_version,
            title=title or "",
            severity=severity,
            confidence=confidence,
            asset=asset,
            endpoint=endpoint,
            http_method=http_method,
            status=FindingStatus(status),
            first_seen_at=first_seen_at.astimezone(timezone.utc),
            last_seen_at=last_seen_at.astimezone(timezone.utc),
            parameter=parameter,
            check_version=check_version,
            cwe_id=cwe_id,
            owasp_category=owasp_category,
            evidence=evidence,
            remediation=remediation,
            references=tuple(references_list or ()),
        )

    def record_finding(
        self,
        *,
        organization_id: str,
        scan_id: str,
        fingerprint: str,
        check_id: str,
        scanner_version: str,
        title: str,
        severity: str,
        confidence: str,
        asset: str,
        endpoint: str,
        http_method: str,
        now: datetime,
        parameter: str | None = None,
        check_version: str | None = None,
        cwe_id: str | None = None,
        owasp_category: str | None = None,
        evidence: str | None = None,
        remediation: str | None = None,
        references: tuple[str, ...] = (),
    ) -> FindingRecord:
        finding_id = str(uuid4())
        with self._pool.connection() as connection:
            row = connection.execute(
                f"""
                INSERT INTO findings (
                    finding_id, organization_id, scan_id, fingerprint, check_id,
                    scanner_version, title, severity, confidence, asset, endpoint,
                    http_method, status, first_seen_at, last_seen_at, parameter,
                    check_version, cwe_id, owasp_category, evidence, remediation,
                    references_list
                ) VALUES (
                    %(finding_id)s, %(organization_id)s, %(scan_id)s, %(fingerprint)s,
                    %(check_id)s, %(scanner_version)s, %(title)s, %(severity)s,
                    %(confidence)s, %(asset)s, %(endpoint)s, %(http_method)s, 'open',
                    %(now)s, %(now)s, %(parameter)s, %(check_version)s, %(cwe_id)s,
                    %(owasp_category)s, %(evidence)s, %(remediation)s, %(references_list)s
                )
                ON CONFLICT (organization_id, fingerprint) DO UPDATE SET
                    scan_id = EXCLUDED.scan_id,
                    scanner_version = EXCLUDED.scanner_version,
                    severity = EXCLUDED.severity,
                    confidence = EXCLUDED.confidence,
                    last_seen_at = EXCLUDED.last_seen_at,
                    check_version = EXCLUDED.check_version,
                    evidence = EXCLUDED.evidence,
                    status = CASE
                        WHEN findings.status = 'resolved' THEN 'reopened'
                        ELSE findings.status
                    END
                RETURNING {_COLUMNS}
                """,  # noqa: S608
                {
                    "finding_id": finding_id,
                    "organization_id": organization_id,
                    "scan_id": scan_id,
                    "fingerprint": fingerprint,
                    "check_id": check_id,
                    "scanner_version": scanner_version,
                    "title": title,
                    "severity": severity,
                    "confidence": confidence,
                    "asset": asset,
                    "endpoint": endpoint,
                    "http_method": http_method,
                    "now": now,
                    "parameter": parameter,
                    "check_version": check_version,
                    "cwe_id": cwe_id,
                    "owasp_category": owasp_category,
                    "evidence": evidence,
                    "remediation": remediation,
                    "references_list": json.dumps(list(references)),
                },
            ).fetchone()
        return self._record_from_row(row)

    def get_finding_scoped(self, finding_id: str, *, organization_id: str) -> FindingRecord:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM findings WHERE finding_id = %s AND organization_id = %s",  # noqa: S608
                (finding_id, organization_id),
            ).fetchone()
        if row is None:
            raise FindingStoreError("finding_not_found", "Finding was not found.")
        return self._record_from_row(row)

    def list_findings_scoped_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        scan_id: str | None = None,
        status: FindingStatus | None = None,
    ) -> tuple[tuple[FindingRecord, ...], bool]:
        clauses = ["organization_id = %s"]
        parameters: list[object] = [organization_id]
        if scan_id is not None:
            clauses.append("scan_id = %s")
            parameters.append(scan_id)
        if status is not None:
            clauses.append("status = %s")
            parameters.append(status.value)
        if after is not None:
            clauses.append("(last_seen_at < %s OR (last_seen_at = %s AND finding_id::text < %s))")
            parameters.extend((after[0], after[0], after[1]))
        parameters.append(limit + 1)
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"""
                SELECT {_COLUMNS} FROM findings
                WHERE {' AND '.join(clauses)}
                ORDER BY last_seen_at DESC, finding_id DESC
                LIMIT %s
                """,  # noqa: S608
                tuple(parameters),
            ).fetchall()
        has_more = len(rows) > limit
        return tuple(self._record_from_row(row) for row in rows[:limit]), has_more

    def update_status(
        self, finding_id: str, *, organization_id: str, new_status: FindingStatus, now: datetime
    ) -> FindingRecord:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT status FROM findings WHERE finding_id = %s AND organization_id = %s",  # noqa: S608
                (finding_id, organization_id),
            ).fetchone()
            if row is None:
                raise FindingStoreError("finding_not_found", "Finding was not found.")
            assert_valid_transition(FindingStatus(row[0]), new_status)
            updated = connection.execute(
                f"""
                UPDATE findings SET status = %s
                WHERE finding_id = %s AND organization_id = %s
                RETURNING {_COLUMNS}
                """,  # noqa: S608
                (new_status.value, finding_id, organization_id),
            ).fetchone()
        return self._record_from_row(updated)


__all__ = ["PostgresFindingRepository"]
