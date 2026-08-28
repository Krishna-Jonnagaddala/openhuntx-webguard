"""Finding persistence and lifecycle (Slice 13 requirements 6-8).

Deduplication rule (requirement 8), stated precisely: the uniqueness
key is ``(organization_id, fingerprint)`` -- exactly the tenant-scoped
key `webguard_contracts.findings.FindingIdentity.fingerprint` already
computes deterministically from ``rule_id + asset + path + method +
parameter`` (proven stable across runs in Slice 11's audit). Two
findings collide (are "the same logical finding") if and only if they
share an organization and a fingerprint; a different organization, a
different asset, or a different endpoint/parameter is a structurally
different fingerprint and therefore always an independent finding.
Tenant ownership is part of the uniqueness constraint itself (a
composite index/key on ``(organization_id, fingerprint)``), not an
application-level filter layered on top of a global one -- so it is
impossible, by construction, for Org A's re-scan to collide with an
identical vulnerability at Org B's differently-owned copy of the same
software.

Lifecycle rule (requirement 7), stated precisely: recording a finding
that already exists (same org + fingerprint) always updates
``last_seen_at`` and ``scan_id`` to the new scan. The ``status``
column is touched only in one specific case: an existing finding whose
status is ``RESOLVED`` and which reappears transitions to ``REOPENED``
-- a deliberate, audited business rule (a bug that was fixed and then
came back is meaningfully different from a bug nobody has looked at
yet). Every other status (``OPEN``, ``CONFIRMED``, ``FALSE_POSITIVE``,
``ACCEPTED_RISK``, already-``REOPENED``) is left untouched by
re-detection -- a human's ``FALSE_POSITIVE``/``ACCEPTED_RISK``
judgment, or an already-open/confirmed/reopened finding's current
status, is never silently overwritten just because the scanner saw it
again. Confidence is never used to set or change status (explicitly
required) -- it is stored purely as descriptive metadata about the
scanner's own certainty, orthogonal to the human/audit-driven lifecycle
status.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


class FindingStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"
    REOPENED = "reopened"


_TERMINAL_UNCHANGED_ON_REDETECTION = {
    FindingStatus.OPEN,
    FindingStatus.CONFIRMED,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.ACCEPTED_RISK,
    FindingStatus.REOPENED,
}

# Requirement 7's explicit lifecycle graph -- transitions outside this
# set are rejected, so "audited" (requirement 7) means "every
# transition that happens is one this graph named", not merely that a
# log line gets written.
_ALLOWED_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.OPEN: frozenset(
        {FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK, FindingStatus.RESOLVED}
    ),
    FindingStatus.CONFIRMED: frozenset(
        {FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK, FindingStatus.RESOLVED}
    ),
    FindingStatus.FALSE_POSITIVE: frozenset({FindingStatus.OPEN, FindingStatus.CONFIRMED}),
    FindingStatus.ACCEPTED_RISK: frozenset({FindingStatus.OPEN, FindingStatus.RESOLVED}),
    FindingStatus.RESOLVED: frozenset({FindingStatus.REOPENED}),
    FindingStatus.REOPENED: frozenset(
        {FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK, FindingStatus.RESOLVED}
    ),
}


class FindingStoreError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class FindingRecord:
    finding_id: str
    organization_id: str
    scan_id: str
    fingerprint: str
    check_id: str
    scanner_version: str
    title: str
    severity: str
    confidence: str
    asset: str
    endpoint: str
    http_method: str
    status: FindingStatus
    first_seen_at: datetime
    last_seen_at: datetime
    parameter: str | None = None
    check_version: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    references: tuple[str, ...] = ()


def assert_valid_transition(current: FindingStatus, target: FindingStatus) -> None:
    if target not in _ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise FindingStoreError(
            "finding_status_transition_invalid",
            f"Cannot transition a finding from {current.value} to {target.value}.",
        )


class InMemoryFindingRepository:
    """Local/unit/lab backend. A new entity with no prior SQLite table
    (findings were never persisted before this slice -- see
    ``docs/scanner/SCANNER_V1_LIMITATIONS.md``'s original "no
    finding_id/first_seen/last_seen" gap, closed here)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_key: dict[tuple[str, str], FindingRecord] = {}
        self._by_id: dict[str, FindingRecord] = {}

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
        key = (organization_id, fingerprint)
        with self._lock:
            existing = self._by_key.get(key)
            if existing is None:
                record = FindingRecord(
                    finding_id=str(uuid4()),
                    organization_id=organization_id,
                    scan_id=scan_id,
                    fingerprint=fingerprint,
                    check_id=check_id,
                    scanner_version=scanner_version,
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    asset=asset,
                    endpoint=endpoint,
                    http_method=http_method,
                    status=FindingStatus.OPEN,
                    first_seen_at=now,
                    last_seen_at=now,
                    parameter=parameter,
                    check_version=check_version,
                    cwe_id=cwe_id,
                    owasp_category=owasp_category,
                    evidence=evidence,
                    remediation=remediation,
                    references=tuple(references),
                )
            else:
                new_status = (
                    FindingStatus.REOPENED
                    if existing.status is FindingStatus.RESOLVED
                    else existing.status
                )
                record = replace(
                    existing,
                    scan_id=scan_id,
                    scanner_version=scanner_version,
                    severity=severity,
                    confidence=confidence,
                    last_seen_at=now,
                    status=new_status,
                    check_version=check_version,
                    evidence=evidence,
                )
            self._by_key[key] = record
            self._by_id[record.finding_id] = record
        return record

    def get_finding_scoped(self, finding_id: str, *, organization_id: str) -> FindingRecord:
        with self._lock:
            record = self._by_id.get(finding_id)
        if record is None or record.organization_id != organization_id:
            raise FindingStoreError("finding_not_found", "Finding was not found.")
        return record

    def list_findings_scoped_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        scan_id: str | None = None,
        status: FindingStatus | None = None,
    ) -> tuple[tuple[FindingRecord, ...], bool]:
        with self._lock:
            values = [r for r in self._by_id.values() if r.organization_id == organization_id]
        if scan_id is not None:
            values = [r for r in values if r.scan_id == scan_id]
        if status is not None:
            values = [r for r in values if r.status is status]
        values.sort(key=lambda r: (r.last_seen_at, r.finding_id), reverse=True)
        if after is not None:
            values = [
                r
                for r in values
                if (r.last_seen_at.isoformat(), r.finding_id) < (after[0], after[1])
            ]
        has_more = len(values) > limit
        return tuple(values[:limit]), has_more

    def update_status(
        self,
        finding_id: str,
        *,
        organization_id: str,
        new_status: FindingStatus,
        now: datetime,
    ) -> FindingRecord:
        with self._lock:
            record = self._by_id.get(finding_id)
            if record is None or record.organization_id != organization_id:
                raise FindingStoreError("finding_not_found", "Finding was not found.")
            assert_valid_transition(record.status, new_status)
            updated = replace(record, status=new_status)
            self._by_id[finding_id] = updated
            self._by_key[(organization_id, record.fingerprint)] = updated
        return updated


__all__ = [
    "FindingRecord",
    "FindingStatus",
    "FindingStoreError",
    "InMemoryFindingRepository",
    "assert_valid_transition",
]
