"""Coverage Truth Map domain record (product vision pillar 5).

v1 scope, decided with the user before any schema or code existed
(see docs/PROJECT_EXECUTION_LEDGER.md's "Coverage Truth Map:
discovery" section): one row per (organization_id, asset, path,
http_method, identity_label, check_id), populated going forward only
(no backfill from existing scan/finding history), exact URL/method
rather than a normalized route pattern, and an explicit
"unauthenticated" identity_label rather than a nullable column.

CoverageStatus is deliberately three values, not the vision's full
six-state lattice (discovered/authorized/attempted/completed/blocked/
unreachable). Only three have a real, already-computed signal behind
them today: a page's ScanCoverage already distinguishes executed
checks from skipped ones, and a failed page's planned checks were
never even attempted. "discovered" would mean a URL the crawler found
but has not yet scanned, which requires tracking individual discovered
URLs, not just counts (CrawlPageScanResult.discovered_links is a
count, no URLs); "authorized" would need a resolved permit/authorization
boundary per operation, not per scan. Populating either from data
that doesn't actually establish it would make the map look more
complete than it is, exactly the failure mode a "truth map" exists to
avoid.

identity_label is only ever "unauthenticated" in v1. NormalizedFinding/
FindingIdentity (webguard_contracts.findings) carries no identity
field at all, so which principal's authentication material a given
check actually ran under cannot be recovered from a report today.
Coverage rows populated by this slice cover the base passive/active
check plan only; authorization-comparison's own per-identity checks
are a known, open gap, not a silent misattribution to
"unauthenticated".
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from urllib.parse import urlsplit


class CoverageStatus(str, Enum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    UNREACHABLE = "unreachable"


UNAUTHENTICATED_IDENTITY_LABEL = "unauthenticated"


class CoverageStoreError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class CoverageRecord:
    organization_id: str
    asset: str
    path: str
    http_method: str
    identity_label: str
    check_id: str
    status: CoverageStatus
    scanner_version: str
    first_observed_at: datetime
    last_observed_at: datetime
    check_version: str | None = None
    last_scan_id: str | None = None
    last_finding_id: str | None = None


_CURSOR_KEY_SEPARATOR = "\x1f"  # ASCII Unit Separator


def coverage_cursor_key(record: CoverageRecord) -> str:
    """A stable, opaque string identifying one coverage row within its
    asset, for pagination. coverage_records has no single-column ID
    (its primary key is the full six-column tuple); this joins the
    part of that key not already fixed by the asset-scoped query
    (path, http_method, identity_label, check_id) with the ASCII Unit
    Separator (0x1F, chosen for exactly this purpose historically),
    not NUL: PostgreSQL text values cannot contain a NUL byte at all
    (confirmed directly: `SELECT 'a' || chr(0)` raises
    ProgramLimitExceeded), so a NUL-joined key would fail the moment
    postgres_coverage.py's matching SQL tried to build or compare it.
    Used only as the pagination cursor's own resource_id half; never
    interpreted as anything but an opaque tie-breaker by the caller."""

    return _CURSOR_KEY_SEPARATOR.join(
        (record.path, record.http_method, record.identity_label, record.check_id)
    )


def _sort_key(record: CoverageRecord) -> tuple:
    return (record.last_observed_at, coverage_cursor_key(record))


class InMemoryCoverageRepository:
    """Local/unit/lab backend (Phase 4 of the Coverage Truth Map:
    an API/report surface). Coverage previously had no in-memory
    repository at all: ScanJobExecutor's own coverage_repository
    defaulted to None, so local/lab-mode scans recorded no coverage
    and there was nothing to build a read surface against. This adds
    the same in-memory backend scan_repository/finding_repository
    already have, so a local demo can populate and read real coverage
    data end to end, mirroring PostgresCoverageRepository's own
    contract exactly."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[tuple[str, str, str, str, str, str], CoverageRecord] = {}

    def record_coverage(
        self,
        *,
        organization_id: str,
        asset: str,
        path: str,
        http_method: str,
        identity_label: str,
        check_id: str,
        status: CoverageStatus,
        scanner_version: str,
        now: datetime,
        check_version: str | None = None,
        scan_id: str | None = None,
        finding_id: str | None = None,
    ) -> CoverageRecord:
        key = (organization_id, asset, path, http_method, identity_label, check_id)
        with self._lock:
            existing = self._records.get(key)
            record = CoverageRecord(
                organization_id=organization_id,
                asset=asset,
                path=path,
                http_method=http_method,
                identity_label=identity_label,
                check_id=check_id,
                status=status,
                scanner_version=scanner_version,
                check_version=check_version,
                last_scan_id=scan_id,
                last_finding_id=finding_id,
                first_observed_at=existing.first_observed_at if existing is not None else now,
                last_observed_at=now,
            )
            self._records[key] = record
        return record

    def list_coverage_for_asset(
        self, organization_id: str, asset: str
    ) -> tuple[CoverageRecord, ...]:
        with self._lock:
            values = [
                r for r in self._records.values()
                if r.organization_id == organization_id and r.asset == asset
            ]
        return tuple(sorted(values, key=lambda r: (r.path, r.http_method, r.identity_label, r.check_id)))

    def list_coverage_for_asset_page(
        self,
        organization_id: str,
        asset: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
    ) -> tuple[tuple[CoverageRecord, ...], bool]:
        with self._lock:
            values = [
                r for r in self._records.values()
                if r.organization_id == organization_id and r.asset == asset
            ]
        values.sort(key=_sort_key, reverse=True)
        if after is not None:
            # after[0] is the cursor's own ISO-8601 string (built by
            # service.py's _timestamp: microsecond precision, "Z"
            # suffix). Comparing it against record.last_observed_at.isoformat()
            # directly would silently miscompare: Python's own
            # isoformat() keeps "+00:00" rather than "Z", a different
            # string for the same instant, so string comparison order
            # would not match datetime order. Parse back to a datetime
            # instead and compare datetimes, never strings, exactly
            # once (a real bug, caught by
            # test_coverage_pagination_returns_a_usable_cursor_for_the_next_page
            # returning one row too many).
            after_at = datetime.fromisoformat(after[0].replace("Z", "+00:00"))
            after_key = (after_at, after[1])
            values = [r for r in values if (r.last_observed_at, coverage_cursor_key(r)) < after_key]
        has_more = len(values) > limit
        return tuple(values[:limit]), has_more

    def count_coverage_by_status(self, organization_id: str, asset: str) -> dict[str, int]:
        """Page-independent totals for this asset's own recorded rows,
        so a paginated view can still show an honest denominator (how
        many rows actually exist, by their real recorded status)
        without depending on how many pages a caller has fetched."""

        with self._lock:
            values = [
                r for r in self._records.values()
                if r.organization_id == organization_id and r.asset == asset
            ]
        counts: dict[str, int] = {}
        for record in values:
            counts[record.status.value] = counts.get(record.status.value, 0) + 1
        return counts


def split_asset_and_path(canonical_url: str) -> tuple[str, str]:
    """Splits an already-canonical scan URL (webguard_contracts'
    ``_canonical_target``/``ScanResult.target``/
    ``CrawlPageScanResult.url``, all validated before this ever runs)
    into (asset, path): asset is the origin, path is everything after
    it. Safe to do with a plain urlsplit here specifically because
    canonicalization already lowercased the host and stripped a
    redundant default port; a non-canonical URL would need the fuller
    normalization ``FindingIdentity``'s own asset parsing does."""

    parsed = urlsplit(canonical_url)
    return f"{parsed.scheme}://{parsed.netloc}", parsed.path or "/"


__all__ = [
    "CoverageRecord",
    "CoverageStatus",
    "CoverageStoreError",
    "InMemoryCoverageRepository",
    "UNAUTHENTICATED_IDENTITY_LABEL",
    "coverage_cursor_key",
    "split_asset_and_path",
]
