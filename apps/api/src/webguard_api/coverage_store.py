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
    "UNAUTHENTICATED_IDENTITY_LABEL",
    "split_asset_and_path",
]
