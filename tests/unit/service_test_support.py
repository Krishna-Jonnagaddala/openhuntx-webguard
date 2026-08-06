from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webguard_contracts import (
    OwnedTargetAuthorization,
    OwnedTargetLimits,
    ScanCoverage,
    ScanResult,
    ScanStatus,
    write_owned_target_authorization_file,
)


NOW = datetime(2026, 8, 6, 18, 0, tzinfo=timezone.utc)
AUTH_ID = "8ae6403f-7832-498c-b37e-c0c87be19ea1"
TARGET = "https://internstack.in/"


def authorization(**changes) -> OwnedTargetAuthorization:
    values = dict(
        authorization_id=AUTH_ID,
        organization="InternStack",
        authorized_by="Krishna Jonnagaddala",
        target=TARGET,
        allowed_hosts=("internstack.in",),
        issued_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=30),
        purpose="Controlled passive production assessment",
        limits=OwnedTargetLimits(),
    )
    values.update(changes)
    return OwnedTargetAuthorization(**values)


def write_authorization(directory: Path, value: OwnedTargetAuthorization | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    path = directory / "internstack.in.json"
    write_owned_target_authorization_file(
        authorization() if value is None else value,
        path,
    )
    os.chmod(path, 0o600)
    return path


def completed_report(scan_id: str, *, status: ScanStatus = ScanStatus.COMPLETED) -> ScanResult:
    errors = ()
    if status in {ScanStatus.FAILED, ScanStatus.COMPLETED_WITH_ERRORS}:
        from webguard_contracts import ScanError
        errors = (
            ScanError(
                code="simulated_error",
                message="Simulated error.",
                stage="test",
                retryable=False,
            ),
        )
    return ScanResult(
        scan_id=scan_id,
        scan_type="passive_http",
        status=status,
        target=TARGET,
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=NOW,
        completed_at=NOW,
        coverage=ScanCoverage(),
        errors=errors,
    )
