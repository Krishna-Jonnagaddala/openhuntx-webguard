from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from webguard_contracts import (
    OwnedTargetAuthorization,
    OwnedTargetLimits,
    ScanCoverage,
    ScanJobMode,
    TrustScanPermitClaims,
    ScanResult,
    ScanStatus,
    write_owned_target_authorization_file,
)


NOW = datetime(2026, 8, 6, 18, 0, tzinfo=timezone.utc)
AUTH_ID = "8ae6403f-7832-498c-b37e-c0c87be19ea1"
TARGET = "https://example.com/"


def authorization(**changes) -> OwnedTargetAuthorization:
    values = dict(
        authorization_id=AUTH_ID,
        organization="InternStack",
        authorized_by="Krishna Jonnagaddala",
        target=TARGET,
        allowed_hosts=("example.com",),
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
    path = directory / "example.com.json"
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

ORG_ID = "11111111-1111-4111-8111-111111111111"
OWNER_ID = "22222222-2222-4222-8222-222222222222"
VIEWER_ID = "33333333-3333-4333-8333-333333333333"
OWNER_TOKEN_ID = "44444444-4444-4444-8444-444444444444"
VIEWER_TOKEN_ID = "55555555-5555-4555-8555-555555555555"


def create_identity_fixture(database: Path, *, role=None, principal_id=None, token_id=None):
    from webguard_api import AuthContext, IdentityStore
    from webguard_contracts import OrganizationRole, PrincipalType

    identity = IdentityStore(database)
    try:
        organization = identity.get_organization(ORG_ID)
    except Exception:
        organization = identity.create_organization(
            "InternStack",
            now=NOW,
            organization_id=ORG_ID,
        )
    effective_role = OrganizationRole.OWNER if role is None else role
    effective_principal_id = OWNER_ID if principal_id is None else principal_id
    effective_token_id = OWNER_TOKEN_ID if token_id is None else token_id
    try:
        principal = identity.get_principal(effective_principal_id)
    except Exception:
        principal = identity.create_principal(
            organization.organization_id,
            "Krishna Jonnagaddala" if effective_role is OrganizationRole.OWNER else "Test Viewer",
            principal_type=PrincipalType.USER,
            role=effective_role,
            now=NOW,
            principal_id=effective_principal_id,
        )
    issued = identity.create_token(
        principal.principal_id,
        label=f"{effective_role.value}-test",
        validity_days=30,
        now=NOW,
        token_id=effective_token_id,
    )
    identity.assign_authorization(
        organization.organization_id,
        AUTH_ID,
        assigned_by=principal.principal_id,
        now=NOW,
    )
    context = AuthContext(
        organization_id=organization.organization_id,
        organization_name=organization.name,
        principal_id=principal.principal_id,
        principal_name=principal.display_name,
        role=principal.role,
        token_id=issued.metadata.token_id,
    )
    return identity, context, issued.token


def trustscan_signer(store):
    from webguard_api import TrustScanSigner

    return TrustScanSigner(store.trustscan_signing_private_key())


def create_trustscan_permit(
    store,
    *,
    value: OwnedTargetAuthorization | None = None,
    organization_id: str = ORG_ID,
    issued_by: str = OWNER_ID,
    permitted_modes: tuple[ScanJobMode, ...] = (ScanJobMode.CRAWL, ScanJobMode.SINGLE_PAGE),
    allowed_http_methods: tuple[str, ...] = ("GET", "HEAD"),
    not_before: datetime = NOW,
    expires_at: datetime | None = None,
    maximum_request_attempts: int | None = None,
    maximum_requests_per_second: float | None = None,
    permit_id: str | None = None,
    active_checks: tuple[str, ...] = (),
):
    """Create one valid persisted TrustScan v1 permit for unit tests."""

    auth = authorization() if value is None else value
    effective_expiry = (
        min(auth.expires_at, NOW + timedelta(days=7))
        if expires_at is None
        else expires_at
    )
    effective_attempts = (
        auth.limits.maximum_request_attempts
        if maximum_request_attempts is None
        else maximum_request_attempts
    )
    effective_rate = (
        min(1.0, 1.0 / auth.limits.minimum_delay_seconds)
        if maximum_requests_per_second is None
        else maximum_requests_per_second
    )
    claims = TrustScanPermitClaims(
        permit_id=str(uuid4()) if permit_id is None else permit_id,
        organization_id=organization_id,
        authorization_id=auth.authorization_id,
        authorization_sha256=auth.fingerprint,
        target=auth.target,
        issued_by=issued_by,
        issued_at=NOW,
        not_before=not_before,
        expires_at=effective_expiry,
        permitted_modes=permitted_modes,
        allowed_http_methods=allowed_http_methods,
        maximum_request_attempts=effective_attempts,
        maximum_requests_per_second=effective_rate,
        maximum_concurrency=1,
        active_checks=active_checks,
    )
    signed = trustscan_signer(store).sign(claims)
    return store.create_scan_permit(signed)
