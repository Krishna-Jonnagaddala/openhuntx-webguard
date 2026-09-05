"""Repository protocols (Slice 12 requirement 9): the narrow, backend-
independent contracts that let identical domain logic run unmodified
against SQLite, an in-memory store, or PostgreSQL.

These are structural (``typing.Protocol``, ``@runtime_checkable``) --
existing classes like ``IdentityStore`` satisfy them without being
rewritten to inherit from anything, which is deliberate: retrofitting
a heavily-tested, years-stable SQLite class to formally subclass a new
ABC is exactly the kind of blast-radius-for-no-behavior-change this
project's own conventions avoid. A class satisfies a protocol here
purely by having the right methods with the right shapes.

Every protocol below is defined by *what existing callers already use*
today (``IdentityStore``'s real method surface, the in-memory
``CallbackRepository``'s real method surface, etc.) -- not by
speculatively imagining a richer interface a future caller might
someday want.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from webguard_contracts import (
    ApiTokenMetadata,
    AuditOutcome,
    Organization,
    OrganizationRole,
    Principal,
    PrincipalType,
    SecurityAuditEvent,
)


@runtime_checkable
class IdentityRepository(Protocol):
    """Organizations, principals, API tokens, authorization
    assignments, and audit events -- the identity -> ownership ->
    authorization -> audit chain. Matches ``IdentityStore``'s existing
    public surface exactly."""

    def create_organization(
        self, name: str, *, now: datetime, organization_id: str | None = None
    ) -> Organization: ...

    def get_organization(self, organization_id: str) -> Organization: ...

    def create_principal(
        self,
        organization_id: str,
        display_name: str,
        *,
        principal_type: PrincipalType,
        role: OrganizationRole,
        now: datetime,
        principal_id: str | None = None,
    ) -> Principal: ...

    def get_principal(self, principal_id: str) -> Principal: ...

    def create_token(
        self,
        principal_id: str,
        *,
        label: str,
        now: datetime,
        validity_days: int,
        token_id: str | None = None,
    ): ...

    def authenticate_token(
        self, token: object, *, now: datetime
    ) -> tuple[ApiTokenMetadata, Principal, Organization]: ...

    def revoke_token(self, token_id: str, *, now: datetime) -> ApiTokenMetadata: ...

    def assign_authorization(
        self, organization_id: str, authorization_id: str, *, assigned_by: str, now: datetime
    ) -> None: ...

    def authorization_is_assigned(
        self, organization_id: str, authorization_id: str
    ) -> bool: ...

    def record_audit_event(self, event: SecurityAuditEvent) -> None: ...

    def list_audit_events_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        outcome: AuditOutcome | None = None,
    ) -> tuple[tuple[SecurityAuditEvent, ...], bool]: ...


@runtime_checkable
class TargetRepository(Protocol):
    """Registered target/asset records -- a new entity this slice
    (requirement 4/19), with no prior SQLite table to stay faithful
    to. Both the in-memory (local/lab) and PostgreSQL (production)
    implementations satisfy this identical surface."""

    def create_target(
        self,
        organization_id: str,
        url: str,
        *,
        created_by: str,
        now: datetime,
        label: str | None = None,
        target_id: str | None = None,
    ): ...

    def get_target(self, target_id: str, *, organization_id: str): ...

    def list_targets(self, organization_id: str, *, include_archived: bool = False): ...

    def archive_target(self, target_id: str, *, organization_id: str, now: datetime): ...


@runtime_checkable
class CallbackRegistrationRepository(Protocol):
    """Callback registration/observation storage -- matches the
    in-memory ``CallbackRepository``'s Slice 12 tenant-isolated surface
    exactly, so ``PostgresCallbackRegistrationRepository`` is a drop-in
    production replacement wherever durability across a restart is
    required."""

    def register(
        self,
        *,
        scan_id: str,
        candidate_fingerprint: str,
        organization_id: str,
        target: str,
        authorization_id: str,
        job_id: str | None = None,
        permit_id: str | None = None,
    ): ...

    def get_registration(self, token_value: str, *, organization_id: str): ...

    def revoke_registration(
        self, token_value: str, *, organization_id: str, now: datetime | None = None
    ): ...

    def record_observation(
        self,
        token_value: str,
        *,
        method: str,
        source_class: str = "external",
        now: datetime | None = None,
    ) -> bool: ...


@runtime_checkable
class TenantScopedCallbackBroker(Protocol):
    """What ``executor.py``'s ``_ScanScopedCallbackBroker`` actually
    needs from whatever ``ScanJobExecutor.callback_repository`` holds:
    a ``policy`` to hand the detector, and tenant-scoped
    register/wait -- distinct from ``CallbackRegistrationRepository``
    above, which is the durable *metadata* surface (no ``policy``, no
    ``wait_for_observation``, and its ``register()`` returns a
    ``ScopedCallbackRegistration``, not a scanner-layer
    ``CallbackToken``). The in-memory ``CallbackRepository`` and
    ``postgres_callback_broker.PostgresCallbackBroker`` both satisfy
    this; a bare ``CallbackRegistrationRepository`` does not."""

    @property
    def policy(self): ...

    def register(
        self,
        *,
        scan_id: str,
        candidate_fingerprint: str,
        organization_id: str,
        target: str,
        authorization_id: str,
        job_id: str | None = None,
        permit_id: str | None = None,
    ): ...

    def wait_for_observation(
        self,
        token,
        *,
        organization_id: str,
        policy,
        cancellation_check=None,
    ): ...


@runtime_checkable
class JobRepository(Protocol):
    """Scan-job queue, lease, and TrustScan-permit-binding surface
    (Slice 13 requirements 1-4). Matches ``store.ScanJobStore``'s real
    method surface exactly -- ``WebGuardJobService``, ``ScanJobExecutor``,
    and ``ScanJobWorker`` are typed against this protocol rather than
    the concrete SQLite class, so ``PostgresJobRepository`` is a drop-in
    production implementation with zero changes to those three classes'
    call sites. Schedule methods are part of this protocol's surface
    (``ScanJobStore`` satisfies them) but a production implementation
    may legitimately raise a controlled error for them if schedule
    runtime-wiring is deferred -- see ``PostgresJobRepository``'s
    module docstring."""

    def submit(
        self,
        request,
        *,
        job_id: str | None = None,
        organization_id: str | None = None,
        submitted_by: str | None = None,
        permit_id: str | None = None,
        permit_sha256: str | None = None,
    ): ...

    def get(self, job_id: str): ...
    def get_scope(self, job_id: str) -> tuple[str, str] | None: ...
    def get_scoped(self, job_id: str, organization_id: str): ...
    def list_jobs_scoped_page(self, organization_id: str, *, limit: int, after=None, state=None, mode=None): ...
    def request_cancellation_scoped(self, job_id: str, organization_id: str, *, now: datetime): ...
    def is_cancellation_requested(self, job_id: str) -> bool: ...

    def claim_next_leased(self, *, now: datetime, worker_id: str, lease_seconds: float): ...
    def renew_lease(self, job_id: str, *, worker_id: str, lease_token: str, now: datetime, lease_seconds: float): ...
    def recover_expired_leases(self, *, now: datetime, maximum_attempts: int): ...
    def finish_result_leased(self, job_id: str, *, worker_id, lease_token, scan_id, result_status, report_ref, audit_ref, now, safety_receipt_ref=None, safety_receipt_sha256=None): ...
    def fail_leased(self, job_id: str, *, worker_id: str, lease_token: str, error_code: str, error_message: str, now: datetime, safety_receipt_ref=None, safety_receipt_sha256=None): ...
    def cancel_running_leased(self, job_id: str, *, worker_id: str, lease_token: str, now: datetime): ...

    def create_scan_permit(self, permit): ...
    def get_scan_permit_scoped(self, permit_id: str, organization_id: str): ...
    def revoke_scan_permit_scoped(self, permit_id: str, organization_id: str, *, revoked_by: str, now: datetime): ...
    def get_job_permit_binding(self, job_id: str) -> tuple[str, str] | None: ...
    def get_job_permit_binding_scoped(self, job_id: str, organization_id: str) -> tuple[str, str] | None: ...
    def get_job_safety_receipt_scoped(self, job_id: str, organization_id: str) -> tuple[str, str] | None: ...

    # Config-validation helpers `ScanJobWorker` calls on its `store` to
    # keep worker and persistence validation rules aligned.
    def _worker_id(self, value: object) -> str: ...
    def _lease_seconds(self, value: object) -> float: ...
    def _maximum_attempts(self, value: object) -> int: ...


@runtime_checkable
class ScanRepository(Protocol):
    """Durable scan-run records (Slice 13 requirement 2) -- distinct
    from ``JobRepository``'s queue/lease entity: a scan record is
    created once execution actually begins and captures the permit
    reference, requested checks, and summary/count metadata a Scans
    page needs. Both ``scan_store.InMemoryScanRepository`` (local/lab)
    and ``postgres_scans.PostgresScanRepository`` (production) satisfy
    this."""

    def create_scan(
        self,
        *,
        organization_id: str,
        job_id: str,
        target: str,
        authorization_id: str,
        mode: str,
        scanner_version: str,
        now: datetime,
        permit_id: str | None = None,
        permit_fingerprint: str | None = None,
        requested_checks: tuple[str, ...] = (),
        scan_id: str | None = None,
    ): ...

    def complete_scan(self, scan_id: str, *, organization_id: str, status: str, report_ref, finding_count: int, now: datetime): ...
    def get_scan_scoped(self, scan_id: str, *, organization_id: str): ...
    def list_scans_scoped(self, organization_id: str): ...


@runtime_checkable
class FindingRepository(Protocol):
    """Deterministic-fingerprint finding persistence, deduplication,
    and lifecycle (Slice 13 requirements 6-8) -- see
    ``finding_store``'s module docstring for the exact dedup/lifecycle
    rules both ``InMemoryFindingRepository`` (local/lab) and
    ``PostgresFindingRepository`` (production) enforce identically."""

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
    ): ...

    def get_finding_scoped(self, finding_id: str, *, organization_id: str): ...
    def list_findings_scoped_page(self, organization_id: str, *, limit: int, after=None, scan_id=None, status=None): ...
    def update_status(self, finding_id: str, *, organization_id: str, new_status, now: datetime): ...


__all__ = [
    "CallbackRegistrationRepository",
    "FindingRepository",
    "IdentityRepository",
    "JobRepository",
    "ScanRepository",
    "TargetRepository",
    "TenantScopedCallbackBroker",
]
