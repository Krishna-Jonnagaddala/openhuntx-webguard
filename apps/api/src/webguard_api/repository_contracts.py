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


__all__ = [
    "CallbackRegistrationRepository",
    "IdentityRepository",
    "TargetRepository",
]
