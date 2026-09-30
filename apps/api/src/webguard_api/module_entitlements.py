"""Module entitlement (platform expansion, docs/PLATFORM_SCOPE.md and
docs/adr/0033-platform-expansion-module-boundaries.md): which of
WebGuard, SOC, and Compliance an organization has access to.

A genuinely new entity with no prior SQLite table to preserve.
Local/unit/lab uses :class:`InMemoryModuleEntitlementRepository`;
production uses :class:`webguard_api.postgres_module_entitlements.PostgresModuleEntitlementRepository`,
mirroring the production-boundary split ``targets.py``/
``postgres_targets.py`` already use, both satisfying the same
method surface.

Every organization is meant to carry exactly one row per
:class:`webguard_contracts.PlatformModule` at all times: WebGuard
enabled by default, SOC and Compliance disabled by default
(``grant_default_entitlements``, called once at organization
creation). ``get_entitlement``/``has_module_access`` fail closed
(``module_entitlement_not_found`` / ``False``) on a missing row rather
than guessing what an absent row would have meant, see the
migration's own comment for why a missing row is meant to be a defect,
not a state application code relies on.
"""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import datetime, timezone

from webguard_contracts import ModuleEntitlement, ModuleEntitlementStatus, PlatformModule


class ModuleEntitlementError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


_DEFAULT_STATUS_BY_MODULE = {
    PlatformModule.WEBGUARD: ModuleEntitlementStatus.ENABLED,
    PlatformModule.SOC: ModuleEntitlementStatus.DISABLED,
    PlatformModule.COMPLIANCE: ModuleEntitlementStatus.DISABLED,
}


class InMemoryModuleEntitlementRepository:
    """Local/unit/lab backend. Matches
    :class:`webguard_api.postgres_module_entitlements.PostgresModuleEntitlementRepository`'s
    behavior and error codes exactly, so contract tests exercise both
    with the same test bodies."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entitlements: dict[tuple[str, PlatformModule], ModuleEntitlement] = {}

    def grant_default_entitlements(
        self, organization_id: str, *, now: datetime
    ) -> tuple[ModuleEntitlement, ...]:
        moment = now.astimezone(timezone.utc)
        with self._lock:
            created = []
            for module, status in _DEFAULT_STATUS_BY_MODULE.items():
                record = ModuleEntitlement(
                    organization_id=organization_id,
                    module=module,
                    status=status,
                    updated_at=moment,
                    enabled_at=moment if status is ModuleEntitlementStatus.ENABLED else None,
                )
                self._entitlements[(organization_id, module)] = record
                created.append(record)
        return tuple(created)

    def set_entitlement(
        self,
        organization_id: str,
        module: PlatformModule,
        *,
        status: ModuleEntitlementStatus,
        now: datetime,
        changed_by: str | None = None,
    ) -> ModuleEntitlement:
        moment = now.astimezone(timezone.utc)
        with self._lock:
            existing = self._entitlements.get((organization_id, module))
            if existing is None:
                raise ModuleEntitlementError(
                    "module_entitlement_not_found",
                    "No module entitlement record exists for this organization and module.",
                )
            if status in (ModuleEntitlementStatus.ENABLED, ModuleEntitlementStatus.TRIAL):
                updated = replace(
                    existing,
                    status=status,
                    updated_at=moment,
                    enabled_at=moment,
                    enabled_by=changed_by,
                )
            else:
                updated = replace(
                    existing,
                    status=status,
                    updated_at=moment,
                    disabled_at=moment,
                    disabled_by=changed_by,
                )
            self._entitlements[(organization_id, module)] = updated
        return updated

    def get_entitlement(self, organization_id: str, module: PlatformModule) -> ModuleEntitlement:
        with self._lock:
            record = self._entitlements.get((organization_id, module))
        if record is None:
            raise ModuleEntitlementError(
                "module_entitlement_not_found",
                "No module entitlement record exists for this organization and module.",
            )
        return record

    def list_entitlements(self, organization_id: str) -> tuple[ModuleEntitlement, ...]:
        with self._lock:
            values = [
                record
                for (org_id, _module), record in self._entitlements.items()
                if org_id == organization_id
            ]
        return tuple(sorted(values, key=lambda record: record.module.value))

    def has_module_access(self, organization_id: str, module: PlatformModule) -> bool:
        with self._lock:
            record = self._entitlements.get((organization_id, module))
        return record is not None and record.status in (
            ModuleEntitlementStatus.ENABLED,
            ModuleEntitlementStatus.TRIAL,
        )


__all__ = ["InMemoryModuleEntitlementRepository", "ModuleEntitlementError"]
