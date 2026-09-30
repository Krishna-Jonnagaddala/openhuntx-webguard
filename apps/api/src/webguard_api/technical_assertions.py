"""Compliance technical assertion catalog (platform expansion,
docs/PLATFORM_SCOPE.md, handoff section 10.1 and 10.3).

A technical assertion describes a specific, checkable question this
codebase knows how to answer from a named SOC connector's own already-
verified data (docs/CONNECTOR_CAPABILITIES.md's "Compliance data
sources" section: initial assertion families read from the same
underlying APIs as the SOC connectors, where authoritative APIs
support them). Like ACTIVE_DETECTOR_REGISTRY
(workers/scanner/src/webguard_scanner/active_detector_registry.py) and
SOC_CONNECTOR_REGISTRY (soc_connectors.py), this is a static,
code-level catalog of what this codebase can check, not any
organization's own live result: it has no organization_id and needs
no database table, since a real assertion inherently ships with its
own collection/evaluation code, not a row an operator could add
without a deploy. A future, separate, tenant-scoped record will track
one organization's own collection attempt and outcome against one of
these assertions (handoff section 10.2's "collection" and "assertion"
status dimensions); nothing here is that record, and this catalog is
the necessary anchor for it, the same "catalog first, tenant-scoped
instance later" order compliance.py's Framework/MasterControl catalog
and compliance_scope.py's ScopedControlImplementation already used.

Deliberately not modeled in this v1 catalog, matching handoff section
10.3's own full field list only partially (the same "ship the real
subset, name the rest" discipline compliance.py's own module docstring
already established): applicable-population definition, input schema,
the assertion logic itself (that lives in this codebase's own future
collection code once written, not as descriptive metadata here),
per-assertion output-state enumeration (every assertion shares the
same four-value AssertionOutcome vocabulary below, handoff section
10.2's "Assertion" status dimension, not a custom set per assertion),
cadence, freshness budget, fixtures, owner, and framework-control
mappings (section 10.1's own explicit split between "assertions/tests"
and "mappings": an assertion's relevance to any specific framework's
control is a separate, later, reviewed relationship, never assumed
here).

Every source_connector_id below is cross-checked at construction time
against SOC_CONNECTOR_REGISTRY (soc_connectors.py), and every
required_permission against that connector's own manifest permissions,
so a technical assertion can never silently reference a connector or
permission this codebase does not actually define. Seeded assertions
below are Entra- and Sentinel-sourced; Defender XDR has no equally
direct fit yet (its own known_limitations already caution against
treating Secure Score as a trend from a single call, which rules it
out as a simple inventory-style assertion source for now).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .soc_connectors import SOC_CONNECTOR_REGISTRY


class AssertionOutcome(str, Enum):
    """handoff section 10.2's own "Assertion" status dimension. One
    shared vocabulary for every technical assertion's own future
    execution result, not a per-assertion customizable set."""

    SATISFIED = "satisfied"
    VIOLATED = "violated"
    INDETERMINATE = "indeterminate"
    NOT_TESTED = "not_tested"


class TechnicalAssertionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class TechnicalAssertion:
    assertion_id: str
    title: str
    objective: str
    version: str
    source_connector_id: str
    required_permissions: tuple[str, ...]

    def __post_init__(self) -> None:
        connector = SOC_CONNECTOR_REGISTRY.get(self.source_connector_id)
        if connector is None:
            raise TechnicalAssertionError(
                "technical_assertion_unknown_connector",
                f"source_connector_id {self.source_connector_id!r} is not registered in "
                f"SOC_CONNECTOR_REGISTRY.",
            )
        manifest_permissions = {permission.name for permission in connector.permissions}
        unlisted = set(self.required_permissions) - manifest_permissions
        if unlisted:
            raise TechnicalAssertionError(
                "technical_assertion_undeclared_permission",
                f"required_permissions references {sorted(unlisted)}, not declared on the "
                f"{self.source_connector_id!r} connector's own manifest.",
            )


_ENTRA_PRIVILEGED_ROLE_INVENTORY = TechnicalAssertion(
    assertion_id="entra_privileged_role_inventory",
    title="Entra privileged directory role assignments",
    objective=(
        "Enumerate active directory role assignments, the population handoff section 10.3 "
        "names first among initial assertion families and the denominator every privileged-"
        "account assertion built on top of this one must expose honestly."
    ),
    version="1.0",
    source_connector_id="entra",
    required_permissions=("RoleManagement.Read.Directory",),
)

_ENTRA_CONDITIONAL_ACCESS_POLICY_MODE = TechnicalAssertion(
    assertion_id="entra_conditional_access_policy_mode",
    title="Entra Conditional Access policy mode and exclusions",
    objective=(
        "Read each Conditional Access policy's enabled/report-only/disabled mode and its "
        "exclusions, preserving the enabled-versus-report-only distinction handoff section "
        "10.3 requires rather than collapsing it into a boolean."
    ),
    version="1.0",
    source_connector_id="entra",
    required_permissions=("Policy.Read.All",),
)

_ENTRA_STALE_PRIVILEGED_ACCOUNT = TechnicalAssertion(
    assertion_id="entra_stale_privileged_account",
    title="Stale privileged account activity",
    objective=(
        "Cross-reference privileged role assignment with sign-in activity to identify "
        "privileged accounts with no recent authentication evidence, one of handoff section "
        "10.3's named initial families."
    ),
    version="1.0",
    source_connector_id="entra",
    required_permissions=("User.Read.All", "AuditLog.Read.All"),
)

_SENTINEL_DATA_CONNECTOR_HEALTH = TechnicalAssertion(
    assertion_id="sentinel_data_connector_health",
    title="Sentinel required log-source connector health",
    objective=(
        "Enumerate configured Sentinel data connectors and their per-data-type enabled "
        "state, the 'required log-source health' family handoff section 10.3 names."
    ),
    version="1.0",
    source_connector_id="sentinel",
    required_permissions=("Microsoft Sentinel Reader",),
)

_SENTINEL_DETECTION_RULE_ENABLEMENT = TechnicalAssertion(
    assertion_id="sentinel_detection_rule_enablement",
    title="Sentinel analytics rule enablement",
    objective=(
        "Enumerate Sentinel analytics rules and their enabled state, the 'detection "
        "enablement' half of handoff section 10.3's named family (execution-error tracking "
        "is a later, evidence-level concern, not modeled by this catalog entry)."
    ),
    version="1.0",
    source_connector_id="sentinel",
    required_permissions=("Microsoft Sentinel Reader",),
)

TECHNICAL_ASSERTION_REGISTRY: dict[str, TechnicalAssertion] = {
    assertion.assertion_id: assertion
    for assertion in (
        _ENTRA_PRIVILEGED_ROLE_INVENTORY,
        _ENTRA_CONDITIONAL_ACCESS_POLICY_MODE,
        _ENTRA_STALE_PRIVILEGED_ACCOUNT,
        _SENTINEL_DATA_CONNECTOR_HEALTH,
        _SENTINEL_DETECTION_RULE_ENABLEMENT,
    )
}

__all__ = [
    "TECHNICAL_ASSERTION_REGISTRY",
    "AssertionOutcome",
    "TechnicalAssertion",
    "TechnicalAssertionError",
]
