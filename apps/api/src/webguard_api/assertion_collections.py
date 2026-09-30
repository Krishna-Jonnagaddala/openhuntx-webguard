"""Technical assertion collection and evaluation (platform expansion,
docs/PLATFORM_SCOPE.md, handoff sections 10.1-10.3; product vision:
one organization's own real result against a catalog entry in
technical_assertions.py, not just the catalog of what could be
checked).

This is the first genuinely executed Compliance signal in this
codebase. Nothing here talks to a live Microsoft tenant: no SOC
connector in this codebase has a live HTTP client yet
(soc_connectors.py's own manifests are all live_validation_state=
CONTRACT_DESIGNED), so every collection here reads either a fixture
evidence set checked into this module (FIXTURE_EVIDENCE_SETS below,
labeled as fixture data everywhere it surfaces, never presented as a
live vendor read) or a caller-supplied evidence payload shaped the
same way a real connector response eventually will be
(EvidenceSource.MANUAL). Building the tenant-scoped collection/
evaluation record against these two evidence paths first, exactly as
this codebase's own connectors and framework catalog were each built
fixture-first before any live client existed, does not require a live
connector to start (docs/PROJECT_EXECUTION_LEDGER.md's "Coverage Truth
Map" and "SOC's first connector contract" sections establish the same
sequencing precedent).

Collection and evaluation are two distinct steps, deliberately kept as
two separate timestamped facts on one record rather than collapsed
into a single pass/fail bit (handoff section 10.2's own split between
the "collection" and "assertion" status dimensions):

- Collection can FAIL entirely (the fixture name is unknown, or the
  supplied evidence does not even parse as the expected shape). A
  failed collection has no evidence and is never evaluated: there is
  nothing to evaluate.
- A collection that SUCCEEDS produces real evidence, which is then
  evaluated into one of AssertionOutcome's four values
  (technical_assertions.py): SATISFIED, VIOLATED, or INDETERMINATE
  when the evidence is missing a field this assertion's own logic
  needs to decide (a real, distinct outcome from either "satisfied" or
  a collection failure, not silently folded into "not tested").
  NOT_TESTED is not something evaluation ever produces here: it
  describes an assertion nobody has attempted yet, which is simply the
  absence of any collection row for that (organization, assertion_id)
  pair, the same "missing row means never decided" discipline
  compliance_scope.py's own ScopedControlImplementation already uses
  for applicability.

v1 implements evaluation for exactly one assertion,
entra_conditional_access_policy_mode, the smallest of the five
catalog entries with an evidence shape simple enough to evaluate
honestly without inventing criteria the handoff never specified. Its
assertion logic, stated plainly since this is exactly the kind of
"why is this code correct" claim CLAUDE.md's own style rule calls out:
**at least one Conditional Access policy in `enabled` mode is required
to satisfy this assertion; report-only or disabled policies do not
enforce anything, so an organization relying solely on those has no
active Conditional Access enforcement regardless of how many policies
exist.** This is a real, defensible reading of what "Conditional
Access policy mode" being satisfied should mean, not an arbitrary
placeholder threshold. The other four catalog assertions have no
evaluation function yet; attempting to collect against one of them
raises TechnicalAssertionCollectionError, not a silently wrong result.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from uuid import uuid4

from .technical_assertions import TECHNICAL_ASSERTION_REGISTRY, AssertionOutcome


class EvidenceSource(str, Enum):
    FIXTURE = "fixture"
    MANUAL = "manual"


class CollectionStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class AssertionCollectionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class AssertionCollectionRecord:
    collection_id: str
    organization_id: str
    assertion_id: str
    assertion_version: str
    evidence_source: EvidenceSource
    evidence_provenance: str
    collection_status: CollectionStatus
    collected_by: str
    collected_at: datetime
    collection_error: str | None = None
    raw_evidence: object | None = None
    outcome: AssertionOutcome | None = None
    outcome_detail: str | None = None
    evaluated_at: datetime | None = None


# Fixture evidence sets (Microsoft Graph conditionalAccessPolicy shape:
# https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy,
# `state` is one of "enabled", "disabled", "enabledForReportingButNotEnforced").
# Labeled as fixture data everywhere a collection built from these
# surfaces (evidence_source=FIXTURE, evidence_provenance names the set
# below by name): never presented as a live Entra tenant read, because
# it is not one.
FIXTURE_EVIDENCE_SETS: dict[str, list[dict]] = {
    "entra_ca_policies_one_enforced": [
        {"id": "ca-001", "displayName": "Require MFA for administrators", "state": "enabled"},
        {
            "id": "ca-002",
            "displayName": "Legacy report-only pilot for contractors",
            "state": "enabledForReportingButNotEnforced",
        },
    ],
    "entra_ca_policies_none_enforced": [
        {
            "id": "ca-003",
            "displayName": "Draft policy, not yet turned on",
            "state": "disabled",
        },
        {
            "id": "ca-004",
            "displayName": "Reporting-only rollout, still being evaluated",
            "state": "enabledForReportingButNotEnforced",
        },
    ],
    "entra_ca_policies_missing_state_field": [
        {"id": "ca-005", "displayName": "Malformed evidence: no state field at all"},
    ],
}


def _evaluate_conditional_access_policy_mode(evidence: list[dict]) -> tuple[AssertionOutcome, str]:
    if not evidence:
        return (
            AssertionOutcome.VIOLATED,
            "0 Conditional Access policies recorded: no active enforcement exists.",
        )
    states: list[str] = []
    for policy in evidence:
        if "state" not in policy:
            return (
                AssertionOutcome.INDETERMINATE,
                f"Policy {policy.get('id', '<unknown id>')!r} carries no 'state' field; "
                f"cannot determine enforcement without it.",
            )
        states.append(policy["state"])
    enabled_count = sum(1 for state in states if state == "enabled")
    if enabled_count > 0:
        return (
            AssertionOutcome.SATISFIED,
            f"{enabled_count} of {len(states)} recorded policies are in 'enabled' mode.",
        )
    return (
        AssertionOutcome.VIOLATED,
        f"0 of {len(states)} recorded policies are in 'enabled' mode "
        f"(report-only/disabled policies enforce nothing).",
    )


_EVALUATORS = {
    "entra_conditional_access_policy_mode": _evaluate_conditional_access_policy_mode,
}


def collect_and_evaluate(
    *,
    organization_id: str,
    assertion_id: str,
    evidence_source: EvidenceSource,
    collected_by: str,
    now: datetime,
    fixture_name: str | None = None,
    manual_evidence: list[dict] | None = None,
    collection_id: str | None = None,
) -> AssertionCollectionRecord:
    """Runs one collection attempt against one assertion and, if
    collection succeeds, evaluates it immediately (v1 keeps these
    synchronous and atomic; a future slice could separate them into
    distinct submit/evaluate steps if collection ever becomes
    asynchronous). Never raises for a collection failure or an
    INDETERMINATE evaluation: those are real, valid outcomes,
    returned on the record, not exceptions. Raises
    AssertionCollectionError only for a genuinely invalid request this
    codebase cannot honor at all (an unknown assertion_id, an
    unevaluatable assertion, or a caller error like naming both/
    neither evidence source)."""

    assertion = TECHNICAL_ASSERTION_REGISTRY.get(assertion_id)
    if assertion is None:
        raise AssertionCollectionError(
            "technical_assertion_unknown", f"{assertion_id!r} is not in TECHNICAL_ASSERTION_REGISTRY."
        )
    evaluator = _EVALUATORS.get(assertion_id)
    if evaluator is None:
        raise AssertionCollectionError(
            "technical_assertion_not_evaluatable",
            f"{assertion_id!r} has no evaluation logic in this version of the codebase yet.",
        )

    if evidence_source is EvidenceSource.FIXTURE:
        if fixture_name is None or manual_evidence is not None:
            raise AssertionCollectionError(
                "assertion_collection_request_invalid",
                "evidence_source=fixture requires fixture_name and no manual_evidence.",
            )
        evidence_provenance = f"fixture:{fixture_name}"
        evidence = FIXTURE_EVIDENCE_SETS.get(fixture_name)
        if evidence is None:
            return AssertionCollectionRecord(
                collection_id=collection_id or str(uuid4()),
                organization_id=organization_id,
                assertion_id=assertion_id,
                assertion_version=assertion.version,
                evidence_source=evidence_source,
                evidence_provenance=evidence_provenance,
                collection_status=CollectionStatus.FAILED,
                collection_error=f"Unknown fixture name {fixture_name!r}.",
                collected_by=collected_by,
                collected_at=now,
            )
    elif evidence_source is EvidenceSource.MANUAL:
        if manual_evidence is None or fixture_name is not None:
            raise AssertionCollectionError(
                "assertion_collection_request_invalid",
                "evidence_source=manual requires manual_evidence and no fixture_name.",
            )
        evidence_provenance = f"manually supplied by principal {collected_by}"
        evidence = manual_evidence
    else:
        raise AssertionCollectionError(
            "assertion_collection_request_invalid", f"Unknown evidence_source {evidence_source!r}."
        )

    outcome, detail = evaluator(evidence)
    return AssertionCollectionRecord(
        collection_id=collection_id or str(uuid4()),
        organization_id=organization_id,
        assertion_id=assertion_id,
        assertion_version=assertion.version,
        evidence_source=evidence_source,
        evidence_provenance=evidence_provenance,
        collection_status=CollectionStatus.SUCCEEDED,
        raw_evidence=evidence,
        outcome=outcome,
        outcome_detail=detail,
        collected_by=collected_by,
        collected_at=now,
        evaluated_at=now,
    )


class InMemoryAssertionCollectionRepository:
    """Local/unit/lab backend, mirroring the rest of this codebase's
    in-memory/Postgres split. record() stores whatever
    AssertionCollectionRecord collect_and_evaluate already built or
    validated: this repository does not itself run collection or
    evaluation logic, only persists the result, the same "service
    orchestrates, repository persists" split every other repository in
    this codebase already follows."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, AssertionCollectionRecord] = {}

    def record(self, record: AssertionCollectionRecord) -> AssertionCollectionRecord:
        with self._lock:
            self._records[record.collection_id] = record
        return record

    def list_for_assertion(
        self, organization_id: str, assertion_id: str
    ) -> tuple[AssertionCollectionRecord, ...]:
        with self._lock:
            values = [
                r for r in self._records.values()
                if r.organization_id == organization_id and r.assertion_id == assertion_id
            ]
        return tuple(sorted(values, key=lambda r: r.collected_at, reverse=True))


__all__ = [
    "FIXTURE_EVIDENCE_SETS",
    "AssertionCollectionError",
    "AssertionCollectionRecord",
    "CollectionStatus",
    "EvidenceSource",
    "InMemoryAssertionCollectionRepository",
    "collect_and_evaluate",
]
