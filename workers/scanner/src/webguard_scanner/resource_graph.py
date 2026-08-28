"""Authorization resource graph and cross-identity comparison eligibility
(Slice 9).

Discovery (`authorization_resource_discovery.py`) produces resources
independently per identity. This module assembles them into a graph
keyed by owning test identity, then applies deterministic eligibility
rules (requirement 9) to decide which resource *pairs* -- never
arbitrary resources -- are allowed to be handed to the existing
IDOR/BOLA comparison engine (`idor_authorization_detector.py`, Slice
8, unchanged). Not every discovered resource is automatically
compared: a resource with `PUBLIC`/`SHARED`/`UNKNOWN` expected access,
an unapproved identifier provenance, or no structurally matching
counterpart under the other identity is simply never paired -- this is
a pre-filter in addition to, not a replacement for, the detector's own
shared/public exclusion in `_classify`.

The graph never stores authentication material -- only
`AuthorizationResource` values, which are references (endpoint,
method, identifier), never secrets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Tuple
from urllib.parse import urlsplit

from .authorization_resource import (
    AuthorizationResource,
    IdentifierLocation,
    IdentifierProvenance,
    ResourceOwnership,
)
from .idor_authorization_detector import AuthorizationResourcePair

MAXIMUM_COMPARISON_PAIRS = 20

# Every IdentifierProvenance member names a legitimate, controlled
# observation mechanism (see authorization_resource.py) -- there is no
# member for a generated/enumerated value. This allow-list exists as an
# explicit, re-checked gate anyway (requirement 5: "the IDOR engine may
# only compare identifiers from approved provenance sources"), rather
# than assuming every current or future enum member is automatically
# comparison-safe.
APPROVED_COMPARISON_PROVENANCE: FrozenSet[IdentifierProvenance] = frozenset(
    IdentifierProvenance
)

_READ_ONLY_METHODS = frozenset({"GET", "HEAD"})


@dataclass
class AuthorizationResourceGraph:
    """Resources discovered so far, keyed by owning test identity label.
    Deduplicated by `resource_id` within each identity."""

    _resources_by_identity: Dict[str, Dict[str, AuthorizationResource]] = field(
        default_factory=dict, init=False, repr=False
    )

    def add_resources(
        self, identity_label: str, resources: Tuple[AuthorizationResource, ...]
    ) -> None:
        bucket = self._resources_by_identity.setdefault(identity_label, {})
        for resource in resources:
            if resource.owning_test_identity != identity_label:
                continue
            bucket.setdefault(resource.resource_id, resource)

    def resources_for(self, identity_label: str) -> Tuple[AuthorizationResource, ...]:
        return tuple(self._resources_by_identity.get(identity_label, {}).values())

    def identities(self) -> Tuple[str, ...]:
        return tuple(self._resources_by_identity)


def _endpoint_template(resource: AuthorizationResource) -> str:
    """A structural key identifying "the same logical endpoint, for any
    identifier value" -- the templated path with this resource's own
    identifier value removed, so two resources for the same endpoint
    shape but different concrete objects produce the same template."""

    parsed = urlsplit(resource.endpoint)
    canonical = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    if (
        resource.identifier_location is IdentifierLocation.PATH
        and resource.identifier_value
        and resource.identifier_value in canonical
    ):
        canonical = canonical.replace(resource.identifier_value, "{identifier}", 1)
    return "|".join(
        (
            canonical,
            resource.method,
            resource.identifier_location.value,
            resource.identifier_name,
        )
    )


def is_eligible_for_comparison(
    primary: AuthorizationResource, secondary: AuthorizationResource
) -> bool:
    """Deterministic eligibility rules (requirement 9). All of the
    following must hold, or the pair is never compared:

    - distinct, controlled owning identities (never comparing a
      resource against itself, or against another resource owned by
      the same identity);
    - the same resource type;
    - a compatible endpoint (same structural template) and method;
    - the same identifier location (never comparing a path-addressed
      resource against a query- or body-addressed one);
    - a private-to-owner expectation on both sides -- SHARED, PUBLIC,
      and UNKNOWN resources are never automatically compared, even if
      both sides happen to be reachable;
    - a read-only (GET/HEAD) operation;
    - an approved identifier provenance on both sides.
    """

    if primary.owning_test_identity == secondary.owning_test_identity:
        return False
    if primary.resource_type != secondary.resource_type:
        return False
    if primary.method != secondary.method:
        return False
    if primary.method not in _READ_ONLY_METHODS:
        return False
    if primary.identifier_location != secondary.identifier_location:
        return False
    if primary.identifier_location is IdentifierLocation.NONE:
        return False
    if (
        primary.expected_access != ResourceOwnership.PRIVATE_TO_OWNER
        or secondary.expected_access != ResourceOwnership.PRIVATE_TO_OWNER
    ):
        return False
    if (
        primary.provenance not in APPROVED_COMPARISON_PROVENANCE
        or secondary.provenance not in APPROVED_COMPARISON_PROVENANCE
    ):
        return False
    if primary.identifier_value == secondary.identifier_value:
        return False
    if _endpoint_template(primary) != _endpoint_template(secondary):
        return False
    return True


def build_comparison_pairs(
    graph: AuthorizationResourceGraph,
    *,
    primary_identity: str,
    secondary_identity: str,
    maximum_pairs: int = MAXIMUM_COMPARISON_PAIRS,
) -> Tuple[AuthorizationResourcePair, ...]:
    """Pair up structurally matching, eligible resources between exactly
    two identities' own discovered resource sets. Bounded by
    `maximum_pairs`; a resource is used in at most one pair (first
    eligible match wins, in discovery order) to keep the resulting
    comparison count predictable."""

    primary_resources = graph.resources_for(primary_identity)
    secondary_resources = graph.resources_for(secondary_identity)

    pairs: list[AuthorizationResourcePair] = []
    used_secondary_ids: set[str] = set()
    for primary_resource in primary_resources:
        if len(pairs) >= maximum_pairs:
            break
        for secondary_resource in secondary_resources:
            if secondary_resource.resource_id in used_secondary_ids:
                continue
            if not is_eligible_for_comparison(primary_resource, secondary_resource):
                continue
            pairs.append(
                AuthorizationResourcePair(
                    primary_resource=primary_resource,
                    secondary_resource=secondary_resource,
                )
            )
            used_secondary_ids.add(secondary_resource.resource_id)
            break
    return tuple(pairs)


__all__ = [
    "APPROVED_COMPARISON_PROVENANCE",
    "MAXIMUM_COMPARISON_PAIRS",
    "AuthorizationResourceGraph",
    "build_comparison_pairs",
    "is_eligible_for_comparison",
]
