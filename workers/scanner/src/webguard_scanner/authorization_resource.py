"""Deterministic authorization-sensitive resource model (Slice 8).

This module intentionally contains no mechanism for generating,
enumerating, or guessing a resource identifier. Every
`AuthorizationResource` this module can produce carries a `source` value
drawn from `ResourceSource` -- an explicit, closed enum -- and the only
way to construct one is to already have the identifier in hand from a
controlled origin (an operator-supplied test-resource specification, in
this slice's actual usage; the other enum members exist so a future
slice that observes a resource id from a legitimate authenticated
response, or one a test identity itself created, has a place to record
that provenance honestly, without inventing a new "we don't really know"
category). There is no `for candidate_id in range(...)` anywhere in this
codebase, and there must never be one that produces an
`AuthorizationResource`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit


class ResourceSource(str, Enum):
    """Where a resource identifier came from. Every value here describes
    a controlled origin; none of them describe guessing or enumeration."""

    EXPLICIT_TEST_RESOURCE = "explicit_test_resource"
    EXPLICIT_FIXTURE = "explicit_fixture"
    CREATED_BY_IDENTITY = "created_by_identity"
    OBSERVED_RESPONSE = "observed_response"
    CONTROLLED_LAB_API = "controlled_lab_api"


class ResourceOwnership(str, Enum):
    """The operator's declared expectation for who should be able to
    access a resource. Drives false-positive suppression: a resource
    that is SHARED or PUBLIC is never reported as an authorization
    failure merely because more than one identity can read it."""

    PRIVATE_TO_OWNER = "private_to_owner"
    SHARED = "shared"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class IdentifierLocation(str, Enum):
    PATH = "path"
    QUERY = "query"
    NONE = "none"


class AuthorizationResourceError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class AuthorizationResource:
    """One authorization-sensitive object, addressed by a controlled
    identifier. ``resource_id`` (the identity used for deduplication and
    evidence references) is derived only from structural fields --
    endpoint, method, identifier location/name/value -- never from
    response content, so a resource's real data is never part of its own
    fingerprint.

    ``owner_marker`` is optional (default ``""``, meaning "none
    configured") and exists purely as an *additional*, explicitly
    opt-in corroborating signal: if the operator or a controlled test
    fixture happens to embed a deterministic, identity-specific string
    in a resource's response (e.g. ``"resource_owner: user-b"``), the
    differential detector can use its presence as PROBABLE-tier
    evidence when an exact content fingerprint match isn't available.
    Detection with no marker configured still works (CONFIRMED-only,
    via fingerprint correlation) -- this field narrows what evidence is
    possible, it never becomes a requirement.
    """

    resource_type: str
    endpoint: str
    method: str
    identifier_location: IdentifierLocation
    identifier_name: str
    identifier_value: str
    owning_test_identity: str
    source: ResourceSource
    content_type: str = ""
    expected_access: ResourceOwnership = ResourceOwnership.PRIVATE_TO_OWNER
    owner_marker: str = ""
    resource_id: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, str) or not self.endpoint.strip():
            raise AuthorizationResourceError(
                "authorization_resource_endpoint_invalid",
                "An authorization resource requires a non-empty endpoint.",
            )
        if not isinstance(self.owning_test_identity, str) or not self.owning_test_identity:
            raise AuthorizationResourceError(
                "authorization_resource_owner_invalid",
                "An authorization resource requires a non-empty owning test identity label.",
            )
        object.__setattr__(self, "method", self.method.upper())
        parsed = urlsplit(self.endpoint)
        canonical_endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        identity_key = "|".join(
            (
                canonical_endpoint,
                self.method,
                self.identifier_location.value,
                self.identifier_name,
                self.identifier_value,
            )
        )
        object.__setattr__(
            self, "resource_id", hashlib.sha256(identity_key.encode()).hexdigest()
        )


__all__ = [
    "AuthorizationResource",
    "AuthorizationResourceError",
    "IdentifierLocation",
    "ResourceOwnership",
    "ResourceSource",
]
