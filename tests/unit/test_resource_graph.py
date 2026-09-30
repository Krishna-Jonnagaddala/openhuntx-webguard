"""Tests for the authorization resource graph and cross-identity
comparison eligibility rules (Slice 9, requirement 9): same resource
type, compatible endpoint/method, same identifier location, private-
to-owner expectation, distinct controlled identities, read-only
operation, and approved identifier provenance. Shared/public/unknown
resources, and resources with no structurally matching counterpart,
must never be paired.
"""

from __future__ import annotations

import unittest

from webguard_scanner import (
    AuthorizationResource,
    AuthorizationResourceGraph,
    IdentifierLocation,
    IdentifierProvenance,
    ResourceOwnership,
    ResourceSource,
    build_comparison_pairs,
    is_eligible_for_comparison,
)


def resource(
    *,
    identity: str,
    identifier_value: str,
    resource_type: str = "orders",
    method: str = "GET",
    identifier_location: IdentifierLocation = IdentifierLocation.PATH,
    identifier_name: str = "id",
    expected_access: ResourceOwnership = ResourceOwnership.PRIVATE_TO_OWNER,
    provenance: IdentifierProvenance = IdentifierProvenance.HTML_LINK,
    endpoint: str | None = None,
) -> AuthorizationResource:
    return AuthorizationResource(
        resource_type=resource_type,
        endpoint=endpoint or f"https://example.com/{resource_type}/{identifier_value}",
        method=method,
        identifier_location=identifier_location,
        identifier_name=identifier_name,
        identifier_value=identifier_value,
        owning_test_identity=identity,
        source=ResourceSource.OBSERVED_RESPONSE,
        expected_access=expected_access,
        provenance=provenance,
    )


class EligibilityTests(unittest.TestCase):
    def test_matching_private_resources_across_identities_are_eligible(self) -> None:
        a = resource(identity="user-a", identifier_value="A-001")
        b = resource(identity="user-b", identifier_value="B-001")
        self.assertTrue(is_eligible_for_comparison(a, b))

    def test_same_identity_is_never_eligible(self) -> None:
        a1 = resource(identity="user-a", identifier_value="A-001")
        a2 = resource(identity="user-a", identifier_value="A-002")
        self.assertFalse(is_eligible_for_comparison(a1, a2))

    def test_different_resource_type_is_not_eligible(self) -> None:
        a = resource(identity="user-a", identifier_value="A-001", resource_type="orders")
        b = resource(identity="user-b", identifier_value="B-001", resource_type="documents")
        self.assertFalse(is_eligible_for_comparison(a, b))

    def test_shared_resource_is_never_eligible(self) -> None:
        a = resource(identity="user-a", identifier_value="A-001")
        b = resource(
            identity="user-b",
            identifier_value="B-001",
            expected_access=ResourceOwnership.SHARED,
        )
        self.assertFalse(is_eligible_for_comparison(a, b))

    def test_public_resource_is_never_eligible(self) -> None:
        a = resource(identity="user-a", identifier_value="A-001")
        b = resource(
            identity="user-b",
            identifier_value="B-001",
            expected_access=ResourceOwnership.PUBLIC,
        )
        self.assertFalse(is_eligible_for_comparison(a, b))

    def test_unknown_expected_access_is_never_eligible(self) -> None:
        a = resource(identity="user-a", identifier_value="A-001")
        b = resource(
            identity="user-b",
            identifier_value="B-001",
            expected_access=ResourceOwnership.UNKNOWN,
        )
        self.assertFalse(is_eligible_for_comparison(a, b))

    def test_non_read_only_method_is_never_eligible(self) -> None:
        a = resource(identity="user-a", identifier_value="A-001", method="POST")
        b = resource(identity="user-b", identifier_value="B-001", method="POST")
        self.assertFalse(is_eligible_for_comparison(a, b))

    def test_mismatched_identifier_location_is_never_eligible(self) -> None:
        a = resource(identity="user-a", identifier_value="A-001")
        b = resource(
            identity="user-b",
            identifier_value="B-001",
            identifier_location=IdentifierLocation.QUERY,
        )
        self.assertFalse(is_eligible_for_comparison(a, b))

    def test_none_location_is_never_eligible(self) -> None:
        # NONE-located resources (e.g. a JSON field with no structural
        # endpoint template) are recorded in the graph but can never be
        # automatically compared -- there is no fetchable sibling
        # endpoint to build a cross-access request against.
        a = resource(
            identity="user-a",
            identifier_value="A-001",
            identifier_location=IdentifierLocation.NONE,
        )
        b = resource(
            identity="user-b",
            identifier_value="B-001",
            identifier_location=IdentifierLocation.NONE,
        )
        self.assertFalse(is_eligible_for_comparison(a, b))

    def test_mismatched_endpoint_template_is_never_eligible(self) -> None:
        a = resource(
            identity="user-a",
            identifier_value="A-001",
            endpoint="https://example.com/orders/A-001",
        )
        b = resource(
            identity="user-b",
            identifier_value="B-001",
            endpoint="https://example.com/v2/orders/B-001",
        )
        self.assertFalse(is_eligible_for_comparison(a, b))

    def test_identical_identifier_value_is_never_eligible(self) -> None:
        # Guards against ever comparing a resource against a
        # structurally-identical copy of itself under a different
        # identity label by coincidence.
        a = resource(identity="user-a", identifier_value="SAME-ID")
        b = resource(identity="user-b", identifier_value="SAME-ID")
        self.assertFalse(is_eligible_for_comparison(a, b))

    def test_numeric_identifier_coinciding_with_a_digit_in_the_host_is_still_eligible(
        self,
    ) -> None:
        # Regression: a naive substring replacement in the endpoint-
        # template computation once matched identifier "12" against the
        # "12" inside the host "127.0.0.1" instead of the trailing path
        # segment, silently breaking eligibility. The identifier must
        # only ever be matched as a whole path segment.
        a = resource(
            identity="user-a",
            identifier_value="11",
            endpoint="http://127.0.0.1:3000/rest/basket/11",
        )
        b = resource(
            identity="user-b",
            identifier_value="12",
            endpoint="http://127.0.0.1:3000/rest/basket/12",
        )
        self.assertTrue(is_eligible_for_comparison(a, b))


class ResourceGraphTests(unittest.TestCase):
    def test_add_resources_only_accepts_matching_identity_label(self) -> None:
        graph = AuthorizationResourceGraph()
        a = resource(identity="user-a", identifier_value="A-001")
        graph.add_resources("user-b", (a,))
        self.assertEqual(graph.resources_for("user-b"), ())

    def test_deduplicates_by_resource_id(self) -> None:
        graph = AuthorizationResourceGraph()
        a = resource(identity="user-a", identifier_value="A-001")
        a_again = resource(identity="user-a", identifier_value="A-001")
        graph.add_resources("user-a", (a, a_again))
        self.assertEqual(len(graph.resources_for("user-a")), 1)

    def test_build_comparison_pairs_excludes_shared_resource(self) -> None:
        graph = AuthorizationResourceGraph()
        a = resource(identity="user-a", identifier_value="A-001")
        b_private = resource(identity="user-b", identifier_value="B-001")
        b_shared = resource(
            identity="user-b",
            identifier_value="TEAM-DOC",
            resource_type="documents",
            expected_access=ResourceOwnership.SHARED,
        )
        graph.add_resources("user-a", (a,))
        graph.add_resources("user-b", (b_private, b_shared))

        pairs = build_comparison_pairs(
            graph, primary_identity="user-a", secondary_identity="user-b"
        )
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0].secondary_resource.identifier_value, "B-001")

    def test_build_comparison_pairs_is_bounded(self) -> None:
        graph = AuthorizationResourceGraph()
        a_resources = tuple(
            resource(identity="user-a", identifier_value=f"A-{i:03d}")
            for i in range(10)
        )
        b_resources = tuple(
            resource(identity="user-b", identifier_value=f"B-{i:03d}")
            for i in range(10)
        )
        graph.add_resources("user-a", a_resources)
        graph.add_resources("user-b", b_resources)

        pairs = build_comparison_pairs(
            graph, primary_identity="user-a", secondary_identity="user-b", maximum_pairs=3
        )
        self.assertEqual(len(pairs), 3)

    def test_no_matching_counterpart_yields_no_pairs(self) -> None:
        graph = AuthorizationResourceGraph()
        a = resource(identity="user-a", identifier_value="A-001", resource_type="orders")
        b = resource(
            identity="user-b", identifier_value="B-001", resource_type="documents"
        )
        graph.add_resources("user-a", (a,))
        graph.add_resources("user-b", (b,))
        pairs = build_comparison_pairs(
            graph, primary_identity="user-a", secondary_identity="user-b"
        )
        self.assertEqual(pairs, ())


if __name__ == "__main__":
    unittest.main()
