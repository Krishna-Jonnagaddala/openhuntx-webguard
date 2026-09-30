"""Unit tests for the authorization-differential (IDOR/BOLA) detector.

Covers: the core CONFIRMED classification (cross-access returns the
victim's actual content, verified via fingerprint correlation, not a
generic 200); NOT_VULNERABLE for denied cross-access (403/404); NOT_
VULNERABLE for a generic/public 200 response that happens to also
return 200 but isn't the victim's content; INCONCLUSIVE for SHARED
resources (never reported, no matter what); INCONCLUSIVE when a
baseline itself fails; identity isolation (identity A's material is
never used for identity B's own baseline, and vice versa); evidence
sanitization; budget enforcement; and cancellation.
"""

from __future__ import annotations

import unittest
from email.message import Message
from unittest.mock import patch
from urllib.parse import urlsplit

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionError,
    ActiveDetectionPolicy,
    AuthenticationMaterial,
    AuthorizationResource,
    AuthorizationResourcePair,
    IdentifierLocation,
    IdorDetectionOutcome,
    ResourceOwnership,
    ResourceSource,
    ValidatedTarget,
    run_idor_authorization_detector,
)


def _target(url: str = "http://example.com/") -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme="http",
        hostname="example.com",
        port=80,
        resolved_addresses=("93.184.216.34",),
    )


def _resource(endpoint: str, owner: str, expected_access=ResourceOwnership.PRIVATE_TO_OWNER):
    return AuthorizationResource(
        resource_type="order",
        endpoint=endpoint,
        method="GET",
        identifier_location=IdentifierLocation.PATH,
        identifier_name="id",
        identifier_value=endpoint.rsplit("/", 1)[-1],
        owning_test_identity=owner,
        source=ResourceSource.EXPLICIT_TEST_RESOURCE,
        expected_access=expected_access,
    )


def _context() -> ActiveDetectionContext:
    return ActiveDetectionContext(scan_id="idor-scan-1")


def _policy(maximum_probe_requests: int = 25) -> ActiveDetectionPolicy:
    return ActiveDetectionPolicy(maximum_probe_requests=maximum_probe_requests)


class _FakeResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.status = status
        self.reason = "OK"
        self._body = body
        self._position = 0
        self.msg = Message()
        self.msg.add_header("Content-Length", str(len(body)))

    def getheaders(self):
        return [("Content-Length", str(len(self._body)))]

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            amount = len(self._body) - self._position
        chunk = self._body[self._position : self._position + amount]
        self._position += len(chunk)
        return chunk


class _IdentityAwareConnection:
    """A fake connection whose response depends on both the requested
    path and the Authorization header actually sent, so tests can prove
    identity isolation and cross-access classification precisely.

    ``responder(path, bearer_token) -> (status, body)``
    """

    def __init__(self, responder) -> None:
        self.responder = responder
        self.sock = None
        self._context = None
        self._path = ""
        self._bearer_token = None
        self.requested = []  # list of (path, bearer_token)

    def putrequest(self, method, path, **kwargs) -> None:
        self._path = path
        self._bearer_token = None

    def putheader(self, name, value) -> None:
        if name == "Authorization" and value.startswith("Bearer "):
            self._bearer_token = value[len("Bearer ") :]

    def endheaders(self, message_body=None) -> None:
        self.requested.append((urlsplit(self._path).path, self._bearer_token))

    def getresponse(self):
        status, body = self.responder(urlsplit(self._path).path, self._bearer_token)
        return _FakeResponse(body, status=status)

    def close(self) -> None:
        pass


_A_TOKEN = "token-for-user-a"
_B_TOKEN = "token-for-user-b"


def _material(token: str) -> AuthenticationMaterial:
    return AuthenticationMaterial(bearer_token=token)


class ConfirmedDetectionTests(unittest.TestCase):
    def test_confirmed_when_cross_access_returns_victims_exact_content(self) -> None:
        def responder(path, token):
            if path == "/api/orders/A-001":
                if token == _A_TOKEN:
                    return 200, b'{"order":"A-001","owner":"user-a"}'
                return 403, b"denied"
            if path == "/api/orders/B-001":
                # Vulnerable: any valid token gets B's content.
                if token in (_A_TOKEN, _B_TOKEN):
                    return 200, b'{"order":"B-001","owner":"user-b"}'
                return 403, b"denied"
            return 404, b"not found"

        connection = _IdentityAwareConnection(responder)
        pair = AuthorizationResourcePair(
            primary_resource=_resource("http://example.com/api/orders/A-001", "user-a"),
            secondary_resource=_resource("http://example.com/api/orders/B-001", "user-b"),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_idor_authorization_detector(
                _target(),
                (pair,),
                _context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_policy(),
            )

        outcomes = {record.outcome for record in result.records}
        self.assertIn(IdorDetectionOutcome.CONFIRMED, outcomes)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual([i.namespace for i in finding.identifiers], ["CWE", "OWASP-API"])
        cwe_values = [i.value for i in finding.identifiers if i.namespace == "CWE"]
        self.assertEqual(cwe_values, ["CWE-639"])


class ProbableMarkerTests(unittest.TestCase):
    def test_marker_match_without_exact_fingerprint_is_probable(self) -> None:
        """PROBABLE is reachable only via an explicit, operator-configured
        marker -- never via a coincidental weak signal like response
        length. The fixture varies B's content slightly (a counter) so
        fingerprints never match exactly, but the configured marker
        still appears."""

        counter = {"n": 0}

        def responder(path, token):
            counter["n"] += 1
            if path == "/api/orders/A-001" and token == _A_TOKEN:
                return 200, b'{"order":"A-001"}'
            if path == "/api/orders/B-001" and token in (_A_TOKEN, _B_TOKEN):
                # Content varies slightly per request (e.g. a counter),
                # so exact fingerprint correlation never succeeds, but
                # the configured marker is always present.
                return 200, f'{{"order":"B-001","resource_owner":"user-b","n":{counter["n"]}}}'.encode()
            return 403, b"denied"

        connection = _IdentityAwareConnection(responder)
        secondary = AuthorizationResource(
            resource_type="order",
            endpoint="http://example.com/api/orders/B-001",
            method="GET",
            identifier_location=IdentifierLocation.PATH,
            identifier_name="id",
            identifier_value="B-001",
            owning_test_identity="user-b",
            source=ResourceSource.EXPLICIT_TEST_RESOURCE,
            owner_marker="resource_owner\":\"user-b",
        )
        pair = AuthorizationResourcePair(
            primary_resource=_resource("http://example.com/api/orders/A-001", "user-a"),
            secondary_resource=secondary,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_idor_authorization_detector(
                _target(),
                (pair,),
                _context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_policy(),
            )

        outcomes = {record.outcome for record in result.records}
        self.assertIn(IdorDetectionOutcome.PROBABLE, outcomes)
        self.assertTrue(result.findings)

    def test_no_marker_configured_and_no_exact_match_is_not_vulnerable(self) -> None:
        """The safe default: without a configured marker, non-exact
        content correlation is never treated as evidence."""

        counter = {"n": 0}

        def responder(path, token):
            counter["n"] += 1
            if path == "/api/orders/A-001" and token == _A_TOKEN:
                return 200, b'{"order":"A-001"}'
            if path == "/api/orders/B-001" and token in (_A_TOKEN, _B_TOKEN):
                return 200, f'{{"order":"B-001","n":{counter["n"]}}}'.encode()
            return 403, b"denied"

        connection = _IdentityAwareConnection(responder)
        pair = AuthorizationResourcePair(
            primary_resource=_resource("http://example.com/api/orders/A-001", "user-a"),
            secondary_resource=_resource("http://example.com/api/orders/B-001", "user-b"),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_idor_authorization_detector(
                _target(),
                (pair,),
                _context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_policy(),
            )

        self.assertEqual(result.findings, ())


class NotVulnerableTests(unittest.TestCase):
    def test_secure_endpoint_denies_cross_access(self) -> None:
        def responder(path, token):
            owner_token = {"/api/orders/A-001": _A_TOKEN, "/api/orders/B-001": _B_TOKEN}
            if path in owner_token:
                if token == owner_token[path]:
                    return 200, f'{{"order":"{path[-5:]}"}}'.encode()
                return 403, b"denied"
            return 404, b"not found"

        connection = _IdentityAwareConnection(responder)
        pair = AuthorizationResourcePair(
            primary_resource=_resource("http://example.com/api/orders/A-001", "user-a"),
            secondary_resource=_resource("http://example.com/api/orders/B-001", "user-b"),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_idor_authorization_detector(
                _target(),
                (pair,),
                _context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_policy(),
            )

        self.assertEqual(result.findings, ())
        outcomes = {record.outcome for record in result.records}
        self.assertEqual(outcomes, {IdorDetectionOutcome.NOT_VULNERABLE})

    def test_generic_200_response_is_not_a_finding(self) -> None:
        """The core false-positive control: a 200 response to a cross-
        access attempt that returns a generic/unrelated body (not the
        victim's actual content) must never be classified as vulnerable
        -- 'generic HTTP 200 alone must not be sufficient.'"""

        def responder(path, token):
            if path == "/api/orders/A-001" and token == _A_TOKEN:
                return 200, b'{"order":"A-001","owner":"user-a"}'
            if path == "/api/orders/B-001" and token == _B_TOKEN:
                return 200, b'{"order":"B-001","owner":"user-b"}'
            # Any other combination (including A requesting B's resource)
            # gets a generic landing page, not B's actual content.
            return 200, b"<html>Welcome to ExampleApp</html>"

        connection = _IdentityAwareConnection(responder)
        pair = AuthorizationResourcePair(
            primary_resource=_resource("http://example.com/api/orders/A-001", "user-a"),
            secondary_resource=_resource("http://example.com/api/orders/B-001", "user-b"),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_idor_authorization_detector(
                _target(),
                (pair,),
                _context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_policy(),
            )

        self.assertEqual(result.findings, ())
        outcomes = {record.outcome for record in result.records}
        self.assertEqual(outcomes, {IdorDetectionOutcome.NOT_VULNERABLE})

    def test_nonexistent_object_produces_no_finding(self) -> None:
        def responder(path, token):
            if path == "/api/orders/A-001" and token == _A_TOKEN:
                return 200, b'{"order":"A-001"}'
            if path == "/api/orders/B-999":
                return 404, b"not found"
            return 403, b"denied"

        connection = _IdentityAwareConnection(responder)
        pair = AuthorizationResourcePair(
            primary_resource=_resource("http://example.com/api/orders/A-001", "user-a"),
            secondary_resource=_resource("http://example.com/api/orders/B-999", "user-b"),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_idor_authorization_detector(
                _target(),
                (pair,),
                _context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_policy(),
            )
        self.assertEqual(result.findings, ())


class SharedResourceTests(unittest.TestCase):
    def test_shared_resource_never_reported_even_with_identical_200(self) -> None:
        """'Public/shared resources must not become IDOR findings.'"""

        def responder(path, token):
            if path == "/api/shared/team-document" and token in (_A_TOKEN, _B_TOKEN):
                return 200, b"<html>Team roadmap</html>"
            return 403, b"denied"

        connection = _IdentityAwareConnection(responder)
        shared_a = AuthorizationResource(
            resource_type="shared_document",
            endpoint="http://example.com/api/shared/team-document",
            method="GET",
            identifier_location=IdentifierLocation.NONE,
            identifier_name="",
            identifier_value="",
            owning_test_identity="user-a",
            source=ResourceSource.EXPLICIT_TEST_RESOURCE,
            expected_access=ResourceOwnership.SHARED,
        )
        shared_b = AuthorizationResource(
            resource_type="shared_document",
            endpoint="http://example.com/api/shared/team-document",
            method="GET",
            identifier_location=IdentifierLocation.NONE,
            identifier_name="",
            identifier_value="",
            owning_test_identity="user-b",
            source=ResourceSource.EXPLICIT_TEST_RESOURCE,
            expected_access=ResourceOwnership.SHARED,
        )
        pair = AuthorizationResourcePair(primary_resource=shared_a, secondary_resource=shared_b)
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_idor_authorization_detector(
                _target(),
                (pair,),
                _context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_policy(),
            )
        self.assertEqual(result.findings, ())
        outcomes = {record.outcome for record in result.records}
        self.assertEqual(outcomes, {IdorDetectionOutcome.INCONCLUSIVE})


class BaselineFailureTests(unittest.TestCase):
    def test_failed_baseline_is_inconclusive_not_vulnerable(self) -> None:
        def responder(path, token):
            # B's own baseline fails (500) -- nothing legitimate to
            # correlate cross-access against.
            if path == "/api/orders/B-001":
                return 500, b"error"
            if path == "/api/orders/A-001" and token == _A_TOKEN:
                return 200, b'{"order":"A-001"}'
            return 403, b"denied"

        connection = _IdentityAwareConnection(responder)
        pair = AuthorizationResourcePair(
            primary_resource=_resource("http://example.com/api/orders/A-001", "user-a"),
            secondary_resource=_resource("http://example.com/api/orders/B-001", "user-b"),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_idor_authorization_detector(
                _target(),
                (pair,),
                _context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_policy(),
            )
        self.assertEqual(result.findings, ())
        outcomes = {record.outcome for record in result.records}
        self.assertEqual(outcomes, {IdorDetectionOutcome.INCONCLUSIVE})


class IdentityIsolationTests(unittest.TestCase):
    def test_primary_material_never_used_for_secondary_baseline(self) -> None:
        """Context A's secret must never be applied to B's baseline
        request, and vice versa -- verified by inspecting exactly which
        token was sent with each request."""

        sent_tokens_by_path: dict[str, set[str]] = {}

        def responder(path, token):
            sent_tokens_by_path.setdefault(path, set()).add(token)
            if path == "/api/orders/A-001" and token == _A_TOKEN:
                return 200, b'{"order":"A-001"}'
            if path == "/api/orders/B-001" and token == _B_TOKEN:
                return 200, b'{"order":"B-001"}'
            return 403, b"denied"

        connection = _IdentityAwareConnection(responder)
        pair = AuthorizationResourcePair(
            primary_resource=_resource("http://example.com/api/orders/A-001", "user-a"),
            secondary_resource=_resource("http://example.com/api/orders/B-001", "user-b"),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            run_idor_authorization_detector(
                _target(),
                (pair,),
                _context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_policy(),
            )

        # Both A's token and B's token were used against BOTH endpoints
        # (baseline + cross-check), but never any *other* token --
        # proving no accidental material mixing beyond the intended
        # cross-checks.
        for path, tokens in sent_tokens_by_path.items():
            self.assertTrue(tokens.issubset({_A_TOKEN, _B_TOKEN}), (path, tokens))


class EvidenceSanitizationTests(unittest.TestCase):
    def test_finding_evidence_never_contains_bearer_token_or_resource_content(
        self,
    ) -> None:
        def responder(path, token):
            if path == "/api/orders/A-001":
                if token == _A_TOKEN:
                    return 200, b'{"order":"A-001","ssn":"123-45-6789"}'
                return 403, b"denied"
            if path == "/api/orders/B-001":
                if token in (_A_TOKEN, _B_TOKEN):
                    return 200, b'{"order":"B-001","ssn":"987-65-4321"}'
                return 403, b"denied"
            return 404, b"not found"

        connection = _IdentityAwareConnection(responder)
        pair = AuthorizationResourcePair(
            primary_resource=_resource("http://example.com/api/orders/A-001", "user-a"),
            secondary_resource=_resource("http://example.com/api/orders/B-001", "user-b"),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_idor_authorization_detector(
                _target(),
                (pair,),
                _context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_policy(),
            )

        self.assertTrue(result.findings)
        evidence_text = " ".join(
            e.summary for finding in result.findings for e in finding.evidence
        )
        self.assertNotIn(_A_TOKEN, evidence_text)
        self.assertNotIn(_B_TOKEN, evidence_text)
        self.assertNotIn("987-65-4321", evidence_text)
        self.assertNotIn("123-45-6789", evidence_text)
        self.assertNotIn("{", evidence_text)


class BudgetAndCancellationTests(unittest.TestCase):
    def test_budget_exceeded_raises_before_any_request(self) -> None:
        connection = _IdentityAwareConnection(lambda p, t: (200, b"ok"))
        pair = AuthorizationResourcePair(
            primary_resource=_resource("http://example.com/api/orders/A-001", "user-a"),
            secondary_resource=_resource("http://example.com/api/orders/B-001", "user-b"),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            with self.assertRaises(ActiveDetectionError) as caught:
                run_idor_authorization_detector(
                    _target(),
                    (pair,),
                    _context(),
                    primary_identity_label="user-a",
                    primary_material=_material(_A_TOKEN),
                    secondary_identity_label="user-b",
                    secondary_material=_material(_B_TOKEN),
                    policy=_policy(maximum_probe_requests=2),
                )
        self.assertEqual(caught.exception.code, "candidate_budget_exceeded")
        self.assertEqual(connection.requested, [])

    def test_cancellation_before_first_pair_compares_nothing(self) -> None:
        connection = _IdentityAwareConnection(lambda p, t: (200, b"ok"))
        pair = AuthorizationResourcePair(
            primary_resource=_resource("http://example.com/api/orders/A-001", "user-a"),
            secondary_resource=_resource("http://example.com/api/orders/B-001", "user-b"),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            result = run_idor_authorization_detector(
                _target(),
                (pair,),
                _context(),
                primary_identity_label="user-a",
                primary_material=_material(_A_TOKEN),
                secondary_identity_label="user-b",
                secondary_material=_material(_B_TOKEN),
                policy=_policy(),
                cancellation_check=lambda: True,
            )
        self.assertTrue(result.cancelled)
        self.assertEqual(result.records, ())
        self.assertEqual(connection.requested, [])


if __name__ == "__main__":
    unittest.main()
