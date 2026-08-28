"""Authorised OWASP Juice Shop authenticated resource discovery
investigation (Slice 9, requirement 16).

Uses two lab accounts created only through Juice Shop's own documented
``POST /api/Users`` registration and ``POST /rest/user/login`` login
endpoints -- never enumeration, never brute-force, never privilege
escalation, never data alteration. Recreated fresh each run rather than
relying on hardcoded historical account state, since the lab container
is ephemeral.

Investigates two independent discovery paths:

1. A genuine authenticated crawl of Juice Shop's own root page, using
   this slice's real `run_authenticated_resource_discovery_crawl`
   (unmodified). Expected, and confirmed below, to find nothing --
   Juice Shop v20.1.1 is an Angular single-page application with no
   server-rendered HTML links or JSON API surface at its root; this is
   the same structural limitation already documented for the
   reflected-XSS and SQL-injection detectors in Slices 1, 4, and 6.

2. Resource discovery (`ResourceDiscoverySink`, the same class the
   crawl above uses internally) run directly against each account's own
   ``POST /rest/user/login`` response body -- a JSON response each
   account legitimately receives while authenticating. Juice Shop's own
   login response body contains a plaintext ``bid`` (basket ID) field
   alongside the JWT (confirmed by direct inspection). With an
   operator-supplied ``endpoint_templates={"bid": "rest/basket/{value}"}``
   (requirement 7's "explicit configuration" signal -- the *value*
   still comes only from the field WebGuard actually observed, never
   guessed), this is a legitimate, non-enumerating discovery of each
   account's own basket resource. The discovered resources are then fed
   into the unmodified Slice 8 `run_idor_authorization_detector`,
   exactly as any other discovered resource pair would be.
"""

from __future__ import annotations

import json
import os
import unittest
import urllib.request
from urllib.error import HTTPError

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionPolicy,
    AuthenticatedCrawlStatus,
    AuthenticationMaterial,
    AuthorizationResourceGraph,
    CrawlPolicy,
    IdorDetectionOutcome,
    ValidatedTarget,
    build_comparison_pairs,
    run_authenticated_resource_discovery_crawl,
    run_idor_authorization_detector,
)
from webguard_scanner.authorization_resource_discovery import ResourceDiscoverySink
from webguard_scanner.safe_http import SafeHttpResponse

RUN_INTEGRATION = os.getenv("WEBGUARD_RUN_INTEGRATION") == "1"
LAB_TARGET = os.getenv("WEBGUARD_LAB_TARGET", "http://127.0.0.1:3000/")


def _post_json(url: str, payload: dict) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _register_and_login(base_url: str, email: str, password: str) -> tuple[str, bytes]:
    status, _ = _post_json(
        f"{base_url}api/Users",
        {
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {
                "id": 1,
                "question": "lab account, no real security question",
                "createdAt": "",
                "updatedAt": "",
            },
            "securityAnswer": "n/a",
        },
    )
    if status not in (201, 400):
        raise AssertionError(f"Unexpected registration status {status} for {email}")

    request = urllib.request.Request(
        f"{base_url}rest/user/login",
        data=json.dumps({"email": email, "password": password}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        raw_body = response.read()
    payload = json.loads(raw_body)
    token = payload["authentication"]["token"]
    return token, raw_body


@unittest.skipUnless(
    RUN_INTEGRATION, "Set WEBGUARD_RUN_INTEGRATION=1 to run this end-to-end lab test."
)
class AuthenticatedDiscoveryJuiceShopLabTests(unittest.TestCase):
    def _target(self) -> ValidatedTarget:
        from urllib.parse import urlsplit

        parsed = urlsplit(LAB_TARGET)
        return ValidatedTarget(
            original_url=LAB_TARGET,
            normalised_url=LAB_TARGET,
            scheme=parsed.scheme,
            hostname=parsed.hostname,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            resolved_addresses=("127.0.0.1",),
        )

    def test_authenticated_crawl_of_juice_shop_root_finds_no_resources(self) -> None:
        # Requirement 16's first, honestly-reported half: a genuine,
        # unmodified authenticated crawl against the real application,
        # not a synthetic fixture.
        token, _ = _register_and_login(
            LAB_TARGET,
            "webguard-discovery-lab-a@example.test",
            "WebGuardDiscoveryLabPassword!A1",
        )
        result = run_authenticated_resource_discovery_crawl(
            self._target(),
            authentication_material=AuthenticationMaterial(bearer_token=token),
            owning_identity="lab-user-a",
            crawl_policy=CrawlPolicy(maximum_pages=5, maximum_depth=1, minimum_delay_seconds=0),
        )
        self.assertEqual(result.status, AuthenticatedCrawlStatus.SUCCEEDED)
        self.assertEqual(
            result.resources,
            (),
            "Juice Shop v20.1.1 is an Angular SPA with no server-rendered "
            "HTML links or JSON API surface at its root -- consistent with "
            "the same structural limitation documented for reflected-XSS "
            "and SQL-injection discovery in prior slices.",
        )

    def test_confirms_basket_access_control_bypass_via_login_response_discovery(
        self,
    ) -> None:
        token_a, login_body_a = _register_and_login(
            LAB_TARGET,
            "webguard-discovery-lab-basket-a@example.test",
            "WebGuardDiscoveryLabPassword!A1",
        )
        token_b, login_body_b = _register_and_login(
            LAB_TARGET,
            "webguard-discovery-lab-basket-b@example.test",
            "WebGuardDiscoveryLabPassword!B1",
        )

        target = self._target()
        login_page_target = ValidatedTarget(
            original_url=f"{LAB_TARGET}rest/user/login",
            normalised_url=f"{LAB_TARGET}rest/user/login",
            scheme=target.scheme,
            hostname=target.hostname,
            port=target.port,
            resolved_addresses=target.resolved_addresses,
        )

        def login_response(body: bytes) -> SafeHttpResponse:
            return SafeHttpResponse(
                status=200,
                reason="OK",
                headers=(("Content-Type", "application/json"),),
                body=body,
                connected_address="127.0.0.1",
                elapsed_milliseconds=1,
            )

        graph = AuthorizationResourceGraph()
        for identity, login_body in (("lab-user-a", login_body_a), ("lab-user-b", login_body_b)):
            sink = ResourceDiscoverySink(
                owning_identity=identity,
                field_patterns=frozenset({"bid"}),
                endpoint_templates={"bid": "rest/basket/{value}"},
            )
            sink.visit_page(login_page_target, login_response(login_body))
            self.assertTrue(
                sink.resources,
                f"expected a discovered basket resource for {identity} from "
                "its own login response body",
            )
            graph.add_resources(identity, sink.resources)

        pairs = build_comparison_pairs(
            graph, primary_identity="lab-user-a", secondary_identity="lab-user-b"
        )
        self.assertTrue(pairs, "expected exactly one eligible basket resource pair")

        result = run_idor_authorization_detector(
            target,
            pairs,
            ActiveDetectionContext(scan_id="idor-discovery-juice-shop-lab-scan"),
            primary_identity_label="lab-user-a",
            primary_material=AuthenticationMaterial(bearer_token=token_a),
            secondary_identity_label="lab-user-b",
            secondary_material=AuthenticationMaterial(bearer_token=token_b),
            policy=ActiveDetectionPolicy(maximum_probe_requests=25),
        )

        outcomes = {record.outcome for record in result.records}
        self.assertIn(
            IdorDetectionOutcome.CONFIRMED,
            outcomes,
            f"expected a CONFIRMED discovered-basket finding; records: {result.records}",
        )
        self.assertTrue(result.findings)
        cwe_values = [
            i.value for i in result.findings[0].identifiers if i.namespace == "CWE"
        ]
        self.assertEqual(cwe_values, ["CWE-639"])


if __name__ == "__main__":
    unittest.main()
