"""Authorised OWASP Juice Shop authorization-differential (IDOR/BOLA)
integration test (Slice 8).

Uses exactly two explicitly-created lab accounts, created only through
Juice Shop's own documented ``POST /api/Users`` registration endpoint
and ``POST /rest/user/login`` login endpoint -- never enumeration,
never brute-force, never privilege escalation, never data alteration.

Resource identifiers come from a controlled lab API response: each
account's own shopping-basket ID (the JWT's ``bid`` claim), obtained
only from that account's own authenticated login response -- never
guessed, generated, or enumerated. This is Juice Shop's well-known,
publicly documented "view another user's shopping basket" broken
access control challenge, and it is reachable with plain read-only GET
requests, which is why (unlike the reflected-XSS and SQL-injection
detectors in earlier slices) this detector *can* be validated against
the live lab, not just the controlled synthetic fixture.
"""

from __future__ import annotations

import base64
import json
import os
import unittest
import urllib.request
from urllib.error import HTTPError

from webguard_scanner import (
    ActiveDetectionContext,
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


def _decode_jwt_payload(token: str) -> dict:
    segment = token.split(".")[1]
    segment += "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment))


def _register_and_login(base_url: str, email: str, password: str) -> tuple[str, int]:
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
    status, payload = _post_json(
        f"{base_url}rest/user/login", {"email": email, "password": password}
    )
    if status != 200:
        raise AssertionError(f"Login failed for {email}: {status} {payload}")
    token = payload["authentication"]["token"]
    basket_id = _decode_jwt_payload(token)["bid"]
    return token, basket_id


@unittest.skipUnless(
    RUN_INTEGRATION, "Set WEBGUARD_RUN_INTEGRATION=1 to run network integration tests."
)
class IdorJuiceShopLabIntegrationTests(unittest.TestCase):
    def test_confirms_basket_access_control_bypass_on_live_juice_shop(self) -> None:
        token_a, bid_a = _register_and_login(
            LAB_TARGET, "webguard-idor-lab-a@example.test", "WebGuardLabPassword!A1"
        )
        token_b, bid_b = _register_and_login(
            LAB_TARGET, "webguard-idor-lab-b@example.test", "WebGuardLabPassword!B1"
        )
        self.assertNotEqual(
            bid_a, bid_b, "the two lab accounts must have distinct basket IDs"
        )

        target = ValidatedTarget(
            original_url=LAB_TARGET,
            normalised_url=LAB_TARGET,
            scheme="http",
            hostname="127.0.0.1",
            port=3000,
            resolved_addresses=("127.0.0.1",),
        )

        def basket_resource(basket_id: int, owner: str) -> AuthorizationResource:
            return AuthorizationResource(
                resource_type="shopping_basket",
                endpoint=f"{LAB_TARGET}rest/basket/{basket_id}",
                method="GET",
                identifier_location=IdentifierLocation.PATH,
                identifier_name="id",
                identifier_value=str(basket_id),
                owning_test_identity=owner,
                source=ResourceSource.CONTROLLED_LAB_API,
                expected_access=ResourceOwnership.PRIVATE_TO_OWNER,
            )

        resource_pairs = (
            AuthorizationResourcePair(
                primary_resource=basket_resource(bid_a, "lab-user-a"),
                secondary_resource=basket_resource(bid_b, "lab-user-b"),
            ),
        )

        result = run_idor_authorization_detector(
            target,
            resource_pairs,
            ActiveDetectionContext(scan_id="idor-juice-shop-lab-scan"),
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
            f"expected a CONFIRMED basket cross-access finding; records: {result.records}",
        )
        self.assertTrue(result.findings)
        finding = result.findings[0]
        cwe_values = [i.value for i in finding.identifiers if i.namespace == "CWE"]
        self.assertEqual(cwe_values, ["CWE-639"])
        evidence_text = " ".join(e.summary for e in finding.evidence)
        self.assertNotIn(token_a, evidence_text)
        self.assertNotIn(token_b, evidence_text)


if __name__ == "__main__":
    unittest.main()
