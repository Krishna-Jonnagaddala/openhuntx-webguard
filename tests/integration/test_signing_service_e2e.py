"""Slice 18 requirement 4: the TrustScan Signing Service E2E proof --

    authorized target -> permit request -> production signing
    service/provider -> signed TrustScan permit -> worker verifies ->
    scan executes

through the real production component assembly
(`build_production_components`), real PostgreSQL, and a real, separate
`SigningServiceServer` process-in-thread reached over real HTTP by the
main stack's `SigningServiceClient` -- only the actual CloudHSM/PKCS#11
boundary is substituted (this harness backs the signing service with
`LocalDevelopmentSigner`, an honest dev-mode stand-in, never claimed as
real CloudHSM validation; see `signing_service.py`'s own module
docstring and docs/audit/production-platform-phase4-edge-signing.md
for the explicit, honest scope of what is and is not proven here).
"""

from __future__ import annotations

import http.client
import json
import os
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit
from uuid import uuid4

from webguard_contracts import (
    OwnedTargetAuthorization,
    OwnedTargetLimits,
    write_owned_target_authorization_file,
)
from webguard_scanner import ValidatedTarget

from tests.integration.webguard_production_harness import run_production_stack

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_SIGNING_SERVICE_E2E = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)


@unittest.skipUnless(
    RUN_SIGNING_SERVICE_E2E,
    "requires WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN",
)
class SigningServiceEndToEndTests(unittest.TestCase):
    def test_permit_signed_by_the_signing_service_verifies_and_the_scan_executes(self) -> None:
        from unittest.mock import patch

        with TemporaryDirectory() as directory:
            fixture_root = Path(directory)

            def fake_validate_target_url(*args, **kwargs):
                url = str(args[0]) if args else str(kwargs["url"])
                parsed = urlsplit(url)
                return ValidatedTarget(
                    original_url=url,
                    normalised_url=url,
                    scheme=parsed.scheme or "https",
                    hostname=parsed.hostname or "signing-e2e.invalid",
                    port=parsed.port or 443,
                    resolved_addresses=("127.0.0.1",),
                )

            with patch(
                "webguard_api.executor.validate_target_url", side_effect=fake_validate_target_url
            ), patch(
                "webguard_scanner.owned_target._public_addresses",
                side_effect=lambda target: target.resolved_addresses,
            ), run_production_stack(
                POSTGRES_TEST_DSN, signing_mode="cloudhsm_signing_service"
            ) as stack:
                target_url = "https://signing-e2e.invalid/"
                now = datetime.now(timezone.utc)
                authorization_id = str(uuid4())
                write_owned_target_authorization_file(
                    OwnedTargetAuthorization(
                        authorization_id=authorization_id,
                        organization="Signing Service E2E Org",
                        authorized_by="E2E Harness",
                        target=target_url,
                        allowed_hosts=("signing-e2e.invalid",),
                        issued_at=now,
                        expires_at=now.replace(year=now.year + 1),
                        purpose="Slice 18 signing-service E2E",
                        limits=OwnedTargetLimits(),
                    ),
                    stack.authorization_directory / "signing-e2e.json",
                )
                stack.components.identity.assign_authorization(
                    stack.organization_id, authorization_id, assigned_by=stack.owner_principal_id, now=now,
                )

                # -- permit request: the real production HTTP API,
                # signed by the real SigningServiceClient over real
                # HTTP to the real (dev-key-backed) SigningServiceServer. --
                permit_body = json.dumps(
                    {
                        "target": target_url,
                        "authorization_id": authorization_id,
                        "confirm_authorization": authorization_id,
                        "permitted_modes": ["single_page"],
                        "allowed_http_methods": ["GET", "HEAD"],
                        "not_before": (datetime.now(timezone.utc) + timedelta(milliseconds=500))
                        .isoformat(timespec="microseconds")
                        .replace("+00:00", "Z"),
                        "expires_at": (now + timedelta(days=7)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "maximum_request_attempts": 10,
                        "maximum_requests_per_second": 1.0,
                        "maximum_concurrency": 1,
                        "active_checks": [],
                        "authentication_context_id": None,
                        "authorization_comparison_plan_id": None,
                    }
                ).encode()
                connection = http.client.HTTPConnection(stack.host, stack.port, timeout=5)
                connection.request(
                    "POST",
                    "/v1/permits",
                    body=permit_body,
                    headers={
                        "Authorization": f"Bearer {stack.owner_token}",
                        "Content-Type": "application/json",
                        "Content-Length": str(len(permit_body)),
                    },
                )
                response = connection.getresponse()
                permit_payload = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 201, permit_payload)
                permit_id = permit_payload["permit"]["claims"]["permit_id"]
                # The permit's own signing_key_id must be the signing
                # service's key, proving it was genuinely signed there
                # -- not silently issued some other way.
                self.assertEqual(
                    permit_payload["permit"]["signature"]["key_id"],
                    stack.components.trustscan_signer.key_id,
                )
                time.sleep(0.6)

                # -- job submission: the worker verifies the permit
                # against its own SigningKeyRegistry (also backed by
                # the SigningServiceClient) before ever executing --
                job_body = json.dumps(
                    {
                        "target": target_url,
                        "authorization_id": authorization_id,
                        "confirm_authorization": authorization_id,
                        "mode": "single_page",
                    }
                ).encode()
                connection = http.client.HTTPConnection(stack.host, stack.port, timeout=5)
                connection.request(
                    "POST",
                    "/v1/jobs",
                    body=job_body,
                    headers={
                        "Authorization": f"Bearer {stack.owner_token}",
                        "TrustScan-Permit": permit_id,
                        "Content-Type": "application/json",
                        "Content-Length": str(len(job_body)),
                        "Idempotency-Key": "signing-service-e2e-job-1",
                    },
                )
                response = connection.getresponse()
                created = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 201, created)
                job_id = created["job_id"]

                deadline = time.monotonic() + 15
                result_payload = None
                while time.monotonic() < deadline:
                    connection = http.client.HTTPConnection(stack.host, stack.port, timeout=5)
                    connection.request(
                        "GET", f"/v1/jobs/{job_id}/result", headers={"Authorization": f"Bearer {stack.owner_token}"}
                    )
                    response = connection.getresponse()
                    payload = json.loads(response.read())
                    connection.close()
                    if response.status == 200:
                        result_payload = payload
                        break
                    time.sleep(0.1)

                self.assertIsNotNone(result_payload, "the worker never completed the signing-service-signed job")
                # The fixture target (127.0.0.1, nothing actually
                # listening) means the scan's own network fetch fails
                # -- expected and irrelevant to what this test proves.
                # What matters is that the permit was accepted (no
                # permit/signature/authorization rejection -- `error`
                # is None, not a signing-chain error code) and that a
                # TrustScan safety receipt was generated and signed --
                # proof the worker's own SigningKeyRegistry (also
                # backed by a SigningServiceClient) verified the
                # permit and the runtime-safety engine actually ran.
                self.assertIsNone(result_payload["error"], result_payload)
                self.assertIsNotNone(result_payload["trustscan_safety_receipt"], result_payload)


if __name__ == "__main__":
    unittest.main()
