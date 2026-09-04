"""P1-B1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
call-site proofs that the TrustScan Signing Service emits the required
structured events, with key_id permitted but never message/signature/
secret material -- and no synthetic sign operation performed merely to
produce the started/stopped events.
"""

from __future__ import annotations

import base64
import io
import json
import unittest

from webguard_api.signing import LocalDevelopmentSigner, SigningKeyRegistry
from webguard_api.signing_service import SigningServiceServer
from webguard_api.structured_logging import configure_structured_logging

import http.client


def _lines(buf: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line]


def _events(buf: io.StringIO, name: str) -> list[dict]:
    return [line for line in _lines(buf) if line.get("event") == name]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class SigningServiceStructuredEventTests(unittest.TestCase):
    BEARER = "unit-test-bearer-token"  # noqa: S105

    def setUp(self) -> None:
        self.buf = io.StringIO()
        configure_structured_logging(service="signing-service", stream=self.buf)
        self.registry = SigningKeyRegistry(LocalDevelopmentSigner(bytes(range(32))))
        self.server = SigningServiceServer(self.registry, bearer_token=self.BEARER)

    def _post_sign(self, message: bytes = b"hello"):
        host, port = self.server._server.server_address[:2]
        conn = http.client.HTTPConnection(host, port, timeout=5)
        body = json.dumps({"message": _b64url(message)}).encode()
        try:
            conn.request(
                "POST", "/v1/sign", body=body,
                headers={"Authorization": f"Bearer {self.BEARER}", "Content-Length": str(len(body))},
            )
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_started_and_stopped(self) -> None:
        self.server.start()
        self.server.stop()
        self.assertEqual(len(_events(self.buf, "signing_service_started")), 1)
        self.assertEqual(len(_events(self.buf, "signing_service_stopped")), 1)

    def test_sign_request_completed_has_key_id_never_message_or_signature(self) -> None:
        self.server.start()
        try:
            status, body = self._post_sign(b"a secret-shaped message payload")
        finally:
            self.server.stop()
        self.assertEqual(status, 200)

        completed = _events(self.buf, "sign_request_completed")
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["key_id"], self.registry.active.key_id)
        dumped = json.dumps(completed[0])
        self.assertNotIn("a secret-shaped message payload", dumped)
        # The response body (which DOES contain the signature -- that
        # is the API's job) must never leak into the log line.
        response_payload = json.loads(body)
        self.assertNotIn(response_payload["signature"], dumped)

    def test_active_key_unavailable_when_disabled(self) -> None:
        self.registry.set_status(self.registry.active.key_id, "disabled")
        self.server.start()
        try:
            status, _ = self._post_sign()
        finally:
            self.server.stop()
        self.assertEqual(status, 500)

        unavailable = _events(self.buf, "active_key_unavailable")
        self.assertEqual(len(unavailable), 1)
        self.assertEqual(unavailable[0]["error_code"], "trustscan_signing_key_disabled")
        self.assertEqual(_events(self.buf, "sign_request_completed"), [])
        self.assertEqual(_events(self.buf, "sign_request_failed"), [], "must be the specific event, not the generic one")


if __name__ == "__main__":
    unittest.main()
