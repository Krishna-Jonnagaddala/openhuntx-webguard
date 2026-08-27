"""Executor-level tests for HTTP-method authorization on POST candidates
(Slice 6, requirement 13). Being able to *represent* a POST/JSON request
is not the same as being *authorized* to send it: a discovered POST
candidate must remain non-executable under a GET-only TrustScan permit,
regardless of active_checks, and must only execute once the permit's own
allowed_http_methods claim explicitly includes POST.
"""

from __future__ import annotations

import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from webguard_api import AuthorizationRepository, ScanJobExecutor, ScanJobStore
from webguard_contracts import ScanJobMode, ScanJobRequest
from webguard_scanner import ValidatedTarget

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
    authorization,
    completed_report,
    create_trustscan_permit,
    trustscan_signer,
    write_authorization,
)


class _FakeTlsContext:
    verify_mode = __import__("ssl").CERT_REQUIRED
    check_hostname = True


class _FakeTlsSocket:
    def getpeercert(self, binary_form: bool = False):
        if binary_form:
            return b"certificate-der"
        return {
            "notBefore": "Mar 15 00:00:00 2026 GMT",
            "notAfter": "Oct  1 00:00:00 2026 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }

    def version(self) -> str:
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def get_verified_chain(self):
        return [object()] * 2


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


_POST_FORM_PAGE = (
    b"<html><body>"
    b'<form method="POST" action="/comment"><input name="id"></form>'
    b"</body></html>"
)


class _PostFormSqliConnection:
    """Serves the root page (a POST-form) and, for POST /comment,
    reflects a database-error signature only when the submitted "id"
    field contains an unescaped apostrophe -- a controlled, clearly
    labeled synthetic fixture, not a real vulnerable app."""

    def __init__(self) -> None:
        self.sock = _FakeTlsSocket()
        self._context = _FakeTlsContext()
        self.requested_paths: list[str] = []
        self.requested_methods: list[str] = []
        self._method = "GET"
        self._path = ""
        self._body = b""

    def putrequest(self, method, path, **kwargs) -> None:
        self._method = method
        self._path = path
        self.requested_methods.append(method)
        self.requested_paths.append(path)

    def putheader(self, name, value) -> None:
        return None

    def endheaders(self, message_body=None) -> None:
        self._body = message_body or b""

    def getresponse(self):
        parsed = urlsplit(self._path)
        if parsed.path == "/comment" and self._method == "POST":
            value = parse_qs(self._body.decode()).get("id", [""])[0]
            if "'" in value:
                return _FakeResponse(
                    b"<html>You have an error in your SQL syntax</html>",
                    status=500,
                )
            return _FakeResponse(b"<html>ok</html>", status=200)
        return _FakeResponse(_POST_FORM_PAGE)

    def close(self) -> None:
        pass


class HttpMethodAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.auth_dir = self.root / "authorizations"
        self.auth_path = write_authorization(self.auth_dir)
        self.artifacts = self.root / "artifacts"
        self.store = ScanJobStore(self.root / "jobs.sqlite3")
        self.signer = trustscan_signer(self.store)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def validated_target() -> ValidatedTarget:
        return ValidatedTarget(
            original_url=TARGET,
            normalised_url=TARGET,
            scheme="https",
            hostname="example.com",
            port=443,
            resolved_addresses=("93.184.216.34",),
        )

    def running_record(self, permit, *, mode: ScanJobMode = ScanJobMode.SINGLE_PAGE):
        auth = authorization()
        request = ScanJobRequest(
            idempotency_key=f"http-method-auth-{mode.value}",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=mode,
            submitted_at=NOW,
        )
        self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=permit.permit.claims.permit_id,
            permit_sha256=permit.permit.fingerprint,
        )
        claimed = self.store.claim_next(now=NOW)
        assert claimed is not None
        return claimed

    def make_executor(self) -> ScanJobExecutor:
        return ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            single_scanner=lambda target, **kwargs: completed_report(
                kwargs["scan_id"]
            ),
        )

    @patch("webguard_api.executor.validate_target_url")
    def test_post_candidate_blocked_under_get_only_permit(
        self, validate_mock
    ) -> None:
        validate_mock.return_value = self.validated_target()
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.sqli.error",),
            allowed_http_methods=("GET", "HEAD"),
            maximum_request_attempts=15,
        )
        record = self.running_record(permit)
        connection = _PostFormSqliConnection()

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            outcome = self.make_executor().execute(record)

        self.assertEqual(outcome.report.findings, ())
        # The discovery fetch (GET /) is allowed; no POST is ever attempted.
        self.assertNotIn("POST", connection.requested_methods)

    @patch("webguard_api.executor.validate_target_url")
    def test_post_candidate_executes_when_permit_allows_post_and_sqli(
        self, validate_mock
    ) -> None:
        validate_mock.return_value = self.validated_target()
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.sqli.error",),
            allowed_http_methods=("GET", "HEAD", "POST"),
            maximum_request_attempts=15,
        )
        record = self.running_record(permit)
        connection = _PostFormSqliConnection()

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            outcome = self.make_executor().execute(record)

        self.assertEqual(len(outcome.report.findings), 1)
        finding = outcome.report.findings[0]
        self.assertEqual(finding.identity.method, "POST")
        self.assertIn("POST", connection.requested_methods)

    @patch("webguard_api.executor.validate_target_url")
    def test_post_candidate_not_probed_when_only_xss_authorized(
        self, validate_mock
    ) -> None:
        """SQLi-only authorization proof, POST transport: a permit that
        allows POST but only authorizes active.xss.reflected must never
        trigger the SQLi detector against the same POST candidate."""
        validate_mock.return_value = self.validated_target()
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.xss.reflected",),
            allowed_http_methods=("GET", "HEAD", "POST"),
            maximum_request_attempts=15,
        )
        record = self.running_record(permit)
        connection = _PostFormSqliConnection()

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            outcome = self.make_executor().execute(record)

        # The SQLi-vulnerable response body never contains the reflected
        # XSS marker, so no XSS finding fires either -- but critically,
        # no SQLi finding fires, proving active_checks independently
        # gates POST-transport detectors exactly as it does GET ones.
        self.assertEqual(outcome.report.findings, ())


if __name__ == "__main__":
    unittest.main()
