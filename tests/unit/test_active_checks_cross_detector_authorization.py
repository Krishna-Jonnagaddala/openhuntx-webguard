"""Executor-level proof that authorizing one active detector does not
implicitly authorize another: an XSS-only permit must never trigger the
SQLi detector, and a SQLi-only permit must never trigger the XSS
detector, even when the same discovered form field is genuinely
vulnerable to both.

Complements (does not replace) test_active_checks_permit_control.py's
permit-issuance-layer RBAC/validation tests and
test_job_executor_active_detection.py's single-detector orchestration
tests -- this file is specifically about the boundary *between* two
authorized detectors.
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


_FORM_PAGE = (
    b"<html><body>"
    b'<form method="GET" action=""><input name="id"></form>'
    b"</body></html>"
)


class _DoublyVulnerableConnection:
    """A single form field genuinely vulnerable to both reflected XSS and
    error-based SQLi -- so a test proving only the *authorized* detector
    fires cannot pass by accident because the other vulnerability simply
    wasn't present to find."""

    def __init__(self) -> None:
        self.closed = False
        self.sock = _FakeTlsSocket()
        self._context = _FakeTlsContext()
        self.requested_paths: list[str] = []

    def putrequest(self, method, path, **kwargs) -> None:
        self.requested_paths.append(path)
        self._path = path

    def putheader(self, name, value) -> None:
        return None

    def endheaders(self) -> None:
        return None

    def getresponse(self):
        parsed = urlsplit(self._path)
        query = parse_qs(parsed.query)
        if "id" not in query:
            return _FakeResponse(_FORM_PAGE)
        value = query["id"][0]
        if value == "'":
            return _FakeResponse(
                b"<html>you have an error in your sql syntax</html>",
                status=500,
            )
        if value.startswith("<wgxss"):
            return _FakeResponse(
                f"<html><body>{value}</body></html>".encode()
            )
        return _FakeResponse(b"<html>Item 1</html>", status=200)

    def close(self) -> None:
        self.closed = True


class CrossDetectorAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.auth_dir = self.root / "authorizations"
        write_authorization(self.auth_dir)
        self.artifacts = self.root / "artifacts"
        self.store = ScanJobStore(self.root / "jobs.sqlite3")

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

    def running_record(self, permit):
        auth = authorization()
        request = ScanJobRequest(
            idempotency_key="cross-detector-single-page",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=ScanJobMode.SINGLE_PAGE,
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
            trustscan_signer=trustscan_signer(self.store),
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            single_scanner=lambda target, **kwargs: completed_report(
                kwargs["scan_id"]
            ),
        )

    def _execute(self, permit):
        record = self.running_record(permit)
        connection = _DoublyVulnerableConnection()
        with patch(
            "webguard_api.executor.validate_target_url",
            return_value=self.validated_target(),
        ), patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            outcome = self.make_executor().execute(record)
        return outcome, connection

    def test_xss_only_permit_never_triggers_sqli(self) -> None:
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.xss.reflected",),
            maximum_request_attempts=15,
        )
        outcome, _connection = self._execute(permit)
        sources = {f.source for f in outcome.report.findings}
        rule_ids = {f.identity.rule_id for f in outcome.report.findings}
        self.assertIn("webguard-active", sources)
        self.assertTrue(
            any(r.startswith("active.xss.reflected") for r in rule_ids)
        )
        self.assertFalse(
            any(r.startswith("active.sqli.error") for r in rule_ids),
            f"SQLi rule fired under an XSS-only permit: {rule_ids}",
        )

    def test_sqli_only_permit_never_triggers_xss(self) -> None:
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.sqli.error",),
            maximum_request_attempts=15,
        )
        outcome, _connection = self._execute(permit)
        rule_ids = {f.identity.rule_id for f in outcome.report.findings}
        self.assertTrue(
            any(r.startswith("active.sqli.error") for r in rule_ids)
        )
        self.assertFalse(
            any(r.startswith("active.xss.reflected") for r in rule_ids),
            f"XSS rule fired under a SQLi-only permit: {rule_ids}",
        )

    def test_both_authorized_both_fire(self) -> None:
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.sqli.error", "active.xss.reflected"),
            maximum_request_attempts=15,
        )
        outcome, _connection = self._execute(permit)
        rule_ids = {f.identity.rule_id for f in outcome.report.findings}
        self.assertTrue(
            any(r.startswith("active.sqli.error") for r in rule_ids)
        )
        self.assertTrue(
            any(r.startswith("active.xss.reflected") for r in rule_ids)
        )

    def test_passive_only_permit_triggers_neither(self) -> None:
        permit = create_trustscan_permit(self.store)  # active_checks=()
        outcome, connection = self._execute(permit)
        self.assertEqual(outcome.report.findings, ())
        self.assertEqual(connection.requested_paths, [])


if __name__ == "__main__":
    unittest.main()
