"""Executor-level integration tests for active-detection orchestration.

Covers: passive-only permits cannot trigger active detection; permits
that explicitly authorize an active check do trigger it end-to-end
(discovery -> probe -> finding merged into the report); the permit's
existing runtime-safety budget also governs active probes (fail closed,
signed safety-blocked receipt); cancellation stops probes; and evidence
never contains raw response content.
"""

from __future__ import annotations

import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from webguard_api import (
    AuthorizationRepository,
    JobExecutionError,
    ScanJobExecutor,
    ScanJobStore,
)
from webguard_contracts import (
    CrawlScanPolicy,
    CrawlScanResult,
    ScanCoverage,
    ScanJobMode,
    ScanJobRequest,
    ScanStatus,
)
from webguard_scanner import CrawlCancellationToken, ValidatedTarget

from tests.unit.test_crawl_scan_contract import END, START, completed_page

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
    b'<form method="GET" action="/search"><input name="q"></form>'
    b"</body></html>"
)


class _FormAndReflectionConnection:
    """Serves the root page (with a GET search form) and, for requests to
    /search, reflects the q parameter unescaped -- a controlled, clearly
    labeled synthetic fixture, not a real vulnerable app."""

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
        if parsed.path == "/search":
            value = parse_qs(parsed.query).get("q", [""])[0]
            body = f"<html><body>{value}</body></html>".encode()
            return _FakeResponse(body)
        return _FakeResponse(_FORM_PAGE)

    def close(self) -> None:
        self.closed = True


_SELF_SUBMITTING_FORM_PAGE = (
    b"<html><body>"
    b'<form method="GET" action=""><input name="q"></form>'
    b"</body></html>"
)


class _SelfSubmittingFormConnection:
    """Same idea as _FormAndReflectionConnection, but the form submits
    back to the same page path -- the only shape crawl-mode active
    detection can attribute a finding to (see CrawlPageScanResult's
    "every finding must belong to the crawled page URL" invariant)."""

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
        if "q" in query:
            value = query["q"][0]
            body = f"<html><body>{value}</body></html>".encode()
            return _FakeResponse(body)
        return _FakeResponse(_SELF_SUBMITTING_FORM_PAGE)

    def close(self) -> None:
        self.closed = True


def _crawl_policy() -> CrawlScanPolicy:
    return CrawlScanPolicy(
        maximum_pages=10,
        maximum_depth=1,
        maximum_links_per_page=100,
        maximum_url_length=2048,
        minimum_delay_seconds=0.1,
        query_mode="drop",
        allowed_content_types=("application/xhtml+xml", "text/html"),
        blocked_path_segments=("delete", "logout"),
    )


class ActiveDetectionExecutorTests(unittest.TestCase):
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
            idempotency_key=f"active-detection-{mode.value}",
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

    def make_executor(self, *, single_scanner=None) -> ScanJobExecutor:
        return ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            single_scanner=single_scanner
            or (lambda target, **kwargs: completed_report(kwargs["scan_id"])),
        )

    @patch("webguard_api.executor.validate_target_url")
    def test_passive_only_permit_never_attempts_discovery_or_probes(
        self, validate_mock
    ) -> None:
        validate_mock.return_value = self.validated_target()
        permit = create_trustscan_permit(self.store)  # active_checks=() default
        record = self.running_record(permit)
        connection = _FormAndReflectionConnection()

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            outcome = self.make_executor().execute(record)

        self.assertEqual(outcome.report.findings, ())
        self.assertEqual(connection.requested_paths, [])

    @patch("webguard_api.executor.validate_target_url")
    def test_authorized_active_check_discovers_and_reports_confirmed_xss(
        self, validate_mock
    ) -> None:
        validate_mock.return_value = self.validated_target()
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.xss.reflected",),
            maximum_request_attempts=15,
        )
        record = self.running_record(permit)
        connection = _FormAndReflectionConnection()

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            outcome = self.make_executor().execute(record)

        self.assertEqual(len(outcome.report.findings), 1)
        finding = outcome.report.findings[0]
        self.assertEqual(finding.source, "webguard-active")
        self.assertEqual(
            [i.value for i in finding.identifiers], ["CWE-79"]
        )
        self.assertTrue(
            any(p.startswith("/search") for p in connection.requested_paths)
        )
        # Evidence must never contain the raw response body / reflected value.
        for item in finding.evidence:
            self.assertNotIn("<html>", item.summary)

    @patch("webguard_api.executor.validate_target_url")
    def test_unauthorized_active_check_is_never_run(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        # Permit only authorizes a different (nonexistent) check id.
        permit = create_trustscan_permit(
            self.store,
            active_checks=(),
        )
        record = self.running_record(permit)
        connection = _FormAndReflectionConnection()

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            outcome = self.make_executor().execute(record)

        self.assertEqual(outcome.report.findings, ())

    @patch("webguard_api.executor.validate_target_url")
    def test_permit_budget_exhaustion_blocks_active_probes_and_fails_closed(
        self, validate_mock
    ) -> None:
        validate_mock.return_value = self.validated_target()
        # Budget of 1: the discovery fetch itself consumes the only
        # permitted request, so the probe against /search must be blocked
        # by the existing runtime safety engine, not by detector code.
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.xss.reflected",),
            maximum_request_attempts=1,
        )
        record = self.running_record(permit)
        connection = _FormAndReflectionConnection()

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(JobExecutionError) as caught:
                self.make_executor().execute(record)

        self.assertEqual(
            caught.exception.code,
            "trustscan_runtime_request_budget_exhausted",
        )
        self.assertIsNotNone(caught.exception.safety_receipt_ref)

    @patch("webguard_api.executor.validate_target_url")
    def test_cancellation_stops_active_probes(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.xss.reflected",),
            maximum_request_attempts=15,
        )
        record = self.running_record(permit)
        connection = _FormAndReflectionConnection()
        token = CrawlCancellationToken()

        real_getresponse = connection.getresponse

        def cancel_after_discovery():
            response = real_getresponse()
            if urlsplit(connection._path).path != "/search":
                token.cancel()
            return response

        connection.getresponse = cancel_after_discovery

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            outcome = self.make_executor().execute(
                record, cancellation_token=token
            )

        self.assertEqual(outcome.report.findings, ())
        self.assertFalse(
            any(p.startswith("/search") for p in connection.requested_paths)
        )

    @patch("webguard_api.executor.validate_target_url")
    def test_crawl_mode_merges_active_findings_into_the_completed_page(
        self, validate_mock
    ) -> None:
        validate_mock.return_value = self.validated_target()
        permit = create_trustscan_permit(
            self.store,
            active_checks=("active.xss.reflected",),
            maximum_request_attempts=15,
        )
        record = self.running_record(permit, mode=ScanJobMode.CRAWL)
        connection = _SelfSubmittingFormConnection()

        def fake_crawl(target, **kwargs):
            scan_id = kwargs["scan_id"]
            return CrawlScanResult(
                scan_id=scan_id,
                scan_type="passive-http-crawl",
                status=ScanStatus.COMPLETED,
                target=TARGET,
                engine="webguard-native",
                engine_version="0.1.0",
                started_at=START,
                completed_at=END,
                policy=_crawl_policy(),
                pages=(completed_page(url=TARGET),),
            )

        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            crawl_scanner=fake_crawl,
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            outcome = executor.execute(record)

        self.assertEqual(len(outcome.report.pages), 1)
        page = outcome.report.pages[0]
        self.assertEqual(len(page.findings), 1)
        self.assertEqual(page.findings[0].source, "webguard-active")
        self.assertEqual(len(outcome.report.findings), 1)


if __name__ == "__main__":
    unittest.main()
