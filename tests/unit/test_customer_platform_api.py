"""Slice 15 Part A: assets, ownership verification, dashboard, team,
API keys, settings, and report download -- against the real HTTP
transport, local/SQLite-backed service, matching the established
``test_http_api.py`` harness pattern."""

from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from webguard_api import (
    ApiTokenAuthenticator,
    AuthorizationRepository,
    FixedWindowRateLimiter,
    ScanJobStore,
    WebGuardJobService,
    create_server,
)
from webguard_api.artifact_store import LocalArtifactStore
from webguard_contracts import OrganizationRole, PrincipalType

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    OWNER_ID,
    VIEWER_ID,
    VIEWER_TOKEN_ID,
    create_identity_fixture,
    write_authorization,
)


class _WellKnownFixtureHandler(BaseHTTPRequestHandler):
    """A real local HTTP server proving verification actually fetches
    and checks content -- not a stub that always says yes."""

    expected_token = ""

    def log_message(self, *args) -> None:  # noqa: D401
        return None

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/.well-known/webguard-verification.txt":
            body = self.expected_token.encode()
            self.send_response(200)
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class CustomerPlatformApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity, self.context, self.token = create_identity_fixture(store.path)
        _, self.viewer_context, self.viewer_token = create_identity_fixture(
            store.path, role=OrganizationRole.VIEWER, principal_id=VIEWER_ID, token_id=VIEWER_TOKEN_ID,
        )
        self.artifact_root = root / "artifacts"
        self.service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=identity,
            clock=lambda: NOW,
            artifact_store=LocalArtifactStore(self.artifact_root),
        )
        self.server = create_server(
            "127.0.0.1", 0, self.service,
            authenticator=ApiTokenAuthenticator(identity),
            rate_limiter=FixedWindowRateLimiter(requests=200, window_seconds=60),
            maximum_request_bytes=4096,
            clock=lambda: NOW,
            epoch_clock=lambda: 1000.0,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method, path, body=None, headers=None, *, token="owner"):
        effective = dict(headers or {})
        if body is not None and "Content-Type" not in effective:
            effective["Content-Type"] = "application/json"
        if token == "owner":
            effective.setdefault("Authorization", f"Bearer {self.token}")
        elif token == "viewer":
            effective.setdefault("Authorization", f"Bearer {self.viewer_token}")
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        connection.request(method, path, body=body, headers=effective)
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        response_headers = dict(response.getheaders())
        connection.close()
        return status, response_headers, payload

    def json_request(self, method, path, body=None, headers=None, *, token="owner"):
        raw = None if body is None else json.dumps(body).encode()
        status, response_headers, payload = self.request(method, path, raw, headers, token=token)
        return status, response_headers, json.loads(payload) if payload else None

    # -- Assets ----------------------------------------------------------

    def test_create_list_get_and_update_asset(self) -> None:
        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://asset.example/", "label": "Prod site"})
        self.assertEqual(status, 201, created)
        target_id = created["target_id"]
        self.assertEqual(created["label"], "Prod site")
        self.assertIsNone(created["default_mode"])

        status, _, listing = self.json_request("GET", "/v1/assets")
        self.assertEqual(status, 200, listing)
        self.assertEqual(len(listing["assets"]), 1)

        status, _, detail = self.json_request("GET", f"/v1/assets/{target_id}")
        self.assertEqual(status, 200, detail)
        self.assertIsNone(detail["verification"])
        self.assertIsNone(detail["authorization"])
        self.assertIsNone(detail["last_scan"])
        self.assertEqual(detail["finding_counts"], {})

        status, _, updated = self.json_request(
            "PATCH", f"/v1/assets/{target_id}", {"label": "Renamed", "default_mode": "crawl"}
        )
        self.assertEqual(status, 200, updated)
        self.assertEqual(updated["label"], "Renamed")
        self.assertEqual(updated["default_mode"], "crawl")

    def test_asset_conflict_on_duplicate_url(self) -> None:
        status, _, _ = self.json_request("POST", "/v1/assets", {"url": "https://dup.example/"})
        self.assertEqual(status, 201)
        status, _, payload = self.json_request("POST", "/v1/assets", {"url": "https://dup.example/"})
        self.assertEqual(status, 409, payload)

    def test_asset_url_typed_without_trailing_slash_still_matches_an_assigned_authorization(self) -> None:
        """The fixture authorization's target is "https://example.com/"
        (CLI-canonicalized, see service_test_support.TARGET). A customer
        naturally types a bare domain with no trailing slash; the asset
        must still store it in the same canonical shape or
        _find_authorization_for_asset's exact-match join never fires."""

        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://example.com"})
        self.assertEqual(status, 201, created)
        target_id = created["target_id"]

        status, _, detail = self.json_request("GET", f"/v1/assets/{target_id}")
        self.assertEqual(status, 200, detail)
        self.assertIsNotNone(detail["authorization"])
        self.assertEqual(detail["authorization"]["authorization_id"], AUTH_ID)

    def test_asset_url_without_trailing_slash_conflicts_with_the_same_url_with_one(self) -> None:
        status, _, _ = self.json_request("POST", "/v1/assets", {"url": "https://dup-slash.example/"})
        status, _, payload = self.json_request("POST", "/v1/assets", {"url": "https://dup-slash.example"})
        self.assertEqual(status, 409, payload)

    def test_asset_url_without_scheme_or_host_is_rejected(self) -> None:
        status, _, payload = self.json_request("POST", "/v1/assets", {"url": "not-a-url"})
        self.assertEqual(status, 400, payload)
        self.assertEqual(payload["error"]["code"], "asset_url_invalid")

    def test_viewer_cannot_create_asset(self) -> None:
        status, _, payload = self.json_request(
            "POST", "/v1/assets", {"url": "https://viewer-cannot.example/"}, token="viewer"
        )
        self.assertEqual(status, 403, payload)

    def test_assets_are_tenant_scoped(self) -> None:
        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://scoped.example/"})
        self.assertEqual(status, 201, created)
        # A different organization's principal cannot see or fetch it.
        from webguard_api import IdentityStore

        other_identity = IdentityStore(Path(self.temporary.name) / "jobs.sqlite3")
        other_org = other_identity.create_organization("Other Org", now=NOW)
        other_principal = other_identity.create_principal(
            other_org.organization_id, "Other Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW,
        )
        issued = other_identity.create_token(other_principal.principal_id, label="other", now=NOW)
        status, _, payload = self.json_request(
            "GET", f"/v1/assets/{created['target_id']}", headers={"Authorization": f"Bearer {issued.token}"}, token=None
        )
        self.assertEqual(status, 404, payload)

    # -- Coverage Truth Map (Phase 4: a read API) --------------------------

    def test_coverage_for_a_never_scanned_asset_is_an_empty_list_not_a_fabricated_total(self) -> None:
        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://never-scanned.example/"})
        self.assertEqual(status, 201, created)

        status, _, payload = self.json_request("GET", f"/v1/assets/{created['target_id']}/coverage")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["coverage"], [])
        self.assertEqual(payload["status_counts"], {"completed": 0, "blocked": 0, "unreachable": 0})
        self.assertEqual(set(payload["not_populated_states"]), {"discovered", "authorized"})
        self.assertIsNone(payload["page"]["next_cursor"])

    def test_coverage_reflects_actually_recorded_rows_with_honest_identity_label(self) -> None:
        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://coverage.example/"})
        self.assertEqual(status, 201, created)

        from webguard_api.coverage_store import CoverageStatus

        self.service.coverage_repository.record_coverage(
            organization_id=self.context.organization_id, asset="https://coverage.example", path="/",
            http_method="GET", identity_label="unauthenticated", check_id="header_analyzer",
            status=CoverageStatus.COMPLETED, scanner_version="1.0.0", now=NOW,
        )
        self.service.coverage_repository.record_coverage(
            organization_id=self.context.organization_id, asset="https://coverage.example", path="/admin",
            http_method="GET", identity_label="unauthenticated", check_id="tls_analyzer",
            status=CoverageStatus.BLOCKED, scanner_version="1.0.0", now=NOW,
        )

        status, _, payload = self.json_request("GET", f"/v1/assets/{created['target_id']}/coverage")
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["coverage"]), 2)
        self.assertEqual(payload["status_counts"], {"completed": 1, "blocked": 1, "unreachable": 0})
        self.assertTrue(all(row["identity_label"] == "unauthenticated" for row in payload["coverage"]))

    def test_coverage_pagination_returns_a_usable_cursor_for_the_next_page(self) -> None:
        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://paged.example/"})
        self.assertEqual(status, 201, created)

        from webguard_api.coverage_store import CoverageStatus

        for index, check_id in enumerate(("a_check", "b_check", "c_check")):
            self.service.coverage_repository.record_coverage(
                organization_id=self.context.organization_id, asset="https://paged.example", path="/",
                http_method="GET", identity_label="unauthenticated", check_id=check_id,
                status=CoverageStatus.COMPLETED, scanner_version="1.0.0",
                now=NOW + timedelta(minutes=index),
            )

        status, _, first_page = self.json_request(
            "GET", f"/v1/assets/{created['target_id']}/coverage?limit=2"
        )
        self.assertEqual(status, 200, first_page)
        self.assertEqual(len(first_page["coverage"]), 2)
        self.assertIsNotNone(first_page["page"]["next_cursor"])
        self.assertEqual(first_page["status_counts"], {"completed": 3, "blocked": 0, "unreachable": 0})

        status, _, second_page = self.json_request(
            "GET",
            f"/v1/assets/{created['target_id']}/coverage?limit=2&cursor={first_page['page']['next_cursor']}",
        )
        self.assertEqual(status, 200, second_page)
        self.assertEqual(len(second_page["coverage"]), 1)
        self.assertIsNone(second_page["page"]["next_cursor"])
        seen_checks = {row["check_id"] for row in first_page["coverage"]} | {row["check_id"] for row in second_page["coverage"]}
        self.assertEqual(seen_checks, {"a_check", "b_check", "c_check"})

    def test_coverage_is_tenant_scoped(self) -> None:
        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://coverage-scoped.example/"})
        self.assertEqual(status, 201, created)

        from webguard_api.coverage_store import CoverageStatus

        self.service.coverage_repository.record_coverage(
            organization_id=self.context.organization_id, asset="https://coverage-scoped.example", path="/",
            http_method="GET", identity_label="unauthenticated", check_id="header_analyzer",
            status=CoverageStatus.COMPLETED, scanner_version="1.0.0", now=NOW,
        )

        from webguard_api import IdentityStore

        other_identity = IdentityStore(Path(self.temporary.name) / "jobs.sqlite3")
        other_org = other_identity.create_organization("Other Coverage Org", now=NOW)
        other_principal = other_identity.create_principal(
            other_org.organization_id, "Other Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW,
        )
        issued = other_identity.create_token(other_principal.principal_id, label="other", now=NOW)
        status, _, payload = self.json_request(
            "GET", f"/v1/assets/{created['target_id']}/coverage",
            headers={"Authorization": f"Bearer {issued.token}"}, token=None,
        )
        self.assertEqual(status, 404, payload)

    def test_coverage_for_unknown_asset_is_404(self) -> None:
        status, _, payload = self.json_request(
            "GET", "/v1/assets/00000000-0000-0000-0000-000000000000/coverage"
        )
        self.assertEqual(status, 404, payload)

    # -- Ownership verification -------------------------------------------

    def test_well_known_verification_succeeds_against_real_fixture(self) -> None:
        fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _WellKnownFixtureHandler)
        fixture_thread = threading.Thread(target=fixture_server.serve_forever, daemon=True)
        fixture_thread.start()
        self.addCleanup(fixture_server.server_close)
        self.addCleanup(fixture_server.shutdown)
        fixture_port = fixture_server.server_address[1]
        target_url = f"http://127.0.0.1:{fixture_port}/"

        status, _, created = self.json_request("POST", "/v1/assets", {"url": target_url})
        self.assertEqual(status, 201, created)
        target_id = created["target_id"]

        status, _, started = self.json_request(
            "POST", f"/v1/assets/{target_id}/verification", {"method": "well_known_http"}
        )
        self.assertEqual(status, 201, started)
        self.assertEqual(started["status"], "pending")
        token = started["instructions"]["expected_content"]
        _WellKnownFixtureHandler.expected_token = token

        from webguard_scanner import ValidatedTarget

        def _validated(url, policy, resolver=None):
            from urllib.parse import urlsplit

            parsed = urlsplit(url)
            return ValidatedTarget(
                original_url=url, normalised_url=url, scheme=parsed.scheme,
                hostname=parsed.hostname, port=parsed.port, resolved_addresses=("127.0.0.1",),
            )

        with patch("webguard_api.target_verification.validate_target_url", side_effect=_validated):
            status, _, checked = self.json_request("POST", f"/v1/assets/{target_id}/verification/check")
        self.assertEqual(status, 200, checked)
        self.assertEqual(checked["status"], "verified")

        status, _, detail = self.json_request("GET", f"/v1/assets/{target_id}")
        self.assertEqual(detail["verification"]["status"], "verified")
        self.assertNotIn("instructions", detail["verification"])

    def test_well_known_verification_stays_pending_and_retryable_on_mismatch(self) -> None:
        """A check that doesn't match yet must never destroy the still-
        valid pending token: the customer should be able to fix
        whatever was wrong and click "Check now" again, not be forced
        to publish an entirely new value first."""

        fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), _WellKnownFixtureHandler)
        fixture_thread = threading.Thread(target=fixture_server.serve_forever, daemon=True)
        fixture_thread.start()
        self.addCleanup(fixture_server.server_close)
        self.addCleanup(fixture_server.shutdown)
        fixture_port = fixture_server.server_address[1]
        target_url = f"http://127.0.0.1:{fixture_port}/"
        _WellKnownFixtureHandler.expected_token = "wrong-token-entirely"

        status, _, created = self.json_request("POST", "/v1/assets", {"url": target_url})
        target_id = created["target_id"]
        status, _, started = self.json_request(
            "POST", f"/v1/assets/{target_id}/verification", {"method": "well_known_http"}
        )
        self.assertEqual(status, 201, started)
        original_token = started["instructions"]["expected_content"]

        from webguard_scanner import ValidatedTarget

        def _validated(url, policy, resolver=None):
            from urllib.parse import urlsplit

            parsed = urlsplit(url)
            return ValidatedTarget(
                original_url=url, normalised_url=url, scheme=parsed.scheme,
                hostname=parsed.hostname, port=parsed.port, resolved_addresses=("127.0.0.1",),
            )

        with patch("webguard_api.target_verification.validate_target_url", side_effect=_validated):
            status, _, checked = self.json_request("POST", f"/v1/assets/{target_id}/verification/check")
        self.assertEqual(status, 200, checked)
        self.assertEqual(checked["status"], "pending")
        self.assertEqual(checked["last_check_detail"], "token-mismatch")
        self.assertEqual(checked["instructions"]["expected_content"], original_token)

        # Fix the fixture (simulating the customer publishing the
        # correct file) and check again with no new verification
        # started: the original token must still be the one honored.
        _WellKnownFixtureHandler.expected_token = original_token
        with patch("webguard_api.target_verification.validate_target_url", side_effect=_validated):
            status, _, rechecked = self.json_request("POST", f"/v1/assets/{target_id}/verification/check")
        self.assertEqual(status, 200, rechecked)
        self.assertEqual(rechecked["status"], "verified")

    def test_verification_start_rejects_unknown_method(self) -> None:
        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://method-invalid.example/"})
        target_id = created["target_id"]
        status, _, started = self.json_request(
            "POST", f"/v1/assets/{target_id}/verification", {"method": "carrier_pigeon"}
        )
        self.assertEqual(status, 400, started)

    def test_dns_txt_verification_succeeds_against_resolved_record(self) -> None:
        """No fixture DNS server is spun up (no such thing as a
        disposable authoritative nameserver here): this mocks
        ``dns.resolver.Resolver.resolve`` at the same boundary the
        well-known tests mock ``validate_target_url`` at, the
        third-party client call itself, not this module's own logic."""

        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://dns-verify.example/"})
        target_id = created["target_id"]
        status, _, started = self.json_request(
            "POST", f"/v1/assets/{target_id}/verification", {"method": "dns_txt"}
        )
        self.assertEqual(status, 201, started)
        self.assertEqual(started["instructions"]["record_type"], "TXT")
        self.assertEqual(started["instructions"]["record_prefix"], "_webguard-verification")
        token = started["instructions"]["expected_content"]

        class _FakeTxtRdata:
            def __init__(self, value: str) -> None:
                self.strings = (value.encode(),)

        def _resolve(resolver, qname, rdtype, *args, **kwargs):
            self.assertEqual(str(qname).rstrip("."), "_webguard-verification.dns-verify.example")
            self.assertEqual(rdtype, "TXT")
            return [_FakeTxtRdata(token)]

        with patch("dns.resolver.Resolver.resolve", _resolve):
            status, _, checked = self.json_request("POST", f"/v1/assets/{target_id}/verification/check")
        self.assertEqual(status, 200, checked)
        self.assertEqual(checked["status"], "verified")

    def test_dns_txt_verification_stays_pending_and_retryable_when_record_missing(self) -> None:
        """The real-world case this method exists for: a record that
        hasn't propagated yet must not cost the customer their
        already-published value. Same non-destructive contract as the
        well-known method's own retry test."""

        import dns.resolver as dns_resolver_module

        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://dns-missing.example/"})
        target_id = created["target_id"]
        status, _, started = self.json_request(
            "POST", f"/v1/assets/{target_id}/verification", {"method": "dns_txt"}
        )
        self.assertEqual(status, 201, started)
        token = started["instructions"]["expected_content"]

        def _not_found(resolver, qname, rdtype, *args, **kwargs):
            raise dns_resolver_module.NXDOMAIN()

        with patch("dns.resolver.Resolver.resolve", _not_found):
            status, _, checked = self.json_request("POST", f"/v1/assets/{target_id}/verification/check")
        self.assertEqual(status, 200, checked)
        self.assertEqual(checked["status"], "pending")
        self.assertEqual(checked["last_check_detail"], "dns-record-not-found")
        self.assertEqual(checked["instructions"]["expected_content"], token)

        class _FakeTxtRdata:
            def __init__(self, value: str) -> None:
                self.strings = (value.encode(),)

        def _now_resolves(resolver, qname, rdtype, *args, **kwargs):
            return [_FakeTxtRdata(token)]

        with patch("dns.resolver.Resolver.resolve", _now_resolves):
            status, _, rechecked = self.json_request("POST", f"/v1/assets/{target_id}/verification/check")
        self.assertEqual(status, 200, rechecked)
        self.assertEqual(rechecked["status"], "verified")

    def test_starting_over_while_still_pending_issues_a_genuinely_new_token(self) -> None:
        """The other half of the retry story: a customer who wants a
        fresh value entirely (not just a retry of the same one) can
        ask for it explicitly, and it must actually be different, not
        the same token re-served."""

        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://dns-restart.example/"})
        target_id = created["target_id"]
        status, _, first = self.json_request(
            "POST", f"/v1/assets/{target_id}/verification", {"method": "dns_txt"}
        )
        self.assertEqual(status, 201, first)
        first_token = first["instructions"]["expected_content"]

        status, _, second = self.json_request(
            "POST", f"/v1/assets/{target_id}/verification", {"method": "dns_txt"}
        )
        self.assertEqual(status, 201, second)
        second_token = second["instructions"]["expected_content"]
        self.assertNotEqual(first_token, second_token)

        # The old token must no longer be the one a check honors.
        class _FakeTxtRdata:
            def __init__(self, value: str) -> None:
                self.strings = (value.encode(),)

        def _resolves_old_token(resolver, qname, rdtype, *args, **kwargs):
            return [_FakeTxtRdata(first_token)]

        with patch("dns.resolver.Resolver.resolve", _resolves_old_token):
            status, _, checked = self.json_request("POST", f"/v1/assets/{target_id}/verification/check")
        self.assertEqual(status, 200, checked)
        self.assertEqual(checked["status"], "pending")
        self.assertEqual(checked["last_check_detail"], "token-mismatch")

    def test_verification_expires_after_the_token_ttl(self) -> None:
        """Closes a real pre-existing gap: a timed-out token used to be
        recorded as plain ``failed``, the same status a genuine
        mismatch produces, even though the schema and
        ``VerificationStatus`` enum both already name ``expired`` as
        its own outcome."""

        status, _, created = self.json_request("POST", "/v1/assets", {"url": "https://dns-expiring.example/"})
        target_id = created["target_id"]
        status, _, started = self.json_request(
            "POST", f"/v1/assets/{target_id}/verification", {"method": "dns_txt"}
        )
        self.assertEqual(status, 201, started)

        from datetime import timedelta

        from webguard_api.target_verification import VERIFICATION_TOKEN_TTL

        original_clock = self.service.clock
        self.service.clock = lambda: NOW + VERIFICATION_TOKEN_TTL + timedelta(seconds=1)
        try:
            status, _, checked = self.json_request("POST", f"/v1/assets/{target_id}/verification/check")
        finally:
            self.service.clock = original_clock
        self.assertEqual(status, 200, checked)
        self.assertEqual(checked["status"], "expired")
        self.assertEqual(checked["evidence"], "verification_token_expired")

    # -- Dashboard ---------------------------------------------------------

    def test_dashboard_summary_reflects_real_counts(self) -> None:
        status, _, summary = self.json_request("GET", "/v1/dashboard/summary")
        self.assertEqual(status, 200, summary)
        self.assertEqual(summary["total_assets"], 0)
        self.assertEqual(summary["active_scans"], 0)
        self.assertEqual(summary["findings_by_severity"], {})

        self.json_request("POST", "/v1/assets", {"url": "https://dashboard.example/"})
        status, _, summary = self.json_request("GET", "/v1/dashboard/summary")
        self.assertEqual(summary["total_assets"], 1)

    # -- Team ----------------------------------------------------------------

    def test_owner_can_invite_update_and_remove_a_member(self) -> None:
        status, _, invited = self.json_request(
            "POST", "/v1/team/invitations",
            {"display_name": "New Analyst", "role": "analyst", "email": "new.analyst@example.com"},
        )
        self.assertEqual(status, 201, invited)
        self.assertEqual(invited["email"], "new.analyst@example.com")
        member_id = invited["principal_id"]

        status, _, listing = self.json_request("GET", "/v1/team")
        self.assertEqual(status, 200, listing)
        self.assertTrue(any(m["principal_id"] == member_id for m in listing["members"]))

        status, _, updated = self.json_request("PATCH", f"/v1/team/{member_id}", {"role": "viewer"})
        self.assertEqual(status, 200, updated)
        self.assertEqual(updated["role"], "viewer")

        status, _, removed = self.json_request("DELETE", f"/v1/team/{member_id}")
        self.assertEqual(status, 200, removed)
        self.assertFalse(removed["active"])

    def test_owner_cannot_modify_own_role_or_remove_self(self) -> None:
        status, _, payload = self.json_request("PATCH", f"/v1/team/{OWNER_ID}", {"role": "viewer"})
        self.assertEqual(status, 403, payload)
        status, _, payload = self.json_request("DELETE", f"/v1/team/{OWNER_ID}")
        self.assertEqual(status, 403, payload)

    def test_non_owner_cannot_grant_owner_role(self) -> None:
        status, _, invited = self.json_request(
            "POST", "/v1/team/invitations",
            {"display_name": "Future Admin", "role": "administrator", "email": "future.admin@example.com"},
        )
        self.assertEqual(status, 201, invited)
        # Slice 16: invitation no longer issues a bearer token directly
        # (it issues a mailed invitation token instead) -- an API token
        # for the invited administrator is created the same way any
        # other out-of-band API token would be, matching this file's
        # own established "provision a second principal/token directly"
        # pattern used elsewhere in this suite (test_assets_are_tenant_scoped).
        admin_token = self.service.identity.create_token(
            invited["principal_id"], label="test-admin", now=NOW
        ).token
        status, _, invited2 = self.json_request(
            "POST", "/v1/team/invitations",
            {"display_name": "Nobody Yet", "role": "viewer", "email": "nobody.yet@example.com"},
            headers={"Authorization": f"Bearer {admin_token}"}, token=None,
        )
        self.assertEqual(status, 201, invited2)
        member_id = invited2["principal_id"]
        status, _, payload = self.json_request(
            "PATCH", f"/v1/team/{member_id}", {"role": "owner"},
            headers={"Authorization": f"Bearer {admin_token}"}, token=None,
        )
        self.assertEqual(status, 403, payload)

    def test_viewer_cannot_invite(self) -> None:
        status, _, payload = self.json_request(
            "POST", "/v1/team/invitations", {"display_name": "X", "role": "viewer"}, token="viewer"
        )
        self.assertEqual(status, 403, payload)

    # -- API keys --------------------------------------------------------

    def test_create_list_and_revoke_own_api_key(self) -> None:
        status, _, created = self.json_request("POST", "/v1/api-keys", {"label": "CI token"})
        self.assertEqual(status, 201, created)
        self.assertTrue(created["token"].startswith("wgt_"))
        token_id = created["token_id"]

        status, _, listing = self.json_request("GET", "/v1/api-keys")
        self.assertEqual(status, 200, listing)
        self.assertTrue(all("token" not in key for key in listing["api_keys"]))
        self.assertTrue(any(k["token_id"] == token_id for k in listing["api_keys"]))

        status, _, revoked = self.json_request("DELETE", f"/v1/api-keys/{token_id}")
        self.assertEqual(status, 200, revoked)
        self.assertIsNotNone(revoked["revoked_at"])

    def test_cannot_revoke_another_principals_api_key(self) -> None:
        status, _, created = self.json_request("POST", "/v1/api-keys", {"label": "Owner key"})
        token_id = created["token_id"]
        status, _, payload = self.json_request("DELETE", f"/v1/api-keys/{token_id}", token="viewer")
        self.assertEqual(status, 404, payload)

    # -- Settings ----------------------------------------------------------

    def test_settings_returns_real_org_and_account_data(self) -> None:
        status, _, settings = self.json_request("GET", "/v1/settings")
        self.assertEqual(status, 200, settings)
        self.assertEqual(settings["organization"]["name"], "InternStack")
        self.assertEqual(settings["account"]["principal_id"], OWNER_ID)

    # -- Report download ----------------------------------------------------

    def test_report_download_returns_bytes_and_is_tenant_scoped(self) -> None:
        scan = self.service.scan_repository.create_scan(
            organization_id=self.context.organization_id, job_id="66666666-6666-4666-8666-666666666666",
            target="https://report-dl.example/", authorization_id="8ae6403f-7832-498c-b37e-c0c87be19ea1",
            mode="single_page", scanner_version="1.0", now=NOW,
        )
        report_path = self.artifact_root / "report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text('{"status": "completed"}', encoding="utf-8")
        self.service.scan_repository.complete_scan(
            scan.scan_id, organization_id=self.context.organization_id, status="completed",
            report_ref="report.json", finding_count=0, now=NOW,
        )
        status, _, created = self.json_request("POST", "/v1/reports", {"scan_id": scan.scan_id})
        self.assertEqual(status, 201, created)
        report_id = created["report_id"]

        status, headers, body = self.request("GET", f"/v1/reports/{report_id}/download")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"status": "completed"}')
        self.assertIn("attachment", headers.get("Content-Disposition", ""))

        status, _, payload = self.json_request("GET", f"/v1/reports/{report_id}/download", token="viewer")
        self.assertEqual(status, 200)  # viewer has REPORT_READ

    def test_report_download_fails_closed_when_bytes_do_not_match_the_persisted_checksum(self) -> None:
        """Slice 17 requirement 14: a report artifact that has been
        corrupted or truncated *after* its checksum was computed and
        persisted (`create_report`) must never be served -- the
        download must fail closed with a clear error, not silently
        hand the customer bytes that no longer match what was
        checksummed at registration time."""

        scan = self.service.scan_repository.create_scan(
            organization_id=self.context.organization_id, job_id="77777777-7777-4777-8777-777777777777",
            target="https://report-integrity.example/", authorization_id="8ae6403f-7832-498c-b37e-c0c87be19ea1",
            mode="single_page", scanner_version="1.0", now=NOW,
        )
        report_path = self.artifact_root / "integrity-report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text('{"status": "completed"}', encoding="utf-8")
        self.service.scan_repository.complete_scan(
            scan.scan_id, organization_id=self.context.organization_id, status="completed",
            report_ref="integrity-report.json", finding_count=0, now=NOW,
        )
        status, _, created = self.json_request("POST", "/v1/reports", {"scan_id": scan.scan_id})
        self.assertEqual(status, 201, created)
        report_id = created["report_id"]

        # Corrupt the artifact on disk *after* its checksum was
        # computed and persisted -- exactly the scenario a truncated
        # write or a bit-flip in storage would produce.
        report_path.write_text('{"status": "tampered"}', encoding="utf-8")

        status, _, payload = self.json_request("GET", f"/v1/reports/{report_id}/download")
        self.assertEqual(status, 500, payload)
        self.assertEqual(payload["error"]["code"], "report_integrity_check_failed")


if __name__ == "__main__":
    unittest.main()
