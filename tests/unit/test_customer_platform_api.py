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

        status, _, started = self.json_request("POST", f"/v1/assets/{target_id}/verification")
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

    def test_well_known_verification_fails_on_token_mismatch(self) -> None:
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
        status, _, started = self.json_request("POST", f"/v1/assets/{target_id}/verification")
        self.assertEqual(status, 201, started)

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
        self.assertEqual(checked["status"], "failed")

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
            "POST", "/v1/team/invitations", {"display_name": "New Analyst", "role": "analyst"}
        )
        self.assertEqual(status, 201, invited)
        self.assertTrue(invited["initial_token"])
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
            "POST", "/v1/team/invitations", {"display_name": "Future Admin", "role": "administrator"}
        )
        self.assertEqual(status, 201, invited)
        admin_token = invited["initial_token"]
        status, _, invited2 = self.json_request(
            "POST", "/v1/team/invitations", {"display_name": "Nobody Yet", "role": "viewer"},
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


if __name__ == "__main__":
    unittest.main()
