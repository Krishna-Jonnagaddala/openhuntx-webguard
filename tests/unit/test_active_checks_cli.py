"""CLI-level tests for `webguard-api permit issue --active-check`.

Exercises the real argparse entry point (main()), not the service layer
directly, so these prove the operator-facing command actually works --
complementing test_active_checks_permit_control.py's service-layer RBAC/
validation coverage rather than duplicating it.
"""

from __future__ import annotations

import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webguard_contracts import (
    OwnedTargetAuthorization,
    OwnedTargetLimits,
    write_owned_target_authorization_file,
)
from webguard_api.cli import main
from webguard_api.service import WebGuardJobService
from webguard_api import AuthorizationRepository, IdentityStore, ScanJobStore
from webguard_api.auth import ApiTokenAuthenticator

TARGET = "https://example.com/"


def _write_wide_window_authorization(directory: Path) -> str:
    """A real-clock-relative authorization, unlike service_test_support's
    fixed-date one, so CLI tests (which use the real clock, not an
    injectable one) never hit a landmine expiry."""

    now = datetime.now(timezone.utc)
    authorization_id = "d3b07384-d113-4ec1-8a2a-2b3c4d5e6f70"
    value = OwnedTargetAuthorization(
        authorization_id=authorization_id,
        organization="CLI Test Org",
        authorized_by="CLI Test Operator",
        target=TARGET,
        allowed_hosts=("example.com",),
        issued_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=365),
        purpose="CLI active-checks control-surface testing",
        limits=OwnedTargetLimits(),
    )
    directory.mkdir(parents=True, exist_ok=True)
    write_owned_target_authorization_file(value, directory / "example.com.json")
    return authorization_id


def _extract(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    assert match is not None, f"pattern {pattern!r} not found in: {text}"
    return match.group(1)


class ActiveChecksCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "jobs.sqlite3"
        self.auth_dir = self.root / "authorizations"
        self.artifacts = self.root / "artifacts"
        self.authorization_id = _write_wide_window_authorization(self.auth_dir)

        output = io.StringIO()
        with redirect_stdout(output):
            result = main(
                [
                    "bootstrap",
                    "--organization",
                    "CLI Test Org",
                    "--principal",
                    "Owner",
                    "--database",
                    str(self.database),
                    "--authorizations",
                    str(self.auth_dir),
                    "--artifacts",
                    str(self.artifacts),
                ]
            )
        assert result == 0
        text = output.getvalue()
        self.organization_id = _extract(r"Organization ID: (\S+)", text)
        self.owner_principal_id = _extract(r"Owner principal ID: (\S+)", text)
        self.owner_token = _extract(r"API token: (\S+)", text)

        output = io.StringIO()
        with redirect_stdout(output):
            result = main(
                [
                    "authorization",
                    "assign",
                    "--organization-id",
                    self.organization_id,
                    "--principal-id",
                    self.owner_principal_id,
                    "--authorization-id",
                    self.authorization_id,
                    "--database",
                    str(self.database),
                    "--authorizations",
                    str(self.auth_dir),
                    "--artifacts",
                    str(self.artifacts),
                ]
            )
        assert result == 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _base_permit_args(self, token: str) -> list[str]:
        return [
            "permit",
            "issue",
            "--token",
            token,
            "--target",
            TARGET,
            "--authorization-id",
            self.authorization_id,
            "--mode",
            "single_page",
            "--database",
            str(self.database),
            "--authorizations",
            str(self.auth_dir),
            "--artifacts",
            str(self.artifacts),
        ]

    def _create_administrator_token(self) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(
                [
                    "principal",
                    "create",
                    "--organization-id",
                    self.organization_id,
                    "--name",
                    "Administrator",
                    "--role",
                    "administrator",
                    "--database",
                    str(self.database),
                    "--authorizations",
                    str(self.auth_dir),
                    "--artifacts",
                    str(self.artifacts),
                ]
            )
        assert result == 0
        principal_id = _extract(
            r"Principal ID: (\S+)", output.getvalue()
        )

        output = io.StringIO()
        with redirect_stdout(output):
            result = main(
                [
                    "token",
                    "create",
                    "--principal-id",
                    principal_id,
                    "--label",
                    "administrator-test",
                    "--database",
                    str(self.database),
                    "--authorizations",
                    str(self.auth_dir),
                    "--artifacts",
                    str(self.artifacts),
                ]
            )
        assert result == 0
        return _extract(r"API token: (\S+)", output.getvalue())

    # -- 1: omitting --active-check means passive-only ------------------

    def test_omitting_active_check_flag_issues_passive_only_permit(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(self._base_permit_args(self.owner_token))
        self.assertEqual(result, 0)
        self.assertIn("Active checks authorized: none (passive-only)", output.getvalue())

    # -- 3: owner may request the registered XSS detector ---------------

    def test_owner_can_request_registered_active_check(self) -> None:
        args = self._base_permit_args(self.owner_token) + [
            "--active-check",
            "active.xss.reflected",
        ]
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(args)
        self.assertEqual(result, 0)
        self.assertIn(
            "Active checks authorized: active.xss.reflected",
            output.getvalue(),
        )

    # -- 4: unknown detector id fails closed -----------------------------

    def test_unknown_active_check_fails_closed(self) -> None:
        args = self._base_permit_args(self.owner_token) + [
            "--active-check",
            "active.sqli.error",
        ]
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = main(args)
        self.assertEqual(result, 1)
        self.assertIn("trustscan_permit_active_checks_unknown", errors.getvalue())

    # -- 5: duplicate detector ids are rejected --------------------------

    def test_duplicate_active_check_flags_are_rejected(self) -> None:
        args = self._base_permit_args(self.owner_token) + [
            "--active-check",
            "active.xss.reflected",
            "--active-check",
            "active.xss.reflected",
        ]
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = main(args)
        self.assertEqual(result, 2)
        self.assertIn("active_checks_duplicate", errors.getvalue())

    # -- 6: unauthorized role cannot issue active-capability permits ----

    def test_administrator_token_cannot_request_active_check(self) -> None:
        admin_token = self._create_administrator_token()
        args = self._base_permit_args(admin_token) + [
            "--active-check",
            "active.xss.reflected",
        ]
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = main(args)
        self.assertEqual(result, 1)
        self.assertIn("permission_denied", errors.getvalue())

    def test_administrator_token_can_still_issue_passive_permit(self) -> None:
        admin_token = self._create_administrator_token()
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(self._base_permit_args(admin_token))
        self.assertEqual(result, 0)
        self.assertIn("passive-only", output.getvalue())

    # -- 10: CLI and API/service produce the same canonical claims ------

    def test_cli_and_service_produce_identical_canonical_claims(self) -> None:
        cli_args = self._base_permit_args(self.owner_token) + [
            "--active-check",
            "active.xss.reflected",
            "--valid-days",
            "7",
            "--maximum-request-attempts",
            "15",
            "--maximum-requests-per-second",
            "1.0",
        ]
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(cli_args)
        self.assertEqual(result, 0)
        cli_permit_id = _extract(r"Permit ID: (\S+)", output.getvalue())

        store = ScanJobStore(self.database)
        identity = IdentityStore(self.database)
        cli_record = store.get_scan_permit(cli_permit_id)
        cli_claims = json.loads(cli_record.permit.to_json())["claims"]

        authenticator = ApiTokenAuthenticator(identity)
        now = datetime.now(timezone.utc)
        context = authenticator.authenticate(
            [f"Bearer {self.owner_token}"], now=now
        )
        service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(self.auth_dir),
            identity=identity,
        )
        submission_body = json.dumps(
            {
                "target": TARGET,
                "authorization_id": self.authorization_id,
                "confirm_authorization": self.authorization_id,
                "permitted_modes": ["single_page"],
                "allowed_http_methods": ["GET", "HEAD"],
                "not_before": (now + timedelta(seconds=2))
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z"),
                "expires_at": (now + timedelta(days=7))
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z"),
                "maximum_request_attempts": 15,
                "maximum_requests_per_second": 1.0,
                "maximum_concurrency": 1,
                "active_checks": ["active.xss.reflected"],
            }
        ).encode("utf-8")
        service_result = service.issue_permit(
            context,
            submission_body,
            request_id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        )
        service_claims = service_result["permit"]["claims"]

        # permit_id/issued_by/timestamps legitimately differ per issuance;
        # everything that describes *what was authorized* must match.
        for field in (
            "organization_id",
            "authorization_id",
            "target",
            "permitted_modes",
            "allowed_http_methods",
            "maximum_request_attempts",
            "maximum_requests_per_second",
            "maximum_concurrency",
            "prohibited_operations",
            "active_checks",
        ):
            self.assertEqual(
                cli_claims[field],
                service_claims[field],
                f"field {field!r} diverged between CLI and service issuance",
            )


if __name__ == "__main__":
    unittest.main()
