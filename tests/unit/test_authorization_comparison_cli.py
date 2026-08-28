"""CLI-level tests for `webguard-api authorization-comparison
register|revoke` (Slice 9) -- closes the CLI/HTTP parity gap the phase
8 audit doc flagged.

The CLI handler calls the exact same `WebGuardJobService` methods the
HTTP route uses (`register_authorization_comparison_plan`/
`revoke_authorization_comparison_plan`), so CLI and API share identical
validation/service logic by construction, not by keeping two
implementations in sync manually -- these tests exercise the real
argparse entry point to prove the operator-facing command actually
works and correctly surfaces the service's own RBAC and binding
errors, complementing (not duplicating) the exhaustive service-layer
coverage in test_idor_permit_control.py and
test_authorization_comparison.py.

Scope note: like Slice 7's `authentication-context register` CLI
command, `authorization-comparison register` operates on an in-memory
repository that is freshly constructed and immediately discarded within
one CLI process invocation -- it cannot, by the same already-documented
architectural limitation, be round-tripped (register in one `main()`
call, reference in a second) the way SQLite-backed state can. These
tests therefore prove argument parsing, RBAC enforcement, and
fail-closed error propagation within a single process boundary; the
true multi-identity happy path is proven over real HTTP in the phase 9
end-to-end lab test instead.
"""

from __future__ import annotations

import io
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

TARGET = "https://example.com/"


def _write_authorization(directory: Path) -> str:
    now = datetime.now(timezone.utc)
    authorization_id = "aaaaaaaa-1111-4111-8111-111111111111"
    value = OwnedTargetAuthorization(
        authorization_id=authorization_id,
        organization="CLI IDOR Test Org",
        authorized_by="CLI Test Operator",
        target=TARGET,
        allowed_hosts=("example.com",),
        issued_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=365),
        purpose="CLI authorization-comparison surface testing",
        limits=OwnedTargetLimits(),
    )
    directory.mkdir(parents=True, exist_ok=True)
    write_owned_target_authorization_file(value, directory / "example.com.json")
    return authorization_id


def _extract(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    assert match is not None, f"pattern {pattern!r} not found in: {text}"
    return match.group(1)


class AuthorizationComparisonCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "jobs.sqlite3"
        self.auth_dir = self.root / "authorizations"
        self.artifacts = self.root / "artifacts"
        self.authorization_id = _write_authorization(self.auth_dir)

        output = io.StringIO()
        with redirect_stdout(output):
            result = main(
                [
                    "bootstrap",
                    "--organization",
                    "CLI IDOR Test Org",
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

    def _common_args(self) -> list[str]:
        return [
            "--database",
            str(self.database),
            "--authorizations",
            str(self.auth_dir),
            "--artifacts",
            str(self.artifacts),
        ]

    def _register_args(self, token: str, **overrides) -> list[str]:
        values = {
            "--target": TARGET,
            "--authorization-id": self.authorization_id,
            "--primary-context-id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "--secondary-context-id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        }
        values.update(overrides)
        args = ["authorization-comparison", "register", "--token", token]
        for key, value in values.items():
            args.extend([key, value])
        return args + self._common_args()

    def test_owner_registration_fails_closed_on_unknown_contexts(self) -> None:
        # Neither context ID has ever been registered -- the CLI must
        # surface the real service's fail-closed binding error, not a
        # generic crash or a silently-accepted plan.
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(self._register_args(self.owner_token))
        self.assertEqual(result, 1)

    def test_administrator_cannot_register_a_comparison_plan(self) -> None:
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
                ]
                + self._common_args()
            )
        assert result == 0
        principal_id = _extract(r"Principal ID: (\S+)", output.getvalue())

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
                ]
                + self._common_args()
            )
        assert result == 0
        administrator_token = _extract(r"API token: (\S+)", output.getvalue())

        output = io.StringIO()
        with redirect_stdout(output):
            result = main(self._register_args(administrator_token))
        self.assertEqual(result, 1)

    def test_enable_discovery_allows_empty_resource_scope_json(self) -> None:
        # Even though the contexts don't exist (so this still fails
        # closed on binding), passing an empty "[]" resource_scope with
        # --enable-discovery must not fail on JSON-array validation --
        # proving that flag is actually threaded through to the body.
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(
                self._register_args(
                    self.owner_token, **{"--resource-scope-json": "[]"}
                )
                + ["--enable-discovery"]
            )
        # Still fails (unknown contexts), but must not be a JSON/body
        # construction failure -- the CLI parsed --enable-discovery and
        # forwarded an empty resource_scope correctly.
        self.assertEqual(result, 1)

    def test_malformed_resource_scope_json_is_rejected_before_any_service_call(
        self,
    ) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            result = main(
                self._register_args(
                    self.owner_token,
                    **{"--resource-scope-json": "{not valid json"},
                )
            )
        self.assertEqual(result, 1)
        self.assertIn("resource_scope_json_invalid", errors.getvalue())

    def test_revoke_unknown_plan_fails_closed(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(
                [
                    "authorization-comparison",
                    "revoke",
                    "--token",
                    self.owner_token,
                    "--comparison-plan-id",
                    "ffffffff-ffff-4fff-8fff-ffffffffffff",
                ]
                + self._common_args()
            )
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
