from __future__ import annotations

import io
import tempfile
import unittest
from importlib.metadata import version as distribution_version
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from webguard_api import __version__
from webguard_api.cli import build_parser, main


class ApiCliTests(unittest.TestCase):
    def test_version_matches_package_version(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                main(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(
            output.getvalue(),
            f"webguard-api {__version__}\n",
        )

    def test_distribution_metadata_matches_package_version(self) -> None:
        self.assertEqual(
            distribution_version("openhuntx-webguard-api"),
            __version__,
        )

    def test_parser_has_init_serve_and_worker(self) -> None:
        parser = build_parser()
        for command in ("init", "serve", "worker", "scheduler"):
            namespace = parser.parse_args([command])
            self.assertEqual(namespace.command, command)

    def test_worker_lease_options_are_available(self) -> None:
        namespace = build_parser().parse_args(
            [
                "worker",
                "--worker-id",
                "worker-a",
                "--worker-lease-seconds",
                "45",
                "--worker-heartbeat-seconds",
                "15",
                "--worker-maximum-attempts",
                "5",
            ]
        )
        self.assertEqual(namespace.worker_id, "worker-a")
        self.assertEqual(namespace.worker_lease_seconds, 45.0)
        self.assertEqual(namespace.worker_heartbeat_seconds, 15.0)
        self.assertEqual(namespace.worker_maximum_attempts, 5)

    def test_scheduler_options_are_available(self) -> None:
        namespace = build_parser().parse_args(
            [
                "scheduler",
                "--scheduler-poll-seconds",
                "2.5",
                "--scheduler-batch-size",
                "25",
            ]
        )
        self.assertEqual(namespace.scheduler_poll_seconds, 2.5)
        self.assertEqual(namespace.scheduler_batch_size, 25)

    def test_init_creates_private_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "var" / "jobs.sqlite3"
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "init",
                        "--database",
                        str(database),
                        "--authorizations",
                        str(root / "authorizations"),
                        "--artifacts",
                        str(root / "artifacts"),
                    ]
                )
            self.assertEqual(result, 0)
            self.assertTrue(database.is_file())
            self.assertIn("Initialized service database", output.getvalue())

    def test_init_honors_explicit_service_secret_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state" / "jobs.sqlite3"
            secret_file = root / "private" / "webguard-secrets.json"

            with redirect_stdout(io.StringIO()):
                result = main(
                    [
                        "init",
                        "--database",
                        str(database),
                        "--service-secrets",
                        str(secret_file),
                        "--authorizations",
                        str(root / "authorizations"),
                        "--artifacts",
                        str(root / "artifacts"),
                    ]
                )

            self.assertEqual(result, 0)
            self.assertTrue(database.is_file())
            self.assertTrue(secret_file.is_file())
            self.assertFalse(
                (database.parent / "service-secrets.json").exists()
            )

    def test_worker_once_reports_empty_queue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "worker",
                        "--once",
                        "--database",
                        str(root / "jobs.sqlite3"),
                        "--authorizations",
                        str(root / "authorizations"),
                        "--artifacts",
                        str(root / "artifacts"),
                    ]
                )
            self.assertEqual(result, 0)
            self.assertIn("No queued job", output.getvalue())

    def test_scheduler_once_reports_empty_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "scheduler",
                        "--once",
                        "--database",
                        str(root / "jobs.sqlite3"),
                        "--authorizations",
                        str(root / "authorizations"),
                        "--artifacts",
                        str(root / "artifacts"),
                    ]
                )
            self.assertEqual(result, 0)
            self.assertIn("inspected=0", output.getvalue())

    def test_public_host_returns_controlled_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            errors = io.StringIO()
            with redirect_stderr(errors):
                result = main(
                    [
                        "init",
                        "--host",
                        "0.0.0.0",
                        "--database",
                        str(root / "jobs.sqlite3"),
                        "--authorizations",
                        str(root / "authorizations"),
                        "--artifacts",
                        str(root / "artifacts"),
                    ]
                )
            self.assertEqual(result, 1)
            self.assertIn("loopback", errors.getvalue())

    def test_invalid_request_limit_returns_failure(self) -> None:
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = main(["init", "--maximum-request-bytes", "1"])
        self.assertEqual(result, 1)
        self.assertIn("maximum_request_bytes", errors.getvalue())


if __name__ == "__main__":
    unittest.main()


class ApiIdentityCliTests(unittest.TestCase):
    def test_parser_has_identity_commands(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.parse_args(["bootstrap", "--organization", "Org", "--principal", "Owner"]).command, "bootstrap")
        self.assertEqual(parser.parse_args(["organization", "create", "--name", "Org"]).organization_command, "create")
        self.assertEqual(parser.parse_args(["principal", "create", "--organization-id", "x", "--name", "N", "--role", "viewer"]).principal_command, "create")
        self.assertEqual(parser.parse_args(["token", "revoke", "--token-id", "x"]).token_command, "revoke")
        self.assertEqual(parser.parse_args(["authorization", "assign", "--organization-id", "x", "--principal-id", "y", "--authorization-id", "z"]).authorization_command, "assign")

    def test_bootstrap_prints_token_once(self) -> None:
        import re
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main([
                    "bootstrap",
                    "--organization", "Example Organisation",
                    "--principal", "Initial Owner",
                    "--database", str(root / "jobs.sqlite3"),
                    "--authorizations", str(root / "authorizations"),
                    "--artifacts", str(root / "artifacts"),
                ])
            self.assertEqual(result, 0)
            text = output.getvalue()
            self.assertRegex(text, r"API token: wgt_[0-9a-f-]+_")
            self.assertIn("will not be displayed again", text)

    def test_bootstrap_duplicate_organization_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = [
                "bootstrap", "--organization", "Example Organisation", "--principal", "Owner",
                "--database", str(root / "jobs.sqlite3"),
                "--authorizations", str(root / "authorizations"),
                "--artifacts", str(root / "artifacts"),
            ]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
            errors = io.StringIO()
            with redirect_stderr(errors):
                self.assertEqual(main(args), 1)
            self.assertIn("organization_conflict", errors.getvalue())
