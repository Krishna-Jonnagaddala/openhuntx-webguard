from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from webguard_api.cli import build_parser, main


class ApiCliTests(unittest.TestCase):
    def test_parser_has_init_serve_and_worker(self) -> None:
        parser = build_parser()
        for command in ("init", "serve", "worker"):
            namespace = parser.parse_args([command])
            self.assertEqual(namespace.command, command)

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
            self.assertIn("Initialized job database", output.getvalue())

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
