from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCANNER_PATH = REPOSITORY_ROOT / "scripts" / "scan-secrets.py"

spec = importlib.util.spec_from_file_location(
    "webguard_phase5_secret_scanner",
    SCANNER_PATH,
)

if spec is None or spec.loader is None:
    raise RuntimeError("Unable to load secret scanner.")

scanner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = scanner
spec.loader.exec_module(scanner)


def secret_canary() -> str:
    return "wgt_" + "AbCdEf0123456789GhIjKlMnOpQrSt"


class Phase5SecretScannerTests(unittest.TestCase):
    def git(
        self,
        root: Path,
        *arguments: str,
    ) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()

    def initialize_repository(
        self,
        root: Path,
    ) -> None:
        self.git(root, "init", "-q")
        self.git(
            root,
            "config",
            "user.name",
            "OpenHuntX Phase5 Audit",
        )
        self.git(
            root,
            "config",
            "user.email",
            "phase5-audit@invalid.local",
        )

    def commit_all(
        self,
        root: Path,
        message: str,
    ) -> None:
        self.git(root, "add", "-A")
        self.git(root, "commit", "-q", "-m", message)

    def test_removed_secret_remains_detectable_in_git_history(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.initialize_repository(root)

            secret_file = root / "historical-secret.txt"
            secret_file.write_text(
                secret_canary(),
                encoding="utf-8",
            )
            self.commit_all(root, "add secret canary")

            secret_file.unlink()
            self.commit_all(root, "remove secret canary")

            self.assertFalse(secret_file.exists())

            findings, scanned = scanner.scan_git_history(root)

            self.assertGreater(scanned, 0)
            self.assertTrue(
                any(
                    identifier == "webguard-api-token"
                    for identifier, _oid in findings
                )
            )

    def test_shallow_repository_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            origin = temp / "origin"
            origin.mkdir()

            self.initialize_repository(origin)

            value = origin / "value.txt"
            value.write_text("one", encoding="utf-8")
            self.commit_all(origin, "first")

            value.write_text("two", encoding="utf-8")
            self.commit_all(origin, "second")

            shallow = temp / "shallow"

            subprocess.run(
                [
                    "git",
                    "clone",
                    "--quiet",
                    "--depth",
                    "1",
                    origin.as_uri(),
                    str(shallow),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(
                self.git(
                    shallow,
                    "rev-parse",
                    "--is-shallow-repository",
                ),
                "true",
            )

            with self.assertRaises(SystemExit) as captured:
                scanner.require_complete_git_history(
                    shallow
                )

            self.assertIn(
                "shallow",
                str(captured.exception).lower(),
            )

    def test_generated_artifact_secret_is_detected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            reports.mkdir()

            artifact = reports / "result.txt"
            artifact.write_text(
                secret_canary(),
                encoding="utf-8",
            )

            files = scanner.generated_artifact_files(root)

            self.assertEqual(files, [artifact])

            findings = scanner.scan_file(
                artifact,
                root=root,
            )

            self.assertTrue(
                any(
                    identifier == "webguard-api-token"
                    for identifier, _line in findings
                )
            )


if __name__ == "__main__":
    unittest.main()
