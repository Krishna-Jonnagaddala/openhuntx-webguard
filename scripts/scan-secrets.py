#!/usr/bin/env python3
"""Fail closed when probable credentials are present in repository source data."""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_TEXT_FILE_BYTES = 5 * 1024 * 1024

GENERATED_ARTIFACT_DIRECTORIES = (
    "scan-results",
    "reports",
    "artifacts",
)


@dataclass(frozen=True)
class Rule:
    identifier: str
    pattern: re.Pattern[bytes]


RULES = (
    Rule(
        "private-key",
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    Rule("webguard-api-token", re.compile(rb"\bwgt_[A-Za-z0-9_-]{16,}\b")),
    Rule(
        "github-token",
        re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    Rule("aws-access-key", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    Rule(
        "slack-token",
        re.compile(rb"\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{20,}\b"),
    ),
    Rule("google-api-key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    Rule(
        "openai-api-key",
        re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    Rule(
        "stripe-live-secret",
        re.compile(rb"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b"),
    ),
)


def fail(message: str) -> None:
    raise SystemExit(f"Secret scan failed: {message}")


def repository_files() -> list[Path]:
    try:
        result = subprocess.run(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"unable to enumerate repository files: {exc}")

    paths: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError:
            fail("git returned a non-UTF-8 repository path")
        candidate = ROOT / relative
        if candidate.is_symlink():
            fail(f"refusing to scan symlinked repository file: {relative}")
        if not candidate.is_file():
            fail(f"enumerated repository path is not a regular file: {relative}")
        paths.append(candidate)
    return sorted(paths)



def _git(
    root: Path,
    *arguments: str,
    input_data: bytes | None = None,
) -> bytes:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            input=input_data,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(
            "unable to inspect Git repository history: "
            f"{exc}"
        )

    return result.stdout


def require_complete_git_history(
    root: Path = ROOT,
) -> None:
    state = _git(
        root,
        "rev-parse",
        "--is-shallow-repository",
    ).strip()

    if state != b"false":
        fail(
            "repository history is shallow; fetch complete "
            "history before running the secret scan"
        )


def git_history_blobs(
    root: Path = ROOT,
) -> list[tuple[str, int]]:
    require_complete_git_history(root)

    objects = _git(
        root,
        "rev-list",
        "--objects",
        "--all",
    )

    object_ids: list[str] = []
    seen: set[str] = set()

    for line in objects.splitlines():
        raw_oid = line.split(b" ", 1)[0]

        try:
            oid = raw_oid.decode("ascii")
        except UnicodeDecodeError:
            fail("Git returned a non-ASCII object identifier")

        if oid and oid not in seen:
            seen.add(oid)
            object_ids.append(oid)

    if not object_ids:
        return []

    request = "".join(
        f"{oid}\n"
        for oid in object_ids
    ).encode("ascii")

    metadata = _git(
        root,
        "cat-file",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        input_data=request,
    )

    blobs: list[tuple[str, int]] = []

    for raw_line in metadata.splitlines():
        try:
            line = raw_line.decode("ascii")
            oid, object_type, size_text = line.split(
                " ",
                2,
            )
            size = int(size_text)
        except (UnicodeDecodeError, ValueError) as exc:
            fail(
                "Git returned invalid object metadata: "
                f"{exc}"
            )

        if object_type == "blob":
            blobs.append((oid, size))

    return blobs


def scan_git_history(
    root: Path = ROOT,
) -> tuple[list[tuple[str, str]], int]:
    findings: list[tuple[str, str]] = []
    scanned = 0

    for oid, size in git_history_blobs(root):
        if size > MAX_TEXT_FILE_BYTES:
            fail(
                "reachable Git blob exceeds secret-scan "
                f"size limit: {oid[:12]} ({size} bytes)"
            )

        data = _git(
            root,
            "cat-file",
            "blob",
            oid,
        )

        if b"\0" in data:
            continue

        scanned += 1

        for rule in RULES:
            if rule.pattern.search(data) is not None:
                findings.append(
                    (
                        rule.identifier,
                        oid,
                    )
                )

    return findings, scanned


def self_test() -> None:
    synthetic = {
        "private-key": b"-----BEGIN " + b"PRIVATE KEY-----",
        "webguard-api-token": b"wgt_" + b"AbCdEf0123456789GhIjKlMn",
        "github-token": b"ghp_" + b"aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "aws-access-key": b"AKIA" + b"ABCDEFGHIJKLMNOP",
        "slack-token": b"xoxb-" + b"123456789012-abcdefghijklmnopqrstuvwxyz",
        "google-api-key": b"AIza" + b"AbCdEfGhIjKlMnOpQrStUvWxYz012345678",
        "openai-api-key": b"sk-" + b"AbCdEfGhIjKlMnOpQrStUvWxYz012345",
        "stripe-live-secret": b"sk_live_" + b"AbCdEfGhIjKlMnOpQrStUvWx",
    }
    by_id = {rule.identifier: rule for rule in RULES}
    if set(by_id) != set(synthetic):
        fail("secret scanner self-test inventory is inconsistent")
    for identifier, sample in synthetic.items():
        if by_id[identifier].pattern.search(sample) is None:
            fail(f"self-test failed for rule {identifier}")


def scan_file(
    path: Path,
    *,
    root: Path = ROOT,
) -> list[tuple[str, int]]:
    relative = path.relative_to(root).as_posix()
    size = path.stat().st_size
    if size > MAX_TEXT_FILE_BYTES:
        fail(f"tracked/unignored file exceeds scan size limit: {relative} ({size} bytes)")

    data = path.read_bytes()
    if b"\0" in data:
        return []

    findings: list[tuple[str, int]] = []
    for rule in RULES:
        for match in rule.pattern.finditer(data):
            line = data.count(b"\n", 0, match.start()) + 1
            findings.append((rule.identifier, line))
    return findings


def generated_artifact_files(
    root: Path = ROOT,
) -> list[Path]:
    paths: list[Path] = []

    for directory in GENERATED_ARTIFACT_DIRECTORIES:
        base = root / directory

        if base.is_symlink():
            fail(
                "refusing to scan symlinked generated-artifact "
                f"directory: {directory}"
            )

        if not base.exists():
            continue

        if not base.is_dir():
            fail(
                "generated-artifact path is not a directory: "
                f"{directory}"
            )

        for candidate in sorted(base.rglob("*")):
            relative = candidate.relative_to(root).as_posix()

            if candidate.is_symlink():
                fail(
                    "refusing to scan symlinked generated "
                    f"artifact: {relative}"
                )

            if candidate.is_dir():
                continue

            if not candidate.is_file():
                fail(
                    "generated-artifact path is not a regular "
                    f"file: {relative}"
                )

            paths.append(candidate)

    return paths


def main() -> int:
    self_test()

    findings: list[tuple[str, str, int]] = []
    repository_scanned = 0
    generated_scanned = 0

    repository_paths = repository_files()
    repository_path_set = set(repository_paths)

    for path in repository_paths:
        repository_scanned += 1
        relative = path.relative_to(ROOT).as_posix()

        for identifier, line in scan_file(path):
            findings.append(
                (
                    identifier,
                    relative,
                    line,
                )
            )

    for path in generated_artifact_files():
        if path in repository_path_set:
            continue

        generated_scanned += 1
        relative = path.relative_to(ROOT).as_posix()

        for identifier, line in scan_file(path):
            findings.append(
                (
                    identifier,
                    relative,
                    line,
                )
            )

    history_findings, history_scanned = scan_git_history()

    if findings or history_findings:
        for identifier, relative, line in findings:
            print(
                f"{relative}:{line}: "
                f"probable secret ({identifier})",
                file=sys.stderr,
            )

        for identifier, oid in history_findings:
            print(
                "git-history:"
                f"{oid[:12]}: probable secret "
                f"({identifier})",
                file=sys.stderr,
            )

        print(
            "Secret scan failed. Do not commit the "
            "credential; rotate/revoke it if real.",
            file=sys.stderr,
        )
        return 1

    print(
        "Secret scan passed "
        f"({repository_scanned} repository files, "
        f"{generated_scanned} generated artifact files and "
        f"{history_scanned} reachable Git blobs checked)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
