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


def scan_file(path: Path) -> list[tuple[str, int]]:
    relative = path.relative_to(ROOT).as_posix()
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


def main() -> int:
    self_test()
    findings: list[tuple[str, str, int]] = []
    scanned = 0
    for path in repository_files():
        scanned += 1
        relative = path.relative_to(ROOT).as_posix()
        for identifier, line in scan_file(path):
            findings.append((identifier, relative, line))

    if findings:
        for identifier, relative, line in findings:
            print(f"{relative}:{line}: probable secret ({identifier})", file=sys.stderr)
        print(
            "Secret scan failed. Do not commit the credential; rotate/revoke it if real.",
            file=sys.stderr,
        )
        return 1

    print(f"Secret scan passed ({scanned} repository files checked).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
