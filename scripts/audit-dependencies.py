#!/usr/bin/env python3
"""Audit exact locked Python packages against current PyPI vulnerability data."""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK_FILES = (
    "requirements-bootstrap.lock",
    "requirements-ci.lock",
    "requirements-security.lock",
)
TIMEOUT_SECONDS = 20
USER_AGENT = "OpenHuntX-WebGuard-Dependency-Audit/1"


def fail(message: str) -> None:
    raise SystemExit(f"Dependency audit failed: {message}")


def logical_requirements(path: Path) -> list[str]:
    records: list[str] = []
    current = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        continuation = line.endswith("\\")
        if continuation:
            line = line[:-1].rstrip()
        current = f"{current} {line}".strip()
        if not continuation:
            records.append(current)
            current = ""
    if current:
        fail(f"unterminated continuation in {path.name}")
    return records


def locked_packages() -> list[tuple[str, str]]:
    packages: dict[str, tuple[str, str]] = {}
    for filename in LOCK_FILES:
        path = ROOT / filename
        if not path.is_file():
            fail(f"missing lock file: {filename}")
        for record in logical_requirements(path):
            match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s]+)(?:\s+.+)?$", record)
            if not match:
                fail(f"non-exact requirement in {filename}: {record}")
            name, version = match.groups()
            canonical = re.sub(r"[-_.]+", "-", name).lower()
            existing = packages.get(canonical)
            if existing is not None and existing != (name, version):
                fail(f"conflicting locked versions for {name}")
            packages[canonical] = (name, version)
    return [packages[key] for key in sorted(packages)]


def pypi_document(name: str, version: str) -> dict[str, object]:
    quoted_name = urllib.parse.quote(name, safe="")
    quoted_version = urllib.parse.quote(version, safe="")
    url = f"https://pypi.org/pypi/{quoted_name}/{quoted_version}/json"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            if response.status != 200:
                fail(f"PyPI returned HTTP {response.status} for {name}=={version}")
            payload = response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        fail(f"unable to query PyPI for {name}=={version}: {exc}")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"invalid PyPI response for {name}=={version}: {exc}")
    if not isinstance(document, dict):
        fail(f"unexpected PyPI response type for {name}=={version}")
    return document


def main() -> int:
    active_findings: list[tuple[str, str, str]] = []
    audited = 0

    for name, version in locked_packages():
        document = pypi_document(name, version)
        info = document.get("info")
        if not isinstance(info, dict) or str(info.get("version")) != version:
            fail(f"PyPI metadata version mismatch for {name}=={version}")
        vulnerabilities = document.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            fail(f"PyPI response has no vulnerability list for {name}=={version}")

        audited += 1
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                fail(f"malformed vulnerability entry for {name}=={version}")
            if vulnerability.get("withdrawn"):
                continue
            identifier = str(vulnerability.get("id") or "unknown-advisory")
            details = str(vulnerability.get("details") or "").strip().replace("\n", " ")
            if len(details) > 160:
                details = details[:157] + "..."
            active_findings.append((f"{name}=={version}", identifier, details))

    if active_findings:
        for package, identifier, details in active_findings:
            suffix = f": {details}" if details else ""
            print(f"{package}: active vulnerability {identifier}{suffix}", file=sys.stderr)
        return 1

    print(f"Dependency audit passed ({audited} exact locked packages checked).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
