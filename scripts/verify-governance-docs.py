#!/usr/bin/env python3
"""Fail closed on Checkpoint 1 security-governance regressions."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DOCUMENTS = {
    "SECURITY.md": ("# OpenHuntX WebGuard Security Policy", "## Reporting a vulnerability"),
    "docs/ARCHITECTURE.md": ("# OpenHuntX WebGuard Architecture", "## 6. Trust boundaries"),
    "docs/AUTHORIZATION_MODEL.md": ("# OpenHuntX WebGuard Authorisation Model", "## 15. Request-boundary enforcement"),
    "docs/DATA_CLASSIFICATION.md": ("# OpenHuntX WebGuard Data Classification and Handling", "### Restricted"),
    "docs/THREAT_MODEL.md": ("# OpenHuntX WebGuard Threat Model", "## 6. Threats and controls"),
    "docs/ROADMAP.md": ("# OpenHuntX WebGuard Roadmap", "## Implemented foundation — through Milestone 1.32"),
    "THIRD_PARTY_NOTICES.md": ("# OpenHuntX WebGuard Third-Party Notices", "cryptography"),
    ".env.example": ("WEBGUARD_RUN_INTEGRATION=0", "WEBGUARD_LAB_TARGET=http://127.0.0.1:3000/"),
}

MINIMUM_DOCUMENT_BYTES = {
    "SECURITY.md": 1500,
    "docs/ARCHITECTURE.md": 5000,
    "docs/AUTHORIZATION_MODEL.md": 4000,
    "docs/DATA_CLASSIFICATION.md": 3000,
    "docs/THREAT_MODEL.md": 6000,
    "docs/ROADMAP.md": 2500,
    "THIRD_PARTY_NOTICES.md": 1500,
    ".env.example": 250,
}

FORBIDDEN_README_MARKERS = (
    "At Milestone 1.31, the repository contains:",
    "887 unit tests",
    "`apps/web` — future customer dashboard",
    "`infra/zap` — future controlled ZAP automation plans",
)

SECRET_PATTERNS = (
    re.compile(r"wgt_[A-Za-z0-9_-]{16,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
)


def fail(message: str) -> None:
    raise SystemExit(f"Governance verification failed: {message}")


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        fail(f"required file is missing: {relative}")
    raw = path.read_bytes()
    if len(raw) < MINIMUM_DOCUMENT_BYTES[relative]:
        fail(f"required file is unexpectedly small: {relative}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"required file is not valid UTF-8: {relative}")


def verify_required_documents() -> None:
    for relative, markers in REQUIRED_DOCUMENTS.items():
        text = read(relative)
        if not text.strip():
            fail(f"required file is empty: {relative}")
        for marker in markers:
            if marker not in text:
                fail(f"required marker {marker!r} is missing from {relative}")


def verify_readme() -> None:
    readme_path = ROOT / "README.md"
    if not readme_path.is_file():
        fail("README.md is missing")
    text = readme_path.read_text(encoding="utf-8")
    for marker in FORBIDDEN_README_MARKERS:
        if marker in text:
            fail(f"README contains stale marker: {marker!r}")
    required = (
        "Milestone 1.32",
        "Current test totals are emitted by `./scripts/verify.sh` and CI.",
        "Python 3.11.15, 3.12.13, 3.13.14, and 3.14.6",
        "docs/ARCHITECTURE.md",
        "docs/THREAT_MODEL.md",
    )
    for marker in required:
        if marker not in text:
            fail(f"README is missing current marker: {marker!r}")


def verify_repository_paths() -> None:
    expected = (
        "apps/api",
        "workers/scanner",
        "packages/contracts",
        "infra/compose",
        "docs",
        "scripts",
        "tests/unit",
        "tests/integration",
    )
    for relative in expected:
        if not (ROOT / relative).exists():
            fail(f"documented repository path does not exist: {relative}")


def verify_env_example() -> None:
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    if re.search(r"^\s*WEBGUARD_API_TOKEN\s*=", text, flags=re.MULTILINE):
        fail(".env.example must not define WEBGUARD_API_TOKEN")
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            fail(".env.example contains secret-like material")


def verify_security_language() -> None:
    combined = "\n".join(
        (ROOT / relative).read_text(encoding="utf-8")
        for relative in (
            "SECURITY.md",
            "docs/AUTHORIZATION_MODEL.md",
            "docs/THREAT_MODEL.md",
            "docs/ROADMAP.md",
        )
    ).lower()
    prohibited_absolute_claims = (
        "webguard is guaranteed safe",
        "webguard is guaranteed secure",
        "webguard proves the target is secure",
        "webguard has zero false positives",
    )
    for phrase in prohibited_absolute_claims:
        if phrase in combined:
            fail(f"governance docs contain prohibited absolute claim: {phrase!r}")


def main() -> int:
    verify_required_documents()
    verify_readme()
    verify_repository_paths()
    verify_env_example()
    verify_security_language()
    print("Security-governance documents verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
