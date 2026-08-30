#!/usr/bin/env python3
"""Fail closed when reviewed CI/dependency pins drift."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED = {
    "pip": "26.2.1",
    "setuptools": "83.0.0",
    "cryptography": "50.0.0",
    "cffi": "2.1.0",
    "pycparser": "3.0",
    "ruff": "0.16.2",
    "psycopg": "3.2.10",
    "psycopg-binary": "3.2.10",
    "psycopg-pool": "3.2.6",
    "typing-extensions": "4.15.0",
    "argon2-cffi": "25.1.0",
    "argon2-cffi-bindings": "26.1.0",
}

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "ece7cb06caefa5fff74198d8649806c4678c61a1"
SETUP_NODE_SHA = "820762786026740c76f36085b0efc47a31fe5020"  # v7.0.0
UPLOAD_ARTIFACT_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"  # v7.0.1
SETUP_TERRAFORM_SHA = "dfe3c3f87815947d99a8997f908cb6525fc44e9e"  # v4.0.1
TRIVY_VERSION = "0.74.0"
TRIVY_LINUX_AMD64_SHA256 = (
    "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
)

EXPECTED_PYTHON_VERSIONS = ("3.11.15", "3.12.13", "3.13.14", "3.14.6")
EXPECTED_PYTHON_REQUIRES = ">=3.11,<3.15"
EXPECTED_RUNNER = "ubuntu-24.04"
JUICE_SHOP_INDEX_DIGEST = (
    "sha256:cd58d79c5cb4d82f22fbaf616f9ff43bbd04ba630cd6b448a9ed99cf652fcebf"
)
RUFF_WHEEL_HASHES = {
    "ab3d62dde0b19facdd632008cc4827fc28ada7736c6bd35ab6f1050f0bfed53f",
    "a2c0d14fcbb26c91f0f867a6dc9bd71bbc30b1b6151829c884f23faeab2e5700",
}


def fail(message: str) -> None:
    raise SystemExit(f"Supply-chain pin verification failed: {message}")


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def logical_requirements(path: str) -> list[str]:
    records: list[str] = []
    current = ""
    for raw in read(path).splitlines():
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
        fail(f"unterminated continuation in {path}")
    return records


def parse_locked(path: str) -> dict[str, tuple[str, tuple[str, ...]]]:
    parsed: dict[str, tuple[str, tuple[str, ...]]] = {}
    for record in logical_requirements(path):
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s]+)(?:\s+(.+))?$", record)
        if not match:
            fail(f"{path} contains a non-exact requirement: {record}")
        name, version, options = match.groups()
        hashes = tuple(re.findall(r"--hash=sha256:([0-9a-f]{64})", options or ""))
        if not hashes:
            fail(f"{path} requirement {name} has no SHA-256 hash")
        parsed[name.lower()] = (version, hashes)
    return parsed


bootstrap = parse_locked("requirements-bootstrap.lock")
if set(bootstrap) != {"pip"} or bootstrap["pip"][0] != EXPECTED["pip"]:
    fail("bootstrap lock does not contain only the reviewed pip version")

locked = parse_locked("requirements-ci.lock")
expected_runtime = {
    "setuptools",
    "cryptography",
    "cffi",
    "pycparser",
    "psycopg",
    "psycopg-binary",
    "psycopg-pool",
    "typing-extensions",
    "argon2-cffi",
    "argon2-cffi-bindings",
}
if set(locked) != expected_runtime:
    fail(f"runtime lock package set changed: {sorted(locked)}")
for name in expected_runtime:
    if locked[name][0] != EXPECTED[name]:
        fail(f"{name} lock version is {locked[name][0]}, expected {EXPECTED[name]}")

security_locked = parse_locked("requirements-security.lock")
if set(security_locked) != {"ruff"}:
    fail(f"security lock package set changed: {sorted(security_locked)}")
if security_locked["ruff"][0] != EXPECTED["ruff"]:
    fail(
        f"ruff lock version is {security_locked['ruff'][0]}, expected {EXPECTED['ruff']}"
    )
if set(security_locked["ruff"][1]) != RUFF_WHEEL_HASHES:
    fail("Ruff security-tool wheel hashes changed from the reviewed platform set")

for path in (
    "packages/contracts/python/pyproject.toml",
    "workers/scanner/pyproject.toml",
    "apps/api/pyproject.toml",
):
    with (ROOT / path).open("rb") as handle:
        document = tomllib.load(handle)
    requires = document["build-system"]["requires"]
    if requires != [f"setuptools=={EXPECTED['setuptools']}"]:
        fail(f"{path} build backend is not exactly pinned")
    if document["project"].get("requires-python") != EXPECTED_PYTHON_REQUIRES:
        fail(f"{path} Python support range is not {EXPECTED_PYTHON_REQUIRES}")

with (ROOT / "apps/api/pyproject.toml").open("rb") as handle:
    api = tomllib.load(handle)
if f"cryptography=={EXPECTED['cryptography']}" not in api["project"]["dependencies"]:
    fail("API cryptography dependency is not exactly pinned")
if f"psycopg[binary]=={EXPECTED['psycopg']}" not in api["project"]["dependencies"]:
    fail("API psycopg dependency is not exactly pinned")
if f"psycopg-pool=={EXPECTED['psycopg-pool']}" not in api["project"]["dependencies"]:
    fail("API psycopg-pool dependency is not exactly pinned")
if f"argon2-cffi=={EXPECTED['argon2-cffi']}" not in api["project"]["dependencies"]:
    fail("API argon2-cffi dependency is not exactly pinned")
if "version" in api["project"]:
    fail("API pyproject must not define a second static version authority")
if api["project"].get("dynamic") != ["version"]:
    fail("API pyproject must declare version as dynamic")
try:
    version_attr = api["tool"]["setuptools"]["dynamic"]["version"]["attr"]
except (KeyError, TypeError):
    fail("API setuptools dynamic version configuration is missing")
if version_attr != "webguard_api._version.__version__":
    fail("API package metadata does not use the canonical version module")
version_source = read("apps/api/src/webguard_api/_version.py")
version_matches = re.findall(r'^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', version_source, re.MULTILINE)
if len(version_matches) != 1:
    fail("canonical API version module must contain exactly one semantic version literal")
api_init = read("apps/api/src/webguard_api/__init__.py")
if "from ._version import __version__" not in api_init:
    fail("API package does not re-export the canonical version")
if re.search(r'^__version__\s*=\s*', api_init, re.MULTILINE):
    fail("API package __init__ contains a duplicate version authority")

dev_records = logical_requirements("requirements-dev.txt")
if not dev_records or any(not record.startswith("-e ") for record in dev_records):
    fail("requirements-dev.txt must contain repository-local editable packages only")

workflow = read(".github/workflows/ci.yml")
if f"actions/checkout@{CHECKOUT_SHA}" not in workflow:
    fail("actions/checkout is not pinned to the reviewed immutable SHA")
if f"actions/setup-python@{SETUP_PYTHON_SHA}" not in workflow:
    fail("actions/setup-python is not pinned to the reviewed immutable SHA")
if re.search(r"uses:\s+actions/(?:checkout|setup-python)@v", workflow):
    fail("a moving GitHub Action major-version tag remains in CI")
# Slice 18 added terraform, frontend, and frontend-e2e to the original
# four jobs (unit-tests, security-gates, authorised-lab-integration,
# postgresql-integration) -- a deliberately reviewed count, bumped as
# part of this change rather than left silently unenforced.
if workflow.count(f"runs-on: {EXPECTED_RUNNER}") != 7:
    fail("CI runner count or reviewed Ubuntu runner pin changed")
if "runs-on: ubuntu-latest" in workflow:
    fail("CI still uses the moving ubuntu-latest runner label")
for version in EXPECTED_PYTHON_VERSIONS:
    if f'python-version: "{version}"' not in workflow and f'- "{version}"' not in workflow:
        fail(f"CI does not pin reviewed Python {version}")
for floating in ("3.11", "3.12", "3.13", "3.14"):
    if re.search(rf'python-version:\s+"{re.escape(floating)}"', workflow):
        fail(f"CI still uses floating Python {floating}")
    if re.search(rf'^\s*-\s+"{re.escape(floating)}"\s*$', workflow, re.MULTILINE):
        fail(f"CI matrix still uses floating Python {floating}")
if f'pip-version: "{EXPECTED["pip"]}"' not in workflow:
    fail("CI does not request the reviewed pip version")
if "./scripts/install-locked-dependencies.sh" not in workflow:
    fail("CI bypasses the locked dependency installer")
if "pip install --upgrade" in workflow:
    fail("CI still performs an unconstrained packaging-tool upgrade")

uses_lines = [
    line.strip().split("uses:", 1)[1].strip()
    for line in workflow.splitlines()
    if line.strip().startswith("uses:")
]
reviewed_actions = {
    f"actions/checkout@{CHECKOUT_SHA}",
    f"actions/setup-python@{SETUP_PYTHON_SHA}",
    f"actions/setup-node@{SETUP_NODE_SHA}",
    f"actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}",
    f"hashicorp/setup-terraform@{SETUP_TERRAFORM_SHA}",
}
for action in uses_lines:
    action_ref = action.split("#", 1)[0].strip()
    if action_ref not in reviewed_actions:
        fail(f"CI uses an unreviewed GitHub Action: {action_ref}")

if "  terraform:" not in workflow:
    fail("CI terraform validation/IaC scan job is missing")
if f"trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz" not in workflow:
    fail("CI does not reference the reviewed Trivy release")
if TRIVY_LINUX_AMD64_SHA256 not in workflow:
    fail("CI does not pin the reviewed Trivy release checksum")

if "  security-gates:" not in workflow:
    fail("CI security-gates job is missing")
if "name: Security gates" not in workflow:
    fail("CI security-gates job has no stable display name")
if "requirements-security.lock" not in workflow:
    fail("CI security tooling lock is not part of the cache/install inputs")
if "./scripts/install-security-tools.sh" not in workflow:
    fail("CI does not install reviewed security tooling")
if "./scripts/run-security-gates.sh" not in workflow:
    fail("CI does not execute the security gates")
if "      - security-gates" not in workflow:
    fail("authorised integration is not gated on the security job")

security_installer = read("scripts/install-security-tools.sh")
if "--require-hashes" not in security_installer:
    fail("security-tool installer does not require reviewed hashes")
if "--only-binary=:all:" not in security_installer:
    fail("security-tool installer permits an unreviewed source build")
if "ruff 0.16.2" not in security_installer:
    fail("security-tool installer does not verify the reviewed Ruff version")

security_runner = read("scripts/run-security-gates.sh")
for required in (
    "python scripts/scan-secrets.py",
    "--select S",
    "--ignore S101",
    "python scripts/audit-dependencies.py",
):
    if required not in security_runner:
        fail(f"security-gate runner is missing reviewed control: {required}")

compose = read("infra/compose/compose.lab.yml")
expected_image = f"bkimminich/juice-shop:v20.1.1@{JUICE_SHOP_INDEX_DIGEST}"
if expected_image not in compose:
    fail("Juice Shop is not pinned to the reviewed multi-platform index digest")

print("Supply-chain pins verified.")
