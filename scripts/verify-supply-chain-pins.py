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
    "cryptography": "46.0.7",
    "cffi": "2.1.0",
    "pycparser": "3.0",
}

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "ece7cb06caefa5fff74198d8649806c4678c61a1"

EXPECTED_PYTHON_VERSIONS = ("3.11.15", "3.13.14", "3.14.6")
EXPECTED_RUNNER = "ubuntu-24.04"
JUICE_SHOP_INDEX_DIGEST = (
    "sha256:cd58d79c5cb4d82f22fbaf616f9ff43bbd04ba630cd6b448a9ed99cf652fcebf"
)


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
expected_runtime = {"setuptools", "cryptography", "cffi", "pycparser"}
if set(locked) != expected_runtime:
    fail(f"runtime lock package set changed: {sorted(locked)}")
for name in expected_runtime:
    if locked[name][0] != EXPECTED[name]:
        fail(f"{name} lock version is {locked[name][0]}, expected {EXPECTED[name]}")

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

with (ROOT / "apps/api/pyproject.toml").open("rb") as handle:
    api = tomllib.load(handle)
if f"cryptography=={EXPECTED['cryptography']}" not in api["project"]["dependencies"]:
    fail("API cryptography dependency is not exactly pinned")

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
if workflow.count(f"runs-on: {EXPECTED_RUNNER}") != 2:
    fail("CI runner is not pinned to the reviewed Ubuntu major release")
if "runs-on: ubuntu-latest" in workflow:
    fail("CI still uses the moving ubuntu-latest runner label")
for version in EXPECTED_PYTHON_VERSIONS:
    if f'python-version: "{version}"' not in workflow and f'- "{version}"' not in workflow:
        fail(f"CI does not pin reviewed Python {version}")
for floating in ("3.11", "3.13", "3.14"):
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

compose = read("infra/compose/compose.lab.yml")
expected_image = f"bkimminich/juice-shop:v20.1.1@{JUICE_SHOP_INDEX_DIGEST}"
if expected_image not in compose:
    fail("Juice Shop is not pinned to the reviewed multi-platform index digest")

print("Supply-chain pins verified.")
