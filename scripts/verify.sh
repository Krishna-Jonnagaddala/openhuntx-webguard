#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

cd "$REPOSITORY_ROOT"

echo "Verifying supply-chain pins..."
python scripts/verify-supply-chain-pins.py

echo "Compiling Python sources..."
python -m compileall \
  -q \
  packages/contracts/python/src \
  workers/scanner/src \
  apps/api/src \
  scripts \
  tests

echo "Running unit tests..."
python -m unittest discover \
  -s tests/unit \
  -p 'test_*.py' \
  -v

echo "Confirming integration tests remain opt-in..."
python -m unittest discover \
  -s tests/integration \
  -p 'test_*.py' \
  -v

echo "WebGuard verification gate passed."
