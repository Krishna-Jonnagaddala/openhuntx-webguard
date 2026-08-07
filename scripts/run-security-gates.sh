#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

RUFF="$REPOSITORY_ROOT/var/security-tools/venv/bin/ruff"

cd "$REPOSITORY_ROOT"

if [[ ! -x "$RUFF" ]]; then
  echo "Security tooling is not installed. Run ./scripts/install-security-tools.sh first." >&2
  exit 1
fi

if [[ "$($RUFF --version)" != "ruff 0.16.2" ]]; then
  echo "Security tooling version drift detected." >&2
  exit 1
fi

echo "Running repository secret scan..."
python scripts/scan-secrets.py

echo "Running static Python security analysis..."
"$RUFF" check \
  --no-cache \
  --select S \
  --ignore S101 \
  packages/contracts/python/src \
  workers/scanner/src \
  apps/api/src

echo "Auditing locked Python dependencies against current PyPI advisories..."
python scripts/audit-dependencies.py

echo "WebGuard security gates passed."
