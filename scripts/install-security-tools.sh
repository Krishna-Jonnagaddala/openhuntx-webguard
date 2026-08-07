#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

SECURITY_ROOT="$REPOSITORY_ROOT/var/security-tools"
SECURITY_VENV="$SECURITY_ROOT/venv"

cd "$REPOSITORY_ROOT"

rm -rf "$SECURITY_VENV"
mkdir -p "$SECURITY_ROOT"

python -m venv "$SECURITY_VENV"

"$SECURITY_VENV/bin/python" -m pip install \
  --disable-pip-version-check \
  --require-hashes \
  -r requirements-bootstrap.lock

"$SECURITY_VENV/bin/python" -m pip install \
  --disable-pip-version-check \
  --no-deps \
  --only-binary=:all: \
  --require-hashes \
  -r requirements-security.lock

actual_ruff="$($SECURITY_VENV/bin/ruff --version)"
if [[ "$actual_ruff" != "ruff 0.16.2" ]]; then
  echo "Unexpected Ruff version: $actual_ruff" >&2
  exit 1
fi

echo "Security tools installed with reviewed hashes."
