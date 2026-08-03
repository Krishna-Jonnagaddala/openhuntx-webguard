#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

cd "$REPOSITORY_ROOT"

PYTHON_COMMAND="${PYTHON_COMMAND:-python3}"

if [[ ! -d ".venv" ]]; then
  "$PYTHON_COMMAND" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel
python -m pip install --requirement requirements-dev.txt

echo
echo "OpenHuntX WebGuard development environment is ready."
echo "Activate it with: source .venv/bin/activate"
