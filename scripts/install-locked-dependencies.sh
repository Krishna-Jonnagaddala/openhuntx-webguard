#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

cd "$REPOSITORY_ROOT"

# Bootstrap pip to the repository-reviewed version. The wheel itself is
# hash-verified before installation.
python -m pip install \
  --disable-pip-version-check \
  --only-binary=:all: \
  --require-hashes \
  --requirement requirements-bootstrap.lock

# Install every external Python dependency from the reviewed hash lock.
python -m pip install \
  --disable-pip-version-check \
  --only-binary=:all: \
  --require-hashes \
  --requirement requirements-ci.lock

# Install repository-owned packages without permitting dependency resolution
# or isolated build environments to fetch anything not present in the lock.
python -m pip install \
  --disable-pip-version-check \
  --no-build-isolation \
  --no-deps \
  --requirement requirements-dev.txt
