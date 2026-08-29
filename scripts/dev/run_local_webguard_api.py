#!/usr/bin/env python3
"""Manual dev helper (Slice 15): start a real production-mode WebGuard
API + worker against a disposable local PostgreSQL, bootstrap one
organization/owner/token, print the token, and block until Ctrl+C.

Intended for manually exercising the `apps/web` frontend against a
genuine backend during development -- not for CI. Reuses
`tests/integration/webguard_production_harness.py`, the same startup
sequence already proven by `test_production_mode_e2e.py`.

Usage:
    docker compose -f infra/compose/compose.postgres.yml up -d
    WEBGUARD_DATABASE_URL=postgresql://webguard:webguard_dev_only_not_for_production@127.0.0.1:5433/webguard \\
        python3 scripts/run-postgres-migrations.py
    python3 scripts/dev/run_local_webguard_api.py
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
for package in ("apps/api/src", "apps/contracts/src", "apps/scanner/src"):
    candidate = REPO_ROOT / package
    if candidate.is_dir():
        sys.path.insert(0, str(candidate))
sys.path.insert(0, str(REPO_ROOT / "tests" / "integration"))

from webguard_production_harness import run_production_stack  # noqa: E402

DEFAULT_DSN = "postgresql://webguard:webguard_dev_only_not_for_production@127.0.0.1:5433/webguard"


def main() -> int:
    dsn = os.environ.get("WEBGUARD_DATABASE_URL", DEFAULT_DSN)
    port = int(os.environ.get("WEBGUARD_PORT", "8765"))
    with run_production_stack(dsn, port=port) as stack:
        print("WebGuard API (production mode, disposable Postgres) is running.")
        print(f"  Base URL:          {stack.base_url}")
        print(f"  Organization ID:   {stack.organization_id}")
        print(f"  Owner principal:   {stack.owner_principal_id}")
        print(f"  Owner email:       {stack.owner_email}")
        print(f"  Owner password:    {stack.owner_password}")
        print(f"  Owner API token:   {stack.owner_token} (for CLI/API automation, not browser login)")
        print()
        print("Sign in at the WebGuard web app's login screen with the email/password above.")
        print(f"Point the frontend at this API with VITE_WEBGUARD_API_BASE_URL={stack.base_url}")
        print("Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
