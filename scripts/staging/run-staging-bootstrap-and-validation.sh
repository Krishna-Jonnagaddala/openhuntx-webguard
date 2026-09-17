#!/usr/bin/env bash
# Runs, against a real (staging) RDS PostgreSQL instance reached through
# the bastion from provision-staging-bastion.sh: migrations, the six
# tenant-isolation bootstrap SQL files in their required order, then the
# exact Postgres test module list CI's own postgresql-integration job
# runs (.github/workflows/ci.yml) -- not a blanket `discover` over
# tests/integration, which would also pick up Juice-Shop-dependent and
# other unrelated lab tests this bastion has no target for. Does NOT run
# the RLS ENABLE/FORCE activation transaction itself -- that is
# docs/production/RLS_STAGING_ACTIVATION.md section 2's own, separately
# approved step. Run this script first (bootstrap + tests against the
# NOT-yet-activated database), then run activation, then re-run
# test_postgres_rls_policies and test_postgres_tenant_isolation_slice13
# to exercise it under real ENABLE/FORCE.
#
# Run this ON the bastion (via `aws ssm start-session`) or through an
# SSM port-forward to the RDS instance from the operator's own machine.
# WEBGUARD_DATABASE_URL must point at the RDS endpoint, not localhost.
#
# Mirrors CI's own connection model exactly: one connection string, the
# RDS master credential, used for both migrations/bootstrap (which need
# CREATEROLE/GRANT privilege) and as the test suite's own admin DSN --
# the same way CI's disposable Postgres container has one "webguard"
# role for everything, because the seven least-privilege roles this
# whole exercise validates (tenant_isolation_roles.sql) are the thing
# BEING tested, not the connection running the test suite itself.
#
# Required environment:
#   WEBGUARD_DATABASE_URL        postgresql://webguard:<master-password>@<rds-endpoint>:5432/webguard
#     Fetch the password from Secrets Manager, e.g.:
#       aws secretsmanager get-secret-value --secret-id <arn-from-terraform-output> \
#         --query SecretString --output text | jq -r .password
#     Never paste it inline in a command that lands in shell history.
#   WEBGUARD_RUN_INTEGRATION=1
#   WEBGUARD_POSTGRES_TEST_DSN   identical value to WEBGUARD_DATABASE_URL

set -euo pipefail

: "${WEBGUARD_DATABASE_URL:?}"
: "${WEBGUARD_RUN_INTEGRATION:?Set to 1}"
: "${WEBGUARD_POSTGRES_TEST_DSN:?}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

export PYTHONPATH="apps/api/src:packages/contracts/python/src:workers/scanner/src:."

echo "== 1. Applying migrations (infra/postgres/migrations/) ==" >&2
python3 scripts/run-postgres-migrations.py

echo "== 2. Applying tenant-isolation bootstrap, in required order ==" >&2
for f in \
  tenant_isolation_roles.sql \
  tenant_isolation_acl.sql \
  tenant_isolation_function_acl.sql \
  tenant_isolation_control_functions.sql \
  tenant_isolation_rls_policies.sql \
  tenant_isolation_runtime_grant.sql
do
  echo "  -- $f" >&2
  psql "$WEBGUARD_DATABASE_URL" -v ON_ERROR_STOP=1 -f "infra/postgres/bootstrap/$f"
done

echo "== 3. Confirming RLS is still OFF post-bootstrap (expected) ==" >&2
# tenant_isolation_rls_policies.sql defines policies but enables nothing.
# This query should return zero rows: no table should have
# relrowsecurity=true yet. A non-empty result here means something ran
# out of order or a previous, uncleaned activation is still active on
# this instance -- stop and investigate before proceeding.
UNEXPECTED_RLS=$(psql "$WEBGUARD_DATABASE_URL" -tA -c "
  SELECT relname FROM pg_class
  WHERE relnamespace = 'public'::regnamespace AND relrowsecurity;
")
if [ -n "$UNEXPECTED_RLS" ]; then
  echo "RLS is already enabled on: $UNEXPECTED_RLS -- stopping, this is unexpected pre-activation state." >&2
  exit 1
fi
echo "  confirmed: relrowsecurity is false on every table." >&2

echo "== 4. Running the exact Postgres test module list CI's postgresql-integration job runs ==" >&2
python3 -m unittest discover -s tests/contract -p "test_*.py" -v
python3 -m unittest tests.integration.test_postgres_connection_pool -v
python3 -m unittest tests.integration.test_postgres_tenant_context_helper -v
python3 -m unittest tests.integration.test_postgres_tenant_role_bootstrap -v
python3 -m unittest tests.integration.test_postgres_tenant_acl_bootstrap -v
python3 -m unittest tests.integration.test_postgres_identity_credentials_write_shape -v
python3 -m unittest tests.integration.test_postgres_function_owner_acl_bootstrap -v
python3 -m unittest tests.integration.test_postgres_control_functions -v
python3 -m unittest tests.integration.test_postgres_rls_policies -v
python3 -m unittest tests.integration.test_postgres_tenant_isolation_slice13 -v
python3 -m unittest tests.integration.test_postgres_sessions -v
python3 -m unittest tests.integration.test_signing_service_e2e -v
python3 -m unittest tests.integration.test_production_mode_e2e -v
python3 -m unittest tests.integration.test_production_runtime_completion_e2e -v
python3 -m unittest tests.integration.test_production_ssrf_callback_e2e -v

echo "" >&2
echo "Bootstrap and pre-activation validation complete against a real RDS instance." >&2
echo "This is the first time this exact test list has ever run against anything" >&2
echo "other than CI's disposable Docker container -- record the outcome in" >&2
echo "docs/production/STAGING_ENVIRONMENT_PROVISIONING.md section 8." >&2
echo "" >&2
echo "Next: run docs/production/RLS_STAGING_ACTIVATION.md section 2 (the" >&2
echo "ENABLE/FORCE transaction) separately, with its own owner approval," >&2
echo "then re-run: python3 -m unittest tests.integration.test_postgres_rls_policies tests.integration.test_postgres_tenant_isolation_slice13 -v" >&2
echo "to exercise the acceptance checks in that document's section 3 against the now-activated instance." >&2
