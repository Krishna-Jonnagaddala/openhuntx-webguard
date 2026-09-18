#!/usr/bin/env bash
# Runs, against a real (staging) RDS PostgreSQL instance reached through
# the bastion from provision-staging-bastion.sh: migrations, the six
# tenant-isolation bootstrap SQL files in their required order, the
# exact Postgres test module list CI's own postgresql-integration job
# runs (.github/workflows/ci.yml), and a real, network exercise of the
# callback_receiver LOGIN role and the standalone callback-service
# process. Not a blanket `discover` over tests/integration, which would
# also pick up Juice-Shop-dependent and other unrelated lab tests this
# bastion has no target for. Does NOT run the RLS ENABLE/FORCE
# activation transaction itself; that is
# docs/production/RLS_STAGING_ACTIVATION.md section 2's own, separately
# approved step. Run this script first (bootstrap + tests against the
# NOT-yet-activated database), then run activation, then re-run
# test_postgres_rls_policies and test_postgres_tenant_isolation_slice13
# to exercise it under real ENABLE/FORCE.
#
# Depends on https://github.com/Krishna-Jonnagaddala/openhuntx-webguard/pull/72
# having already merged to main: that PR closed the P1-2 Phase H gaps
# and added the callback_receiver role plus the widened/new SECURITY
# DEFINER functions to tenant_isolation_control_functions.sql and
# tenant_isolation_roles.sql, including the 2026-09-18 follow-up that
# fixed set_password_hash and six sibling methods' own tenant-context
# gap. Running this script against a pre-#72 checkout applies an older
# bootstrap chain and this test list (which references files #72 adds)
# will fail to import.
#
# Run this ON the bastion (via `aws ssm start-session`) or through an
# SSM port-forward to the RDS instance from the operator's own machine.
# WEBGUARD_DATABASE_URL must point at the RDS endpoint, not localhost.
#
# Credentials, two of them, not one: the RDS master credential
# (WEBGUARD_DATABASE_URL) is used for migrations/bootstrap (which need
# CREATEROLE/GRANT privilege) and as the test suite's own admin DSN,
# the same way CI's disposable Postgres container has one "webguard"
# role for everything, because the eight least-privilege roles this
# whole exercise validates (tenant_isolation_roles.sql: the original
# seven, plus #72's callback_receiver) are the thing BEING tested, not
# the connection running the test suite itself. callback_receiver gets
# its own, second credential, generated fresh by this script (see step
# 5 below), never checked into any file.
#
# Required environment:
#   WEBGUARD_DATABASE_URL        postgresql://webguard:<master-password>@<rds-endpoint>:5432/webguard
#     Fetch the password from Secrets Manager, e.g.:
#       aws secretsmanager get-secret-value --secret-id <arn-from-terraform-output> \
#         --query SecretString --output text | jq -r .password
#     Never paste it inline in a command that lands in shell history.
#   WEBGUARD_RUN_INTEGRATION=1
#   WEBGUARD_POSTGRES_TEST_DSN   identical value to WEBGUARD_DATABASE_URL
#   AWS_REGION                   region the staging instance was provisioned in
#   CALLBACK_RECEIVER_SECRET_NAME  name for the new Secrets Manager secret this
#                                   script creates for callback_receiver's password
#                                   (e.g. webguard-staging-callback-receiver)

set -euo pipefail

: "${WEBGUARD_DATABASE_URL:?}"
: "${WEBGUARD_RUN_INTEGRATION:?Set to 1}"
: "${WEBGUARD_POSTGRES_TEST_DSN:?}"
: "${AWS_REGION:?}"
: "${CALLBACK_RECEIVER_SECRET_NAME:?}"

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
# this instance: stop and investigate before proceeding.
UNEXPECTED_RLS=$(psql "$WEBGUARD_DATABASE_URL" -tA -c "
  SELECT relname FROM pg_class
  WHERE relnamespace = 'public'::regnamespace AND relrowsecurity;
")
if [ -n "$UNEXPECTED_RLS" ]; then
  echo "RLS is already enabled on: $UNEXPECTED_RLS, stopping since this is unexpected pre-activation state." >&2
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
python3 -m unittest tests.integration.test_postgres_phase_h_gap_closure -v
python3 -m unittest tests.integration.test_postgres_password_hash_tenant_context -v
python3 -m unittest tests.integration.test_postgres_schema_upgrade_compatibility -v
python3 -m unittest tests.integration.test_postgres_sessions -v
python3 -m unittest tests.integration.test_signing_service_e2e -v
python3 -m unittest tests.integration.test_production_mode_e2e -v
python3 -m unittest tests.integration.test_production_runtime_completion_e2e -v
python3 -m unittest tests.integration.test_production_ssrf_callback_e2e -v

echo "== 5. Exercising callback_receiver and the standalone callback-service process ==" >&2
# The previous version of this document/script left callback_receiver
# as a documented-but-unexercised gap: every test above runs the
# callback path against a disposable database using either the master
# credential or a synthetic per-test role, never callback_receiver's
# own real LOGIN credential over a real network connection to real
# RDS. This step closes that, or the whole exercise is only proving
# the RLS/GRANT model, not "the completed runtime security boundary"
# staging is meant to validate.
CALLBACK_RECEIVER_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
psql "$WEBGUARD_DATABASE_URL" -v ON_ERROR_STOP=1 -c \
  "ALTER ROLE callback_receiver PASSWORD '${CALLBACK_RECEIVER_PASSWORD}'"

RDS_HOST_PORT_DB="$(python3 -c "
from urllib.parse import urlsplit
p = urlsplit('${WEBGUARD_DATABASE_URL}')
print(f'{p.hostname}:{p.port}/{p.path.lstrip(\"/\")}')
")"
export WEBGUARD_CALLBACK_DATABASE_URL="postgresql://callback_receiver:${CALLBACK_RECEIVER_PASSWORD}@${RDS_HOST_PORT_DB}"

aws secretsmanager create-secret \
  --region "$AWS_REGION" \
  --name "$CALLBACK_RECEIVER_SECRET_NAME" \
  --secret-string "$WEBGUARD_CALLBACK_DATABASE_URL" >/dev/null \
  || aws secretsmanager put-secret-value \
    --region "$AWS_REGION" \
    --secret-id "$CALLBACK_RECEIVER_SECRET_NAME" \
    --secret-string "$WEBGUARD_CALLBACK_DATABASE_URL" >/dev/null
echo "  callback_receiver password set and stored in Secrets Manager as $CALLBACK_RECEIVER_SECRET_NAME" >&2

# Fixture registration, inserted directly (the same shape
# test_postgres_control_functions.py's own
# test_callback_observation_valid_expired_and_revoked already proves
# correct): this smoke test's target is callback_receiver's own
# credential and the standalone HTTP process, not the registration
# path itself, which the test suite in step 4 already covers.
CALLBACK_TOKEN="staging-smoke-$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')"
STAGING_ORG_ID="$(psql "$WEBGUARD_DATABASE_URL" -tA -c "
  INSERT INTO organizations (organization_id, name, name_key, status, created_at)
  VALUES (gen_random_uuid(), 'staging-callback-smoke', 'staging-callback-smoke-' || extract(epoch from now()), 'active', now())
  RETURNING organization_id;
")"
psql "$WEBGUARD_DATABASE_URL" -v ON_ERROR_STOP=1 -c "
  INSERT INTO callback_registrations
    (token_value, organization_id, scan_id, job_id, permit_id, target, authorization_id, candidate_fingerprint, created_at, expires_at)
  VALUES ('${CALLBACK_TOKEN}', '${STAGING_ORG_ID}', 'staging-smoke-scan', 'staging-smoke-job', 'staging-smoke-permit',
          'https://example.com', 'staging-smoke-auth', repeat('f', 64), now(), now() + interval '1 hour');
"

python3 -m webguard_api callback-service &
CALLBACK_SERVICE_PID=$!
trap 'kill "$CALLBACK_SERVICE_PID" 2>/dev/null || true' EXIT
sleep 2

HTTP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8767/x/${CALLBACK_TOKEN}")
if [ "$HTTP_STATUS" != "204" ] && [ "$HTTP_STATUS" != "200" ]; then
  echo "callback-service smoke test failed: HTTP $HTTP_STATUS from the real callback_receiver-authenticated process." >&2
  exit 1
fi

kill "$CALLBACK_SERVICE_PID" 2>/dev/null || true
trap - EXIT

OBSERVATION_COUNT=$(psql "$WEBGUARD_DATABASE_URL" -tA -c "
  SELECT count(*) FROM callback_observations WHERE token_value = '${CALLBACK_TOKEN}';
")
if [ "$OBSERVATION_COUNT" != "1" ]; then
  echo "callback-service smoke test failed: expected exactly 1 observation row, found $OBSERVATION_COUNT." >&2
  exit 1
fi
echo "  confirmed: callback_receiver's real credential, real grant, and resolve_and_record_callback_observation" >&2
echo "  all worked end to end against real RDS: HTTP $HTTP_STATUS, 1 observation row recorded." >&2

echo "" >&2
echo "Bootstrap and pre-activation validation complete against a real RDS instance, including" >&2
echo "the callback_receiver LOGIN role. This is the first time this exact test list and the" >&2
echo "callback-service exercise have ever run against anything other than CI's disposable" >&2
echo "Docker container. Record the outcome in" >&2
echo "docs/production/STAGING_ENVIRONMENT_PROVISIONING.md section 10." >&2
echo "" >&2
echo "Next: run docs/production/RLS_STAGING_ACTIVATION.md section 2 (the" >&2
echo "ENABLE/FORCE transaction) separately, with its own owner approval," >&2
echo "then re-run: python3 -m unittest tests.integration.test_postgres_rls_policies tests.integration.test_postgres_tenant_isolation_slice13 -v" >&2
echo "to exercise the acceptance checks in that document's section 3 against the now-activated instance." >&2
