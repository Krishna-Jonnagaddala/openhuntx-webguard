# Staging Environment Provisioning for P1-2 RLS Activation

## Status

**Nothing in this document has been executed. No AWS resource described here has been created.** This is the provisioning half that `docs/production/RLS_STAGING_ACTIVATION.md` (the RLS ENABLE/FORCE procedure itself) assumes already exists. That document opens by saying activation "requires a staging environment that does not exist yet." This document is what would create that environment, at the smallest size that lets every check in `RLS_STAGING_ACTIVATION.md` section 3 actually run against real, persistent PostgreSQL. It ends with a concrete proposal (resources, cost, rollback) for an owner to approve before anything here runs. Nothing here should be run without that approval, and running it does not by itself close P1-2; the activation procedure and its acceptance checks still have to pass against whatever this provisions.

## 1. What this does and does not provision

**Provisions:** the two pieces of `infra/terraform` that P1-2 validation actually needs, `networking.tf` (a private-only VPC, two subnets, the Postgres security group) and `postgres.tf` (one `db.t4g.micro` RDS PostgreSQL 16.4 instance, KMS-encrypted, not publicly accessible), plus one temporary, minimal EC2 instance outside the reviewed `infra/terraform` tree, acting purely as a network bastion so a human or a CI job outside the VPC can reach the private RDS instance to run migrations, bootstrap SQL, and the test suite against it.

**Does not provision:** `cloudhsm.tf` (CloudHSM cluster, P1-9's concern, not P1-2's; the task this document supports is PostgreSQL tenant isolation, not signing hardware), `signing.tf` (the KMS signing key, same reasoning), `storage.tf` (the S3 artifact bucket, not needed to validate RLS; add it later only if a fuller application-level staging deployment is separately approved), `cloudflare.tf` (no public edge is needed to run a SQL test suite against a private database), or any compute to run the `webguard-api` service processes long-term (`serve`/`worker`/`scheduler` as persistent services). Provisioning long-lived application compute is a separate, larger decision (there is no Dockerfile or deployment target for it anywhere in this repository yet) and is explicitly out of scope for what P1-2 validation requires.

The bastion is deliberately not added to `infra/terraform/`: that tree is the reviewed, production-shaped configuration, and a throwaway test-runner instance has no place being versioned alongside it or contributing to its own drift. It lives as a plain, auditable shell script instead (`scripts/staging/provision-staging-bastion.sh`), and is torn down the same session it's created.

## 2. Why a bastion, and why this satisfies "generic PostgreSQL" vs. "AWS/RDS-specific" separately

`postgres.tf`'s RDS instance is `publicly_accessible = false` and its security group only accepts inbound 5432 from `var.application_security_group_id`, a required variable with no default, because this configuration deliberately provisions no compute of its own to be that source. Two distinct kinds of evidence follow from this, and this document keeps them separate rather than conflating them:

- **Generic PostgreSQL correctness** (does the RLS policy set, the role/grant model, and the SECURITY DEFINER control functions behave correctly under `ENABLE`/`FORCE ROW LEVEL SECURITY`) is already fully proven, repeatedly, by `tests/integration/test_postgres_rls_policies.py` and `tests/integration/test_postgres_tenant_isolation_slice13.py` against disposable Postgres (local Docker, and CI's own ephemeral container). Nothing in this document adds new evidence of this kind; it only asks the identical, already-passing test suite to run again in a different location.
- **AWS/RDS-specific evidence** (does this same behavior hold on the actual managed Postgres 16.4 service OpenHuntX would run in production, over the actual network path, against the actual KMS-encrypted storage, surviving an actual RDS restart or failover) does not exist anywhere in this repository today, because no RDS instance has ever been created. That is the one thing this document's provisioning step, plus a bootstrap-and-validate run against the result, actually adds. The bastion's only job is to be the thing that carries that already-written test suite across the gap from "proven on Docker Postgres" to "proven on RDS."

## 3. Minimal staging architecture

```
                      ┌─────────────────────────────────────────┐
                      │  VPC 10.42.0.0/24 (networking.tf)        │
                      │                                           │
  operator/CI ──SSM──▶│  bastion (t3.micro, private subnet A,    │
  (no public IP        │  no public IP, reached via AWS Systems   │
   on the bastion)      │  Manager Session Manager, not SSH)       │
                      │       │                                   │
                      │       │ 5432, security-group-scoped        │
                      │       ▼                                   │
                      │  RDS db.t4g.micro (postgres.tf)          │
                      │  PostgreSQL 16.4, 20GB gp3, KMS-encrypted│
                      │  private subnet B, publicly_accessible=false │
                      └─────────────────────────────────────────┘
```

- **Database**: `aws_db_instance.webguard` exactly as `postgres.tf` defines it, with two overrides for a disposable staging instance (not production defaults): `deletion_protection = false` (so teardown can actually delete it; `postgres.tf`'s own default is `true`, correct for production, wrong for a throwaway validation instance) and `skip_final_snapshot = true` is NOT set (leave the default, which per `postgres.tf` takes a final snapshot on deletion: cheap, and useful if something needs re-examining after teardown).
- **Network access**: no public IP anywhere. The bastion is reached over AWS Systems Manager Session Manager (`aws ssm start-session`), which needs no open inbound port, no SSH key to manage or leak, and no bastion security-group ingress rule at all beyond what SSM's own VPC endpoint traffic requires. RDS accepts inbound 5432 from the bastion's security group only, per `postgres.tf`'s existing design (`application_security_group_id` set to the bastion's security group ID for this validation run only).
- **Secrets**: the RDS master credential is managed by RDS itself (`manage_master_user_password = true` per `postgres.tf`, stored in AWS Secrets Manager, never written to disk or passed as a CLI argument). `scripts/staging/run-staging-bootstrap-and-validation.sh` reads it via `aws secretsmanager get-secret-value` from the bastion's own IAM instance profile (read-only, scoped to exactly that one secret ARN), not a hardcoded credential.
- **Postgres version and runtime roles**: PostgreSQL 16.4 (the same version pinned in `postgres.tf` and in `infra/compose/compose.postgres.yml`'s `postgres:16.10-alpine`, the 16.x minor-version difference between CI's Docker image and RDS's engine version is worth noting explicitly and is not expected to matter for RLS/GRANT semantics, but should be confirmed, not assumed, during validation). Runtime roles are exactly the eight created by `tenant_isolation_roles.sql`: the original seven, plus `callback_receiver`, added by [PR #72](https://github.com/Krishna-Jonnagaddala/openhuntx-webguard/pull/72) (the P1-2 Phase H tenant-isolation gap closure). No new role is introduced by staging itself. This plan assumes PR #72 has already merged to `main`; running it against a checkout from before that PR applies an older bootstrap chain and skips the eight-role/`callback_receiver` verification the current test suite expects. The bastion's own connection during validation uses the RDS master credential throughout, for bootstrap SQL, migrations, and as the test suite's own admin DSN; this mirrors CI's own `postgresql-integration` job exactly: its disposable Docker container likewise has one `webguard` role for everything (`.github/workflows/ci.yml`'s `WEBGUARD_DATABASE_URL`/`WEBGUARD_POSTGRES_TEST_DSN` are the identical connection string). The eight least-privilege roles are what this whole exercise validates, exercised *by* the test suite (which internally connects as each of them in turn to prove isolation); they are not the connection the test suite itself runs under. `callback_receiver` is the one exception worth flagging here: unlike the other seven (NOLOGIN, reached via `SET LOCAL ROLE` from `webguard`), it is a genuinely separate LOGIN identity with no password set by bootstrap SQL, so exercising the standalone `webguard-api callback-service` process against this instance (not covered by `run-staging-bootstrap-and-validation.sh`) needs its own, separately-approved `ALTER ROLE callback_receiver PASSWORD ...` step and a `WEBGUARD_CALLBACK_DATABASE_URL` pointed at that credential; see [PR #72](https://github.com/Krishna-Jonnagaddala/openhuntx-webguard/pull/72)'s own description for the exact grant this role carries.

## 4. Provisioning order

1. `terraform init` (real backend now required, `versions.tf` deliberately configures none; pick and configure one, e.g. an S3 backend with DynamoDB locking, before the first `apply`, since this instance's state must survive between the provisioning session and the teardown session).
2. `terraform apply -target=aws_vpc.webguard -target=aws_subnet.private -target=aws_db_subnet_group.webguard -target=aws_security_group.postgres` (networking only, no RDS yet, the security group needs to exist before the bastion script can reference it, and the bastion needs to exist before `postgres.tf`'s `application_security_group_id` variable can be supplied).
3. `scripts/staging/provision-staging-bastion.sh` (creates the bastion EC2 instance and its own minimal security group inside the VPC/subnet just created; prints the bastion's security group ID).
4. `terraform apply` with `application_security_group_id` set to that printed ID (creates `aws_db_instance.webguard`, this is the step that actually starts billing for RDS).
5. `scripts/staging/run-staging-bootstrap-and-validation.sh` (from the bastion, or via SSM port-forwarding to run it from the operator's own machine): applies `infra/postgres/migrations/`, then the six bootstrap SQL files in `RLS_STAGING_ACTIVATION.md` section 1's exact order, then runs the acceptance test suite, but does **not** run the `ENABLE`/`FORCE ROW LEVEL SECURITY` transaction itself; that step is `RLS_STAGING_ACTIVATION.md` section 2's own, separate, explicit action, kept as its own approval gate rather than folded into provisioning.
6. Only after an owner separately approves it: run `RLS_STAGING_ACTIVATION.md` section 2's activation transaction, then its section 3 acceptance checks, then its bake period.
7. `scripts/staging/teardown-staging.sh` (terminates the bastion first, then `terraform destroy -target=aws_db_instance.webguard`, then the remaining networking resources); run this whether the validation passed or failed, once its outcome is recorded; there is no reason to leave a validated-or-failed disposable staging database running.

## 5. Cost

Estimates only, not verified against current AWS pricing at execution time; an operator must re-check actual current on-demand rates for the target region before approving spend:

| Resource | Approximate on-demand cost | Duration this plan needs it |
|---|---|---|
| `db.t4g.micro` RDS PostgreSQL, single-AZ, 20GB gp3 | roughly $0.02-0.03/hour instance, plus a few cents/month for 20GB storage | Provisioning through teardown, a few hours to a day if the bake period (section 3.5 of `RLS_STAGING_ACTIVATION.md`) is honored |
| `t3.micro` bastion EC2 | roughly $0.01/hour | Only while actively running bootstrap/validation commands, should be stopped or terminated between sessions, not left running |
| KMS key (RDS storage encryption) | roughly $1/month per key, prorated | For the key's lifetime, delete it (with the mandatory 7-30 day AWS deletion window) at teardown if this staging environment will not be reused |
| Secrets Manager secret (RDS master credential) | roughly $0.40/month | Same as KMS key |
| Data transfer, CloudWatch basic metrics | effectively negligible at this scale | N/A |

Total order of magnitude: low single-digit dollars for a one-day validation window, assuming teardown happens promptly. This is not a number to act on without checking current pricing directly; it is here so the scale of the decision is clear (this is a small, easily-reversible spend, not a production commitment), not as a firm quote.

## 6. Observability during the bake period

No Grafana/Datadog/CloudWatch-alarm integration exists in this repository (confirmed absent by the read-only audit), and none is provisioned here either; adding a monitoring stack is out of scope for validating PostgreSQL isolation. What this plan relies on instead, all free or already-included:

- RDS's own default CloudWatch metrics (CPU, connections, storage, IOPS) are automatically collected for any RDS instance at no extra setup cost; sufficient to notice a stuck bake period or a connection leak.
- `webguard_api`'s own structured JSON logging (`structured_logging.py`), redirected to a file on the bastion for the duration of the bake period and reviewed manually; this is exactly what `RLS_STAGING_ACTIVATION.md` section 3.5 asks for ("watch application error logs"), and needs no new infrastructure.
- `pg_stat_database`'s error/rollback counters, queried directly via `psql` from the bastion before and after the bake period; again, no new infrastructure, just a query this plan's validation script runs and records.

## 7. Backup restoration validation (P1-8, kept separate from P1-2)

`docs/production/BACKUP_RESTORE.md` already rehearsed `scripts/backup-postgres.py`/`restore-postgres.py` locally (33 tables, 696 rows, sub-second timing) and was explicit that this proves data-level mechanics only, not RDS snapshot behavior or real RTO/RPO. This document's staging environment, once provisioned, is also the smallest way to close that specific gap, but doing so means creating a **second**, temporary RDS instance to restore into (an RDS snapshot restore always creates a new instance; it cannot restore in place), which roughly doubles this plan's RDS cost for the restore window. Because P1-8 is a separate, independently-tracked P1 item, this document keeps it as an explicitly optional, separately-approved add-on rather than bundling its cost into the P1-2 estimate above:

1. Take a manual RDS snapshot of the staging instance once it holds real bootstrap-and-test-suite data (`aws rds create-db-snapshot`).
2. Restore that snapshot into a new, second `db.t4g.micro` instance (`aws rds restore-db-instance-from-db-snapshot`), timing the operation from snapshot-restore start to the new instance reaching `available`.
3. Run `scripts/backup-postgres.py`'s own row-count manifest logic (or the restored instance's own copy of `tests/contract`) against the restored instance and diff against the source, exactly as the local rehearsal already did, to confirm row-for-row integrity.
4. Record the measured restore time as the first real RTO data point this project has ever had, and update `docs/PROJECT_EXECUTION_LEDGER.md`'s P1-8 row with it; this alone does not close P1-8 (PITR and a real cutover sequence are still untested), but it replaces "no data at all" with one real, dated measurement.
5. Tear down the second (restored) instance immediately after, it has no purpose beyond producing this one measurement.

## 8. Record of what was validated (fill in at execution time, do not leave templated)

```
Application commit under test:        <git rev-parse HEAD, exact SHA>
Terraform state / workspace:          <backend location, workspace name>
AWS account ID / region:              <redact in any shared doc, keep internally>
RDS instance identifier / ARN:        <from terraform output after apply>
RDS engine version (actual, post-apply): <from `aws rds describe-db-instances`, confirm matches 16.4>
Bastion instance ID:                  <from provision-staging-bastion.sh output>
Provisioning started / completed at:  <UTC timestamps>
Bootstrap files applied, in order:    <confirm all six ran without error, paste script output>
Migrations applied:                   <scripts/run-postgres-migrations.py output>
RLS activation run:                   <yes/no, timestamp if yes>
Acceptance checks (RLS_STAGING_ACTIVATION.md section 3): <pass/fail per item 1-5>
Bake period start / end, incident count: <>
Backup restoration test (section 7):  <run or not run; if run, measured restore time>
Teardown completed at:                <UTC timestamp, confirm via `aws rds describe-db-instances` returning nothing>
```

## 9. What this document does not do

It does not run any command in it automatically, does not itself flip RLS on (that remains `RLS_STAGING_ACTIVATION.md`'s own, separately-gated section 2), does not provision CloudHSM, S3 artifact storage, the Cloudflare edge, or any long-lived application compute, and does not, by itself, close P1-2 or P1-8, closing either requires this plan to actually run, its numbers to actually be recorded in section 8 above, and `RLS_STAGING_ACTIVATION.md`'s own acceptance checks to actually pass, not just to be written down correctly here.
