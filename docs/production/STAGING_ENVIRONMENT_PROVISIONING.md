# Staging Environment Provisioning for P1-2 RLS Activation

## Status

**Nothing in this document has been executed. No AWS resource described here has been created.** This is the provisioning half that `docs/production/RLS_STAGING_ACTIVATION.md` (the RLS ENABLE/FORCE procedure itself) assumes already exists. That document opens by saying activation "requires a staging environment that does not exist yet." This document is what would create that environment, at the smallest size that lets every check in `RLS_STAGING_ACTIVATION.md` section 3 actually run against real, persistent PostgreSQL, including the one path the previous version of this document left unexercised: the standalone `callback_receiver` LOGIN identity and the callback-service process that authenticates as it. It ends with a concrete proposal (resources, cost, rollback) for an owner to approve before anything here runs. Nothing here should be run without that approval, and running it does not by itself close P1-2; the activation procedure and its acceptance checks still have to pass against whatever this provisions.

**Revision, 2026-09-18**: this version corrects the previous one's central assumption, that a private-subnet, no-public-IP bastion can reach AWS Systems Manager, Secrets Manager, and an OS package repository with no further network configuration. It cannot: `networking.tf` provisions no NAT gateway, no internet gateway, and no VPC endpoints, so a subnet with neither has no route to any of those services regardless of what the bastion's own security group permits outbound. Section 3 below adds the missing network path (`infra/terraform/networking.tf`'s new `var.create_staging_bastion_networking` opt-in), and the cost table in section 5 is rebuilt from AWS's own published pricing for `eu-west-2` (the region `docs/production/PROVIDER_EVALUATION.md` actually recommends; the previous version never named a region), not from a same-as-everywhere assumption. Section 4 also now exercises the `callback_receiver` DSN directly rather than deferring it, per the explicit correction that "validates the completed runtime security boundary" cannot mean "except the one LOGIN role."

## 1. What this does and does not provision

**Provisions:** the three pieces of `infra/terraform` that P1-2 validation actually needs: `networking.tf` (a private-only VPC, two private subnets, the Postgres security group, plus the new opt-in NAT path described in section 3), `postgres.tf` (one `db.t4g.micro` RDS PostgreSQL instance, KMS-encrypted, not publicly accessible), and one temporary, minimal EC2 instance outside the reviewed `infra/terraform` tree, acting as a network bastion so a human or a CI job outside the VPC can reach the private RDS instance to run migrations, bootstrap SQL, and the test suite (including the `callback_receiver` exercise) against it.

**Does not provision:** `cloudhsm.tf` (CloudHSM cluster, P1-9's concern, not P1-2's; the task this document supports is PostgreSQL tenant isolation, not signing hardware), `signing.tf` (the KMS signing key, same reasoning), `storage.tf` (the S3 artifact bucket, not needed to validate RLS; add it later only if a fuller application-level staging deployment is separately approved), `cloudflare.tf` (no public edge is needed to run a SQL test suite against a private database, and the callback-service exercise in section 4 talks to the callback-service process directly over the VPC, not through Cloudflare), or any compute to run the `webguard-api` service processes long-term (`serve`/`worker`/`scheduler` as persistent services). Provisioning long-lived application compute is a separate, larger decision (there is no Dockerfile or deployment target for it anywhere in this repository yet) and is explicitly out of scope for what P1-2 validation requires; the callback-service exercise below runs it as a short-lived background process on the bastion for the duration of one smoke test, not as a persistent service.

The bastion is deliberately not added to `infra/terraform/`: that tree is the reviewed, production-shaped configuration, and a throwaway test-runner instance has no place being versioned alongside it or contributing to its own drift. It lives as a plain, auditable shell script instead (`scripts/staging/provision-staging-bastion.sh`), and is torn down the same session it's created.

## 2. Why a bastion, and why this satisfies "generic PostgreSQL" vs. "AWS/RDS-specific" separately

`postgres.tf`'s RDS instance is `publicly_accessible = false` and its security group only accepts inbound 5432 from `var.application_security_group_id`, a required variable with no default, because this configuration deliberately provisions no long-lived compute of its own to be that source. Two distinct kinds of evidence follow from this, and this document keeps them separate rather than conflating them:

- **Generic PostgreSQL correctness** (does the RLS policy set, the role/grant model, and the SECURITY DEFINER control functions behave correctly under `ENABLE`/`FORCE ROW LEVEL SECURITY`) is already fully proven, repeatedly, by `tests/integration/test_postgres_rls_policies.py`, `tests/integration/test_postgres_tenant_isolation_slice13.py`, `tests/integration/test_postgres_phase_h_gap_closure.py`, and `tests/integration/test_postgres_password_hash_tenant_context.py` against disposable Postgres (local Docker, and CI's own ephemeral container). Nothing in this document adds new evidence of this kind; it only asks the identical, already-passing test suite to run again in a different location.
- **AWS/RDS-specific evidence** (does this same behavior hold on the actual managed Postgres service OpenHuntX would run in production, over the actual network path, against the actual KMS-encrypted storage and the actual `callback_receiver` LOGIN credential, surviving an actual RDS restart or failover) does not exist anywhere in this repository today, because no RDS instance has ever been created. That is the one thing this document's provisioning step, plus a bootstrap-and-validate run against the result, actually adds. The bastion's only job is to be the thing that carries that already-written test suite, and the callback-service process itself, across the gap from "proven on Docker Postgres" to "proven on RDS."

## 3. Minimal staging architecture

```
              ┌────────────────────────────────────────────────────────────┐
              │  VPC 10.42.0.0/24 (networking.tf)                            │
              │                                                              │
              │   public subnet 10.42.0.128/26 (AZ-a, staging-only)          │
              │   ┌────────────────────────────────────────────────┐        │
  operator/CI │   │  NAT Gateway + Elastic IP (public IPv4)         │        │
  ──SSM──────▶│   └───────────────────────▲────────────────────────┘        │
  (no public   │                           │ 0.0.0.0/0 via NAT               │
   IP on the   │   private subnet A (AZ-a) │        private subnet B (AZ-b) │
   bastion)    │   ┌───────────────────────┴──┐   ┌──────────────────────┐ │
              │   │  bastion (t3.micro,       │   │  (RDS subnet-group    │ │
              │   │  no public IP, reached    │   │   member only, no     │ │
              │   │  via SSM Session Manager) │   │   instance here)      │ │
              │   └───────────┬───────────────┘   └───────────────────────┘ │
              │               │ 5432, security-group-scoped                 │
              │               ▼                                             │
              │   RDS db.t4g.micro (postgres.tf), PostgreSQL 16.15,          │
              │   20GB gp3, KMS-encrypted, publicly_accessible=false         │
              └────────────────────────────────────────────────────────────┘
```

The NAT path (public subnet, internet gateway, Elastic IP, NAT Gateway, and the private subnets' `0.0.0.0/0 -> NAT` route) is new in this revision, gated behind `infra/terraform/variables.tf`'s `create_staging_bastion_networking` (default `false`, so a production apply of this configuration provisions none of it, unchanged from before). Without it, the bastion's security group would permit outbound traffic, but the subnet itself would have no route anywhere: AWS Systems Manager Session Manager needs to reach SSM's own service endpoints, `dnf`/`pip` need to reach a package repository to install `git`/`python3`/`psycopg2`'s build dependencies, and the bootstrap step needs to reach Secrets Manager for the RDS master credential, none of which a security-group rule alone makes reachable. `terraform validate` and a `terraform plan`-equivalent Trivy config scan (`trivy config --tf-vars ... --severity LOW,MEDIUM,HIGH,CRITICAL infra/terraform`) both pass clean with this flag set to `true`, confirmed directly, not assumed.

An interface-VPC-endpoint-only alternative (four endpoints, `ssm`, `ssmmessages`, `ec2messages`, `secretsmanager`, at $0.011/hour each per AZ, no general internet egress at all) was considered and rejected for this specific, short-lived use: it still leaves the OS-package-installation problem unsolved (no route to any package repository) unless the bastion's AMI is pre-baked with every dependency, which is more moving parts to get right for a environment that exists for a few hours. A single NAT Gateway is one resource, well-understood, and correctly costed below; the endpoint-only path is the better choice for a *long-lived* bastion, which this deliberately is not.

- **Database**: `aws_db_instance.webguard` exactly as `postgres.tf` defines it, with two overrides for a disposable staging instance (not production defaults): `deletion_protection = false` (so teardown can actually delete it; `postgres.tf`'s own default is `true`, correct for production, wrong for a throwaway validation instance) and `skip_final_snapshot` left at its default `false` (a final snapshot is taken on deletion: cheap, and useful if something needs re-examining after teardown; see section 5's note on what that snapshot costs if it is not also cleaned up).
- **Postgres version**: `postgres_engine_version`'s default was `16.4`; this revision bumps it to `16.15`, the latest 16.x minor RDS was offering for new-instance creation per AWS's 2026-08 PostgreSQL minor-version announcement (`18.6`/`17.11`/`16.15`/`15.19`/`14.24`). `16.4` predates that by roughly two years of minor releases and should not be assumed still available for new-instance creation; confirm with `aws rds describe-db-engine-versions --engine postgres --engine-version 16.15 --region eu-west-2` before the first real apply, since AWS periodically retires individual old minors independent of major-version end-of-life, and this document cannot verify current availability without a real AWS account. The 16.x-vs-16.10 difference between this and CI's own `postgres:16.10-alpine` Docker image is worth confirming, not assumed, during validation, though no RLS/GRANT semantic difference is expected across 16.x minors.
- **Network access**: no public IP anywhere on the bastion or on RDS. The bastion is reached over AWS Systems Manager Session Manager (`aws ssm start-session`), which needs no open inbound port, no SSH key to manage or leak, and no bastion security-group ingress rule at all beyond what SSM's own traffic requires (routed via the NAT path above, not via an ingress rule). RDS accepts inbound 5432 from the bastion's security group only, per `postgres.tf`'s existing design (`application_security_group_id` set to the bastion's security group ID for this validation run only).
- **Credentials**: two separate credentials are actually in play here, not one, worth being explicit about since "separate admin/runtime credentials" is easy to conflate with the eight *database roles* this exercise validates. The RDS **master credential** (`manage_master_user_password = true` per `postgres.tf`, stored in AWS Secrets Manager, never written to disk or passed as a CLI argument) is the one connection used for migrations, bootstrap SQL, and as the test suite's own admin DSN; this mirrors CI's own `postgresql-integration` job exactly, whose disposable Docker container likewise has one `webguard` role for everything. The eight least-privilege *database roles* `tenant_isolation_roles.sql` creates (the original seven, NOLOGIN, reached via `SET LOCAL ROLE` from `webguard`; plus `callback_receiver`, the one genuinely separate LOGIN identity) are what this whole exercise validates, exercised *by* the test suite connecting as each in turn; they are not, and should not be, the connection the test suite itself runs under. `callback_receiver` needs its own, third credential, set explicitly in step 5 below (`ALTER ROLE callback_receiver PASSWORD ...`, generated fresh for this run, never checked into any file) and read back only from the bastion's own Secrets Manager access, exactly like the master credential (see step 5).
- **IAM**: the bastion's instance role holds `AmazonSSMManagedInstanceCore` (for Session Manager) plus a narrow, resource-scoped `secretsmanager:GetSecretValue` on exactly two secret ARNs (the RDS master credential's auto-created secret, and the `callback_receiver` password this document's own step 5 creates), never a wildcard `secretsmanager:*` grant, and never IAM database authentication (this project's roles are password/`SET ROLE`-based, not IAM-auth-based, so there is nothing to reconcile there).

## 4. Provisioning order

1. `terraform init` with a real backend now configured (`versions.tf` deliberately configures none by default; see section 6 below for the specific backend this document proposes, which must exist before the first `apply`, since state has to survive between the provisioning session and the teardown session).
2. `terraform apply -var create_staging_bastion_networking=true -target=aws_vpc.webguard -target=aws_subnet.private -target=aws_subnet.public_nat -target=aws_internet_gateway.webguard -target=aws_eip.nat -target=aws_nat_gateway.webguard -target=aws_route_table.public_nat -target=aws_route_table.private_egress -target=aws_route_table_association.public_nat -target=aws_route_table_association.private_egress -target=aws_db_subnet_group.webguard -target=aws_security_group.postgres` (networking and the NAT egress path, no RDS yet: the security group needs to exist before the bastion script can reference it, and the bastion needs to exist before `postgres.tf`'s `application_security_group_id` variable can be supplied).
3. `scripts/staging/provision-staging-bastion.sh` (creates the bastion EC2 instance, launched into the *private* subnet with the NAT route from step 2, and its own minimal security group; prints the bastion's security group ID). Confirm SSM connectivity works (`aws ssm start-session --target <instance-id>`) before proceeding: this is the exact assumption this revision stopped taking on faith.
4. `terraform apply -var create_staging_bastion_networking=true` with `application_security_group_id` set to that printed ID (creates `aws_db_instance.webguard`; this is the step that actually starts billing for RDS).
5. `scripts/staging/run-staging-bootstrap-and-validation.sh` (from the bastion, or via SSM port-forwarding to run it from the operator's own machine): applies `infra/postgres/migrations/`, then the six bootstrap SQL files in `RLS_STAGING_ACTIVATION.md` section 1's exact order, sets a fresh `callback_receiver` password and stores it in Secrets Manager, runs the full acceptance test suite, and runs the `callback_receiver`/callback-service smoke test described below, but does **not** run the `ENABLE`/`FORCE ROW LEVEL SECURITY` transaction itself; that step is `RLS_STAGING_ACTIVATION.md` section 2's own, separate, explicit action, kept as its own approval gate rather than folded into provisioning.
6. Only after an owner separately approves it: run `RLS_STAGING_ACTIVATION.md` section 2's activation transaction, then its section 3 acceptance checks (re-running the same test suite plus the callback-service smoke test against the now-activated instance), then its bake period.
7. `scripts/staging/teardown-staging.sh` (verifies the destroy plan first, then terminates the bastion, then destroys RDS, then the NAT/networking resources, then reports what was retained and what still needs a manual follow-up (see section 9's own fuller description); run this whether the validation passed or failed, once its outcome is recorded; there is no reason to leave a validated-or-failed disposable staging environment running.

**Callback-service exercise (new in this revision, the last part of step 5)**: `callback_receiver` is a genuinely separate LOGIN identity (`tenant_isolation_roles.sql`), not reached via `SET LOCAL ROLE` like the other seven roles, and the previous version of this document left it as a documented gap ("needs its own... step... at that time") rather than something staging actually proves. Presenting staging as validation of "the completed runtime security boundary" while silently excluding the one LOGIN role from that boundary is not an acceptable scope-narrowing to leave implicit, so `run-staging-bootstrap-and-validation.sh` now, after running the test suite: (a) generates a fresh, random password and sets it with `ALTER ROLE callback_receiver PASSWORD ...`, storing it in a dedicated Secrets Manager secret rather than in any file or shell history; (b) builds `WEBGUARD_CALLBACK_DATABASE_URL` from it; (c) launches `python3 -m webguard_api callback-service` (`cli.py`'s own `callback-service` subcommand, confirmed against `apps/api/src/webguard_api/cli.py`'s `_callback_service_command`, which reads `WEBGUARD_CALLBACK_DATABASE_URL` specifically, never `WEBGUARD_DATABASE_URL`) as a short-lived background process on the bastion, bound to `127.0.0.1:8767` by default; (d) inserts one fixture `callback_registrations` row directly (the same shape `test_postgres_control_functions.py`'s own `test_callback_observation_valid_expired_and_revoked` already proves correct; the registration path itself is already covered by the test suite that ran earlier in this same step, so this part's own target is only the credential and the standalone process) and issues a real HTTP request against the callback-service process's own listener, confirming `200`/`204` and that `callback_observations` gained exactly one row; (e) kills the process. This proves `callback_receiver`'s credential, grant, and the `resolve_and_record_callback_observation` function actually work end to end against real RDS, not merely that the role and grant exist. If a future run needs to skip this (e.g. a time-boxed validation that only cares about the RLS policy set), that is a valid choice, but it must be stated explicitly in that run's own section 10 record as a narrowed acceptance scope, not left implicit the way the previous revision left it.

## 5. Cost

Sourced directly from AWS's own published pricing (the official Price List API offer files for `AmazonRDS`, `AmazonEC2`, `AmazonVPC`, `awskms`, and `AWSSecretsManager`, region `eu-west-2`, fetched 2026-09-18: not a generic or `us-east-1` estimate carried over by habit, and not the AWS Pricing Calculator's UI, which does not expose a stable citation). Re-verify against current rates at execution time regardless; AWS pricing changes without much notice.

| Resource | eu-west-2 on-demand rate | Source |
|---|---|---|
| RDS `db.t4g.micro`, Single-AZ, PostgreSQL | $0.018/hour | AWS `AmazonRDS` offer file, SKU `ATYF9R3XTURNBSMZ` |
| RDS gp3 storage | $0.133/GB-month | AWS `AmazonRDS` offer file, SKU `GSPER49HB8KZCR7E` |
| RDS backup storage beyond the free allocation (100% of provisioned storage while the instance exists) | $0.10/GB-month | AWS `AmazonRDS` offer file, SKU `86WGCR64MN2MPQCT` |
| EC2 `t3.micro`, Linux, on-demand | $0.0118/hour | AWS `AmazonEC2` offer file, SKU `6BZBC9RT9Y98ZRJV` |
| NAT Gateway, hourly | $0.05/hour | AWS `AmazonEC2` offer file (`EUW2-NatGateway-Hours`) |
| NAT Gateway, data processed | $0.05/GB | AWS `AmazonEC2` offer file (`EUW2-NatGateway-Bytes`) |
| Public IPv4 address, in-use (the NAT Gateway's Elastic IP) | $0.005/hour | AWS `AmazonVPC` offer file, SKU `CB3E2ZKHCN8Y7SYP` (this is the 2024-02 public-IPv4 pricing change; the previous version of this document did not account for it at all) |
| KMS customer-managed key | $1/month, prorated hourly, per key | AWS `awskms` offer file (`eu-west-2-KMS-Keys`) |
| KMS API requests | $0.03 per 10,000 | AWS `awskms` offer file |
| Secrets Manager secret | $0.40/month, prorated, per secret | AWS `AWSSecretsManager` offer file |
| Secrets Manager API calls | $0.05 per 10,000 | AWS `AWSSecretsManager` offer file |

**This plan creates two KMS keys, not one**: `postgres.tf`'s own RDS storage-encryption key, and `networking.tf`'s existing (already-provisioned regardless of this document) VPC-flow-logs encryption key. The previous version of this cost table only counted the first. Both are within the same networking/database apply this document scopes, so both belong in the estimate.

**One-day validation window** (provisioning through teardown, the plan's actual intended duration, NAT and bastion running the whole window as a conservative upper bound even though the runbook stops the bastion between active sessions):

| Item | Calculation | Cost |
|---|---|---|
| RDS compute | 24h x $0.018 | $0.43 |
| RDS storage (20GB) | $0.133 x 20 / 30 | $0.09 |
| RDS backup storage | within free allocation | $0.00 |
| Bastion EC2 | 24h x $0.0118 | $0.28 |
| NAT Gateway, hourly | 24h x $0.05 | $1.20 |
| NAT Gateway, data (package installs, git checkout, test runs; assume 2GB) | 2 x $0.05 | $0.10 |
| Public IPv4 (NAT's EIP) | 24h x $0.005 | $0.12 |
| KMS, 2 keys | 2 x ($1 / 30) | $0.07 |
| Secrets Manager, 2 secrets (RDS master + `callback_receiver`) | 2 x ($0.40 / 30) | $0.03 |
| API request costs (KMS, Secrets Manager) | low thousands of calls | <$0.01 |
| **Total** | | **~$2.30** |

**If teardown is forgotten and everything runs for a full month** (not this plan's intent, but the number an approver should see so nothing here is mistaken for negligible): RDS compute+storage ~$14, bastion (if left running rather than stopped between sessions, contrary to the runbook) ~$8.61, NAT Gateway hourly ~$36.50 plus data processing (call it $2-10 depending on actual traffic), public IPv4 ~$3.65, KMS (2 keys) $2, Secrets Manager (2 secrets) $0.80: **roughly $67-75/month**, overwhelmingly driven by the NAT Gateway's flat hourly charge, not by RDS or KMS. **The previous version's claim that "only RDS and KMS incur ongoing costs" was wrong even on its own pre-NAT architecture** (it omitted the bastion EC2 hourly charge and Secrets Manager's monthly per-secret charge, both real even without a NAT Gateway); this revision's NAT/EIP addition makes the gap larger, not smaller, which is exactly why teardown discipline (section 9) matters more here than the previous version implied.

**Retained-resource costs after teardown**: resources that do not disappear the instant `terraform destroy` returns, and their approximate ongoing cost until someone explicitly removes them.

| Retained item | Why it survives teardown | Ongoing cost while retained |
|---|---|---|
| Final RDS snapshot (taken automatically since `skip_final_snapshot` stays at its default `false`) | Snapshots are not a Terraform-managed resource; `terraform destroy` removing `aws_db_instance.webguard` does not delete the snapshot it creates as a side effect. Not mentioned or cleaned up by the previous version's teardown script at all. | 20GB x $0.10/GB-month (backup-storage rate; no free allocation applies once the source instance is gone) = ~$2/month until manually deleted (`aws rds delete-db-snapshot`) |
| KMS keys (both) | AWS enforces a mandatory 7-30 day pending-deletion window; `terraform destroy` schedules deletion, it does not delete immediately | Up to $2 total (2 keys x up to 30 days, prorated) accruing during the window, then $0 |
| Secrets Manager secrets (both) | Same kind of mandatory recovery window, default 30 days unless force-deleted with `--force-delete-without-recovery` | Up to ~$0.80 total accruing during the window, then $0 |
| CloudWatch Logs group for VPC flow logs, and its own dedicated KMS key | `networking.tf`'s flow-log resources are destroyed along with the rest of the VPC by an untargeted `terraform destroy`, so this row is only relevant if teardown is run with narrower `-target` flags that skip them | Negligible ingestion/storage for one day of light traffic (a few cents at most), but persists at whatever rate it accrued until explicitly deleted if skipped |

## 6. Terraform state

`versions.tf` deliberately configures no backend, so state defaults to a local `terraform.tfstate` file, which must not be how a shared, destroy-later environment is run: whoever provisions it and whoever tears it down need to see the same state, and a local file on one laptop is a real risk of losing track of what exists. Concretely, before the first `apply` in section 4:

1. Create (once, manually, or via a separate one-time bootstrap script, not part of this document's own apply, to avoid a chicken-and-egg backend-for-the-backend problem) an S3 bucket for state, with versioning enabled (so a bad state write can be rolled back) and default SSE-KMS encryption, and a DynamoDB table for state locking (`LockID` as its partition key, on-demand billing mode: at this scale, provisioned capacity is not worth the extra configuration).
2. Add a `backend "s3"` block to `versions.tf` (or a `-backend-config` file kept out of version control, since it names an actual bucket/table) naming that bucket, table, and the `eu-west-2` region, with a state key path that identifies this as the staging environment specifically (e.g. `webguard/staging/terraform.tfstate`), distinct from whatever key a real production apply would use, so the two environments' state can never collide.
3. `terraform init` picks up the backend automatically once configured; `terraform state list` after each apply is a cheap sanity check that state and reality agree.
4. **Recovery**: if the state file is lost or corrupted before teardown has run, the resources it described do not disappear, they become unmanaged, and would otherwise be found only by manually searching the AWS console/CLI for anything tagged `Environment = staging` (every resource in `networking.tf`/`postgres.tf` carries this tag already) and importing each one back into a fresh state file (`terraform import`) before `destroy` can be trusted to remove everything. This is exactly the scenario S3 versioning in step 1 exists to make recoverable (restore the previous state-file version) rather than needing a manual import sweep at all; the DynamoDB lock table prevents the more common cause of state corruption (two concurrent applies) in the first place.

## 7. Observability during the bake period

No Grafana/Datadog/CloudWatch-alarm integration exists in this repository (confirmed absent by the read-only audit), and none is provisioned here either; adding a monitoring stack is out of scope for validating PostgreSQL isolation. What this plan relies on instead, all free or already-included:

- RDS's own default CloudWatch metrics (CPU, connections, storage, IOPS) are automatically collected for any RDS instance at no extra setup cost; sufficient to notice a stuck bake period or a connection leak.
- `webguard_api`'s own structured JSON logging (`structured_logging.py`), redirected to a file on the bastion for the duration of the bake period and reviewed manually; this is exactly what `RLS_STAGING_ACTIVATION.md` section 3.5 asks for ("watch application error logs"), and needs no new infrastructure. The callback-service smoke test's own process output is included in this.
- `pg_stat_database`'s error/rollback counters, queried directly via `psql` from the bastion before and after the bake period; again, no new infrastructure, just a query this plan's validation script runs and records.

## 8. Backup restoration validation (P1-8, kept separate from P1-2)

`docs/production/BACKUP_RESTORE.md` already rehearsed `scripts/backup-postgres.py`/`restore-postgres.py` locally (33 tables, 696 rows, sub-second timing) and was explicit that this proves data-level mechanics only, not RDS snapshot behavior or real RTO/RPO. This document's staging environment, once provisioned, is also the smallest way to close that specific gap, but doing so means creating a **second**, temporary RDS instance to restore into (an RDS snapshot restore always creates a new instance; it cannot restore in place), which roughly doubles this plan's RDS cost for the restore window. Because P1-8 is a separate, independently-tracked P1 item, this document keeps it as an explicitly optional, separately-approved add-on rather than bundling its cost into the P1-2 estimate above:

1. Take a manual RDS snapshot of the staging instance once it holds real bootstrap-and-test-suite data (`aws rds create-db-snapshot`).
2. Restore that snapshot into a new, second `db.t4g.micro` instance (`aws rds restore-db-instance-from-db-snapshot`), timing the operation from snapshot-restore start to the new instance reaching `available`.
3. Run `scripts/backup-postgres.py`'s own row-count manifest logic (or the restored instance's own copy of `tests/contract`) against the restored instance and diff against the source, exactly as the local rehearsal already did, to confirm row-for-row integrity.
4. Record the measured restore time as the first real RTO data point this project has ever had, and update `docs/PROJECT_EXECUTION_LEDGER.md`'s P1-8 row with it; this alone does not close P1-8 (PITR and a real cutover sequence are still untested), but it replaces "no data at all" with one real, dated measurement.
5. Tear down the second (restored) instance immediately after: it has no purpose beyond producing this one measurement. Delete the manual snapshot from step 1 once both instances are gone too, or it becomes exactly the kind of retained-cost item section 5's table above describes.

## 9. Teardown

Run `scripts/staging/teardown-staging.sh`, whether validation passed or failed, once its outcome is recorded in section 10 below. It now does the following, in order, correcting the previous version's gaps (no Secrets Manager cleanup, no accounting for the second KMS key, no pre-destroy verification step, no NAT/EIP-aware ordering):

1. **Verify before destroying**: runs `terraform plan -destroy -var create_staging_bastion_networking=true -out=/tmp/staging-destroy.plan` and prints the full resource-address list from that plan for manual review before anything is actually deleted, confirming the target list is exactly this staging environment's own resources (matched by the `Environment = staging` tag every resource here carries) and not, for instance, a stale `-target` flag reaching into an unrelated environment's state. This is a read-only step; nothing is destroyed until the next step explicitly applies this exact saved plan.
2. Terminates the bastion instance and removes its IAM role/instance profile/security group, same as before.
3. Deletes the `callback_receiver` and RDS-master Secrets Manager secrets created during provisioning (`aws secretsmanager delete-secret`, default 30-day recovery window). Pass `--force-delete-without-recovery` instead if the operator explicitly wants the retained-cost window in section 5 skipped; that is a real tradeoff, irreversible recovery versus an extra ~30 days of ~$0.40/secret, and this script asks rather than assuming either answer. Not present in the previous version at all.
4. Applies the saved destroy plan from step 1 (`terraform apply /tmp/staging-destroy.plan`), which removes `aws_db_instance.webguard` (taking the final snapshot noted in section 5's retained-cost table), then the NAT Gateway/EIP/internet gateway/public subnet, then the remaining VPC/subnet/security-group/flow-log resources, in Terraform's own dependency order.
5. Prints an explicit reminder of what section 5 already flagged as retained rather than destroyed: the final RDS snapshot (delete manually with `aws rds delete-db-snapshot` once nobody needs it, or accept the ~$2/month it costs to keep for a while) and the two KMS keys' 7-30 day pending-deletion window (no action needed, just an accrual to expect, not a bug if the keys still show as `PendingDeletion` in the AWS console for a few weeks).
6. Confirms deletion with `aws rds describe-db-instances --region eu-west-2 --query 'DBInstances[?DBInstanceIdentifier==`webguard`]'` (expect an empty list) and `aws ec2 describe-vpcs --region eu-west-2 --filters Name=tag:Environment,Values=staging` (expect an empty list, modulo the snapshot and pending-deletion KMS keys/secrets already called out as intentionally retained).

## 10. Record of what was validated (fill in at execution time, do not leave templated)

```
Application commit under test:        <git rev-parse HEAD, exact SHA>
Terraform state backend:              <S3 bucket / DynamoDB table names, section 6>
AWS account ID / region:              <redact in any shared doc, keep internally; region should be eu-west-2>
RDS instance identifier / ARN:        <from terraform output after apply>
RDS engine version (actual, post-apply): <from `aws rds describe-db-instances`, confirm matches 16.15 or whatever version was actually available>
NAT Gateway / EIP allocation ID:      <from terraform output>
Bastion instance ID:                  <from provision-staging-bastion.sh output>
Provisioning started / completed at:  <UTC timestamps>
Bootstrap files applied, in order:    <confirm all six ran without error, paste script output>
Migrations applied:                   <scripts/run-postgres-migrations.py output>
callback_receiver exercised:          <yes/no; if no, state explicitly that this run's acceptance scope excludes the callback-service boundary, per section 4's own note>
RLS activation run:                   <yes/no, timestamp if yes>
Acceptance checks (RLS_STAGING_ACTIVATION.md section 3): <pass/fail per item 1-5>
Bake period start / end, incident count: <>
Backup restoration test (section 8):  <run or not run; if run, measured restore time>
Teardown destroy-plan review:         <confirm the resource list matched expectations before applying it>
Secrets Manager secrets deleted:      <secret ARNs, recovery window or force-deleted>
Final snapshot retained or deleted:   <snapshot identifier if retained, or confirm deleted>
Teardown completed at:                <UTC timestamp, confirm via the describe-db-instances/describe-vpcs checks in section 9>
```

## 11. What this document does not do

It does not run any command in it automatically, does not itself flip RLS on (that remains `RLS_STAGING_ACTIVATION.md`'s own, separately-gated section 2), does not provision CloudHSM, S3 artifact storage, the Cloudflare edge, or any long-lived application compute, and does not, by itself, close P1-2 or P1-8. Closing either requires this plan to actually run, its numbers to actually be recorded in section 10 above, and `RLS_STAGING_ACTIVATION.md`'s own acceptance checks to actually pass, not just to be written down correctly here.
