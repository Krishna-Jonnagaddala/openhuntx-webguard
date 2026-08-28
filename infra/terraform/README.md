# WebGuard Production Infrastructure (Slice 12, requirement 16-17)

## Status: unapplied

**No account has been created, no resource has been provisioned, and
no `terraform apply` has been run against this configuration.** This
is reviewed, syntactically-complete Infrastructure-as-Code for the two
things this slice's own remediation work actually needs -- PostgreSQL
and a signing key -- not a full deployment of the stack recommended in
[`docs/production/PROVIDER_EVALUATION.md`](../../docs/production/PROVIDER_EVALUATION.md).

Per the slice brief: *"Do not create an enormous infrastructure stack
in one change. Focus only on networking foundation where unavoidable,
PostgreSQL, signing/security foundation."* Redis/ElastiCache, S3, ECS
Fargate, Cloudflare, Grafana Cloud, and Postmark are all explicitly
**not** provisioned here -- see
[`docs/production/INFRASTRUCTURE_REQUIREMENTS.md`](../../docs/production/INFRASTRUCTURE_REQUIREMENTS.md)
for why each is deferred rather than built speculatively.

## Scope

| File | Provisions | Why it's here |
|---|---|---|
| `networking.tf` | A VPC, two private subnets across two AZs, a DB subnet group, and a security group scoped to PostgreSQL's port from the application's own security group only | RDS cannot be created without a subnet group; this is the minimum networking a private, non-publicly-accessible database requires -- not a general-purpose network topology |
| `postgres.tf` | One `aws_db_instance` (PostgreSQL, encrypted, private, RDS-managed master password, automated backups enabled) | The Slice 12 PostgreSQL foundation (requirement 4) |
| `signing.tf` | One `aws_kms_key` (`ECC_NIST_P256`, `SIGN_VERIFY`) for the AWS-side counterpart of `KmsSigningProvider` | Requirement 2's KMS-backed signing path -- **note the key spec is ECDSA, not Ed25519**; see below |
| `variables.tf` | Every input this configuration needs, with no unsafe defaults | Nothing here should apply cleanly by accident |
| `outputs.tf` | The RDS endpoint, the KMS key ARN, and the security group ID | What the application's own config (`ProductionServiceConfig`) needs to be told after a real deployment |

Nothing here provisions compute (ECS/Fargate), object storage (S3), a
CDN/WAF (Cloudflare), observability (Grafana Cloud), or email
(Postmark) -- those remain design-only per
`INFRASTRUCTURE_REQUIREMENTS.md` until a slice actually needs them
provisioned.

## The Ed25519 / KMS gap, reflected in this IaC

AWS KMS has no Ed25519 `KeySpec`. `signing.tf`'s
`aws_kms_key.trustscan_permit_signing` therefore requests
`ECC_NIST_P256` with `SIGN_VERIFY` usage -- the AWS-side resource a
`KmsSigningProvider` (see
[`apps/api/src/webguard_api/signing.py`](../../apps/api/src/webguard_api/signing.py))
would actually call, using `ECDSA_SHA_256`. This key is **not** wired
as TrustScan's active signer anywhere in this slice's application
code, and this Terraform resource does not change that -- provisioning
the key is a prerequisite for a *future*, separate, explicit decision
to migrate TrustScan's permit-signing algorithm, not that decision
itself.

## Secrets discipline

No password, API key, or credential appears anywhere in this
directory. The RDS instance uses `manage_master_user_password = true`
(RDS-managed credentials stored in AWS Secrets Manager, never a
Terraform variable or state value) specifically so a database password
never needs to exist in a `.tfvars` file, an environment variable
passed to `terraform apply`, or Git history. `terraform.tfstate` itself
is not checked into this repository (see `.gitignore`) since it can
contain resource attribute values that, while not secrets in this
configuration's case, should never become a Git-tracked artifact as a
matter of general practice.

## Applying this (when there is a reason to)

This configuration intentionally has no configured backend (no S3/
DynamoDB remote state) and no committed `.tfvars` file -- an operator
who actually decides to provision this reads `variables.tf`, supplies
real values for their AWS account/region/VPC CIDR choices, configures
a remote state backend appropriate to their team, and only then runs
`terraform init && terraform plan`. Reviewing the plan output against
`docs/production/INFRASTRUCTURE_REQUIREMENTS.md` and
`docs/production/PROVIDER_EVALUATION.md` before ever running `apply`
is expected, not optional.

No `terraform validate`/`plan` has been run against this configuration
in this environment (no Terraform binary or AWS credentials are
available here) -- it has been reviewed by hand for correctness, not
machine-validated. Run `terraform validate` as the first step before
any real use.
