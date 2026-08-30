# WebGuard Production Infrastructure (Slice 12 requirements 16-17; extended in Slice 17 requirement 23)

## Status: unapplied

**No account has been created, no resource has been provisioned, and
no `terraform apply` has been run against this configuration.** This
is reviewed, syntactically-complete Infrastructure-as-Code for what
this project's completed slices actually need -- PostgreSQL, a signing
key, and (Slice 17) object storage for generated reports -- not a full
deployment of the stack recommended in
[`docs/production/PROVIDER_EVALUATION.md`](../../docs/production/PROVIDER_EVALUATION.md).

Per the original slice brief: *"Do not create an enormous
infrastructure stack in one change."* Each addition since has followed
the same discipline -- provision exactly what the slice that needs it
requires, nothing speculative. Redis/ElastiCache, ECS Fargate,
Cloudflare, and Grafana Cloud are still **not** provisioned here -- see
[`docs/production/INFRASTRUCTURE_REQUIREMENTS.md`](../../docs/production/INFRASTRUCTURE_REQUIREMENTS.md)
for why each is deferred rather than built speculatively. Postmark
(Slice 17's transactional-email provider) has no Terraform-manageable
AWS-side resource at all -- see
[`docs/production/TRANSACTIONAL_EMAIL.md`](../../docs/production/TRANSACTIONAL_EMAIL.md)
for its configuration, which lives in application environment
variables, not this directory.

## Scope

| File | Provisions | Why it's here |
|---|---|---|
| `networking.tf` | A VPC, two private subnets across two AZs, a DB subnet group, and a security group scoped to PostgreSQL's port from the application's own security group only | RDS cannot be created without a subnet group; this is the minimum networking a private, non-publicly-accessible database requires -- not a general-purpose network topology |
| `postgres.tf` | One `aws_db_instance` (PostgreSQL, encrypted, private, RDS-managed master password, automated backups enabled) | The Slice 12 PostgreSQL foundation (requirement 4) |
| `signing.tf` | One `aws_kms_key` (`ECC_NIST_P256`, `SIGN_VERIFY`) for the AWS-side counterpart of `KmsSigningProvider` | Requirement 2's KMS-backed signing path -- **note the key spec is ECDSA, not Ed25519**; see below |
| `storage.tf` | One S3 bucket (versioned, SSE-KMS encrypted with a dedicated key, public access fully blocked, a bucket policy denying insecure/unencrypted writes, a lifecycle policy for retention), plus a least-privilege IAM policy for the compute role that runs the API/worker | Slice 17 requirements 7-13's real object-storage backend for `ObjectStorageArtifactStore` -- see [`docs/production/ARTIFACT_STORAGE.md`](../../docs/production/ARTIFACT_STORAGE.md) for the full design |
| `variables.tf` | Every input this configuration needs, with no unsafe defaults | Nothing here should apply cleanly by accident |
| `outputs.tf` | The RDS endpoint, the KMS key ARNs, the S3 bucket name, the IAM policy ARN, and the security group ID | What the application's own config (`ProductionServiceConfig`) needs to be told after a real deployment |

Nothing here provisions compute (ECS/Fargate), a CDN/WAF (Cloudflare),
or observability (Grafana Cloud) -- those remain design-only per
`INFRASTRUCTURE_REQUIREMENTS.md` until a slice actually needs them
provisioned. `storage.tf`'s IAM policy is deliberately a standalone,
attachable `aws_iam_policy` resource, not a full IAM role -- provisioning
compute (and the role it would run under) remains out of this
directory's scope, exactly like every other resource here that would
require it.

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

## Object-storage encryption, retention, and IAM (Slice 17)

`storage.tf` uses **SSE-KMS with a dedicated customer-managed key**
(`aws_kms_key.artifact_storage_encryption`), not the AWS-managed
SSE-S3 default -- a deliberate choice (`docs/production/ARTIFACT_STORAGE.md`
§3 has the full comparison), mirroring `postgres.tf`'s own dedicated
RDS encryption key rather than introducing a second pattern. The
bucket policy independently denies any insecure (`http`) or
unencrypted `PutObject` request regardless of what the application
sends -- defense in depth beyond the application always specifying the
right parameters. Retention (`object_storage_retention_days`,
`object_storage_transition_days` in `variables.tf`) is one uniform
lifecycle policy today; there is no per-organization override, a named
gap (`docs/production/ARTIFACT_STORAGE.md` §5). The IAM policy this
file provisions (`aws_iam_policy.artifact_storage_access`) is scoped to
exactly the S3 actions `ObjectStorageArtifactStore` calls against this
one bucket, plus the two KMS actions needed to use this one key --
never a wildcard resource. It is not attached to anything by this
configuration (no compute/IAM role exists here to attach it to);
attach it to whatever real compute role a deployment runs the API/
worker under.

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
