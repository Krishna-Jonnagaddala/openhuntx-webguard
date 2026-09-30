# Per-responsibility IAM policies (Slice 18 requirement 18): "worker
# access to S3 does not imply CloudHSM admin permission; API access to
# Postgres does not imply unrestricted KMS admin." Four roles are named
# in the brief -- API, worker, callback, signing-service -- and each is
# addressed below, though not all four get a Terraform resource, and
# that asymmetry is itself the point:
#
#   * API and worker each get a real, distinct aws_iam_policy (below) --
#     read-only vs write-only artifact access, split by which process
#     actually calls which artifact_store method (see storage.tf's own
#     comment for the exact call sites).
#   * The callback service (webguard-api callback-service) gets NO
#     policy here, deliberately: it never calls S3, KMS, or the signing
#     key in any form (callback_server.py only ever talks to Postgres,
#     which is network+credential authenticated, not IAM-authenticated).
#     A policy with zero legitimate statements is not "least privilege
#     expressed as an empty resource" -- it is a resource that
#     shouldn't exist. Its absence here is the least-privilege boundary,
#     not a gap.
#   * The signing service (webguard-api signing-service) also gets no
#     KMS/CloudHSM IAM policy here, for a similar but distinct reason:
#     CloudHSM's *data-plane* key-use boundary (actually signing a
#     message) is enforced by the HSM's own Crypto User
#     authentication (a PIN, delivered through the existing
#     SecretProvider architecture -- requirement 19), not by AWS IAM,
#     and CloudHSM's network boundary is the security-group rule in
#     cloudhsm.tf, not an IAM policy either. There is therefore no
#     meaningful `aws_iam_policy` statement that would narrow the
#     signing service's access beyond what the security group and HSM
#     Crypto User already do. (An operator who *also* needs
#     control-plane CloudHSM permissions -- describing the cluster,
#     managing backups -- for a separate operations/automation role
#     should scope that separately to `cloudhsm:Describe*` actions;
#     that is an operator-identity concern, not the signing service's
#     own runtime identity, so it is out of this file's scope.)

# --- API role ---
#
# Read-only artifact access (service.py's `artifact_store.get_reference()`
# is the only call site) plus, only when signing_provider = "kms",
# narrowly-scoped use of the one TrustScan signing key -- never
# kms:CreateKey, kms:ScheduleKeyDeletion, kms:PutKeyPolicy, or any other
# key-administration action, and never access to any other KMS key
# (e.g. the artifact-storage encryption key is reached with Decrypt
# only, and the signing key, when granted at all, is reached with
# Sign/GetPublicKey only -- the two grants are never combined into one
# statement with a shared resource list, so neither key's permission
# set can accidentally widen the other's).
data "aws_iam_policy_document" "api_service_access" {
  statement {
    sid       = "ArtifactObjectRead"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
  }

  statement {
    sid       = "ArtifactBucketMetadataAccess"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.artifacts.arn]
  }

  statement {
    sid       = "ArtifactEncryptionKeyDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.artifact_storage_encryption.arn]
  }

  dynamic "statement" {
    for_each = var.signing_provider == "kms" ? [1] : []
    content {
      sid       = "TrustScanSigningKeyUse"
      effect    = "Allow"
      actions   = ["kms:Sign", "kms:GetPublicKey"]
      resources = [aws_kms_key.trustscan_permit_signing.arn]
    }
  }
}

resource "aws_iam_policy" "api_service_access" {
  name        = "webguard-${var.environment_name}-api-service-access"
  description = "Least-privilege access for the compute role running `webguard-api serve`: read-only artifact access, no CloudHSM/signing-service permissions of any kind (it calls the signing service over HTTP, not AWS APIs)."
  policy      = data.aws_iam_policy_document.api_service_access.json

  tags = {
    Name        = "webguard-${var.environment_name}-api-service-access"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}

# --- Worker role ---
#
# Write-only artifact access (executor.py's `artifact_store.put()` is
# the only call site -- the worker never reads a report back) plus,
# only when signing_provider = "kms", the same narrowly-scoped signing-
# key grant the API gets -- both processes construct their own
# KmsSigningProvider under that mode (see production_startup.py), so
# both legitimately need it; what this policy still refuses the worker
# is everything CloudHSM/KMS *administration* would require, and any
# permission on any other key or bucket.
data "aws_iam_policy_document" "worker_service_access" {
  statement {
    sid       = "ArtifactObjectWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
  }

  statement {
    sid       = "ArtifactEncryptionKeyEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey"]
    resources = [aws_kms_key.artifact_storage_encryption.arn]
  }

  dynamic "statement" {
    for_each = var.signing_provider == "kms" ? [1] : []
    content {
      sid       = "TrustScanSigningKeyUse"
      effect    = "Allow"
      actions   = ["kms:Sign", "kms:GetPublicKey"]
      resources = [aws_kms_key.trustscan_permit_signing.arn]
    }
  }
}

resource "aws_iam_policy" "worker_service_access" {
  name        = "webguard-${var.environment_name}-worker-service-access"
  description = "Least-privilege access for the compute role running `webguard-api worker`: write-only artifact access, no CloudHSM administration permission of any kind."
  policy      = data.aws_iam_policy_document.worker_service_access.json

  tags = {
    Name        = "webguard-${var.environment_name}-worker-service-access"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}
