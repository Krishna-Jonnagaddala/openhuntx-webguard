# Production artifact object storage (Slice 17 requirements 7-13).
# Completes `ObjectStorageArtifactStore` (apps/api/src/webguard_api/
# artifact_store.py) with the real AWS-side resource it writes
# generated reports to. Scope discipline matches every other file in
# this directory (see signing.tf/postgres.tf's own README notes): only
# what this slice's own object-storage requirement needs -- one
# bucket, one dedicated KMS key, one least-privilege IAM policy, one
# lifecycle policy. No compute (ECS/Fargate) is provisioned here, same
# as everywhere else in this configuration -- the IAM policy below is
# meant to be attached to whatever compute role a real deployment
# eventually runs the API/worker under.

# A dedicated customer-managed KMS key for SSE-KMS, not the AWS-managed
# SSE-S3 default -- mirrors postgres.tf's own
# `aws_kms_key.rds_storage_encryption` pattern exactly, and matches
# `docs/production/ARTIFACT_STORAGE.md` §3's deliberate encryption
# choice: a customer-managed key gives per-principal CloudTrail
# auditing and a real revocation path (disable/schedule-deletion of
# this key) that the AWS-managed SSE-S3 key cannot offer.
resource "aws_kms_key" "artifact_storage_encryption" {
  description             = "Encrypts WebGuard report/artifact objects in S3 at rest (SSE-KMS)."
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "webguard-${var.environment_name}-artifact-storage"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "artifact_storage_encryption" {
  name          = "alias/webguard-${var.environment_name}-artifact-storage"
  target_key_id = aws_kms_key.artifact_storage_encryption.key_id
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "webguard-${var.environment_name}-artifacts"

  tags = {
    Name        = "webguard-${var.environment_name}-artifacts"
    Environment = var.environment_name
    ManagedBy   = "terraform"
    Purpose     = "generated-reports-and-evidence-artifacts"
  }
}

# Versioning is defense in depth against the "arbitrary overwrite"
# concern requirement 9 names -- object keys are always server-
# generated (see artifact_store.py's own docstring) so an overwrite
# should never legitimately happen, but a bug or a compromised
# credential that did overwrite a report would leave the prior version
# recoverable rather than silently gone.
resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.artifact_storage_encryption.arn
    }
    # Reduces KMS API call volume/cost for frequent small-object
    # writes (every completed scan's report) -- does not weaken the
    # encryption guarantee, only how often a fresh data key is
    # requested from KMS.
    bucket_key_enabled = true
  }
}

# Requirement 11: the customer must never see an unrestricted bucket
# URL or a permanent public object. This bucket is never public by any
# mechanism -- no bucket ACL, no bucket policy grant, no object ACL.
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket-policy-level enforcement, independent of the application
# always passing the right parameters (defense in depth, requirement
# 10): denies any request over plain HTTP, and denies any PutObject
# that does not specify SSE-KMS -- so even a misconfigured or
# compromised caller cannot write an unencrypted or publicly-readable
# object into this bucket.
data "aws_iam_policy_document" "artifacts_bucket_policy" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyUnencryptedObjectUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid       = "DenyWrongKmsKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.artifact_storage_encryption.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts_bucket_policy.json
}

# Requirement 13: retention. Reports/evidence are not left indefinitely
# merely because storage is inexpensive -- transition to a cheaper
# storage class first (still immediately readable, just costs less),
# then expire outright after `object_storage_retention_days`. Both are
# operator-tunable (variables.tf), and `abort_incomplete_multipart_upload`
# cleans up any interrupted upload rather than leaving orphaned parts
# billed forever -- covering the "failed/incomplete artifact uploads"
# retention case explicitly.
#
# This is one uniform policy for every object today -- there is no
# per-organization retention override yet (see
# docs/production/ARTIFACT_STORAGE.md §5 for the honestly-named gap and
# the object-tagging extension point a future slice would use to add
# one, without needing a second bucket or a rule per organization).
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-and-transition-artifacts"
    status = "Enabled"

    filter {}

    transition {
      days          = var.object_storage_transition_days
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.object_storage_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Least-privilege access policy for whatever compute identity actually
# runs the API/worker (an ECS task role, in the stack
# docs/production/PROVIDER_EVALUATION.md recommends -- not provisioned
# here, matching this directory's existing "no compute" scope). Scoped
# to exactly the four S3 actions ObjectStorageArtifactStore calls, this
# bucket only, plus the KMS actions needed to use its specific
# encryption key -- never a wildcard resource, never access to any
# other bucket or key.
data "aws_iam_policy_document" "artifact_storage_access" {
  statement {
    sid    = "ArtifactObjectAccess"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
    ]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
  }

  statement {
    sid       = "ArtifactBucketMetadataAccess"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.artifacts.arn]
  }

  statement {
    sid    = "ArtifactEncryptionKeyAccess"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = [aws_kms_key.artifact_storage_encryption.arn]
  }
}

resource "aws_iam_policy" "artifact_storage_access" {
  name        = "webguard-${var.environment_name}-artifact-storage-access"
  description = "Least-privilege S3/KMS access for the WebGuard API/worker's ObjectStorageArtifactStore -- attach to the compute role that runs them."
  policy      = data.aws_iam_policy_document.artifact_storage_access.json

  tags = {
    Name        = "webguard-${var.environment_name}-artifact-storage-access"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}
