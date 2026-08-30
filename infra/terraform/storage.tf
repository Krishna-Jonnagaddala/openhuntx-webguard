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

# Slice 18 Terraform security review (requirement 17, Trivy AWS-0089):
# a separate destination bucket, per AWS's own recommendation (a bucket
# should not log to itself). Holds only access-log records -- no
# report/artifact content ever lands here -- so it needs none of the
# artifacts bucket's own SSE-KMS/versioning/retention machinery; SSE-S3
# (the bucket default) and a short expiry are enough for what is purely
# an operational audit trail.
resource "aws_s3_bucket" "artifacts_access_logs" {
  bucket = "webguard-${var.environment_name}-artifacts-access-logs"

  tags = {
    Name        = "webguard-${var.environment_name}-artifacts-access-logs"
    Environment = var.environment_name
    ManagedBy   = "terraform"
    Purpose     = "s3-server-access-logs"
  }
}

resource "aws_s3_bucket_versioning" "artifacts_access_logs" {
  bucket = aws_s3_bucket.artifacts_access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts_access_logs" {
  bucket = aws_s3_bucket.artifacts_access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts_access_logs" {
  bucket = aws_s3_bucket.artifacts_access_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }
}

# Grants the S3 log-delivery service principal write access to this
# bucket only -- the modern (policy-based, not ACL-based) mechanism for
# S3 server access logging, which works even with
# block_public_acls/ignore_public_acls fully enabled above.
# `aws:SourceArn`/`aws:SourceAccount` scope this grant to log deliveries
# that actually originate from the artifacts bucket in this account,
# not an arbitrary bucket anywhere.
data "aws_iam_policy_document" "artifacts_access_logs_delivery" {
  statement {
    sid       = "S3ServerAccessLogsDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts_access_logs.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.artifacts.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts_access_logs" {
  bucket = aws_s3_bucket.artifacts_access_logs.id
  policy = data.aws_iam_policy_document.artifacts_access_logs_delivery.json
}

resource "aws_s3_bucket_logging" "artifacts" {
  bucket        = aws_s3_bucket.artifacts.id
  target_bucket = aws_s3_bucket.artifacts_access_logs.id
  target_prefix = "artifacts-access-logs/"
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

# Slice 18 requirement 18 split the single undifferentiated
# artifact-storage policy this file used to define here into separate,
# read-vs-write, per-responsibility policies -- see iam.tf. Reusing one
# policy for both the API (which only ever reads a generated report
# back for download -- service.py's `artifact_store.get_reference()`)
# and the worker (which is the only process that ever writes one --
# executor.py's `artifact_store.put()`) would grant each process
# permissions the other has no legitimate reason to hold; iam.tf keeps
# that distinction real rather than asserting it only in documentation.
