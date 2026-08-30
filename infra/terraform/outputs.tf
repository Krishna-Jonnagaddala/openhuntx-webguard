output "postgres_endpoint" {
  description = "RDS PostgreSQL connection endpoint (host:port). The application's WEBGUARD_DATABASE_URL is built from this plus the RDS-managed credential retrieved from Secrets Manager -- never printed here."
  value       = aws_db_instance.webguard.endpoint
}

output "postgres_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the RDS-managed master credential. Fetch the credential value out-of-band (e.g. via the deployment pipeline's own IAM-scoped access), never through Terraform output."
  value       = aws_db_instance.webguard.master_user_secret[0].secret_arn
}

output "postgres_security_group_id" {
  description = "Security group ID protecting the RDS instance, for reference when wiring up the application's own security group rules."
  value       = aws_security_group.postgres.id
}

output "trustscan_signing_kms_key_arn" {
  description = "ARN of the TrustScan permit-signing KMS key, for KmsSigningProvider configuration (WEBGUARD_KMS_KEY_ID)."
  value       = aws_kms_key.trustscan_permit_signing.arn
}

output "artifact_storage_bucket_name" {
  description = "S3 bucket name for ObjectStorageArtifactStore configuration (WEBGUARD_OBJECT_STORAGE_BUCKET)."
  value       = aws_s3_bucket.artifacts.id
}

output "artifact_storage_kms_key_arn" {
  description = "ARN of the artifact-storage encryption KMS key, for ObjectStorageArtifactStore configuration (WEBGUARD_OBJECT_STORAGE_KMS_KEY_ID)."
  value       = aws_kms_key.artifact_storage_encryption.arn
}

output "artifact_storage_access_policy_arn" {
  description = "ARN of the least-privilege S3/KMS access policy -- attach this to whatever compute role (e.g. an ECS task role) actually runs the API/worker."
  value       = aws_iam_policy.artifact_storage_access.arn
}
