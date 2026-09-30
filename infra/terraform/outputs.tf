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

output "api_service_access_policy_arn" {
  description = "ARN of the API role's least-privilege policy (read-only artifact access, plus TrustScan permit-signing key use when signing_provider = \"kms\") -- attach to whatever compute role runs `webguard-api serve`."
  value       = aws_iam_policy.api_service_access.arn
}

output "worker_service_access_policy_arn" {
  description = "ARN of the worker role's least-privilege policy (write-only artifact access, plus TrustScan signing key use when signing_provider = \"kms\") -- attach to whatever compute role runs `webguard-api worker`."
  value       = aws_iam_policy.worker_service_access.arn
}

output "cloudhsm_cluster_id" {
  description = "CloudHSM v2 cluster ID -- needed for the manual activation ceremony documented in cloudhsm.tf (initialize-cluster, crypto user creation) before the TrustScan Signing Service can use it."
  value       = aws_cloudhsm_v2_cluster.trustscan_signing.cluster_id
}

output "cloudflare_zone_id" {
  description = "Cloudflare zone ID for openhuntx.com -- needed by any future Cloudflare resource added outside this configuration."
  value       = cloudflare_zone.openhuntx.id
}

output "cloudflare_zone_name_servers" {
  description = "The Cloudflare-assigned nameservers for openhuntx.com. An operator updates the domain registrar's NS records to these values to actually activate the zone -- Terraform cannot do this step, since it happens at the registrar, not Cloudflare."
  value       = cloudflare_zone.openhuntx.name_servers
}
