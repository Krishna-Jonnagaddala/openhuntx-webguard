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
