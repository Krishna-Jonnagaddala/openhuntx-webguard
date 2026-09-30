# Production PostgreSQL (Slice 12 requirement 4). No master password
# variable exists anywhere in this configuration -- manage_master_user_password
# delegates credential generation and storage entirely to AWS Secrets
# Manager, so a database password never needs to exist in a .tfvars
# file, a `terraform apply -var` invocation, or this repository's Git
# history.

resource "aws_kms_key" "rds_storage_encryption" {
  description             = "Encrypts the WebGuard RDS PostgreSQL instance at rest."
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "webguard-${var.environment_name}-rds-storage"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}

resource "aws_db_instance" "webguard" {
  identifier     = "webguard-${var.environment_name}"
  engine         = "postgres"
  engine_version = var.postgres_engine_version
  instance_class = var.postgres_instance_class

  allocated_storage     = var.postgres_allocated_storage_gb
  max_allocated_storage = var.postgres_allocated_storage_gb * 4
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds_storage_encryption.arn

  db_name  = "webguard"
  username = "webguard"

  # RDS-managed credential -- generated and rotated by AWS Secrets
  # Manager, never surfaced to Terraform state or this configuration.
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.webguard.name
  vpc_security_group_ids = [aws_security_group.postgres.id]
  publicly_accessible    = false
  multi_az               = var.postgres_multi_az

  backup_retention_period   = var.postgres_backup_retention_days
  backup_window             = "03:00-04:00"
  maintenance_window        = "mon:04:30-mon:05:30"
  copy_tags_to_snapshot     = true
  deletion_protection       = var.postgres_deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "webguard-${var.environment_name}-final"

  # Point-in-time recovery is implicit in RDS whenever automated
  # backups are enabled (backup_retention_period > 0) -- there is no
  # separate PITR toggle to set.
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Slice 18 Terraform security review (requirement 17): purely
  # additive -- this only makes IAM-token authentication *possible* for
  # a database user later granted the `rds_iam` role; it does not
  # disable, replace, or weaken manage_master_user_password above, and
  # no application code or connection string changes as a result of
  # enabling it. Kept on as a defense-in-depth emergency-access path
  # (e.g. break-glass access authenticated by IAM rather than a stored
  # password) that costs nothing to leave available.
  iam_database_authentication_enabled = true

  # Slice 18 Terraform security review (requirement 17, Trivy AWS-0133):
  # session-level diagnostic data (active queries, wait events) that
  # would materially help investigate a suspected compromise or a
  # runaway query -- not enabled purely for performance tuning.
  # Encrypted with the same CMK already protecting this instance's
  # storage, rather than introducing a second key for one database.
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.rds_storage_encryption.arn
  performance_insights_retention_period = 7

  tags = {
    Name        = "webguard-${var.environment_name}"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}
