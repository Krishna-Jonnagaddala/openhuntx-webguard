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

  tags = {
    Name        = "webguard-${var.environment_name}"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}
