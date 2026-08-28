variable "aws_region" {
  description = "AWS region for the production PostgreSQL and KMS resources. docs/production/PROVIDER_EVALUATION.md recommends eu-west-2 (London) or eu-west-1 (Dublin) for UK/EU data residency."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "aws_region must be a valid AWS region identifier, e.g. eu-west-2."
  }
}

variable "environment_name" {
  description = "A short identifier for this deployment (e.g. \"production\"), used to tag every resource this configuration creates."
  type        = string

  validation {
    condition     = length(var.environment_name) > 0 && length(var.environment_name) <= 32
    error_message = "environment_name must be 1-32 characters."
  }
}

variable "vpc_cidr_block" {
  description = "CIDR block for the VPC this configuration creates. Kept small and private-only -- this VPC exists to give RDS a subnet group, not as general-purpose network infrastructure."
  type        = string
  default     = "10.42.0.0/24"
}

variable "private_subnet_cidr_blocks" {
  description = "Exactly two private subnet CIDR blocks, one per availability zone, both within vpc_cidr_block. RDS requires at least two subnets in two AZs for its subnet group even in single-AZ mode."
  type        = list(string)
  default     = ["10.42.0.0/26", "10.42.0.64/26"]

  validation {
    condition     = length(var.private_subnet_cidr_blocks) == 2
    error_message = "Exactly two private subnet CIDR blocks are required."
  }
}

variable "availability_zones" {
  description = "Exactly two availability zones within aws_region to place the private subnets in."
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) == 2
    error_message = "Exactly two availability zones are required."
  }
}

variable "application_security_group_id" {
  description = "Security group ID of the compute (ECS task, EC2 instance, etc.) that will connect to PostgreSQL. PostgreSQL's security group only permits inbound traffic on 5432 from this security group -- never from 0.0.0.0/0. Left as a required variable (no default) since this configuration does not provision compute itself."
  type        = string
}

variable "postgres_engine_version" {
  description = "PostgreSQL major.minor version for RDS. Pin explicitly rather than defaulting to \"latest\" so a provider-side default change never silently changes what gets provisioned."
  type        = string
  default     = "16.4"
}

variable "postgres_instance_class" {
  description = "RDS instance class. db.t4g.micro is a reasonable small-scale starting point; this is not a scale recommendation, only a safe default that will not surprise anyone with cost."
  type        = string
  default     = "db.t4g.micro"
}

variable "postgres_allocated_storage_gb" {
  description = "Initial allocated storage in GB for the RDS instance."
  type        = number
  default     = 20

  validation {
    condition     = var.postgres_allocated_storage_gb >= 20
    error_message = "postgres_allocated_storage_gb must be at least 20 (the RDS PostgreSQL minimum)."
  }
}

variable "postgres_backup_retention_days" {
  description = "Automated backup retention period in days (requirement 18). RDS's maximum is 35."
  type        = number
  default     = 7

  validation {
    condition     = var.postgres_backup_retention_days >= 1 && var.postgres_backup_retention_days <= 35
    error_message = "postgres_backup_retention_days must be from 1 to 35."
  }
}

variable "postgres_multi_az" {
  description = "Whether to provision a Multi-AZ standby replica. False by default (cost-conscious starting point) -- flip to true once real traffic justifies the added availability."
  type        = bool
  default     = false
}

variable "postgres_deletion_protection" {
  description = "Whether RDS deletion protection is enabled. True by default -- a production database should never be destroyable by a single terraform destroy without first disabling this explicitly."
  type        = bool
  default     = true
}
