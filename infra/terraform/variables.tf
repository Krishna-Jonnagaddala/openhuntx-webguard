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

variable "create_staging_bastion_networking" {
  description = "Provisions one public subnet, an internet gateway, a single-AZ NAT Gateway, and the routes that give the private subnets outbound internet access. Default false: a production apply of this configuration provisions none of this, exactly as before this variable existed. Set true only for docs/production/STAGING_ENVIRONMENT_PROVISIONING.md's temporary validation bastion, which needs this path to reach AWS Systems Manager, Secrets Manager, and an OS package repository; see networking.tf's own header for why a security group's default egress rule is not, by itself, enough."
  type        = bool
  default     = false
}

variable "public_subnet_cidr_block" {
  description = "CIDR block for the one public subnet created when create_staging_bastion_networking is true. Must be within vpc_cidr_block and must not overlap private_subnet_cidr_blocks. Unused (and not created) otherwise."
  type        = string
  default     = "10.42.0.128/26"
}

variable "application_security_group_id" {
  description = "Security group ID of the compute (ECS task, EC2 instance, etc.) that will connect to PostgreSQL. PostgreSQL's security group only permits inbound traffic on 5432 from this security group -- never from 0.0.0.0/0. Left as a required variable (no default) since this configuration does not provision compute itself."
  type        = string
}

variable "postgres_engine_version" {
  description = "PostgreSQL major.minor version for RDS. Pin explicitly rather than defaulting to \"latest\" so a provider-side default change never silently changes what gets provisioned. 16.15 is the latest 16.x minor RDS was offering new instances as of the 2026-08 RDS PostgreSQL minor-version announcement (18.6/17.11/16.15/15.19/14.24); this default was previously pinned to 16.4, which predates that by roughly two years of minor releases and should not be assumed still available for new-instance creation. Confirm with `aws rds describe-db-engine-versions --engine postgres --engine-version 16.15 --region <region>` before relying on this default in a real apply, since AWS periodically retires individual old minor versions from new-instance creation independent of major-version end-of-life."
  type        = string
  default     = "16.15"
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

variable "object_storage_retention_days" {
  description = "How long a report/evidence artifact object is kept before S3 expires it (Slice 17 requirement 13). 400 days is a reasonable default retention window for a security-report product; revisit against a real compliance/data-retention policy before relying on it."
  type        = number
  default     = 400

  validation {
    condition     = var.object_storage_retention_days >= 1
    error_message = "object_storage_retention_days must be at least 1."
  }
}

variable "signing_provider" {
  description = "Which TrustScanSigner backend the API and worker are deployed against -- must match WEBGUARD_SIGNING_PROVIDER in the application's own environment configuration (production_config.py). Controls whether the API/worker IAM policies in iam.tf include kms:Sign/kms:GetPublicKey on the TrustScan signing key at all: under \"cloudhsm_signing_service\" (this slice's recommended v1 direction), neither process touches the signing key by any AWS API whatsoever -- they only hold a bearer token for the dedicated signing service (requirement 2). Under \"kms\", each process still constructs its own KmsSigningProvider directly (see production_startup.py) and therefore still needs this narrowly-scoped grant -- a named architectural gap, not an oversight; see docs/production/TRUSTSCAN_SIGNING_SERVICE.md."
  type        = string
  default     = "cloudhsm_signing_service"

  validation {
    condition     = contains(["kms", "cloudhsm_signing_service"], var.signing_provider)
    error_message = "signing_provider must be \"kms\" or \"cloudhsm_signing_service\" -- the same two values production_config.py accepts."
  }
}

variable "cloudhsm_hsm_type" {
  description = "CloudHSM v2 HSM type. hsm2m.medium is the current generation at the time this configuration was written -- confirm against AWS's own CloudHSM documentation before applying, since AWS periodically introduces newer generations."
  type        = string
  default     = "hsm2m.medium"
}

variable "signing_service_security_group_id" {
  description = "Security group ID of the compute that runs the TrustScan Signing Service (webguard-api signing-service). The CloudHSM cluster's auto-created security group only permits inbound CloudHSM client traffic from this security group -- never from the API or worker security groups (requirement 2). No default -- this configuration provisions no compute (see README.md), exactly like application_security_group_id above."
  type        = string
}

variable "object_storage_transition_days" {
  description = "How long a report/evidence artifact object stays in S3 Standard before transitioning to Standard-IA (cheaper, still immediately readable). Must be less than object_storage_retention_days."
  type        = number
  default     = 90

  validation {
    condition     = var.object_storage_transition_days >= 1
    error_message = "object_storage_transition_days must be at least 1."
  }
}

# --- Public edge (Cloudflare) -- Slice 18 requirements 5-9 ---
#
# None of these have a default that assumes openhuntx.com is actually
# on Cloudflare yet (requirement 5: "do not assume these DNS names
# exist unless verified"). An operator who has actually registered the
# domain and created a Cloudflare account supplies real values for all
# of these before ever running `terraform plan` against cloudflare.tf.

variable "cloudflare_account_id" {
  description = "The Cloudflare account ID that will own the openhuntx.com zone. No default (like application_security_group_id above) -- an operator supplies this only once a real Cloudflare account exists."
  type        = string
}

variable "root_domain" {
  description = "The root domain name fronted by Cloudflare. WebGuard's three public hostnames (app./api./callback.) are subdomains of this."
  type        = string
  default     = "openhuntx.com"
}

variable "origin_web_hostname" {
  description = "The real, non-public origin hostname the app.<root_domain> DNS record proxies to (e.g. an internal load balancer's DNS name). No default -- no such origin exists yet in this configuration (it provisions no compute; see README.md)."
  type        = string
}

variable "origin_api_hostname" {
  description = "The real, non-public origin hostname the api.<root_domain> DNS record proxies to. No default -- see origin_web_hostname."
  type        = string
}

variable "origin_callback_hostname" {
  description = "The real, non-public origin hostname the callback.<root_domain> DNS record proxies to. Deliberately a distinct origin from origin_api_hostname -- requirement 15 requires the callback receiver to be independently deployable/scalable from the main API. No default -- see origin_web_hostname."
  type        = string
}

variable "cloudflare_security_level" {
  description = "Cloudflare zone security_level (off/essentially_off/low/medium/high/under_attack). \"medium\" is Cloudflare's own recommended default and is not aggressive enough to challenge normal WebGuard API/browser traffic -- requirement 8 explicitly warns against enabling aggressive rules that break WebGuard workflows."
  type        = string
  default     = "medium"

  validation {
    condition     = contains(["off", "essentially_off", "low", "medium", "high", "under_attack"], var.cloudflare_security_level)
    error_message = "cloudflare_security_level must be one of: off, essentially_off, low, medium, high, under_attack."
  }
}

variable "cloudflare_edge_rate_limit_login_requests_per_minute" {
  description = "Edge-level (Cloudflare) request cap for /v1/auth/login per client IP per minute -- a coarse, complementary outer bound in front of the application's own InMemoryAuthRateLimiter (requirement 10: edge and application limits should complement, not contradict). Deliberately looser than the application's own limit so the application layer, which has the actual per-account lockout logic, is always what actually decides an auth-abuse response; the edge rule exists only to blunt a volumetric flood before it reaches the origin at all."
  type        = number
  default     = 60

  validation {
    condition     = var.cloudflare_edge_rate_limit_login_requests_per_minute >= 1
    error_message = "cloudflare_edge_rate_limit_login_requests_per_minute must be at least 1."
  }
}

variable "cloudflare_edge_rate_limit_asset_verification_requests_per_minute" {
  description = "Edge-level request cap for /v1/assets/*/verification* per client IP per minute -- same complementary-outer-bound rationale as the login limit above."
  type        = number
  default     = 30

  validation {
    condition     = var.cloudflare_edge_rate_limit_asset_verification_requests_per_minute >= 1
    error_message = "cloudflare_edge_rate_limit_asset_verification_requests_per_minute must be at least 1."
  }
}

variable "cloudflare_edge_rate_limit_report_requests_per_minute" {
  description = "Edge-level request cap for /v1/reports* per client IP per minute -- same complementary-outer-bound rationale as the login limit above."
  type        = number
  default     = 60

  validation {
    condition     = var.cloudflare_edge_rate_limit_report_requests_per_minute >= 1
    error_message = "cloudflare_edge_rate_limit_report_requests_per_minute must be at least 1."
  }
}

variable "cloudflare_managed_ruleset_id" {
  description = "Cloudflare's own \"Cloudflare Managed Ruleset\" ID. This is a stable, publicly documented ID (the same for every Cloudflare account/zone -- see Cloudflare's own WAF managed-rules documentation and Terraform examples), not an account-specific secret. Left overridable in case Cloudflare ever changes it."
  type        = string
  default     = "efb7b8c949ac4650a09736fc376e9aee"
}

variable "cloudflare_owasp_ruleset_id" {
  description = "Cloudflare's own \"Cloudflare OWASP Core Ruleset\" ID -- same stable-and-public nature as cloudflare_managed_ruleset_id above."
  type        = string
  default     = "4814384a9e5d4991b9815dcfc25d2f1f"
}
