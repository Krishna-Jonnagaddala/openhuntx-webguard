# Minimal networking foundation -- only what an RDS subnet group and a
# private database actually require. This is not a general-purpose VPC
# design; it deliberately has no public subnets, no NAT gateway, and no
# internet gateway, since nothing provisioned in this configuration
# needs outbound internet access.

resource "aws_vpc" "webguard" {
  cidr_block           = var.vpc_cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "webguard-${var.environment_name}"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.webguard.id
  cidr_block        = var.private_subnet_cidr_blocks[count.index]
  availability_zone = var.availability_zones[count.index]

  # No public IP assignment -- these subnets host only RDS, which is
  # never publicly accessible in this configuration.
  map_public_ip_on_launch = false

  tags = {
    Name        = "webguard-${var.environment_name}-private-${count.index}"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}

resource "aws_db_subnet_group" "webguard" {
  name       = "webguard-${var.environment_name}"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name        = "webguard-${var.environment_name}"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}

resource "aws_security_group" "postgres" {
  name        = "webguard-${var.environment_name}-postgres"
  description = "Allows PostgreSQL access only from the application's own security group."
  vpc_id      = aws_vpc.webguard.id

  tags = {
    Name        = "webguard-${var.environment_name}-postgres"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}

resource "aws_security_group_rule" "postgres_ingress_from_application" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.postgres.id
  source_security_group_id = var.application_security_group_id
  description              = "PostgreSQL from the application layer only -- never 0.0.0.0/0."
}


# Slice 18 Terraform security review (requirement 17): this security
# group deliberately defines NO egress rule at all -- an AWS security
# group with zero egress rules denies all outbound traffic by default.
# An earlier version of this file had a 0.0.0.0/0 egress rule "for
# AWS-managed traffic, patching, etc.", but RDS's own patching, backup,
# encryption-key use, and credential rotation are all performed by the
# RDS control plane out-of-band -- not by the database instance
# dialing out over this security group -- so there is no legitimate
# traffic this instance actually needs to originate. Tightening this
# closed a real scanner finding (Trivy AWS-0104, CRITICAL) rather than
# just documenting it as accepted.

# Slice 18 Terraform security review (requirement 17): VPC Flow Logs
# (Trivy AWS-0178). A CloudWatch Logs destination is used rather than
# S3 -- simpler for this single-VPC configuration, and consistent with
# postgres.tf's own use of CloudWatch for RDS log exports. Encrypted
# with a dedicated CMK (Trivy AWS-0017) rather than CloudWatch's
# AWS-managed default -- mirrors every other resource in this
# configuration's own "dedicated customer-managed key" choice
# (postgres.tf, storage.tf, signing.tf).
resource "aws_kms_key" "vpc_flow_logs_encryption" {
  description             = "Encrypts the WebGuard VPC flow log group at rest."
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.vpc_flow_logs_encryption.json

  tags = {
    Name        = "webguard-${var.environment_name}-vpc-flow-logs"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}

# CloudWatch Logs encryption requires the log-group's *service*
# principal to be granted key use directly in the key policy -- an IAM
# policy attached to a role is not sufficient, since it is the
# `logs.<region>.amazonaws.com` service itself (not a role) making the
# Encrypt/Decrypt calls on the log group's behalf. Scoped with an
# `aws:SourceArn` condition to exactly this VPC's flow-log group, so
# this key cannot be used to encrypt any other account log group.
data "aws_iam_policy_document" "vpc_flow_logs_encryption" {
  statement {
    sid       = "EnableAccountRootFullAccess"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogsServiceUse"
    effect = "Allow"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/webguard/${var.environment_name}/vpc-flow-logs"]
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/webguard/${var.environment_name}/vpc-flow-logs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.vpc_flow_logs_encryption.arn

  tags = {
    Name        = "webguard-${var.environment_name}-vpc-flow-logs"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}

data "aws_iam_policy_document" "vpc_flow_logs_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "vpc_flow_logs" {
  name               = "webguard-${var.environment_name}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.vpc_flow_logs_assume_role.json

  tags = {
    Name        = "webguard-${var.environment_name}-vpc-flow-logs"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}

# Scoped to exactly the one log group above -- this role can deliver
# flow-log records and nothing else (no access to any other log group,
# no access to any other AWS service).
data "aws_iam_policy_document" "vpc_flow_logs_delivery" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"]
  }
}

resource "aws_iam_role_policy" "vpc_flow_logs_delivery" {
  name   = "webguard-${var.environment_name}-vpc-flow-logs-delivery"
  role   = aws_iam_role.vpc_flow_logs.id
  policy = data.aws_iam_policy_document.vpc_flow_logs_delivery.json
}

resource "aws_flow_log" "webguard" {
  vpc_id               = aws_vpc.webguard.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn         = aws_iam_role.vpc_flow_logs.arn

  tags = {
    Name        = "webguard-${var.environment_name}-vpc-flow-log"
    Environment = var.environment_name
    ManagedBy   = "terraform"
  }
}
