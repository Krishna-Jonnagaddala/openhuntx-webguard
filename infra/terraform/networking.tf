# Minimal networking foundation -- only what an RDS subnet group and a
# private database actually require. This is not a general-purpose VPC
# design; by default it has no public subnets, no NAT gateway, and no
# internet gateway, since nothing in a real deployment of this
# configuration needs outbound internet access (the application layer
# that reaches RDS is separate compute with its own networking, not
# provisioned here).
#
# var.create_staging_bastion_networking is the one deliberate opt-in
# exception, default false so it changes nothing about a production
# apply. docs/production/STAGING_ENVIRONMENT_PROVISIONING.md's own
# bastion (a temporary EC2 instance reached via AWS Systems Manager
# Session Manager, used only to run bootstrap SQL and the test suite
# against a real RDS instance during P1-2 validation) cannot actually
# reach anything without this: SSM Session Manager needs to reach
# AWS's own SSM service endpoints, and the bastion also needs to
# install OS packages (git, python3, psycopg2's build dependencies)
# and read the RDS master credential from Secrets Manager, none of
# which a security-group egress rule alone makes reachable if the
# subnet itself has no route to the internet at all. A security
# group's default "allow all egress" rule permits the traffic to
# leave the instance; it does not give the SUBNET a path anywhere,
# and those are two separate layers, the second one being what a
# no-NAT/no-IGW private subnet is missing. This block gives the
# bastion exactly that path, one NAT Gateway in one AZ (not
# highly-available: a deliberate corner-cut for a disposable,
# few-hours validation environment, not a production posture), and
# nothing else: no change to the RDS security group, no public IP on
# RDS itself, no route from the private subnets to anywhere except
# through this NAT.

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

resource "aws_internet_gateway" "webguard" {
  count  = var.create_staging_bastion_networking ? 1 : 0
  vpc_id = aws_vpc.webguard.id

  tags = {
    Name        = "webguard-${var.environment_name}-igw"
    Environment = var.environment_name
    ManagedBy   = "terraform"
    Purpose     = "staging-bastion-egress"
  }
}

resource "aws_subnet" "public_nat" {
  count             = var.create_staging_bastion_networking ? 1 : 0
  vpc_id            = aws_vpc.webguard.id
  cidr_block        = var.public_subnet_cidr_block
  availability_zone = var.availability_zones[0]

  # Only the NAT Gateway's own ENI lives here; the bastion stays in
  # the private subnet with no public IP of its own (postgres.tf's
  # RDS instance and the bastion are both unreachable from the
  # internet directly; only this one subnet, holding only the NAT
  # Gateway, is public).
  map_public_ip_on_launch = false

  tags = {
    Name        = "webguard-${var.environment_name}-public-nat"
    Environment = var.environment_name
    ManagedBy   = "terraform"
    Purpose     = "staging-bastion-egress"
  }
}

resource "aws_eip" "nat" {
  count  = var.create_staging_bastion_networking ? 1 : 0
  domain = "vpc"

  tags = {
    Name        = "webguard-${var.environment_name}-nat"
    Environment = var.environment_name
    ManagedBy   = "terraform"
    Purpose     = "staging-bastion-egress"
  }
}

# Single NAT Gateway, single AZ: see this file's header for why a
# non-HA NAT is an accepted corner-cut here (disposable, few-hours
# validation environment) rather than the two-NAT/two-AZ pattern a
# production network would need.
resource "aws_nat_gateway" "webguard" {
  count         = var.create_staging_bastion_networking ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public_nat[0].id
  depends_on    = [aws_internet_gateway.webguard]

  tags = {
    Name        = "webguard-${var.environment_name}-nat"
    Environment = var.environment_name
    ManagedBy   = "terraform"
    Purpose     = "staging-bastion-egress"
  }
}

resource "aws_route_table" "public_nat" {
  count  = var.create_staging_bastion_networking ? 1 : 0
  vpc_id = aws_vpc.webguard.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.webguard[0].id
  }

  tags = {
    Name        = "webguard-${var.environment_name}-public-nat"
    Environment = var.environment_name
    ManagedBy   = "terraform"
    Purpose     = "staging-bastion-egress"
  }
}

resource "aws_route_table_association" "public_nat" {
  count          = var.create_staging_bastion_networking ? 1 : 0
  subnet_id      = aws_subnet.public_nat[0].id
  route_table_id = aws_route_table.public_nat[0].id
}

resource "aws_route_table" "private_egress" {
  count  = var.create_staging_bastion_networking ? 1 : 0
  vpc_id = aws_vpc.webguard.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.webguard[0].id
  }

  tags = {
    Name        = "webguard-${var.environment_name}-private-egress"
    Environment = var.environment_name
    ManagedBy   = "terraform"
    Purpose     = "staging-bastion-egress"
  }
}

# Both private subnets route through the same single NAT Gateway.
# The bastion only ever runs in private_subnet[0] (see
# provision-staging-bastion.sh), but RDS's own subnet group spans both
# for its own two-AZ requirement (Terraform, not this route), so both
# get the egress route for consistency; RDS itself never uses it (it
# has no outbound need and no security-group egress rule permitting
# it).
resource "aws_route_table_association" "private_egress" {
  count          = var.create_staging_bastion_networking ? 2 : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private_egress[0].id
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
