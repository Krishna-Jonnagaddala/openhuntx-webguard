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

resource "aws_security_group_rule" "postgres_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.postgres.id
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Standard unrestricted egress for the DB instance itself (AWS-managed traffic, patching, etc.)."
}
