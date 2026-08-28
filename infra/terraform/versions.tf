terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # No backend configured deliberately -- see README.md "Applying
  # this". An operator who actually provisions this must choose and
  # configure a remote state backend appropriate to their team before
  # running `terraform init`.
}

provider "aws" {
  region = var.aws_region
}
