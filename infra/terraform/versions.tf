terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
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

# No `api_token` attribute set here -- the provider reads
# CLOUDFLARE_API_TOKEN from the environment on its own (requirement 19:
# no secret ever appears in Terraform source or Git). See
# cloudflare.tf's own header comment for the full public-edge scope.
provider "cloudflare" {}
