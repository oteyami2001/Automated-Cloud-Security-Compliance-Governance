terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
  }

  # Partial configuration: terraform init -backend-config=../envs/<env>/backend.hcl
  # (bucket, key, region, encrypt, kms_key_id, use_lockfile = true).
  backend "s3" {}
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.aws_account_id] # wrong account → plan fails before any API change

  default_tags {
    tags = {
      Project            = "acscg"
      Environment        = var.environment
      ManagedBy          = "terraform"
      Owner              = var.owner
      DataClassification = "internal"
      Repository         = "Automated-Cloud-Security-Compliance-Governance"
    }
  }
}

# Used only by the scenario 3 fixture: a resource created WITHOUT the default required tags.
provider "aws" {
  alias               = "untagged"
  region              = var.region
  allowed_account_ids = [var.aws_account_id]
}
