terraform {
  # >= 1.10 for native S3 state locking (use_lockfile).
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
  }

  # Local state for the first apply; then migrate to the bucket this configuration creates
  # (backend.tf.example → backend.tf, git-ignored because the bucket name contains the account ID).
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = {
      Project            = "acscg"
      Environment        = "shared"
      ManagedBy          = "terraform"
      Owner              = var.owner
      DataClassification = "internal"
      Repository         = "Automated-Cloud-Security-Compliance-Governance"
      Component          = "bootstrap"
    }
  }
}
