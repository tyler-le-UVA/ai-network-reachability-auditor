terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Remote state in S3 with native locking (no DynamoDB table needed on Terraform >= 1.10).
  # Backend blocks can't use variables, so replace the bucket name with your own.
  backend "s3" {
    bucket       = "tf-state-209901331329-us-east-1"
    key          = "network-auditor/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  # Every resource this project creates gets these tags automatically.
  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Repo      = var.repo_name
    }
  }
}
