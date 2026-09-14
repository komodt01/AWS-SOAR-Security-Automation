terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # Uncomment to use an S3 backend for shared environments.
  # Production use would require an appropriately secured state bucket
  # and state-locking configuration.
  #
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "soar/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-state-lock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "aws-soar-security-automation"
      Owner       = "security-architecture"
      ManagedBy   = "Terraform"
      Environment = var.environment
    }
  }
}
