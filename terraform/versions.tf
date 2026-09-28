terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60.0, < 7.0.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # For team / production use, store state remotely. See backend.tf.example.
}

provider "aws" {
  region = var.region

  default_tags {
    tags = merge(
      {
        Project   = var.project_name
        ManagedBy = "terraform"
        Purpose   = "security-forensics"
      },
      var.tags,
    )
  }
}
