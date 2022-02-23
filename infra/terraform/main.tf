terraform {
  required_version = "~> 1.1.4"

  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region = "ap-southeast-2"
}

# Standardize Naming
module "project_label" {
  source = "cloudposse/label/null"

  namespace = "blueprint"
  //stage     = "demo"
  name      = "rust"
  delimiter = "-"

  tags = {
    owner = "your@email.com"
  }
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {
  provider = aws
}