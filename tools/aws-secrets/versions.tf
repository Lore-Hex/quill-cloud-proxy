terraform {
  required_version = ">= 1.7, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region              = "eu-west-1"
  allowed_account_ids = ["330422590279"]
}

provider "aws" {
  alias               = "paris"
  region              = "eu-west-3"
  allowed_account_ids = ["330422590279"]
}
