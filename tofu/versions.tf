terraform {
  required_version = "~> 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  # S3 backend for state storage
  # Replace placeholder values with your state backend outputs
  backend "s3" {
    bucket         = "REPLACE_BUCKET_NAME"
    key            = "REPLACE_KEY"
    region         = "REPLACE_REGION"
    dynamodb_table = "REPLACE_DYNAMODB_TABLE"
    encrypt        = true
  }
}
