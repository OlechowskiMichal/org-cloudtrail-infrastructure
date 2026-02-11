variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "management_account_id" {
  description = "The account ID of the management account"
  type        = string
}

variable "state_bucket_name" {
  description = "S3 bucket name for state backend (monitored by CloudTrail)"
  type        = string
}

variable "organization_id" {
  description = "The ID of the AWS Organization"
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  type        = string
}
