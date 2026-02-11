variable "bucket_name" {
  description = "Name of the CloudTrail S3 bucket"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for bucket encryption"
  type        = string
}

variable "security_audit_account_id" {
  description = "The account ID of the security-audit account"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "management_account_id" {
  description = "The account ID of the management account"
  type        = string
}

variable "organization_id" {
  description = "The ID of the AWS Organization"
  type        = string
}
