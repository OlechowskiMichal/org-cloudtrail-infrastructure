variable "organization_id" {
  description = "The ID of the AWS Organization"
  type        = string
}

variable "management_account_id" {
  description = "The account ID of the management account"
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

variable "state_bucket_name" {
  description = "S3 bucket name for state backend (monitored by CloudTrail)"
  type        = string
}
