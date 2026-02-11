variable "kms_key_id" {
  description = "The ID of the KMS key for SNS encryption"
  type        = string
}

variable "cloudwatch_log_group_name" {
  description = "The name of the CloudWatch log group for metric filters"
  type        = string
}

variable "budget_alert_email" {
  description = "Email address for security alert notifications"
  type        = string
  sensitive   = true
}
