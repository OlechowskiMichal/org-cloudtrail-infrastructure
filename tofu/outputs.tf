output "trail_arn" {
  description = "The ARN of the organization CloudTrail"
  value       = module.trail.trail_arn
}

output "kms_key_arn" {
  description = "The ARN of the KMS key used for CloudTrail encryption"
  value       = module.trail.kms_key_arn
}

output "kms_key_id" {
  description = "KMS key ID for use by security alerting module"
  value       = module.trail.kms_key_id
}

output "bucket_name" {
  description = "The name of the CloudTrail S3 bucket"
  value       = module.bucket.bucket_id
}

output "cloudwatch_log_group_name" {
  description = "CloudWatch log group name for metric filters"
  value       = module.trail.cloudwatch_log_group_name
}
