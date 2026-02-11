output "trail_arn" {
  description = "The ARN of the organization CloudTrail"
  value       = module.trail.trail_arn
}

output "kms_key_arn" {
  description = "The ARN of the KMS key used for CloudTrail encryption"
  value       = module.trail.kms_key_arn
}

output "bucket_name" {
  description = "The name of the CloudTrail S3 bucket"
  value       = module.bucket.bucket_id
}

output "security_alerts_topic_arn" {
  description = "The ARN of the security alerts SNS topic"
  value       = module.alerting.security_alerts_topic_arn
}
