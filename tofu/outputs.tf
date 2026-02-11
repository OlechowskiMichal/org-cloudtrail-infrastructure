output "trail_arn" {
  description = "The ARN of the organization CloudTrail"
  value       = aws_cloudtrail.org_trail.arn
}

output "kms_key_arn" {
  description = "The ARN of the KMS key used for CloudTrail encryption"
  value       = aws_kms_key.cloudtrail.arn
}

output "bucket_name" {
  description = "The name of the CloudTrail S3 bucket"
  value       = aws_s3_bucket.cloudtrail.id
}

output "security_alerts_topic_arn" {
  description = "The ARN of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}
