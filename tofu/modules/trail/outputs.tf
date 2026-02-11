output "trail_arn" {
  description = "The ARN of the organization CloudTrail"
  value       = aws_cloudtrail.org_trail.arn
}

output "kms_key_arn" {
  description = "The ARN of the KMS key used for CloudTrail encryption"
  value       = aws_kms_key.cloudtrail.arn
}

output "kms_key_id" {
  description = "The ID of the KMS key used for CloudTrail encryption"
  value       = aws_kms_key.cloudtrail.id
}

output "cloudwatch_log_group_arn" {
  description = "The ARN of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.cloudtrail.arn
}

output "cloudwatch_log_group_name" {
  description = "The name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "cloudtrail_bucket_name" {
  description = "The name of the CloudTrail S3 bucket"
  value       = var.cloudtrail_bucket_name
}
