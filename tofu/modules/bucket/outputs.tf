output "bucket_id" {
  description = "The ID of the CloudTrail S3 bucket"
  value       = aws_s3_bucket.cloudtrail.id
}

output "bucket_arn" {
  description = "The ARN of the CloudTrail S3 bucket"
  value       = aws_s3_bucket.cloudtrail.arn
}

output "access_logs_bucket_id" {
  description = "The ID of the access logs S3 bucket"
  value       = aws_s3_bucket.cloudtrail_access_logs.id
}
