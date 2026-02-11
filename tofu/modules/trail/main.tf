resource "aws_cloudtrail" "org_trail" {
  name                       = "org-trail"
  s3_bucket_name             = var.cloudtrail_bucket_name
  is_organization_trail      = true
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = aws_kms_key.cloudtrail.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      values = [
        "arn:aws:s3:::${var.cloudtrail_bucket_name}/",
        "arn:aws:s3:::${var.state_bucket_name}/",
      ]
    }
  }

  depends_on = [aws_kms_key.cloudtrail]
}
