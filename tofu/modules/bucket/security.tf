resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  provider = aws.security_audit

  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  provider = aws.security_audit

  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "cloudtrail-lifecycle"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 180
    }
  }
}

resource "aws_s3_bucket_logging" "cloudtrail" {
  provider = aws.security_audit

  bucket        = aws_s3_bucket.cloudtrail.id
  target_bucket = aws_s3_bucket.cloudtrail_access_logs.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  provider = aws.security_audit

  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket.json
}
