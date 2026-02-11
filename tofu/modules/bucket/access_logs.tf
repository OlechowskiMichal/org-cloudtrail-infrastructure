# --------------------------------------------------------------------------
# S3 Access Logging - audit access to the CloudTrail bucket itself
# --------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_access_logs" {
  provider = aws.security_audit

  bucket        = "${var.bucket_name}-access-logs"
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_access_logs" {
  provider = aws.security_audit

  bucket = aws_s3_bucket.cloudtrail_access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_access_logs" {
  provider = aws.security_audit

  bucket = aws_s3_bucket.cloudtrail_access_logs.id

  # SSE-S3 (AES256) used because the KMS key is in the management account;
  # cross-account KMS for S3 server access logs is not supported.
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_access_logs" {
  provider = aws.security_audit

  bucket = aws_s3_bucket.cloudtrail_access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_access_logs" {
  provider = aws.security_audit

  bucket = aws_s3_bucket.cloudtrail_access_logs.id

  rule {
    id     = "access-logs-lifecycle"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 90
    }
  }
}
