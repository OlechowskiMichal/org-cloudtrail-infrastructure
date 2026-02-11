terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.security_audit]
    }
  }
}

# --------------------------------------------------------------------------
# CloudTrail S3 Bucket - in security-audit account
# --------------------------------------------------------------------------
resource "aws_s3_bucket" "cloudtrail" {
  provider = aws.security_audit

  bucket              = var.bucket_name
  force_destroy       = false
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "cloudtrail" {
  provider = aws.security_audit
  bucket   = aws_s3_bucket.cloudtrail.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 180
    }
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  provider = aws.security_audit

  bucket = aws_s3_bucket.cloudtrail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  provider = aws.security_audit

  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}
