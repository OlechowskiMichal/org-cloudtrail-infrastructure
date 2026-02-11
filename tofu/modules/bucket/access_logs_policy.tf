resource "aws_s3_bucket_policy" "cloudtrail_access_logs" {
  provider = aws.security_audit

  bucket = aws_s3_bucket.cloudtrail_access_logs.id

  policy = data.aws_iam_policy_document.cloudtrail_access_logs.json
}

data "aws_iam_policy_document" "cloudtrail_access_logs" {
  statement {
    sid    = "S3LogDeliveryWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_access_logs.arn}/access-logs/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.security_audit_account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.cloudtrail.arn]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.cloudtrail_access_logs.arn,
      "${aws_s3_bucket.cloudtrail_access_logs.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}
