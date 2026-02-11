# --------------------------------------------------------------------------
# SNS Topic for security alerts
# --------------------------------------------------------------------------
resource "aws_sns_topic" "security_alerts" {
  name              = "security-alerts"
  kms_master_key_id = var.kms_key_id
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.budget_alert_email
}

data "aws_iam_policy_document" "security_alerts_topic" {
  statement {
    sid    = "AllowCloudWatchAlarms"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }

  statement {
    sid    = "AllowEventBridgePublish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = data.aws_iam_policy_document.security_alerts_topic.json
}

# --------------------------------------------------------------------------
# Metric Filters and Alarms - Unauthorized API calls
# --------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = "UnauthorizedAPICalls"
  log_group_name = var.cloudwatch_log_group_name

  pattern = "{ ($.errorCode = \"*UnauthorizedAccess*\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name          = "UnauthorizedAPICalls"
    namespace     = "CloudTrailMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "unauthorized-api-calls"
  alarm_description   = "Triggers on unauthorized API calls detected by CloudTrail"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alerts.arn]
}

# --------------------------------------------------------------------------
# Metric Filters and Alarms - Root account usage
# --------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "root_account_usage" {
  name           = "RootAccountUsage"
  log_group_name = var.cloudwatch_log_group_name

  pattern = "{ ($.userIdentity.type = \"Root\") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != \"AwsServiceEvent\") }"

  metric_transformation {
    name          = "RootAccountUsage"
    namespace     = "CloudTrailMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_account_usage" {
  alarm_name          = "root-account-usage"
  alarm_description   = "Triggers when the root account is used"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alerts.arn]
}

# --------------------------------------------------------------------------
# Metric Filters and Alarms - Console sign-in without MFA
# --------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "console_signin_without_mfa" {
  name           = "ConsoleSignInWithoutMFA"
  log_group_name = var.cloudwatch_log_group_name

  pattern = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") }"

  metric_transformation {
    name          = "ConsoleSignInWithoutMFA"
    namespace     = "CloudTrailMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_signin_without_mfa" {
  alarm_name          = "console-signin-without-mfa"
  alarm_description   = "Triggers when an IAM user signs in to the console without MFA"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleSignInWithoutMFA"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alerts.arn]
}

# --------------------------------------------------------------------------
# EventBridge - GuardDuty HIGH/CRITICAL findings
# --------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "guardduty-high-critical-findings"
  description = "Matches GuardDuty findings with HIGH or CRITICAL severity"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=", 7] }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "guardduty-to-sns"
  arn       = aws_sns_topic.security_alerts.arn
}

# --------------------------------------------------------------------------
# EventBridge - SecurityHub HIGH/CRITICAL findings
# --------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  name        = "securityhub-high-critical-findings"
  description = "Matches SecurityHub findings with HIGH or CRITICAL severity"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["HIGH", "CRITICAL"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_sns" {
  rule      = aws_cloudwatch_event_rule.securityhub_findings.name
  target_id = "securityhub-to-sns"
  arn       = aws_sns_topic.security_alerts.arn
}
