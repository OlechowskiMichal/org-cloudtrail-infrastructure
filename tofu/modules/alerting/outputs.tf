output "security_alerts_topic_arn" {
  description = "The ARN of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}
