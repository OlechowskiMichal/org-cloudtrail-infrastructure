# org-cloudtrail

Organization-wide CloudTrail with KMS encryption, S3 bucket (security-audit account), CloudWatch alerting, and EventBridge rules.

## Usage

```hcl
module "cloudtrail" {
  source = "git::https://github.com/OlechowskiMichal/org-cloudtrail.git//tofu?ref=v1.0.0"

  organization_id           = data.aws_organizations_organization.current.id
  management_account_id     = data.aws_caller_identity.current.account_id
  security_audit_account_id = aws_organizations_account.this["security-audit"].id
  aws_region                = "us-east-1"
  state_bucket_name         = "my-state-bucket"
  budget_alert_email        = "alerts@example.com"

  providers = {
    aws                = aws
    aws.security_audit = aws.security_audit
  }
}
```

## Resources Created

- KMS key + alias for CloudTrail encryption
- Organization CloudTrail (multi-region, log validation)
- S3 bucket with object lock, versioning, encryption, lifecycle (security-audit account)
- S3 access logging bucket
- CloudWatch Log Group + IAM role for log delivery
- SNS topic for security alerts (KMS encrypted)
- CloudWatch metric filters + alarms (unauthorized API calls, root usage, MFA-less sign-in)
- EventBridge rules for GuardDuty and SecurityHub high/critical findings

## Inputs

| Name | Description | Type | Required |
|------|-------------|------|----------|
| organization_id | AWS Organization ID | string | yes |
| management_account_id | Management account ID | string | yes |
| security_audit_account_id | Security-audit account ID | string | yes |
| aws_region | AWS region | string | yes |
| state_bucket_name | State bucket name (monitored by CloudTrail) | string | yes |
| budget_alert_email | Email for security alerts | string | yes |

## Outputs

| Name | Description |
|------|-------------|
| trail_arn | CloudTrail ARN |
| kms_key_arn | KMS key ARN |
| bucket_name | CloudTrail S3 bucket name |
| security_alerts_topic_arn | Security alerts SNS topic ARN |

## Providers

Requires two AWS provider configurations:

- `aws` -- management account (default)
- `aws.security_audit` -- security-audit account
