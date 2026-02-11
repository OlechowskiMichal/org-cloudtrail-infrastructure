# Agent Instructions: org-cloudtrail

## Overview

Standalone OpenTofu module for organization-wide AWS CloudTrail. Deploys CloudTrail with KMS encryption, S3 bucket in a security-audit account, CloudWatch log delivery and alerting, and EventBridge rules for GuardDuty/SecurityHub findings.

## Tech Stack

| Component | Tool | Version |
|-----------|------|---------|
| IaC | OpenTofu | ~> 1.9 |
| Cloud | AWS | ~> 5.0 provider |
| Testing | Go + Terratest | 1.23 |
| Local testing | LocalStack | 4.x |
| Linting | golangci-lint | 1.62 (custom build) |
| CI/CD | GitHub Actions | v4 |
| Task runner | Task | 3.x |
| Tool management | mise | latest |
| Git hooks | lefthook | latest |
| Commit lint | commitlint | 19.x |
| Terraform lint | tflint | latest (AWS plugin) |

## Key Files

```text
tofu/main.tf                    # All CloudTrail resources (KMS, S3, CloudWatch, EventBridge)
tofu/variables.tf               # Input variables (org ID, account IDs, region, etc.)
tofu/outputs.tf                 # trail_arn, kms_key_arn, bucket_name, sns topic ARN
test/                           # Go/Terratest tests
conftest.toml                   # OPA policy config
```

## Module Resources

| Resource | Account | Purpose |
|----------|---------|---------|
| KMS key + alias | Management | CloudTrail log encryption |
| CloudTrail (org trail) | Management | Multi-region, log validation, S3 data events |
| S3 bucket (object lock) | Security-audit | CloudTrail log storage with lifecycle |
| S3 access logging bucket | Security-audit | Audit access to CloudTrail bucket |
| CloudWatch Log Group | Management | CloudTrail log delivery (90-day retention) |
| IAM role + policy | Management | CloudTrail -> CloudWatch Logs delivery |
| SNS topic | Management | Security alert notifications (KMS encrypted) |
| Metric filters + alarms | Management | Unauthorized API, root usage, MFA-less sign-in |
| EventBridge rules | Management | GuardDuty + SecurityHub high/critical findings |

## Provider Configuration

This module requires two AWS provider configurations:

- `aws` -- management account (default)
- `aws.security_audit` -- security-audit account (S3 buckets)

## Commands

```bash
task setup              # Install tools and git hooks
task tofu:fmt           # Format OpenTofu files
task tofu:validate      # Init and validate
task tofu:tflint        # Run tflint
task lint:go            # Run golangci-lint
task test:unit          # Unit tests
task test:integration   # Integration tests (LocalStack)
task ci:validate        # Full CI validation
```

## Development Guidelines

- Follow existing HCL patterns and naming conventions
- Conventional commits enforced via lefthook
- Use feature branches, create PRs
- Run `task ci:validate` before pushing
- Go source files must be <= 120 lines (test files excluded)
