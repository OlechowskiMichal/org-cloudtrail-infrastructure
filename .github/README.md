# CI/CD Workflows

GitHub Actions workflows for AWS infrastructure management with OpenTofu.

## Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `plan.yml` | PR + push to main (path-filtered) | Run `tofu plan`, OPA policy check, post results to PR |
| `apply.yml` | Manual (`workflow_dispatch`) | Apply infrastructure changes (main branch only) |
| `drift.yml` | Daily cron (midnight UTC) | Detect infrastructure drift via scheduled plan |
| `lint.yml` | PR to main, push to main | Lint workflows, YAML, OpenTofu, Markdown, Go |
| `e2e-cleanup.yml` | Daily cron (midnight UTC) | Prune orphaned e2e test resources from AWS |

## Pipeline Flow

```text
PR opened/updated
  -> lint.yml (actionlint, yamllint, tofu fmt, tflint, markdownlint, golangci-lint)
  -> plan.yml (tofu init -> validate -> plan -> OPA -> PR comment)

PR merged to main
  -> plan.yml (tofu plan on main)

Manual trigger (workflow_dispatch, type "apply")
  -> apply.yml (tofu init -> plan -> OPA policy check -> apply, main branch only)

Scheduled (daily midnight UTC)
  -> drift.yml (reuses plan.yml -> analyze plan output for changes)
  -> e2e-cleanup.yml (prune orphaned S3 buckets + DynamoDB tables)
```

## Required Secrets

### AWS OIDC Authentication (recommended)

| Secret | Description |
|--------|-------------|
| `AWS_ROLE_TO_ASSUME` | IAM role ARN for GitHub Actions OIDC federation |

To set up AWS OIDC for GitHub Actions:

1. Create an IAM OIDC identity provider for `token.actions.githubusercontent.com`
2. Create an IAM role with a trust policy allowing the GitHub OIDC provider
3. Attach the necessary permissions to the role (S3, DynamoDB, and any managed resources)
4. Add the role ARN as a repository secret named `AWS_ROLE_TO_ASSUME`

### GitHub Environment

The `apply.yml` workflow uses a `production` environment. Configure this in repository settings:

1. Go to Settings -> Environments -> New environment -> `production`
2. Add required reviewers if desired
3. Restrict to the `main` branch

## Bash Scripting Standards

All shell steps in workflows follow these conventions:

- `set -euo pipefail` at the top of multi-line scripts (exit on error, undefined vars, pipe failures)
- Variables are quoted to prevent word splitting
- `$GITHUB_OUTPUT` for passing data between steps (heredoc syntax for multiline)
- `$GITHUB_STEP_SUMMARY` for job summaries
- `::error::` annotations for actionable failures
- Timeouts on every step to prevent hung jobs

## Tool Management

All workflows use [mise](https://mise.jdx.dev) for tool version management with `MISE_ENV=ci`. Tool versions are pinned in `.mise.toml` (base) and `.mise.ci.toml` (CI profile). This ensures CI uses the same tool versions as local development.

## Concurrency

- `plan.yml`: Cancels in-progress runs for the same branch (`tofu-plan-${{ github.ref }}`)
- `apply.yml`: Never cancels in-progress runs (`tofu-apply`, `cancel-in-progress: false`)
- `drift.yml`: Never cancels in-progress runs (`drift-detection`)
- `e2e-cleanup.yml`: Never cancels in-progress runs (`e2e-cleanup`)
