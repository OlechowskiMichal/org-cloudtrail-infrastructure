# Infrastructure AWS Template

AWS infrastructure template with OpenTofu, Go/Terratest, LocalStack, OPA policies, and CI/CD.

## Prerequisites

- [mise](https://mise.jdx.dev) — tool version manager
- [Docker](https://www.docker.com) — for LocalStack testing

## Quick Start

### 1. Create Repository from Template

```bash
gh repo create my-aws-project --template YOUR-ORG/infrastructure-aws-template
cd my-aws-project
```

### 2. Install Tools

```bash
task setup
```

This installs all tools via mise and configures git hooks (lefthook).

### 3. Configure Backend

Edit `tofu/versions.tf` and replace the placeholder values:

```hcl
backend "s3" {
  bucket         = "REPLACE_BUCKET_NAME"
  key            = "REPLACE_KEY"        # e.g., "env/prod/terraform.tfstate"
  region         = "REPLACE_REGION"
  dynamodb_table = "REPLACE_DYNAMODB_TABLE"
  encrypt        = true
}
```

### 4. Configure GitHub Secrets

| Secret | Description |
|--------|-------------|
| `AWS_ROLE_TO_ASSUME` | IAM role ARN for OIDC authentication |

### 5. Validate and Deploy

```bash
task tofu:validate
task tofu:fmt:check
task tofu:policy          # Requires plan.json (run tofu plan + tofu show -json first)
task test:default
# Review changes, then deploy via GitHub Actions workflow
```

## Directory Structure

```text
├── .github/workflows/          # CI/CD pipelines
│   ├── plan.yml               # Plan on PR with OPA policy checks
│   ├── apply.yml              # Manual apply (production)
│   ├── drift.yml              # Daily drift detection
│   ├── lint.yml               # Code linting (IaC + Go)
│   └── e2e-cleanup.yml        # Daily cleanup of orphaned e2e resources
├── tofu/                       # OpenTofu configuration
│   ├── versions.tf            # Backend config (S3) and providers
│   ├── providers.tf           # AWS provider with default tags
│   ├── variables.tf           # Input variables
│   ├── locals.tf              # Common tags and name prefix
│   ├── main.tf                # Resources (add yours here)
│   ├── outputs.tf             # Outputs
│   ├── modules/example/       # Example module pattern
│   └── environments/          # SOPS-encrypted tfvars
│       └── prod.tfvars.example
├── policies/                   # OPA security policies (commented)
│   ├── s3.rego                # S3 bucket security
│   ├── dynamodb.rego          # DynamoDB table security
│   ├── cloudwatch.rego        # CloudWatch log compliance
│   └── README.md              # Policy documentation
├── test/                       # Go/Terratest test infrastructure
│   ├── go.mod
│   ├── helpers_test.go        # Shared AWS helpers
│   ├── config_localstack_test.go  # LocalStack init (!e2e)
│   ├── config_e2e_test.go     # Real AWS init (e2e)
│   ├── static_analysis_test.go    # Credential scanning
│   ├── example_test.go        # Example Terratest test
│   └── fixtures/              # Test fixtures (add your own)
├── taskfiles/                  # Task runner subtasks
│   ├── setup.yml              # Tool installation
│   ├── tofu.yml               # OpenTofu tasks
│   ├── lint.yml               # Go + CI linters
│   ├── test.yml               # Test execution
│   ├── localstack.yml         # LocalStack management
│   ├── sops.yml               # Secrets management
│   └── ci.yml                 # CI validation
├── lefthook/                   # Git hook configs
│   ├── general.yml            # File checks
│   ├── terraform.yml          # OpenTofu formatting + tflint
│   ├── go.yml                 # Go lint, fmt, vet, test, security
│   ├── ci.yml                 # actionlint, yamllint, markdownlint
│   └── commit-msg.yml         # Conventional commits
├── Taskfile.yml                # Task runner entrypoint
├── lefthook.yml                # Git hooks entrypoint
├── docker-compose.yml          # LocalStack for testing
├── .mise.toml                  # Base tool versions
├── .mise.ci.toml               # CI tool profile
├── .mise.development.toml      # Development tool profile
├── .golangci.yml               # Go linting (30+ linters)
├── .custom-gcl.yml             # Custom golangci-lint plugin config
├── .tflint.hcl                 # Terraform linting (AWS plugin)
├── .sops.yaml                  # SOPS encryption config
└── README.md
```

## Available Tasks

| Task | Description |
|------|-------------|
| `task setup` | Install tools and git hooks |
| `task tofu:fmt` | Format OpenTofu files |
| `task tofu:fmt:check` | Check formatting |
| `task tofu:validate` | Init and validate configuration |
| `task tofu:tflint` | Run tflint |
| `task tofu:tflint:all` | All linters (tflint + actionlint + yamllint + markdownlint + fmt) |
| `task tofu:policy` | OPA policy checks (requires plan.json) |
| `task lint:go` | Run golangci-lint on Go test files |
| `task lint:go:fix` | Run golangci-lint with auto-fix |
| `task test:default` | Full test suite (auto-starts LocalStack) |
| `task test:unit` | Unit tests only |
| `task test:integration` | Integration tests (requires LocalStack) |
| `task test:e2e` | E2E tests against real AWS |
| `task localstack:up` | Start LocalStack |
| `task localstack:down` | Stop LocalStack |
| `task sops:decrypt ENV=<env>` | Decrypt environment tfvars |
| `task sops:encrypt ENV=<env>` | Encrypt environment tfvars |
| `task sops:edit ENV=<env>` | Decrypt, edit, re-encrypt |
| `task ci:validate` | Full CI validation |
| `task ci:test` | Full CI validation + test suite |
| `task tofu:clean` | Remove generated files |

## Testing

Tests use Go + Terratest and run against LocalStack by default.

```bash
task test:default       # Full suite (auto-starts LocalStack)
task test:unit          # Unit tests only (go test -short)
task test:integration   # Integration tests (requires running LocalStack)
task test:e2e           # E2E tests against real AWS (requires credentials)
```

Build tags control which AWS backend is used:

| Tag | Backend | Usage |
|-----|---------|-------|
| `!e2e` (default) | LocalStack | `go test ./...` |
| `e2e` | Real AWS | `go test -tags e2e ./...` |

## Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| Plan | PR, push to main | Preview changes + OPA policy validation |
| Apply | Manual | Deploy infrastructure (main branch only) |
| Drift | Daily schedule | Detect configuration drift |
| Lint | PR, push to main | Code quality checks (IaC + Go) |
| E2E Cleanup | Daily schedule | Remove orphaned e2e test resources |

## Tool Management

Tools are managed via [mise](https://mise.jdx.dev) with three profiles:

| Profile | File | Purpose |
|---------|------|---------|
| Base | `.mise.toml` | Shared tools (go, golangci-lint, opentofu, opa, task, tflint, linters, sops, age) |
| CI | `.mise.ci.toml` | CI — inherits base only |
| Development | `.mise.development.toml` | Local dev — adds lefthook, govulncheck, gosec, node, awscli |

CI workflows set `MISE_ENV=ci` and run `mise install` to get consistent tool versions.

## Secrets Management (SOPS)

Per-environment secrets are encrypted using [SOPS](https://github.com/getsops/sops) with [AGE](https://github.com/FiloSottile/age) keys.

### Setup

1. Generate an AGE keypair: `age-keygen -o key.txt`
2. Put the public key in `.sops.yaml`
3. Store the private key in AWS SSM Parameter Store or Secrets Manager
4. Export key locally:

```bash
export SOPS_AGE_KEY=$(aws ssm get-parameter \
  --name "/YOUR-PROJECT/sops-age-key" \
  --with-decryption --query "Parameter.Value" --output text)
```

### Usage

```bash
task sops:edit ENV=prod     # Edit encrypted vars in-place
task sops:decrypt ENV=prod  # Decrypt to .tfvars.decrypted (gitignored)
task sops:encrypt ENV=prod  # Re-encrypt after manual edits
```

## OPA Policies

All policy rules ship commented out. Uncomment the ones relevant to your infrastructure. See `policies/README.md` for details.

| File | Package | Rules |
|------|---------|-------|
| `s3.rego` | `policies.s3` | Public access block, encryption, versioning, lifecycle |
| `dynamodb.rego` | `policies.dynamodb` | SSE, point-in-time recovery |
| `cloudwatch.rego` | `policies.cloudwatch` | Log retention |

## Contributing

1. Create feature branch
2. Make changes
3. Run `task ci:test` locally
4. Open PR (plan + lint run automatically)
5. Review and merge
6. Trigger Apply workflow
