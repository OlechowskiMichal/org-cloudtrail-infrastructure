# Agent Instructions: infrastructure-aws-template

## Overview

AWS infrastructure template with OpenTofu, Go/Terratest, LocalStack, OPA policies, and CI/CD. AWS-only — no GCP/Azure.

## Tech Stack

| Component | Tool | Version |
|-----------|------|---------|
| IaC | OpenTofu | ~> 1.9 |
| Cloud | AWS | ~> 5.0 provider |
| Policy | Conftest + OPA (Rego) | latest |
| Testing | Go + Terratest | 1.23 |
| Local testing | LocalStack | 4.x |
| Linting | golangci-lint | 1.62 (custom build) |
| CI/CD | GitHub Actions | v4 |
| Task runner | Task | 3.x |
| Tool management | mise | latest |
| Secrets | SOPS + AGE | latest |
| Git hooks | lefthook | latest |
| Commit lint | commitlint | 19.x |
| Terraform lint | tflint | latest (AWS plugin) |

## Mise Profiles

| Profile | File | Tools |
|---------|------|-------|
| Base | `.mise.toml` | go, golangci-lint, opentofu, opa, task, tflint, actionlint, yamllint, markdownlint-cli2, sops, age |
| CI | `.mise.ci.toml` | Inherits base only |
| Development | `.mise.development.toml` | lefthook, govulncheck, gosec, node, yq, awscli |

## Key Files

```text
tofu/*.tf                       # OpenTofu configuration (AWS)
tofu/modules/                   # Reusable modules
tofu/environments/              # SOPS-encrypted tfvars per environment
conftest.toml                    # Conftest configuration (policies pulled from opa-policies repo)
test/*.go                       # Go/Terratest tests
test/fixtures/                  # Test fixtures (add your own)
docker-compose.yml              # LocalStack (s3, dynamodb, sts, kms)
.github/workflows/              # CI/CD workflows
Taskfile.yml                    # Task runner entrypoint
taskfiles/                      # Task runner subtasks
lefthook.yml                    # Git hooks entrypoint
lefthook/                       # Git hook configs
.mise.toml                      # Base tool versions
.golangci.yml                   # Go linting (30+ linters + custom filelength)
.custom-gcl.yml                 # Custom golangci-lint plugin build
.tflint.hcl                     # Terraform linting (AWS plugin active)
.sops.yaml                      # SOPS encryption config
```

## Commands

```bash
# Setup (first time)
task setup

# Format
task tofu:fmt            # Format all .tf files
task tofu:fmt:check      # Check formatting

# Validate
task tofu:validate       # Init + validate

# Lint
task tofu:tflint         # Run tflint
task tofu:tflint:all     # All linters (tflint + actionlint + yamllint + markdownlint + fmt)
task lint:go             # Run golangci-lint on Go test files
task lint:go:fix         # Run golangci-lint with auto-fix

# Policy
task tofu:policy         # Conftest policy check (requires plan.json)

# Testing
task test:default        # Full test suite (starts LocalStack automatically)
task test:unit           # Unit tests only (go test -short ./...)
task test:integration    # Integration tests (requires LocalStack)
task test:e2e            # E2E tests against real AWS

# LocalStack
task localstack:up       # Start LocalStack
task localstack:wait     # Wait for LocalStack to be ready
task localstack:down     # Stop LocalStack
task localstack:logs     # View LocalStack logs

# Secrets
task sops:decrypt ENV=dev   # Decrypt environment tfvars
task sops:encrypt ENV=dev   # Encrypt environment tfvars
task sops:edit ENV=dev      # Decrypt, edit, re-encrypt

# CI
task ci:validate    # Full CI validation (fmt + validate + lint)
task ci:test        # Full CI validation + test suite

# Cleanup
task tofu:clean     # Remove generated files
```

## Testing Architecture

Tests use Go + Terratest. Build tags switch between backends:

| Build tag | Backend | Config file |
|-----------|---------|-------------|
| `!e2e` (default) | LocalStack at `localhost:4566` | `config_localstack_test.go` |
| `e2e` | Real AWS (default credential chain) | `config_e2e_test.go` |

**Test files:**

- `helpers_test.go` — AWS config factory, S3/DynamoDB clients, waiter helpers
- `config_localstack_test.go` — LocalStack init (`!e2e` build tag)
- `config_e2e_test.go` — Real AWS init (`e2e` build tag)
- `static_analysis_test.go` — Credential scanning in .tf and .go files
- `example_test.go` — Commented Terratest patterns (init/plan, apply/destroy)

**Fixtures:** Create fixtures in `test/fixtures/` for your infrastructure. See `example_test.go` for patterns.

## SOPS Workflow

1. Generate AGE keypair: `age-keygen -o key.txt`
2. Put public key in `.sops.yaml`
3. Store private key in AWS SSM Parameter Store
4. Export key: `export SOPS_AGE_KEY=$(aws ssm get-parameter --name "/PROJECT/sops-age-key" --with-decryption --query "Parameter.Value" --output text)`
5. Use `task sops:encrypt/decrypt/edit ENV=<env>` to manage secrets

## Post-Clone Cleanup

After creating a repository from this template, remove or replace template scaffolding:

| Action | Target | What to do |
|--------|--------|------------|
| Replace | `tofu/versions.tf` | Replace `REPLACE_*` backend placeholders with real values |
| Replace | `tofu/providers.tf` | Update `default_tags` for your project |
| Replace | `tofu/variables.tf` | Update defaults (`project_name`, `aws_region`) |
| Delete | `tofu/modules/example/` | Remove example module, add your own |
| Replace | `tofu/environments/prod.tfvars.example` | Create real encrypted `.tfvars` files |
| Replace | `.sops.yaml` | Replace placeholder AGE public key |
| Delete | `policies/` | Not needed — policies pulled from central opa-policies repo |
| Delete | `test/example_test.go` | Remove after writing real tests |
| Replace | `README.md` | Replace with project-specific documentation |
| Replace | `AGENTS.md` | Replace with project-specific agent instructions (delete this section) |
| Replace | `LICENSE` | Update or remove |
| Replace | `.github/workflows/e2e-cleanup.yml` | Update `PREFIX` to match your project naming |
| Replace | `test/go.mod` | Update module path to your repo |

After cleanup, run `task ci:validate` to verify everything still works.

## Development Guidelines

- Follow existing OpenTofu/HCL patterns and naming conventions
- Keep changes focused and minimal
- Policies are centralized in the opa-policies repo and pulled via conftest at runtime
- Conventional commits enforced via commitlint/lefthook
- Never commit `*.tfvars.decrypted` files (gitignored)
- Go source files must be <= 120 lines (test files excluded)

## Anti-Patterns

| Do | Don't |
|----|-------|
| Use `task` commands | Run raw `tofu` commands without mise |
| Encrypt secrets with SOPS | Commit plaintext tfvars |
| Pin tool versions in mise | Install tools manually |
| Use feature branches | Work on main |
| Run `task ci:test` before pushing | Skip linting or tests |
| Use LocalStack for development testing | Test against real AWS in dev |

## Git Workflow

1. `git status` first
2. Create feature branch from main
3. Make changes, run `task ci:test`
4. Commit with conventional commits (enforced by lefthook)
5. Push (triggers pre-push hooks: full lint + vulncheck)
6. Create PR (triggers GitHub Actions: plan, OPA validation, linting)
7. Merge to main
8. Manual apply via GitHub Actions workflow_dispatch

## Task Completion Criteria

- All `task ci:test` checks pass
- Conftest policies pass (`task tofu:policy`)
- Static analysis tests pass (no hardcoded credentials)
- No decrypted `.tfvars.decrypted` files in git
- Conventional commit messages
- Feature branch with PR
