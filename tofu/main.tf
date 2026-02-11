locals {
  cloudtrail_bucket_name = "aws-org-cloudtrail-${var.organization_id}"
}

module "trail" {
  source = "./modules/trail"

  aws_region             = var.aws_region
  management_account_id  = var.management_account_id
  state_bucket_name      = var.state_bucket_name
  organization_id        = var.organization_id
  cloudtrail_bucket_name = local.cloudtrail_bucket_name
}

module "bucket" {
  source = "./modules/bucket"

  providers = {
    aws.security_audit = aws.security_audit
  }

  bucket_name               = local.cloudtrail_bucket_name
  kms_key_arn               = module.trail.kms_key_arn
  security_audit_account_id = var.security_audit_account_id
  aws_region                = var.aws_region
  management_account_id     = var.management_account_id
  organization_id           = var.organization_id
}
