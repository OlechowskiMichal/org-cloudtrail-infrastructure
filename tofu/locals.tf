# Local values for computed or repeated values

locals {
  # Common tags applied to all resources
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "opentofu"
  })

}
