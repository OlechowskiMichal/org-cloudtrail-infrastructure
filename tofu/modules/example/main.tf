# Example Module
# This demonstrates the module pattern for this project.
# Replace with your actual AWS infrastructure resources.

resource "random_pet" "this" {
  prefix    = var.prefix
  separator = "-"
}
