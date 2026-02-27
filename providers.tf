# Provider Configuration

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = merge(
      var.common_tags,
      {
        ManagedBy = "Terraform"
        Project   = var.project_name
      }
    )
  }
}
