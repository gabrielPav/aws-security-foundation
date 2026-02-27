# IAM - Account-level security controls

# IAM password policy
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = var.password_minimum_length
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = var.password_reuse_prevention
  max_password_age               = var.password_max_age_days
  allow_users_to_change_password = true
  hard_expiry                    = var.password_hard_expiry
}

# External access analyzer - detects resources shared outside the account
resource "aws_accessanalyzer_analyzer" "external" {
  analyzer_name = "${var.project_name}-external-access-analyzer"
  type          = var.is_organization_account ? "ORGANIZATION" : "ACCOUNT"

}

# Unused access analyzer - surfaces overly broad grants that should be tightened
resource "aws_accessanalyzer_analyzer" "unused" {
  count = var.enable_unused_access_analyzer ? 1 : 0

  analyzer_name = "${var.project_name}-unused-access-analyzer"
  type          = var.is_organization_account ? "ORGANIZATION_UNUSED_ACCESS" : "ACCOUNT_UNUSED_ACCESS"

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age_days
    }
  }

}
