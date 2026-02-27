# Locals - Computed values and policy construction

locals {
  # Inspector resource types (combine based on feature flags)
  inspector_resource_types = compact([
    var.enable_inspector_ec2 ? "EC2" : "",
    var.enable_inspector_ecr ? "ECR" : "",
    var.enable_inspector_lambda ? "LAMBDA" : "",
    var.enable_inspector_lambda_code ? "LAMBDA_CODE" : "",
  ])

  # Budget notification emails (filter empty strings)
  budget_emails = [for email in var.budget_notification_emails : email if email != ""]
}
