# Billing & Account Governance

# Monthly cost budget - detects runaway costs from compromised resources
resource "aws_budgets_budget" "monthly" {
  count = var.enable_budget_alerts ? 1 : 0

  lifecycle {
    precondition {
      condition     = length(var.budget_notification_emails) > 0
      error_message = "budget_notification_emails must not be empty when enable_budget_alerts is true."
    }
  }

  name         = "${var.project_name}-monthly-budget"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_amount)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # 80% early warning
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_notification_emails
  }

  # 100% budget exceeded
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_notification_emails
  }

  # 120% forecast - projected overspend
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 120
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.budget_notification_emails
  }

  tags = {
    Name    = "${var.project_name}-monthly-budget"
    Purpose = "Cost governance and anomaly detection"
  }
}

# Cost Anomaly Detection - ML-based per-service cost spike monitoring
resource "aws_ce_anomaly_monitor" "main" {
  count = var.enable_cost_anomaly_detection ? 1 : 0

  name              = "${var.project_name}-cost-anomaly-monitor"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"

  tags = {
    Name    = "${var.project_name}-cost-anomaly-monitor"
    Purpose = "ML-based cost anomaly detection"
  }
}

resource "aws_ce_anomaly_subscription" "main" {
  count = var.enable_cost_anomaly_detection && length(var.budget_notification_emails) > 0 ? 1 : 0

  name = "${var.project_name}-cost-anomaly-subscription"

  monitor_arn_list = [aws_ce_anomaly_monitor.main[0].arn]

  frequency = "DAILY"

  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      match_options = ["GREATER_THAN_OR_EQUAL"]
      values        = [tostring(var.cost_anomaly_threshold_amount)]
    }
  }

  dynamic "subscriber" {
    for_each = var.budget_notification_emails
    content {
      type    = "EMAIL"
      address = subscriber.value
    }
  }

  tags = {
    Name    = "${var.project_name}-cost-anomaly-subscription"
    Purpose = "Cost anomaly alert delivery to subscribers"
  }
}

# Alternate contacts - security, billing, operations
resource "aws_account_alternate_contact" "security" {
  count = var.security_contact_email != "" ? 1 : 0

  alternate_contact_type = "SECURITY"
  name                   = var.security_contact_name
  title                  = var.security_contact_title
  email_address          = var.security_contact_email
  phone_number           = var.security_contact_phone
}

resource "aws_account_alternate_contact" "billing" {
  count = var.billing_contact_email != "" ? 1 : 0

  alternate_contact_type = "BILLING"
  name                   = var.billing_contact_name
  title                  = var.billing_contact_title
  email_address          = var.billing_contact_email
  phone_number           = var.billing_contact_phone
}

resource "aws_account_alternate_contact" "operations" {
  count = var.operations_contact_email != "" ? 1 : 0

  alternate_contact_type = "OPERATIONS"
  name                   = var.operations_contact_name
  title                  = var.operations_contact_title
  email_address          = var.operations_contact_email
  phone_number           = var.operations_contact_phone
}
