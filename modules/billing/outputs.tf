output "monthly_budget_id" {
  description = "ID of the monthly cost budget"
  value       = var.enable_budget_alerts ? aws_budgets_budget.monthly[0].id : ""
}

output "cost_anomaly_monitor_arn" {
  description = "ARN of the cost anomaly monitor"
  value       = var.enable_cost_anomaly_detection ? aws_ce_anomaly_monitor.main[0].arn : ""
}

output "security_contact_configured" {
  description = "Whether the security alternate contact is configured"
  value       = var.security_contact_email != ""
}

output "billing_contact_configured" {
  description = "Whether the billing alternate contact is configured"
  value       = var.billing_contact_email != ""
}

output "operations_contact_configured" {
  description = "Whether the operations alternate contact is configured"
  value       = var.operations_contact_email != ""
}
