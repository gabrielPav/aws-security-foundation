output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : ""
}

output "security_hub_arn" {
  description = "ARN of the Security Hub account"
  value       = var.enable_security_hub ? aws_securityhub_account.main[0].arn : ""
}

output "macie_account_id" {
  description = "ID of the Macie account"
  value       = var.enable_macie ? aws_macie2_account.main[0].id : ""
}

output "inspector_enabled_resource_types" {
  description = "Resource types enabled for Inspector scanning"
  value       = var.enable_inspector ? var.inspector_resource_types : []
}

output "detective_graph_arn" {
  description = "ARN of the Detective graph"
  value       = var.enable_detective ? aws_detective_graph.main[0].graph_arn : ""
}
