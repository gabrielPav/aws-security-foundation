output "external_access_analyzer_arn" {
  description = "ARN of the external access IAM Access Analyzer"
  value       = aws_accessanalyzer_analyzer.external.arn
}

output "unused_access_analyzer_arn" {
  description = "ARN of the unused access IAM Access Analyzer"
  value       = var.enable_unused_access_analyzer ? aws_accessanalyzer_analyzer.unused[0].arn : ""
}
