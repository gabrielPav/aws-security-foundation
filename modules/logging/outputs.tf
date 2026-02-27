output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = var.enable_cloudtrail ? aws_cloudtrail.main[0].arn : ""
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail trail"
  value       = var.enable_cloudtrail ? aws_cloudtrail.main[0].name : ""
}

output "cloudtrail_s3_bucket_name" {
  description = "Name of the S3 bucket storing CloudTrail logs"
  value       = var.enable_cloudtrail ? aws_s3_bucket.cloudtrail[0].id : ""
}

output "cloudtrail_cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for CloudTrail"
  value       = var.enable_cloudtrail ? aws_cloudwatch_log_group.cloudtrail[0].arn : ""
}

output "config_recorder_id" {
  description = "ID of the AWS Config recorder"
  value       = var.enable_config ? aws_config_configuration_recorder.main[0].id : ""
}

output "config_s3_bucket_name" {
  description = "Name of the S3 bucket storing Config snapshots"
  value       = var.enable_config ? aws_s3_bucket.config[0].id : ""
}

output "access_logs_bucket_name" {
  description = "Name of the S3 access logging bucket for audit buckets"
  value       = var.enable_cloudtrail || var.enable_config ? aws_s3_bucket.access_logs[0].id : ""
}

output "access_logs_meta_bucket_name" {
  description = "Name of the S3 meta-logging bucket for the access logs bucket"
  value       = var.enable_cloudtrail || var.enable_config ? aws_s3_bucket.access_logs_meta[0].id : ""
}

output "security_alarms_sns_topic_arn" {
  description = "ARN of the SNS topic for security alarm notifications (empty if no email configured)"
  value       = local.create_notifications ? aws_sns_topic.security_alarms[0].arn : ""
}

output "security_alarms_enabled" {
  description = "Whether security alarms are enabled"
  value       = local.create_alarms
}

output "security_dashboard_name" {
  description = "Name of the CloudWatch dashboard for security alarms"
  value       = local.create_alarms ? aws_cloudwatch_dashboard.security[0].dashboard_name : ""
}

output "sns_subscription_pending_confirmation" {
  description = "Whether the alarm email subscription is pending confirmation (alarms will NOT be delivered)"
  value       = local.create_notifications ? aws_sns_topic_subscription.security_alarms_email[0].pending_confirmation : null
}

output "findings_dlq_arn" {
  description = "ARN of the SQS dead-letter queue for failed EventBridge finding deliveries"
  value       = local.create_finding_notifications ? aws_sqs_queue.findings_dlq[0].arn : ""
}

output "sns_subscription_dlq_arn" {
  description = "ARN of the SQS dead-letter queue for failed SNS email subscription deliveries"
  value       = local.create_notifications ? aws_sqs_queue.sns_subscription_dlq[0].arn : ""
}
