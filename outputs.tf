# Root Outputs

# Identity & Access Management

output "external_access_analyzer_arn" {
  description = "ARN of the external access IAM Access Analyzer"
  value       = module.iam.external_access_analyzer_arn
}

output "unused_access_analyzer_arn" {
  description = "ARN of the unused access IAM Access Analyzer"
  value       = module.iam.unused_access_analyzer_arn
}

# S3 Account Security

output "s3_account_public_access_block_id" {
  description = "The AWS account ID for the S3 public access block"
  value       = module.s3_account_security.account_public_access_block_id
}

# Encryption & KMS Keys

output "ebs_encryption_enabled" {
  description = "Whether EBS encryption by default is enabled"
  value       = module.encryption.ebs_encryption_enabled
}

output "kms_compute_key_arn" {
  description = "ARN of the compute layer KMS key (EBS, Auto Scaling)"
  value       = module.encryption.kms_compute_key_arn
}

output "kms_observability_key_arn" {
  description = "ARN of the observability layer KMS key (CloudTrail, CloudWatch, SNS)"
  value       = module.encryption.kms_observability_key_arn
}

output "kms_storage_key_arn" {
  description = "ARN of the storage layer KMS key (S3 log buckets)"
  value       = module.encryption.kms_storage_key_arn
}

output "ami_block_public_access_state" {
  description = "State of AMI public access blocking"
  value       = module.encryption.ami_block_public_access_state
}

output "ebs_snapshot_block_public_access_state" {
  description = "State of EBS snapshot public access blocking"
  value       = module.encryption.ebs_snapshot_block_public_access_state
}

# Logging

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = module.logging.cloudtrail_arn
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail trail"
  value       = module.logging.cloudtrail_name
}

output "cloudtrail_s3_bucket_name" {
  description = "S3 bucket storing CloudTrail logs"
  value       = module.logging.cloudtrail_s3_bucket_name
}

output "cloudtrail_cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for CloudTrail"
  value       = module.logging.cloudtrail_cloudwatch_log_group_arn
}

output "config_recorder_id" {
  description = "ID of the AWS Config recorder"
  value       = module.logging.config_recorder_id
}

output "config_s3_bucket_name" {
  description = "S3 bucket storing Config snapshots"
  value       = module.logging.config_s3_bucket_name
}

# S3 Access Logging

output "access_logs_bucket_name" {
  description = "Name of the centralized S3 access logging bucket"
  value       = module.logging.access_logs_bucket_name
}

output "access_logs_meta_bucket_name" {
  description = "Name of the S3 meta-logging bucket for the access logs bucket"
  value       = module.logging.access_logs_meta_bucket_name
}

# Security Alarms

output "security_alarms_sns_topic_arn" {
  description = "ARN of the SNS topic for security alarms"
  value       = module.logging.security_alarms_sns_topic_arn
}

output "security_alarms_enabled" {
  description = "Whether security alarms are enabled"
  value       = module.logging.security_alarms_enabled
}

output "security_dashboard_name" {
  description = "Name of the CloudWatch dashboard for security alarms"
  value       = module.logging.security_dashboard_name
}

# Threat Detection

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = module.threat_detection.guardduty_detector_id
}

output "security_hub_arn" {
  description = "ARN of the Security Hub account"
  value       = module.threat_detection.security_hub_arn
}

output "inspector_enabled_resource_types" {
  description = "Resource types enabled for Inspector scanning"
  value       = module.threat_detection.inspector_enabled_resource_types
}

output "detective_graph_arn" {
  description = "ARN of the Detective graph"
  value       = module.threat_detection.detective_graph_arn
}

# Organizations

output "deny_root_usage_scp_id" {
  description = "ID of the deny-root-usage SCP"
  value       = module.organizations.deny_root_usage_scp_id
}

output "deny_unapproved_regions_scp_id" {
  description = "ID of the deny-unapproved-regions SCP"
  value       = module.organizations.deny_unapproved_regions_scp_id
}

output "deny_disable_security_scp_id" {
  description = "ID of the deny-disable-security SCP"
  value       = module.organizations.deny_disable_security_scp_id
}

output "enforce_encryption_scp_id" {
  description = "ID of the enforce-encryption SCP"
  value       = module.organizations.enforce_encryption_scp_id
}

output "deny_public_ami_scp_id" {
  description = "ID of the deny-public-ami SCP"
  value       = module.organizations.deny_public_ami_scp_id
}

output "deny_leave_organization_scp_id" {
  description = "ID of the deny-leave-organization SCP"
  value       = module.organizations.deny_leave_organization_scp_id
}

output "deny_delete_flow_logs_scp_id" {
  description = "ID of the deny-delete-flow-logs SCP"
  value       = module.organizations.deny_delete_flow_logs_scp_id
}

output "deny_deactivate_mfa_scp_id" {
  description = "ID of the deny-deactivate-mfa SCP"
  value       = module.organizations.deny_deactivate_mfa_scp_id
}

output "deny_imdsv1_scp_id" {
  description = "ID of the deny-imdsv1 SCP"
  value       = module.organizations.deny_imdsv1_scp_id
}

# Billing

output "monthly_budget_id" {
  description = "ID of the monthly cost budget"
  value       = module.billing.monthly_budget_id
}

output "cost_anomaly_monitor_arn" {
  description = "ARN of the cost anomaly monitor"
  value       = module.billing.cost_anomaly_monitor_arn
}

output "security_contact_configured" {
  description = "Whether the security alternate contact is configured"
  value       = module.billing.security_contact_configured
}

output "billing_contact_configured" {
  description = "Whether the billing alternate contact is configured"
  value       = module.billing.billing_contact_configured
}

output "operations_contact_configured" {
  description = "Whether the operations alternate contact is configured"
  value       = module.billing.operations_contact_configured
}

# Summary

output "security_baseline_summary" {
  description = "Summary of enabled security baseline components"
  value = {
    cloudtrail              = var.enable_cloudtrail
    aws_config              = var.enable_config
    guardduty               = var.enable_guardduty
    security_hub            = var.enable_security_hub
    macie                   = var.enable_macie
    inspector               = var.enable_inspector
    detective               = var.enable_detective
    security_alarms         = var.enable_security_alarms
    budget_alerts           = var.enable_budget_alerts
    cost_anomaly_detection  = var.enable_cost_anomaly_detection
    organization_guardrails = var.is_organization_account && var.enable_scps
  }
}
