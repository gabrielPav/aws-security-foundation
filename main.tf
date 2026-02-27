# Root Module

# IAM - Password policy and access analyzers

module "iam" {
  source = "./modules/iam"

  project_name = var.project_name

  # Password Policy
  password_minimum_length   = var.password_minimum_length
  password_reuse_prevention = var.password_reuse_prevention
  password_max_age_days     = var.password_max_age_days
  password_hard_expiry      = var.password_hard_expiry

  # Access Analyzer
  is_organization_account       = var.is_organization_account
  enable_unused_access_analyzer = var.enable_unused_access_analyzer
  unused_access_age_days        = var.unused_access_age_days

}

# S3 - Account-level public access block

module "s3_account_security" {
  source = "./modules/s3"
}

# Encryption — KMS keys per layer, EBS default encryption

module "encryption" {
  source = "./modules/data-protection"

  project_name             = var.project_name
  kms_rotation_period_days = var.kms_rotation_period_days
  ebs_default_kms_key_arn  = var.ebs_default_kms_key_arn

  # EC2 instance defaults
  enable_imdsv2_default      = var.enable_imdsv2_default
  imdsv2_hop_limit           = var.imdsv2_hop_limit
  disable_ec2_serial_console = var.disable_ec2_serial_console

  # EMR
  enable_emr_block_public_access = var.enable_emr_block_public_access

}

# Logging - CloudTrail, Config, CloudWatch alarms

module "logging" {
  source = "./modules/logging"

  project_name = var.project_name

  # KMS keys from encryption module
  kms_observability_key_arn = module.encryption.kms_observability_key_arn
  kms_observability_key_id  = module.encryption.kms_observability_key_id
  kms_storage_key_arn       = module.encryption.kms_storage_key_arn

  # CloudTrail
  enable_cloudtrail             = var.enable_cloudtrail
  cloudtrail_log_retention_days = var.cloudtrail_log_retention_days
  is_organization_trail         = var.is_organization_account && var.is_organization_trail
  organization_id               = var.organization_id
  enable_s3_data_events         = var.enable_s3_data_events

  # AWS Config
  enable_config                        = var.enable_config
  config_log_retention_days            = var.config_log_retention_days
  enable_cis_config_rules              = var.enable_cis_config_rules
  enable_config_rule_root_access_key   = var.enable_config_rule_root_access_key
  enable_config_rule_root_mfa          = var.enable_config_rule_root_mfa
  enable_config_rule_root_hardware_mfa = var.enable_config_rule_root_hardware_mfa
  enable_config_rule_ebs_encryption    = var.enable_config_rule_ebs_encryption
  enable_config_rule_rds_encryption    = var.enable_config_rule_rds_encryption
  enable_config_rule_kms_rotation      = var.enable_config_rule_kms_rotation
  enable_config_rule_default_sg_closed = var.enable_config_rule_default_sg_closed
  enable_config_rule_iam_user_mfa      = var.enable_config_rule_iam_user_mfa
  enable_config_rule_s3_encryption     = var.enable_config_rule_s3_encryption

  # CloudWatch
  cloudwatch_log_retention_days          = var.cloudwatch_log_retention_days
  cloudwatch_log_deletion_protection     = var.cloudwatch_log_deletion_protection
  enable_cloudwatch_data_protection      = var.enable_cloudwatch_data_protection

  # S3 Object Lock
  s3_object_lock_mode                      = var.s3_object_lock_mode
  enable_s3_object_lock_cloudtrail         = var.enable_s3_object_lock_cloudtrail
  s3_object_lock_cloudtrail_retention_days = var.s3_object_lock_cloudtrail_retention_days
  enable_s3_object_lock_config             = var.enable_s3_object_lock_config
  s3_object_lock_config_retention_days     = var.s3_object_lock_config_retention_days

  # S3 Access Logging
  enable_s3_object_lock_access_logs              = var.enable_s3_object_lock_access_logs
  s3_object_lock_access_logs_retention_days      = var.s3_object_lock_access_logs_retention_days
  enable_s3_object_lock_access_logs_meta         = var.enable_s3_object_lock_access_logs_meta
  s3_object_lock_access_logs_meta_retention_days = var.s3_object_lock_access_logs_meta_retention_days
  access_log_retention_days                      = var.access_log_retention_days

  # Security Alarms
  enable_security_alarms   = var.enable_security_alarms
  alarm_notification_email = var.alarm_notification_email
  is_organization_account  = var.is_organization_account

  # Finding notifications (EventBridge → SNS for HIGH/CRITICAL findings)
  enable_finding_notifications = var.enable_finding_notifications

}

# Cross-module precondition - finding notifications need detection services

resource "terraform_data" "validate_finding_notifications" {
  count = var.enable_finding_notifications ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.enable_guardduty || var.enable_security_hub || var.enable_inspector || var.enable_macie
      error_message = "enable_finding_notifications requires at least one detection service (enable_guardduty, enable_security_hub, enable_inspector, or enable_macie) to be enabled. EventBridge rules would have no findings to route."
    }
  }
}

# Threat Detection - GuardDuty, Security Hub, Macie, Inspector, Detective

module "threat_detection" {
  source = "./modules/threat-detection"

  project_name = var.project_name

  # GuardDuty
  enable_guardduty                    = var.enable_guardduty
  enable_guardduty_s3_protection      = var.enable_guardduty_s3_protection
  enable_guardduty_eks_protection     = var.enable_guardduty_eks_protection
  enable_guardduty_malware_protection = var.enable_guardduty_malware_protection
  enable_guardduty_rds_protection     = var.enable_guardduty_rds_protection
  enable_guardduty_runtime_monitoring = var.enable_guardduty_runtime_monitoring
  enable_guardduty_lambda_protection  = var.enable_guardduty_lambda_protection

  # Security Hub
  enable_security_hub                  = var.enable_security_hub
  enable_security_hub_cis              = var.enable_security_hub_cis
  enable_security_hub_aws_foundational = var.enable_security_hub_aws_foundational
  enable_security_hub_pci_dss          = var.enable_security_hub_pci_dss
  enable_security_hub_nist_800_171     = var.enable_security_hub_nist_800_171
  enable_security_hub_nist_800_53      = var.enable_security_hub_nist_800_53
  enable_security_hub_cross_region     = var.enable_security_hub_cross_region

  # Security Hub standard versions
  security_hub_cis_version              = var.security_hub_cis_version
  security_hub_aws_foundational_version = var.security_hub_aws_foundational_version
  security_hub_pci_dss_version          = var.security_hub_pci_dss_version
  security_hub_nist_800_171_version     = var.security_hub_nist_800_171_version
  security_hub_nist_800_53_version      = var.security_hub_nist_800_53_version

  # Macie
  enable_macie                            = var.enable_macie
  macie_classification_export_bucket_name = var.macie_classification_export_bucket_name
  macie_kms_key_arn                       = var.macie_kms_key_arn

  # Inspector
  enable_inspector         = var.enable_inspector
  inspector_resource_types = local.inspector_resource_types

  # Detective
  enable_detective = var.enable_detective

}

# Organizations - SCPs, tag/backup/AI policies (conditional on management account)

module "organizations" {
  source = "./modules/organizations"

  project_name = var.project_name

  # SCPs
  enable_scps                        = var.is_organization_account && var.enable_scps
  enable_scp_deny_root_usage         = var.enable_scp_deny_root_usage
  enable_scp_deny_unapproved_regions = var.enable_scp_deny_unapproved_regions
  enable_scp_deny_disable_security   = var.enable_scp_deny_disable_security
  enable_scp_enforce_encryption      = var.enable_scp_enforce_encryption
  enable_scp_deny_public_ami         = var.enable_scp_deny_public_ami
  enable_scp_deny_leave_organization = var.enable_scp_deny_leave_organization
  enable_scp_deny_delete_flow_logs   = var.enable_scp_deny_delete_flow_logs
  enable_scp_deny_deactivate_mfa     = var.enable_scp_deny_deactivate_mfa
  enable_scp_deny_imdsv1             = var.enable_scp_deny_imdsv1
  scp_target_ou_ids                  = var.scp_target_ou_ids
  allowed_regions                    = var.allowed_regions

  # Tag Policies
  enable_tag_policies = var.is_organization_account && var.enable_tag_policies
  required_tags       = var.required_tags

  # Backup Policies
  enable_backup_policies = var.is_organization_account && var.enable_backup_policies
  backup_retention_days  = var.backup_retention_days
  backup_regions         = var.backup_regions

  # AI Opt-Out
  enable_ai_opt_out_policy = var.is_organization_account && var.enable_ai_opt_out_policy

  # RAM Sharing
  enable_ram_org_sharing = var.is_organization_account && var.enable_ram_org_sharing

}

# Billing - Budget alerts, cost anomaly detection, alternate contacts

module "billing" {
  source = "./modules/billing"

  project_name = var.project_name

  # Budget
  enable_budget_alerts       = var.enable_budget_alerts && length(local.budget_emails) > 0
  monthly_budget_amount      = var.monthly_budget_amount
  budget_notification_emails = local.budget_emails

  # Cost Anomaly Detection
  enable_cost_anomaly_detection = var.enable_cost_anomaly_detection
  cost_anomaly_threshold_amount = var.cost_anomaly_threshold_amount

  # Alternate Contacts
  security_contact_name  = var.security_contact_name
  security_contact_title = var.security_contact_title
  security_contact_email = var.security_contact_email
  security_contact_phone = var.security_contact_phone

  billing_contact_name  = var.billing_contact_name
  billing_contact_title = var.billing_contact_title
  billing_contact_email = var.billing_contact_email
  billing_contact_phone = var.billing_contact_phone

  operations_contact_name  = var.operations_contact_name
  operations_contact_title = var.operations_contact_title
  operations_contact_email = var.operations_contact_email
  operations_contact_phone = var.operations_contact_phone

}
