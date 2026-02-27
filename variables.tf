# Root Variables - Feature flags and configuration

variable "aws_region" {
  description = "Primary AWS region for security baseline deployment"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "security-baseline"
}

variable "common_tags" {
  description = "Common tags applied to all resources via provider default_tags. ManagedBy and Project are set automatically."
  type        = map(string)
  default     = {}
}

# Account Context

variable "is_organization_account" {
  description = <<-EOT
    Whether this account is the management account of an AWS Organization.

    When true:
    - IAM Access Analyzers use ORGANIZATION scope
    - Organization-level features (SCPs, tag policies, etc.) can be enabled
    - CloudTrail can be configured as an organization trail

    When false (default):
    - All controls operate at the individual account level
    - Organization features are skipped regardless of their flags
  EOT
  type        = bool
  default     = false
}

variable "organization_id" {
  description = "AWS Organization ID (e.g., o-abc123). Required if is_organization_account is true."
  type        = string
  default     = ""

  validation {
    condition     = var.organization_id == "" || can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "organization_id must match the format o-xxxxxxxxxx (e.g., o-abc123def4)."
  }
}

# Identity & Access Management

variable "password_minimum_length" {
  description = "Minimum IAM password length (14+ recommended)"
  type        = number
  default     = 14

  validation {
    condition     = var.password_minimum_length >= 14
    error_message = "Minimum password length must be at least 14."
  }
}

variable "password_reuse_prevention" {
  description = "Number of previous passwords to remember (24 recommended)"
  type        = number
  default     = 24

  validation {
    condition     = var.password_reuse_prevention >= 1 && var.password_reuse_prevention <= 24
    error_message = "Must be between 1 and 24."
  }
}

variable "password_max_age_days" {
  description = "Maximum password age in days before forced rotation (90 recommended)"
  type        = number
  default     = 90

  validation {
    condition     = var.password_max_age_days >= 1 && var.password_max_age_days <= 365
    error_message = "Must be between 1 and 365 days."
  }
}

variable "password_hard_expiry" {
  description = "Whether expired passwords require administrator reset (CIS 1.9)"
  type        = bool
  default     = true
}

variable "enable_unused_access_analyzer" {
  description = "Enable IAM Access Analyzer for unused access findings (paid feature)"
  type        = bool
  default     = true
}

variable "unused_access_age_days" {
  description = "Days of inactivity before access is flagged as unused"
  type        = number
  default     = 90

  validation {
    condition     = var.unused_access_age_days >= 1 && var.unused_access_age_days <= 365
    error_message = "Unused access age must be between 1 and 365 days."
  }
}

# Encryption & Data Protection

variable "kms_rotation_period_days" {
  description = "KMS key rotation period in days for all auto-created keys (compute, observability, storage). Minimum 90, maximum 2560."
  type        = number
  default     = 90

  validation {
    condition     = var.kms_rotation_period_days >= 90 && var.kms_rotation_period_days <= 2560
    error_message = "KMS rotation period must be between 90 and 2560 days."
  }
}

variable "ebs_default_kms_key_arn" {
  description = "ARN of an existing KMS key to override the internally created compute key for EBS default encryption. Leave empty to use the auto-created key."
  type        = string
  default     = ""

  validation {
    condition     = var.ebs_default_kms_key_arn == "" || can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/", var.ebs_default_kms_key_arn))
    error_message = "ebs_default_kms_key_arn must be a valid KMS key ARN (arn:aws:kms:REGION:ACCOUNT:key/KEY-ID) or empty."
  }
}

variable "enable_imdsv2_default" {
  description = "Enforce IMDSv2 as the account-level default for all new EC2 instances. Does not affect existing instances."
  type        = bool
  default     = true
}

variable "imdsv2_hop_limit" {
  description = "HTTP PUT response hop limit for IMDSv2. Default is 1. In a container environment, set the hop limit to 2 (recommended)."
  type        = number
  default     = 1
}

variable "disable_ec2_serial_console" {
  description = "Disable EC2 Serial Console access for the account. Eliminates out-of-band access path."
  type        = bool
  default     = true
}

variable "enable_emr_block_public_access" {
  description = "Block public access on Amazon EMR on EC2. Prevents EMR clusters from launching with public security group rules."
  type        = bool
  default     = true
}

# Logging & Monitoring

variable "enable_cloudtrail" {
  description = "Enable CloudTrail multi-region trail. Strongly recommended."
  type        = bool
  default     = true
}

variable "cloudtrail_log_retention_days" {
  description = "Days to retain CloudTrail logs in S3 before expiration"
  type        = number
  default     = 2555
}

variable "is_organization_trail" {
  description = "Create an organization-wide CloudTrail (requires management account)"
  type        = bool
  default     = false
}

variable "enable_s3_data_events" {
  description = "Enable S3 data event logging in CloudTrail. Increases cost."
  type        = bool
  default     = false
}

variable "enable_config" {
  description = "Enable AWS Config recorder and delivery channel"
  type        = bool
  default     = true
}

variable "config_log_retention_days" {
  description = "Days to retain Config snapshots in S3"
  type        = number
  default     = 2555
}

variable "enable_cis_config_rules" {
  description = "Enable AWS Config managed rules. Parent toggle - individual rules can be disabled below."
  type        = bool
  default     = true
}

variable "enable_config_rule_root_access_key" {
  description = "Config rule to flag if root account has access keys"
  type        = bool
  default     = true
}

variable "enable_config_rule_root_mfa" {
  description = "Config rule to flag if root account lacks MFA"
  type        = bool
  default     = true
}

variable "enable_config_rule_root_hardware_mfa" {
  description = "Config rule to flag if root account lacks hardware MFA"
  type        = bool
  default     = true
}

variable "enable_config_rule_ebs_encryption" {
  description = "Config rule to flag unencrypted EBS volumes"
  type        = bool
  default     = true
}

variable "enable_config_rule_rds_encryption" {
  description = "Config rule to flag unencrypted RDS instances"
  type        = bool
  default     = true
}

variable "enable_config_rule_kms_rotation" {
  description = "Config rule to flag CMKs without automatic rotation"
  type        = bool
  default     = true
}

variable "enable_config_rule_default_sg_closed" {
  description = "Config rule to flag default security groups with rules"
  type        = bool
  default     = true
}

variable "enable_config_rule_iam_user_mfa" {
  description = "Config rule to flag IAM users without MFA"
  type        = bool
  default     = true
}

variable "enable_config_rule_s3_encryption" {
  description = "Config rule to flag S3 buckets without encryption"
  type        = bool
  default     = true
}

variable "cloudwatch_log_retention_days" {
  description = "Default retention period for CloudWatch log groups in days"
  type        = number
  default     = 365

  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.cloudwatch_log_retention_days)
    error_message = "Must be a valid CloudWatch Logs retention value."
  }
}

variable "cloudwatch_log_deletion_protection" {
  description = "Enable deletion protection on the CloudTrail CloudWatch log group"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_data_protection" {
  description = "Enable data protection policy to automatically mask credentials (AWS secret keys, SSH/PGP/PKCS/Putty private keys) if they appear in CloudTrail logs"
  type        = bool
  default     = true
}

# S3 Access Logging

variable "s3_object_lock_mode" {
  description = "S3 Object Lock retention mode. GOVERNANCE allows privileged users to override, COMPLIANCE prevents all deletions including root."
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.s3_object_lock_mode)
    error_message = "s3_object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "enable_s3_object_lock_cloudtrail" {
  description = "Enable S3 Object Lock on the CloudTrail logs bucket. Mode controlled by s3_object_lock_mode. WARNING: flipping this on an existing bucket destroys and recreates it."
  type        = bool
  default     = false
}

variable "s3_object_lock_cloudtrail_retention_days" {
  description = "Days to retain CloudTrail log objects under Object Lock"
  type        = number
  default     = 90

  validation {
    condition     = var.s3_object_lock_cloudtrail_retention_days >= 1
    error_message = "Object Lock retention must be at least 1 day."
  }
}

variable "enable_s3_object_lock_config" {
  description = "Enable S3 Object Lock on the Config logs bucket. Mode controlled by s3_object_lock_mode. WARNING: flipping this on an existing bucket destroys and recreates it."
  type        = bool
  default     = false
}

variable "s3_object_lock_config_retention_days" {
  description = "Days to retain Config log objects under Object Lock"
  type        = number
  default     = 90

  validation {
    condition     = var.s3_object_lock_config_retention_days >= 1
    error_message = "Object Lock retention must be at least 1 day."
  }
}

variable "enable_s3_object_lock_access_logs" {
  description = "Enable S3 Object Lock on the access logs bucket. Mode controlled by s3_object_lock_mode. WARNING: flipping this on an existing bucket destroys and recreates it."
  type        = bool
  default     = false
}

variable "s3_object_lock_access_logs_retention_days" {
  description = "Days to retain access log objects under Object Lock"
  type        = number
  default     = 30

  validation {
    condition     = var.s3_object_lock_access_logs_retention_days >= 1
    error_message = "Object Lock retention must be at least 1 day."
  }
}

variable "enable_s3_object_lock_access_logs_meta" {
  description = "Enable S3 Object Lock on the access logs meta bucket. Mode controlled by s3_object_lock_mode."
  type        = bool
  default     = false
}

variable "s3_object_lock_access_logs_meta_retention_days" {
  description = "Days to retain access logs meta objects under Object Lock"
  type        = number
  default     = 30

  validation {
    condition     = var.s3_object_lock_access_logs_meta_retention_days >= 1
    error_message = "Object Lock retention must be at least 1 day."
  }
}

variable "access_log_retention_days" {
  description = "Number of days to retain S3 access logs before expiration."
  type        = number
  default     = 365

  validation {
    condition     = var.access_log_retention_days >= 365
    error_message = "Access log retention must be at least 365 days."
  }
}

# Security Alarms
# For active security monitoring, set alarm_notification_email.

variable "enable_security_alarms" {
  description = "Enable CloudWatch metric filters and alarms for security events. Requires enable_cloudtrail = true. Optionally set alarm_notification_email for email notifications."
  type        = bool
  default     = true
}

variable "alarm_notification_email" {
  description = "Email address to receive security alarm notifications. When empty, alarms are still created but no email notifications are sent."
  type        = string
  default     = ""

  validation {
    condition     = var.alarm_notification_email == "" || can(regex("^[^@]+@[^@]+\\.[^@]+$", var.alarm_notification_email))
    error_message = "alarm_notification_email must be a valid email address or empty."
  }
}

variable "enable_finding_notifications" {
  description = "Route HIGH and CRITICAL findings from GuardDuty, Security Hub, Inspector, and Macie to the security alarms SNS topic via EventBridge. Requires alarm_notification_email to be set."
  type        = bool
  default     = false
}

variable "eventbridge_bus_name" {
  description = "Name of the EventBridge bus to use for finding notifications. Defaults to the default bus."
  type        = string
  default     = "default"
}

# Threat Detection & Security Services

# GuardDuty

variable "enable_guardduty" {
  description = "Enable Amazon GuardDuty for threat detection"
  type        = bool
  default     = true
}

variable "enable_guardduty_s3_protection" {
  description = "Enable GuardDuty S3 data event monitoring"
  type        = bool
  default     = true
}

variable "enable_guardduty_eks_protection" {
  description = "Enable GuardDuty EKS audit log monitoring"
  type        = bool
  default     = true
}

variable "enable_guardduty_malware_protection" {
  description = "Enable GuardDuty malware protection (EBS volume scanning on suspicious activity)"
  type        = bool
  default     = true
}

variable "enable_guardduty_rds_protection" {
  description = "Enable GuardDuty RDS login activity monitoring"
  type        = bool
  default     = true
}

variable "enable_guardduty_runtime_monitoring" {
  description = "Enable GuardDuty Runtime Monitoring"
  type        = bool
  default     = true
}

variable "enable_guardduty_lambda_protection" {
  description = "Enable GuardDuty Lambda network activity monitoring"
  type        = bool
  default     = true
}

# Security Hub

variable "enable_security_hub" {
  description = "Enable AWS Security Hub for centralized security posture management"
  type        = bool
  default     = true
}

variable "enable_security_hub_cis" {
  description = "Enable CIS Foundations Benchmark standard in Security Hub"
  type        = bool
  default     = true
}

variable "enable_security_hub_aws_foundational" {
  description = "Enable AWS Foundational Security Best Practices in Security Hub"
  type        = bool
  default     = true
}

variable "enable_security_hub_pci_dss" {
  description = "Enable PCI DSS standard in Security Hub (for payment card environments)"
  type        = bool
  default     = false
}

variable "enable_security_hub_nist_800_171" {
  description = "Enable NIST SP 800-171 Revision 2 standard in Security Hub (for CUI protection requirements)"
  type        = bool
  default     = false
}

variable "enable_security_hub_nist_800_53" {
  description = "Enable NIST SP 800-53 Revision 5 standard in Security Hub (for federal information systems)"
  type        = bool
  default     = false
}

variable "enable_security_hub_cross_region" {
  description = "Enable cross-region finding aggregation in Security Hub"
  type        = bool
  default     = true
}

# Run 'aws securityhub describe-standards' to list all available standards and versions in your region.

variable "security_hub_cis_version" {
  description = "Version of the CIS AWS Foundations Benchmark standard. Run 'aws securityhub describe-standards' to see available versions."
  type        = string
  default     = "3.0.0"
}

variable "security_hub_aws_foundational_version" {
  description = "Version of the AWS Foundational Security Best Practices standard. Run 'aws securityhub describe-standards' to see available versions."
  type        = string
  default     = "1.0.0"
}

variable "security_hub_pci_dss_version" {
  description = "Version of the PCI DSS standard. Run 'aws securityhub describe-standards' to see available versions."
  type        = string
  default     = "4.0.1"
}

variable "security_hub_nist_800_171_version" {
  description = "Version of the NIST SP 800-171 standard. Run 'aws securityhub describe-standards' to see available versions."
  type        = string
  default     = "2.0.0"
}

variable "security_hub_nist_800_53_version" {
  description = "Version of the NIST SP 800-53 standard. Run 'aws securityhub describe-standards' to see available versions."
  type        = string
  default     = "5.0.0"
}

# Macie

variable "enable_macie" {
  description = "Enable Amazon Macie for sensitive data discovery"
  type        = bool
  default     = true
}

variable "macie_classification_export_bucket_name" {
  description = "S3 bucket for Macie classification results. Leave empty to skip."
  type        = string
  default     = ""
}

variable "macie_kms_key_arn" {
  description = "KMS key ARN for Macie classification export encryption"
  type        = string
  default     = ""

  validation {
    condition     = var.macie_kms_key_arn == "" || can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/", var.macie_kms_key_arn))
    error_message = "macie_kms_key_arn must be a valid KMS key ARN (arn:aws:kms:REGION:ACCOUNT:key/KEY-ID) or empty."
  }
}

# Inspector

variable "enable_inspector" {
  description = "Enable Amazon Inspector v2 for vulnerability scanning"
  type        = bool
  default     = true
}

variable "enable_inspector_ec2" {
  description = "Enable Inspector EC2 instance scanning"
  type        = bool
  default     = true
}

variable "enable_inspector_ecr" {
  description = "Enable Inspector ECR container image scanning"
  type        = bool
  default     = true
}

variable "enable_inspector_lambda" {
  description = "Enable Inspector Lambda function scanning"
  type        = bool
  default     = true
}

# Lambda code scanning is a premium feature with additional cost.
# Unlike standard Lambda scanning (which checks dependencies for known CVEs),
# this scans your actual application code for vulnerabilities like injection flaws and hardcoded secrets.
# To enable it, add enable_inspector_lambda_code = true in your terraform.tfvars
variable "enable_inspector_lambda_code" {
  description = "Enable Inspector Lambda code scanning for code vulnerabilities"
  type        = bool
  default     = false
}

# Detective

variable "enable_detective" {
  description = "Enable Amazon Detective for security investigation"
  type        = bool
  default     = true
}

# AWS Organizations Guardrails (Conditional)

variable "enable_scps" {
  description = "Enable Service Control Policies. Parent toggle — requires is_organization_account = true."
  type        = bool
  default     = false
}

variable "enable_scp_deny_root_usage" {
  description = "SCP: Block all root user actions in member accounts"
  type        = bool
  default     = true
}

variable "enable_scp_deny_unapproved_regions" {
  description = "SCP: Restrict API calls to approved regions only. Requires allowed_regions to be set."
  type        = bool
  default     = true
}

variable "enable_scp_deny_disable_security" {
  description = "SCP: Block disabling CloudTrail, GuardDuty, Config, Security Hub, Access Analyzer, S3 BPA"
  type        = bool
  default     = true
}

variable "enable_scp_enforce_encryption" {
  description = "SCP: Deny unencrypted RDS/EBS creation and KMS key deletion with < 14 day window"
  type        = bool
  default     = true
}

variable "enable_scp_deny_public_ami" {
  description = "SCP: Block making AMIs public via ModifyImageAttribute"
  type        = bool
  default     = true
}

variable "enable_scp_deny_leave_organization" {
  description = "SCP: Prevent member accounts from leaving the organization"
  type        = bool
  default     = false
}

variable "enable_scp_deny_delete_flow_logs" {
  description = "SCP: Prevent deletion of VPC flow logs"
  type        = bool
  default     = false
}

variable "enable_scp_deny_deactivate_mfa" {
  description = "SCP: Prevent deactivating or deleting MFA devices and creating root access keys"
  type        = bool
  default     = false
}

variable "enable_scp_deny_imdsv1" {
  description = "SCP: Prevent launching EC2 instances without IMDSv2 required and prevent modifying existing instances to disable IMDSv2"
  type        = bool
  default     = false
}

variable "scp_target_ou_ids" {
  description = "List of OU IDs to attach SCPs to. Can be the organization root ID (e.g., ou-ab12-cdef3456, r-ab12)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.scp_target_ou_ids : can(regex("^(ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}|r-[a-z0-9]{4,32})$", id))])
    error_message = "Each scp_target_ou_ids entry must be a valid OU ID (ou-xxxx-xxxxxxxx) or organization root ID (r-xxxx)."
  }
}

variable "allowed_regions" {
  description = "AWS regions allowed by region-deny SCP. Leave empty to skip region restriction (e.g., us-east-1, eu-west-2)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for r in var.allowed_regions : can(regex("^[a-z]{2}(-gov)?-(north|south|east|west|central|northeast|southeast|northwest|southwest)-[0-9]+$", r))])
    error_message = "Each allowed_regions entry must be a valid AWS region (e.g., us-east-1, eu-west-2, us-gov-west-1)."
  }
}

variable "enable_tag_policies" {
  description = "Enable organization-wide tag policies"
  type        = bool
  default     = false
}

variable "required_tags" {
  description = "Map of required tag keys and enforcement configuration for tag policies"
  type = map(object({
    enforced_values = optional(list(string))
    enforced_for    = optional(list(string))
  }))
  default = {
    Environment = {
      enforced_values = ["dev", "staging", "production"]
      enforced_for    = null
    }
    ManagedBy = {
      enforced_values = ["Terraform"]
      enforced_for    = null
    }
  }
}

variable "enable_backup_policies" {
  description = "Enable organization-wide backup policies"
  type        = bool
  default     = false
}

variable "backup_retention_days" {
  description = "Days to retain backups via organization backup policy"
  type        = number
  default     = 35
}

variable "backup_regions" {
  description = "List of AWS regions where backups should run. Leave empty to back up in all regions (e.g., us-east-1, eu-west-2)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for r in var.backup_regions : can(regex("^[a-z]{2}(-gov)?-(north|south|east|west|central|northeast|southeast|northwest|southwest)-[0-9]+$", r))])
    error_message = "Each backup_regions entry must be a valid AWS region (e.g., us-east-1, eu-west-2, us-gov-west-1)."
  }
}

variable "enable_ai_opt_out_policy" {
  description = "Opt out of AWS AI services using content for model training"
  type        = bool
  default     = false
}

variable "enable_ram_org_sharing" {
  description = "Enable AWS RAM sharing within the organization"
  type        = bool
  default     = false
}

# Billing & Account Governance

variable "enable_budget_alerts" {
  description = "Enable monthly cost budget with alert notifications"
  type        = bool
  default     = true
}

variable "monthly_budget_amount" {
  description = "Monthly budget amount in USD"
  type        = number
  default     = 1000
}

variable "budget_notification_emails" {
  description = "Email addresses for budget and cost anomaly notifications"
  type        = list(string)
  default     = []
}

variable "enable_cost_anomaly_detection" {
  description = "Enable AWS Cost Anomaly Detection"
  type        = bool
  default     = true
}

variable "cost_anomaly_threshold_amount" {
  description = "Minimum dollar impact before triggering cost anomaly alert"
  type        = number
  default     = 100
}

# Alternate Contacts

variable "security_contact_name" {
  description = "Security contact name"
  type        = string
  default     = ""
}

variable "security_contact_title" {
  description = "Security contact title"
  type        = string
  default     = "Security Team"
}

variable "security_contact_email" {
  description = "Security contact email. Leave empty to skip."
  type        = string
  default     = ""
}

variable "security_contact_phone" {
  description = "Security contact phone number"
  type        = string
  default     = ""
}

variable "billing_contact_name" {
  description = "Billing contact name"
  type        = string
  default     = ""
}

variable "billing_contact_title" {
  description = "Billing contact title"
  type        = string
  default     = "Finance Team"
}

variable "billing_contact_email" {
  description = "Billing contact email. Leave empty to skip."
  type        = string
  default     = ""
}

variable "billing_contact_phone" {
  description = "Billing contact phone number"
  type        = string
  default     = ""
}

variable "operations_contact_name" {
  description = "Operations contact name"
  type        = string
  default     = ""
}

variable "operations_contact_title" {
  description = "Operations contact title"
  type        = string
  default     = "Operations Team"
}

variable "operations_contact_email" {
  description = "Operations contact email. Leave empty to skip."
  type        = string
  default     = ""
}

variable "operations_contact_phone" {
  description = "Operations contact phone number"
  type        = string
  default     = ""
}
