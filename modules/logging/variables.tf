variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

# KMS Keys

variable "kms_observability_key_arn" {
  description = "ARN of the observability layer KMS key for CloudTrail trail, CloudWatch log groups, and SNS topics"
  type        = string
}

variable "kms_observability_key_id" {
  description = "ID of the observability layer KMS key (used for SNS kms_master_key_id)"
  type        = string
}

variable "kms_storage_key_arn" {
  description = "ARN of the storage layer KMS key for S3 log buckets (CloudTrail, Config)"
  type        = string
}

# CloudTrail

variable "enable_cloudtrail" {
  description = "Enable CloudTrail multi-region trail"
  type        = bool
  default     = true
}

variable "cloudtrail_log_retention_days" {
  description = "Number of days to retain CloudTrail logs in S3 before expiration"
  type        = number
  default     = 2555

  validation {
    condition     = var.cloudtrail_log_retention_days >= 365
    error_message = "CloudTrail logs should be retained for at least 365 days for compliance."
  }
}

variable "is_organization_trail" {
  description = "Whether to create an organization-wide trail (requires Organization management account)"
  type        = bool
  default     = false
}

variable "organization_id" {
  description = "AWS Organization ID (required if is_organization_trail is true)"
  type        = string
  default     = ""
}

variable "enable_s3_data_events" {
  description = "Enable S3 data event logging in CloudTrail. Increases cost but provides object-level audit trail."
  type        = bool
  default     = false
}

# AWS Config

variable "enable_config" {
  description = "Enable AWS Config recorder and delivery channel"
  type        = bool
  default     = true
}

variable "config_log_retention_days" {
  description = "Number of days to retain Config snapshots in S3 before expiration"
  type        = number
  default     = 2555

  validation {
    condition     = var.config_log_retention_days >= 365
    error_message = "Config log retention must be at least 365 days for compliance."
  }
}

variable "enable_cis_config_rules" {
  description = "Enable AWS Config managed rules for detective controls. Parent toggle - individual rules can be disabled below."
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

# CloudWatch

variable "cloudwatch_log_retention_days" {
  description = "Default retention period for CloudWatch log groups in days"
  type        = number
  default     = 365
}

# Security Alarms

variable "enable_security_alarms" {
  description = "Enable CloudWatch metric filters and alarms for security events. Requires enable_cloudtrail = true. Optionally set alarm_notification_email for email notifications."
  type        = bool
  default     = false
}

variable "alarm_notification_email" {
  description = "Email address to receive security alarm notifications. When empty, alarms are still created but no email notifications are sent."
  type        = string
  default     = ""
}

variable "enable_finding_notifications" {
  description = "Route HIGH and CRITICAL findings from GuardDuty, Security Hub, Inspector, and Macie to the security alarms SNS topic via EventBridge. Requires alarm_notification_email to be set."
  type        = bool
  default     = true
}

variable "is_organization_account" {
  description = "Whether this is an Organization management account. Controls whether Organizations change alarms are created."
  type        = bool
  default     = false
}

# S3 Lifecycle Tiering

variable "s3_transition_to_ia_days" {
  description = "Days before transitioning S3 objects to STANDARD_IA"
  type        = number
  default     = 90
}

variable "s3_transition_to_glacier_days" {
  description = "Days before transitioning S3 objects to GLACIER"
  type        = number
  default     = 365
}

# S3 Object Lock

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
}

# S3 Access Logging

variable "enable_s3_object_lock_access_logs" {
  description = "Enable S3 Object Lock on the access logs bucket. Mode controlled by s3_object_lock_mode. WARNING: flipping this on an existing bucket destroys and recreates it."
  type        = bool
  default     = false
}

variable "s3_object_lock_access_logs_retention_days" {
  description = "Days to retain access log objects under Object Lock"
  type        = number
  default     = 30
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
}

variable "access_log_retention_days" {
  description = "Number of days to retain S3 access logs before expiration."
  type        = number
  default     = 365
}

