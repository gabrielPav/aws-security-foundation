variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

# SCPs

variable "enable_scps" {
  description = "Enable Service Control Policies. Parent toggle - requires AWS Organizations management account."
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
  description = "List of Organization Unit IDs to attach SCPs to. Can also be the organization root ID (e.g., ou-ab12-cdef3456, r-ab12)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.scp_target_ou_ids : can(regex("^(ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}|r-[a-z0-9]{4,32})$", id))])
    error_message = "Each scp_target_ou_ids entry must be a valid OU ID (ou-xxxx-xxxxxxxx) or organization root ID (r-xxxx)."
  }
}

variable "allowed_regions" {
  description = "List of AWS regions allowed by the region-deny SCP. Leave empty to skip region restriction (e.g., us-east-1, eu-west-2)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for r in var.allowed_regions : can(regex("^[a-z]{2}(-gov)?-(north|south|east|west|central|northeast|southeast|northwest|southwest)-[0-9]+$", r))])
    error_message = "Each allowed_regions entry must be a valid AWS region (e.g., us-east-1, eu-west-2, us-gov-west-1)."
  }
}

# Tag Policies

variable "enable_tag_policies" {
  description = "Enable organization-wide tag policies for consistent tagging"
  type        = bool
  default     = false
}

variable "required_tags" {
  description = "Map of required tag keys and their enforcement configuration"
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

# Backup Policies

variable "enable_backup_policies" {
  description = "Enable organization-wide backup policies"
  type        = bool
  default     = false
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

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 35

  validation {
    condition     = var.backup_retention_days >= 1
    error_message = "Backup retention must be at least 1 day."
  }
}

# AI Opt-Out

variable "enable_ai_opt_out_policy" {
  description = "Enable AI services opt-out policy to prevent AWS from using content for ML training"
  type        = bool
  default     = false
}

# RAM

variable "enable_ram_org_sharing" {
  description = "Enable AWS RAM sharing within the organization"
  type        = bool
  default     = false
}

