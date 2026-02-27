variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "kms_rotation_period_days" {
  description = "KMS key rotation period in days. Minimum 90, maximum 2560. CIS requires at least annual (365)."
  type        = number
  default     = 90

  validation {
    condition     = var.kms_rotation_period_days >= 90 && var.kms_rotation_period_days <= 2560
    error_message = "KMS rotation period must be between 90 and 2560 days."
  }
}

variable "ebs_default_kms_key_arn" {
  description = "ARN of an existing customer-managed KMS key for default EBS encryption. Used only when an externally managed key is preferred over the internally created one. Leave empty to use the internally created compute key."
  type        = string
  default     = ""

  validation {
    condition     = var.ebs_default_kms_key_arn == "" || can(regex("^arn:aws(-[a-z]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/", var.ebs_default_kms_key_arn))
    error_message = "ebs_default_kms_key_arn must be a valid KMS key ARN (arn:aws:kms:REGION:ACCOUNT:key/KEY-ID) or empty."
  }
}

# IMDSv2

variable "enable_imdsv2_default" {
  description = "Enforce IMDSv2 as the account-level default for all new EC2 instances. Does not affect existing instances."
  type        = bool
  default     = true
}

variable "imdsv2_hop_limit" {
  description = "HTTP PUT response hop limit for IMDSv2. Default is 1. In a container environment, set the hop limit to 2 (recommended)."
  type        = number
  default     = 1

  validation {
    condition     = var.imdsv2_hop_limit >= 1 && var.imdsv2_hop_limit <= 64
    error_message = "Hop limit must be between 1 and 64."
  }
}

# EC2 Serial Console

variable "disable_ec2_serial_console" {
  description = "Disable EC2 Serial Console access for the account. Eliminates out-of-band access path."
  type        = bool
  default     = true
}

# EMR

variable "enable_emr_block_public_access" {
  description = "Block public access on Amazon EMR on EC2. Prevents EMR clusters from launching with public security group rules."
  type        = bool
  default     = true
}

