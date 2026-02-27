variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

# Password Policy

variable "password_minimum_length" {
  description = "Minimum password length (14+ recommended)"
  type        = number
  default     = 14
}

variable "password_reuse_prevention" {
  description = "Number of previous passwords to remember (24 recommended)"
  type        = number
  default     = 24
}

variable "password_max_age_days" {
  description = "Maximum password age in days before forced rotation (90 recommended)"
  type        = number
  default     = 90
}

variable "password_hard_expiry" {
  description = "Whether expired passwords require administrator reset (true) or allow self-service reset (false)"
  type        = bool
  default     = true
}

# Access Analyzer

variable "is_organization_account" {
  description = "Whether this account is the management account of an AWS Organization. Controls Access Analyzer scope (ORGANIZATION vs ACCOUNT)."
  type        = bool
  default     = false
}

variable "enable_unused_access_analyzer" {
  description = "Enable IAM Access Analyzer for unused access findings. Requires IAM Access Analyzer paid feature."
  type        = bool
  default     = true
}

variable "unused_access_age_days" {
  description = "Number of days of inactivity before access is flagged as unused"
  type        = number
  default     = 90
}
