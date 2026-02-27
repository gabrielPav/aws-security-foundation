variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

# Budget

variable "enable_budget_alerts" {
  description = "Enable monthly cost budget with alerts"
  type        = bool
  default     = true
}

variable "monthly_budget_amount" {
  description = "Monthly budget amount in USD"
  type        = number
  default     = 1000

  validation {
    condition     = var.monthly_budget_amount > 0
    error_message = "Monthly budget must be greater than 0."
  }
}

variable "budget_notification_emails" {
  description = "List of email addresses to receive budget and cost anomaly notifications"
  type        = list(string)
  default     = []
}

# Cost Anomaly Detection

variable "enable_cost_anomaly_detection" {
  description = "Enable AWS Cost Anomaly Detection for ML-based cost monitoring"
  type        = bool
  default     = true
}

variable "cost_anomaly_threshold_amount" {
  description = "Minimum dollar amount of impact before triggering a cost anomaly alert"
  type        = number
  default     = 100

  validation {
    condition     = var.cost_anomaly_threshold_amount > 0
    error_message = "Cost anomaly threshold must be greater than 0."
  }
}

# Security Contact

variable "security_contact_name" {
  description = "Name of the security contact"
  type        = string
  default     = ""
}

variable "security_contact_title" {
  description = "Title of the security contact"
  type        = string
  default     = "Security Team"
}

variable "security_contact_email" {
  description = "Email address of the security contact. Leave empty to skip."
  type        = string
  default     = ""
}

variable "security_contact_phone" {
  description = "Phone number of the security contact"
  type        = string
  default     = ""
}

# Billing Contact

variable "billing_contact_name" {
  description = "Name of the billing contact"
  type        = string
  default     = ""
}

variable "billing_contact_title" {
  description = "Title of the billing contact"
  type        = string
  default     = "Finance Team"
}

variable "billing_contact_email" {
  description = "Email address of the billing contact. Leave empty to skip."
  type        = string
  default     = ""
}

variable "billing_contact_phone" {
  description = "Phone number of the billing contact"
  type        = string
  default     = ""
}

# Operations Contact

variable "operations_contact_name" {
  description = "Name of the operations contact"
  type        = string
  default     = ""
}

variable "operations_contact_title" {
  description = "Title of the operations contact"
  type        = string
  default     = "Operations Team"
}

variable "operations_contact_email" {
  description = "Email address of the operations contact. Leave empty to skip."
  type        = string
  default     = ""
}

variable "operations_contact_phone" {
  description = "Phone number of the operations contact"
  type        = string
  default     = ""
}

