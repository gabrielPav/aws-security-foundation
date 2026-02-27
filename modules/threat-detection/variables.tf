variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

# GuardDuty

variable "enable_guardduty" {
  description = "Enable Amazon GuardDuty for intelligent threat detection"
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
  description = "Enable GuardDuty Runtime Monitoring for OS-level threat detection"
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
  description = "Enable AWS Foundational Security Best Practices standard in Security Hub"
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

variable "enable_security_hub_cross_region" {
  description = "Enable cross-region finding aggregation in Security Hub"
  type        = bool
  default     = true
}

# Macie

variable "enable_macie" {
  description = "Enable Amazon Macie for sensitive data discovery in S3"
  type        = bool
  default     = true
}

variable "macie_classification_export_bucket_name" {
  description = "S3 bucket name for Macie classification export results. Leave empty to skip export configuration."
  type        = string
  default     = ""
}

variable "macie_kms_key_arn" {
  description = "KMS key ARN for encrypting Macie classification export results"
  type        = string
  default     = ""

  validation {
    condition     = var.macie_kms_key_arn == "" || can(regex("^arn:aws(-[a-z]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/", var.macie_kms_key_arn))
    error_message = "macie_kms_key_arn must be a valid KMS key ARN (arn:aws:kms:REGION:ACCOUNT:key/KEY-ID) or empty."
  }
}

# Inspector

variable "enable_inspector" {
  description = "Enable Amazon Inspector v2 for vulnerability scanning"
  type        = bool
  default     = true
}

variable "inspector_resource_types" {
  description = "Resource types to enable for Inspector scanning"
  type        = list(string)
  default     = ["EC2", "ECR", "LAMBDA"]

  validation {
    condition     = alltrue([for rt in var.inspector_resource_types : contains(["EC2", "ECR", "LAMBDA", "LAMBDA_CODE"], rt)])
    error_message = "Inspector resource types must be one or more of: EC2, ECR, LAMBDA, LAMBDA_CODE."
  }
}

# Detective

variable "enable_detective" {
  description = "Enable Amazon Detective for security investigation and incident response"
  type        = bool
  default     = true
}

