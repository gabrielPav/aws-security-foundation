# Threat Detection & Security Services

# Pre-flight: detect existing singleton resources (AWS allows only one per region)
data "external" "existing_guardduty_detector" {
  count   = var.enable_guardduty ? 1 : 0
  program = [
    "bash", "-c",
    "id=$(aws guardduty list-detectors --region ${data.aws_region.current.name} --query 'DetectorIds[0]' --output text 2>/dev/null || echo ''); [ \"$id\" = 'None' ] && id=''; printf '{\"id\":\"%s\"}' \"$id\""
  ]
}

data "external" "existing_security_hub" {
  count   = var.enable_security_hub ? 1 : 0
  program = [
    "bash", "-c",
    "arn=$(aws securityhub describe-hub --region ${data.aws_region.current.name} --query 'HubArn' --output text 2>/dev/null || echo ''); [ \"$arn\" = 'None' ] && arn=''; printf '{\"arn\":\"%s\"}' \"$arn\""
  ]
}

data "external" "existing_macie" {
  count   = var.enable_macie ? 1 : 0
  program = [
    "bash", "-c",
    "status=$(aws macie2 get-macie-session --region ${data.aws_region.current.name} --query 'status' --output text 2>/dev/null || echo ''); [ \"$status\" = 'ENABLED' ] && printf '{\"enabled\":\"true\"}' || printf '{\"enabled\":\"false\"}'"
  ]
}

data "external" "existing_detective" {
  count   = var.enable_detective ? 1 : 0
  program = [
    "bash", "-c",
    "arn=$(aws detective list-graphs --region ${data.aws_region.current.name} --query 'GraphList[0].Arn' --output text 2>/dev/null || echo ''); [ \"$arn\" = 'None' ] && arn=''; printf '{\"arn\":\"%s\"}' \"$arn\""
  ]
}

# Pre-flight validations: fail at plan time if a singleton resource exists in AWS
# but is NOT already managed by Terraform (needs import or manual cleanup).
resource "terraform_data" "validate_guardduty" {
  count = var.enable_guardduty ? 1 : 0

  lifecycle {
    precondition {
      condition     = data.external.existing_guardduty_detector[0].result.id == "" || length(aws_guardduty_detector.main) > 0
      error_message = <<-EOT
        A GuardDuty detector '${data.external.existing_guardduty_detector[0].result.id}' already exists in ${data.aws_region.current.name}.
        AWS allows only one detector per region. Either:
          1. Import it:  terraform import 'module.threat_detection.aws_guardduty_detector.main[0]' ${data.external.existing_guardduty_detector[0].result.id}
          2. Delete it:  aws guardduty delete-detector --region ${data.aws_region.current.name} --detector-id ${data.external.existing_guardduty_detector[0].result.id}
      EOT
    }
  }
}

resource "terraform_data" "validate_security_hub" {
  count = var.enable_security_hub ? 1 : 0

  lifecycle {
    precondition {
      condition     = data.external.existing_security_hub[0].result.arn == "" || length(aws_securityhub_account.main) > 0
      error_message = <<-EOT
        Security Hub is already enabled in ${data.aws_region.current.name} (${data.external.existing_security_hub[0].result.arn}).
        AWS allows only one Security Hub per region. Either:
          1. Import it:  terraform import 'module.threat_detection.aws_securityhub_account.main[0]' ${data.aws_caller_identity.current.account_id}
          2. Disable it: aws securityhub disable-security-hub --region ${data.aws_region.current.name}
      EOT
    }
  }
}

resource "terraform_data" "validate_macie" {
  count = var.enable_macie ? 1 : 0

  lifecycle {
    precondition {
      condition     = data.external.existing_macie[0].result.enabled == "false" || length(aws_macie2_account.main) > 0
      error_message = <<-EOT
        Macie is already enabled in ${data.aws_region.current.name}.
        AWS allows only one Macie session per region. Either:
          1. Import it:  terraform import 'module.threat_detection.aws_macie2_account.main[0]' ${data.aws_caller_identity.current.account_id}
          2. Disable it: aws macie2 disable-macie --region ${data.aws_region.current.name}
      EOT
    }
  }
}

resource "terraform_data" "validate_detective" {
  count = var.enable_detective ? 1 : 0

  lifecycle {
    precondition {
      condition     = data.external.existing_detective[0].result.arn == "" || length(aws_detective_graph.main) > 0
      error_message = <<-EOT
        A Detective graph already exists in ${data.aws_region.current.name} (${data.external.existing_detective[0].result.arn}).
        AWS allows only one Detective graph per region. Either:
          1. Import it:  terraform import 'module.threat_detection.aws_detective_graph.main[0]' ${data.external.existing_detective[0].result.arn}
          2. Delete it:  aws detective delete-graph --region ${data.aws_region.current.name} --graph-arn ${data.external.existing_detective[0].result.arn}
      EOT
    }
  }
}

# GuardDuty - threat detection
resource "aws_guardduty_detector" "main" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = {
    Name     = "${var.project_name}-guardduty"
    Purpose  = "Continuous threat detection and anomaly monitoring"
    Security = "threat-detection"
  }
}

# Optional GuardDuty features, toggled individually via variables
locals {
  guardduty_features = var.enable_guardduty ? {
    for name, enabled in {
      "S3_DATA_EVENTS"         = var.enable_guardduty_s3_protection
      "EKS_AUDIT_LOGS"         = var.enable_guardduty_eks_protection
      "EBS_MALWARE_PROTECTION" = var.enable_guardduty_malware_protection
      "RDS_LOGIN_EVENTS"       = var.enable_guardduty_rds_protection
      "RUNTIME_MONITORING"     = var.enable_guardduty_runtime_monitoring
      "LAMBDA_NETWORK_LOGS"    = var.enable_guardduty_lambda_protection
    } : name => name if enabled
  } : {}
}

resource "aws_guardduty_detector_feature" "features" {
  for_each = local.guardduty_features

  detector_id = aws_guardduty_detector.main[0].id
  name        = each.key
  status      = "ENABLED"
}

# Security Hub - centralized security posture management
resource "aws_securityhub_account" "main" {
  count = var.enable_security_hub ? 1 : 0

  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true
}

# Compliance standards, toggled individually via variables
locals {
  security_hub_standards = var.enable_security_hub ? {
    for key, cfg in {
      cis = {
        arn     = "arn:aws:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/${var.security_hub_cis_version}"
        enabled = var.enable_security_hub_cis
      }
      aws_foundational = {
        arn     = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/${var.security_hub_aws_foundational_version}"
        enabled = var.enable_security_hub_aws_foundational
      }
      pci_dss = {
        arn     = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/${var.security_hub_pci_dss_version}"
        enabled = var.enable_security_hub_pci_dss
      }
      nist_800_171 = {
        arn     = "arn:aws:securityhub:${data.aws_region.current.name}::standards/nist-800-171/v/${var.security_hub_nist_800_171_version}"
        enabled = var.enable_security_hub_nist_800_171
      }
      nist_800_53 = {
        arn     = "arn:aws:securityhub:${data.aws_region.current.name}::standards/nist-800-53/v/${var.security_hub_nist_800_53_version}"
        enabled = var.enable_security_hub_nist_800_53
      }
    } : key => cfg.arn if cfg.enabled
  } : {}
}

resource "aws_securityhub_standards_subscription" "standards" {
  for_each = local.security_hub_standards

  standards_arn = each.value

  depends_on = [aws_securityhub_account.main[0]]
}

# Cross-region finding aggregation
resource "aws_securityhub_finding_aggregator" "main" {
  count = var.enable_security_hub && var.enable_security_hub_cross_region ? 1 : 0

  linking_mode = "ALL_REGIONS"

  depends_on = [aws_securityhub_account.main[0]]
}

# Macie - sensitive data discovery in S3
resource "aws_macie2_account" "main" {
  count = var.enable_macie ? 1 : 0

  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# Macie classification export configuration
resource "aws_macie2_classification_export_configuration" "main" {
  count = var.enable_macie && var.macie_classification_export_bucket_name != "" ? 1 : 0

  s3_destination {
    bucket_name = var.macie_classification_export_bucket_name
    key_prefix  = "macie/classification-results/"
    kms_key_arn = var.macie_kms_key_arn
  }

  lifecycle {
    precondition {
      condition     = var.macie_kms_key_arn != ""
      error_message = "macie_kms_key_arn is required when macie_classification_export_bucket_name is set."
    }
  }

  depends_on = [aws_macie2_account.main[0]]
}

# Inspector v2 - vulnerability scanning for EC2, ECR, Lambda
resource "aws_inspector2_enabler" "main" {
  count = var.enable_inspector ? 1 : 0

  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = var.inspector_resource_types
}

# Detective - security investigation and incident response
resource "aws_detective_graph" "main" {
  count = var.enable_detective ? 1 : 0

  tags = {
    Name    = "${var.project_name}-detective"
    Purpose = "Security investigation and incident response"
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
