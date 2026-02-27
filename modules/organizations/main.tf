# Organizations Guardrails - conditional, management account only

data "aws_caller_identity" "current" {}

resource "terraform_data" "validate_scp_targets" {
  count = var.enable_scps ? 1 : 0

  lifecycle {
    precondition {
      condition     = length(var.scp_target_ou_ids) > 0
      error_message = "scp_target_ou_ids must not be empty when enable_scps is true. SCPs would be created but not attached to any OU."
    }
  }
}

# SCP: Deny root account usage - forces IAM-based access
resource "aws_organizations_policy" "deny_root_usage" {
  count = var.enable_scps && var.enable_scp_deny_root_usage ? 1 : 0

  name        = "${var.project_name}-deny-root-usage"
  description = "Deny all actions by root user to enforce IAM-based access"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyRootUsage"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:root"
          }
        }
      }
    ]
  })

  tags = { Purpose = "Prevent root account usage" }
}

resource "aws_organizations_policy_attachment" "deny_root_usage" {
  for_each = var.enable_scps && var.enable_scp_deny_root_usage ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.deny_root_usage[0].id
  target_id = each.value
}

resource "terraform_data" "validate_allowed_regions" {
  count = var.enable_scps && var.enable_scp_deny_unapproved_regions ? 1 : 0

  lifecycle {
    precondition {
      condition     = length(var.allowed_regions) > 0
      error_message = "allowed_regions must not be empty when enable_scp_deny_unapproved_regions is true. The SCP would not be created."
    }
  }
}

# SCP: Deny unapproved regions - restricts API calls to allowed regions
resource "aws_organizations_policy" "deny_unapproved_regions" {
  count = var.enable_scps && var.enable_scp_deny_unapproved_regions && length(var.allowed_regions) > 0 ? 1 : 0

  name        = "${var.project_name}-deny-unapproved-regions"
  description = "Restrict usage to approved AWS regions only"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnapprovedRegions"
        Effect = "Deny"
        NotAction = [
          "a4b:*",
          "account:*",
          "acm:*",
          "artifact:*",
          "aws-marketplace*:*",
          "billing:*",
          "budgets:*",
          "ce:*",
          "chime:*",
          "cloudfront:*",
          "consolidatedbilling:*",
          "cur:*",
          "freetier:*",
          "globalaccelerator:*",
          "health:*",
          "iam:*",
          "importexport:*",
          "invoicing:*",
          "organizations:*",
          "payments:*",
          "pricing:*",
          "route53:*",
          "route53domains:*",
          "s3:GetBucketLocation",
          "s3:ListAllMyBuckets",
          "savingsplans:*",
          "shield:*",
          "sts:*",
          "support:*",
          "tag:*",
          "tax:*",
          "trustedadvisor:*",
          "waf-regional:*",
          "waf:*",
          "wafv2:*"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = var.allowed_regions
          }
        }
      }
    ]
  })

  tags = { Purpose = "Region restriction" }
}

resource "aws_organizations_policy_attachment" "deny_unapproved_regions" {
  for_each = var.enable_scps && var.enable_scp_deny_unapproved_regions && length(var.allowed_regions) > 0 ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.deny_unapproved_regions[0].id
  target_id = each.value
}

# SCP: Deny disabling security services - protects CloudTrail, GuardDuty, Config, etc.
resource "aws_organizations_policy" "deny_disable_security" {
  count = var.enable_scps && var.enable_scp_deny_disable_security ? 1 : 0

  name        = "${var.project_name}-deny-disable-security-services"
  description = "Prevent disabling of critical security services"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyDisableCloudTrail"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:PutEventSelectors"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisableGuardDuty"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:DisassociateFromAdministratorAccount",
          "guardduty:DeletePublishingDestination",
          "guardduty:UpdatePublishingDestination"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisableConfig"
        Effect = "Deny"
        Action = [
          "config:StopConfigurationRecorder",
          "config:DeleteConfigurationRecorder",
          "config:DeleteDeliveryChannel"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisableSecurityHub"
        Effect = "Deny"
        Action = [
          "securityhub:DisableSecurityHub",
          "securityhub:DeleteMembers",
          "securityhub:DisassociateMembers"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisableAccessAnalyzer"
        Effect = "Deny"
        Action = [
          "access-analyzer:DeleteAnalyzer"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisableMacie"
        Effect = "Deny"
        Action = [
          "macie2:DisableMacie",
          "macie2:DisassociateFromAdministratorAccount",
          "macie2:DisassociateFromMasterAccount"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisableInspector"
        Effect = "Deny"
        Action = [
          "inspector2:Disable",
          "inspector2:DisassociateMember"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisableDetective"
        Effect = "Deny"
        Action = [
          "detective:DeleteGraph",
          "detective:DisassociateMembership"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyModifyAccountPublicAccessBlock"
        Effect = "Deny"
        Action = [
          "s3:PutAccountPublicAccessBlock",
          "s3:DeleteAccountPublicAccessBlock"
        ]
        Resource = "*"
      }
    ]
  })

  tags = { Purpose = "Protect security services from being disabled" }
}

resource "aws_organizations_policy_attachment" "deny_disable_security" {
  for_each = var.enable_scps && var.enable_scp_deny_disable_security ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.deny_disable_security[0].id
  target_id = each.value
}

# SCP: Enforce encryption - deny unencrypted RDS/EBS and short KMS deletion windows
resource "aws_organizations_policy" "enforce_encryption" {
  count = var.enable_scps && var.enable_scp_enforce_encryption ? 1 : 0

  name        = "${var.project_name}-enforce-encryption"
  description = "Enforce encryption requirements for data at rest"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyUnencryptedRDS"
        Effect   = "Deny"
        Action   = "rds:CreateDBInstance"
        Resource = "*"
        Condition = {
          Bool = {
            "rds:StorageEncrypted" = "false"
          }
        }
      },
      {
        Sid      = "DenyUnencryptedEBS"
        Effect   = "Deny"
        Action   = "ec2:CreateVolume"
        Resource = "*"
        Condition = {
          Bool = {
            "ec2:Encrypted" = "false"
          }
        }
      },
      {
        Sid      = "DenyKMSKeyDeletionWithShortWindow"
        Effect   = "Deny"
        Action   = "kms:ScheduleKeyDeletion"
        Resource = "*"
        Condition = {
          NumericLessThan = {
            "kms:ScheduleKeyDeletionPendingWindowInDays" = "14"
          }
        }
      }
    ]
  })

  tags = { Purpose = "Enforce encryption guardrails" }
}

resource "aws_organizations_policy_attachment" "enforce_encryption" {
  for_each = var.enable_scps && var.enable_scp_enforce_encryption ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.enforce_encryption[0].id
  target_id = each.value
}

# SCP: Deny public AMI sharing
resource "aws_organizations_policy" "deny_public_ami" {
  count = var.enable_scps && var.enable_scp_deny_public_ami ? 1 : 0

  name        = "${var.project_name}-deny-public-ami-snapshot-sharing"
  description = "Prevent sharing AMIs and EBS snapshots publicly"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyPublicAMI"
        Effect   = "Deny"
        Action   = "ec2:ModifyImageAttribute"
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:Add/group" = "all"
          }
        }
      },
      {
        Sid      = "DenyPublicSnapshot"
        Effect   = "Deny"
        Action   = "ec2:ModifySnapshotAttribute"
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:Add/group" = "all"
          }
        }
      }
    ]
  })

  tags = { Purpose = "Prevent public AMI and snapshot sharing" }
}

resource "aws_organizations_policy_attachment" "deny_public_ami" {
  for_each = var.enable_scps && var.enable_scp_deny_public_ami ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.deny_public_ami[0].id
  target_id = each.value
}

# SCP: Deny leaving the organization - prevents accounts from detaching and escaping SCPs
resource "aws_organizations_policy" "deny_leave_organization" {
  count = var.enable_scps && var.enable_scp_deny_leave_organization ? 1 : 0

  name        = "${var.project_name}-deny-leave-organization"
  description = "Prevent member accounts from leaving the organization"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyLeaveOrganization"
        Effect   = "Deny"
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
      }
    ]
  })

  tags = { Purpose = "Prevent accounts from leaving organization" }
}

resource "aws_organizations_policy_attachment" "deny_leave_organization" {
  for_each = var.enable_scps && var.enable_scp_deny_leave_organization ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.deny_leave_organization[0].id
  target_id = each.value
}

# SCP: Deny deleting VPC flow logs - protects network audit trail
resource "aws_organizations_policy" "deny_delete_flow_logs" {
  count = var.enable_scps && var.enable_scp_deny_delete_flow_logs ? 1 : 0

  name        = "${var.project_name}-deny-delete-flow-logs"
  description = "Prevent deletion of VPC flow logs"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyDeleteFlowLogs"
        Effect   = "Deny"
        Action   = "ec2:DeleteFlowLogs"
        Resource = "*"
      }
    ]
  })

  tags = { Purpose = "Protect VPC flow logs from deletion" }
}

resource "aws_organizations_policy_attachment" "deny_delete_flow_logs" {
  for_each = var.enable_scps && var.enable_scp_deny_delete_flow_logs ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.deny_delete_flow_logs[0].id
  target_id = each.value
}

# SCP: Deny deactivating MFA - prevents credential compromise escalation
resource "aws_organizations_policy" "deny_deactivate_mfa" {
  count = var.enable_scps && var.enable_scp_deny_deactivate_mfa ? 1 : 0

  name        = "${var.project_name}-deny-deactivate-mfa"
  description = "Prevent deactivating MFA devices and creating root access keys"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyDeactivateMFA"
        Effect = "Deny"
        Action = [
          "iam:DeactivateMFADevice",
          "iam:DeleteVirtualMFADevice"
        ]
        Resource = "*"
      },
      {
        Sid      = "DenyCreateRootAccessKey"
        Effect   = "Deny"
        Action   = "iam:CreateAccessKey"
        Resource = "arn:aws:iam::*:root"
      }
    ]
  })

  tags = { Purpose = "Protect MFA devices and prevent root access keys" }
}

resource "aws_organizations_policy_attachment" "deny_deactivate_mfa" {
  for_each = var.enable_scps && var.enable_scp_deny_deactivate_mfa ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.deny_deactivate_mfa[0].id
  target_id = each.value
}

# SCP - Deny launching EC2 instances without IMDSv2
resource "aws_organizations_policy" "deny_imdsv1" {
  count = var.enable_scps && var.enable_scp_deny_imdsv1 ? 1 : 0

  name        = "${var.project_name}-deny-imdsv1"
  description = "Prevent launching EC2 instances without IMDSv2 required"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyIMDSv1"
        Effect   = "Deny"
        Action   = "ec2:RunInstances"
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens" = "required"
          }
        }
      },
      {
        Sid      = "DenyModifyToIMDSv1"
        Effect   = "Deny"
        Action   = "ec2:ModifyInstanceMetadataOptions"
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens" = "required"
          }
        }
      }
    ]
  })

  tags = { Purpose = "Enforce IMDSv2" }
}

resource "aws_organizations_policy_attachment" "deny_imdsv1" {
  for_each = var.enable_scps && var.enable_scp_deny_imdsv1 ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.deny_imdsv1[0].id
  target_id = each.value
}

# Tag policy - enforce consistent tagging across the organization
resource "aws_organizations_policy" "tag_policy" {
  count = var.enable_tag_policies ? 1 : 0

  name        = "${var.project_name}-tag-policy"
  description = "Enforce consistent tagging across the organization"
  type        = "TAG_POLICY"

  content = jsonencode({
    tags = {
      for tag_key, tag_config in var.required_tags : tag_key => {
        tag_key = {
          "@@assign" = tag_key
        }
        tag_value = tag_config.enforced_values != null ? {
          "@@assign" = tag_config.enforced_values
        } : {}
        enforced_for = tag_config.enforced_for != null ? {
          "@@assign" = tag_config.enforced_for
        } : {}
      }
    }
  })

  tags = { Purpose = "Tag governance" }
}

resource "aws_organizations_policy_attachment" "tag_policy" {
  for_each = var.enable_tag_policies ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.tag_policy[0].id
  target_id = each.value
}

# Backup policy - organization-wide daily backup with retention
resource "aws_organizations_policy" "backup_policy" {
  count = var.enable_backup_policies ? 1 : 0

  name        = "${var.project_name}-backup-policy"
  description = "Organization-wide backup policy for critical resources"
  type        = "BACKUP_POLICY"

  content = jsonencode({
    plans = {
      "${var.project_name}-backup-plan" = {
        regions = {
          "@@assign" = var.backup_regions
        }
        rules = {
          daily_backup = {
            schedule_expression = {
              "@@assign" = "cron(0 5 ? * * *)"
            }
            start_backup_window_minutes = {
              "@@assign" = "60"
            }
            complete_backup_window_minutes = {
              "@@assign" = "180"
            }
            lifecycle = {
              delete_after_days = {
                "@@assign" = tostring(var.backup_retention_days)
              }
            }
            target_backup_vault_name = {
              "@@assign" = "Default"
            }
          }
        }
        selections = {
          tags = {
            backup_tagged = {
              iam_role_arn = {
                "@@assign" = "arn:aws:iam::$account:role/aws-service-role/backup.amazonaws.com/AWSServiceRoleForBackup"
              }
              tag_key = {
                "@@assign" = "Backup"
              }
              tag_value = {
                "@@assign" = ["true", "True", "TRUE"]
              }
            }
          }
        }
      }
    }
  })

  tags = { Purpose = "Centralized backup governance" }
}

resource "aws_organizations_policy_attachment" "backup_policy" {
  for_each = var.enable_backup_policies ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.backup_policy[0].id
  target_id = each.value
}

# AI services opt-out - prevents AWS from using content for ML training
resource "aws_organizations_policy" "ai_opt_out" {
  count = var.enable_ai_opt_out_policy ? 1 : 0

  name        = "${var.project_name}-ai-services-opt-out"
  description = "Opt out of AWS AI services using content for model improvement"
  type        = "AISERVICES_OPT_OUT_POLICY"

  content = jsonencode({
    services = {
      "@@operators_allowed_for_child_policies" = ["@@none"]
      default = {
        "@@operators_allowed_for_child_policies" = ["@@none"]
        opt_out_policy = {
          "@@assign"                               = "optOut"
          "@@operators_allowed_for_child_policies" = ["@@none"]
        }
      }
    }
  })

  tags = { Purpose = "AI services data privacy" }
}

resource "aws_organizations_policy_attachment" "ai_opt_out" {
  for_each = var.enable_ai_opt_out_policy ? toset(var.scp_target_ou_ids) : toset([])

  policy_id = aws_organizations_policy.ai_opt_out[0].id
  target_id = each.value
}

# RAM sharing within organization - no external invitations needed
resource "aws_ram_resource_share" "org_sharing" {
  count = var.enable_ram_org_sharing ? 1 : 0

  name                      = "${var.project_name}-org-resource-share"
  allow_external_principals = false

  tags = { Purpose = "Organization resource sharing" }
}
