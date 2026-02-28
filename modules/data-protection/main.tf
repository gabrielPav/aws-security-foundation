# Encryption & Data Protection - KMS keys per layer, account-level defaults

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# EBS encryption by default
resource "aws_ebs_encryption_by_default" "enabled" {
  enabled = true
}

# KMS Key - Compute Layer (EBS, Auto Scaling)
resource "aws_kms_key" "compute" {
  description             = "KMS key for ${var.project_name} compute layer - EBS and Auto Scaling"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = var.kms_rotation_period_days

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowEC2ToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "AllowAutoScalingToUseTheKey"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowAutoScalingToCreateGrants"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        }
        Action   = "kms:CreateGrant"
        Resource = "*"
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      }
    ]
  })

  tags = {
    Name     = "${var.project_name}-kms-compute"
    Purpose  = "Encryption for EBS volumes and Auto Scaling"
    Security = "encryption-at-rest"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "compute" {
  name          = "alias/${var.project_name}-compute"
  target_key_id = aws_kms_key.compute.key_id
}

# Account-level EBS default key - external ARN overrides if provided
resource "aws_ebs_default_kms_key" "ebs" {
  key_arn = var.ebs_default_kms_key_arn != "" ? var.ebs_default_kms_key_arn : aws_kms_key.compute.arn
}

# KMS Key - Observability Layer (CloudTrail, CloudWatch Logs, SNS)
resource "aws_kms_key" "observability" {
  description             = "KMS key for ${var.project_name} observability layer - CloudTrail, CloudWatch, SNS"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = var.kms_rotation_period_days

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogsToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "logs.${local.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${local.region}:${local.account_id}:*"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${local.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "AllowCloudWatchAlarmsToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "AllowSNSToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "AllowSQSToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "sqs.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "AllowEventBridgeToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })

  tags = {
    Name     = "${var.project_name}-kms-observability"
    Purpose  = "Encryption for CloudTrail CloudWatch Logs and SNS"
    Security = "encryption-at-rest"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "observability" {
  name          = "alias/${var.project_name}-observability"
  target_key_id = aws_kms_key.observability.key_id
}

# KMS Key - Storage Layer (S3 Log Buckets)
resource "aws_kms_key" "storage" {
  description             = "KMS key for ${var.project_name} storage layer - S3 log buckets"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = var.kms_rotation_period_days

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowS3ToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "AllowConfigToDeliverEncryptedSnapshots"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "AllowCloudTrailToEncryptLogs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${local.account_id}:trail/*"
          }
        }
      }
    ]
  })

  tags = {
    Name     = "${var.project_name}-kms-storage"
    Purpose  = "Encryption for S3 audit log buckets and Config snapshots"
    Security = "encryption-at-rest"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "storage" {
  name          = "alias/${var.project_name}-storage"
  target_key_id = aws_kms_key.storage.key_id
}

# Block public AMI sharing
resource "aws_ec2_image_block_public_access" "enabled" {
  state = "block-new-sharing"
}

# Block public EBS snapshot sharing
resource "aws_ebs_snapshot_block_public_access" "enabled" {
  state = "block-all-sharing"
}

# IMDSv2 by default - prevents SSRF-based credential theft from metadata endpoint
resource "aws_ec2_instance_metadata_defaults" "imdsv2" {
  count = var.enable_imdsv2_default ? 1 : 0

  http_tokens                 = "required"
  http_put_response_hop_limit = var.imdsv2_hop_limit
  http_endpoint               = "enabled"
  instance_metadata_tags      = "disabled"
}

# Disable EC2 Serial Console - eliminates out-of-band access path
resource "aws_ec2_serial_console_access" "disabled" {
  count = var.disable_ec2_serial_console ? 1 : 0

  enabled = false
}

# Block public access for EMR - prevents clusters with public security groups
resource "aws_emr_block_public_access_configuration" "enabled" {
  count = var.enable_emr_block_public_access ? 1 : 0

  block_public_security_group_rules = true
}
