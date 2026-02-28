# Logging & Monitoring - CloudTrail, AWS Config, CloudWatch

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# =====================================================================
# 1. S3 Audit Buckets
#    CloudTrail, Config, access logs, and access logs meta buckets.
#    Hardened: versioning, public access blocking, ACLs disabled,
#    KMS encryption (AES256 for log-target buckets), TLS-only policies,
#    lifecycle management, and optional Object Lock (Governance Mode).
# =====================================================================

# CloudTrail S3 bucket
resource "aws_s3_bucket" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket              = "${var.project_name}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy       = false
  object_lock_enabled = var.enable_s3_object_lock_cloudtrail

  tags = {
    Name     = "${var.project_name}-cloudtrail-logs"
    Purpose  = "CloudTrail audit log storage"
    Security = "audit-logs"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Enforce bucket owner ownership - disables ACLs
resource "aws_s3_bucket_ownership_controls" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Versioning protects against accidental or malicious log deletion
resource "aws_s3_bucket_versioning" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption for CloudTrail logs at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_storage_key_arn
    }
    bucket_key_enabled = true
  }
}

# Block all public access to audit logs
resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket                  = aws_s3_bucket.cloudtrail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "cloudtrail" {
  count = var.enable_cloudtrail && var.enable_s3_object_lock_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    default_retention {
      mode = var.s3_object_lock_mode
      days = var.s3_object_lock_cloudtrail_retention_days
    }
  }
}

# Access logging bucket - shared by CloudTrail and Config (requires SSE-S3, not KMS)
resource "aws_s3_bucket" "access_logs" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket              = "${var.project_name}-s3-access-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy       = false
  object_lock_enabled = var.enable_s3_object_lock_access_logs

  tags = {
    Name    = "${var.project_name}-s3-access-logs"
    Purpose = "Centralized S3 server access logs"
  }
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.access_logs[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.access_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "access_logs" {
  count = var.enable_cloudtrail || var.enable_config ? (var.enable_s3_object_lock_access_logs ? 1 : 0) : 0

  bucket = aws_s3_bucket.access_logs[0].id

  rule {
    default_retention {
      mode = var.s3_object_lock_mode
      days = var.s3_object_lock_access_logs_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.access_logs[0]]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.access_logs[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket                  = aws_s3_bucket.access_logs[0].id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.access_logs[0].id

  rule {
    id     = "transition-logs-to-ia"
    status = "Enabled"
    filter {}

    dynamic "transition" {
      for_each = var.access_log_retention_days > var.s3_transition_to_ia_days ? [1] : []
      content {
        days          = var.s3_transition_to_ia_days
        storage_class = "STANDARD_IA"
      }
    }
  }

  rule {
    id     = "transition-logs-to-glacier"
    status = "Enabled"
    filter {}

    dynamic "transition" {
      for_each = var.access_log_retention_days > var.s3_transition_to_glacier_days ? [1] : []
      content {
        days          = var.s3_transition_to_glacier_days
        storage_class = "GLACIER"
      }
    }
  }

  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = var.access_log_retention_days
    }
  }

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.access_logs[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ServerAccessLogsPolicy"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.access_logs[0].arn}/*"
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:s3:::${var.project_name}-*"
          }
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.access_logs[0].arn,
          "${aws_s3_bucket.access_logs[0].arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.access_logs[0]]
}

# Meta-logging bucket - receives access logs FROM the access_logs bucket
resource "aws_s3_bucket" "access_logs_meta" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket              = "${var.project_name}-s3-access-logs-meta-${data.aws_caller_identity.current.account_id}"
  force_destroy       = false
  object_lock_enabled = var.enable_s3_object_lock_access_logs_meta

  tags = {
    Name    = "${var.project_name}-s3-access-logs-meta"
    Purpose = "Terminal S3 access log destination for the access logs bucket"
  }
}

resource "aws_s3_bucket_ownership_controls" "access_logs_meta" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.access_logs_meta[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "access_logs_meta" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.access_logs_meta[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "access_logs_meta" {
  count = var.enable_cloudtrail || var.enable_config ? (var.enable_s3_object_lock_access_logs_meta ? 1 : 0) : 0

  bucket = aws_s3_bucket.access_logs_meta[0].id

  rule {
    default_retention {
      mode = var.s3_object_lock_mode
      days = var.s3_object_lock_access_logs_meta_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.access_logs_meta[0]]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs_meta" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.access_logs_meta[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs_meta" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket                  = aws_s3_bucket.access_logs_meta[0].id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs_meta" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.access_logs_meta[0].id

  rule {
    id     = "transition-logs-to-ia"
    status = "Enabled"
    filter {}

    dynamic "transition" {
      for_each = var.access_log_retention_days > var.s3_transition_to_ia_days ? [1] : []
      content {
        days          = var.s3_transition_to_ia_days
        storage_class = "STANDARD_IA"
      }
    }
  }

  rule {
    id     = "transition-logs-to-glacier"
    status = "Enabled"
    filter {}

    dynamic "transition" {
      for_each = var.access_log_retention_days > var.s3_transition_to_glacier_days ? [1] : []
      content {
        days          = var.s3_transition_to_glacier_days
        storage_class = "GLACIER"
      }
    }
  }

  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = var.access_log_retention_days
    }
  }

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs_meta" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.access_logs_meta[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ServerAccessLogsPolicy"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.access_logs_meta[0].arn}/*"
        Condition = {
          ArnLike = {
            "aws:SourceArn" = aws_s3_bucket.access_logs[0].arn
          }
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.access_logs_meta[0].arn,
          "${aws_s3_bucket.access_logs_meta[0].arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.access_logs_meta[0]]
}

# Enable access logging on the access_logs bucket itself
resource "aws_s3_bucket_logging" "access_logs" {
  count = var.enable_cloudtrail || var.enable_config ? 1 : 0

  bucket        = aws_s3_bucket.access_logs[0].id
  target_bucket = aws_s3_bucket.access_logs_meta[0].id
  target_prefix = "access-logs-bucket/"

  depends_on = [aws_s3_bucket_policy.access_logs_meta[0]]
}

# Enable access logging on CloudTrail bucket
resource "aws_s3_bucket_logging" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket        = aws_s3_bucket.cloudtrail[0].id
  target_bucket = aws_s3_bucket.access_logs[0].id
  target_prefix = "cloudtrail-bucket/"

  depends_on = [aws_s3_bucket_policy.access_logs[0]]
}

# Lifecycle rule to transition old logs to cheaper storage and expire
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    id     = "archive-and-expire"
    status = "Enabled"

    filter {}

    dynamic "transition" {
      for_each = var.cloudtrail_log_retention_days > var.s3_transition_to_ia_days ? [1] : []
      content {
        days          = var.s3_transition_to_ia_days
        storage_class = "STANDARD_IA"
      }
    }

    dynamic "transition" {
      for_each = var.cloudtrail_log_retention_days > var.s3_transition_to_glacier_days ? [1] : []
      content {
        days          = var.s3_transition_to_glacier_days
        storage_class = "GLACIER"
      }
    }

    expiration {
      days = var.cloudtrail_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }
  }

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Bucket policy allowing CloudTrail service to write logs
resource "aws_s3_bucket_policy" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.project_name}-trail"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = var.is_organization_trail ? "${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${var.organization_id}/*" : "${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.project_name}-trail"
          }
        }
      },
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail[0].arn,
          "${aws_s3_bucket.cloudtrail[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail[0].arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      # Both keys allowed: CloudTrail writes with the observability key, S3 encrypts at rest with the storage key
      {
        Sid       = "DenyWrongKMSKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail[0].arn}/*"
        Condition = {
          StringNotEqualsIfExists = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = [var.kms_storage_key_arn, var.kms_observability_key_arn]
          }
        }
      }
    ]
  })

  depends_on = [
    aws_s3_bucket_public_access_block.cloudtrail[0],
    aws_s3_bucket_ownership_controls.cloudtrail[0]
  ]
}

# =====================================================================
# 2. CloudTrail
#    Multi-region trail with CloudWatch Logs integration, credential
#    masking via data protection policy, and IAM role for log delivery.
# =====================================================================

# CloudWatch log group for CloudTrail - enables real-time metric filter alerting
resource "aws_cloudwatch_log_group" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  name                        = "/aws/cloudtrail/${var.project_name}"
  retention_in_days           = var.cloudwatch_log_retention_days
  kms_key_id        = var.kms_observability_key_arn

  tags = {
    Name    = "${var.project_name}-cloudtrail-logs"
    Purpose = "CloudTrail event streaming for real-time monitoring"
  }
}

# Automatically mask credentials if they ever show up in CloudTrail logs.
# This catches AWS secret keys and private keys (SSH, PGP, PKCS, Putty).
# Findings are sent to the CloudTrail S3 bucket for investigation.
resource "aws_cloudwatch_log_data_protection_policy" "cloudtrail" {
  count = var.enable_cloudtrail && var.enable_cloudwatch_data_protection ? 1 : 0

  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  policy_document = jsonencode({
    Name        = "data-protection-policy"
    Description = "Mask credentials that appear in CloudTrail logs"
    Version     = "2021-06-01"
    Statement = [
      {
        Sid = "audit-policy"
        DataIdentifier = [
          "arn:aws:dataprotection::aws:data-identifier/AwsSecretKey",
          "arn:aws:dataprotection::aws:data-identifier/OpenSshPrivateKey",
          "arn:aws:dataprotection::aws:data-identifier/PgpPrivateKey",
          "arn:aws:dataprotection::aws:data-identifier/PkcsPrivateKey",
          "arn:aws:dataprotection::aws:data-identifier/PuttyPrivateKey"
        ]
        Operation = {
          Audit = {
            FindingsDestination = {
              S3 = {
                Bucket = aws_s3_bucket.cloudtrail[0].id
              }
            }
          }
        }
      },
      {
        Sid = "redact-policy"
        DataIdentifier = [
          "arn:aws:dataprotection::aws:data-identifier/AwsSecretKey",
          "arn:aws:dataprotection::aws:data-identifier/OpenSshPrivateKey",
          "arn:aws:dataprotection::aws:data-identifier/PgpPrivateKey",
          "arn:aws:dataprotection::aws:data-identifier/PkcsPrivateKey",
          "arn:aws:dataprotection::aws:data-identifier/PuttyPrivateKey"
        ]
        Operation = {
          Deidentify = {
            MaskConfig = {}
          }
        }
      }
    ]
  })
}

# IAM role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  count = var.enable_cloudtrail ? 1 : 0

  name = "${var.project_name}-cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudTrailAssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnLike = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.project_name}-trail"
          }
        }
      }
    ]
  })

  tags = {
    Name    = "${var.project_name}-cloudtrail-cloudwatch-role"
    Purpose = "CloudTrail to CloudWatch Logs delivery"
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  count = var.enable_cloudtrail ? 1 : 0

  name = "${var.project_name}-cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cloudwatch[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
      }
    ]
  })
}

# CloudTrail - Multi-region trail
resource "aws_cloudtrail" "main" {
  count = var.enable_cloudtrail ? 1 : 0

  name = "${var.project_name}-trail"

  is_multi_region_trail      = true
  enable_log_file_validation = true

  # Organization trail captures events from all member accounts
  is_organization_trail = var.is_organization_trail

  s3_bucket_name = aws_s3_bucket.cloudtrail[0].id

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch[0].arn

  # Two-layer encryption by design: CloudTrail encrypts log files with the observability
  # key before writing to S3, then S3 applies its own at-rest encryption with the storage
  # key. The bucket policy allows both keys for this reason. Different keys because
  # CloudTrail logs feed CloudWatch (observability concern) but are stored in S3 (storage concern).
  kms_key_id = var.kms_observability_key_arn

  # Include global service events (IAM, STS, CloudFront) in the trail
  include_global_service_events = true

  insight_selector {
    insight_type = "ApiCallRateInsight"
  }

  insight_selector {
    insight_type = "ApiErrorRateInsight"
  }

  # Management events (console logins, IAM changes, etc.)
  advanced_event_selector {
    name = "ManagementEvents"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # Optionally log S3 data events for audit trails on object access
  dynamic "advanced_event_selector" {
    for_each = var.enable_s3_data_events ? [1] : []
    content {
      name = "S3DataEvents"

      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }

      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }
    }
  }

  lifecycle {
    precondition {
      condition     = !var.is_organization_trail || var.organization_id != ""
      error_message = "organization_id is required when is_organization_trail is true."
    }
    precondition {
      condition     = !var.enable_s3_data_events || var.cloudtrail_log_retention_days >= 90
      error_message = "S3 data events generate high log volume and cost. cloudtrail_log_retention_days should be >= 90 when enable_s3_data_events is true to justify the expense."
    }
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail[0],
    aws_iam_role_policy.cloudtrail_cloudwatch[0]
  ]

  tags = {
    Name     = "${var.project_name}-trail"
    Purpose  = "Multi-region API activity audit trail"
    Security = "audit-trail"
  }
}

# =====================================================================
# 3. AWS Config
#    Configuration recorder, S3 bucket for snapshots, delivery channel,
#    IAM role, and CIS-aligned Config rules. Includes pre-flight checks
#    to detect existing recorders/channels before deployment.
# =====================================================================

# Pre-flight: detect existing Config resources (AWS allows only one recorder and one delivery channel per region)
data "external" "existing_config_recorder" {
  count   = var.enable_config ? 1 : 0
  program = [
    "bash", "-c",
    "name=$(aws configservice describe-configuration-recorders --region ${data.aws_region.current.name} --query 'ConfigurationRecorders[0].name' --output text 2>/dev/null || echo ''); [ \"$name\" = 'None' ] && name=''; printf '{\"name\":\"%s\"}' \"$name\""
  ]
}

data "external" "existing_delivery_channel" {
  count   = var.enable_config ? 1 : 0
  program = [
    "bash", "-c",
    "name=$(aws configservice describe-delivery-channels --region ${data.aws_region.current.name} --query 'DeliveryChannels[0].name' --output text 2>/dev/null || echo ''); [ \"$name\" = 'None' ] && name=''; printf '{\"name\":\"%s\"}' \"$name\""
  ]
}

# Pre-flight validations: fail at plan time if a singleton resource exists in AWS
# but is NOT already managed by Terraform (needs import or manual cleanup).
resource "terraform_data" "validate_config_recorder" {
  count = var.enable_config ? 1 : 0

  lifecycle {
    precondition {
      condition = (
        data.external.existing_config_recorder[0].result.name == "" ||
        data.external.existing_config_recorder[0].result.name == "${var.project_name}-config-recorder" ||
        length(aws_config_configuration_recorder.main) > 0
      )
      error_message = <<-EOT
        An AWS Config recorder '${data.external.existing_config_recorder[0].result.name}' already exists in ${data.aws_region.current.name}.
        AWS allows only one Config recorder per region. Either:
          1. Import it:  terraform import 'module.logging.aws_config_configuration_recorder.main[0]' ${data.external.existing_config_recorder[0].result.name}
          2. Delete it:  aws configservice delete-configuration-recorder --region ${data.aws_region.current.name} --configuration-recorder-name ${data.external.existing_config_recorder[0].result.name}
      EOT
    }
  }
}

resource "terraform_data" "validate_delivery_channel" {
  count = var.enable_config ? 1 : 0

  lifecycle {
    precondition {
      condition = (
        data.external.existing_delivery_channel[0].result.name == "" ||
        data.external.existing_delivery_channel[0].result.name == "${var.project_name}-config-delivery" ||
        length(aws_config_delivery_channel.main) > 0
      )
      error_message = <<-EOT
        An AWS Config delivery channel '${data.external.existing_delivery_channel[0].result.name}' already exists in ${data.aws_region.current.name}.
        AWS allows only one delivery channel per region. Either:
          1. Import it:  terraform import 'module.logging.aws_config_delivery_channel.main[0]' ${data.external.existing_delivery_channel[0].result.name}
          2. Delete it:  aws configservice delete-delivery-channel --region ${data.aws_region.current.name} --delivery-channel-name ${data.external.existing_delivery_channel[0].result.name}
      EOT
    }
  }
}

# AWS Config recorder
resource "aws_config_configuration_recorder" "main" {
  count = var.enable_config ? 1 : 0

  name     = "${var.project_name}-config-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

# S3 bucket for Config snapshots and history
resource "aws_s3_bucket" "config" {
  count = var.enable_config ? 1 : 0

  bucket              = "${var.project_name}-config-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy       = false
  object_lock_enabled = var.enable_s3_object_lock_config

  tags = {
    Name     = "${var.project_name}-config-logs"
    Purpose  = "AWS Config configuration history storage"
    Security = "config-history"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "config" {
  count = var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.config[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "config" {
  count = var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.config[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count = var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.config[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_storage_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count = var.enable_config ? 1 : 0

  bucket                  = aws_s3_bucket.config[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "config" {
  count = var.enable_config && var.enable_s3_object_lock_config ? 1 : 0

  bucket = aws_s3_bucket.config[0].id

  rule {
    default_retention {
      mode = var.s3_object_lock_mode
      days = var.s3_object_lock_config_retention_days
    }
  }
}

# Enable access logging on Config bucket
resource "aws_s3_bucket_logging" "config" {
  count = var.enable_config ? 1 : 0

  bucket        = aws_s3_bucket.config[0].id
  target_bucket = aws_s3_bucket.access_logs[0].id
  target_prefix = "config-bucket/"

  depends_on = [aws_s3_bucket_policy.access_logs[0]]
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  count = var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.config[0].id

  rule {
    id     = "archive-and-expire"
    status = "Enabled"

    filter {}

    dynamic "transition" {
      for_each = var.config_log_retention_days > var.s3_transition_to_ia_days ? [1] : []
      content {
        days          = var.s3_transition_to_ia_days
        storage_class = "STANDARD_IA"
      }
    }

    dynamic "transition" {
      for_each = var.config_log_retention_days > var.s3_transition_to_glacier_days ? [1] : []
      content {
        days          = var.s3_transition_to_glacier_days
        storage_class = "GLACIER"
      }
    }

    expiration {
      days = var.config_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }
  }

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  count = var.enable_config ? 1 : 0

  bucket = aws_s3_bucket.config[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.config[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.config[0].arn,
          "${aws_s3_bucket.config[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config[0].arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "DenyWrongKMSKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config[0].arn}/*"
        Condition = {
          StringNotEqualsIfExists = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = var.kms_storage_key_arn
          }
        }
      }
    ]
  })

  depends_on = [
    aws_s3_bucket_public_access_block.config[0],
    aws_s3_bucket_ownership_controls.config[0]
  ]
}

# IAM role for AWS Config
resource "aws_iam_role" "config" {
  count = var.enable_config ? 1 : 0

  name = "${var.project_name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowConfigAssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = {
    Name    = "${var.project_name}-config-role"
    Purpose = "AWS Config recorder and delivery"
  }
}

resource "aws_iam_role_policy_attachment" "config" {
  count = var.enable_config ? 1 : 0

  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  count = var.enable_config ? 1 : 0

  name = "${var.project_name}-config-s3-policy"
  role = aws_iam_role.config[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowConfigBucketAccess"
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl"
        ]
        Resource = aws_s3_bucket.config[0].arn
      },
      {
        Sid    = "AllowConfigObjectDelivery"
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.config[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
      },
      {
        Sid    = "AllowConfigKMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.kms_storage_key_arn
      }
    ]
  })
}

# Config delivery channel
resource "aws_config_delivery_channel" "main" {
  count = var.enable_config ? 1 : 0

  name           = "${var.project_name}-config-delivery"
  s3_bucket_name = aws_s3_bucket.config[0].id

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [
    aws_config_configuration_recorder.main[0],
    aws_s3_bucket_policy.config[0]
  ]
}

# Start the Config recorder
resource "aws_config_configuration_recorder_status" "main" {
  count = var.enable_config ? 1 : 0

  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main[0]]
}

# CIS Config rules - only create the ones the user has toggled on
locals {
  config_rules = var.enable_config && var.enable_cis_config_rules ? {
    for name, rule in {
      "iam-root-access-key-check"                = { id = "IAM_ROOT_ACCESS_KEY_CHECK", enabled = var.enable_config_rule_root_access_key }
      "root-account-mfa-enabled"                 = { id = "ROOT_ACCOUNT_MFA_ENABLED", enabled = var.enable_config_rule_root_mfa }
      "root-account-hardware-mfa-enabled"        = { id = "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED", enabled = var.enable_config_rule_root_hardware_mfa }
      "encrypted-volumes"                        = { id = "ENCRYPTED_VOLUMES", enabled = var.enable_config_rule_ebs_encryption }
      "rds-storage-encrypted"                    = { id = "RDS_STORAGE_ENCRYPTED", enabled = var.enable_config_rule_rds_encryption }
      "cmk-backing-key-rotation-enabled"         = { id = "CMK_BACKING_KEY_ROTATION_ENABLED", enabled = var.enable_config_rule_kms_rotation }
      "vpc-default-security-group-closed"        = { id = "VPC_DEFAULT_SECURITY_GROUP_CLOSED", enabled = var.enable_config_rule_default_sg_closed }
      "iam-user-mfa-enabled"                     = { id = "IAM_USER_MFA_ENABLED", enabled = var.enable_config_rule_iam_user_mfa }
      "s3-bucket-server-side-encryption-enabled" = { id = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED", enabled = var.enable_config_rule_s3_encryption }
    } : name => rule if rule.enabled
  } : {}
}

resource "aws_config_config_rule" "cis" {
  for_each = local.config_rules

  name = each.key
  source {
    owner             = "AWS"
    source_identifier = each.value.id
  }

  depends_on = [aws_config_configuration_recorder_status.main[0]]

  tags = {
    Name    = each.key
    Purpose = "CIS compliance rule"
  }
}

# =====================================================================
# 4. Validation Preconditions
#    Catch cross-variable misconfigurations at plan time instead of
#    silently skipping resources or failing at apply time.
# =====================================================================

# Cross-variable preconditions - catch misconfigurations at plan time instead of silently skipping resources

resource "terraform_data" "validate_security_alarms" {
  count = var.enable_security_alarms ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.enable_cloudtrail
      error_message = "enable_security_alarms requires enable_cloudtrail = true. Security alarms use CloudWatch metric filters on CloudTrail log groups."
    }
  }
}

resource "terraform_data" "validate_finding_notifications" {
  count = var.enable_finding_notifications ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.alarm_notification_email != ""
      error_message = "enable_finding_notifications requires alarm_notification_email to be set. EventBridge routes findings to the security alarms SNS topic."
    }
  }
}

resource "terraform_data" "validate_cis_config_rules" {
  count = var.enable_cis_config_rules ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.enable_config
      error_message = "enable_cis_config_rules requires enable_config = true. Config rules depend on the Config recorder."
    }
  }
}

# =====================================================================
# 5. Security Alarms & Notifications
#    SNS topic, CIS-aligned CloudWatch metric filters and alarms,
#    email subscription with DLQ, and security dashboard.
# =====================================================================

# CloudWatch Security Alarms - CIS-aligned metric filters and alarms
# For active security monitoring, set alarm_notification_email.

locals {
  create_alarms                = var.enable_cloudtrail && var.enable_security_alarms
  create_finding_notifications = var.enable_finding_notifications && var.alarm_notification_email != ""
  create_notifications         = (local.create_alarms || local.create_finding_notifications) && var.alarm_notification_email != ""
  alarm_namespace              = "${var.project_name}/SecurityBaseline/CloudTrailMetrics"

  # Each entry becomes one metric filter + one alarm via for_each below.
  # To add a new alarm, just add a map entry - no new resources needed.
  security_alarms = {
    console-signin-without-mfa = {
      pattern     = "{($.eventName=\"ConsoleLogin\") && ($.additionalEventData.MFAUsed !=\"Yes\") && ($.userIdentity.type !=\"AssumedRole\")}"
      metric_name = "ConsoleSignInWithoutMFA"
      description = "Console sign-in detected without MFA"
      threshold   = 1
    }
    console-signin-failures = {
      pattern     = "{($.eventName=\"ConsoleLogin\") && ($.errorMessage=\"Failed authentication\")}"
      metric_name = "ConsoleSignInFailures"
      description = "3+ failed console sign-in attempts in 5 minutes"
      threshold   = 3
    }
    cloudtrail-config-changes = {
      pattern     = "{($.eventSource=cloudtrail.amazonaws.com)&&(($.eventName=CreateTrail)||($.eventName=UpdateTrail)||($.eventName=DeleteTrail)||($.eventName=StartLogging)||($.eventName=StopLogging))}"
      metric_name = "CloudTrailConfigChanges"
      description = "CloudTrail trail created, updated, deleted, or logging toggled"
      threshold   = 1
    }
    config-changes = {
      pattern     = "{($.eventSource=config.amazonaws.com)&&(($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder))}"
      metric_name = "AWSConfigChanges"
      description = "Config recorder or delivery channel modified or stopped"
      threshold   = 1
    }
    iam-policy-changes = {
      pattern     = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
      metric_name = "IAMPolicyChanges"
      description = "IAM policy created, modified, attached, or deleted"
      threshold   = 1
    }
    kms-cmk-changes = {
      pattern     = "{($.eventSource=kms.amazonaws.com)&&(($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))}"
      metric_name = "KMSCMKChanges"
      description = "KMS key disabled or scheduled for deletion"
      threshold   = 1
    }
    s3-bucket-policy-changes = {
      pattern     = "{($.eventSource=s3.amazonaws.com)&&(($.eventName=PutBucketAcl)||($.eventName=PutBucketPolicy)||($.eventName=PutBucketCors)||($.eventName=PutBucketLifecycle)||($.eventName=PutBucketReplication)||($.eventName=DeleteBucketPolicy)||($.eventName=DeleteBucketCors)||($.eventName=DeleteBucketLifecycle)||($.eventName=DeleteBucketReplication))}"
      metric_name = "S3BucketPolicyChanges"
      description = "S3 bucket policy, ACL, CORS, lifecycle, or replication changed"
      threshold   = 1
    }
    security-group-changes = {
      pattern     = "{($.eventSource=ec2.amazonaws.com)&&(($.eventName=AuthorizeSecurityGroupIngress)||($.eventName=AuthorizeSecurityGroupEgress)||($.eventName=RevokeSecurityGroupIngress)||($.eventName=RevokeSecurityGroupEgress)||($.eventName=CreateSecurityGroup)||($.eventName=DeleteSecurityGroup))}"
      metric_name = "SecurityGroupChanges"
      description = "Security group or its rules created, modified, or deleted"
      threshold   = 1
    }
    network-gateway-changes = {
      pattern     = "{($.eventSource=ec2.amazonaws.com)&&(($.eventName=CreateCustomerGateway)||($.eventName=DeleteCustomerGateway)||($.eventName=AttachInternetGateway)||($.eventName=CreateInternetGateway)||($.eventName=DeleteInternetGateway)||($.eventName=DetachInternetGateway)||($.eventName=CreateNatGateway)||($.eventName=DeleteNatGateway))}"
      metric_name = "NetworkGatewayChanges"
      description = "Internet, NAT, or customer gateway created or deleted"
      threshold   = 1
    }
    route-table-changes = {
      pattern     = "{($.eventSource=ec2.amazonaws.com)&&(($.eventName=CreateRoute)||($.eventName=CreateRouteTable)||($.eventName=ReplaceRoute)||($.eventName=ReplaceRouteTableAssociation)||($.eventName=DeleteRouteTable)||($.eventName=DeleteRoute)||($.eventName=DisassociateRouteTable))}"
      metric_name = "RouteTableChanges"
      description = "Route table or route created, replaced, or deleted"
      threshold   = 1
    }
    vpc-changes = {
      pattern     = "{($.eventSource=ec2.amazonaws.com)&&(($.eventName=CreateVpc)||($.eventName=DeleteVpc)||($.eventName=ModifyVpcAttribute)||($.eventName=AcceptVpcPeeringConnection)||($.eventName=CreateVpcPeeringConnection)||($.eventName=DeleteVpcPeeringConnection)||($.eventName=RejectVpcPeeringConnection))}"
      metric_name = "VPCChanges"
      description = "VPC or peering connection created, deleted, or modified"
      threshold   = 1
    }
    unauthorized-api-calls = {
      pattern     = "{($.errorCode=\"*UnauthorizedAccess\")||($.errorCode=\"AccessDenied*\")}"
      metric_name = "UnauthorizedAPICalls"
      description = "5+ unauthorized API calls (AccessDenied) in 5 minutes"
      threshold   = 5
    }
    root-account-usage = {
      pattern     = "{$.userIdentity.type=\"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\"}"
      metric_name = "RootAccountUsage"
      description = "Root account used directly (API call or console login)"
      threshold   = 1
    }
    ec2-instance-changes = {
      pattern     = "{($.eventName=RunInstances)||($.eventName=RebootInstances)||($.eventName=StartInstances)||($.eventName=StopInstances)||($.eventName=TerminateInstances)}"
      metric_name = "EC2InstanceChanges"
      description = "EC2 instance launched, rebooted, started, stopped, or terminated"
      threshold   = 1
    }
    network-acl-changes = {
      pattern     = "{($.eventName=CreateNetworkAcl)||($.eventName=CreateNetworkAclEntry)||($.eventName=DeleteNetworkAcl)||($.eventName=DeleteNetworkAclEntry)||($.eventName=ReplaceNetworkAclEntry)||($.eventName=ReplaceNetworkAclAssociation)}"
      metric_name = "NetworkACLChanges"
      description = "Network ACL or ACL entry created, deleted, or replaced"
      threshold   = 1
    }
  }

  # Org changes alarm only applies to management accounts
  org_alarm = var.is_organization_account ? {
    organizations-changes = {
      pattern     = "{($.eventSource=organizations.amazonaws.com)&&(($.eventName=AcceptHandshake)||($.eventName=AttachPolicy)||($.eventName=CancelHandshake)||($.eventName=CreateAccount)||($.eventName=CreateOrganization)||($.eventName=CreateOrganizationalUnit)||($.eventName=CreatePolicy)||($.eventName=DeclineHandshake)||($.eventName=DeleteOrganization)||($.eventName=DeleteOrganizationalUnit)||($.eventName=DeletePolicy)||($.eventName=EnableAllFeatures)||($.eventName=EnablePolicyType)||($.eventName=InviteAccountToOrganization)||($.eventName=LeaveOrganization)||($.eventName=DetachPolicy)||($.eventName=DisablePolicyType)||($.eventName=MoveAccount)||($.eventName=RemoveAccountFromOrganization)||($.eventName=UpdateOrganizationalUnit)||($.eventName=UpdatePolicy))}"
      metric_name = "OrganizationsChanges"
      description = "AWS Organizations membership, structure, or policies changed"
      threshold   = 1
    }
  } : {}

  # Final map - only populated when alarms are enabled
  all_alarms = local.create_alarms ? merge(local.security_alarms, local.org_alarm) : {}
}

# SNS topic - security alarm notifications
resource "aws_sns_topic" "security_alarms" {
  count = local.create_notifications ? 1 : 0

  name              = "${var.project_name}-security-alarms"
  kms_master_key_id = var.kms_observability_key_id

  # X-Ray tracing for end-to-end visibility into notification delivery
  tracing_config = "Active"

  tags = {
    Name    = "${var.project_name}-security-alarms"
    Purpose = "Security alarm notifications"
  }
}

resource "aws_sns_topic_policy" "security_alarms" {
  count = local.create_notifications ? 1 : 0

  arn = aws_sns_topic.security_alarms[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "AllowCloudWatchAlarmsPublish"
          Effect = "Allow"
          Principal = {
            Service = "cloudwatch.amazonaws.com"
          }
          Action   = "sns:Publish"
          Resource = aws_sns_topic.security_alarms[0].arn
          Condition = {
            StringEquals = {
              "aws:SourceAccount" = data.aws_caller_identity.current.account_id
            }
          }
        },
        {
          Sid       = "EnforceTLS"
          Effect    = "Deny"
          Principal = "*"
          Action    = "sns:Publish"
          Resource  = aws_sns_topic.security_alarms[0].arn
          Condition = {
            Bool = {
              "aws:SecureTransport" = "false"
            }
          }
        }
      ],
      local.create_finding_notifications ? [
        {
          Sid    = "AllowEventBridgePublish"
          Effect = "Allow"
          Principal = {
            Service = "events.amazonaws.com"
          }
          Action   = "sns:Publish"
          Resource = aws_sns_topic.security_alarms[0].arn
          Condition = {
            StringEquals = {
              "aws:SourceAccount" = data.aws_caller_identity.current.account_id
            }
          }
        }
      ] : []
    )
  })
}

# SQS dead-letter queue for SNS subscription delivery failures (email bounces, throttling)
resource "aws_sqs_queue" "sns_subscription_dlq" {
  count = local.create_notifications ? 1 : 0

  name                              = "${var.project_name}-sns-subscription-dlq"
  message_retention_seconds         = 1209600 # 14 days
  kms_master_key_id                 = var.kms_observability_key_id
  kms_data_key_reuse_period_seconds = 300

  tags = {
    Name    = "${var.project_name}-sns-subscription-dlq"
    Purpose = "Dead-letter queue for failed SNS email subscription deliveries"
  }
}

resource "aws_sqs_queue_policy" "sns_subscription_dlq" {
  count = local.create_notifications ? 1 : 0

  queue_url = aws_sqs_queue.sns_subscription_dlq[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSNSSendMessage"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.sns_subscription_dlq[0].arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.security_alarms[0].arn
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "security_alarms_email" {
  count = local.create_notifications ? 1 : 0

  topic_arn            = aws_sns_topic.security_alarms[0].arn
  protocol             = "email"
  endpoint             = var.alarm_notification_email
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.sns_subscription_dlq[0].arn
  })
}

# One metric filter per alarm - feeds CloudWatch metrics from CloudTrail logs
resource "aws_cloudwatch_log_metric_filter" "security" {
  for_each = local.all_alarms

  name           = "${var.project_name}-${each.key}"
  pattern        = each.value.pattern
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  metric_transformation {
    name      = each.value.metric_name
    namespace = local.alarm_namespace
    value     = "1"
  }
}

# One alarm per metric filter - fires when threshold is breached in a 5-min window
resource "aws_cloudwatch_metric_alarm" "security" {
  for_each = local.all_alarms

  alarm_name          = "${var.project_name}-${each.key}"
  alarm_description   = each.value.description
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = each.value.metric_name
  namespace           = local.alarm_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = each.value.threshold
  treat_missing_data  = "notBreaching"

  alarm_actions = local.create_notifications ? [aws_sns_topic.security_alarms[0].arn] : []
  ok_actions    = local.create_notifications ? [aws_sns_topic.security_alarms[0].arn] : []

}

# CloudWatch dashboard - single-pane view of all security alarm states
resource "aws_cloudwatch_dashboard" "security" {
  count = local.create_alarms ? 1 : 0

  dashboard_name = "${var.project_name}-security-alarms"

  dashboard_body = jsonencode({
    widgets = concat(
      # Header widget
      [
        {
          type   = "text"
          x      = 0
          y      = 0
          width  = 24
          height = 2
          properties = {
            markdown = join("\n", [
              "# Security Alarms Dashboard",
              "CIS-aligned CloudWatch alarms monitoring CloudTrail events. Each alarm triggers when suspicious activity exceeds its threshold within a 5-minute window.",
              local.create_notifications ? "**Notifications:** Enabled (${var.alarm_notification_email})" : "**Notifications:** Disabled - set `alarm_notification_email` for email alerts.",
            ])
          }
        }
      ],
      # One alarm-status widget per alarm, laid out in a 3-column grid
      [
        for i, key in sort(keys(local.all_alarms)) : {
          type   = "metric"
          x      = (i % 3) * 8
          y      = 2 + floor(i / 3) * 6
          width  = 8
          height = 6
          properties = {
            title = replace(key, "-", " ")
            metrics = [
              [local.alarm_namespace, local.all_alarms[key].metric_name, { stat = "Sum", period = 300 }]
            ]
            view    = "timeSeries"
            stacked = false
            region  = data.aws_region.current.name
            period  = 300
            yAxis   = { left = { min = 0 } }
            annotations = {
              horizontal = [
                {
                  label = "Alarm threshold"
                  value = local.all_alarms[key].threshold
                  color = "#d62728"
                }
              ]
            }
          }
        }
      ]
    )
  })
}

# =====================================================================
# 6. Finding Notifications (EventBridge)
#    EventBridge rules on the default bus that route HIGH/CRITICAL
#    findings from GuardDuty, Security Hub, Inspector, and Macie to
#    the security alarms SNS topic. Includes SQS dead-letter queue
#    for failed deliveries.
# =====================================================================

# Security services publish finding events to the default bus in the account and region where findings are generated
# This module only creates rules and targets on the default bus

locals {
  finding_notification_rules = local.create_finding_notifications ? toset([
    "guardduty", "securityhub", "inspector", "macie"
  ]) : toset([])

  finding_notification_config = {
    guardduty = {
      source      = "aws.guardduty"
      detail_type = "GuardDuty Finding"
      event_pattern = jsonencode({
        source      = ["aws.guardduty"]
        detail-type = ["GuardDuty Finding"]
        detail      = { severity = [{ numeric = [">=", 7] }] }
      })
    }
    securityhub = {
      source      = "aws.securityhub"
      detail_type = "Security Hub Findings - Imported"
      event_pattern = jsonencode({
        source      = ["aws.securityhub"]
        detail-type = ["Security Hub Findings - Imported"]
        detail = {
          findings = {
            Severity = { Label = ["HIGH", "CRITICAL"] }
            Workflow = { Status = ["NEW"] }
          }
        }
      })
    }
    inspector = {
      source      = "aws.inspector2"
      detail_type = "Inspector2 Finding"
      event_pattern = jsonencode({
        source      = ["aws.inspector2"]
        detail-type = ["Inspector2 Finding"]
        detail      = { severity = ["HIGH", "CRITICAL"] }
      })
    }
    macie = {
      source      = "aws.macie"
      detail_type = "Macie Finding"
      event_pattern = jsonencode({
        source      = ["aws.macie"]
        detail-type = ["Macie Finding"]
        detail      = { severity = { description = ["High", "Critical"] } }
      })
    }
  }
}

resource "aws_cloudwatch_event_rule" "findings" {
  for_each = local.finding_notification_rules

  name           = "${var.project_name}-${each.value}-high-critical"
  description    = "Route HIGH and CRITICAL ${each.value} findings to SNS"
  event_bus_name = "default"

  event_pattern = local.finding_notification_config[each.value].event_pattern

  tags = { Purpose = "Security finding notifications" }
}

# SQS dead-letter queue - captures events that EventBridge fails to deliver to SNS
resource "aws_sqs_queue" "findings_dlq" {
  count = local.create_finding_notifications ? 1 : 0

  name                       = "${var.project_name}-findings-dlq"
  message_retention_seconds  = 1209600 # 14 days
  kms_master_key_id          = var.kms_observability_key_id
  kms_data_key_reuse_period_seconds = 300

  tags = {
    Name    = "${var.project_name}-findings-dlq"
    Purpose = "Dead-letter queue for failed EventBridge-to-SNS finding deliveries"
  }
}

resource "aws_sqs_queue_policy" "findings_dlq" {
  count = local.create_finding_notifications ? 1 : 0

  queue_url = aws_sqs_queue.findings_dlq[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgeSendMessage"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.findings_dlq[0].arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = [for rule in aws_cloudwatch_event_rule.findings : rule.arn]
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "findings_to_sns" {
  for_each = local.finding_notification_rules

  rule           = aws_cloudwatch_event_rule.findings[each.key].name
  event_bus_name = "default"
  target_id      = "${each.value}-to-sns"
  arn            = aws_sns_topic.security_alarms[0].arn

  dead_letter_config {
    arn = aws_sqs_queue.findings_dlq[0].arn
  }
}
