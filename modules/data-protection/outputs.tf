output "ebs_encryption_enabled" {
  description = "Whether EBS encryption by default is enabled"
  value       = aws_ebs_encryption_by_default.enabled.enabled
}

# Compute Layer KMS Key (EBS, Auto Scaling)

output "kms_compute_key_arn" {
  description = "ARN of the compute layer KMS key (EBS, Auto Scaling)"
  value       = aws_kms_key.compute.arn
}

output "kms_compute_key_id" {
  description = "ID of the compute layer KMS key"
  value       = aws_kms_key.compute.key_id
}

# Observability Layer KMS Key (CloudTrail, CloudWatch, SNS)

output "kms_observability_key_arn" {
  description = "ARN of the observability layer KMS key (CloudTrail, CloudWatch, SNS)"
  value       = aws_kms_key.observability.arn
}

output "kms_observability_key_id" {
  description = "ID of the observability layer KMS key"
  value       = aws_kms_key.observability.key_id
}

# Storage Layer KMS Key (S3 Log Buckets)

output "kms_storage_key_arn" {
  description = "ARN of the storage layer KMS key (S3 log buckets)"
  value       = aws_kms_key.storage.arn
}

output "kms_storage_key_id" {
  description = "ID of the storage layer KMS key"
  value       = aws_kms_key.storage.key_id
}

# Public Access Blocks

output "ami_block_public_access_state" {
  description = "State of AMI public access blocking"
  value       = aws_ec2_image_block_public_access.enabled.state
}

output "ebs_snapshot_block_public_access_state" {
  description = "State of EBS snapshot public access blocking"
  value       = aws_ebs_snapshot_block_public_access.enabled.state
}

# EC2 Instance Defaults

output "imdsv2_default_enabled" {
  description = "Whether IMDSv2 is enforced as the account default for new instances"
  value       = var.enable_imdsv2_default
}

output "ec2_serial_console_disabled" {
  description = "Whether EC2 Serial Console access is disabled"
  value       = var.disable_ec2_serial_console
}

output "emr_block_public_access_enabled" {
  description = "Whether EMR block public access is enabled"
  value       = var.enable_emr_block_public_access
}
