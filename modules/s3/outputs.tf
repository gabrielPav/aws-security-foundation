output "account_public_access_block_id" {
  description = "The AWS account ID for the S3 public access block configuration"
  value       = aws_s3_account_public_access_block.account.id
}
