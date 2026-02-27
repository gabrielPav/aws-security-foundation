# S3 - Account-level security controls

# S3 Block Public Access - prevents any bucket in the account from being public
resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
