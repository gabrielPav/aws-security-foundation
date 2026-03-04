# AWS Security Foundation

![AWS Badge](https://img.shields.io/badge/AWS-Deployed-FF9900.svg?style=flat&logo=amazon-aws&logoColor=white)
![Terraform Badge](https://img.shields.io/badge/Terraform-1.5+-5c4ee5.svg?style=flat&logo=terraform&logoColor=white)
![Secure Badge](https://img.shields.io/badge/Secure-Ready-4EAA25.svg?style=flat&logo=shield&logoColor=white)
![Compliance Badge](https://img.shields.io/badge/Compliance-Ready-1565c0.svg?style=flat&logo=checkmarx&logoColor=white)

A Terraform project that deploys **production-grade security controls** for AWS accounts and organizations.

**What it provides:**
- 100+ security controls aligned with CIS benchmarks and AWS best practices
- Account-level guardrails (no impact on workloads)
- Automated threat detection and compliance monitoring

**Use cases:**
- Landing zone security layer for new AWS accounts
- Compliance automation (CIS, PCI DSS, AWS Foundational Security)
- Multi-account security guardrails via AWS Organizations

## Features

### Encryption & Data Protection
- Purpose-built KMS keys (compute, observability, storage) with automatic rotation and safe deletion windows
- EBS default encryption enforced at account level with a Customer-Managed Key
- All KMS key policies scoped to prevent confused deputy attacks
- Public AMI/snapshot sharing blocked
- IMDSv2 enforced as account default
- EC2 serial console disabled

### Threat Detection
- GuardDuty with S3, EKS, RDS, Lambda, malware, and runtime protection enabled by default
- Security Hub with five compliance standards and cross-region finding aggregation
- Macie with optional classification export
- Inspector v2 scanning EC2/ECR/Lambda
- Detective for graph-based investigation

### IAM & Access Control
- Strong CIS-hardened password policy
- External Access Analyzer always-on at account or organization scope
- Unused Access Analyzer opt-in with configurable inactivity threshold for zero-trust access reviews

### Organizations Guardrails
- 10 SCPs covering root usage, region restriction, security service protection, encryption enforcement, public AMI/snapshot blocking, org departure, flow log deletion, MFA deactivation, and IMDSv2 enforcement
- Region-deny SCP handles global service exceptions
- Tag policies, backup policies, and AI opt-out policies all conditional

### S3 Security
- All audit buckets (CloudTrail, Config, access logs, access logs meta) hardened with KMS encryption, public access blocking, TLS-only policies, versioning, ACLs disabled, and source-scoped write permissions
- Lifecycle rules manage storage tiering, expiration, multipart cleanup, and noncurrent version retention
- Object Lock (Governance Mode by default) supported on all four buckets for tamper-proof immutability (off by default, enable per-bucket as needed)

### CloudTrail
- Multi-region trail with log file validation and Insight selectors for anomaly detection
- S3 data events opt-in to control costs
- Organization trail support conditional and validated
- CloudWatch Logs integration via a least-privilege IAM role hardened against confused deputy escalation
- Automatic credential masking via CloudWatch data protection policy (catches AWS secret keys and private keys if they ever appear in logs)

### AWS Config
- Continuous recording of all resource types including global resources
- Least-privilege IAM role with daily configuration snapshots
- CIS-aligned managed rules for compliance checks
- Pre-flight validation detects existing recorders and delivery channels before deployment to avoid conflicts

### Security Alarms
- 13 CIS-aligned CloudWatch metric filters and alarms covering auth failures, unauthorized API calls, root usage, and changes to CloudTrail, Config, IAM, KMS, S3, security groups, networking, and VPCs
- KMS-encrypted SNS topic with TLS enforcement, tuned to reduce false positives
- SQS dead-letter queue for SNS delivery failures
- CloudWatch dashboard for single-pane security visibility

### Finding Notifications
- EventBridge rules routing HIGH and CRITICAL findings from GuardDuty, Security Hub, Inspector, and Macie to the security alarms SNS topic
- SQS dead-letter queue for failed deliveries
- Off by default
- Enable when you're ready for near real-time alerting

### Billing & Governance
- Monthly cost budgets with multi-threshold alerts
- ML-powered Cost Anomaly Detection
- Alternate contacts for security, billing, and operations

## Security Best Practices

For a detailed breakdown of all implemented security controls, see [SECURITY.md](SECURITY.md).

---

## Prerequisites

- [Terraform](https://www.terraform.io/downloads.html) >= 1.5.0.
- [AWS CLI](https://aws.amazon.com/cli/) configured with appropriate credentials.
- An AWS account with sufficient permissions.

## Quick Start

### Clone the Repository

```bash
git clone https://github.com/gabrielPav/aws-security-foundation.git
cd aws-security-foundation
```

### Configure Variables

Create a `terraform.tfvars` file from the example:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your values. At minimum, configure:

```hcl
# terraform.tfvars

project_name = "security-baseline"
aws_region   = "us-east-1"

# Security alarms (highly recommended)
enable_security_alarms   = true
alarm_notification_email = "secops@domain.com"

# Budget alerts
budget_notification_emails = ["finops@domain.com"]

# Security findings alerts (optional but recommended)
enable_finding_notifications = true
```

### Initialize and Apply

```bash
terraform init
terraform plan -out=baseline.tfplan
terraform apply baseline.tfplan
```

### Confirm Subscription

Check your email for SNS subscription confirmation.

### Destroy Infrastructure

> **Note:** S3 buckets and KMS keys have `prevent_destroy = true` to guard against accidental deletion. To tear down, set `prevent_destroy = false` in these files before running `terraform destroy`:
> - `modules/logging/main.tf` (CloudTrail bucket, KMS key)
> - `modules/data-protection/main.tf` (EBS, compute, and observability KMS keys)

```bash
terraform destroy
```

### Existing AWS Services

Some AWS security services only allow a single instance per account, per region. If you've previously enabled any of these, this module will catch it for you.

During `terraform plan`, built-in pre-flight checks query your account for existing resources. If a conflict is found, the plan fails early with a clear error message that tells you exactly what exists and how to fix it. This requires AWS CLI installed on the machine running `terraform plan` and valid AWS credentials available at plan time.

| Service | Limit |
|---------|-------|
| **AWS Config** | One recorder and one delivery channel per region |
| **GuardDuty** | One detector per region |
| **Security Hub** | One enablement per region |
| **Macie** | One session per region |
| **Detective** | One graph per region |

If conflicts are detected, you can resolve them using either of the following methods:

**Option A: Import the existing resource (recommended).** This tells Terraform to adopt what's already there. On the next apply, Terraform updates it to match your configuration (no data is lost):

```bash
terraform import '<resource-address>' <identifier>
```

**Option B: Delete and recreate.** Remove the existing resource using the delete command from the error message, then re-run `terraform plan`. This is safe. Note that for AWS Config the delivery channel must be deleted before the recorder:

```bash
aws configservice delete-delivery-channel --region <aws-region> --delivery-channel-name <channel-name>
aws configservice delete-configuration-recorder --region <aws-region> --configuration-recorder-name <recorder-name>
```

---

## Organization vs. Standalone Account

### Standalone Account (Default)

All organization features are disabled by default. The baseline applies to a single account:

```hcl
is_organization_account = false
```

### Organization Management Account

Enable organization-wide guardrails by setting:

```hcl
is_organization_account  = true
organization_id          = "o-abc123def4"
enable_scps              = true
scp_target_ou_ids        = ["ou-abc1-12345678"]
allowed_regions          = ["us-east-1", "us-west-2"]
enable_tag_policies      = true
enable_backup_policies   = true
enable_ai_opt_out_policy = true
enable_ram_org_sharing   = true
```

**Important:** This module does not create accounts or OUs, it expects them to already exist. You provide your OU IDs via `scp_target_ou_ids` and the module attaches policies to them. SCPs are attached to the specified OUs, not to the management account itself.

### Break-Glass Emergency Access for SCPs (Optional)

The `deny-disable-security` and `deny-deactivate-mfa` SCPs block everyone in member accounts from disabling security services. In an emergency, for example, a misbehaving GuardDuty detector flooding your account with false positives, you need a controlled way to act without detaching the SCP and briefly exposing all accounts.

The recommended approach is **account-based break-glass isolation**. Create a dedicated AWS account in its own OU, and don't attach SCPs to that OU. Because this project controls attachment via `scp_target_ou_ids`, you simply leave the break-glass OU out of the list.

#### Setup

1. Create a `SecurityBreakGlass` OU in your organization.
2. Create or move a dedicated break-glass account into that OU.
3. Keep the OU out of `scp_target_ou_ids` so deny policies don't apply to it.
4. In each member account, create a cross-account role that only the break-glass account can assume:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::BREAKGLASS_ACCOUNT:root" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": { "aws:MultiFactorAuthPresent": "true" }
      }
    }
  ]
}
```

5. Scope the role's permissions to only the actions the SCPs are blocking (disabling security services, deactivating MFA). Don't grant full admin.
6. Enable MFA on the break-glass account's root user and any IAM users. Store credentials in a secure vault.
7. Monitor the break-glass account with CloudTrail so any usage triggers an immediate alert.

#### During an Incident

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::MEMBER_ACCOUNT:role/BreakGlassAccess \
  --role-session-name emergency \
  --serial-number arn:aws:iam::BREAKGLASS_ACCOUNT:mfa/admin \
  --token-code 123456
```

The SCP stays in place for all other accounts. Only the break-glass session can act.

---

## Input Variables

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `project_name` | Project name for resource naming and tagging | `string` | `"security-baseline"` | No |
| `aws_region` | Primary AWS region | `string` | `"us-east-1"` | No |
| `is_organization_account` | Whether this is the Organization management account | `bool` | `false` | No |
| `enable_security_alarms` | Enable CIS-aligned CloudWatch alarms and dashboard | `bool` | `true` | No |
| `alarm_notification_email` | Email for security alarm notifications (opt-in) | `string` | `""` | No |
| `enable_guardduty` | Enable GuardDuty threat detection | `bool` | `true` | No |
| `enable_security_hub` | Enable Security Hub | `bool` | `true` | No |
| `enable_macie` | Enable Macie sensitive data discovery | `bool` | `true` | No |
| `enable_inspector` | Enable Inspector vulnerability scanning | `bool` | `true` | No |
| `enable_detective` | Enable Detective for investigations | `bool` | `true` | No |
| `enable_finding_notifications` | Route HIGH/CRITICAL findings to SNS via EventBridge | `bool` | `true` | No |
| `enable_scps` | Enable Service Control Policies (requires Organization) | `bool` | `false` | No |
| `enable_budget_alerts` | Enable monthly cost budget with alerts | `bool` | `true` | No |
| `monthly_budget_amount` | Monthly budget amount in USD | `number` | `1000` | No |

See `variables.tf` for the complete list of available variables.

## Outputs

| Name | Description |
|------|-------------|
| `security_baseline_summary` | Map of all enabled security components |
| `cloudtrail_arn` | ARN of the CloudTrail trail |
| `cloudtrail_s3_bucket_name` | S3 bucket storing CloudTrail logs |
| `config_recorder_id` | AWS Config recorder ID |
| `guardduty_detector_id` | GuardDuty detector ID |
| `security_hub_arn` | Security Hub ARN |
| `access_logs_meta_bucket_name` | S3 meta-logging bucket for the access logs bucket |
| `security_alarms_sns_topic_arn` | SNS topic ARN for security alarm notifications |
| `security_dashboard_name` | CloudWatch dashboard name for security alarms |
| `external_access_analyzer_arn` | IAM Access Analyzer ARN (external access) |
| `ebs_encryption_enabled` | Whether EBS encryption by default is enabled |
| `cost_anomaly_monitor_arn` | Cost Anomaly Detection monitor ARN |

## Known AWS API Limitations

| Service | Limitation |
|---------|-----------|
| **S3 Block Public Access** | Account-level setting - cannot be reversed without API call |
| **EBS Encryption Default** | Only applies to new volumes - existing volumes are not retroactively encrypted |
| **GuardDuty** | Cannot be re-enabled for 30 days after suspension in some cases |
| **Security Hub** | Standards enablement can take up to 24 hours to fully evaluate |
| **Macie** | 30-day free trial, then costs apply per GB scanned |
| **Config Rules** | Evaluation can take up to 3 hours after recorder starts |
| **SCPs** | Cannot be applied to management account. Take up to 5 minutes to propagate |
| **Alternate Contacts** | API may not be available in all partitions |
| **IAM Access Analyzer (Unused Access)** | Paid feature - charges per analyzer per month |
| **SNS Email Subscriptions** | Require manual confirmation - check inbox after first apply |

## Cost Considerations

| Service | Cost Model |
|---------|-----------|
| CloudTrail | First trail free. Data events charged per 100K events |
| Config | $0.003 per configuration item recorded |
| GuardDuty | 30-day free trial; then per-event pricing |
| Security Hub | $0.0010 per finding check (first 10K free during the 30-day trial) |
| Macie | 30-day free trial; per-GB scanning costs |
| Inspector | Per-instance/image scanned |
| Detective | 30-day free trial; per-GB data processed |
| CloudWatch Alarms | $0.10 per alarm per month (Standard resolution) |
| SNS | First 1,000 email notifications free per month |

## Architecture

```
terraform-aws-security-foundation/
├── main.tf                          # Root module - wires everything together
├── variables.tf                     # All feature flags and configuration
├── outputs.tf                       # Security baseline status outputs
├── locals.tf                        # Computed values and policy construction
├── providers.tf                     # AWS provider configuration
├── versions.tf                      # Terraform and provider version pins
├── terraform.tfvars.example         # Example configuration
├── modules/
│   ├── iam/                         # Password policy, Access Analyzers
│   ├── s3/                          # S3 Block Public Access (account-level)
│   ├── data-protection/             # EBS encryption, AMI/snapshot blocking
│   ├── logging/                     # CloudTrail, Config, CloudWatch, security alarms
│   ├── threat-detection/            # GuardDuty, Security Hub, Macie, Inspector, Detective
│   ├── organizations/               # SCPs, tag/backup/AI policies, RAM
│   └── billing/                     # Budgets, Cost Anomaly Detection, alternate contacts
```
