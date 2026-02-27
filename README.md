# AWS Security Foundation with Terraform

![AWS Badge](https://img.shields.io/badge/AWS-Deployed-4EAA25.svg?style=flat&logo=amazon-aws&logoColor=white)
![Terraform Badge](https://img.shields.io/badge/Terraform-IaC-5c4ee5.svg?style=flat&logo=terraform&logoColor=white)

This project automates the deployment of a production-grade, account-level security baseline on AWS. It establishes hardened guardrails aligned with the industry best practices, delivering over 100 operational security controls.

By operating strictly at the account boundary, the project remains entirely decoupled from application or workload infrastructure, serving as a foundational 'Landing Zone Security Layer' safe for use in regulated environments.

## Features

### IAM & Access Control
> CIS-hardened password policy. External Access Analyzer always-on at account or organization scope. Unused Access Analyzer opt-in with configurable inactivity threshold for zero-trust access reviews.

### Encryption & Data Protection
> Multiple purpose-built KMS keys (compute, observability, storage) with automatic rotation and safe deletion windows. EBS default encryption enforced at account level with a Customer-Managed Key. All KMS key policies scoped to prevent confused deputy attacks. Public AMI/snapshot sharing blocked, IMDSv2 enforced as account default, EC2 serial console disabled.

### Threat Detection
> GuardDuty with six individually toggleable protection features, Security Hub with five compliance standards and cross-region finding aggregation, Macie with optional classification export, Inspector v2 scanning EC2/ECR/Lambda, and Detective for graph-based investigation.

### Organizations Guardrails
> 10 SCPs covering root usage, region restriction, security service protection, encryption enforcement, public AMI/snapshot blocking, org departure, flow log deletion, MFA deactivation, and IMDSv2 enforcement. Region-deny SCP handles global service exceptions. Tag policies, backup policies, and AI opt-out policies all conditional.

### CloudTrail
> Multi-region trail with log file validation and Insight selectors for anomaly detection. S3 data events opt-in to control costs. Organization trail support conditional and validated. CloudWatch Logs integration via a least-privilege IAM role hardened against confused deputy escalation. Automatic credential masking via CloudWatch data protection policy (catches AWS secret keys and private keys if they ever appear in logs).

### AWS Config
> Continuous recording of all resource types including global resources. Least-privilege IAM role with daily configuration snapshots. CIS-aligned managed rules for compliance checks. Pre-flight validation detects existing recorders and delivery channels before deployment to avoid conflicts.

### S3 Security
> All audit buckets (CloudTrail, Config, access logs, access logs meta) hardened with KMS encryption, public access blocking, TLS-only policies, versioning, ACLs disabled, and source-scoped write permissions. Lifecycle rules manage storage tiering, expiration, multipart cleanup, and noncurrent version retention. Object Lock (Governance Mode by default) supported on all four buckets for tamper-proof immutability (off by default, enable per-bucket as needed).

### Security Alarms
> 13 CIS-aligned CloudWatch metric filters and alarms covering auth failures, unauthorized API calls, root usage, and changes to CloudTrail, Config, IAM, KMS, S3, security groups, networking, and VPCs. KMS-encrypted SNS topic with TLS enforcement, tuned to reduce false positives. SQS dead-letter queue for SNS delivery failures. CloudWatch dashboard for single-pane security visibility.

### Finding Notifications
> EventBridge rules routing HIGH and CRITICAL findings from GuardDuty, Security Hub, Inspector, and Macie to the security alarms SNS topic. SQS dead-letter queue for failed deliveries. Off by default. Enable when you're ready for near real-time alerting.

### Billing & Governance
> Monthly cost budgets with multi-threshold alerts, ML-powered Cost Anomaly Detection, and alternate contacts for security, billing, and operations.

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

### Verify

```bash
terraform output security_baseline_summary
```

### Destroy Infrastructure

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

Here's what a typical conflict looks like:

```
Error: Resource precondition failed

  A GuardDuty detector 'abcd1234abcd' already exists in us-east-1.
  AWS allows only one detector per region. Either:
    1. Import it:  terraform import 'module.threat_detection.aws_guardduty_detector.main[0]' abcd1234abcd
    2. Delete it:  aws guardduty delete-detector --region us-east-1 --detector-id abcd1234abcd
```

You have two ways to resolve it:

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

## Implemented Security Best Practices

### Identity & Access Management:

- CIS-aligned IAM password policy (minimum 14 characters, complexity, 90-day rotation, 24-password reuse prevention)
- IAM Access Analyzer for external access detection (ORGANIZATION or ACCOUNT scope)
- IAM Access Analyzer for unused access detection (identifies overly broad permissions)
- Password hard expiry configurable for administrator-forced reset

### S3 Account Security:

- Account-level S3 Block Public Access (all four settings enforced)
- Blocks public ACLs, public policies, ignores existing public ACLs, restricts public buckets
- Applied globally, overrides any individual bucket configuration

### Data Protection & Encryption:

- EBS encryption by default for all new volumes and snapshots
- Optional customer-managed KMS key for EBS default encryption
- AMI public access blocked (prevents public sharing of machine images)
- EBS snapshot public access blocked (prevents public sharing of volume data)

### Logging & Auditing:

- CloudTrail multi-region trail capturing all API activity across all regions
- CloudTrail log file validation for tamper detection
- CloudTrail Insights for API call rate and error rate anomaly detection
- CloudTrail integration with CloudWatch Logs for real-time monitoring
- Optional S3 data event logging for object-level audit trails
- Optional organization-wide CloudTrail for multi-account visibility
- AWS Config recorder with continuous recording of all supported resources
- CIS-aligned Config managed rules (root MFA, root access keys, EBS encryption, RDS encryption, KMS rotation, default SG, IAM user MFA, S3 encryption)
- Dedicated S3 buckets for CloudTrail and Config with BucketOwnerEnforced ownership, versioning, encryption, public access blocking, lifecycle policies, and TLS-only bucket policies
- Full access logging chain: CloudTrail and Config buckets log to a shared access logs bucket, which logs to a dedicated access logs meta bucket as the terminal destination
- Optional S3 Object Lock (Governance Mode) on CloudTrail, Config, access logs, and access logs meta buckets (makes audit logs tamper-proof for a configurable retention period)

### Security Alarms & Monitoring:

- Console sign-in without MFA detection
- Console sign-in failures (3+ in 5 minutes, possible brute-force)
- CloudTrail configuration changes (create, update, delete, start/stop logging)
- AWS Config service configuration changes
- Unauthorized API calls (AccessDenied errors, 5+ in 5 minutes)
- Root account usage detection (any API call or console login)
- AWS Organizations changes (conditional — create/delete org, create/remove account)
- CloudWatch dashboard with time-series graphs for every alarm metric and threshold annotations (provides a single-pane security overview even without email notifications)
- SNS topic with CloudWatch-only publish policy for alarm delivery
- Alarms and dashboard deployed when `enable_security_alarms = true`; email notifications are opt-in via `alarm_notification_email`. For active security monitoring, set `alarm_notification_email`

### Threat Detection:

- GuardDuty with S3, EKS, RDS, Lambda, malware, and runtime protection
- Security Hub with CIS Benchmark, AWS Foundational Security Best Practices, and optional PCI DSS standards
- Security Hub cross-region finding aggregation
- Macie for automated sensitive data discovery in S3
- Inspector v2 for EC2, ECR, and Lambda vulnerability scanning
- Detective for graph-based security investigation and incident response
- Optional EventBridge rules routing HIGH/CRITICAL findings from GuardDuty, Security Hub, Inspector, and Macie to the security alarms SNS topic for near real-time notification

### Organizations Guardrails (Conditional):

- SCP: Deny root account usage in member accounts
- SCP: Deny unapproved regions (configurable region allowlist, global services exempted)
- SCP: Deny disabling security services (CloudTrail, GuardDuty, Config, Security Hub, Access Analyzer, Macie, Inspector, Detective, S3 BPA)
- SCP: Enforce encryption (deny unencrypted RDS/EBS creation, KMS key deletion with < 14 day window)
- SCP: Deny public AMI and snapshot sharing
- SCP: Deny leaving the organization
- SCP: Deny deleting VPC flow logs
- SCP: Deny deactivating MFA devices
- SCP: Deny launching EC2 instances without IMDSv2
- Tag policies for consistent tagging across the organization
- Backup policies for centralized daily backup schedules
- AI services opt-out policy (prevents AWS from using content for ML training)
- RAM resource sharing within the organization

### Break-Glass Emergency Access for SCPs (Optional)

The `deny-disable-security` and `deny-deactivate-mfa` SCPs block everyone in member accounts from disabling security services. In an emergency, for example, a misbehaving GuardDuty detector flooding your account with false positives, you need a controlled way to act without detaching the SCP and briefly exposing all accounts.

The recommended approach is **account-based break-glass isolation**. Create a dedicated AWS account in its own OU, and don't attach SCPs to that OU. Because this project controls attachment via `scp_target_ou_ids`, you simply leave the break-glass OU out of the list.

**Setup:**

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

**During an incident:**

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::MEMBER_ACCOUNT:role/BreakGlassAccess \
  --role-session-name emergency \
  --serial-number arn:aws:iam::BREAKGLASS_ACCOUNT:mfa/admin \
  --token-code 123456
```

The SCP stays in place for all other accounts. Only the break-glass session can act.

### Billing & Governance:

- Monthly cost budget with alerts at 80% (early warning), 100% (exceeded), and 120% (forecasted overspend).
- Cost Anomaly Detection with ML-based per-service cost spike monitoring.
- Alternate contacts configured for security, billing, and operations teams.
- All budget alerts conditional on email notification list being provided.

## State Management (Optional)

We recommend using a remote backend (S3 + DynamoDB) for secure state management and collaboration.

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
