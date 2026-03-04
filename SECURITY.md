# Implemented Security Best Practices

This document details the security controls deployed by the AWS Security Foundation.

## Identity & Access Management

- CIS-aligned IAM password policy (minimum 14 characters, complexity, 90-day rotation, 24-password reuse prevention)
- IAM Access Analyzer for external access detection (ORGANIZATION or ACCOUNT scope)
- IAM Access Analyzer for unused access detection (identifies overly broad permissions)
- Password hard expiry configurable for administrator-forced reset

## S3 Account Security

- Account-level S3 Block Public Access (all four settings enforced)
- Blocks public ACLs, public policies, ignores existing public ACLs, restricts public buckets
- Applied globally, overrides any individual bucket configuration

## Data Protection & Encryption

- EBS encryption by default for all new volumes and snapshots
- Optional customer-managed KMS key for EBS default encryption
- AMI public access blocked (prevents public sharing of machine images)
- EBS snapshot public access blocked (prevents public sharing of volume data)
- Three purpose-built KMS keys with automatic rotation (90 days default):
  - Compute layer key (EBS volumes, Auto Scaling)
  - Observability layer key (CloudTrail, CloudWatch Logs, SNS, SQS, EventBridge)
  - Storage layer key (S3 buckets, AWS Config, AWS Backup)
- All KMS key policies include confused deputy protection via aws:SourceAccount conditions
- KMS keys have 30-day deletion window to prevent accidental data loss
- EMR block public access configuration enabled (prevents clusters with public security groups)
- EC2 serial console disabled (eliminates out-of-band access path)
- IMDSv2 enforced as account default (prevents SSRF-based credential theft from metadata endpoint)

## Logging & Auditing

- CloudTrail multi-region trail capturing all API activity across all regions
- CloudTrail log file validation for tamper detection
- CloudTrail Insights for API call rate and error rate anomaly detection
- CloudTrail integration with CloudWatch Logs for real-time monitoring
- CloudWatch data protection policy automatically masks credentials in logs (AWS secret keys, SSH private keys, PGP keys, PKCS keys, Putty keys)
- Masked credential findings sent to CloudTrail S3 bucket for investigation
- Optional S3 data event logging for object-level audit trails
- Optional organization-wide CloudTrail for multi-account visibility
- AWS Config recorder with continuous recording of all supported resources
- CIS-aligned Config managed rules (root MFA, root access keys, EBS encryption, RDS encryption, KMS rotation, default SG, IAM user MFA, S3 encryption)
- Config bucket with dedicated KMS encryption (storage layer key)
- Config bucket with BucketOwnerEnforced ownership, versioning, public access blocking, and TLS-only policy
- Config bucket lifecycle rules for storage tiering and noncurrent version retention
- Config bucket logging to shared access logs bucket
- Optional S3 Object Lock (Governance Mode) on Config bucket for tamper-proof configuration history
- IAM role for Config with least-privilege permissions and confused deputy protection
- Daily configuration snapshots to S3
- Dedicated S3 buckets for CloudTrail and Config with BucketOwnerEnforced ownership, versioning, encryption, public access blocking, lifecycle policies, and TLS-only bucket policies
- Full access logging chain: CloudTrail and Config buckets log to a shared access logs bucket, which logs to a dedicated access logs meta bucket as the terminal destination
- Optional S3 Object Lock (Governance Mode) on CloudTrail, Config, access logs, and access logs meta buckets (makes audit logs tamper-proof for a configurable retention period)

## Security Alarms & Monitoring

- Console sign-in without MFA detection
- Console sign-in failures (3+ in 5 minutes, possible brute-force)
- CloudTrail configuration changes (create, update, delete, start/stop logging)
- AWS Config service configuration changes
- Unauthorized API calls (AccessDenied errors, 5+ in 5 minutes)
- Root account usage detection (any API call or console login)
- IAM policy changes alarm
- Network ACL changes alarm
- Network gateway changes alarm
- Route table changes alarm
- Security group changes alarm
- VPC changes alarm
- S3 bucket policy changes alarm
- KMS key configuration changes alarm (disable/delete)
- AWS Organizations changes (conditional — create/delete org, create/remove account)
- CloudWatch dashboard with time-series graphs for every alarm metric and threshold annotations (provides a single-pane security overview even without email notifications)
- SNS topic encrypted with KMS (observability layer key)
- SNS topic policy restricted to CloudWatch and EventBridge only
- SQS dead-letter queue for failed EventBridge-to-SNS deliveries
- SQS dead-letter queue encrypted with KMS (observability layer key)
- EventBridge rules for HIGH/CRITICAL findings from GuardDuty, Security Hub, Inspector, and Macie
- All EventBridge rules target the security alarms SNS topic with DLQ fallback
- Alarms and dashboard deployed when `enable_security_alarms = true`; email notifications are opt-in via `alarm_notification_email`. For active security monitoring, set `alarm_notification_email`

## Threat Detection

- GuardDuty with S3, EKS, RDS, Lambda, malware, and runtime protection
- GuardDuty features: S3 Protection, EKS Protection, RDS Protection, Lambda Protection, Malware Protection, Runtime Monitoring
- Security Hub with CIS Benchmark, AWS Foundational Security Best Practices, and optional PCI DSS standards
- Security Hub standards: CIS AWS Foundations Benchmark v1.2.0, AWS Foundational Security Best Practices v1.0.0, PCI DSS v3.2.1 (optional), NIST 800-53 Rev. 5 (optional), CIS AWS Foundations Benchmark v3.0.0 (optional)
- Security Hub cross-region finding aggregation
- Macie for automated sensitive data discovery in S3
- Inspector v2 for EC2, ECR, and Lambda vulnerability scanning
- Detective for graph-based security investigation and incident response
- Pre-flight validation checks for existing GuardDuty detectors, Security Hub enablement, Macie sessions, and Detective graphs
- Automatic import guidance provided if conflicts detected
- Optional EventBridge rules routing HIGH/CRITICAL findings from GuardDuty, Security Hub, Inspector, and Macie to the security alarms SNS topic for near real-time notification

## Organizations Guardrails (Conditional)

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


## Billing & Governance

- Monthly cost budget with alerts at three thresholds: 80% (early warning), 100% (exceeded), 120% (forecasted overspend)
- Cost Anomaly Detection with per-service monitoring using ML models
- Anomaly alerts sent to budget notification emails
- Alternate contacts for security, billing, and operations teams (enables AWS to reach the right team during incidents)
- All budget alerts conditional on email notification list being provided

## S3 Bucket Hardening

All audit buckets (CloudTrail, Config, access logs, access logs meta) implement defense-in-depth:

- KMS encryption with appropriate layer-specific keys
- Versioning enabled for audit trail integrity
- Public access blocking (all four settings)
- BucketOwnerEnforced ownership (ACLs disabled)
- TLS-only bucket policies (deny unencrypted transport)
- Source-scoped write permissions (prevents confused deputy attacks)
- Lifecycle rules for automated storage tiering and cost optimization
- Noncurrent version expiration after configurable retention period
- Incomplete multipart upload cleanup after 7 days
- Optional S3 Object Lock (Governance Mode) for immutable audit logs
- Access logging chain: CloudTrail/Config → access logs → access logs meta (terminal destination)
