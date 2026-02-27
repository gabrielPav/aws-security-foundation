output "deny_root_usage_scp_id" {
  description = "ID of the deny-root-usage SCP"
  value       = var.enable_scps && var.enable_scp_deny_root_usage ? aws_organizations_policy.deny_root_usage[0].id : ""
}

output "deny_unapproved_regions_scp_id" {
  description = "ID of the deny-unapproved-regions SCP"
  value       = var.enable_scps && var.enable_scp_deny_unapproved_regions && length(var.allowed_regions) > 0 ? aws_organizations_policy.deny_unapproved_regions[0].id : ""
}

output "deny_disable_security_scp_id" {
  description = "ID of the deny-disable-security SCP"
  value       = var.enable_scps && var.enable_scp_deny_disable_security ? aws_organizations_policy.deny_disable_security[0].id : ""
}

output "enforce_encryption_scp_id" {
  description = "ID of the enforce-encryption SCP"
  value       = var.enable_scps && var.enable_scp_enforce_encryption ? aws_organizations_policy.enforce_encryption[0].id : ""
}

output "deny_public_ami_scp_id" {
  description = "ID of the deny-public-ami SCP"
  value       = var.enable_scps && var.enable_scp_deny_public_ami ? aws_organizations_policy.deny_public_ami[0].id : ""
}

output "deny_leave_organization_scp_id" {
  description = "ID of the deny-leave-organization SCP"
  value       = var.enable_scps && var.enable_scp_deny_leave_organization ? aws_organizations_policy.deny_leave_organization[0].id : ""
}

output "deny_delete_flow_logs_scp_id" {
  description = "ID of the deny-delete-flow-logs SCP"
  value       = var.enable_scps && var.enable_scp_deny_delete_flow_logs ? aws_organizations_policy.deny_delete_flow_logs[0].id : ""
}

output "deny_deactivate_mfa_scp_id" {
  description = "ID of the deny-deactivate-mfa SCP"
  value       = var.enable_scps && var.enable_scp_deny_deactivate_mfa ? aws_organizations_policy.deny_deactivate_mfa[0].id : ""
}

output "deny_imdsv1_scp_id" {
  description = "ID of the deny-imdsv1 SCP"
  value       = var.enable_scps && var.enable_scp_deny_imdsv1 ? aws_organizations_policy.deny_imdsv1[0].id : ""
}

output "tag_policy_id" {
  description = "ID of the tag policy"
  value       = var.enable_tag_policies ? aws_organizations_policy.tag_policy[0].id : ""
}

output "backup_policy_id" {
  description = "ID of the backup policy"
  value       = var.enable_backup_policies ? aws_organizations_policy.backup_policy[0].id : ""
}

output "ai_opt_out_policy_id" {
  description = "ID of the AI opt-out policy"
  value       = var.enable_ai_opt_out_policy ? aws_organizations_policy.ai_opt_out[0].id : ""
}
