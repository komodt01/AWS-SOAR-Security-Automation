output "hub_arn" {
  value = var.enable_security_hub ? aws_securityhub_account.main[0].id : ""
}
