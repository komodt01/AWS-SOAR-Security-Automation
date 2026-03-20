output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = module.guardduty.detector_id
}

output "security_hub_arn" {
  description = "Security Hub ARN"
  value       = module.security_hub.hub_arn
}

output "iam_state_machine_arn" {
  description = "ARN of the IAM credential compromise playbook state machine"
  value       = module.step_functions.iam_state_machine_arn
}

output "ec2_state_machine_arn" {
  description = "ARN of the EC2 isolation playbook state machine"
  value       = module.step_functions.ec2_state_machine_arn
}

output "sns_alert_topic_arn" {
  description = "SNS topic ARN for SOC alerts"
  value       = module.sns.alert_topic_arn
}

output "audit_bucket_name" {
  description = "S3 bucket name for audit artifacts"
  value       = module.logging.audit_bucket_name
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN"
  value       = module.logging.cloudtrail_arn
}
