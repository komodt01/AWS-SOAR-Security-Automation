variable "name_prefix" { type = string }
variable "aws_region" { type = string }
variable "enrich_finding_lambda_arn" { type = string }
variable "notify_soc_lambda_arn" { type = string }
variable "iam_remediation_lambda_arn" { type = string }
variable "ec2_isolation_lambda_arn" { type = string }
variable "write_audit_lambda_arn" { type = string }
variable "cloudwatch_log_group_arn" { type = string }
