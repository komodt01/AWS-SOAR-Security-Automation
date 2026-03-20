variable "name_prefix" { type = string }
variable "aws_region" { type = string }
variable "sns_alert_topic_arn" { type = string }
variable "audit_bucket_name" { type = string }
variable "audit_bucket_arn" { type = string }
variable "lambda_log_retention_days" {
  type    = number
  default = 30
}
variable "shared_policy_arns" {
  type = object({
    lambda_logs    = string
    write_audit_s3 = string
  })
}
