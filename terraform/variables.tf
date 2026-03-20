variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Project name prefix for all resources"
  type        = string
  default     = "soar"
}

variable "alert_email" {
  description = "Email address for SOC alert notifications"
  type        = string
}

variable "enable_guardduty" {
  description = "Enable GuardDuty (set false if already enabled in account)"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub (set false if already enabled in account)"
  type        = bool
  default     = true
}

variable "guardduty_finding_frequency" {
  description = "Frequency of GuardDuty findings export to Security Hub"
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_frequency)
    error_message = "Finding frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "cloudtrail_retention_days" {
  description = "CloudWatch log retention for CloudTrail (days)"
  type        = number
  default     = 90
}

variable "audit_s3_retention_days" {
  description = "S3 lifecycle rule — transition audit artifacts to IA storage (days)"
  type        = number
  default     = 90
}

variable "lambda_log_retention_days" {
  description = "CloudWatch log retention for Lambda functions (days)"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
