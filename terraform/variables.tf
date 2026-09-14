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
  description = "Resource name prefix for the SOAR deployment"
  type        = string
  default     = "soar"
}

variable "alert_email" {
  description = "Email address for SOC alert notifications"
  type        = string
}

variable "enable_guardduty" {
  description = "Enable GuardDuty (set false if already enabled in the account)"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub (set false if already enabled in the account)"
  type        = bool
  default     = true
}

variable "guardduty_finding_frequency" {
  description = "Frequency at which GuardDuty publishes updated findings"
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition = contains(
      ["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"],
      var.guardduty_finding_frequency
    )

    error_message = "Finding frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "cloudtrail_retention_days" {
  description = "CloudWatch retention for CloudTrail and Step Functions logs (days)"
  type        = number
  default     = 90
}

variable "audit_s3_retention_days" {
  description = "Retention period for current and noncurrent audit objects in S3 (days)"
  type        = number
  default     = 90
}

variable "lambda_log_retention_days" {
  description = "CloudWatch log retention for Lambda functions (days)"
  type        = number
  default     = 30
}
