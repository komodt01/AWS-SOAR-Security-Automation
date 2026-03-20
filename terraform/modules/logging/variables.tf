variable "name_prefix" { type = string }
variable "aws_region" { type = string }
variable "cloudtrail_retention_days" {
  type    = number
  default = 90
}

variable "audit_s3_retention_days" {
  type    = number
  default = 90
}
