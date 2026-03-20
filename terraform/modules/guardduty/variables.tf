variable "name_prefix" {
  type = string
}

variable "enable_guardduty" {
  type    = bool
  default = true
}

variable "finding_publish_frequency" {
  type    = string
  default = "FIFTEEN_MINUTES"
}

variable "findings_bucket_arn" {
  type    = string
  default = ""
}

variable "kms_key_arn" {
  type    = string
  default = ""
}
