variable "name_prefix" {
  type = string
}

variable "enable_security_hub" {
  type    = bool
  default = true
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}