resource "aws_securityhub_account" "main" {
  count                    = var.enable_security_hub ? 1 : 0
  enable_default_standards = false # We manage standards explicitly below
  auto_enable_controls     = true
}

# AWS Foundational Security Best Practices
resource "aws_securityhub_standards_subscription" "fsbp" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]

  timeouts {
    create = "15m"
  }
}

# PCI DSS v3.2.1
resource "aws_securityhub_standards_subscription" "pci" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/3.2.1"

  depends_on = [aws_securityhub_account.main]

  timeouts {
    create = "15m"
  }
}

# GuardDuty → Security Hub integration
resource "aws_securityhub_product_subscription" "guardduty" {
  count       = var.enable_security_hub ? 1 : 0
  product_arn = "arn:aws:securityhub:${data.aws_region.current.name}::product/aws/guardduty"
  depends_on  = [aws_securityhub_account.main]
}

# Inspector → Security Hub integration
resource "aws_securityhub_product_subscription" "inspector" {
  count       = var.enable_security_hub ? 1 : 0
  product_arn = "arn:aws:securityhub:${data.aws_region.current.name}::product/aws/inspector"
  depends_on  = [aws_securityhub_account.main]
}

# Macie → Security Hub integration
resource "aws_securityhub_product_subscription" "macie" {
  count       = var.enable_security_hub ? 1 : 0
  product_arn = "arn:aws:securityhub:${data.aws_region.current.name}::product/aws/macie"
  depends_on  = [aws_securityhub_account.main]
}

data "aws_region" "current" {}
