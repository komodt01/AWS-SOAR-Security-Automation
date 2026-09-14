data "aws_region" "current" {}


# ─── SECURITY HUB ─────────────────────────────────────────────────────────────
#
# Security Hub acts as the normalized finding layer for the SOAR workflow.
# GuardDuty findings are imported into Security Hub and then routed through
# EventBridge to the appropriate Step Functions playbook.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_securityhub_account" "main" {
  count                    = var.enable_security_hub ? 1 : 0
  enable_default_standards = false
  auto_enable_controls     = true
}


# ─── AWS FOUNDATIONAL SECURITY BEST PRACTICES ─────────────────────────────────

resource "aws_securityhub_standards_subscription" "fsbp" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = (
    "arn:aws:securityhub:"
    "${data.aws_region.current.name}::"
    "standards/aws-foundational-security-best-practices/v/1.0.0"
  )

  depends_on = [
    aws_securityhub_account.main
  ]

  timeouts {
    create = "15m"
  }
}


# ─── GUARDDUTY → SECURITY HUB ─────────────────────────────────────────────────
#
# GuardDuty findings are imported into Security Hub so EventBridge can route
# normalized findings to the IAM or EC2 response playbooks.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_securityhub_product_subscription" "guardduty" {
  count = var.enable_security_hub ? 1 : 0

  product_arn = (
    "arn:aws:securityhub:"
    "${data.aws_region.current.name}::"
    "product/aws/guardduty"
  )

  depends_on = [
    aws_securityhub_account.main
  ]
}
