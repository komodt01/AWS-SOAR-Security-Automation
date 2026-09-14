# ─── SOC ALERT TOPIC ──────────────────────────────────────────────────────────
#
# Used by the notify_soc Lambda to deliver playbook notifications and
# escalation messages to the configured security-team email address.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_sns_topic" "soc_alerts" {
  name              = "${var.name_prefix}-soc-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Name = "${var.name_prefix}-soc-alerts"
  }
}


# ─── EMAIL SUBSCRIPTION ───────────────────────────────────────────────────────
#
# AWS requires the recipient to confirm the SNS email subscription before
# notifications can be delivered.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.soc_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
