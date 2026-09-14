# ─── GUARDDUTY DETECTOR ──────────────────────────────────────────────────────
#
# GuardDuty provides threat-detection findings that can be imported into
# Security Hub and routed through EventBridge to the SOAR playbooks.
#
# The detector uses the standard GuardDuty threat-detection capability and
# enables EC2 malware protection because the EC2 containment playbook is
# specifically designed to respond to suspicious or malicious EC2 activity.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  malware_protection {
    scan_ec2_instance_with_findings {
      ebs_volumes {
        enable = true
      }
    }
  }

  finding_publishing_frequency = var.finding_publish_frequency

  tags = {
    Name = "${var.name_prefix}-guardduty"
  }
}


# ─── GUARDDUTY FINDINGS EXPORT ────────────────────────────────────────────────
#
# Export GuardDuty findings to the centralized audit bucket using the
# dedicated KMS key supplied by the logging module.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_guardduty_publishing_destination" "s3" {
  count = var.enable_guardduty ? 1 : 0

  detector_id     = aws_guardduty_detector.main[0].id
  destination_arn = var.findings_bucket_arn
  kms_key_arn     = var.kms_key_arn
}
