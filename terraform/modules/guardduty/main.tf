resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  finding_publishing_frequency = var.finding_publish_frequency

  tags = {
    Name = "${var.name_prefix}-guardduty"
  }
}

resource "aws_guardduty_publishing_destination" "s3" {
  count = var.enable_guardduty ? 1 : 0

  detector_id     = aws_guardduty_detector.main[0].id
  destination_arn = var.findings_bucket_arn
  kms_key_arn     = var.kms_key_arn

  depends_on = [aws_guardduty_detector.main]
}

