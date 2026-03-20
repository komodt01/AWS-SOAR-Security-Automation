output "detector_id" {
  value = var.enable_guardduty ? aws_guardduty_detector.main[0].id : ""
}
