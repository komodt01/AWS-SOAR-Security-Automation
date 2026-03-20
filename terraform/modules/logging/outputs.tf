output "audit_bucket_name" { value = aws_s3_bucket.audit.id }
output "audit_bucket_arn" { value = aws_s3_bucket.audit.arn }
output "cloudtrail_arn" { value = aws_cloudtrail.main.arn }
output "sfn_log_group_arn" { value = aws_cloudwatch_log_group.step_functions.arn }
output "kms_key_arn" { value = aws_kms_key.guardduty.arn }