output "shared_policy_arns" {
  value = {
    lambda_logs    = aws_iam_policy.lambda_logs.arn
    write_audit_s3 = aws_iam_policy.write_audit_s3.arn
  }
}
