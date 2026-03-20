data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Shared policy: write audit artifacts to S3
resource "aws_iam_policy" "write_audit_s3" {
  name        = "${var.name_prefix}-write-audit-s3"
  description = "Allow Lambda functions to write SOAR audit artifacts to S3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "WriteAuditArtifacts"
      Effect = "Allow"
      Action = [
        "s3:PutObject",
        "s3:PutObjectAcl"
      ]
      Resource = "${var.audit_bucket_arn}/playbook-artifacts/*"
    }]
  })
}

# Shared policy: write CloudWatch logs
resource "aws_iam_policy" "lambda_logs" {
  name        = "${var.name_prefix}-lambda-cloudwatch-logs"
  description = "Allow Lambda functions to write CloudWatch logs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-*"
    }]
  })
}
