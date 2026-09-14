data "aws_caller_identity" "current" {}

data "aws_region" "current" {}


# ─── SHARED POLICY: WRITE SOAR AUDIT ARTIFACTS ────────────────────────────────
#
# Used only by the write_audit Lambda.
# Access is restricted to the playbook-artifacts prefix in the
# designated SOAR audit bucket.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_iam_policy" "write_audit_s3" {
  name        = "${var.name_prefix}-write-audit-s3"
  description = "Allow the SOAR audit Lambda to write execution artifacts to the audit S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Sid    = "WriteAuditArtifacts"
      Effect = "Allow"

      Action = [
        "s3:PutObject"
      ]

      Resource = "${var.audit_bucket_arn}/playbook-artifacts/*"
    }]
  })
}


# ─── SHARED POLICY: WRITE LAMBDA LOGS ─────────────────────────────────────────
#
# Lambda log groups are created separately by Terraform.
# Functions require only permission to create streams and publish log events.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_iam_policy" "lambda_logs" {
  name        = "${var.name_prefix}-lambda-cloudwatch-logs"
  description = "Allow SOAR Lambda functions to write to their CloudWatch log groups"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Sid    = "WriteLambdaLogs"
      Effect = "Allow"

      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]

      Resource = (
        "arn:aws:logs:"
        "${data.aws_region.current.name}:"
        "${data.aws_caller_identity.current.account_id}:"
        "log-group:/aws/lambda/${var.name_prefix}-*:*"
      )
    }]
  })
}
