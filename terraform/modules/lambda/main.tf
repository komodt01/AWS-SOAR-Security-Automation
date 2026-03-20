data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─── LAMBDA EXECUTION ROLE FACTORY ───────────────────────────────────────────
# Each function gets its own role — least privilege per playbook step

locals {
  lambda_assume_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# ─── FUNCTION: enrich_finding ─────────────────────────────────────────────────

resource "aws_iam_role" "enrich_finding" {
  name               = "${var.name_prefix}-enrich-finding-role"
  assume_role_policy = local.lambda_assume_policy
}

resource "aws_iam_role_policy" "enrich_finding" {
  name = "${var.name_prefix}-enrich-finding-policy"
  role = aws_iam_role.enrich_finding.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadIAMContext"
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:ListAccessKeys",
          "iam:ListUserPolicies",
          "iam:ListAttachedUserPolicies",
          "iam:GetLoginProfile"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"
      },
      {
        Sid    = "ReadEC2Context"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkInterfaces"
        ]
        Resource = "*"
      },
      {
        Sid    = "ReadSecurityHubFinding"
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:BatchUpdateFindings"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "enrich_finding_logs" {
  role       = aws_iam_role.enrich_finding.name
  policy_arn = var.shared_policy_arns.lambda_logs
}

resource "aws_cloudwatch_log_group" "enrich_finding" {
  name              = "/aws/lambda/${var.name_prefix}-enrich-finding"
  retention_in_days = var.lambda_log_retention_days
}

data "archive_file" "enrich_finding" {
  type        = "zip"
  source_dir  = "${path.root}/../lambda/enrich_finding"
  output_path = "${path.root}/../lambda/dist/enrich_finding.zip"
}

resource "aws_lambda_function" "enrich_finding" {
  function_name    = "${var.name_prefix}-enrich-finding"
  role             = aws_iam_role.enrich_finding.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.enrich_finding.output_path
  source_code_hash = data.archive_file.enrich_finding.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      LOG_LEVEL   = "INFO"
      ENVIRONMENT = var.name_prefix
    }
  }

  depends_on = [aws_cloudwatch_log_group.enrich_finding]

  tags = { Name = "${var.name_prefix}-enrich-finding" }
}

# ─── FUNCTION: notify_soc ─────────────────────────────────────────────────────

resource "aws_iam_role" "notify_soc" {
  name               = "${var.name_prefix}-notify-soc-role"
  assume_role_policy = local.lambda_assume_policy
}

resource "aws_iam_role_policy" "notify_soc" {
  name = "${var.name_prefix}-notify-soc-policy"
  role = aws_iam_role.notify_soc.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PublishSNSAlert"
      Effect   = "Allow"
      Action   = ["sns:Publish"]
      Resource = var.sns_alert_topic_arn
    }]
  })
}

resource "aws_iam_role_policy_attachment" "notify_soc_logs" {
  role       = aws_iam_role.notify_soc.name
  policy_arn = var.shared_policy_arns.lambda_logs
}

resource "aws_cloudwatch_log_group" "notify_soc" {
  name              = "/aws/lambda/${var.name_prefix}-notify-soc"
  retention_in_days = var.lambda_log_retention_days
}

data "archive_file" "notify_soc" {
  type        = "zip"
  source_dir  = "${path.root}/../lambda/notify_soc"
  output_path = "${path.root}/../lambda/dist/notify_soc.zip"
}

resource "aws_lambda_function" "notify_soc" {
  function_name    = "${var.name_prefix}-notify-soc"
  role             = aws_iam_role.notify_soc.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.notify_soc.output_path
  source_code_hash = data.archive_file.notify_soc.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      SNS_TOPIC_ARN = var.sns_alert_topic_arn
      LOG_LEVEL     = "INFO"
    }
  }

  depends_on = [aws_cloudwatch_log_group.notify_soc]
  tags       = { Name = "${var.name_prefix}-notify-soc" }
}

# ─── FUNCTION: iam_remediation ────────────────────────────────────────────────

resource "aws_iam_role" "iam_remediation" {
  name               = "${var.name_prefix}-iam-remediation-role"
  assume_role_policy = local.lambda_assume_policy
}

resource "aws_iam_role_policy" "iam_remediation" {
  name = "${var.name_prefix}-iam-remediation-policy"
  role = aws_iam_role.iam_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DisableIAMCredentials"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:PutUserPolicy",
          "iam:TagUser"
        ]
        # Scope to users only — cannot act on roles or root
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"
      },
      {
        Sid    = "GetUserInfo"
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:ListAccessKeys"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"
      },
      {
        # Explicit deny: cannot create/delete users or modify roles
        Sid    = "DenyDestructiveIAM"
        Effect = "Deny"
        Action = [
          "iam:DeleteUser",
          "iam:CreateUser",
          "iam:AttachRolePolicy",
          "iam:PutRolePolicy",
          "iam:UpdateRole"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "iam_remediation_logs" {
  role       = aws_iam_role.iam_remediation.name
  policy_arn = var.shared_policy_arns.lambda_logs
}

resource "aws_cloudwatch_log_group" "iam_remediation" {
  name              = "/aws/lambda/${var.name_prefix}-iam-remediation"
  retention_in_days = var.lambda_log_retention_days
}

data "archive_file" "iam_remediation" {
  type        = "zip"
  source_dir  = "${path.root}/../lambda/iam_remediation"
  output_path = "${path.root}/../lambda/dist/iam_remediation.zip"
}

resource "aws_lambda_function" "iam_remediation" {
  function_name    = "${var.name_prefix}-iam-remediation"
  role             = aws_iam_role.iam_remediation.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.iam_remediation.output_path
  source_code_hash = data.archive_file.iam_remediation.output_base64sha256
  timeout          = 60
  memory_size      = 128

  environment {
    variables = {
      LOG_LEVEL   = "INFO"
      ENVIRONMENT = var.name_prefix
    }
  }

  depends_on = [aws_cloudwatch_log_group.iam_remediation]
  tags       = { Name = "${var.name_prefix}-iam-remediation" }
}

# ─── FUNCTION: ec2_isolation ──────────────────────────────────────────────────

resource "aws_iam_role" "ec2_isolation" {
  name               = "${var.name_prefix}-ec2-isolation-role"
  assume_role_policy = local.lambda_assume_policy
}

resource "aws_iam_role_policy" "ec2_isolation" {
  name = "${var.name_prefix}-ec2-isolation-policy"
  role = aws_iam_role.ec2_isolation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IsolateEC2"
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateSnapshot",
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSecurityGroups",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "CreateQuarantineSG"
        Effect = "Allow"
        Action = [
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = "*"
      },
      {
        # Explicit deny: cannot terminate or start instances
        Sid    = "DenyDestructiveEC2"
        Effect = "Deny"
        Action = [
          "ec2:TerminateInstances",
          "ec2:RunInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_isolation_logs" {
  role       = aws_iam_role.ec2_isolation.name
  policy_arn = var.shared_policy_arns.lambda_logs
}

resource "aws_cloudwatch_log_group" "ec2_isolation" {
  name              = "/aws/lambda/${var.name_prefix}-ec2-isolation"
  retention_in_days = var.lambda_log_retention_days
}

data "archive_file" "ec2_isolation" {
  type        = "zip"
  source_dir  = "${path.root}/../lambda/ec2_isolation"
  output_path = "${path.root}/../lambda/dist/ec2_isolation.zip"
}

resource "aws_lambda_function" "ec2_isolation" {
  function_name    = "${var.name_prefix}-ec2-isolation"
  role             = aws_iam_role.ec2_isolation.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.ec2_isolation.output_path
  source_code_hash = data.archive_file.ec2_isolation.output_base64sha256
  timeout          = 120
  memory_size      = 256

  environment {
    variables = {
      LOG_LEVEL   = "INFO"
      ENVIRONMENT = var.name_prefix
    }
  }

  depends_on = [aws_cloudwatch_log_group.ec2_isolation]
  tags       = { Name = "${var.name_prefix}-ec2-isolation" }
}

# ─── FUNCTION: write_audit ────────────────────────────────────────────────────

resource "aws_iam_role" "write_audit" {
  name               = "${var.name_prefix}-write-audit-role"
  assume_role_policy = local.lambda_assume_policy
}

resource "aws_iam_role_policy_attachment" "write_audit_s3" {
  role       = aws_iam_role.write_audit.name
  policy_arn = var.shared_policy_arns.write_audit_s3
}

resource "aws_iam_role_policy_attachment" "write_audit_logs" {
  role       = aws_iam_role.write_audit.name
  policy_arn = var.shared_policy_arns.lambda_logs
}

resource "aws_cloudwatch_log_group" "write_audit" {
  name              = "/aws/lambda/${var.name_prefix}-write-audit"
  retention_in_days = var.lambda_log_retention_days
}

data "archive_file" "write_audit" {
  type        = "zip"
  source_dir  = "${path.root}/../lambda/write_audit"
  output_path = "${path.root}/../lambda/dist/write_audit.zip"
}

resource "aws_lambda_function" "write_audit" {
  function_name    = "${var.name_prefix}-write-audit"
  role             = aws_iam_role.write_audit.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.write_audit.output_path
  source_code_hash = data.archive_file.write_audit.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      AUDIT_BUCKET = var.audit_bucket_name
      LOG_LEVEL    = "INFO"
    }
  }

  depends_on = [aws_cloudwatch_log_group.write_audit]
  tags       = { Name = "${var.name_prefix}-write-audit" }
}
