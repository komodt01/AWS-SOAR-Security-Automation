data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─── IAM CREDENTIAL COMPROMISE PLAYBOOK ──────────────────────────────────────
# Playbook: UnauthorizedAccess:IAMUser/AnomalousBehavior
# Flow: Enrich → Notify → Remediate → Choice(success|fail) → Audit

locals {
  iam_playbook_asl = jsonencode({
    Comment = "SOAR Playbook: IAM Credential Compromise Response"
    StartAt = "EnrichFinding"
    States = {
      EnrichFinding = {
        Type     = "Task"
        Resource = var.enrich_finding_lambda_arn
        Comment  = "Enrich finding with IAM user context (access keys, policies, login profile)"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.TooManyRequestsException"]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "EnrichFailed"
          ResultPath  = "$.error"
        }]
        ResultPath = "$.enriched"
        Next       = "NotifySOC"
      }

      NotifySOC = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Send HIGH severity alert to security team via SNS"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException"]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 1.5
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "NotifyFailed"
          ResultPath  = "$.error"
        }]
        ResultPath = "$.notification"
        Next       = "RemediateIAM"
      }

      RemediateIAM = {
        Type     = "Task"
        Resource = var.iam_remediation_lambda_arn
        Comment  = "Disable access keys, attach DenyAll inline policy, tag user QUARANTINE"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
          IntervalSeconds = 5
          MaxAttempts     = 2
          BackoffRate     = 2
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "RemediationFailed"
          ResultPath  = "$.error"
        }]
        ResultPath = "$.remediation"
        Next       = "CheckRemediationSuccess"
      }

      CheckRemediationSuccess = {
        Type    = "Choice"
        Comment = "Branch on remediation outcome — success to audit, failure to escalation"
        Choices = [{
          Variable     = "$.remediation.status"
          StringEquals = "SUCCESS"
          Next         = "WriteAuditArtifact"
        }]
        Default = "RemediationFailed"
      }

      WriteAuditArtifact = {
        Type     = "Task"
        Resource = var.write_audit_lambda_arn
        Comment  = "Write compliance evidence artifact to S3 — satisfies SOC2 CC4.1, FedRAMP AU-2"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException"]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2
        }]
        ResultPath = "$.audit"
        Next       = "PlaybookSucceeded"
      }

      PlaybookSucceeded = {
        Type    = "Succeed"
        Comment = "IAM credential compromise playbook completed successfully"
      }

      EnrichFailed = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Enrichment failed — notify SOC for manual investigation"
        Parameters = {
          "finding.$"     = "$.finding"
          "error.$"       = "$.error"
          "alert_type"    = "ENRICHMENT_FAILED"
          "severity"      = "HIGH"
          "manual_action" = "Review finding in Security Hub — automated enrichment failed"
        }
        Next = "PlaybookFailed"
      }

      NotifyFailed = {
        Type     = "Task"
        Resource = var.write_audit_lambda_arn
        Comment  = "Notification failed — write failure artifact and continue to remediation"
        Parameters = {
          "finding.$"  = "$.finding"
          "error.$"    = "$.error"
          "event_type" = "NOTIFICATION_FAILURE"
        }
        Next = "RemediateIAM"
      }

      RemediationFailed = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Automated remediation failed — escalate to SOC for manual action"
        Parameters = {
          "finding.$"     = "$.finding"
          "error.$"       = "$.error"
          "alert_type"    = "REMEDIATION_FAILED"
          "severity"      = "CRITICAL"
          "manual_action" = "URGENT: Automated IAM remediation failed. Manually disable credentials for affected user."
        }
        ResultPath = "$.escalation"
        Next       = "WriteAuditArtifact"
      }

      PlaybookFailed = {
        Type  = "Fail"
        Error = "PlaybookExecutionFailed"
        Cause = "SOAR playbook failed — see execution history for details"
      }
    }
  })

  # ─── EC2 ISOLATION PLAYBOOK ────────────────────────────────────────────────
  # Playbook: Backdoor:EC2/C&CActivity.B or Trojan:EC2/BlackholeTraffic
  # Flow: Enrich → Notify → Snapshot+Isolate → Choice → Audit

  ec2_playbook_asl = jsonencode({
    Comment = "SOAR Playbook: EC2 Instance Isolation — Malware / C2 Activity"
    StartAt = "EnrichFinding"
    States = {
      EnrichFinding = {
        Type     = "Task"
        Resource = var.enrich_finding_lambda_arn
        Comment  = "Enrich finding with EC2 instance metadata, VPC, attached SGs, running processes"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "EnrichFailed"
          ResultPath  = "$.error"
        }]
        ResultPath = "$.enriched"
        Next       = "NotifySOC"
      }

      NotifySOC = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Alert SOC — include instance ID, VPC, finding type, and proposed isolation action"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException"]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 1.5
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          ResultPath  = "$.notify_error"
          Next        = "IsolateEC2"
        }]
        ResultPath = "$.notification"
        Next       = "IsolateEC2"
      }

      IsolateEC2 = {
        Type     = "Task"
        Resource = var.ec2_isolation_lambda_arn
        Comment  = "1) Tag instance QUARANTINE_PENDING  2) Snapshot EBS volumes  3) Replace SG with deny-all quarantine group"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
          IntervalSeconds = 10
          MaxAttempts     = 2
          BackoffRate     = 2
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "IsolationFailed"
          ResultPath  = "$.error"
        }]
        ResultPath = "$.isolation"
        Next       = "CheckIsolationSuccess"
      }

      CheckIsolationSuccess = {
        Type    = "Choice"
        Comment = "Verify all isolation steps completed — snapshot + SG replacement required"
        Choices = [{
          And = [
            { Variable = "$.isolation.snapshot_created", BooleanEquals = true },
            { Variable = "$.isolation.sg_replaced", BooleanEquals = true }
          ]
          Next = "WriteAuditArtifact"
        }]
        Default = "IsolationPartial"
      }

      IsolationPartial = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Partial isolation — some steps failed. Notify SOC for manual completion."
        Parameters = {
          "finding.$"     = "$.finding"
          "isolation.$"   = "$.isolation"
          "alert_type"    = "ISOLATION_PARTIAL"
          "severity"      = "CRITICAL"
          "manual_action" = "Review EC2 isolation steps — snapshot or SG replacement may be incomplete."
        }
        ResultPath = "$.escalation"
        Next       = "WriteAuditArtifact"
      }

      WriteAuditArtifact = {
        Type     = "Task"
        Resource = var.write_audit_lambda_arn
        Comment  = "Write forensic preservation evidence to S3 — snapshot IDs, SG changes, timeline"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException"]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2
        }]
        ResultPath = "$.audit"
        Next       = "PlaybookSucceeded"
      }

      PlaybookSucceeded = {
        Type    = "Succeed"
        Comment = "EC2 isolation playbook completed — instance quarantined, evidence preserved"
      }

      EnrichFailed = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Enrichment failed — alert SOC with raw finding for manual triage"
        Parameters = {
          "finding.$"     = "$.finding"
          "error.$"       = "$.error"
          "alert_type"    = "ENRICHMENT_FAILED"
          "severity"      = "HIGH"
          "manual_action" = "Manually review EC2 instance in GuardDuty console — automated enrichment failed."
        }
        Next = "PlaybookFailed"
      }

      IsolationFailed = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Full isolation failed — CRITICAL escalation, instance still exposed"
        Parameters = {
          "finding.$"     = "$.finding"
          "error.$"       = "$.error"
          "alert_type"    = "ISOLATION_FAILED"
          "severity"      = "CRITICAL"
          "manual_action" = "URGENT: Automated EC2 isolation failed. Manually isolate instance immediately."
        }
        ResultPath = "$.escalation"
        Next       = "WriteAuditArtifact"
      }

      PlaybookFailed = {
        Type  = "Fail"
        Error = "PlaybookExecutionFailed"
        Cause = "EC2 isolation playbook failed — see execution history for details"
      }
    }
  })
}

# ─── IAM EXECUTION ROLE FOR STATE MACHINES ────────────────────────────────────

resource "aws_iam_role" "step_functions" {
  name = "${var.name_prefix}-sfn-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "step_functions" {
  name = "${var.name_prefix}-sfn-execution-policy"
  role = aws_iam_role.step_functions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeLambdaFunctions"
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [
          var.enrich_finding_lambda_arn,
          var.notify_soc_lambda_arn,
          var.iam_remediation_lambda_arn,
          var.ec2_isolation_lambda_arn,
          var.write_audit_lambda_arn
        ]
      },
      {
        Sid    = "WriteExecutionLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "WriteXRayTraces"
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets"
        ]
        Resource = "*"
      }
    ]
  })
}

# ─── IAM ROLE FOR EVENTBRIDGE → STEP FUNCTIONS ────────────────────────────────

resource "aws_iam_role" "eventbridge_invoke_sfn" {
  name = "${var.name_prefix}-eventbridge-sfn-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge_invoke_sfn" {
  name = "${var.name_prefix}-eventbridge-sfn-policy"
  role = aws_iam_role.eventbridge_invoke_sfn.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "StartStateMachineExecution"
      Effect = "Allow"
      Action = ["states:StartExecution"]
      Resource = [
        aws_sfn_state_machine.iam_playbook.arn,
        aws_sfn_state_machine.ec2_playbook.arn
      ]
    }]
  })
}

# ─── STATE MACHINES ───────────────────────────────────────────────────────────

resource "aws_sfn_state_machine" "iam_playbook" {
  name       = "${var.name_prefix}-iam-credential-compromise"
  role_arn   = aws_iam_role.step_functions.arn
  definition = local.iam_playbook_asl

  logging_configuration {
    log_destination        = "${var.cloudwatch_log_group_arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tracing_configuration {
    enabled = true
  }

  tags = { Name = "${var.name_prefix}-iam-playbook" }
}

resource "aws_sfn_state_machine" "ec2_playbook" {
  name       = "${var.name_prefix}-ec2-isolation"
  role_arn   = aws_iam_role.step_functions.arn
  definition = local.ec2_playbook_asl

  logging_configuration {
    log_destination        = "${var.cloudwatch_log_group_arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tracing_configuration {
    enabled = true
  }

  tags = { Name = "${var.name_prefix}-ec2-playbook" }
}
