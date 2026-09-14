data "aws_caller_identity" "current" {}

data "aws_region" "current" {}


# ─── IAM CREDENTIAL COMPROMISE PLAYBOOK ──────────────────────────────────────
#
# Flow:
# Enrich → Notify → Remediate → Evaluate → Audit
#
# Failure paths:
# - Enrichment failure → SOC escalation → Fail
# - Notification failure → record failure → continue remediation
# - Remediation failure/partial result → SOC escalation → Audit
# ─────────────────────────────────────────────────────────────────────────────

locals {
  iam_playbook_asl = jsonencode({
    Comment = "SOAR Playbook: IAM Credential Compromise Response"
    StartAt = "EnrichFinding"

    States = {

      EnrichFinding = {
        Type     = "Task"
        Resource = var.enrich_finding_lambda_arn
        Comment  = "Enrich finding with IAM user context including access keys, policies, and login profile"

        Retry = [{
          ErrorEquals = [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.TooManyRequestsException"
          ]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2
        }]

        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "EnrichFailed"
          ResultPath  = "$.error"
        }]

        Next = "NotifySOC"
      }


      NotifySOC = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Notify the security team with finding and enrichment context"

        Retry = [{
          ErrorEquals = [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.TooManyRequestsException"
          ]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 1.5
        }]

        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "NotifyFailed"
          ResultPath  = "$.notification_error"
        }]

        Next = "RemediateIAM"
      }


      RemediateIAM = {
        Type     = "Task"
        Resource = var.iam_remediation_lambda_arn
        Comment  = "Disable active access keys, apply emergency explicit-deny policy, and tag the IAM user for quarantine"

        Retry = [{
          ErrorEquals = [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.TooManyRequestsException"
          ]
          IntervalSeconds = 5
          MaxAttempts     = 2
          BackoffRate     = 2
        }]

        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "RemediationFailed"
          ResultPath  = "$.error"
        }]

        Next = "CheckRemediationStatus"
      }


      CheckRemediationStatus = {
        Type    = "Choice"
        Comment = "Evaluate the IAM remediation result"

        Choices = [
          {
            Variable     = "$.remediation.status"
            StringEquals = "SUCCESS"
            Next         = "WriteAuditArtifact"
          },
          {
            Variable     = "$.remediation.status"
            StringEquals = "PARTIAL"
            Next         = "RemediationPartial"
          }
        ]

        Default = "RemediationFailed"
      }


      RemediationPartial = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "IAM remediation completed only partially and requires analyst review"

        Parameters = {
          "playbook.$"    = "$.playbook"
          "finding.$"     = "$.finding"
          "enriched.$"    = "$.enriched"
          "remediation.$" = "$.remediation"

          "alert_type" = "REMEDIATION_PARTIAL"
          "severity"   = "CRITICAL"

          "manual_action" = "Review IAM remediation results and manually complete any remaining containment actions."
        }

        ResultPath = "$.escalation"

        Next = "WriteAuditArtifact"
      }


      WriteAuditArtifact = {
        Type     = "Task"
        Resource = var.write_audit_lambda_arn
        Comment  = "Write structured playbook execution artifact to S3 for incident review and audit evidence"

        Retry = [{
          ErrorEquals = [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.TooManyRequestsException"
          ]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2
        }]

        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "AuditWriteFailed"
          ResultPath  = "$.audit_error"
        }]

        Next = "PlaybookSucceeded"
      }


      EnrichFailed = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Automated enrichment failed; notify SOC for manual investigation"

        Parameters = {
          "playbook.$" = "$.playbook"
          "finding.$"  = "$.finding"
          "error.$"    = "$.error"

          "alert_type" = "ENRICHMENT_FAILED"
          "severity"   = "HIGH"

          "manual_action" = "Review the finding in Security Hub because automated IAM enrichment failed."
        }

        Next = "PlaybookFailed"
      }


      NotifyFailed = {
        Type     = "Task"
        Resource = var.write_audit_lambda_arn
        Comment  = "SOC notification failed; record available execution context before continuing remediation"

        Retry = [{
          ErrorEquals = [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException"
          ]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 2
        }]

        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "RemediateIAM"
          ResultPath  = "$.audit_error"
        }]

        Next = "RemediateIAM"
      }


      RemediationFailed = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Automated IAM remediation failed; escalate to SOC for manual containment"

        Parameters = {
          "playbook.$" = "$.playbook"
          "finding.$"  = "$.finding"
          "error.$"    = "$.error"

          "alert_type" = "REMEDIATION_FAILED"
          "severity"   = "CRITICAL"

          "manual_action" = "URGENT: Automated IAM remediation failed. Manually disable or contain credentials for the affected IAM user."
        }

        ResultPath = "$.escalation"

        Next = "WriteAuditArtifact"
      }


      AuditWriteFailed = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Audit artifact creation failed; notify SOC that execution evidence requires manual review"

        Parameters = {
          "playbook.$"    = "$.playbook"
          "finding.$"     = "$.finding"
          "audit_error.$" = "$.audit_error"

          "alert_type" = "AUDIT_WRITE_FAILED"
          "severity"   = "HIGH"

          "manual_action" = "Review Step Functions and CloudWatch execution history because the S3 audit artifact could not be written."
        }

        Next = "PlaybookFailed"
      }


      PlaybookSucceeded = {
        Type    = "Succeed"
        Comment = "IAM credential compromise response workflow completed"
      }


      PlaybookFailed = {
        Type  = "Fail"
        Error = "PlaybookExecutionFailed"
        Cause = "IAM credential compromise workflow requires manual review; see execution history for details"
      }
    }
  })


  # ─── EC2 ISOLATION PLAYBOOK ────────────────────────────────────────────────
  #
  # Flow:
  # Enrich → Notify → Initiate snapshots and restrict network access
  # → Evaluate → Audit
  #
  # Failure paths:
  # - Enrichment failure → SOC escalation → Fail
  # - Notification failure → continue containment
  # - Partial isolation → SOC escalation → Audit
  # - Isolation exception → SOC escalation → Audit
  # ──────────────────────────────────────────────────────────────────────────

  ec2_playbook_asl = jsonencode({
    Comment = "SOAR Playbook: EC2 Instance Isolation for Malware or Command-and-Control Activity"
    StartAt = "EnrichFinding"

    States = {

      EnrichFinding = {
        Type     = "Task"
        Resource = var.enrich_finding_lambda_arn
        Comment  = "Enrich finding with EC2 metadata, VPC, security groups, IAM profile, and EBS volume context"

        Retry = [{
          ErrorEquals = [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.TooManyRequestsException"
          ]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2
        }]

        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "EnrichFailed"
          ResultPath  = "$.error"
        }]

        Next = "NotifySOC"
      }


      NotifySOC = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Notify SOC with instance context and proposed containment action"

        Retry = [{
          ErrorEquals = [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.TooManyRequestsException"
          ]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 1.5
        }]

        Catch = [{
          ErrorEquals = ["States.ALL"]
          ResultPath  = "$.notification_error"
          Next        = "IsolateEC2"
        }]

        Next = "IsolateEC2"
      }


      IsolateEC2 = {
        Type     = "Task"
        Resource = var.ec2_isolation_lambda_arn
        Comment  = "Tag instance for quarantine, initiate EBS snapshots, and replace security groups with a restrictive quarantine group"

        Retry = [{
          ErrorEquals = [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.TooManyRequestsException"
          ]
          IntervalSeconds = 10
          MaxAttempts     = 2
          BackoffRate     = 2
        }]

        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "IsolationFailed"
          ResultPath  = "$.error"
        }]

        Next = "CheckIsolationStatus"
      }


      CheckIsolationStatus = {
        Type    = "Choice"
        Comment = "Evaluate the overall EC2 containment result returned by the isolation function"

        Choices = [
          {
            Variable     = "$.isolation.status"
            StringEquals = "SUCCESS"
            Next         = "WriteAuditArtifact"
          },
          {
            Variable     = "$.isolation.status"
            StringEquals = "PARTIAL"
            Next         = "IsolationPartial"
          }
        ]

        Default = "IsolationFailed"
      }


      IsolationPartial = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "EC2 containment completed only partially; notify SOC for manual completion"

        Parameters = {
          "playbook.$"  = "$.playbook"
          "finding.$"   = "$.finding"
          "enriched.$"  = "$.enriched"
          "isolation.$" = "$.isolation"

          "alert_type" = "ISOLATION_PARTIAL"
          "severity"   = "CRITICAL"

          "manual_action" = "Review EC2 containment results and manually complete any remaining isolation or investigation steps."
        }

        ResultPath = "$.escalation"

        Next = "WriteAuditArtifact"
      }


      WriteAuditArtifact = {
        Type     = "Task"
        Resource = var.write_audit_lambda_arn
        Comment  = "Write structured EC2 response artifact to S3 including containment actions and snapshot identifiers"

        Retry = [{
          ErrorEquals = [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.TooManyRequestsException"
          ]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2
        }]

        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "AuditWriteFailed"
          ResultPath  = "$.audit_error"
        }]

        Next = "PlaybookSucceeded"
      }


      EnrichFailed = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Automated EC2 enrichment failed; notify SOC using available finding context"

        Parameters = {
          "playbook.$" = "$.playbook"
          "finding.$"  = "$.finding"
          "error.$"    = "$.error"

          "alert_type" = "ENRICHMENT_FAILED"
          "severity"   = "HIGH"

          "manual_action" = "Review the affected EC2 resource and GuardDuty finding because automated enrichment failed."
        }

        Next = "PlaybookFailed"
      }


      IsolationFailed = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Automated EC2 containment failed; escalate immediately for manual isolation"

        Parameters = {
          "playbook.$" = "$.playbook"
          "finding.$"  = "$.finding"
          "error.$"    = "$.error"

          "alert_type" = "ISOLATION_FAILED"
          "severity"   = "CRITICAL"

          "manual_action" = "URGENT: Automated EC2 containment failed. Manually isolate the affected instance and review attached resources."
        }

        ResultPath = "$.escalation"

        Next = "WriteAuditArtifact"
      }


      AuditWriteFailed = {
        Type     = "Task"
        Resource = var.notify_soc_lambda_arn
        Comment  = "Audit artifact creation failed; notify SOC that execution evidence requires manual review"

        Parameters = {
          "playbook.$"    = "$.playbook"
          "finding.$"     = "$.finding"
          "audit_error.$" = "$.audit_error"

          "alert_type" = "AUDIT_WRITE_FAILED"
          "severity"   = "HIGH"

          "manual_action" = "Review Step Functions and CloudWatch execution history because the S3 audit artifact could not be written."
        }

        Next = "PlaybookFailed"
      }


      PlaybookSucceeded = {
        Type    = "Succeed"
        Comment = "EC2 containment workflow completed and execution context recorded"
      }


      PlaybookFailed = {
        Type  = "Fail"
        Error = "PlaybookExecutionFailed"
        Cause = "EC2 containment workflow requires manual review; see execution history for details"
      }
    }
  })
}


# ─── IAM EXECUTION ROLE FOR STEP FUNCTIONS ────────────────────────────────────

resource "aws_iam_role" "step_functions" {
  name = "${var.name_prefix}-sfn-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"

      Principal = {
        Service = "states.amazonaws.com"
      }
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

        Action = [
          "lambda:InvokeFunction"
        ]

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
      Action = "sts:AssumeRole"
      Effect = "Allow"

      Principal = {
        Service = "events.amazonaws.com"
      }
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

      Action = [
        "states:StartExecution"
      ]

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

  tags = {
    Name = "${var.name_prefix}-iam-playbook"
  }
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

  tags = {
    Name = "${var.name_prefix}-ec2-playbook"
  }
}
