# ─── IAM CREDENTIAL COMPROMISE RULE ──────────────────────────────────────────
# Matches HIGH/CRITICAL GuardDuty IAM findings from Security Hub

resource "aws_cloudwatch_event_rule" "iam_playbook" {
  name        = "${var.name_prefix}-iam-credential-compromise"
  description = "Route HIGH/CRITICAL IAM GuardDuty findings to SOAR IAM playbook"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["HIGH", "CRITICAL"]
        }
        ProductName = ["GuardDuty"]
        Types = [{
          prefix = "TTPs/Initial Access/UnauthorizedAccess:IAMUser"
        }]
        RecordState   = ["ACTIVE"]
        WorkflowState = ["NEW"]
      }
    }
  })

  tags = { Name = "${var.name_prefix}-iam-rule" }
}

resource "aws_cloudwatch_event_target" "iam_playbook" {
  rule     = aws_cloudwatch_event_rule.iam_playbook.name
  arn      = var.iam_state_machine_arn
  role_arn = var.sfn_invoke_role_arn

  # Transform the Security Hub finding into a clean input for Step Functions
  input_transformer {
    input_paths = {
      findingId    = "$.detail.findings[0].Id"
      severity     = "$.detail.findings[0].Severity.Label"
      title        = "$.detail.findings[0].Title"
      description  = "$.detail.findings[0].Description"
      accountId    = "$.detail.findings[0].AwsAccountId"
      region       = "$.detail.findings[0].Region"
      resourceId   = "$.detail.findings[0].Resources[0].Id"
      resourceType = "$.detail.findings[0].Resources[0].Type"
      findingType  = "$.detail.findings[0].Types[0]"
      updatedAt    = "$.detail.findings[0].UpdatedAt"
    }
    input_template = <<-EOT
    {
      "playbook": "iam-credential-compromise",
      "finding": {
        "id": <findingId>,
        "severity": <severity>,
        "title": <title>,
        "description": <description>,
        "account_id": <accountId>,
        "region": <region>,
        "resource_id": <resourceId>,
        "resource_type": <resourceType>,
        "finding_type": <findingType>,
        "updated_at": <updatedAt>
      }
    }
    EOT
  }
}

# ─── EC2 ISOLATION RULE ───────────────────────────────────────────────────────
# Matches HIGH/CRITICAL GuardDuty EC2 backdoor/malware findings

resource "aws_cloudwatch_event_rule" "ec2_playbook" {
  name        = "${var.name_prefix}-ec2-malware-isolation"
  description = "Route HIGH/CRITICAL EC2 GuardDuty findings to SOAR EC2 isolation playbook"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["HIGH", "CRITICAL"]
        }
        ProductName = ["GuardDuty"]
        Types = [{
          prefix = "TTPs/Command and Control/Backdoor:EC2"
        }]
        RecordState   = ["ACTIVE"]
        WorkflowState = ["NEW"]
      }
    }
  })

  tags = { Name = "${var.name_prefix}-ec2-rule" }
}

resource "aws_cloudwatch_event_target" "ec2_playbook" {
  rule     = aws_cloudwatch_event_rule.ec2_playbook.name
  arn      = var.ec2_state_machine_arn
  role_arn = var.sfn_invoke_role_arn

  input_transformer {
    input_paths = {
      findingId    = "$.detail.findings[0].Id"
      severity     = "$.detail.findings[0].Severity.Label"
      title        = "$.detail.findings[0].Title"
      description  = "$.detail.findings[0].Description"
      accountId    = "$.detail.findings[0].AwsAccountId"
      region       = "$.detail.findings[0].Region"
      instanceId   = "$.detail.findings[0].Resources[0].Id"
      resourceType = "$.detail.findings[0].Resources[0].Type"
      findingType  = "$.detail.findings[0].Types[0]"
      updatedAt    = "$.detail.findings[0].UpdatedAt"
    }
    input_template = <<-EOT
    {
      "playbook": "ec2-isolation",
      "finding": {
        "id": <findingId>,
        "severity": <severity>,
        "title": <title>,
        "description": <description>,
        "account_id": <accountId>,
        "region": <region>,
        "instance_id": <instanceId>,
        "resource_type": <resourceType>,
        "finding_type": <findingType>,
        "updated_at": <updatedAt>
      }
    }
    EOT
  }
}
