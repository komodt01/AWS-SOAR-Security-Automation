resource "aws_sns_topic" "soc_alerts" {
  name              = "${var.name_prefix}-soc-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Name = "${var.name_prefix}-soc-alerts"
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.soc_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# SNS topic policy — allow Security Hub and EventBridge to publish
resource "aws_sns_topic_policy" "soc_alerts" {
  arn    = aws_sns_topic.soc_alerts.arn
  policy = data.aws_iam_policy_document.sns_policy.json
}

data "aws_iam_policy_document" "sns_policy" {
  statement {
    sid    = "AllowAccountPublish"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }
    actions   = ["SNS:Publish", "SNS:Subscribe", "SNS:ListSubscriptionsByTopic"]
    resources = [aws_sns_topic.soc_alerts.arn]
  }

  statement {
    sid    = "AllowLambdaPublish"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.soc_alerts.arn]
  }
}

data "aws_caller_identity" "current" {}
