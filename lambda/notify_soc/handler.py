"""
notify_soc — SOAR Playbook Step 2

Publishes structured security notifications to the configured SNS topic.

The function formats finding and enrichment context into a
human-readable alert containing severity, resource details, and
response context. It can also publish escalation notifications when
upstream workflow steps identify a condition requiring analyst action.
"""

import boto3
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

sns_client = boto3.client("sns")
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

SEVERITY_PREFIX = {
    "CRITICAL": "[CRITICAL]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]",
}


def lambda_handler(event: dict, context) -> dict:
    logger.info(
        "notify_soc invoked | playbook=%s alert_type=%s",
        event.get("playbook"),
        event.get("alert_type", "FINDING_DETECTED"),
    )

    finding = event.get("finding", {})
    enriched = event.get("enriched", {})
    alert_type = event.get("alert_type", "FINDING_DETECTED")
    severity = event.get("severity") or finding.get("severity", "HIGH")

    subject = build_subject(
        severity,
        alert_type,
        finding,
    )

    message = build_message(
        event,
        finding,
        enriched,
        alert_type,
        severity,
    )

    try:
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=message,
            MessageAttributes={
                "severity": {
                    "DataType": "String",
                    "StringValue": severity,
                },
                "playbook": {
                    "DataType": "String",
                    "StringValue": event.get(
                        "playbook",
                        "unknown",
                    ),
                },
                "alert_type": {
                    "DataType": "String",
                    "StringValue": alert_type,
                },
            },
        )

        message_id = response["MessageId"]

        logger.info(
            "SNS alert published | message_id=%s severity=%s",
            message_id,
            severity,
        )

        return {
            **event,
            "notification": {
                "status": "SENT",
                "message_id": message_id,
                "topic_arn": SNS_TOPIC_ARN,
                "alert_type": alert_type,
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
            },
        }

    except Exception as exc:
        logger.error(
            "SNS publish failed: %s",
            exc,
            exc_info=True,
        )
        raise


def build_subject(
    severity: str,
    alert_type: str,
    finding: dict,
) -> str:
    prefix = SEVERITY_PREFIX.get(
        severity,
        f"[{severity}]",
    )

    title = finding.get(
        "title",
        "Security Finding Detected",
    )

    return (
        f"{prefix} SOAR Alert: "
        f"{alert_type} — {title}"
    )


def build_message(
    event: dict,
    finding: dict,
    enriched: dict,
    alert_type: str,
    severity: str,
) -> str:
    now = datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "=" * 70,
        f"  SOAR SECURITY ALERT — {alert_type}",
        "=" * 70,
        "",
        f"  Timestamp  : {now}",
        f"  Severity   : {severity}",
        f"  Playbook   : {event.get('playbook', 'N/A')}",
        f"  Account    : {finding.get('account_id', 'N/A')}",
        f"  Region     : {finding.get('region', 'N/A')}",
        "",
        "  FINDING DETAILS",
        "  " + "-" * 50,
        f"  Finding ID : {finding.get('id', 'N/A')}",
        f"  Type       : {finding.get('finding_type', 'N/A')}",
        f"  Title      : {finding.get('title', 'N/A')}",
        f"  Description: {finding.get('description', 'N/A')}",
        "",
    ]

    resource_type = enriched.get(
        "resource_type",
        "",
    )

    if resource_type == "IAM_USER":
        lines += [
            "  IAM RESOURCE CONTEXT",
            "  " + "-" * 50,
            f"  Username         : {enriched.get('username', 'N/A')}",
            f"  User ARN         : {enriched.get('user_arn', 'N/A')}",
            f"  Active Keys      : {enriched.get('active_key_count', 'N/A')}",
            f"  Console Access   : {enriched.get('has_console_access', 'N/A')}",
            (
                "  Managed Policies : "
                f"{len(enriched.get('managed_policies', []))}"
            ),
            "",
        ]

    elif resource_type == "EC2_INSTANCE":
        lines += [
            "  EC2 RESOURCE CONTEXT",
            "  " + "-" * 50,
            f"  Instance ID      : {enriched.get('instance_id', 'N/A')}",
            f"  Instance Type    : {enriched.get('instance_type', 'N/A')}",
            f"  State            : {enriched.get('state', 'N/A')}",
            f"  VPC              : {enriched.get('vpc_id', 'N/A')}",
            f"  Private IP       : {enriched.get('private_ip', 'N/A')}",
            f"  Public IP        : {enriched.get('public_ip', 'N/A')}",
            (
                "  EBS Volumes      : "
                f"{len(enriched.get('ebs_volumes', []))}"
            ),
            "",
        ]

    manual_action = event.get(
        "manual_action"
    )

    if manual_action:
        lines += [
            "  MANUAL ACTION REQUIRED",
            "  " + "-" * 50,
            f"  {manual_action}",
            "",
        ]

    lines += [
        "  RESPONSE LINKS",
        "  " + "-" * 50,
        "  Security Hub  : https://console.aws.amazon.com/securityhub/home",
        "  Step Functions: https://console.aws.amazon.com/states/home",
        "  GuardDuty     : https://console.aws.amazon.com/guardduty/home",
        "",
        (
            "  This alert was generated automatically "
            "by the AWS SOAR pipeline."
        ),
        "=" * 70,
    ]

    return "\n".join(lines)
