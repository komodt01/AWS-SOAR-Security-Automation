"""
write_audit — SOAR Playbook Final Step

Writes a structured execution artifact to S3.

The artifact captures:
  - Original finding details
  - Enrichment results
  - Remediation or isolation actions
  - Notification and escalation context
  - Playbook outcome
  - Lambda execution metadata

The resulting artifact can support incident review, auditability,
operational analysis, and compliance evidence collection within a
broader control environment.

Artifact path:
s3://<bucket>/playbook-artifacts/<playbook>/<date>/<finding-id>.json
"""

import boto3
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

s3_client = boto3.client("s3")
AUDIT_BUCKET = os.environ["AUDIT_BUCKET"]


def lambda_handler(event: dict, context) -> dict:
    playbook = event.get("playbook", "unknown")
    finding = event.get("finding", {})
    finding_id = finding.get("id", "unknown-finding")

    logger.info(
        "write_audit invoked | playbook=%s finding_id=%s",
        playbook,
        finding_id,
    )

    artifact = build_artifact(
        event,
        context,
    )

    now = datetime.now(
        timezone.utc
    )

    date_prefix = now.strftime(
        "%Y/%m/%d"
    )

    safe_id = (
        finding_id
        .replace(":", "_")
        .replace("/", "_")
        .replace(" ", "_")
    )

    s3_key = (
        f"playbook-artifacts/"
        f"{playbook}/"
        f"{date_prefix}/"
        f"{safe_id}.json"
    )

    try:
        s3_client.put_object(
            Bucket=AUDIT_BUCKET,
            Key=s3_key,
            Body=json.dumps(
                artifact,
                indent=2,
                default=str,
            ),
            ContentType="application/json",
            ServerSideEncryption="AES256",
            Metadata={
                "playbook": playbook,
                "severity": finding.get(
                    "severity",
                    "UNKNOWN",
                ),
                "finding-id": safe_id[:256],
                "timestamp": now.isoformat(),
            },
        )

        artifact_uri = (
            f"s3://{AUDIT_BUCKET}/{s3_key}"
        )

        logger.info(
            "Audit artifact written | uri=%s",
            artifact_uri,
        )

        return {
            **event,
            "audit": {
                "status": "SUCCESS",
                "artifact_uri": artifact_uri,
                "s3_bucket": AUDIT_BUCKET,
                "s3_key": s3_key,
                "timestamp": now.isoformat(),
            },
        }

    except Exception as exc:
        logger.error(
            "Failed to write audit artifact: %s",
            exc,
            exc_info=True,
        )
        raise


def build_artifact(
    event: dict,
    context,
) -> dict:
    """
    Assemble the structured playbook execution artifact.

    The artifact is intended to support incident review,
    auditability, operational analysis, and downstream ingestion.
    """
    now = datetime.now(
        timezone.utc
    )

    finding = event.get(
        "finding",
        {},
    )

    enriched = event.get(
        "enriched",
        {},
    )

    remediation_block = event.get(
        "remediation",
        event.get(
            "isolation",
            {},
        ),
    )

    outcome = _determine_outcome(
        remediation_block,
        event,
    )

    return {
        "schema_version": "1.0",
        "artifact_type": "SOAR_PLAYBOOK_EXECUTION",
        "generated_at": now.isoformat(),
        "generated_by": "aws-soar-security-automation",

        "playbook": {
            "name": event.get(
                "playbook",
                "unknown",
            ),
            "outcome": outcome,
        },

        "finding": {
            "id": finding.get("id"),
            "type": finding.get(
                "finding_type"
            ),
            "title": finding.get(
                "title"
            ),
            "description": finding.get(
                "description"
            ),
            "severity": finding.get(
                "severity"
            ),
            "account_id": finding.get(
                "account_id"
            ),
            "region": finding.get(
                "region"
            ),
            "resource_id": (
                finding.get("resource_id")
                or finding.get("instance_id")
            ),
            "updated_at": finding.get(
                "updated_at"
            ),
        },

        "enrichment": enriched,

        "response": remediation_block,

        "notification": event.get(
            "notification",
            {},
        ),

        "escalation": event.get(
            "escalation",
            {},
        ),

        "evidence_context": {
            "purpose": (
                "Preserve structured execution context "
                "for incident review, auditability, "
                "and compliance evidence collection."
            ),
            "retention_note": (
                "Retention should follow organizational "
                "security, legal, and records-management policy."
            ),
        },

        "lambda_context": {
            "function_name": getattr(
                context,
                "function_name",
                None,
            ),
            "function_version": getattr(
                context,
                "function_version",
                None,
            ),
            "request_id": getattr(
                context,
                "aws_request_id",
                None,
            ),
            "log_group": getattr(
                context,
                "log_group_name",
                None,
            ),
            "log_stream": getattr(
                context,
                "log_stream_name",
                None,
            ),
        },
    }


def _determine_outcome(
    response_block: dict,
    event: dict,
) -> str:
    """
    Derive a high-level playbook outcome from the response status.
    """
    status = response_block.get(
        "status",
        "",
    )

    if status == "SUCCESS":
        return "SUCCESS"

    if status == "PARTIAL":
        return "PARTIAL"

    if status == "FAILED":
        return "ESCALATED"

    if event.get("escalation"):
        return "ESCALATED"

    return "UNKNOWN"
