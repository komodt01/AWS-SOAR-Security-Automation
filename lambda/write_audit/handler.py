"""
write_audit — SOAR Playbook Final Step
Writes a structured compliance evidence artifact to S3.

The artifact captures the full execution context:
  - Original finding details
  - Enrichment results
  - All remediation/isolation actions taken
  - Timeline and status

This satisfies evidence requirements for:
  SOC 2    : CC4.1 (monitoring activities), CC5.3 (change management)
  FedRAMP  : AU-2 (audit events), AU-9 (protection of audit info)
  ISO 27001: A.12.4.1 (event logging), A.16.1.7 (evidence collection)

Artifact path: s3://<bucket>/playbook-artifacts/<playbook>/<date>/<finding-id>.json
"""

import boto3
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

s3_client    = boto3.client("s3")
AUDIT_BUCKET = os.environ["AUDIT_BUCKET"]


def lambda_handler(event: dict, context) -> dict:
    playbook   = event.get("playbook", "unknown")
    finding    = event.get("finding", {})
    finding_id = finding.get("id", "unknown-finding")

    logger.info("write_audit invoked | playbook=%s finding_id=%s", playbook, finding_id)

    # Build the compliance evidence artifact
    artifact = build_artifact(event, context)

    # Construct S3 key with date partitioning for easy querying
    now     = datetime.now(timezone.utc)
    date_prefix = now.strftime("%Y/%m/%d")
    # Sanitize finding_id for S3 key (remove colons and slashes)
    safe_id = finding_id.replace(":", "_").replace("/", "_").replace(" ", "_")
    s3_key  = f"playbook-artifacts/{playbook}/{date_prefix}/{safe_id}.json"

    try:
        s3_client.put_object(
            Bucket=AUDIT_BUCKET,
            Key=s3_key,
            Body=json.dumps(artifact, indent=2, default=str),
            ContentType="application/json",
            ServerSideEncryption="AES256",
            Metadata={
                "playbook":   playbook,
                "severity":   finding.get("severity", "UNKNOWN"),
                "finding-id": safe_id[:256],  # metadata value max 256 chars
                "timestamp":  now.isoformat(),
            },
        )

        artifact_uri = f"s3://{AUDIT_BUCKET}/{s3_key}"
        logger.info("Audit artifact written | uri=%s", artifact_uri)

        return {
            **event,
            "audit": {
                "status":       "SUCCESS",
                "artifact_uri": artifact_uri,
                "s3_bucket":    AUDIT_BUCKET,
                "s3_key":       s3_key,
                "timestamp":    now.isoformat(),
            },
        }

    except Exception as exc:
        logger.error("Failed to write audit artifact: %s", exc, exc_info=True)
        raise


def build_artifact(event: dict, context) -> dict:
    """
    Assembles the full compliance evidence document.
    Structured for readability by auditors and SIEM ingestion.
    """
    now      = datetime.now(timezone.utc)
    finding  = event.get("finding", {})
    enriched = event.get("enriched", {})

    # Collect all remediation/isolation actions from whichever playbook ran
    remediation_block = event.get("remediation", event.get("isolation", {}))

    # Determine overall playbook outcome
    outcome = "UNKNOWN"
    if event.get("audit") is None:  # not yet set
        rem_status = remediation_block.get("status", "")
        if rem_status == "SUCCESS":
            outcome = "REMEDIATED"
        elif rem_status == "PARTIAL":
            outcome = "PARTIALLY_REMEDIATED"
        elif rem_status == "FAILED":
            outcome = "ESCALATED"
        elif event.get("escalation"):
            outcome = "ESCALATED"

    return {
        "schema_version": "1.0",
        "artifact_type":  "SOAR_PLAYBOOK_EXECUTION",
        "generated_at":   now.isoformat(),
        "generated_by":   "aws-soar-security-automation",

        "playbook": {
            "name":    event.get("playbook", "unknown"),
            "outcome": outcome,
        },

        "finding": {
            "id":           finding.get("id"),
            "type":         finding.get("finding_type"),
            "title":        finding.get("title"),
            "description":  finding.get("description"),
            "severity":     finding.get("severity"),
            "account_id":   finding.get("account_id"),
            "region":       finding.get("region"),
            "resource_id":  finding.get("resource_id") or finding.get("instance_id"),
            "updated_at":   finding.get("updated_at"),
        },

        "enrichment": enriched,

        "remediation": remediation_block,

        "notifications": event.get("notification", {}),
        "escalation":    event.get("escalation", {}),

        "compliance_evidence": {
            "soc2_controls":    ["CC6.1", "CC6.8", "CC7.2", "CC7.3", "CC4.1", "CC5.3"],
            "fedramp_controls": ["AC-2", "AC-2(3)", "AC-12", "AU-2", "AU-9", "IR-4"],
            "iso_controls":     ["A.9.4.1", "A.12.4.1", "A.16.1.5", "A.16.1.7"],
            "artifact_note":    (
                "This artifact constitutes automated evidence of security incident "
                "detection and response. Retain per organizational data retention policy."
            ),
        },

        "lambda_context": {
            "function_name":    context.function_name,
            "function_version": context.function_version,
            "request_id":       context.aws_request_id,
            "log_group":        context.log_group_name,
            "log_stream":       context.log_stream_name,
        },
    }
