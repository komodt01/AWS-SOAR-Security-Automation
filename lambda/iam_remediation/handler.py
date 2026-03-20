"""
iam_remediation — SOAR Playbook Step 3 (IAM Playbook)
Automated response to compromised IAM credentials.

Actions performed (in order):
  1. Disable all active access keys for the affected user
  2. Attach an inline DenyAll policy to block console and API access
  3. Tag the user as QUARANTINE for analyst tracking
  4. Return structured result for Step Functions Choice state

Compliance:
  SOC 2   : CC6.1 (logical access), CC6.8 (unauthorized access response)
  FedRAMP : AC-2(3) (disable inactive accounts), AC-12 (session termination)
  ISO 27001: A.9.4.1 (information access restriction)
"""

import boto3
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

iam_client = boto3.client("iam")

DENY_ALL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SOAREmergencyDenyAll",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": "*"
                }
            }
        }
    ]
}

QUARANTINE_TAG_KEY   = "SOARStatus"
QUARANTINE_TAG_VALUE = "QUARANTINE"


def lambda_handler(event: dict, context) -> dict:
    finding  = event.get("finding", {})
    enriched = event.get("enriched", {})
    username = enriched.get("username") or _extract_username(finding.get("resource_id", ""))

    logger.info("iam_remediation invoked | user=%s finding_id=%s",
                username, finding.get("id"))

    if not username:
        logger.error("Cannot remediate — no username found in enriched context")
        return {**event, "remediation": {"status": "FAILED", "reason": "No username extracted"}}

    results = {
        "username": username,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "finding_id": finding.get("id"),
        "actions": [],
        "status": "SUCCESS",
    }

    # ── Step 1: Disable all active access keys ────────────────────────────────
    try:
        keys_disabled = _disable_access_keys(username)
        results["actions"].append({
            "action": "DISABLE_ACCESS_KEYS",
            "status": "SUCCESS",
            "keys_disabled": keys_disabled,
        })
        logger.info("Disabled %d access key(s) for user=%s", keys_disabled, username)
    except Exception as exc:
        logger.error("Failed to disable access keys for %s: %s", username, exc)
        results["actions"].append({"action": "DISABLE_ACCESS_KEYS", "status": "FAILED", "error": str(exc)})
        results["status"] = "PARTIAL"

    # ── Step 2: Attach DenyAll inline policy ──────────────────────────────────
    try:
        _attach_deny_all_policy(username, finding.get("id", "unknown"))
        results["actions"].append({
            "action": "ATTACH_DENY_ALL_POLICY",
            "status": "SUCCESS",
            "policy_name": "SOAREmergencyDenyAll",
        })
        logger.info("DenyAll inline policy attached to user=%s", username)
    except Exception as exc:
        logger.error("Failed to attach DenyAll policy for %s: %s", username, exc)
        results["actions"].append({"action": "ATTACH_DENY_ALL_POLICY", "status": "FAILED", "error": str(exc)})
        results["status"] = "PARTIAL"

    # ── Step 3: Tag user as QUARANTINE ────────────────────────────────────────
    try:
        _tag_user_quarantine(username, finding.get("id", "unknown"), finding.get("severity", "HIGH"))
        results["actions"].append({
            "action": "TAG_USER_QUARANTINE",
            "status": "SUCCESS",
            "tag": f"{QUARANTINE_TAG_KEY}={QUARANTINE_TAG_VALUE}",
        })
        logger.info("Quarantine tag applied to user=%s", username)
    except Exception as exc:
        logger.error("Failed to tag user %s: %s", username, exc)
        results["actions"].append({"action": "TAG_USER_QUARANTINE", "status": "FAILED", "error": str(exc)})
        # Tagging failure doesn't degrade remediation status — keys and policy are more critical

    logger.info("IAM remediation complete | user=%s status=%s actions=%d",
                username, results["status"], len(results["actions"]))

    return {**event, "remediation": results}


def _disable_access_keys(username: str) -> int:
    """Disable all ACTIVE access keys. Returns count of keys disabled."""
    keys = iam_client.list_access_keys(UserName=username)["AccessKeyMetadata"]
    disabled = 0
    for key in keys:
        if key["Status"] == "Active":
            iam_client.update_access_key(
                UserName=username,
                AccessKeyId=key["AccessKeyId"],
                Status="Inactive",
            )
            disabled += 1
            logger.info("Disabled access key %s for user %s", key["AccessKeyId"], username)
    return disabled


def _attach_deny_all_policy(username: str, finding_id: str) -> None:
    """
    Attach an inline DenyAll policy. Inline policy chosen over managed policy
    so the restriction is user-specific and immediately visible in the IAM console.
    """
    iam_client.put_user_policy(
        UserName=username,
        PolicyName="SOAREmergencyDenyAll",
        PolicyDocument=json.dumps(DENY_ALL_POLICY),
    )


def _tag_user_quarantine(username: str, finding_id: str, severity: str) -> None:
    """Tag the IAM user for analyst tracking and audit trail."""
    iam_client.tag_user(
        UserName=username,
        Tags=[
            {"Key": QUARANTINE_TAG_KEY,         "Value": QUARANTINE_TAG_VALUE},
            {"Key": "SOARFindingId",             "Value": finding_id},
            {"Key": "SOARRemediationTimestamp",  "Value": datetime.now(timezone.utc).isoformat()},
            {"Key": "SOARSeverity",              "Value": severity},
            {"Key": "SOARReviewRequired",        "Value": "true"},
        ],
    )


def _extract_username(resource_id: str) -> str:
    """Extract IAM username from resource ARN: arn:aws:iam::123:user/username"""
    return resource_id.split("/")[-1] if "/" in resource_id else resource_id
