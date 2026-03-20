"""
ec2_isolation — SOAR Playbook Step 3 (EC2 Playbook)
Automated response to EC2 backdoor / C2 / malware findings.

Actions performed:
  1. Tag instance as QUARANTINE_PENDING
  2. Create EBS snapshots of all attached volumes (forensic preservation)
  3. Create a deny-all quarantine security group (if not exists)
  4. Replace all instance security groups with the quarantine group
  5. Tag instance as QUARANTINE_COMPLETE

Returns structured result with snapshot IDs and SG change details
for the Step Functions Choice state to evaluate.

Compliance:
  SOC 2    : CC6.6 (network segmentation), CC7.2 (incident monitoring)
  FedRAMP  : IR-4 (incident handling), SC-7 (boundary protection)
  ISO 27001: A.16.1.5 (incident response), A.13.1.3 (network segregation)
"""

import boto3
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

ec2_client = boto3.client("ec2")

QUARANTINE_SG_NAME        = "soar-quarantine-deny-all"
QUARANTINE_SG_DESCRIPTION = "SOAR automated quarantine — deny all traffic — do not modify"


def lambda_handler(event: dict, context) -> dict:
    finding  = event.get("finding", {})
    enriched = event.get("enriched", {})

    instance_id = enriched.get("instance_id") or _extract_instance_id(finding.get("instance_id", ""))
    vpc_id      = enriched.get("vpc_id")
    volumes     = enriched.get("ebs_volumes", [])

    logger.info("ec2_isolation invoked | instance=%s vpc=%s volumes=%d",
                instance_id, vpc_id, len(volumes))

    if not instance_id:
        logger.error("Cannot isolate — no instance_id in enriched context")
        return {**event, "isolation": {"status": "FAILED", "reason": "No instance_id found"}}

    results = {
        "instance_id": instance_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "finding_id": finding.get("id"),
        "snapshot_created": False,
        "sg_replaced": False,
        "actions": [],
        "status": "IN_PROGRESS",
    }

    # ── Step 1: Tag instance QUARANTINE_PENDING ───────────────────────────────
    try:
        _tag_instance(instance_id, "QUARANTINE_PENDING", finding.get("id", "unknown"))
        results["actions"].append({"action": "TAG_QUARANTINE_PENDING", "status": "SUCCESS"})
        logger.info("Tagged instance=%s as QUARANTINE_PENDING", instance_id)
    except Exception as exc:
        logger.warning("Tagging failed (non-critical): %s", exc)
        results["actions"].append({"action": "TAG_QUARANTINE_PENDING", "status": "FAILED", "error": str(exc)})

    # ── Step 2: Snapshot all EBS volumes ─────────────────────────────────────
    snapshot_ids = []
    try:
        snapshot_ids = _snapshot_volumes(volumes, instance_id, finding.get("id", "unknown"))
        results["snapshot_ids"] = snapshot_ids
        results["snapshot_created"] = len(snapshot_ids) > 0
        results["actions"].append({
            "action": "SNAPSHOT_EBS_VOLUMES",
            "status": "SUCCESS",
            "snapshot_count": len(snapshot_ids),
            "snapshot_ids": snapshot_ids,
        })
        logger.info("Created %d snapshot(s) for instance=%s: %s",
                    len(snapshot_ids), instance_id, snapshot_ids)
    except Exception as exc:
        logger.error("EBS snapshot failed for instance=%s: %s", instance_id, exc)
        results["actions"].append({"action": "SNAPSHOT_EBS_VOLUMES", "status": "FAILED", "error": str(exc)})
        # Snapshot failure is serious but we should still attempt isolation

    # ── Step 3: Get or create quarantine security group ───────────────────────
    quarantine_sg_id = None
    try:
        quarantine_sg_id = _get_or_create_quarantine_sg(vpc_id)
        results["quarantine_sg_id"] = quarantine_sg_id
        results["actions"].append({
            "action": "GET_OR_CREATE_QUARANTINE_SG",
            "status": "SUCCESS",
            "sg_id": quarantine_sg_id,
        })
        logger.info("Quarantine SG ready: %s", quarantine_sg_id)
    except Exception as exc:
        logger.error("Failed to get/create quarantine SG: %s", exc)
        results["actions"].append({"action": "GET_OR_CREATE_QUARANTINE_SG", "status": "FAILED", "error": str(exc)})

    # ── Step 4: Replace instance security groups ──────────────────────────────
    if quarantine_sg_id:
        try:
            original_sgs = [sg["group_id"] for sg in enriched.get("current_security_groups", [])]
            ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[quarantine_sg_id],
            )
            results["original_security_groups"] = original_sgs
            results["sg_replaced"] = True
            results["actions"].append({
                "action": "REPLACE_SECURITY_GROUPS",
                "status": "SUCCESS",
                "original_sgs": original_sgs,
                "quarantine_sg": quarantine_sg_id,
            })
            logger.info("SG replaced for instance=%s | original=%s quarantine=%s",
                        instance_id, original_sgs, quarantine_sg_id)
        except Exception as exc:
            logger.error("SG replacement failed for instance=%s: %s", instance_id, exc)
            results["actions"].append({"action": "REPLACE_SECURITY_GROUPS", "status": "FAILED", "error": str(exc)})

    # ── Step 5: Final tagging ─────────────────────────────────────────────────
    final_tag = "QUARANTINE_COMPLETE" if results["sg_replaced"] else "QUARANTINE_PARTIAL"
    try:
        _tag_instance(instance_id, final_tag, finding.get("id", "unknown"))
        results["actions"].append({"action": f"TAG_{final_tag}", "status": "SUCCESS"})
    except Exception as exc:
        logger.warning("Final tagging failed: %s", exc)

    # Determine overall status for Step Functions Choice state
    if results["snapshot_created"] and results["sg_replaced"]:
        results["status"] = "SUCCESS"
    elif results["sg_replaced"]:
        results["status"] = "PARTIAL"  # Isolated but no forensic snapshot
    else:
        results["status"] = "FAILED"

    logger.info("EC2 isolation complete | instance=%s snapshot=%s sg_replaced=%s status=%s",
                instance_id, results["snapshot_created"], results["sg_replaced"], results["status"])

    return {**event, "isolation": results}


def _tag_instance(instance_id: str, quarantine_status: str, finding_id: str) -> None:
    ec2_client.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": "SOARStatus",                "Value": quarantine_status},
            {"Key": "SOARFindingId",              "Value": finding_id},
            {"Key": "SOARIsolationTimestamp",     "Value": datetime.now(timezone.utc).isoformat()},
            {"Key": "SOARReviewRequired",         "Value": "true"},
        ],
    )


def _snapshot_volumes(volumes: list, instance_id: str, finding_id: str) -> list:
    """Create EBS snapshots for forensic preservation. Returns list of snapshot IDs."""
    snapshot_ids = []
    for vol in volumes:
        volume_id   = vol.get("volume_id")
        device_name = vol.get("device_name", "unknown")
        if not volume_id:
            continue
        snap = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=f"SOAR forensic snapshot | instance={instance_id} finding={finding_id}",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "Name",            "Value": f"soar-forensic-{instance_id}-{device_name}"},
                    {"Key": "SOARFindingId",   "Value": finding_id},
                    {"Key": "SOARInstanceId",  "Value": instance_id},
                    {"Key": "SOARDevice",      "Value": device_name},
                    {"Key": "SOARTimestamp",   "Value": datetime.now(timezone.utc).isoformat()},
                    {"Key": "SOARPurpose",     "Value": "ForensicPreservation"},
                ],
            }],
        )
        snapshot_ids.append(snap["SnapshotId"])
    return snapshot_ids


def _get_or_create_quarantine_sg(vpc_id: str) -> str:
    """
    Return existing quarantine SG or create a new one.
    The quarantine SG has no ingress or egress rules — complete network isolation.
    """
    # Check if quarantine SG already exists in this VPC
    existing = ec2_client.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [QUARANTINE_SG_NAME]},
            {"Name": "vpc-id",     "Values": [vpc_id]},
        ]
    )
    sgs = existing.get("SecurityGroups", [])
    if sgs:
        logger.info("Using existing quarantine SG: %s", sgs[0]["GroupId"])
        return sgs[0]["GroupId"]

    # Create quarantine SG with no rules
    sg = ec2_client.create_security_group(
        GroupName=QUARANTINE_SG_NAME,
        Description=QUARANTINE_SG_DESCRIPTION,
        VpcId=vpc_id,
        TagSpecifications=[{
            "ResourceType": "security-group",
            "Tags": [
                {"Key": "Name",    "Value": QUARANTINE_SG_NAME},
                {"Key": "Purpose", "Value": "SOAR automated quarantine"},
            ],
        }],
    )
    sg_id = sg["GroupId"]

    # Remove default outbound rule (AWS adds allow-all egress by default)
    ec2_client.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    logger.info("Created quarantine SG: %s in VPC: %s", sg_id, vpc_id)
    return sg_id


def _extract_instance_id(resource_id: str) -> str:
    """Extract instance ID from ARN or plain resource ID."""
    if resource_id.startswith("arn:"):
        return resource_id.split("/")[-1]
    return resource_id
