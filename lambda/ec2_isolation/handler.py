"""
ec2_isolation — SOAR Playbook Step 3 (EC2 Playbook)

Automated response to suspicious or compromised EC2 instances.

Actions performed:
  1. Tag the instance as QUARANTINE_PENDING
  2. Initiate EBS snapshots of attached volumes for investigation and preservation
  3. Create or reuse a restrictive quarantine security group
  4. Replace the instance security groups with the quarantine group
  5. Tag the instance as QUARANTINE_COMPLETE or QUARANTINE_PARTIAL
  6. Return structured isolation results for Step Functions evaluation

These actions can support incident containment, investigation,
network-segmentation, and audit objectives. Formal compliance depends
on the broader control environment.
"""

import boto3
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

ec2_client = boto3.client("ec2")

QUARANTINE_SG_NAME = "soar-quarantine-deny-all"
QUARANTINE_SG_DESCRIPTION = (
    "SOAR automated quarantine — restricted network connectivity — do not modify"
)


def lambda_handler(event: dict, context) -> dict:
    finding = event.get("finding", {})
    enriched = event.get("enriched", {})

    instance_id = enriched.get("instance_id") or _extract_instance_id(
        finding.get("instance_id", "")
    )
    vpc_id = enriched.get("vpc_id")
    volumes = enriched.get("ebs_volumes", [])

    logger.info(
        "ec2_isolation invoked | instance=%s vpc=%s volumes=%d",
        instance_id,
        vpc_id,
        len(volumes),
    )

    if not instance_id:
        logger.error("Cannot isolate — no instance_id in enriched context")
        return {
            **event,
            "isolation": {
                "status": "FAILED",
                "reason": "No instance_id found",
            },
        }

    if not vpc_id:
        logger.error("Cannot isolate — no vpc_id in enriched context")
        return {
            **event,
            "isolation": {
                "status": "FAILED",
                "reason": "No vpc_id found",
            },
        }

    results = {
        "instance_id": instance_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "finding_id": finding.get("id"),
        "snapshot_created": False,
        "sg_replaced": False,
        "actions": [],
        "status": "IN_PROGRESS",
    }

    # Step 1: Tag instance as QUARANTINE_PENDING
    try:
        _tag_instance(
            instance_id,
            "QUARANTINE_PENDING",
            finding.get("id", "unknown"),
        )

        results["actions"].append(
            {
                "action": "TAG_QUARANTINE_PENDING",
                "status": "SUCCESS",
            }
        )

        logger.info(
            "Tagged instance=%s as QUARANTINE_PENDING",
            instance_id,
        )

    except Exception as exc:
        logger.warning(
            "Initial tagging failed (non-critical): %s",
            exc,
        )

        results["actions"].append(
            {
                "action": "TAG_QUARANTINE_PENDING",
                "status": "FAILED",
                "error": str(exc),
            }
        )

    # Step 2: Initiate EBS snapshots
    snapshot_ids = []

    try:
        snapshot_ids = _snapshot_volumes(
            volumes,
            instance_id,
            finding.get("id", "unknown"),
        )

        results["snapshot_ids"] = snapshot_ids
        results["snapshot_created"] = len(snapshot_ids) > 0

        results["actions"].append(
            {
                "action": "INITIATE_EBS_SNAPSHOTS",
                "status": "SUCCESS",
                "snapshot_count": len(snapshot_ids),
                "snapshot_ids": snapshot_ids,
            }
        )

        logger.info(
            "Initiated %d snapshot(s) for instance=%s: %s",
            len(snapshot_ids),
            instance_id,
            snapshot_ids,
        )

    except Exception as exc:
        logger.error(
            "EBS snapshot initiation failed for instance=%s: %s",
            instance_id,
            exc,
        )

        results["actions"].append(
            {
                "action": "INITIATE_EBS_SNAPSHOTS",
                "status": "FAILED",
                "error": str(exc),
            }
        )

        # Snapshot failure should not prevent the containment attempt.

    # Step 3: Get or create quarantine security group
    quarantine_sg_id = None

    try:
        quarantine_sg_id = _get_or_create_quarantine_sg(vpc_id)

        results["quarantine_sg_id"] = quarantine_sg_id

        results["actions"].append(
            {
                "action": "GET_OR_CREATE_QUARANTINE_SG",
                "status": "SUCCESS",
                "sg_id": quarantine_sg_id,
            }
        )

        logger.info(
            "Quarantine security group ready: %s",
            quarantine_sg_id,
        )

    except Exception as exc:
        logger.error(
            "Failed to get/create quarantine security group: %s",
            exc,
        )

        results["actions"].append(
            {
                "action": "GET_OR_CREATE_QUARANTINE_SG",
                "status": "FAILED",
                "error": str(exc),
            }
        )

    # Step 4: Replace instance security groups
    if quarantine_sg_id:
        try:
            original_sgs = [
                sg["group_id"]
                for sg in enriched.get(
                    "current_security_groups",
                    [],
                )
            ]

            ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[quarantine_sg_id],
            )

            results["original_security_groups"] = original_sgs
            results["sg_replaced"] = True

            results["actions"].append(
                {
                    "action": "REPLACE_SECURITY_GROUPS",
                    "status": "SUCCESS",
                    "original_sgs": original_sgs,
                    "quarantine_sg": quarantine_sg_id,
                }
            )

            logger.info(
                "Security groups replaced for instance=%s "
                "| original=%s quarantine=%s",
                instance_id,
                original_sgs,
                quarantine_sg_id,
            )

        except Exception as exc:
            logger.error(
                "Security-group replacement failed for instance=%s: %s",
                instance_id,
                exc,
            )

            results["actions"].append(
                {
                    "action": "REPLACE_SECURITY_GROUPS",
                    "status": "FAILED",
                    "error": str(exc),
                }
            )

    # Step 5: Final tagging
    final_tag = (
        "QUARANTINE_COMPLETE"
        if results["sg_replaced"]
        else "QUARANTINE_PARTIAL"
    )

    try:
        _tag_instance(
            instance_id,
            final_tag,
            finding.get("id", "unknown"),
        )

        results["actions"].append(
            {
                "action": f"TAG_{final_tag}",
                "status": "SUCCESS",
            }
        )

    except Exception as exc:
        logger.warning(
            "Final tagging failed: %s",
            exc,
        )

        results["actions"].append(
            {
                "action": f"TAG_{final_tag}",
                "status": "FAILED",
                "error": str(exc),
            }
        )

    # Determine overall status for Step Functions
    if results["snapshot_created"] and results["sg_replaced"]:
        results["status"] = "SUCCESS"
    elif results["sg_replaced"]:
        results["status"] = "PARTIAL"
    else:
        results["status"] = "FAILED"

    logger.info(
        "EC2 isolation complete | instance=%s "
        "snapshot=%s sg_replaced=%s status=%s",
        instance_id,
        results["snapshot_created"],
        results["sg_replaced"],
        results["status"],
    )

    return {
        **event,
        "isolation": results,
    }


def _tag_instance(
    instance_id: str,
    quarantine_status: str,
    finding_id: str,
) -> None:
    """
    Tag the EC2 instance for containment status and analyst review.
    """
    ec2_client.create_tags(
        Resources=[instance_id],
        Tags=[
            {
                "Key": "SOARStatus",
                "Value": quarantine_status,
            },
            {
                "Key": "SOARFindingId",
                "Value": finding_id,
            },
            {
                "Key": "SOARIsolationTimestamp",
                "Value": datetime.now(timezone.utc).isoformat(),
            },
            {
                "Key": "SOARReviewRequired",
                "Value": "true",
            },
        ],
    )


def _snapshot_volumes(
    volumes: list,
    instance_id: str,
    finding_id: str,
) -> list:
    """
    Initiate EBS snapshots for attached volumes.

    Returns:
        List of snapshot IDs returned by AWS.

    Note:
        Snapshot IDs indicate that snapshot creation was initiated.
        This function does not wait for snapshots to reach the
        completed state.
    """
    snapshot_ids = []

    for volume in volumes:
        volume_id = volume.get("volume_id")
        device_name = volume.get(
            "device_name",
            "unknown",
        )

        if not volume_id:
            continue

        snapshot = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=(
                "SOAR investigation snapshot "
                f"| instance={instance_id} "
                f"finding={finding_id}"
            ),
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": (
                                f"soar-investigation-"
                                f"{instance_id}-"
                                f"{device_name}"
                            ),
                        },
                        {
                            "Key": "SOARFindingId",
                            "Value": finding_id,
                        },
                        {
                            "Key": "SOARInstanceId",
                            "Value": instance_id,
                        },
                        {
                            "Key": "SOARDevice",
                            "Value": device_name,
                        },
                        {
                            "Key": "SOARTimestamp",
                            "Value": datetime.now(
                                timezone.utc
                            ).isoformat(),
                        },
                        {
                            "Key": "SOARPurpose",
                            "Value": "InvestigationPreservation",
                        },
                    ],
                }
            ],
        )

        snapshot_ids.append(
            snapshot["SnapshotId"]
        )

    return snapshot_ids


def _get_or_create_quarantine_sg(
    vpc_id: str,
) -> str:
    """
    Return the existing quarantine security group or create a new one.

    The quarantine group is configured without ingress rules and with
    the default IPv4 allow-all egress rule removed to restrict instance
    network connectivity during containment.
    """
    existing = ec2_client.describe_security_groups(
        Filters=[
            {
                "Name": "group-name",
                "Values": [QUARANTINE_SG_NAME],
            },
            {
                "Name": "vpc-id",
                "Values": [vpc_id],
            },
        ]
    )

    security_groups = existing.get(
        "SecurityGroups",
        [],
    )

    if security_groups:
        logger.info(
            "Using existing quarantine security group: %s",
            security_groups[0]["GroupId"],
        )

        return security_groups[0]["GroupId"]

    security_group = ec2_client.create_security_group(
        GroupName=QUARANTINE_SG_NAME,
        Description=QUARANTINE_SG_DESCRIPTION,
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [
                    {
                        "Key": "Name",
                        "Value": QUARANTINE_SG_NAME,
                    },
                    {
                        "Key": "Purpose",
                        "Value": "SOAR automated quarantine",
                    },
                ],
            }
        ],
    )

    sg_id = security_group["GroupId"]

    # AWS creates a default IPv4 allow-all egress rule.
    # Remove it so the quarantine group restricts outbound traffic.
    ec2_client.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0",
                    }
                ],
            }
        ],
    )

    logger.info(
        "Created quarantine security group: %s in VPC: %s",
        sg_id,
        vpc_id,
    )

    return sg_id


def _extract_instance_id(
    resource_id: str,
) -> str:
    """
    Extract an EC2 instance ID from an ARN or plain resource ID.
    """
    if resource_id.startswith("arn:"):
        return resource_id.split("/")[-1]

    return resource_id
