"""
enrich_finding — SOAR Playbook Step 1
Enriches an incoming Security Hub / GuardDuty finding with live AWS context.

For IAM findings:  fetches user details, active access keys, attached policies
For EC2 findings:  fetches instance metadata, VPC, security groups, volumes

Input (from EventBridge input_transformer):
  {
    "playbook": "iam-credential-compromise" | "ec2-isolation",
    "finding": { "id", "severity", "resource_id", "instance_id", ... }
  }

Output:
  Same event with "enriched" key added containing AWS resource context.
"""

import boto3
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

iam_client = boto3.client("iam")
ec2_client = boto3.client("ec2")


def lambda_handler(event: dict, context) -> dict:
    logger.info("enrich_finding invoked | playbook=%s finding_id=%s",
                event.get("playbook"), event.get("finding", {}).get("id"))

    playbook = event.get("playbook", "")
    finding  = event.get("finding", {})

    try:
        if "iam" in playbook:
            enriched = enrich_iam_finding(finding)
        elif "ec2" in playbook:
            enriched = enrich_ec2_finding(finding)
        else:
            enriched = {"note": "No enrichment handler for playbook type", "playbook": playbook}

        logger.info("Enrichment complete | resource=%s", finding.get("resource_id", finding.get("instance_id")))
        return {**event, "enriched": enriched}

    except Exception as exc:
        logger.error("Enrichment failed: %s", exc, exc_info=True)
        raise


# ─── IAM ENRICHMENT ──────────────────────────────────────────────────────────

def enrich_iam_finding(finding: dict) -> dict:
    """
    Extract IAM username from the resource ARN and fetch:
    - User metadata
    - Active/inactive access keys
    - Inline and attached managed policies
    - Whether a console login profile exists
    """
    resource_id = finding.get("resource_id", "")
    # resource_id format: arn:aws:iam::123456789012:user/username
    username = resource_id.split("/")[-1] if "/" in resource_id else resource_id

    enriched = {
        "resource_type": "IAM_USER",
        "username": username,
        "enrichment_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # User metadata
    try:
        user = iam_client.get_user(UserName=username)["User"]
        enriched["user_id"]     = user.get("UserId")
        enriched["user_arn"]    = user.get("Arn")
        enriched["create_date"] = user.get("CreateDate", "").isoformat() if user.get("CreateDate") else None
        enriched["tags"]        = {t["Key"]: t["Value"] for t in user.get("Tags", [])}
    except iam_client.exceptions.NoSuchEntityException:
        enriched["user_exists"] = False
        logger.warning("IAM user not found: %s", username)
        return enriched

    # Access keys
    keys = iam_client.list_access_keys(UserName=username)["AccessKeyMetadata"]
    enriched["access_keys"] = [
        {
            "access_key_id": k["AccessKeyId"],
            "status": k["Status"],
            "created": k["CreateDate"].isoformat(),
        }
        for k in keys
    ]
    enriched["active_key_count"] = sum(1 for k in keys if k["Status"] == "Active")

    # Inline policies
    inline = iam_client.list_user_policies(UserName=username)["PolicyNames"]
    enriched["inline_policies"] = inline

    # Managed policies
    managed = iam_client.list_attached_user_policies(UserName=username)["AttachedPolicies"]
    enriched["managed_policies"] = [p["PolicyArn"] for p in managed]

    # Console login profile
    try:
        iam_client.get_login_profile(UserName=username)
        enriched["has_console_access"] = True
    except iam_client.exceptions.NoSuchEntityException:
        enriched["has_console_access"] = False

    logger.info("IAM enrichment complete | user=%s active_keys=%d",
                username, enriched["active_key_count"])
    return enriched


# ─── EC2 ENRICHMENT ──────────────────────────────────────────────────────────

def enrich_ec2_finding(finding: dict) -> dict:
    """
    Fetch EC2 instance metadata:
    - Instance state, type, AMI, launch time
    - VPC and subnet
    - Current security groups
    - Attached EBS volumes (for snapshot targeting)
    - Public/private IPs
    """
    instance_id = finding.get("instance_id", "").split("/")[-1]

    enriched = {
        "resource_type": "EC2_INSTANCE",
        "instance_id": instance_id,
        "enrichment_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        if not reservations:
            enriched["instance_found"] = False
            logger.warning("EC2 instance not found: %s", instance_id)
            return enriched

        instance = reservations[0]["Instances"][0]

        enriched["instance_type"]  = instance.get("InstanceType")
        enriched["state"]          = instance.get("State", {}).get("Name")
        enriched["launch_time"]    = instance.get("LaunchTime", "").isoformat() if instance.get("LaunchTime") else None
        enriched["image_id"]       = instance.get("ImageId")
        enriched["vpc_id"]         = instance.get("VpcId")
        enriched["subnet_id"]      = instance.get("SubnetId")
        enriched["private_ip"]     = instance.get("PrivateIpAddress")
        enriched["public_ip"]      = instance.get("PublicIpAddress")
        enriched["key_name"]       = instance.get("KeyName")
        enriched["iam_profile"]    = instance.get("IamInstanceProfile", {}).get("Arn")
        enriched["tags"]           = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}

        # Current security groups (will be replaced during isolation)
        enriched["current_security_groups"] = [
            {"group_id": sg["GroupId"], "group_name": sg["GroupName"]}
            for sg in instance.get("SecurityGroups", [])
        ]

        # EBS volumes (needed for snapshot step)
        enriched["ebs_volumes"] = [
            {
                "volume_id": bdm["Ebs"]["VolumeId"],
                "device_name": bdm["DeviceName"],
                "delete_on_termination": bdm["Ebs"].get("DeleteOnTermination"),
            }
            for bdm in instance.get("BlockDeviceMappings", [])
            if "Ebs" in bdm
        ]

        logger.info("EC2 enrichment complete | instance=%s state=%s volumes=%d",
                    instance_id, enriched["state"], len(enriched["ebs_volumes"]))

    except ec2_client.exceptions.ClientError as e:
        logger.error("EC2 describe failed: %s", e)
        enriched["error"] = str(e)

    return enriched
