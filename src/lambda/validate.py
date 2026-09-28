"""Step 1: validate the investigation request and capture instance metadata."""
import datetime
import os

from common import (
    ACCOUNT_ID_RE,
    CASE_ID_RE,
    INSTANCE_ID_RE,
    REGION_RE,
    ValidationError,
    append_history,
    local_account_id,
    source_ec2,
    update_case,
)


def _allowed_accounts():
    raw = os.environ.get("ALLOWED_ACCOUNT_IDS", "")
    accounts = {a.strip() for a in raw.split(",") if a.strip()}
    accounts.add(local_account_id())
    return accounts


def _bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "y")


def handler(event, _context):
    request = event.get("input", event) or {}
    execution_name = event.get("execution_name", "")

    instance_id = str(request.get("instance_id", "")).strip()
    if not INSTANCE_ID_RE.match(instance_id):
        raise ValidationError(f"instance_id '{instance_id}' is not a valid EC2 instance id")

    account_id = str(request.get("account_id") or local_account_id()).strip()
    if not ACCOUNT_ID_RE.match(account_id):
        raise ValidationError(f"account_id '{account_id}' is not a 12 digit AWS account id")
    if account_id not in _allowed_accounts():
        raise ValidationError(f"account {account_id} is not in the allowed account list")

    region = str(request.get("region") or os.environ["AWS_REGION"]).strip()
    if not REGION_RE.match(region):
        raise ValidationError(f"region '{region}' is not valid")
    if region != os.environ["AWS_REGION"]:
        raise ValidationError(
            "This deployment analyses instances in its own region only "
            f"({os.environ['AWS_REGION']}). Deploy another stack per region."
        )

    case_id = str(request.get("case_id") or "").strip()
    if not case_id:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
        case_id = f"CASE-{stamp}-{instance_id[-6:]}"
    if not CASE_ID_RE.match(case_id):
        raise ValidationError("case_id must be 6-64 characters of letters, digits and dashes")

    state = {
        "case_id": case_id,
        "execution_name": execution_name,
        "account_id": account_id,
        "region": region,
        "instance_id": instance_id,
        "requested_by": str(request.get("requested_by", "unknown"))[:128],
        "reason": str(request.get("reason", "not provided"))[:512],
        "isolate": _bool(request.get("isolate", False)),
        "cross_account": account_id != local_account_id(),
    }

    ec2 = source_ec2(state)
    reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    if not reservations or not reservations[0]["Instances"]:
        raise ValidationError(f"instance {instance_id} not found in {account_id}/{region}")
    inst = reservations[0]["Instances"][0]

    if inst["State"]["Name"] in ("terminated", "shutting-down"):
        raise ValidationError(f"instance {instance_id} is {inst['State']['Name']}")

    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
    if tags.get("Role") == "ForensicWorkstation" or instance_id == os.environ.get("WORKSTATION_INSTANCE_ID"):
        raise ValidationError("refusing to investigate the forensic workstation itself")

    volumes = []
    for bdm in inst.get("BlockDeviceMappings", []):
        if "Ebs" in bdm:
            volumes.append({"volume_id": bdm["Ebs"]["VolumeId"], "device": bdm["DeviceName"]})
    if not volumes:
        raise ValidationError(f"instance {instance_id} has no EBS volumes to preserve")

    max_volumes = int(os.environ.get("MAX_VOLUMES", "4"))
    if len(volumes) > max_volumes:
        raise ValidationError(f"instance has {len(volumes)} volumes; limit is {max_volumes}")

    state["instance"] = {
        "availability_zone": inst["Placement"]["AvailabilityZone"],
        "vpc_id": inst.get("VpcId"),
        "subnet_id": inst.get("SubnetId"),
        "private_ip": inst.get("PrivateIpAddress"),
        "instance_type": inst.get("InstanceType"),
        "image_id": inst.get("ImageId"),
        "launch_time": str(inst.get("LaunchTime")),
        "iam_instance_profile": (inst.get("IamInstanceProfile") or {}).get("Arn"),
        "security_groups": [g["GroupId"] for g in inst.get("SecurityGroups", [])],
        "network_interfaces": [n["NetworkInterfaceId"] for n in inst.get("NetworkInterfaces", [])],
        "name": tags.get("Name", ""),
        "state": inst["State"]["Name"],
    }
    state["volumes"] = volumes

    append_history(state, "request_validated", volumes=len(volumes))
    update_case(
        case_id,
        "PENDING_APPROVAL",
        account_id=account_id,
        instance_id=instance_id,
        requested_by=state["requested_by"],
        reason=state["reason"],
        execution_name=execution_name,
        created_at=state["history"][0]["at"],
    )
    return state
