"""Step 7: run the forensic scan on the workstation through SSM Run Command.

No SSH, no inbound ports: the workstation is reached only via AWS Systems
Manager. Inputs are validated with strict regexes before being placed in the
shell command to prevent command injection.
"""
import os

from common import CASE_ID_RE, REGION_RE, VOLUME_ID_RE, WorkstationNotReady, append_history, local_client


class ScanFailed(Exception):
    """The scan command finished with a non-success status."""


def start_handler(state, _context):
    ssm = local_client("ssm")
    ws_id = os.environ["WORKSTATION_INSTANCE_ID"]
    bucket = os.environ["EVIDENCE_BUCKET"]
    kms_key = os.environ["FORENSICS_KMS_KEY_ARN"]
    region = os.environ["AWS_REGION"]
    case_id = state["case_id"]

    info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [ws_id]}])
    online = [i for i in info.get("InstanceInformationList", []) if i.get("PingStatus") == "Online"]
    if not online:
        raise WorkstationNotReady(f"SSM agent on {ws_id} is not online yet")

    pairs = []
    for vol in state["analysis_volumes"]:
        a, s = vol["analysis_volume_id"], vol["source_volume_id"]
        if not (VOLUME_ID_RE.match(a) and VOLUME_ID_RE.match(s)):
            raise ValueError("unexpected volume id format")
        pairs.append(f"{a}:{s}")
    if not CASE_ID_RE.match(case_id) or not REGION_RE.match(region):
        raise ValueError("unexpected case id or region format")
    if not bucket.replace("-", "").replace(".", "").isalnum():
        raise ValueError("unexpected bucket name")

    commands = [
        "set -euo pipefail",
        # Wait for first-boot tool installation to finish (fresh workstation).
        "for i in $(seq 1 60); do [ -f /opt/forensics/.bootstrap-complete ] && break; sleep 10; done",
        "test -f /opt/forensics/.bootstrap-complete",
        "export PATH=$PATH:/snap/bin:/usr/local/bin",
        f"aws s3 cp s3://{bucket}/tools/forensic-scan.sh /opt/forensics/forensic-scan.sh --region {region} --only-show-errors",
        f"aws s3 cp s3://{bucket}/tools/rules/ /opt/forensics/rules/ --recursive --region {region} --only-show-errors",
        "chmod 0700 /opt/forensics/forensic-scan.sh",
        (
            f"/opt/forensics/forensic-scan.sh --case-id {case_id} --bucket {bucket} "
            f"--kms-key-id {kms_key} --region {region} --volumes {','.join(pairs)}"
        ),
    ]
    timeout = os.environ.get("SCAN_TIMEOUT_SECONDS", "7200")
    resp = ssm.send_command(
        InstanceIds=[ws_id],
        DocumentName="AWS-RunShellScript",
        Comment=f"Forensic scan {case_id}"[:100],
        Parameters={"commands": commands, "executionTimeout": [timeout]},
        TimeoutSeconds=600,
        OutputS3BucketName=bucket,
        OutputS3KeyPrefix=f"cases/{case_id}/ssm-output",
        CloudWatchOutputConfig={
            "CloudWatchOutputEnabled": True,
            "CloudWatchLogGroupName": os.environ.get("SCAN_LOG_GROUP", "/forensics/scan"),
        },
    )
    state["scan"] = {"command_id": resp["Command"]["CommandId"], "status": "InProgress"}
    append_history(state, "scan_started", command_id=state["scan"]["command_id"])
    return state


def check_handler(state, _context):
    ssm = local_client("ssm")
    ws_id = os.environ["WORKSTATION_INSTANCE_ID"]
    command_id = state["scan"]["command_id"]
    try:
        inv = ssm.get_command_invocation(CommandId=command_id, InstanceId=ws_id)
    except ssm.exceptions.InvocationDoesNotExist:
        state["scan"]["status"] = "InProgress"
        return state

    status = inv["Status"]
    if status in ("Pending", "InProgress", "Delayed"):
        state["scan"]["status"] = "InProgress"
        return state
    if status != "Success":
        err = (inv.get("StandardErrorContent") or "")[-1500:]
        raise ScanFailed(f"SSM command {command_id} ended with {status}: {err}")

    state["scan"]["status"] = "Success"
    append_history(state, "scan_completed", command_id=command_id)
    return state
