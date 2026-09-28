"""Steps 3-5: preserve evidence as EBS snapshots under the forensics KMS key.

Snapshot phases (tracked in state["snapshot_phase"]):
  source    - point-in-time snapshot of every volume, taken in the source account
  encrypted - copy of each snapshot re-encrypted with the forensics KMS key
              (this is what makes cross-account sharing possible: snapshots
              encrypted with the default aws/ebs key can never be shared)
  evidence  - (cross-account only) copy owned by the forensics account

The final "evidence" snapshot is the authoritative, write-once record for the
case. The automation role is denied DeleteSnapshot on it by IAM condition.
"""
import os

from common import (
    LOG,
    append_history,
    case_tags,
    forensics_ec2,
    local_account_id,
    source_ec2,
    update_case,
)


def _snapshot_ids(state, phase):
    key = {"source": "source_snapshot_id", "encrypted": "encrypted_snapshot_id", "evidence": "evidence_snapshot_id"}[phase]
    return [s[key] for s in state["snapshots"]]


def create_handler(state, _context):
    ec2 = source_ec2(state)
    instance_id = state["instance_id"]

    # Preserve the instance: block accidental termination while the case is open.
    try:
        ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": True})
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{"Key": "ForensicsHold", "Value": state["case_id"]}],
        )
    except Exception as exc:  # preservation is best effort, evidence capture is not
        LOG.warning("Could not enable termination protection on %s: %s", instance_id, exc)

    snapshots = []
    for vol in state["volumes"]:
        resp = ec2.create_snapshot(
            VolumeId=vol["volume_id"],
            Description=f"Forensic evidence {state['case_id']} {instance_id} {vol['device']}",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": case_tags(state, ForensicsStage="original", SourceVolume=vol["volume_id"], Device=vol["device"],
                                  Name=f"{state['case_id']}-{vol['volume_id']}-original"),
            }],
        )
        snapshots.append({
            "volume_id": vol["volume_id"],
            "device": vol["device"],
            "source_snapshot_id": resp["SnapshotId"],
            "snapshot_started_at": str(resp.get("StartTime")),
        })

    state["snapshots"] = snapshots
    state["snapshot_phase"] = "source"
    state["snapshots_ready"] = False
    append_history(state, "snapshots_started", snapshot_ids=_snapshot_ids(state, "source"))
    update_case(state["case_id"], "COLLECTING_EVIDENCE", approval=state.get("approval", {}))
    return state


def check_handler(state, _context):
    phase = state["snapshot_phase"]
    ids = _snapshot_ids(state, phase)
    ec2 = forensics_ec2() if phase == "evidence" else source_ec2(state)
    snaps = ec2.describe_snapshots(SnapshotIds=ids)["Snapshots"]

    errored = [s["SnapshotId"] for s in snaps if s["State"] == "error"]
    if errored:
        raise RuntimeError(f"Snapshots entered error state: {errored}")

    ready = len(snaps) == len(ids) and all(s["State"] == "completed" for s in snaps)
    state["snapshots_ready"] = ready
    state["snapshot_progress"] = {s["SnapshotId"]: s.get("Progress", "") for s in snaps}
    if ready:
        append_history(state, f"snapshots_{phase}_completed", snapshot_ids=ids)
    return state


def copy_handler(state, _context):
    """Re-encrypt each snapshot with the forensics CMK (runs in the source account)."""
    ec2 = source_ec2(state)
    kms_key_arn = os.environ["FORENSICS_KMS_KEY_ARN"]
    for snap in state["snapshots"]:
        resp = ec2.copy_snapshot(
            SourceSnapshotId=snap["source_snapshot_id"],
            SourceRegion=state["region"],
            Encrypted=True,
            KmsKeyId=kms_key_arn,
            Description=f"Forensic evidence {state['case_id']} {snap['volume_id']} (forensics CMK)",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": case_tags(
                    state,
                    ForensicsStage="evidence" if not state["cross_account"] else "transfer",
                    SourceVolume=snap["volume_id"],
                    Device=snap["device"],
                    Name=f"{state['case_id']}-{snap['volume_id']}-"
                         + ("evidence" if not state["cross_account"] else "transfer"),
                ),
            }],
        )
        snap["encrypted_snapshot_id"] = resp["SnapshotId"]
        if not state["cross_account"]:
            snap["evidence_snapshot_id"] = resp["SnapshotId"]

    state["snapshot_phase"] = "encrypted"
    state["snapshots_ready"] = False
    append_history(state, "snapshots_reencrypted", snapshot_ids=_snapshot_ids(state, "encrypted"))
    return state


def share_and_copy_handler(state, _context):
    """Cross-account only: share the CMK-encrypted snapshot, then copy it into the forensics account."""
    src = source_ec2(state)
    dst = forensics_ec2()
    forensics_account = local_account_id()
    kms_key_arn = os.environ["FORENSICS_KMS_KEY_ARN"]
    for snap in state["snapshots"]:
        src.modify_snapshot_attribute(
            SnapshotId=snap["encrypted_snapshot_id"],
            Attribute="createVolumePermission",
            OperationType="add",
            UserIds=[forensics_account],
        )
        resp = dst.copy_snapshot(
            SourceSnapshotId=snap["encrypted_snapshot_id"],
            SourceRegion=state["region"],
            Encrypted=True,
            KmsKeyId=kms_key_arn,
            Description=f"Forensic evidence {state['case_id']} {snap['volume_id']} from {state['account_id']}",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": case_tags(state, ForensicsStage="evidence", SourceVolume=snap["volume_id"], Device=snap["device"],
                                  Name=f"{state['case_id']}-{snap['volume_id']}-evidence"),
            }],
        )
        snap["evidence_snapshot_id"] = resp["SnapshotId"]

    state["snapshot_phase"] = "evidence"
    state["snapshots_ready"] = False
    append_history(state, "snapshots_copied_to_forensics_account", snapshot_ids=_snapshot_ids(state, "evidence"))
    return state
