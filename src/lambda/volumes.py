"""Step 6: create working volumes from the evidence snapshots and attach them
to the forensic workstation. The evidence snapshot itself is never modified;
the analysis runs on a disposable copy that is deleted after the scan.
"""
import os

from common import WorkstationNotReady, append_history, case_tags, forensics_ec2, update_case

CANDIDATE_DEVICES = [f"/dev/sd{c}" for c in "fghijklmnop"]


def _workstation(ec2):
    ws_id = os.environ["WORKSTATION_INSTANCE_ID"]
    inst = ec2.describe_instances(InstanceIds=[ws_id])["Reservations"][0]["Instances"][0]
    return ws_id, inst


def attach_handler(state, _context):
    ec2 = forensics_ec2()
    ws_id, ws = _workstation(ec2)
    ws_state = ws["State"]["Name"]
    if ws_state == "stopped":
        # Cost saving: the workstation can be left stopped between cases.
        ec2.start_instances(InstanceIds=[ws_id])
        raise WorkstationNotReady(f"Started forensic workstation {ws_id}; retrying once it is running")
    if ws_state != "running":
        raise WorkstationNotReady(f"Forensic workstation {ws_id} is {ws_state}")
    az = ws["Placement"]["AvailabilityZone"]
    used = {b["DeviceName"] for b in ws.get("BlockDeviceMappings", [])}
    free = [d for d in CANDIDATE_DEVICES if d not in used]
    if len(free) < len(state["snapshots"]):
        raise RuntimeError("Not enough free device slots on the workstation; another case may be running")

    analysis = []
    for snap in state["snapshots"]:
        vol = ec2.create_volume(
            SnapshotId=snap["evidence_snapshot_id"],
            AvailabilityZone=az,
            VolumeType="gp3",
            Encrypted=True,
            KmsKeyId=os.environ["FORENSICS_KMS_KEY_ARN"],
            TagSpecifications=[{
                "ResourceType": "volume",
                "Tags": case_tags(state, ForensicsStage="analysis", SourceVolume=snap["volume_id"],
                                  Name=f"{state['case_id']}-{snap['volume_id']}-analysis"),
            }],
        )
        analysis.append({
            "analysis_volume_id": vol["VolumeId"],
            "source_volume_id": snap["volume_id"],
            "evidence_snapshot_id": snap["evidence_snapshot_id"],
            "source_device": snap["device"],
        })

    # Record volumes before waiting so cleanup can remove them if anything fails.
    state["analysis_volumes"] = analysis
    ids = [a["analysis_volume_id"] for a in analysis]
    ec2.get_waiter("volume_available").wait(VolumeIds=ids, WaiterConfig={"Delay": 5, "MaxAttempts": 60})

    for vol, device in zip(analysis, free):
        ec2.attach_volume(VolumeId=vol["analysis_volume_id"], InstanceId=ws_id, Device=device)
        vol["workstation_device"] = device
    ec2.get_waiter("volume_in_use").wait(VolumeIds=ids, WaiterConfig={"Delay": 5, "MaxAttempts": 60})

    append_history(state, "analysis_volumes_attached", workstation=ws_id, volumes=ids)
    update_case(state["case_id"], "ANALYZING", evidence_snapshots=[s["evidence_snapshot_id"] for s in state["snapshots"]])
    return state
