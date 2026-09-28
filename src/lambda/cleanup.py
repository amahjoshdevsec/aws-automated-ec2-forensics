"""Step 8: detach and delete the disposable analysis volumes and remove the
intermediate snapshots. The evidence snapshot is always kept.

Runs on both the success path and the failure path, so it tolerates any
subset of resources having been created.
"""
import os

from common import LOG, append_history, forensics_ec2, source_ec2


def _detach_and_delete(ec2, volume_ids):
    if not volume_ids:
        return
    existing = ec2.describe_volumes(
        Filters=[{"Name": "volume-id", "Values": volume_ids}]
    )["Volumes"]
    attached = [v["VolumeId"] for v in existing if v["State"] == "in-use"]
    for vid in attached:
        ec2.detach_volume(VolumeId=vid)
    ids = [v["VolumeId"] for v in existing]
    if ids:
        ec2.get_waiter("volume_available").wait(VolumeIds=ids, WaiterConfig={"Delay": 5, "MaxAttempts": 60})
    for vid in ids:
        ec2.delete_volume(VolumeId=vid)


def handler(state, _context):
    errors = []
    ec2 = forensics_ec2()

    try:
        _detach_and_delete(ec2, [v["analysis_volume_id"] for v in state.get("analysis_volumes", [])])
    except Exception as exc:
        LOG.exception("analysis volume cleanup failed")
        errors.append(f"volumes: {exc}")

    delete_intermediate = os.environ.get("DELETE_INTERMEDIATE_SNAPSHOTS", "true").lower() == "true"
    evidence_ready = state.get("snapshot_phase") in ("encrypted", "evidence") and state.get("snapshots_ready")
    if delete_intermediate and evidence_ready and "error" not in state:
        try:
            src = source_ec2(state)
            for snap in state.get("snapshots", []):
                intermediates = [snap.get("source_snapshot_id")]
                if state.get("cross_account"):
                    intermediates.append(snap.get("encrypted_snapshot_id"))
                for sid in filter(None, intermediates):
                    if sid != snap.get("evidence_snapshot_id"):
                        src.delete_snapshot(SnapshotId=sid)
        except Exception as exc:
            LOG.exception("intermediate snapshot cleanup failed")
            errors.append(f"snapshots: {exc}")

    state["cleanup"] = {"completed": not errors, "errors": errors}
    append_history(state, "cleanup_finished", errors=errors)
    return state
