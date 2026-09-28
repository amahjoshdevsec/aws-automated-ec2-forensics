"""Step 9: write the chain-of-custody manifest, tag the evidence and notify.

The scan writes cases/<case_id>/analysis/summary.json to the evidence bucket.
This function combines it with the workflow history into
cases/<case_id>/chain-of-custody.json, stores the manifest's SHA-256 in
DynamoDB and tags each evidence snapshot with the disk image hash.
"""
import hashlib
import json
import os

from common import LOG, append_history, forensics_ec2, local_client, now_iso, publish, update_case


def _load_summary(s3, bucket, case_id):
    try:
        obj = s3.get_object(Bucket=bucket, Key=f"cases/{case_id}/analysis/summary.json")
        return json.loads(obj["Body"].read())
    except Exception as exc:
        LOG.warning("summary.json not found for %s: %s", case_id, exc)
        return {}


def handler(state, _context):
    case_id = state["case_id"]
    bucket = os.environ["EVIDENCE_BUCKET"]
    s3 = local_client("s3")
    summary = _load_summary(s3, bucket, case_id)
    state["findings"] = summary.get("totals", {})

    # Tag each evidence snapshot with the SHA-256 of its disk image.
    hashes = {v.get("source_volume_id"): v.get("sha256") for v in summary.get("volumes", [])}
    ec2 = forensics_ec2()
    for snap in state.get("snapshots", []):
        digest = hashes.get(snap["volume_id"])
        if digest:
            snap["image_sha256"] = digest
            ec2.create_tags(
                Resources=[snap["evidence_snapshot_id"]],
                Tags=[{"Key": "EvidenceSha256", "Value": digest}],
            )

    append_history(state, "case_finalized")
    manifest = {
        "schema": "aws-automated-ec2-forensics/chain-of-custody/v1",
        "generated_at": now_iso(),
        "case_id": case_id,
        "requested_by": state.get("requested_by"),
        "reason": state.get("reason"),
        "approval": state.get("approval"),
        "source": {
            "account_id": state["account_id"],
            "region": state["region"],
            "instance_id": state["instance_id"],
            "instance": state.get("instance"),
        },
        "evidence": [
            {
                "source_volume_id": s["volume_id"],
                "device": s["device"],
                "evidence_snapshot_id": s.get("evidence_snapshot_id"),
                "image_sha256": s.get("image_sha256"),
            }
            for s in state.get("snapshots", [])
        ],
        "analysis": {
            "workstation_instance_id": os.environ.get("WORKSTATION_INSTANCE_ID"),
            "ssm_command_id": state.get("scan", {}).get("command_id"),
            "report_prefix": f"s3://{bucket}/cases/{case_id}/analysis/",
            "totals": summary.get("totals", {}),
            "tool_versions": summary.get("tool_versions", {}),
        },
        "history": state.get("history", []),
    }
    body = json.dumps(manifest, indent=2, default=str).encode()
    manifest_sha256 = hashlib.sha256(body).hexdigest()
    s3.put_object(
        Bucket=bucket,
        Key=f"cases/{case_id}/chain-of-custody.json",
        Body=body,
        ContentType="application/json",
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=os.environ["FORENSICS_KMS_KEY_ARN"],
    )
    state["custody_manifest"] = {
        "s3_uri": f"s3://{bucket}/cases/{case_id}/chain-of-custody.json",
        "sha256": manifest_sha256,
    }

    totals = summary.get("totals", {})
    update_case(
        case_id,
        "COMPLETE",
        completed_at=now_iso(),
        custody_manifest=state["custody_manifest"],
        findings=totals,
    )
    region = os.environ["AWS_REGION"]
    console = f"https://{region}.console.aws.amazon.com/s3/buckets/{bucket}?prefix=cases/{case_id}/"
    publish(
        "NOTIFY_TOPIC_ARN",
        f"[Forensics] Report ready: {case_id}",
        (
            f"The forensic analysis for {state['instance_id']} ({state['account_id']}) is complete.\n\n"
            f"ClamAV detections:  {totals.get('clamav_detections', 'n/a')}\n"
            f"YARA matches:       {totals.get('yara_matches', 'n/a')}\n"
            f"Persistence items:  {totals.get('persistence_items', 'n/a')}\n"
            f"Suspicious files:   {totals.get('suspicious_files', 'n/a')}\n\n"
            f"Report:        s3://{bucket}/cases/{case_id}/analysis/report.md\n"
            f"Custody file:  {state['custody_manifest']['s3_uri']} (sha256 {manifest_sha256})\n"
            f"Console:       {console}\n\n"
            f"Isolation requested: {state.get('isolate')}"
        ),
    )
    return state
