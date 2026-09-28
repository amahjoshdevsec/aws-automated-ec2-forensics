"""Step 2: human approval gate (Step Functions callback pattern).

request_handler  - invoked with .waitForTaskToken. Stores the task token under a
                   random, single-use approval id and emails the approver.
callback_handler - behind API Gateway. GET renders a confirmation page (so email
                   link scanners that prefetch URLs cannot approve anything);
                   POST records the decision and resumes the workflow.
"""
import base64
import html
import json
import os
import secrets
import time
import urllib.parse

from common import LOG, local_client, now_iso, publish, update_case


def request_handler(event, _context):
    state = event["state"]
    token = event["task_token"]
    approval_id = secrets.token_urlsafe(32)
    ttl_seconds = int(os.environ.get("APPROVAL_TIMEOUT_SECONDS", "86400"))

    local_client("dynamodb").put_item(
        TableName=os.environ["APPROVALS_TABLE"],
        Item={
            "approval_id": {"S": approval_id},
            "task_token": {"S": token},
            "case_id": {"S": state["case_id"]},
            "created_at": {"S": now_iso()},
            "expires_at": {"N": str(int(time.time()) + ttl_seconds)},
        },
        ConditionExpression="attribute_not_exists(approval_id)",
    )

    url = f"{os.environ['APPROVAL_API_URL'].rstrip('/')}/decision?id={approval_id}"
    inst = state.get("instance", {})
    volumes = ", ".join(v["volume_id"] for v in state.get("volumes", []))
    message = (
        "A forensic investigation has been requested and needs your approval.\n\n"
        f"Case ID:        {state['case_id']}\n"
        f"Requested by:   {state.get('requested_by')}\n"
        f"Reason:         {state.get('reason')}\n"
        f"Account/Region: {state['account_id']} / {state['region']}\n"
        f"Instance:       {state['instance_id']} ({inst.get('name') or 'no Name tag'})\n"
        f"Private IP:     {inst.get('private_ip')}\n"
        f"EBS volumes:    {volumes}\n"
        f"Isolate after analysis: {state.get('isolate')}\n\n"
        "Approving will snapshot every EBS volume, copy the snapshots into the forensics\n"
        "account under the forensics KMS key and scan them on the isolated workstation.\n\n"
        f"Review and decide: {url}\n\n"
        f"This link is single use and expires in {ttl_seconds // 3600} hour(s)."
    )
    publish("APPROVAL_TOPIC_ARN", f"[Forensics] Approval needed: {state['case_id']}", message)
    update_case(state["case_id"], "PENDING_APPROVAL", approval_requested_at=now_iso())
    return {"approval_requested": True}


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forensics approval</title>
<style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#16191f}}
button{{font-size:16px;padding:10px 20px;margin-right:12px;border-radius:6px;border:0;cursor:pointer}}
.ok{{background:#1d8102;color:#fff}}.no{{background:#d13212;color:#fff}}code{{background:#f2f3f3;padding:2px 4px}}</style>
</head><body>{body}</body></html>"""


def _html(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
            "Referrer-Policy": "no-referrer",
        },
        "body": PAGE.format(body=body),
    }


def _params(event):
    params = dict(event.get("queryStringParameters") or {})
    body = event.get("body")
    if body:
        if event.get("isBase64Encoded"):
            body = base64.b64decode(body).decode("utf-8")
        for key, values in urllib.parse.parse_qs(body).items():
            params[key] = values[0]
    return params


def callback_handler(event, _context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET").upper()
    params = _params(event)
    approval_id = params.get("id", "")
    if not approval_id or len(approval_id) > 128:
        return _html(400, "<h2>Invalid request</h2>")

    ddb = local_client("dynamodb")
    table = os.environ["APPROVALS_TABLE"]
    item = ddb.get_item(TableName=table, Key={"approval_id": {"S": approval_id}}, ConsistentRead=True).get("Item")
    if not item or int(item["expires_at"]["N"]) < time.time():
        return _html(410, "<h2>This approval link is invalid, expired or already used.</h2>")
    case_id = html.escape(item["case_id"]["S"])

    if method == "GET":
        safe_id = html.escape(approval_id, quote=True)
        return _html(
            200,
            f"<h2>Forensic investigation <code>{case_id}</code></h2>"
            "<p>Approve evidence collection (EBS snapshots, forensic copy and automated scan)?</p>"
            f'<form method="post" action="decision"><input type="hidden" name="id" value="{safe_id}">'
            '<button class="ok" name="action" value="approve">Approve</button>'
            '<button class="no" name="action" value="reject">Reject</button></form>',
        )

    action = params.get("action")
    if action not in ("approve", "reject"):
        return _html(400, "<h2>Unknown action</h2>")

    # Single use: delete the record atomically before resuming the workflow.
    try:
        ddb.delete_item(
            TableName=table,
            Key={"approval_id": {"S": approval_id}},
            ConditionExpression="attribute_exists(approval_id)",
        )
    except ddb.exceptions.ConditionalCheckFailedException:
        return _html(410, "<h2>This approval link was already used.</h2>")

    source_ip = event.get("requestContext", {}).get("http", {}).get("sourceIp", "unknown")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent", "unknown")
    decision = {
        "approved": action == "approve",
        "decision": action,
        "decided_at": now_iso(),
        "source_ip": source_ip,
        "user_agent": user_agent[:256],
    }
    sfn = local_client("stepfunctions")
    try:
        sfn.send_task_success(taskToken=item["task_token"]["S"], output=json.dumps(decision))
    except (sfn.exceptions.TaskTimedOut, sfn.exceptions.TaskDoesNotExist, sfn.exceptions.InvalidToken):
        LOG.warning("Task token for case %s is no longer valid", case_id)
        return _html(410, "<h2>The investigation is no longer waiting for approval.</h2>")

    LOG.info(json.dumps({"case_id": item["case_id"]["S"], "event": "approval_decision", **decision}))
    verb = "approved" if decision["approved"] else "rejected"
    return _html(200, f"<h2>Case <code>{case_id}</code> {verb}.</h2><p>You can close this window.</p>")
