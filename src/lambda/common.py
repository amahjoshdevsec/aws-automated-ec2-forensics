"""Shared helpers for the EC2 forensics orchestration Lambdas.

Every orchestration Lambda receives the full investigation "state" document from
AWS Step Functions and returns it (enriched) so the workflow carries a single,
auditable record from start to finish.
"""
import datetime
import json
import logging
import os
import re

import boto3
from botocore.config import Config

LOG = logging.getLogger()
LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

BOTO_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})

INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
VOLUME_ID_RE = re.compile(r"^vol-[0-9a-f]{8,17}$")
ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-[0-9]$")
CASE_ID_RE = re.compile(r"^[A-Za-z0-9-]{6,64}$")

_LOCAL_ACCOUNT = None


class ValidationError(Exception):
    """Raised when an investigation request is invalid. Not retried."""


class WorkstationNotReady(Exception):
    """The workstation is starting or its SSM agent is not online yet (Step Functions retries this)."""


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"Missing required environment variable {name}")
    return value


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_session(region=None):
    return boto3.session.Session(region_name=region or os.environ.get("AWS_REGION"))


def local_client(service, region=None):
    return local_session(region).client(service, config=BOTO_CONFIG)


def local_account_id():
    global _LOCAL_ACCOUNT
    if _LOCAL_ACCOUNT is None:
        _LOCAL_ACCOUNT = local_client("sts").get_caller_identity()["Account"]
    return _LOCAL_ACCOUNT


def source_session(state):
    """Return a boto3 session for the account that owns the suspect instance.

    Same account: the Lambda's own credentials.
    Different account: assume the member-account responder role (deployed with
    terraform/modules/member-account-role).
    """
    account_id = state["account_id"]
    region = state["region"]
    if account_id == local_account_id():
        return local_session(region)

    partition = env("FORENSICS_PARTITION", "aws")
    role_name = env("MEMBER_ROLE_NAME")
    role_arn = f"arn:{partition}:iam::{account_id}:role/{role_name}"
    creds = local_client("sts").assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"forensics-{state['case_id']}"[:64],
        DurationSeconds=3600,
    )["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def source_ec2(state):
    return source_session(state).client("ec2", config=BOTO_CONFIG)


def forensics_ec2(state=None):
    return local_client("ec2")


def case_tags(state, **extra):
    tags = {
        "Purpose": "forensics",
        "CaseId": state["case_id"],
        "SourceAccount": state["account_id"],
        "SourceInstance": state["instance_id"],
        "ManagedBy": "aws-automated-ec2-forensics",
    }
    tags.update({k: str(v) for k, v in extra.items()})
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def update_case(case_id, status, **attrs):
    """Upsert the investigation record in DynamoDB (audit trail)."""
    table = os.environ.get("CASES_TABLE")
    if not table:
        return
    names = {"#s": "status", "#u": "updated_at"}
    values = {":s": {"S": status}, ":u": {"S": now_iso()}}
    sets = ["#s = :s", "#u = :u"]
    for i, (key, val) in enumerate(attrs.items()):
        names[f"#a{i}"] = key
        values[f":a{i}"] = {"S": val if isinstance(val, str) else json.dumps(val, default=str)}
        sets.append(f"#a{i} = :a{i}")
    local_client("dynamodb").update_item(
        TableName=table,
        Key={"case_id": {"S": case_id}},
        UpdateExpression="SET " + ", ".join(sets),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def append_history(state, event, **details):
    entry = {"at": now_iso(), "event": event}
    entry.update(details)
    state.setdefault("history", []).append(entry)
    LOG.info(json.dumps({"case_id": state.get("case_id"), **entry}, default=str))
    return state


def publish(topic_env, subject, message):
    topic_arn = os.environ.get(topic_env)
    if not topic_arn:
        LOG.warning("No topic configured in %s; skipping notification", topic_env)
        return
    local_client("sns").publish(TopicArn=topic_arn, Subject=subject[:99], Message=message)
