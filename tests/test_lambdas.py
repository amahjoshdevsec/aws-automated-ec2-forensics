"""Unit tests for the forensics workflow Lambdas.

Run with:  python -m pytest tests/   (or: python -m unittest discover tests)
AWS calls are replaced with mocks, so no account or credentials are needed.
"""
import json
import os
import sys
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src", "lambda"))

# Allow the tests to run where boto3 is not installed (it is always present in Lambda).
try:  # pragma: no cover
    import boto3  # noqa: F401
except ImportError:  # pragma: no cover
    boto3_stub = types.ModuleType("boto3")
    boto3_stub.session = types.SimpleNamespace(Session=mock.MagicMock())
    sys.modules["boto3"] = boto3_stub
    botocore_stub = types.ModuleType("botocore")
    config_stub = types.ModuleType("botocore.config")
    config_stub.Config = lambda **kw: kw
    sys.modules["botocore"] = botocore_stub
    sys.modules["botocore.config"] = config_stub

os.environ.update({
    "AWS_REGION": "us-east-1",
    "WORKSTATION_INSTANCE_ID": "i-0ffffffffffffffff",
    "EVIDENCE_BUCKET": "ec2-forensics-evidence-111111111111-us-east-1",
    "FORENSICS_KMS_KEY_ARN": "arn:aws:kms:us-east-1:111111111111:key/abc",
    "APPROVALS_TABLE": "approvals",
    "APPROVAL_API_URL": "https://example.execute-api.us-east-1.amazonaws.com/",
    "MEMBER_ROLE_NAME": "ForensicsResponderRole",
})

import approval  # noqa: E402
import cleanup  # noqa: E402
import common  # noqa: E402
import isolate  # noqa: E402
import scan  # noqa: E402
import snapshots  # noqa: E402
import validate  # noqa: E402
import volumes  # noqa: E402

LOCAL = "111111111111"


def base_state(**overrides):
    state = {
        "case_id": "CASE-20260928-010203-abcdef",
        "account_id": LOCAL,
        "region": "us-east-1",
        "instance_id": "i-0123456789abcdef0",
        "cross_account": False,
        "isolate": False,
        "volumes": [{"volume_id": "vol-0aaaaaaaaaaaaaaaa", "device": "/dev/xvda"}],
    }
    state.update(overrides)
    return state


def instance(**overrides):
    inst = {
        "InstanceId": "i-0123456789abcdef0",
        "State": {"Name": "running"},
        "Placement": {"AvailabilityZone": "us-east-1a"},
        "VpcId": "vpc-1",
        "SubnetId": "subnet-1",
        "PrivateIpAddress": "10.0.0.5",
        "Tags": [{"Key": "Name", "Value": "web-01"}],
        "BlockDeviceMappings": [
            {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-0aaaaaaaaaaaaaaaa"}},
            {"DeviceName": "/dev/sdf", "Ebs": {"VolumeId": "vol-0bbbbbbbbbbbbbbbb"}},
        ],
        "SecurityGroups": [{"GroupId": "sg-1"}],
        "NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-1"}]}],
    }
    inst.update(overrides)
    return {"Reservations": [{"Instances": [inst]}]}


class Base(unittest.TestCase):
    def setUp(self):
        patches = [
            mock.patch.object(common, "local_account_id", return_value=LOCAL),
            mock.patch.object(validate, "local_account_id", return_value=LOCAL),
            mock.patch.object(snapshots, "local_account_id", return_value=LOCAL),
            mock.patch.object(validate, "update_case"),
            mock.patch.object(snapshots, "update_case"),
            mock.patch.object(isolate, "update_case"),
            mock.patch.object(isolate, "publish"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)


class ValidateTests(Base):
    def run_validate(self, request, describe=None):
        ec2 = mock.MagicMock()
        ec2.describe_instances.return_value = describe or instance()
        with mock.patch.object(validate, "source_ec2", return_value=ec2):
            return validate.handler({"input": request, "execution_name": "exec-1"}, None)

    def test_valid_request_builds_state(self):
        state = self.run_validate({"instance_id": "i-0123456789abcdef0", "requested_by": "analyst", "isolate": "true"})
        self.assertRegex(state["case_id"], r"^CASE-\d{8}-\d{6}-bcdef0$")
        self.assertEqual(len(state["volumes"]), 2)
        self.assertTrue(state["isolate"])
        self.assertFalse(state["cross_account"])
        self.assertEqual(state["instance"]["availability_zone"], "us-east-1a")

    def test_rejects_malformed_instance_id(self):
        with self.assertRaises(common.ValidationError):
            self.run_validate({"instance_id": "i-123; rm -rf /"})

    def test_rejects_unlisted_account(self):
        with self.assertRaises(common.ValidationError):
            self.run_validate({"instance_id": "i-0123456789abcdef0", "account_id": "999999999999"})

    def test_rejects_other_region(self):
        with self.assertRaises(common.ValidationError):
            self.run_validate({"instance_id": "i-0123456789abcdef0", "region": "eu-west-1"})

    def test_refuses_to_investigate_workstation(self):
        desc = instance(Tags=[{"Key": "Role", "Value": "ForensicWorkstation"}])
        with self.assertRaises(common.ValidationError):
            self.run_validate({"instance_id": "i-0123456789abcdef0"}, desc)

    def test_refuses_terminated_instance(self):
        with self.assertRaises(common.ValidationError):
            self.run_validate({"instance_id": "i-0123456789abcdef0"}, instance(State={"Name": "terminated"}))


class SnapshotTests(Base):
    def test_create_enables_termination_protection_and_snapshots_each_volume(self):
        ec2 = mock.MagicMock()
        ec2.create_snapshot.side_effect = [{"SnapshotId": "snap-1"}, {"SnapshotId": "snap-2"}]
        state = base_state(volumes=[{"volume_id": "vol-1", "device": "/dev/xvda"}, {"volume_id": "vol-2", "device": "/dev/sdf"}])
        with mock.patch.object(snapshots, "source_ec2", return_value=ec2):
            out = snapshots.create_handler(state, None)
        ec2.modify_instance_attribute.assert_called_once()
        self.assertEqual([s["source_snapshot_id"] for s in out["snapshots"]], ["snap-1", "snap-2"])
        self.assertEqual(out["snapshot_phase"], "source")
        tags = ec2.create_snapshot.call_args.kwargs["TagSpecifications"][0]["Tags"]
        self.assertIn({"Key": "ForensicsStage", "Value": "original"}, tags)

    def test_check_waits_until_all_completed(self):
        ec2 = mock.MagicMock()
        ec2.describe_snapshots.return_value = {"Snapshots": [
            {"SnapshotId": "snap-1", "State": "completed"}, {"SnapshotId": "snap-2", "State": "pending", "Progress": "40%"}]}
        state = base_state(snapshot_phase="source", snapshots=[
            {"volume_id": "vol-1", "device": "a", "source_snapshot_id": "snap-1"},
            {"volume_id": "vol-2", "device": "b", "source_snapshot_id": "snap-2"}])
        with mock.patch.object(snapshots, "source_ec2", return_value=ec2):
            self.assertFalse(snapshots.check_handler(state, None)["snapshots_ready"])
        ec2.describe_snapshots.return_value["Snapshots"][1]["State"] = "completed"
        with mock.patch.object(snapshots, "source_ec2", return_value=ec2):
            self.assertTrue(snapshots.check_handler(state, None)["snapshots_ready"])

    def test_check_raises_on_error_state(self):
        ec2 = mock.MagicMock()
        ec2.describe_snapshots.return_value = {"Snapshots": [{"SnapshotId": "snap-1", "State": "error"}]}
        state = base_state(snapshot_phase="source", snapshots=[{"volume_id": "v", "device": "d", "source_snapshot_id": "snap-1"}])
        with mock.patch.object(snapshots, "source_ec2", return_value=ec2), self.assertRaises(RuntimeError):
            snapshots.check_handler(state, None)

    def test_copy_single_account_marks_copy_as_evidence(self):
        ec2 = mock.MagicMock()
        ec2.copy_snapshot.return_value = {"SnapshotId": "snap-enc"}
        state = base_state(snapshots=[{"volume_id": "vol-1", "device": "/dev/xvda", "source_snapshot_id": "snap-1"}])
        with mock.patch.object(snapshots, "source_ec2", return_value=ec2):
            out = snapshots.copy_handler(state, None)
        self.assertEqual(out["snapshots"][0]["evidence_snapshot_id"], "snap-enc")
        kwargs = ec2.copy_snapshot.call_args.kwargs
        self.assertTrue(kwargs["Encrypted"])
        self.assertEqual(kwargs["KmsKeyId"], os.environ["FORENSICS_KMS_KEY_ARN"])

    def test_copy_cross_account_marks_copy_as_transfer(self):
        ec2 = mock.MagicMock()
        ec2.copy_snapshot.return_value = {"SnapshotId": "snap-enc"}
        state = base_state(account_id="222222222222", cross_account=True,
                           snapshots=[{"volume_id": "vol-1", "device": "/dev/xvda", "source_snapshot_id": "snap-1"}])
        with mock.patch.object(snapshots, "source_ec2", return_value=ec2):
            out = snapshots.copy_handler(state, None)
        self.assertNotIn("evidence_snapshot_id", out["snapshots"][0])
        tags = ec2.copy_snapshot.call_args.kwargs["TagSpecifications"][0]["Tags"]
        self.assertIn({"Key": "ForensicsStage", "Value": "transfer"}, tags)


class ApprovalTests(Base):
    def setUp(self):
        super().setUp()
        self.ddb = mock.MagicMock()
        self.ddb.exceptions.ConditionalCheckFailedException = type("CCF", (Exception,), {})
        self.sfn = mock.MagicMock()
        for name in ("TaskTimedOut", "TaskDoesNotExist", "InvalidToken"):
            setattr(self.sfn.exceptions, name, type(name, (Exception,), {}))
        clients = {"dynamodb": self.ddb, "stepfunctions": self.sfn}
        p = mock.patch.object(approval, "local_client", side_effect=lambda svc, region=None: clients[svc])
        p.start()
        self.addCleanup(p.stop)
        self.ddb.get_item.return_value = {"Item": {
            "approval_id": {"S": "abc"}, "task_token": {"S": "TOKEN"},
            "case_id": {"S": "CASE-1"}, "expires_at": {"N": "9999999999"}}}

    def event(self, method, body=None):
        return {"requestContext": {"http": {"method": method, "sourceIp": "198.51.100.7", "userAgent": "test"}},
                "queryStringParameters": {"id": "abc"}, "body": body}

    def test_get_only_renders_confirmation(self):
        resp = approval.callback_handler(self.event("GET"), None)
        self.assertEqual(resp["statusCode"], 200)
        self.assertIn("<form", resp["body"])
        self.sfn.send_task_success.assert_not_called()
        self.ddb.delete_item.assert_not_called()

    def test_post_approve_resumes_workflow_once(self):
        resp = approval.callback_handler(self.event("POST", "id=abc&action=approve"), None)
        self.assertEqual(resp["statusCode"], 200)
        self.ddb.delete_item.assert_called_once()
        kwargs = self.sfn.send_task_success.call_args.kwargs
        self.assertEqual(kwargs["taskToken"], "TOKEN")
        self.assertTrue(json.loads(kwargs["output"])["approved"])

    def test_post_reject(self):
        approval.callback_handler(self.event("POST", "id=abc&action=reject"), None)
        self.assertFalse(json.loads(self.sfn.send_task_success.call_args.kwargs["output"])["approved"])

    def test_expired_link(self):
        self.ddb.get_item.return_value["Item"]["expires_at"] = {"N": "1"}
        self.assertEqual(approval.callback_handler(self.event("GET"), None)["statusCode"], 410)

    def test_reused_link(self):
        self.ddb.delete_item.side_effect = self.ddb.exceptions.ConditionalCheckFailedException()
        resp = approval.callback_handler(self.event("POST", "id=abc&action=approve"), None)
        self.assertEqual(resp["statusCode"], 410)
        self.sfn.send_task_success.assert_not_called()


class ScanTests(Base):
    def ssm(self, online=True):
        client = mock.MagicMock()
        client.describe_instance_information.return_value = {
            "InstanceInformationList": [{"PingStatus": "Online"}] if online else []}
        client.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
        client.exceptions.InvocationDoesNotExist = type("IDNE", (Exception,), {})
        return client

    def state(self):
        return base_state(analysis_volumes=[
            {"analysis_volume_id": "vol-0cccccccccccccccc", "source_volume_id": "vol-0aaaaaaaaaaaaaaaa"}])

    def test_start_requires_online_agent(self):
        with mock.patch.object(scan, "local_client", return_value=self.ssm(online=False)):
            with self.assertRaises(scan.WorkstationNotReady):
                scan.start_handler(self.state(), None)

    def test_start_builds_validated_command(self):
        client = self.ssm()
        with mock.patch.object(scan, "local_client", return_value=client):
            out = scan.start_handler(self.state(), None)
        self.assertEqual(out["scan"]["command_id"], "cmd-1")
        cmd = client.send_command.call_args.kwargs["Parameters"]["commands"][-1]
        self.assertIn("--volumes vol-0cccccccccccccccc:vol-0aaaaaaaaaaaaaaaa", cmd)

    def test_start_rejects_injected_volume_id(self):
        state = self.state()
        state["analysis_volumes"][0]["analysis_volume_id"] = "vol-1;curl evil"
        with mock.patch.object(scan, "local_client", return_value=self.ssm()), self.assertRaises(ValueError):
            scan.start_handler(state, None)

    def test_check_statuses(self):
        client = self.ssm()
        state = self.state()
        state["scan"] = {"command_id": "cmd-1", "status": "InProgress"}
        with mock.patch.object(scan, "local_client", return_value=client):
            client.get_command_invocation.return_value = {"Status": "InProgress"}
            self.assertEqual(scan.check_handler(state, None)["scan"]["status"], "InProgress")
            client.get_command_invocation.return_value = {"Status": "Success"}
            self.assertEqual(scan.check_handler(state, None)["scan"]["status"], "Success")
            client.get_command_invocation.return_value = {"Status": "Failed", "StandardErrorContent": "boom"}
            with self.assertRaises(scan.ScanFailed):
                scan.check_handler(state, None)


class VolumeTests(Base):
    def test_starts_stopped_workstation_and_asks_for_retry(self):
        ec2 = mock.MagicMock()
        ec2.describe_instances.return_value = instance(State={"Name": "stopped"})
        with mock.patch.object(volumes, "forensics_ec2", return_value=ec2), self.assertRaises(common.WorkstationNotReady):
            volumes.attach_handler(base_state(snapshots=[]), None)
        ec2.start_instances.assert_called_once()

    def test_attaches_each_evidence_copy_to_a_free_device(self):
        ec2 = mock.MagicMock()
        ec2.describe_instances.return_value = instance(BlockDeviceMappings=[{"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-r"}},
                                                                            {"DeviceName": "/dev/sdf", "Ebs": {"VolumeId": "vol-x"}}])
        ec2.create_volume.side_effect = [{"VolumeId": "vol-a1"}, {"VolumeId": "vol-a2"}]
        state = base_state(snapshots=[{"volume_id": "vol-1", "device": "/dev/xvda", "evidence_snapshot_id": "snap-1"},
                                      {"volume_id": "vol-2", "device": "/dev/sdf", "evidence_snapshot_id": "snap-2"}])
        with mock.patch.object(volumes, "forensics_ec2", return_value=ec2), mock.patch.object(volumes, "update_case"):
            out = volumes.attach_handler(state, None)
        self.assertEqual([v["workstation_device"] for v in out["analysis_volumes"]], ["/dev/sdg", "/dev/sdh"])
        self.assertTrue(ec2.create_volume.call_args.kwargs["Encrypted"])


class CleanupTests(Base):
    def test_never_deletes_evidence_snapshot(self):
        fx, src = mock.MagicMock(), mock.MagicMock()
        fx.describe_volumes.return_value = {"Volumes": [{"VolumeId": "vol-c", "State": "in-use"}]}
        state = base_state(snapshot_phase="encrypted", snapshots_ready=True,
                           snapshots=[{"volume_id": "vol-a", "device": "d", "source_snapshot_id": "snap-src",
                                       "encrypted_snapshot_id": "snap-ev", "evidence_snapshot_id": "snap-ev"}],
                           analysis_volumes=[{"analysis_volume_id": "vol-c"}])
        with mock.patch.object(cleanup, "forensics_ec2", return_value=fx), \
                mock.patch.object(cleanup, "source_ec2", return_value=src):
            out = cleanup.handler(state, None)
        fx.detach_volume.assert_called_once_with(VolumeId="vol-c")
        fx.delete_volume.assert_called_once_with(VolumeId="vol-c")
        src.delete_snapshot.assert_called_once_with(SnapshotId="snap-src")
        self.assertTrue(out["cleanup"]["completed"])

    def test_failure_path_keeps_all_snapshots(self):
        fx, src = mock.MagicMock(), mock.MagicMock()
        fx.describe_volumes.return_value = {"Volumes": []}
        state = base_state(error={"Error": "X"}, snapshot_phase="encrypted", snapshots_ready=True,
                           snapshots=[{"volume_id": "v", "device": "d", "source_snapshot_id": "s1", "evidence_snapshot_id": "s2"}])
        with mock.patch.object(cleanup, "forensics_ec2", return_value=fx), \
                mock.patch.object(cleanup, "source_ec2", return_value=src):
            cleanup.handler(state, None)
        src.delete_snapshot.assert_not_called()


class IsolateTests(Base):
    def test_moves_every_eni_to_quarantine_group(self):
        ec2 = mock.MagicMock()
        ec2.describe_instances.return_value = instance(NetworkInterfaces=[
            {"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-1"}]},
            {"NetworkInterfaceId": "eni-2", "Groups": [{"GroupId": "sg-2"}]}])
        ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        ec2.create_security_group.return_value = {"GroupId": "sg-q"}
        with mock.patch.object(isolate, "source_ec2", return_value=ec2):
            out = isolate.handler(base_state(isolate=True), None)
        ec2.revoke_security_group_egress.assert_called_once()
        self.assertEqual(ec2.modify_network_interface_attribute.call_count, 2)
        self.assertEqual(out["isolation"]["previous_security_groups"], {"eni-1": ["sg-1"], "eni-2": ["sg-2"]})


class StateMachineDefinitionTests(unittest.TestCase):
    def test_asl_template_is_valid_json_and_all_transitions_exist(self):
        path = os.path.join(ROOT, "terraform", "templates", "state_machine.asl.json")
        with open(path) as fh:
            raw = fh.read()
        import re
        rendered = re.sub(r"\$\{(execution_timeout|approval_timeout)\}", "3600", raw)
        rendered = re.sub(r"\$\{[a-z_]+\}", "arn:aws:lambda:us-east-1:111111111111:function:x", rendered)
        asl = json.loads(rendered)
        states = asl["States"]
        self.assertIn(asl["StartAt"], states)
        targets = set()
        for name, st in states.items():
            if "Next" in st:
                targets.add(st["Next"])
            for c in st.get("Catch", []):
                targets.add(c["Next"])
            for c in st.get("Choices", []):
                targets.add(c["Next"])
            if "Default" in st:
                targets.add(st["Default"])
        self.assertTrue(targets <= set(states), f"undefined states: {targets - set(states)}")
        unreachable = set(states) - targets - {asl["StartAt"]}
        self.assertFalse(unreachable, f"unreachable states: {unreachable}")


if __name__ == "__main__":
    unittest.main()
