"""Step 10 (optional): contain the suspect instance.

Replaces every ENI's security groups with a quarantine group that has no
inbound or outbound rules and tags the instance. The previous security groups
are recorded so the change can be reverted after the investigation.
Note: security groups are stateful; already-tracked connections may persist
until they time out. Pair with a NACL change for immediate cut-off.
"""
from common import append_history, publish, source_ec2, update_case

QUARANTINE_SG_NAME = "forensics-quarantine"


def _quarantine_sg(ec2, vpc_id, state):
    found = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": [QUARANTINE_SG_NAME]}]
    )["SecurityGroups"]
    if found:
        return found[0]["GroupId"]
    sg_id = ec2.create_security_group(
        GroupName=QUARANTINE_SG_NAME,
        Description="Forensics quarantine - no inbound or outbound traffic",
        VpcId=vpc_id,
        TagSpecifications=[{
            "ResourceType": "security-group",
            "Tags": [{"Key": "Name", "Value": QUARANTINE_SG_NAME}, {"Key": "ManagedBy", "Value": "aws-automated-ec2-forensics"}],
        }],
    )["GroupId"]
    ec2.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    return sg_id


def handler(state, _context):
    ec2 = source_ec2(state)
    inst = ec2.describe_instances(InstanceIds=[state["instance_id"]])["Reservations"][0]["Instances"][0]
    sg_id = _quarantine_sg(ec2, inst["VpcId"], state)

    previous = {}
    for eni in inst.get("NetworkInterfaces", []):
        previous[eni["NetworkInterfaceId"]] = [g["GroupId"] for g in eni.get("Groups", [])]
        ec2.modify_network_interface_attribute(NetworkInterfaceId=eni["NetworkInterfaceId"], Groups=[sg_id])

    ec2.create_tags(
        Resources=[state["instance_id"]],
        Tags=[{"Key": "ForensicsStatus", "Value": "Isolated"}, {"Key": "ForensicsCase", "Value": state["case_id"]}],
    )
    state["isolation"] = {"quarantine_sg": sg_id, "previous_security_groups": previous}
    append_history(state, "instance_isolated", quarantine_sg=sg_id)
    update_case(state["case_id"], "COMPLETE_ISOLATED", isolation=state["isolation"])
    publish(
        "NOTIFY_TOPIC_ARN",
        f"[Forensics] Instance isolated: {state['instance_id']}",
        f"Case {state['case_id']}: {state['instance_id']} moved to quarantine SG {sg_id}.\n"
        f"Previous security groups: {previous}",
    )
    return state
