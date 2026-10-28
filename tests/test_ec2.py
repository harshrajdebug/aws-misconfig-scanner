from misconfig.checks.ec2 import _covers_admin_port
from misconfig.models import Status

from .conftest import REGION, client


def _sg(name, perms):
    ec2 = client("ec2")
    vpc = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"][0]["VpcId"]
    gid = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc)["GroupId"]
    if perms:
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    return f"{gid} ({name}, {REGION})"


def test_covers_admin_port():
    assert _covers_admin_port("-1", None, None) == [22, 3389]
    assert _covers_admin_port("tcp", 0, 1024) == [22]
    assert _covers_admin_port("tcp", 3389, 3389) == [3389]
    assert _covers_admin_port("tcp", 80, 443) == []
    assert _covers_admin_port("icmp", -1, -1) == []
    assert _covers_admin_port("6", 22, 22) == [22]


def test_sg_admin_ports_ipv4(scan):
    ssh = _sg("ssh-world", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    wide = _sg("range-world", [{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    allp = _sg("all-world", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    office = _sg("ssh-office", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.0/24"}]}])
    web = _sg("web-world", [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    r = scan("ec2-sg-admin-ports-ipv4")
    assert r[ssh] == (Status.FAIL, "0.0.0.0/0 can reach port(s) [22]")
    assert r[wide] == (Status.FAIL, "0.0.0.0/0 can reach port(s) [22, 3389]")
    assert r[allp][0] is Status.FAIL
    assert r[office][0] is Status.PASS
    assert r[web][0] is Status.PASS


def test_sg_admin_ports_ipv6(scan):
    rdp6 = _sg("rdp-v6", [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    r = scan("ec2-sg-admin-ports-ipv6")
    assert r[rdp6] == (Status.FAIL, "::/0 can reach port(s) [3389]")
    assert scan("ec2-sg-admin-ports-ipv4")[rdp6][0] is Status.PASS


def test_nacl_rule_order(scan):
    ec2 = client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]

    def nacl(entries):
        acl = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
        for num, action, frm, to in entries:
            ec2.create_network_acl_entry(NetworkAclId=acl, RuleNumber=num, Protocol="6", RuleAction=action,
                                         Egress=False, CidrBlock="0.0.0.0/0", PortRange={"From": frm, "To": to})
        return f"{acl} ({REGION})"

    open_acl = nacl([(100, "allow", 0, 65535)])
    denied_first = nacl([(90, "deny", 22, 22), (91, "deny", 3389, 3389), (100, "allow", 0, 65535)])
    allow_first = nacl([(90, "allow", 0, 65535), (100, "deny", 22, 22)])
    r = scan("ec2-nacl-admin-ports")
    assert r[open_acl] == (Status.FAIL, "0.0.0.0/0 allowed to port(s) [22, 3389]")
    assert r[denied_first][0] is Status.PASS
    assert r[allow_first][0] is Status.FAIL


def test_default_sg_has_rules_by_default(scan):
    r = scan("ec2-default-sg-restricted")
    defaults = [v for k, v in r.items() if "(default," in k]
    # A new VPC's default group allows all traffic from itself and all egress.
    assert defaults and all(s is Status.FAIL for s, _ in defaults)


def test_default_sg_after_removing_rules(scan):
    ec2 = client("ec2")
    group = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["default"]}])["SecurityGroups"][0]
    if group["IpPermissions"]:
        ec2.revoke_security_group_ingress(GroupId=group["GroupId"], IpPermissions=group["IpPermissions"])
    if group["IpPermissionsEgress"]:
        ec2.revoke_security_group_egress(GroupId=group["GroupId"], IpPermissions=group["IpPermissionsEgress"])
    assert scan("ec2-default-sg-restricted")[f"{group['GroupId']} (default, {REGION})"][0] is Status.PASS


def test_vpc_flow_logs(scan):
    ec2 = client("ec2")
    logged = ec2.create_vpc(CidrBlock="10.2.0.0/16")["Vpc"]["VpcId"]
    unlogged = ec2.create_vpc(CidrBlock="10.3.0.0/16")["Vpc"]["VpcId"]
    client("s3").create_bucket(Bucket="flow-logs")
    ec2.create_flow_logs(ResourceIds=[logged], ResourceType="VPC", TrafficType="REJECT",
                         LogDestinationType="s3", LogDestination="arn:aws:s3:::flow-logs")
    r = scan("ec2-vpc-flow-logs")
    assert r[f"{logged} ({REGION})"][0] is Status.PASS
    assert r[f"{unlogged} ({REGION})"][0] is Status.FAIL


def test_ebs_default_encryption(scan):
    key = f"ebs-default-encryption ({REGION})"
    assert scan("ec2-ebs-default-encryption")[key][0] is Status.FAIL
    client("ec2").enable_ebs_encryption_by_default()
    assert scan("ec2-ebs-default-encryption")[key][0] is Status.PASS


def test_imdsv2(scan):
    ec2 = client("ec2")
    ami = ec2.describe_images()["Images"][0]["ImageId"]
    v1 = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1,
                           MetadataOptions={"HttpTokens": "optional"})["Instances"][0]["InstanceId"]
    v2 = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1,
                           MetadataOptions={"HttpTokens": "required"})["Instances"][0]["InstanceId"]
    r = scan("ec2-imdsv2")
    assert r[f"{v1} ({REGION})"] == (Status.FAIL, "HttpTokens is optional, so IMDSv1 is allowed")
    assert r[f"{v2} ({REGION})"][0] is Status.PASS
