"""Exposure that does not use a literal 0.0.0.0/0 or ::/0 rule."""
from misconfig.models import Status

from .conftest import REGION, client


def _vpc():
    return client("ec2").describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"][0]["VpcId"]


def _sg(name, perms):
    ec2 = client("ec2")
    gid = ec2.create_security_group(GroupName=name, Description=name, VpcId=_vpc())["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    return f"{gid} ({name}, {REGION})"


def _prefix_list(name, cidrs, family="IPv4"):
    return client("ec2").create_managed_prefix_list(
        PrefixListName=name, AddressFamily=family, MaxEntries=10,
        Entries=[{"Cidr": c} for c in cidrs])["PrefixList"]["PrefixListId"]


def _ssh(**sources):
    return [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, **sources}]


def test_prefix_list_covering_the_internet(scan):
    split = _prefix_list("split", ["0.0.0.0/1", "128.0.0.0/1"])
    whole = _prefix_list("whole", ["0.0.0.0/0"])
    office = _prefix_list("office", ["203.0.113.0/24", "198.51.100.0/24"])
    a = _sg("pl-split", _ssh(PrefixListIds=[{"PrefixListId": split}]))
    b = _sg("pl-whole", _ssh(PrefixListIds=[{"PrefixListId": whole}]))
    c = _sg("pl-office", _ssh(PrefixListIds=[{"PrefixListId": office}]))
    r = scan("ec2-sg-admin-ports-ipv4")
    assert r[a] == (Status.FAIL, "0.0.0.0/0 can reach port(s) [22]")
    assert r[b][0] is Status.FAIL
    assert r[c][0] is Status.PASS


def test_split_cidrs_in_one_rule(scan):
    sg = _sg("split-ranges", _ssh(IpRanges=[{"CidrIp": "0.0.0.0/1"}, {"CidrIp": "128.0.0.0/1"}]))
    assert scan("ec2-sg-admin-ports-ipv4")[sg][0] is Status.FAIL


def test_split_cidrs_across_rules(scan):
    sg = _sg("split-rules", [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/1"}]},
        {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 1024, "IpRanges": [{"CidrIp": "128.0.0.0/1"}]},
    ])
    assert scan("ec2-sg-admin-ports-ipv4")[sg] == (Status.FAIL, "0.0.0.0/0 can reach port(s) [22]")


def test_half_the_internet_is_not_reported_as_all(scan):
    sg = _sg("half", _ssh(IpRanges=[{"CidrIp": "0.0.0.0/1"}]))
    assert scan("ec2-sg-admin-ports-ipv4")[sg][0] is Status.PASS


def test_ipv6_split_and_prefix_list(scan):
    split = _sg("v6-split", _ssh(Ipv6Ranges=[{"CidrIpv6": "::/1"}, {"CidrIpv6": "8000::/1"}]))
    pl = _prefix_list("v6-any", ["::/0"], family="IPv6")
    listed = _sg("v6-pl", _ssh(PrefixListIds=[{"PrefixListId": pl}]))
    r = scan("ec2-sg-admin-ports-ipv6")
    assert r[split] == (Status.FAIL, "::/0 can reach port(s) [22]")
    assert r[listed][0] is Status.FAIL
    # An IPv6 prefix list must not be reported by the IPv4 check.
    assert scan("ec2-sg-admin-ports-ipv4")[listed][0] is Status.PASS


def test_nacl_ipv6(scan):
    ec2 = client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.9.0.0/16", AmazonProvidedIpv6CidrBlock=True)["Vpc"]["VpcId"]

    def nacl(entries):
        acl = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
        for num, action, port in entries:
            ec2.create_network_acl_entry(NetworkAclId=acl, RuleNumber=num, Protocol="6", RuleAction=action, Egress=False,
                                         Ipv6CidrBlock="::/0", PortRange={"From": port[0], "To": port[1]})
        return f"{acl} ({REGION})"

    open_v6 = nacl([(100, "allow", (0, 65535))])
    guarded = nacl([(50, "deny", (22, 22)), (51, "deny", (3389, 3389)), (100, "allow", (0, 65535))])
    r = scan("ec2-nacl-admin-ports")
    assert r[open_v6] == (Status.FAIL, "::/0 allowed to port(s) [22, 3389]")
    assert r[guarded][0] is Status.PASS
