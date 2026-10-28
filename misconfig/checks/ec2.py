from __future__ import annotations

import ipaddress

from ..context import ScanContext
from ..models import Severity, Status
from ..registry import check

ADMIN_PORTS = (22, 3389)
ANY_V4 = "0.0.0.0/0"
ANY_V6 = "::/0"


def _covers_admin_port(protocol: str, from_port, to_port) -> list[int]:
    """Admin ports reachable through a rule. Protocol "-1" means every protocol and port;
    an all-protocol NACL entry has no PortRange."""
    if str(protocol) in ("-1", "all"):
        return list(ADMIN_PORTS)
    if str(protocol) not in ("tcp", "6", "udp", "17"):
        return []
    if from_port is None or to_port is None:
        return list(ADMIN_PORTS)
    return [p for p in ADMIN_PORTS if from_port <= p <= to_port]


def _security_groups(ctx: ScanContext, region: str):
    for page in ctx.client("ec2", region).get_paginator("describe_security_groups").paginate():
        yield from page["SecurityGroups"]


def _prefix_list_cidrs(ctx: ScanContext, region: str, prefix_list_id: str) -> list[str]:
    cache = ctx.__dict__.setdefault("_prefix_lists", {})
    key = (region, prefix_list_id)
    if key not in cache:
        ec2 = ctx.client("ec2", region)
        cidrs = []
        for page in ec2.get_paginator("get_managed_prefix_list_entries").paginate(PrefixListId=prefix_list_id):
            cidrs.extend(e["Cidr"] for e in page["Entries"])
        cache[key] = cidrs
    return cache[key]


def _covers_everything(cidrs: list[str], version: int) -> bool:
    """True if the CIDRs of one IP version together cover the whole address space, so
    0.0.0.0/1 plus 128.0.0.0/1 counts the same as 0.0.0.0/0."""
    nets = [n for n in (ipaddress.ip_network(c, strict=False) for c in cidrs) if n.version == version]
    return any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(nets))


def _open_admin_ports(ctx: ScanContext, region: str, group: dict, version: int) -> list[int]:
    reachable: dict[int, list[str]] = {p: [] for p in ADMIN_PORTS}
    for perm in group.get("IpPermissions", []):
        ports = _covers_admin_port(perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort"))
        if not ports:
            continue
        cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])] + [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
        for pl in perm.get("PrefixListIds", []):
            cidrs.extend(_prefix_list_cidrs(ctx, region, pl["PrefixListId"]))
        for port in ports:
            reachable[port].extend(cidrs)
    return [p for p in ADMIN_PORTS if _covers_everything(reachable[p], version)]


def _sg_resource(group: dict, region: str) -> str:
    return f"{group['GroupId']} ({group.get('GroupName', '')}, {region})"


@check("ec2-sg-admin-ports-ipv4", "No security group allows 0.0.0.0/0 to SSH or RDP", "ec2", Severity.HIGH,
       "EC2.53", "5.3", "5.2", "Restrict port 22 and 3389 ingress to known address ranges, or use SSM Session Manager.")
def sg_admin_ports_ipv4(ctx: ScanContext, region: str):
    for group in _security_groups(ctx, region):
        ports = _open_admin_ports(ctx, region, group, 4)
        if ports:
            yield Status.FAIL, _sg_resource(group, region), f"0.0.0.0/0 can reach port(s) {ports}"
        else:
            yield Status.PASS, _sg_resource(group, region), "no admin port open to 0.0.0.0/0"


@check("ec2-sg-admin-ports-ipv6", "No security group allows ::/0 to SSH or RDP", "ec2", Severity.HIGH,
       "EC2.54", "5.4", "5.3", "Restrict port 22 and 3389 ingress to known IPv6 ranges, or use SSM Session Manager.")
def sg_admin_ports_ipv6(ctx: ScanContext, region: str):
    for group in _security_groups(ctx, region):
        ports = _open_admin_ports(ctx, region, group, 6)
        if ports:
            yield Status.FAIL, _sg_resource(group, region), f"::/0 can reach port(s) {ports}"
        else:
            yield Status.PASS, _sg_resource(group, region), "no admin port open to ::/0"


@check("ec2-nacl-admin-ports", "No network ACL allows 0.0.0.0/0 to SSH or RDP", "ec2", Severity.MEDIUM,
       "EC2.21", "5.2", "5.1", "Add a deny entry for ports 22 and 3389 from 0.0.0.0/0 ahead of any broad allow entry.")
def nacl_admin_ports(ctx: ScanContext, region: str):
    acls = ctx.client("ec2", region).describe_network_acls()["NetworkAcls"]
    for acl in acls:
        resource = f"{acl['NetworkAclId']} ({region})"
        # NACL entries are evaluated in rule-number order and the first match wins, so an
        # admin port is exposed only if an allow entry matches before any deny entry does.
        # IPv4 and IPv6 entries are separate rule sets.
        ingress = sorted((e for e in acl.get("Entries", []) if not e.get("Egress")), key=lambda e: e["RuleNumber"])
        exposed = []
        for anywhere, field in ((ANY_V4, "CidrBlock"), (ANY_V6, "Ipv6CidrBlock")):
            for port in ADMIN_PORTS:
                for entry in ingress:
                    if entry.get(field) != anywhere:
                        continue
                    pr = entry.get("PortRange", {})
                    if port not in _covers_admin_port(entry.get("Protocol"), pr.get("From"), pr.get("To")):
                        continue
                    if entry.get("RuleAction") == "allow":
                        exposed.append((anywhere, port))
                    break
        if exposed:
            by_source = {}
            for anywhere, port in exposed:
                by_source.setdefault(anywhere, []).append(port)
            detail = "; ".join(f"{src} allowed to port(s) {ports}" for src, ports in by_source.items())
            yield Status.FAIL, resource, detail
        else:
            yield Status.PASS, resource, "admin ports not allowed from 0.0.0.0/0 or ::/0"


@check("ec2-default-sg-restricted", "Default security groups allow no traffic", "ec2", Severity.MEDIUM,
       "EC2.2", "5.5", "5.4", "Remove every inbound and outbound rule from each VPC's default security group.")
def default_sg(ctx: ScanContext, region: str):
    for group in _security_groups(ctx, region):
        if group.get("GroupName") != "default":
            continue
        rules = len(group.get("IpPermissions", [])) + len(group.get("IpPermissionsEgress", []))
        if rules:
            yield Status.FAIL, _sg_resource(group, region), f"{rules} rule(s) present"
        else:
            yield Status.PASS, _sg_resource(group, region), "no rules"


@check("ec2-vpc-flow-logs", "VPC flow logging is enabled", "ec2", Severity.MEDIUM,
       "EC2.6", "3.7", "3.7", "Create a flow log for each VPC that captures at least REJECT traffic.")
def vpc_flow_logs(ctx: ScanContext, region: str):
    ec2 = ctx.client("ec2", region)
    logged = {fl["ResourceId"] for fl in ec2.describe_flow_logs()["FlowLogs"]}
    for vpc in ec2.describe_vpcs()["Vpcs"]:
        resource = f"{vpc['VpcId']} ({region})"
        if vpc["VpcId"] in logged:
            yield Status.PASS, resource, "flow log present"
        else:
            yield Status.FAIL, resource, "no flow log"


@check("ec2-ebs-default-encryption", "EBS encryption by default is enabled", "ec2", Severity.MEDIUM,
       "EC2.7", "5.1.1", "2.2.1", "Enable EBS encryption by default in every region you use.")
def ebs_default_encryption(ctx: ScanContext, region: str):
    enabled = ctx.client("ec2", region).get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    status = Status.PASS if enabled else Status.FAIL
    yield status, f"ebs-default-encryption ({region})", "enabled" if enabled else "disabled"


@check("ec2-imdsv2", "EC2 instances require IMDSv2", "ec2", Severity.HIGH,
       "EC2.8", "5.7", "5.6", "Set HttpTokens to required on each instance and in launch templates.")
def imdsv2(ctx: ScanContext, region: str):
    pages = ctx.client("ec2", region).get_paginator("describe_instances").paginate()
    for page in pages:
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                if inst.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                    continue
                tokens = inst.get("MetadataOptions", {}).get("HttpTokens", "optional")
                resource = f"{inst['InstanceId']} ({region})"
                if tokens == "required":
                    yield Status.PASS, resource, "IMDSv2 required"
                else:
                    yield Status.FAIL, resource, f"HttpTokens is {tokens}, so IMDSv1 is allowed"
