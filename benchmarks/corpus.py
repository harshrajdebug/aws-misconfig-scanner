"""Labelled benchmark: build known-good and known-bad resources in moto, scan them, and
report precision and recall.

Each scenario runs in its own emulated account and returns the expected status for
specific resources. Some cases are traps in both directions: exposure that does not use a
literal 0.0.0.0/0, and safe setups that look risky.

    python benchmarks/corpus.py
"""
from __future__ import annotations

import json
import os
import sys

for k, v in {"AWS_ACCESS_KEY_ID": "bench", "AWS_SECRET_ACCESS_KEY": "bench", "AWS_DEFAULT_REGION": "us-east-1"}.items():
    os.environ[k] = v
os.environ.pop("AWS_PROFILE", None)

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from misconfig.context import ScanContext  # noqa: E402
from misconfig.registry import CHECKS  # noqa: E402
from misconfig.scanner import run  # noqa: E402

REGION = "us-east-1"
FULL_BPA = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
NO_BPA = {k: False for k in FULL_BPA}
SCENARIOS = []


def scenario(func):
    SCENARIOS.append(func)
    return func


def c(service):
    return boto3.client(service, region_name=REGION)


def _sg(name, perms):
    ec2 = c("ec2")
    vpc = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"][0]["VpcId"]
    gid = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    return gid


def _port(port, **src):
    return [{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, **src}]


def _pl(name, cidrs, family="IPv4"):
    return c("ec2").create_managed_prefix_list(PrefixListName=name, AddressFamily=family, MaxEntries=10,
                                               Entries=[{"Cidr": x} for x in cidrs])["PrefixList"]["PrefixListId"]


@scenario
def network():
    w = [{"CidrIp": "0.0.0.0/0"}]
    return [
        ("ec2-sg-admin-ports-ipv4", _sg("ssh-world", _port(22, IpRanges=w)), "FAIL"),
        ("ec2-sg-admin-ports-ipv6", _sg("rdp-v6", _port(3389, Ipv6Ranges=[{"CidrIpv6": "::/0"}])), "FAIL"),
        ("ec2-sg-admin-ports-ipv4", _sg("all-traffic", [{"IpProtocol": "-1", "IpRanges": w}]), "FAIL"),
        ("ec2-sg-admin-ports-ipv4", _sg("wide-range", [{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": w}]), "FAIL"),
        ("ec2-sg-admin-ports-ipv4", _sg("split-cidrs", _port(22, IpRanges=[{"CidrIp": "0.0.0.0/1"}, {"CidrIp": "128.0.0.0/1"}])), "FAIL"),
        ("ec2-sg-admin-ports-ipv4", _sg("split-rules", _port(22, IpRanges=[{"CidrIp": "0.0.0.0/1"}])
                                         + [{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 1024, "IpRanges": [{"CidrIp": "128.0.0.0/1"}]}]), "FAIL"),
        ("ec2-sg-admin-ports-ipv4", _sg("pl-split", _port(22, PrefixListIds=[{"PrefixListId": _pl("split", ["0.0.0.0/1", "128.0.0.0/1"])}])), "FAIL"),
        ("ec2-sg-admin-ports-ipv6", _sg("v6-split", _port(22, Ipv6Ranges=[{"CidrIpv6": "::/1"}, {"CidrIpv6": "8000::/1"}])), "FAIL"),
        ("ec2-sg-admin-ports-ipv4", _sg("pl-office", _port(22, PrefixListIds=[{"PrefixListId": _pl("office", ["203.0.113.0/24"])}])), "PASS"),
        ("ec2-sg-admin-ports-ipv4", _sg("ssh-office", _port(22, IpRanges=[{"CidrIp": "203.0.113.0/24"}])), "PASS"),
        ("ec2-sg-admin-ports-ipv4", _sg("https-world", _port(443, IpRanges=w)), "PASS"),
        ("ec2-sg-admin-ports-ipv4", _sg("half-internet", _port(22, IpRanges=[{"CidrIp": "0.0.0.0/1"}])), "PASS"),
    ]


@scenario
def network_acls():
    ec2 = c("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.7.0.0/16", AmazonProvidedIpv6CidrBlock=True)["Vpc"]["VpcId"]

    def acl(entries):
        acl_id = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
        for num, action, lo, hi, v6 in entries:
            src = {"Ipv6CidrBlock": "::/0"} if v6 else {"CidrBlock": "0.0.0.0/0"}
            ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=num, Protocol="6", RuleAction=action, Egress=False,
                                         PortRange={"From": lo, "To": hi}, **src)
        return acl_id

    return [
        ("ec2-nacl-admin-ports", acl([(100, "allow", 0, 65535, False)]), "FAIL"),
        ("ec2-nacl-admin-ports", acl([(50, "deny", 22, 22, False), (51, "deny", 3389, 3389, False), (100, "allow", 0, 65535, False)]), "PASS"),
        ("ec2-nacl-admin-ports", acl([(100, "allow", 0, 65535, True)]), "FAIL"),
        ("ec2-nacl-admin-ports", acl([(90, "allow", 0, 65535, False), (100, "deny", 22, 22, False)]), "FAIL"),
    ]


def _bucket(name, statement_condition=None, bpa=None, acl=None, public=True):
    s3 = c("s3")
    s3.create_bucket(Bucket=name)
    if bpa is not None:
        s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=bpa)
    if acl:
        s3.put_bucket_acl(Bucket=name, ACL=acl)
    if public:
        st = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{name}/*"}
        if statement_condition:
            st["Condition"] = statement_condition
        s3.put_bucket_policy(Bucket=name, Policy=json.dumps({"Version": "2012-10-17", "Statement": [st]}))
    return f"arn:aws:s3:::{name}"


@scenario
def s3_public():
    labels = [
        ("s3-public-bucket", _bucket("plain-public"), "FAIL"),
        ("s3-public-bucket", _bucket("acl-public", acl="public-read", public=False), "FAIL"),
        ("s3-public-bucket", _bucket("tls-cond", {"Bool": {"aws:SecureTransport": "true"}}), "FAIL"),
        ("s3-public-bucket", _bucket("any-ip", {"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}}), "FAIL"),
        ("s3-public-bucket", _bucket("wild-org", {"StringLike": {"aws:PrincipalOrgID": "o-*"}}), "FAIL"),
        ("s3-public-bucket", _bucket("not-ip", {"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}}), "FAIL"),
        ("s3-public-bucket", _bucket("if-exists", {"StringEqualsIfExists": {"aws:PrincipalOrgID": "o-abc123def4"}}), "FAIL"),
        ("s3-public-bucket", _bucket("org-only", {"StringEquals": {"aws:PrincipalOrgID": "o-abc123def4"}}), "PASS"),
        ("s3-public-bucket", _bucket("vpce-only", {"StringEquals": {"aws:SourceVpce": "vpce-0123456789abcdef0"}}), "PASS"),
        ("s3-public-bucket", _bucket("office-ip", {"IpAddress": {"aws:SourceIp": "198.51.100.0/24"}}), "PASS"),
        ("s3-public-bucket", _bucket("private", public=False), "PASS"),
    ]
    blocked = _bucket("blocked-by-bpa")
    c("s3").put_public_access_block(Bucket="blocked-by-bpa", PublicAccessBlockConfiguration=FULL_BPA)
    labels.append(("s3-public-bucket", blocked, "PASS"))
    return labels


@scenario
def s3_settings():
    s3, s3c = c("s3"), c("s3control")
    account = c("sts").get_caller_identity()["Account"]
    _bucket("tls-required", public=False)
    s3.put_bucket_policy(Bucket="tls-required", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": ["arn:aws:s3:::tls-required", "arn:aws:s3:::tls-required/*"],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))
    _bucket("no-tls-policy", public=False)
    s3.create_bucket(Bucket="ap-source")
    s3c.create_access_point(AccountId=account, Name="ap-default", Bucket="ap-source")
    s3c.create_access_point(AccountId=account, Name="ap-open", Bucket="ap-source", PublicAccessBlockConfiguration=NO_BPA)
    return [
        ("s3-tls-only", "arn:aws:s3:::tls-required", "PASS"),
        ("s3-tls-only", "arn:aws:s3:::no-tls-policy", "FAIL"),
        ("s3-access-point-block-public-access", "accesspoint/ap-open", "FAIL"),
        ("s3-access-point-block-public-access", "accesspoint/ap-default", "PASS"),
        ("s3-account-block-public-access", f"account/{account}", "FAIL"),
    ]


@scenario
def iam_policies():
    iam = c("iam")
    admin = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    s3_all = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
    trust = json.dumps({"Version": "2012-10-17", "Statement": []})
    managed_admin = iam.create_policy(PolicyName="managed-admin", PolicyDocument=admin)["Policy"]["Arn"]
    managed_s3 = iam.create_policy(PolicyName="managed-s3", PolicyDocument=s3_all)["Policy"]["Arn"]
    iam.create_role(RoleName="app", AssumeRolePolicyDocument=trust)
    iam.attach_role_policy(RoleName="app", PolicyArn=managed_admin)
    iam.attach_role_policy(RoleName="app", PolicyArn=managed_s3)
    iam.create_role(RoleName="inline-admin", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(RoleName="inline-admin", PolicyName="all", PolicyDocument=admin)
    iam.create_user(UserName="inline-narrow")
    iam.put_user_policy(UserName="inline-narrow", PolicyName="s3", PolicyDocument=s3_all)
    iam.create_user(UserName="console-no-mfa")
    iam.create_login_profile(UserName="console-no-mfa", Password="Bench-password-123")
    return [
        ("iam-full-admin-policy", managed_admin, "FAIL"),
        ("iam-full-admin-policy", managed_s3, "PASS"),
        ("iam-inline-admin-policy", "role/inline-admin", "FAIL"),
        ("iam-inline-admin-policy", "user/inline-narrow", "PASS"),
        ("iam-user-console-mfa", "user/console-no-mfa", "FAIL"),
        ("iam-password-length", "account-password-policy", "FAIL"),
    ]


@scenario
def compute_keys_databases():
    ec2, kms, rds = c("ec2"), c("kms"), c("rds")
    ami = ec2.describe_images()["Images"][0]["ImageId"]
    v1 = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "optional"})["Instances"][0]["InstanceId"]
    v2 = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "required"})["Instances"][0]["InstanceId"]
    off = kms.create_key()["KeyMetadata"]["Arn"]
    on = kms.create_key()["KeyMetadata"]
    kms.enable_key_rotation(KeyId=on["KeyId"])

    def db(name, public, encrypted):
        return rds.create_db_instance(DBInstanceIdentifier=name, Engine="postgres", DBInstanceClass="db.t3.micro",
                                      AllocatedStorage=20, MasterUsername="bench1", MasterUserPassword="bench-password-1",
                                      PubliclyAccessible=public, StorageEncrypted=encrypted)["DBInstance"]["DBInstanceArn"]

    public_db, private_db = db("public-db", True, False), db("private-db", False, True)
    return [
        ("ec2-imdsv2", v1, "FAIL"), ("ec2-imdsv2", v2, "PASS"),
        ("kms-key-rotation", off, "FAIL"), ("kms-key-rotation", on["Arn"], "PASS"),
        ("rds-public-access", public_db, "FAIL"), ("rds-public-access", private_db, "PASS"),
        ("rds-encryption", public_db, "FAIL"), ("rds-encryption", private_db, "PASS"),
    ]


@scenario
def cloudtrail_write_only():
    c("s3").create_bucket(Bucket="trail-logs")
    ct = c("cloudtrail")
    ct.create_trail(Name="writes", S3BucketName="trail-logs", IsMultiRegionTrail=True)
    ct.start_logging(Name="writes")
    ct.put_event_selectors(TrailName="writes", EventSelectors=[{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}])
    account = c("sts").get_caller_identity()["Account"]
    return [("cloudtrail-multi-region", f"account {account}", "FAIL")]


@scenario
def cloudtrail_good():
    c("s3").create_bucket(Bucket="trail-logs-ok")
    ct = c("cloudtrail")
    arn = ct.create_trail(Name="all", S3BucketName="trail-logs-ok", IsMultiRegionTrail=True, EnableLogFileValidation=True)["TrailARN"]
    ct.start_logging(Name="all")
    return [("cloudtrail-multi-region", arn, "PASS"), ("cloudtrail-log-validation", arn, "PASS")]


def evaluate():
    rows = []
    for build in SCENARIOS:
        with mock_aws():
            labels = build()
            ctx = ScanContext(boto3.session.Session(region_name=REGION), [REGION])
            findings = run(ctx, list(CHECKS.values()))
        for check_id, resource, expected in labels:
            if check_id not in CHECKS:
                rows.append((build.__name__, check_id, resource, expected, "MISSING"))
                continue
            got = [f.status.value for f in findings if f.check_id == check_id and resource in f.resource]
            actual = "FAIL" if "FAIL" in got else ("ERROR" if "ERROR" in got else ("PASS" if "PASS" in got else "NONE"))
            rows.append((build.__name__, check_id, resource, expected, actual))
    return rows


def main() -> int:
    rows = evaluate()
    tp = sum(1 for *_, e, a in rows if e == "FAIL" and a == "FAIL")
    fn = sum(1 for *_, e, a in rows if e == "FAIL" and a != "FAIL")
    fp = sum(1 for *_, e, a in rows if e == "PASS" and a == "FAIL")
    tn = sum(1 for *_, e, a in rows if e == "PASS" and a == "PASS")
    other = sum(1 for *_, e, a in rows if e == "PASS" and a not in ("PASS", "FAIL"))
    for scen, check_id, resource, expected, actual in rows:
        mark = "ok " if expected == actual else "XX "
        print(f"{mark} {scen:<24} {check_id:<36} {resource[-40:]:<40} expected {expected:<4} got {actual}")
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    print(f"\nlabels {len(rows)}: true positives {tp}, false negatives {fn}, false positives {fp}, "
          f"true negatives {tn}, passes not observed {other}")
    print(f"precision {precision:.3f}, recall {recall:.3f}")
    return 0 if fn == fp == other == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
