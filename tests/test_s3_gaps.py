"""S3 exposure that the first version missed, and Security Hub semantics it did not follow."""
import json

from misconfig.models import Status

from .conftest import REGION, client


def _public_policy(bucket, condition=None):
    st = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}
    if condition:
        st["Condition"] = condition
    return json.dumps({"Version": "2012-10-17", "Statement": [st]})


def _bucket_with_policy(name, condition=None):
    s3 = client("s3")
    s3.create_bucket(Bucket=name)
    s3.put_bucket_policy(Bucket=name, Policy=_public_policy(name, condition))
    return f"arn:aws:s3:::{name}"


def test_conditions_that_do_not_restrict_the_caller_are_still_public(scan):
    tls = _bucket_with_policy("tls-only-public", {"Bool": {"aws:SecureTransport": "true"}})
    any_ip = _bucket_with_policy("any-ip", {"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}})
    wildcard = _bucket_with_policy("wildcard-org", {"StringLike": {"aws:PrincipalOrgID": "o-*"}})
    variable = _bucket_with_policy("variable-arn", {"StringEquals": {"aws:PrincipalArn": "${aws:username}"}})
    org = _bucket_with_policy("org-only", {"StringEquals": {"aws:PrincipalOrgID": "o-abc123def4"}})
    office = _bucket_with_policy("office-ip", {"IpAddress": {"aws:SourceIp": ["203.0.113.0/24"]}})
    vpce = _bucket_with_policy("vpce-only", {"StringEquals": {"aws:SourceVpce": "vpce-0123456789abcdef0"}})
    r = scan("s3-public-bucket")
    for arn in (tls, any_ip, wildcard, variable):
        assert r[arn][0] is Status.FAIL, arn
    for arn in (org, office, vpce):
        assert r[arn][0] is Status.PASS, arn


def test_access_point_block_public_access(scan, ctx):
    s3c = client("s3control")
    client("s3").create_bucket(Bucket="ap-source")
    s3c.create_access_point(AccountId=ctx.account_id, Name="locked-ap", Bucket="ap-source")
    s3c.create_access_point(AccountId=ctx.account_id, Name="open-ap", Bucket="ap-source",
                            PublicAccessBlockConfiguration={"BlockPublicAcls": False, "IgnorePublicAcls": False,
                                                            "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
    r = scan("s3-access-point-block-public-access")
    by_name = {k.rsplit("/", 1)[-1].split(" ")[0]: v for k, v in r.items()}
    assert by_name["locked-ap"][0] is Status.PASS
    assert by_name["open-ap"][0] is Status.FAIL and "BlockPublicPolicy" in by_name["open-ap"][1]
    assert all(REGION in k for k in r)


def test_mfa_delete_skips_buckets_with_lifecycle_rules(scan):
    s3 = client("s3")
    s3.create_bucket(Bucket="with-lifecycle")
    s3.put_bucket_lifecycle_configuration(Bucket="with-lifecycle", LifecycleConfiguration={"Rules": [
        {"ID": "expire", "Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 30}}]})
    s3.create_bucket(Bucket="without-lifecycle")
    r = scan("s3-mfa-delete")
    assert "arn:aws:s3:::with-lifecycle" not in r
    assert r["arn:aws:s3:::without-lifecycle"][0] is Status.FAIL


def test_negated_and_ifexists_conditions_are_not_restrictions(scan):
    not_ip = _bucket_with_policy("not-ip", {"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}})
    if_exists = _bucket_with_policy("if-exists", {"StringEqualsIfExists": {"aws:PrincipalOrgID": "o-abc123def4"}})
    r = scan("s3-public-bucket")
    assert r[not_ip][0] is Status.FAIL
    assert r[if_exists][0] is Status.FAIL
