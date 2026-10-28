import json

from misconfig.models import Status

from .conftest import client

FULL_BPA = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}


def _bucket(name, policy=None, bpa=None, acl=None):
    s3 = client("s3")
    s3.create_bucket(Bucket=name)
    if bpa is not None:
        s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=bpa)
    if acl:
        s3.put_bucket_acl(Bucket=name, ACL=acl)
    if policy:
        s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))


def _arn(name):
    return f"arn:aws:s3:::{name}"


PUBLIC_READ = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::open/*"}]}
TLS_ONLY = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": ["arn:aws:s3:::locked", "arn:aws:s3:::locked/*"],
     "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}


def test_block_public_access(scan):
    _bucket("open")
    _bucket("locked", bpa=FULL_BPA)
    _bucket("partial", bpa={**FULL_BPA, "RestrictPublicBuckets": False})
    r = scan("s3-block-public-access")
    assert r[_arn("open")][0] is Status.FAIL
    assert r[_arn("locked")][0] is Status.PASS
    assert r[_arn("partial")] == (Status.FAIL, "not enabled at bucket or account level: RestrictPublicBuckets")


def test_account_level_block_public_access_covers_buckets(scan, ctx):
    _bucket("open")
    client("s3control").put_public_access_block(AccountId=ctx.account_id, PublicAccessBlockConfiguration=FULL_BPA)
    assert scan("s3-block-public-access")[_arn("open")][0] is Status.PASS


def test_public_bucket_by_policy_and_acl(scan):
    _bucket("open", policy=PUBLIC_READ)
    _bucket("acl-open", acl="public-read")
    _bucket("blocked", policy=PUBLIC_READ | {"Statement": [PUBLIC_READ["Statement"][0] | {"Resource": "arn:aws:s3:::blocked/*"}]})
    client("s3").put_public_access_block(Bucket="blocked", PublicAccessBlockConfiguration=FULL_BPA)
    _bucket("private")
    r = scan("s3-public-bucket")
    assert r[_arn("open")][0] is Status.FAIL and "s3:GetObject to anyone" in r[_arn("open")][1]
    assert r[_arn("acl-open")][0] is Status.FAIL and "AllUsers" in r[_arn("acl-open")][1]
    assert r[_arn("blocked")][0] is Status.PASS
    assert r[_arn("private")][0] is Status.PASS


def test_tls_only(scan):
    _bucket("locked", policy=TLS_ONLY)
    _bucket("plain")
    r = scan("s3-tls-only")
    assert r[_arn("locked")][0] is Status.PASS
    assert r[_arn("plain")][0] is Status.FAIL


def test_mfa_delete_off_by_default(scan):
    _bucket("bkt")
    assert scan("s3-mfa-delete")[_arn("bkt")][0] is Status.FAIL
