from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ..context import ScanContext, error_code
from ..models import Severity, Status
from ..registry import check

BPA_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GRANTEES = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def _buckets(ctx: ScanContext) -> list[tuple[str, str]]:
    """(name, region) for every bucket, cached for the scan."""
    cache = ctx.__dict__.setdefault("_s3_buckets", None)
    if cache is not None:
        return cache
    s3 = ctx.client("s3")
    buckets = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        location = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
        region = {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(location, location)
        buckets.append((name, region))
    ctx.__dict__["_s3_buckets"] = buckets
    return buckets


def _account_bpa(ctx: ScanContext) -> dict:
    try:
        return ctx.client("s3control").get_public_access_block(AccountId=ctx.account_id)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return {}
        raise


def _bucket_bpa(ctx: ScanContext, name: str, region: str) -> dict:
    try:
        return ctx.client("s3", region).get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return {}
        raise


def _effective_bpa(ctx: ScanContext, name: str, region: str) -> dict[str, bool]:
    account, bucket = _account_bpa(ctx), _bucket_bpa(ctx, name, region)
    return {k: bool(account.get(k) or bucket.get(k)) for k in BPA_KEYS}


def _policy(ctx: ScanContext, name: str, region: str) -> dict | None:
    try:
        return json.loads(ctx.client("s3", region).get_bucket_policy(Bucket=name)["Policy"])
    except ClientError as exc:
        if error_code(exc) == "NoSuchBucketPolicy":
            return None
        raise


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def _statements(policy: dict | None) -> list[dict]:
    return _as_list(policy.get("Statement", [])) if policy else []


def _is_anyone(principal) -> bool:
    if principal == "*":
        return True
    return isinstance(principal, dict) and "*" in _as_list(principal.get("AWS", []))


@check("s3-account-block-public-access", "Account-level S3 Block Public Access is enabled", "s3", Severity.HIGH,
       "S3.1", "2.1.4", "2.1.4",
       "Turn on all four Block Public Access settings at the account level.", scope="global")
def account_block_public_access(ctx: ScanContext, region: str):
    account = _account_bpa(ctx)
    missing = [k for k in BPA_KEYS if not account.get(k)]
    resource = f"arn:aws:s3:::account/{ctx.account_id}"
    if missing:
        yield Status.FAIL, resource, "not enabled at account level: " + ", ".join(missing)
    else:
        yield Status.PASS, resource, "all four settings enabled for the account"


@check("s3-block-public-access", "S3 buckets have Block Public Access enabled", "s3", Severity.HIGH,
       "S3.8", "2.1.4", "2.1.4",
       "Turn on all four Block Public Access settings for the account, or for each bucket.", scope="global")
def block_public_access(ctx: ScanContext, region: str):
    for name, bucket_region in _buckets(ctx):
        bpa = _effective_bpa(ctx, name, bucket_region)
        missing = [k for k in BPA_KEYS if not bpa[k]]
        if missing:
            yield Status.FAIL, f"arn:aws:s3:::{name}", "not enabled at bucket or account level: " + ", ".join(missing)
        else:
            yield Status.PASS, f"arn:aws:s3:::{name}", "all four settings enabled"


@check("s3-public-bucket", "No S3 bucket is open to the public", "s3", Severity.CRITICAL,
       "S3.2/S3.3", "", "",
       "Remove AllUsers and AuthenticatedUsers grants and Principal \"*\" Allow statements, and enable Block Public Access.",
       scope="global")
def public_bucket(ctx: ScanContext, region: str):
    for name, bucket_region in _buckets(ctx):
        resource = f"arn:aws:s3:::{name}"
        bpa = _effective_bpa(ctx, name, bucket_region)
        reasons = []
        if not bpa["IgnorePublicAcls"]:
            acl = ctx.client("s3", bucket_region).get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                uri = grant.get("Grantee", {}).get("URI", "")
                if uri in PUBLIC_GRANTEES:
                    reasons.append(f"ACL grants {grant['Permission']} to {uri.rsplit('/', 1)[-1]}")
        if not bpa["RestrictPublicBuckets"]:
            for st in _statements(_policy(ctx, name, bucket_region)):
                if st.get("Effect") == "Allow" and _is_anyone(st.get("Principal")) and not st.get("Condition"):
                    reasons.append("policy allows " + ", ".join(map(str, _as_list(st.get("Action", [])))) + " to anyone")
        if reasons:
            yield Status.FAIL, resource, "; ".join(reasons)
        else:
            yield Status.PASS, resource, "no public ACL grant or policy statement in effect"


def _denies_insecure_transport(policy: dict | None) -> bool:
    for st in _statements(policy):
        if st.get("Effect") != "Deny" or not _is_anyone(st.get("Principal")):
            continue
        actions = [a.lower() for a in map(str, _as_list(st.get("Action", [])))]
        if not ({"s3:*", "*"} & set(actions)):
            continue
        cond = st.get("Condition", {}).get("Bool", {})
        value = cond.get("aws:SecureTransport", cond.get("aws:securetransport"))
        if str(value).lower() == "false":
            return True
    return False


@check("s3-tls-only", "S3 bucket policies deny requests without TLS", "s3", Severity.MEDIUM,
       "S3.5", "2.1.1", "2.1.1",
       "Add a Deny statement for s3:* with Condition Bool aws:SecureTransport false to the bucket policy.", scope="global")
def tls_only(ctx: ScanContext, region: str):
    for name, bucket_region in _buckets(ctx):
        resource = f"arn:aws:s3:::{name}"
        if _denies_insecure_transport(_policy(ctx, name, bucket_region)):
            yield Status.PASS, resource, "policy denies aws:SecureTransport false"
        else:
            yield Status.FAIL, resource, "no policy statement denies plain HTTP requests"


@check("s3-mfa-delete", "S3 buckets have MFA delete enabled", "s3", Severity.LOW,
       "S3.20", "2.1.2", "2.1.2",
       "Enable versioning with MFA delete using the root user's MFA device.", scope="global")
def mfa_delete(ctx: ScanContext, region: str):
    for name, bucket_region in _buckets(ctx):
        versioning = ctx.client("s3", bucket_region).get_bucket_versioning(Bucket=name)
        if versioning.get("MFADelete") == "Enabled":
            yield Status.PASS, f"arn:aws:s3:::{name}", "MFA delete enabled"
        else:
            yield Status.FAIL, f"arn:aws:s3:::{name}", f"versioning {versioning.get('Status', 'off')}, MFA delete off"
