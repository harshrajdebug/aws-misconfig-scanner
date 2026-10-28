from __future__ import annotations

from ..context import ScanContext
from ..models import Severity, Status
from ..registry import check


def _instances(ctx: ScanContext, region: str):
    for page in ctx.client("rds", region).get_paginator("describe_db_instances").paginate():
        yield from page["DBInstances"]


@check("rds-public-access", "RDS instances are not publicly accessible", "rds", Severity.CRITICAL,
       "RDS.2", "2.2.3", "2.3.3", "Set PubliclyAccessible to false and reach the database through private networking.")
def public_access(ctx: ScanContext, region: str):
    for db in _instances(ctx, region):
        if db.get("PubliclyAccessible"):
            yield Status.FAIL, db["DBInstanceArn"], "PubliclyAccessible is true"
        else:
            yield Status.PASS, db["DBInstanceArn"], "not publicly accessible"


@check("rds-encryption", "RDS instances are encrypted at rest", "rds", Severity.HIGH,
       "RDS.3", "2.2.1", "2.3.1", "Restore an encrypted copy from a snapshot; encryption cannot be turned on in place.")
def encryption(ctx: ScanContext, region: str):
    for db in _instances(ctx, region):
        if db.get("StorageEncrypted"):
            yield Status.PASS, db["DBInstanceArn"], "storage encrypted"
        else:
            yield Status.FAIL, db["DBInstanceArn"], "storage not encrypted"


@check("rds-minor-version-upgrade", "RDS automatic minor version upgrades are on", "rds", Severity.LOW,
       "RDS.13", "2.2.2", "2.3.2", "Set AutoMinorVersionUpgrade to true so security patches are applied.")
def minor_version_upgrade(ctx: ScanContext, region: str):
    for db in _instances(ctx, region):
        if db.get("AutoMinorVersionUpgrade"):
            yield Status.PASS, db["DBInstanceArn"], "enabled"
        else:
            yield Status.FAIL, db["DBInstanceArn"], "disabled"
