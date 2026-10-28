from __future__ import annotations

from dataclasses import dataclass, field

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .models import Finding, Status

SESSION_NAME = "misconfig-scanner"


@dataclass
class Target:
    """One account to scan: a ready session, or the reason no session could be made."""

    account_id: str
    name: str = ""
    session: boto3.session.Session | None = None
    error: str = ""
    role_arn: str = field(default="", repr=False)


def caller_account(session: boto3.session.Session) -> str:
    return session.client("sts").get_caller_identity()["Account"]


def org_accounts(session: boto3.session.Session) -> list[tuple[str, str]]:
    """(id, name) for every active account in the caller's organization. Requires the
    management account or a delegated administrator."""
    accounts = []
    for page in session.client("organizations").get_paginator("list_accounts").paginate():
        for acct in page["Accounts"]:
            if acct.get("Status", "ACTIVE") == "ACTIVE" and acct.get("State", "ACTIVE") == "ACTIVE":
                accounts.append((acct["Id"], acct.get("Name", "")))
    return sorted(accounts)


def _partition(session: boto3.session.Session) -> str:
    return session.get_partition_for_region(session.region_name or "us-east-1")


def assume(session: boto3.session.Session, account_id: str, role_name: str,
           external_id: str | None = None) -> tuple[boto3.session.Session, str]:
    role_arn = f"arn:{_partition(session)}:iam::{account_id}:role/{role_name}"
    params = {"RoleArn": role_arn, "RoleSessionName": SESSION_NAME}
    if external_id:
        params["ExternalId"] = external_id
    creds = session.client("sts").assume_role(**params)["Credentials"]
    assumed = boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"], region_name=session.region_name)
    return assumed, role_arn


def resolve(session: boto3.session.Session, accounts: list[str] | None, use_org: bool, role_name: str,
            external_id: str | None = None) -> list[Target]:
    """Build a Target per requested account. The caller's own account is scanned with the
    base session; every other account through the named role."""
    own = caller_account(session)
    if use_org:
        wanted = org_accounts(session)
    elif accounts:
        wanted = [(a, "") for a in dict.fromkeys(accounts)]
    else:
        return [Target(own, session=session)]

    targets = []
    for account_id, name in wanted:
        if account_id == own:
            targets.append(Target(account_id, name, session=session))
            continue
        try:
            assumed, arn = assume(session, account_id, role_name, external_id)
            targets.append(Target(account_id, name, session=assumed, role_arn=arn))
        except (ClientError, BotoCoreError) as exc:
            arn = f"arn:{_partition(session)}:iam::{account_id}:role/{role_name}"
            targets.append(Target(account_id, name, error=str(exc), role_arn=arn))
    return targets


def assume_error_finding(target: Target) -> Finding:
    return Finding(check_id="assume-role", status=Status.ERROR, resource=target.role_arn, region="global",
                   detail=f"account not scanned: {target.error}", title="Assume the scan role",
                   service="sts", severity="", account=target.account_id)
