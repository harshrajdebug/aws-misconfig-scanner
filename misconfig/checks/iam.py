from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from ..context import ScanContext, error_code
from ..models import Severity, Status
from ..registry import check

ROOT = "<root_account>"
UNUSED_DAYS = 45
ROTATION_DAYS = 90


def _date(value: str) -> datetime | None:
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _users(ctx: ScanContext) -> list[dict[str, str]]:
    return [row for row in ctx.credential_report if row["user"] != ROOT]


@check("iam-root-access-key", "Root user has no access keys", "iam", Severity.CRITICAL,
       "IAM.4", "1.3", "1.4", "Delete the root user's access keys and use IAM roles or users instead.", scope="global")
def root_access_key(ctx: ScanContext, region: str):
    present = ctx.account_summary.get("AccountAccessKeysPresent", 0)
    if present:
        yield Status.FAIL, "root", f"root user has {present} access key(s)"
    else:
        yield Status.PASS, "root", "no root access keys"


@check("iam-root-mfa", "Root user has MFA enabled", "iam", Severity.CRITICAL,
       "IAM.9", "1.4", "1.5", "Enable MFA on the root user, preferably a hardware or passkey device.", scope="global")
def root_mfa(ctx: ScanContext, region: str):
    summary = ctx.account_summary
    if summary.get("AccountMFAEnabled", 0):
        yield Status.PASS, "root", "root MFA enabled"
    elif not any(summary.get(k, 1) for k in ("AccountPasswordPresent", "AccountAccessKeysPresent",
                                            "AccountSigningCertificatesPresent")):
        # Accounts under centralized root access management can have their root credentials
        # removed. With no password, access key or certificate, nothing can sign in as root.
        yield Status.PASS, "root", "root user has no password, access keys or signing certificates"
    else:
        yield Status.FAIL, "root", "root user has no MFA device"


@check("iam-user-console-mfa", "IAM users with a console password have MFA", "iam", Severity.HIGH,
       "IAM.5", "1.9", "1.10", "Assign an MFA device to every IAM user that can sign in to the console.", scope="global")
def console_mfa(ctx: ScanContext, region: str):
    for row in _users(ctx):
        if row["password_enabled"] != "true":
            continue
        if row["mfa_active"] == "true":
            yield Status.PASS, row["arn"], "console user has MFA"
        else:
            yield Status.FAIL, row["arn"], "console password without MFA"


@check("iam-access-key-rotation", "Active access keys are rotated within 90 days", "iam", Severity.MEDIUM,
       "IAM.3", "1.13", "1.14", "Create a new access key, move workloads to it, then deactivate and delete the old one.",
       scope="global")
def key_rotation(ctx: ScanContext, region: str):
    now = datetime.now(timezone.utc)
    for row in _users(ctx):
        for n in ("1", "2"):
            if row[f"access_key_{n}_active"] != "true":
                continue
            rotated = _date(row[f"access_key_{n}_last_rotated"])
            resource = f"{row['arn']} (key {n})"
            if rotated and now - rotated > timedelta(days=ROTATION_DAYS):
                yield Status.FAIL, resource, f"key last rotated {(now - rotated).days} days ago"
            else:
                yield Status.PASS, resource, "key rotated within 90 days"


@check("iam-unused-credentials", "Credentials unused for 45 days are disabled", "iam", Severity.MEDIUM,
       "IAM.22", "1.11", "1.12", "Disable or remove passwords and access keys that have not been used for 45 days.",
       scope="global")
def unused_credentials(ctx: ScanContext, region: str):
    now = datetime.now(timezone.utc)
    limit = timedelta(days=UNUSED_DAYS)
    for row in _users(ctx):
        stale = []
        if row["password_enabled"] == "true":
            # A password that was never used counts from when it was last set.
            last = _date(row["password_last_used"]) or _date(row["password_last_changed"])
            if last and now - last > limit:
                stale.append(f"password unused for {(now - last).days} days")
        for n in ("1", "2"):
            if row[f"access_key_{n}_active"] != "true":
                continue
            last = _date(row[f"access_key_{n}_last_used_date"]) or _date(row[f"access_key_{n}_last_rotated"])
            if last and now - last > limit:
                stale.append(f"access key {n} unused for {(now - last).days} days")
        if stale:
            yield Status.FAIL, row["arn"], "; ".join(stale)
        elif row["password_enabled"] == "true" or "true" in (row["access_key_1_active"], row["access_key_2_active"]):
            yield Status.PASS, row["arn"], "all active credentials used within 45 days"


def _password_policy(ctx: ScanContext) -> dict | None:
    try:
        return ctx.client("iam").get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if error_code(exc) == "NoSuchEntity":
            return None
        raise


@check("iam-password-length", "Password policy requires 14 or more characters", "iam", Severity.MEDIUM,
       "IAM.15", "1.7", "1.8", "Set an account password policy with MinimumPasswordLength of at least 14.", scope="global")
def password_length(ctx: ScanContext, region: str):
    policy = _password_policy(ctx)
    if policy is None:
        yield Status.FAIL, "account-password-policy", "no account password policy is set"
        return
    length = policy.get("MinimumPasswordLength", 0)
    status = Status.PASS if length >= 14 else Status.FAIL
    yield status, "account-password-policy", f"minimum length {length}"


@check("iam-password-reuse", "Password policy prevents reuse", "iam", Severity.LOW,
       "IAM.16", "1.8", "1.9", "Set PasswordReusePrevention to 24 in the account password policy.", scope="global")
def password_reuse(ctx: ScanContext, region: str):
    policy = _password_policy(ctx)
    if policy is None:
        yield Status.FAIL, "account-password-policy", "no account password policy is set"
        return
    reuse = policy.get("PasswordReusePrevention", 0)
    status = Status.PASS if reuse >= 24 else Status.FAIL
    yield status, "account-password-policy", f"remembers {reuse} previous passwords"


@check("iam-user-attached-policies", "IAM users get permissions only through groups or roles", "iam", Severity.LOW,
       "IAM.2", "1.14", "1.15", "Move policies from users to groups, and attach users to those groups.", scope="global")
def user_policies(ctx: ScanContext, region: str):
    iam = ctx.client("iam")
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
            inline = iam.list_user_policies(UserName=name)["PolicyNames"]
            if attached or inline:
                yield Status.FAIL, user["Arn"], f"{len(attached)} attached and {len(inline)} inline policies on the user"
            else:
                yield Status.PASS, user["Arn"], "no policies on the user"


@check("iam-cloudshell-full-access", "No identity has AWSCloudShellFullAccess", "iam", Severity.MEDIUM,
       "IAM.27", "1.21", "1.22", "Detach AWSCloudShellFullAccess and grant a narrower CloudShell policy if needed.",
       scope="global")
def cloudshell_full_access(ctx: ScanContext, region: str):
    arn = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
    try:
        entities = ctx.client("iam").list_entities_for_policy(PolicyArn=arn)
    except ClientError as exc:
        if error_code(exc) == "NoSuchEntity":
            yield Status.PASS, arn, "policy is not attached anywhere"
            return
        raise
    attached = [u["UserName"] for u in entities["PolicyUsers"]] + [g["GroupName"] for g in entities["PolicyGroups"]] + [
        r["RoleName"] for r in entities["PolicyRoles"]
    ]
    if attached:
        yield Status.FAIL, arn, "attached to " + ", ".join(sorted(attached))
    else:
        yield Status.PASS, arn, "policy is not attached anywhere"


def _statements(document) -> list[dict]:
    if isinstance(document, str):
        document = json.loads(urllib.parse.unquote(document))
    statements = document.get("Statement", [])
    return statements if isinstance(statements, list) else [statements]


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def grants_full_admin(document) -> bool:
    """True if any Allow statement grants every action on every resource."""
    for st in _statements(document):
        if st.get("Effect") != "Allow" or "NotAction" in st or "NotResource" in st:
            continue
        if "*" in _as_list(st.get("Action", [])) and "*" in _as_list(st.get("Resource", [])):
            return True
    return False


@check("iam-full-admin-policy", "No attached customer managed policy allows *:*", "iam", Severity.HIGH,
       "IAM.1", "", "", "Replace \"Action\": \"*\" on \"Resource\": \"*\" with the specific actions the workload needs.",
       scope="global")
def full_admin_policy(ctx: ScanContext, region: str):
    iam = ctx.client("iam")
    for page in iam.get_paginator("list_policies").paginate(Scope="Local", OnlyAttached=True):
        for policy in page["Policies"]:
            version = iam.get_policy_version(PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"])
            if grants_full_admin(version["PolicyVersion"]["Document"]):
                yield Status.FAIL, policy["Arn"], "default version allows Action * on Resource *"
            else:
                yield Status.PASS, policy["Arn"], "no full administrative statement"


@check("iam-inline-admin-policy", "No inline policy allows *:*", "iam", Severity.HIGH,
       "-", "", "",
       "Replace inline policies that allow Action * on Resource * with managed policies scoped to the needed actions.",
       scope="global")
def inline_admin_policy(ctx: ScanContext, region: str):
    iam = ctx.client("iam")
    kinds = (
        ("list_users", "Users", "UserName", "list_user_policies", "get_user_policy"),
        ("list_groups", "Groups", "GroupName", "list_group_policies", "get_group_policy"),
        ("list_roles", "Roles", "RoleName", "list_role_policies", "get_role_policy"),
    )
    for list_op, key, name_key, list_policies, get_policy in kinds:
        for page in iam.get_paginator(list_op).paginate():
            for identity in page[key]:
                name = identity[name_key]
                names = []
                for ppage in iam.get_paginator(list_policies).paginate(**{name_key: name}):
                    names.extend(ppage["PolicyNames"])
                if not names:
                    continue
                admin = [n for n in names
                         if grants_full_admin(getattr(iam, get_policy)(**{name_key: name, "PolicyName": n})["PolicyDocument"])]
                if admin:
                    yield Status.FAIL, identity["Arn"], "inline policy allows Action * on Resource *: " + ", ".join(admin)
                else:
                    yield Status.PASS, identity["Arn"], f"{len(names)} inline policies, none with full administrative access"
