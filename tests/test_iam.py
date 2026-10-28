import json
from datetime import datetime, timedelta, timezone

from misconfig.checks.iam import grants_full_admin
from misconfig.models import Status

from .conftest import client

NOW = datetime.now(timezone.utc)


def _days_ago(n):
    return (NOW - timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _row(user, **fields):
    row = {"user": user, "arn": f"arn:aws:iam::123456789012:user/{user}", "password_enabled": "false",
           "password_last_used": "N/A", "password_last_changed": "N/A", "mfa_active": "false",
           "access_key_1_active": "false", "access_key_1_last_rotated": "N/A", "access_key_1_last_used_date": "N/A",
           "access_key_2_active": "false", "access_key_2_last_rotated": "N/A", "access_key_2_last_used_date": "N/A"}
    row.update(fields)
    return row


def test_console_mfa_from_real_report(scan):
    iam = client("iam")
    for name in ("alice", "bob", "svc"):
        iam.create_user(UserName=name)
    iam.create_login_profile(UserName="alice", Password="Correct-horse-battery-1")
    iam.create_login_profile(UserName="bob", Password="Correct-horse-battery-2")
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob")["VirtualMFADevice"]["SerialNumber"]
    iam.enable_mfa_device(UserName="bob", SerialNumber=serial, AuthenticationCode1="123456", AuthenticationCode2="654321")
    r = {k.rsplit("/", 1)[-1]: v for k, v in scan("iam-user-console-mfa").items()}
    assert r["alice"] == (Status.FAIL, "console password without MFA")
    assert r["bob"][0] is Status.PASS
    assert "svc" not in r  # no console password, so the check does not apply


def test_key_rotation_and_unused(scan, ctx):
    ctx.__dict__["credential_report"] = [
        _row("<root_account>"),
        _row("old-key", access_key_1_active="true", access_key_1_last_rotated=_days_ago(120),
             access_key_1_last_used_date=_days_ago(1)),
        _row("fresh-key", access_key_1_active="true", access_key_1_last_rotated=_days_ago(10),
             access_key_1_last_used_date=_days_ago(1)),
        _row("idle-key", access_key_1_active="true", access_key_1_last_rotated=_days_ago(60),
             access_key_1_last_used_date=_days_ago(50)),
        _row("never-used", access_key_1_active="true", access_key_1_last_rotated=_days_ago(46)),
        _row("stale-console", password_enabled="true", password_last_used=_days_ago(70)),
        _row("inactive-old", access_key_1_active="false", access_key_1_last_rotated=_days_ago(400)),
    ]
    rot = {k.split("/")[-1]: v for k, v in scan("iam-access-key-rotation").items()}
    assert rot["old-key (key 1)"] == (Status.FAIL, "key last rotated 120 days ago")
    assert rot["fresh-key (key 1)"][0] is Status.PASS
    assert not any(k.startswith("inactive-old") for k in rot)
    unused = {k.split("/")[-1]: v for k, v in scan("iam-unused-credentials").items()}
    assert unused["idle-key"] == (Status.FAIL, "access key 1 unused for 50 days")
    assert unused["never-used"] == (Status.FAIL, "access key 1 unused for 46 days")
    assert unused["stale-console"] == (Status.FAIL, "password unused for 70 days")
    assert unused["fresh-key"][0] is Status.PASS
    assert "inactive-old" not in unused


def test_root_checks(scan, ctx):
    ctx.__dict__["account_summary"] = {"AccountAccessKeysPresent": 1, "AccountMFAEnabled": 0}
    assert scan("iam-root-access-key")["root"] == (Status.FAIL, "root user has 1 access key(s)")
    assert scan("iam-root-mfa")["root"][0] is Status.FAIL
    ctx.__dict__["account_summary"] = {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1}
    assert scan("iam-root-access-key")["root"][0] is Status.PASS
    assert scan("iam-root-mfa")["root"][0] is Status.PASS


def test_root_mfa_with_root_credentials_removed(scan, ctx):
    ctx.__dict__["account_summary"] = {"AccountMFAEnabled": 0, "AccountPasswordPresent": 0,
                                       "AccountAccessKeysPresent": 0, "AccountSigningCertificatesPresent": 0}
    assert scan("iam-root-mfa")["root"] == (Status.PASS, "root user has no password, access keys or signing certificates")
    ctx.__dict__["account_summary"] = {"AccountMFAEnabled": 0, "AccountPasswordPresent": 1,
                                       "AccountAccessKeysPresent": 0, "AccountSigningCertificatesPresent": 0}
    assert scan("iam-root-mfa")["root"] == (Status.FAIL, "root user has no MFA device")
    # A summary without the credential keys is treated as credentials present.
    ctx.__dict__["account_summary"] = {"AccountMFAEnabled": 0}
    assert scan("iam-root-mfa")["root"][0] is Status.FAIL


def test_password_policy(scan):
    r = scan("iam-password-length")["account-password-policy"]
    assert r == (Status.FAIL, "no account password policy is set")
    client("iam").update_account_password_policy(MinimumPasswordLength=8, PasswordReusePrevention=5)
    assert scan("iam-password-length")["account-password-policy"] == (Status.FAIL, "minimum length 8")
    assert scan("iam-password-reuse")["account-password-policy"][0] is Status.FAIL
    client("iam").update_account_password_policy(MinimumPasswordLength=14, PasswordReusePrevention=24)
    assert scan("iam-password-length")["account-password-policy"][0] is Status.PASS
    assert scan("iam-password-reuse")["account-password-policy"][0] is Status.PASS


def test_user_attached_policies(scan):
    iam = client("iam")
    iam.create_user(UserName="direct")
    iam.create_user(UserName="via-group")
    iam.put_user_policy(UserName="direct", PolicyName="p", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}))
    iam.create_group(GroupName="devs")
    iam.add_user_to_group(GroupName="devs", UserName="via-group")
    r = {k.rsplit("/", 1)[-1]: v for k, v in scan("iam-user-attached-policies").items()}
    assert r["direct"] == (Status.FAIL, "0 attached and 1 inline policies on the user")
    assert r["via-group"][0] is Status.PASS


def test_grants_full_admin():
    allow_all = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    assert grants_full_admin(allow_all)
    assert grants_full_admin({"Statement": {"Effect": "Allow", "Action": ["s3:*", "*"], "Resource": ["*"]}})
    assert not grants_full_admin({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
    assert not grants_full_admin({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
    assert not grants_full_admin({"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Action": "*", "Resource": "*"}]})


def test_full_admin_policy_only_when_attached(scan):
    iam = client("iam")
    doc = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    attached = iam.create_policy(PolicyName="god-mode", PolicyDocument=doc)["Policy"]["Arn"]
    iam.create_policy(PolicyName="unused-god-mode", PolicyDocument=doc)
    iam.create_role(RoleName="r", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}))
    iam.attach_role_policy(RoleName="r", PolicyArn=attached)
    r = scan("iam-full-admin-policy")
    assert r[attached] == (Status.FAIL, "default version allows Action * on Resource *")
    assert not any("unused-god-mode" in k for k in r)


def test_inline_admin_policies_on_users_groups_and_roles(scan):
    iam = client("iam")
    admin = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    narrow = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    trust = json.dumps({"Version": "2012-10-17", "Statement": []})
    iam.create_user(UserName="u-admin")
    iam.put_user_policy(UserName="u-admin", PolicyName="everything", PolicyDocument=admin)
    iam.create_group(GroupName="g-admin")
    iam.put_group_policy(GroupName="g-admin", PolicyName="everything", PolicyDocument=admin)
    iam.create_role(RoleName="r-admin", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(RoleName="r-admin", PolicyName="everything", PolicyDocument=admin)
    iam.create_role(RoleName="r-narrow", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(RoleName="r-narrow", PolicyName="read", PolicyDocument=narrow)
    r = scan("iam-inline-admin-policy")
    failing = {k for k, (s, _) in r.items() if s is Status.FAIL}
    assert any("user/u-admin" in k for k in failing)
    assert any("group/g-admin" in k for k in failing)
    assert any("role/r-admin" in k for k in failing)
    assert all("r-narrow" not in k for k in failing)
    assert any("r-narrow" in k and s is Status.PASS for k, (s, _) in r.items())
