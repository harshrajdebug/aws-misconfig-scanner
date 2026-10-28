import json

import boto3

from misconfig.accounts import org_accounts, resolve
from misconfig.cli import main

from .conftest import REGION, client


def _org_with_members(*names):
    org = client("organizations")
    org.create_organization(FeatureSet="ALL")
    ids = {}
    for name in names:
        status = org.create_account(Email=f"{name}@example.com", AccountName=name)["CreateAccountStatus"]
        ids[name] = status["AccountId"]
    return ids


def _member_session(account_id, role="OrganizationAccountAccessRole"):
    creds = client("sts").assume_role(RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
                                      RoleSessionName="test-setup")["Credentials"]
    return boto3.session.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                                 aws_session_token=creds["SessionToken"], region_name=REGION)


def _open_ssh(session):
    session.client("ec2").authorize_security_group_ingress(GroupName="default", IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])


def test_org_accounts_lists_management_and_members():
    ids = _org_with_members("prod", "dev")
    listed = dict(org_accounts(boto3.session.Session(region_name=REGION)))
    assert ids["prod"] in listed and ids["dev"] in listed
    assert listed[ids["prod"]] == "prod"


def test_own_account_uses_base_session_without_assuming():
    base = boto3.session.Session(region_name=REGION)
    own = base.client("sts").get_caller_identity()["Account"]
    targets = resolve(base, [own], use_org=False, role_name="DoesNotMatter")
    assert len(targets) == 1 and targets[0].session is base and not targets[0].error


def test_org_scan_attributes_findings_to_the_right_account(capsys):
    ids = _org_with_members("prod", "dev")
    _open_ssh(_member_session(ids["prod"]))
    code = main(["--org", "--checks", "ec2-sg-admin-ports-ipv4", "--format", "json", "--fail-on", "HIGH"])
    out = json.loads(capsys.readouterr().out)
    assert code == 1
    by_account = {}
    for f in out["findings"]:
        by_account.setdefault(f["account"], set()).add(f["status"])
    assert "FAIL" in by_account[ids["prod"]]
    assert by_account[ids["dev"]] == {"PASS"}
    assert {a["id"] for a in out["accounts"]} >= {ids["prod"], ids["dev"]}
    prod = next(a for a in out["accounts"] if a["id"] == ids["prod"])
    assert prod["name"] == "prod" and prod["summary"]["FAIL"] >= 1


def test_explicit_accounts_and_custom_role(capsys):
    ids = _org_with_members("audit-target")
    _open_ssh(_member_session(ids["audit-target"], role="MisconfigScannerRole"))
    code = main(["--accounts", ids["audit-target"], "--role-name", "MisconfigScannerRole",
                 "--checks", "ec2-sg-admin-ports-ipv4", "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert [a["id"] for a in out["accounts"]] == [ids["audit-target"]]
    assert any(f["status"] == "FAIL" and f["account"] == ids["audit-target"] for f in out["findings"])


def test_unassumable_account_is_reported_and_fails_the_run(capsys, monkeypatch):
    ids = _org_with_members("locked")
    import misconfig.accounts as accounts

    real_assume = accounts.assume

    def deny(session, account_id, role_name, external_id=None):
        if account_id == ids["locked"]:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "AssumeRole")
        return real_assume(session, account_id, role_name, external_id)

    monkeypatch.setattr(accounts, "assume", deny)
    code = main(["--org", "--checks", "ec2-ebs-default-encryption", "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 2
    errors = [f for f in out["findings"] if f["check_id"] == "assume-role"]
    assert len(errors) == 1 and errors[0]["account"] == ids["locked"] and errors[0]["status"] == "ERROR"
    assert "AccessDenied" in errors[0]["detail"]
    # The other accounts were still scanned.
    assert any(f["check_id"] == "ec2-ebs-default-encryption" for f in out["findings"])


def test_external_id_is_passed(monkeypatch):
    ids = _org_with_members("partner")
    seen = {}
    import misconfig.accounts as accounts

    real_client = boto3.session.Session.client

    def spy(self, service, *a, **k):
        c = real_client(self, service, *a, **k)
        if service == "sts":
            orig = c.assume_role

            def assume_role(**params):
                seen.update(params)
                return orig(**params)
            c.assume_role = assume_role
        return c

    monkeypatch.setattr(boto3.session.Session, "client", spy)
    targets = accounts.resolve(boto3.session.Session(region_name=REGION), [ids["partner"]], False,
                               "MisconfigScannerRole", external_id="shared-secret-123")
    assert targets[0].session is not None
    assert seen["ExternalId"] == "shared-secret-123"
    assert seen["RoleArn"] == f"arn:aws:iam::{ids['partner']}:role/MisconfigScannerRole"


def test_text_report_groups_by_account(capsys):
    ids = _org_with_members("prod")
    _open_ssh(_member_session(ids["prod"]))
    main(["--org", "--checks", "ec2-sg-admin-ports-ipv4"])
    text = capsys.readouterr().out
    assert f"Account {ids['prod']} (prod)" in text
    assert "All 2 accounts:" in text
