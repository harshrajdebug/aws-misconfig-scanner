import json

from botocore.exceptions import ClientError

from misconfig.cli import main
from misconfig.models import Status
from misconfig.registry import CHECKS
from misconfig.scanner import run

from .conftest import client


def test_access_denied_is_reported_as_error(ctx, monkeypatch):
    class Denied:
        def __getattr__(self, name):
            def call(*args, **kwargs):
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, name)
            return call

    monkeypatch.setattr(ctx, "client", lambda *a, **k: Denied())
    findings = run(ctx, [CHECKS["ec2-ebs-default-encryption"]])
    assert [f.status for f in findings] == [Status.ERROR]
    assert findings[0].detail.startswith("AccessDenied")


def test_cli_json_and_fail_on(capsys):
    client("ec2").authorize_security_group_ingress(
        GroupName="default", IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    code = main(["--services", "ec2", "--format", "json", "--fail-on", "HIGH"])
    out = json.loads(capsys.readouterr().out)
    assert code == 1
    failing = {f["check_id"] for f in out["findings"] if f["status"] == "FAIL"}
    assert "ec2-sg-admin-ports-ipv4" in failing
    assert out["summary"]["ERROR"] == 0


def test_cli_passes_when_nothing_at_threshold(capsys):
    assert main(["--checks", "ec2-ebs-default-encryption", "--fail-on", "CRITICAL"]) == 0
    assert "ec2-ebs-default-encryption" in capsys.readouterr().out


def test_every_check_has_mappings_and_remediation():
    for c in CHECKS.values():
        assert c.securityhub and c.remediation, c.id
