import boto3
import pytest
from moto import mock_aws

from misconfig.context import ScanContext
from misconfig.models import Status
from misconfig.registry import CHECKS
from misconfig.scanner import run

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    # Fake credentials so nothing can reach a real account.
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        yield


@pytest.fixture
def ctx():
    return ScanContext(boto3.session.Session(region_name=REGION), [REGION])


@pytest.fixture
def scan(ctx):
    """Run one check and return {resource: (status, detail)}."""

    def _scan(check_id):
        findings = run(ctx, [CHECKS[check_id]])
        errors = [f for f in findings if f.status is Status.ERROR]
        assert not errors, errors
        return {f.resource: (f.status, f.detail) for f in findings}

    return _scan


def client(service, region=REGION):
    return boto3.client(service, region_name=region)
