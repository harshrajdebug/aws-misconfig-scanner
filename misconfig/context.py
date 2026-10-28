from __future__ import annotations

import csv
import io
import time
from functools import cached_property

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

_RETRY = Config(retries={"max_attempts": 10, "mode": "adaptive"})


class ScanContext:
    """Holds the boto3 session and caches clients and account-wide data for one scan."""

    def __init__(self, session: boto3.session.Session, regions: list[str], global_region: str = "us-east-1"):
        self.session = session
        self.regions = regions
        self.global_region = global_region
        self._clients: dict[tuple[str, str], object] = {}

    def client(self, service: str, region: str | None = None):
        key = (service, region or self.global_region)
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=key[1], config=_RETRY)
        return self._clients[key]

    @cached_property
    def account_id(self) -> str:
        return self.client("sts").get_caller_identity()["Account"]

    @cached_property
    def credential_report(self) -> list[dict[str, str]]:
        """Rows of the IAM credential report, generating one if none is ready yet."""
        iam = self.client("iam")
        for _ in range(30):
            if iam.generate_credential_report()["State"] == "COMPLETE":
                break
            time.sleep(2)
        content = iam.get_credential_report()["Content"]
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        return list(csv.DictReader(io.StringIO(content)))

    @cached_property
    def account_summary(self) -> dict[str, int]:
        return self.client("iam").get_account_summary()["SummaryMap"]


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")
