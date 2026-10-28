from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from . import checks  # noqa: F401  (registers checks)
from .context import ScanContext, error_code
from .models import Check, Finding, Status
from .registry import CHECKS


def select(ids: list[str] | None = None, services: list[str] | None = None) -> list[Check]:
    chosen = list(CHECKS.values())
    if ids:
        unknown = set(ids) - CHECKS.keys()
        if unknown:
            raise ValueError("unknown check id(s): " + ", ".join(sorted(unknown)))
        chosen = [c for c in chosen if c.id in ids]
    if services:
        chosen = [c for c in chosen if c.service in services]
    return chosen


def _finding(chk: Check, status: Status, resource: str, region: str, detail: str) -> Finding:
    return Finding(
        check_id=chk.id, status=status, resource=resource, region=region, detail=detail,
        title=chk.title, service=chk.service, severity=chk.severity.name, securityhub=chk.securityhub,
        cis_v5=chk.cis_v5, cis_v3=chk.cis_v3, remediation=chk.remediation,
    )


def run(ctx: ScanContext, selected: list[Check]) -> list[Finding]:
    findings = _run(ctx, selected)
    try:
        account = ctx.account_id
    except (ClientError, BotoCoreError):
        account = ""
    for f in findings:
        f.account = account
    return findings


def _run(ctx: ScanContext, selected: list[Check]) -> list[Finding]:
    findings: list[Finding] = []
    for chk in selected:
        regions = [ctx.global_region] if chk.scope == "global" else ctx.regions
        for region in regions:
            label = "global" if chk.scope == "global" else region
            try:
                for status, resource, detail in chk.func(ctx, region):
                    findings.append(_finding(chk, status, resource, label, detail))
            except ClientError as exc:
                # Report the gap instead of letting a missing permission read as a pass.
                findings.append(_finding(chk, Status.ERROR, "-", label, f"{error_code(exc)}: {exc}"))
            except BotoCoreError as exc:
                findings.append(_finding(chk, Status.ERROR, "-", label, str(exc)))
    return findings
