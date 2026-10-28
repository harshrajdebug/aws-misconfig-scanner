from __future__ import annotations

import argparse
import sys

import boto3

from . import __version__
from .context import ScanContext
from .models import Severity, Status
from .report import to_json, to_text
from .scanner import run, select


def _regions(session: boto3.session.Session, value: str | None) -> list[str]:
    if value == "all":
        ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
        return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])
    if value:
        return [r.strip() for r in value.split(",") if r.strip()]
    return [session.region_name or "us-east-1"]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="misconfig", description="Read-only AWS misconfiguration scanner.")
    p.add_argument("--profile", help="AWS profile to use")
    p.add_argument("--regions", help="comma-separated regions, or 'all' (default: the profile's region)")
    p.add_argument("--checks", help="comma-separated check ids to run")
    p.add_argument("--services", help="comma-separated services to run (iam,s3,ec2,cloudtrail,kms,rds)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--show-pass", action="store_true", help="include passing results in text output")
    p.add_argument("--fail-on", choices=[s.name for s in Severity],
                   help="exit 1 if any check fails at this severity or above")
    p.add_argument("--list-checks", action="store_true", help="list the checks and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    if args.list_checks:
        selected = select()
        for c in selected:
            print(f"{c.id:<34} {c.severity.name:<8} {c.securityhub:<13} CIS v5 {c.cis_v5 or '-':<6} {c.title}")
        return 0

    session = boto3.session.Session(profile_name=args.profile)
    try:
        selected = select(args.checks.split(",") if args.checks else None,
                          args.services.split(",") if args.services else None)
    except ValueError as exc:
        p.error(str(exc))
    ctx = ScanContext(session, _regions(session, args.regions))
    findings = run(ctx, selected)
    account = ctx.account_id
    print(to_json(findings, account) if args.format == "json" else to_text(findings, account, args.show_pass))

    if args.fail_on:
        threshold = Severity[args.fail_on]
        if any(f.status is Status.FAIL and Severity[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
