from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from . import __version__
from .accounts import Target, assume_error_finding, resolve
from .context import ScanContext
from .models import Check, Finding, Severity, Status
from .report import to_json, to_text
from .scanner import run, select


def _regions(session: boto3.session.Session, value: str | None) -> list[str]:
    if value == "all":
        # Opt-in regions differ between accounts, so this is resolved per account.
        ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
        return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])
    if value:
        return [r.strip() for r in value.split(",") if r.strip()]
    return [session.region_name or "us-east-1"]


def _scan_target(target: Target, regions: str | None, selected: list[Check]) -> list[Finding]:
    if target.session is None:
        return [assume_error_finding(target)]
    try:
        scan_regions = _regions(target.session, regions)
        ctx = ScanContext(target.session, scan_regions, global_region=target.session.region_name or scan_regions[0])
    except (ClientError, BotoCoreError) as exc:
        target.error = f"could not list regions: {exc}"
        return [assume_error_finding(target)]
    findings = run(ctx, selected)
    for f in findings:
        f.account = target.account_id
    return findings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="misconfig", description="Read-only AWS misconfiguration scanner.")
    p.add_argument("--profile", help="AWS profile to use")
    p.add_argument("--regions", help="comma-separated regions, or 'all' (default: the profile's region)")
    p.add_argument("--checks", help="comma-separated check ids to run")
    p.add_argument("--services", help="comma-separated services to run (iam,s3,ec2,cloudtrail,kms,rds)")
    accounts = p.add_mutually_exclusive_group()
    accounts.add_argument("--accounts", help="comma-separated account ids to scan through --role-name")
    accounts.add_argument("--org", action="store_true",
                          help="scan every active account in the organization (run from the management "
                               "account or a delegated administrator)")
    p.add_argument("--role-name", default="OrganizationAccountAccessRole",
                   help="role to assume in each other account (default: %(default)s)")
    p.add_argument("--external-id", help="external ID to pass when assuming the role")
    p.add_argument("--workers", type=int, default=4, help="accounts to scan in parallel (default: %(default)s)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--show-pass", action="store_true", help="include passing results in text output")
    p.add_argument("--fail-on", choices=[s.name for s in Severity],
                   help="exit 1 if any check fails at this severity or above")
    p.add_argument("--list-checks", action="store_true", help="list the checks and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    if args.list_checks:
        for c in select():
            print(f"{c.id:<34} {c.severity.name:<8} {c.securityhub:<13} CIS v5 {c.cis_v5 or '-':<6} {c.title}")
        return 0
    if args.workers < 1:
        p.error("--workers must be at least 1")

    try:
        selected = select(args.checks.split(",") if args.checks else None,
                          args.services.split(",") if args.services else None)
    except ValueError as exc:
        p.error(str(exc))

    session = boto3.session.Session(profile_name=args.profile)
    account_ids = [a.strip() for a in args.accounts.split(",") if a.strip()] if args.accounts else None
    try:
        targets = resolve(session, account_ids, args.org, args.role_name, args.external_id)
    except (ClientError, BotoCoreError) as exc:
        print(f"misconfig: could not list accounts: {exc}", file=sys.stderr)
        return 2

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = pool.map(lambda t: _scan_target(t, args.regions, selected), targets)
        findings = [f for batch in results for f in batch]

    listed = [(t.account_id, t.name) for t in targets]
    print(to_json(findings, listed) if args.format == "json" else to_text(findings, listed, args.show_pass))

    if any(f.check_id == "assume-role" for f in findings):
        # An account that was never scanned must not let a pipeline pass.
        return 2
    if args.fail_on:
        threshold = Severity[args.fail_on]
        failed = any(f.status is Status.FAIL and f.severity and Severity[f.severity] >= threshold for f in findings)
        if failed:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
