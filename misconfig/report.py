from __future__ import annotations

import json
from collections import Counter

from .models import Finding, Severity, Status


def summary(findings: list[Finding]) -> dict:
    counts = Counter(f.status.value for f in findings)
    failed = Counter(f.severity for f in findings if f.status is Status.FAIL)
    return {"total": len(findings), **{s.value: counts.get(s.value, 0) for s in Status},
            "failed_by_severity": {s.name: failed.get(s.name, 0) for s in sorted(Severity, reverse=True)}}


def to_json(findings: list[Finding], accounts: list[tuple[str, str]]) -> str:
    per_account = [{"id": a, "name": n, "summary": summary([f for f in findings if f.account == a])}
                   for a, n in accounts]
    return json.dumps({"accounts": per_account, "summary": summary(findings),
                       "findings": [f.to_dict() for f in findings]}, indent=2)


def _summary_line(findings: list[Finding]) -> str:
    s = summary(findings)
    sev = ", ".join(f"{k} {v}" for k, v in s["failed_by_severity"].items() if v)
    return f"{s['total']} results: {s['PASS']} passed, {s['FAIL']} failed ({sev or 'none'}), {s['ERROR']} errors"


def to_text(findings: list[Finding], accounts: list[tuple[str, str]], show_pass: bool = False) -> str:
    order = {s.name: s.value for s in Severity}
    lines = []
    for account, name in accounts:
        mine = [f for f in findings if f.account == account]
        rows = [f for f in mine if show_pass or f.status is not Status.PASS]
        rows.sort(key=lambda f: (f.status is not Status.FAIL, -order.get(f.severity, 0), f.check_id, f.resource))
        lines.append(f"Account {account}" + (f" ({name})" if name else ""))
        for f in rows:
            if f.check_id == "assume-role":
                lines.append(f"[{f.status.value}] {f.check_id}  {f.resource}")
                lines.append(f"    {f.detail}")
                continue
            cis = f"CIS v5 {f.cis_v5}" if f.cis_v5 else "no CIS mapping"
            lines.append(f"[{f.status.value}] {f.severity:<8} {f.check_id}  ({f.securityhub}, {cis})")
            lines.append(f"    {f.resource}  [{f.region}]")
            lines.append(f"    {f.detail}")
            if f.status is Status.FAIL:
                lines.append(f"    fix: {f.remediation}")
        lines.append(_summary_line(mine))
        lines.append("")
    if len(accounts) > 1:
        lines.append(f"All {len(accounts)} accounts: {_summary_line(findings)}")
    return "\n".join(lines).rstrip()
