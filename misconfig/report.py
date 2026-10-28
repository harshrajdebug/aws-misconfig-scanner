from __future__ import annotations

import json
from collections import Counter

from .models import Finding, Severity, Status


def to_json(findings: list[Finding], account: str) -> str:
    return json.dumps({"account": account, "summary": summary(findings),
                       "findings": [f.to_dict() for f in findings]}, indent=2)


def summary(findings: list[Finding]) -> dict:
    counts = Counter(f.status.value for f in findings)
    failed = Counter(f.severity for f in findings if f.status is Status.FAIL)
    return {"total": len(findings), **{s.value: counts.get(s.value, 0) for s in Status},
            "failed_by_severity": {s.name: failed.get(s.name, 0) for s in sorted(Severity, reverse=True)}}


def to_text(findings: list[Finding], account: str, show_pass: bool = False) -> str:
    order = {s.name: s.value for s in Severity}
    rows = [f for f in findings if show_pass or f.status is not Status.PASS]
    rows.sort(key=lambda f: (f.status is not Status.FAIL, -order.get(f.severity, 0), f.check_id, f.resource))
    lines = [f"Account {account}"]
    for f in rows:
        cis = f"CIS v5 {f.cis_v5}" if f.cis_v5 else "no CIS mapping"
        lines.append(f"[{f.status.value}] {f.severity:<8} {f.check_id}  ({f.securityhub}, {cis})")
        lines.append(f"    {f.resource}  [{f.region}]")
        lines.append(f"    {f.detail}")
        if f.status is Status.FAIL:
            lines.append(f"    fix: {f.remediation}")
    s = summary(findings)
    sev = ", ".join(f"{k} {v}" for k, v in s["failed_by_severity"].items() if v)
    lines.append(f"\n{s['total']} results: {s['PASS']} passed, {s['FAIL']} failed ({sev or 'none'}), {s['ERROR']} errors")
    return "\n".join(lines)
