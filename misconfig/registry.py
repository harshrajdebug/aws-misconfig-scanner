from __future__ import annotations

from collections.abc import Callable

from .models import Check, Severity

CHECKS: dict[str, Check] = {}


def check(
    id: str,
    title: str,
    service: str,
    severity: Severity,
    securityhub: str,
    cis_v5: str,
    cis_v3: str,
    remediation: str,
    scope: str = "regional",
) -> Callable:
    """Register a check function. The function receives a ScanContext and a region and
    yields (status, resource, detail) tuples."""

    def wrap(func: Callable) -> Callable:
        if id in CHECKS:
            raise ValueError(f"duplicate check id {id}")
        if scope not in ("global", "regional"):
            raise ValueError(f"check {id}: scope must be global or regional")
        CHECKS[id] = Check(id, title, service, severity, securityhub, cis_v5, cis_v3, remediation, scope, func)
        return func

    return wrap
