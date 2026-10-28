from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from collections.abc import Callable, Iterator


class Severity(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Status(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    # The check could not run, usually because the caller lacks a read permission.
    ERROR = "ERROR"


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    service: str
    severity: Severity
    # Security Hub CSPM control ID, and the matching requirement in CIS AWS Foundations
    # Benchmark v5.0.0 and v3.0.0 (empty when that version has no such requirement).
    securityhub: str
    cis_v5: str
    cis_v3: str
    remediation: str
    # "global" checks run once per account, "regional" checks once per region.
    scope: str
    func: Callable[..., Iterator[Finding]] = field(compare=False, repr=False)


@dataclass
class Finding:
    check_id: str
    status: Status
    resource: str
    region: str
    detail: str
    title: str = ""
    service: str = ""
    severity: str = ""
    securityhub: str = ""
    cis_v5: str = ""
    cis_v3: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d
