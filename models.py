from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


@dataclass
class Vulnerability:
    id: str
    package: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    type: str
    description: str = ""


@dataclass
class ScanResult:
    repo: str
    scanner: str
    scan_date: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for v in self.vulnerabilities:
            sev = v.severity.upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["UNKNOWN"] += 1
        return counts

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = self.summary
        return d
