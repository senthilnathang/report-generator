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
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    risk_score: Optional[float] = None
    risk_level: str = ""


@dataclass
class LicenseFinding:
    name: str
    severity: str
    category: str
    package: str
    file_path: str
    confidence: float
    link: str = ""


@dataclass
class ScanResult:
    repo: str
    scanner: str
    scan_date: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    licenses: list[LicenseFinding] = field(default_factory=list)

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

    @property
    def license_summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for l in self.licenses:
            counts[l.name] = counts.get(l.name, 0) + 1
        return counts

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = self.summary
        d["license_summary"] = self.license_summary
        return d
