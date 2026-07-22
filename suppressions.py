from typing import Any

import yaml

from models import ScanResult, Vulnerability


class SuppressionRule:
    def __init__(self, rule: dict[str, str]):
        self.id = rule.get("id", "").strip()
        self.package = rule.get("package", "").strip()
        self.scanner = rule.get("scanner", "").strip()
        self.severity = rule.get("severity", "").strip().upper()
        self.repo = rule.get("repo", "").strip()
        self.type = rule.get("type", "").strip().lower()
        self.reason = rule.get("reason", "suppressed")

    def matches(self, vuln: Vulnerability, scan: ScanResult) -> bool:
        if self.id and self.id not in vuln.id:
            return False
        if self.package and self.package.lower() not in vuln.package.lower():
            return False
        if self.scanner and self.scanner.lower() != scan.scanner.lower():
            return False
        if self.severity and self.severity != vuln.severity.upper():
            return False
        if self.repo and self.repo not in scan.repo:
            return False
        if self.type and self.type != vuln.type.lower():
            return False
        return True

    def __repr__(self) -> str:
        parts = []
        for attr in ("id", "package", "scanner", "severity", "repo", "type"):
            val = getattr(self, attr)
            if val:
                parts.append(f"{attr}={val}")
        return f"Suppression({', '.join(parts)})"


class SuppressionManager:
    def __init__(self, rules: list[SuppressionRule] | None = None):
        self.rules = rules or []

    @classmethod
    def load(cls, path: str | None) -> "SuppressionManager":
        if not path:
            return cls()
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except FileNotFoundError:
            return cls()
        if not data or "suppressions" not in data:
            return cls()
        rules = [SuppressionRule(r) for r in data["suppressions"]]
        return cls(rules)

    def is_suppressed(self, vuln: Vulnerability, scan: ScanResult) -> bool:
        return any(r.matches(vuln, scan) for r in self.rules)

    def filter_results(
        self, results: list[ScanResult]
    ) -> tuple[list[ScanResult], list[dict]]:
        suppressed_log: list[dict] = []
        filtered: list[ScanResult] = []
        for scan in results:
            kept: list[Vulnerability] = []
            for v in scan.vulnerabilities:
                if self.is_suppressed(v, scan):
                    suppressed_log.append({
                        "id": v.id,
                        "package": v.package,
                        "severity": v.severity,
                        "scanner": scan.scanner,
                        "repo": scan.repo,
                    })
                else:
                    kept.append(v)
            filtered.append(ScanResult(
                repo=scan.repo,
                scanner=scan.scanner,
                scan_date=scan.scan_date,
                vulnerabilities=kept,
                errors=scan.errors,
                licenses=scan.licenses,
            ))
        return filtered, suppressed_log
