from typing import Any

import yaml

from models import ScanResult, Vulnerability


class ControlRule:
    def __init__(self, rule: dict[str, str]):
        self.severity = rule.get("severity", "").strip().upper()
        self.type = rule.get("type", "").strip().lower()
        self.id = rule.get("id", "").strip()
        self.package = rule.get("package", "").strip()
        self.scanner = rule.get("scanner", "").strip()

    def matches(self, vuln: Vulnerability, scan: ScanResult) -> bool:
        if self.severity:
            sevs = [s.strip().upper() for s in self.severity.split(",")]
            if vuln.severity.upper() not in sevs:
                return False
        if self.type and self.type != vuln.type.lower():
            return False
        if self.id and self.id != vuln.id:
            return False
        if self.package and self.package.lower() not in vuln.package.lower():
            return False
        if self.scanner and self.scanner.lower() != scan.scanner.lower():
            return False
        return True


class Control:
    def __init__(self, data: dict[str, Any]):
        self.id = data.get("id", "")
        self.name = data.get("name", "")
        self.description = data.get("description", "")
        self.rules = [ControlRule(r) for r in data.get("rules", [])]

    def check(self, vuln: Vulnerability, scan: ScanResult) -> bool:
        if not self.rules:
            return True
        return any(r.matches(vuln, scan) for r in self.rules)


class Framework:
    def __init__(self, data: dict[str, Any]):
        self.id = data.get("id", "")
        self.version = data.get("version", "")
        self.controls = [Control(c) for c in data.get("controls", [])]

    def evaluate(
        self, results: list[ScanResult]
    ) -> dict[str, Any]:
        control_results = []
        for ctrl in self.controls:
            affected: list[dict[str, Any]] = []
            for scan in results:
                for v in scan.vulnerabilities:
                    if ctrl.check(v, scan):
                        affected.append({
                            "id": v.id,
                            "package": v.package,
                            "severity": v.severity,
                            "scanner": scan.scanner,
                            "repo": scan.repo,
                            "type": v.type,
                        })
            control_results.append({
                "id": ctrl.id,
                "name": ctrl.name,
                "description": ctrl.description,
                "status": "violated" if affected else "passed",
                "violations": len(affected),
                "affected_findings": affected[:50],
                "total_affected": len(affected),
            })

        violated = sum(1 for c in control_results if c["status"] == "violated")
        total = len(control_results)
        score = int((total - violated) / max(total, 1) * 100) if total else 100

        return {
            "id": self.id,
            "version": self.version,
            "controls": control_results,
            "violated_controls": violated,
            "total_controls": total,
            "compliance_score": score,
        }


class ComplianceEngine:
    def __init__(self, frameworks: list[Framework]):
        self.frameworks = frameworks

    @classmethod
    def load(cls, path: str | None) -> "ComplianceEngine":
        if not path:
            return cls([])
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except FileNotFoundError:
            return cls([])
        if not data or "frameworks" not in data:
            return cls([])
        frameworks = [Framework(fw) for fw in data["frameworks"]]
        return cls(frameworks)

    def evaluate(self, results: list[ScanResult]) -> dict[str, Any]:
        framework_results = {}
        for fw in self.frameworks:
            framework_results[fw.id] = fw.evaluate(results)
        return {
            "frameworks": framework_results,
            "generated_at": __import__("datetime").datetime.now().isoformat(),
        }
