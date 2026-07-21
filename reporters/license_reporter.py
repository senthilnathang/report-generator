import json
from pathlib import Path


POLICY_ACTIONS = ["allow", "deny"]


class LicenseReporter:
    def __init__(self, output_dir: str = "reports", policy: dict[str, str] | None = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.policy = policy or {}

    def generate(self, results: list, name: str = "license_report") -> str:
        data = []
        policy_violations = []

        for r in results:
            entry = {
                "repo": r.repo,
                "scanner": r.scanner,
                "scan_date": r.scan_date,
                "licenses": [{
                    "name": l.name,
                    "severity": l.severity,
                    "category": l.category,
                    "package": l.package,
                    "file_path": l.file_path,
                    "confidence": l.confidence,
                    "link": l.link,
                } for l in r.licenses],
                "license_summary": r.license_summary,
            }
            data.append(entry)

            if self.policy:
                for l in r.licenses:
                    action = self._check_policy(l.name)
                    if action == "deny":
                        policy_violations.append({
                            "repo": r.repo,
                            "license": l.name,
                            "package": l.package,
                            "file_path": l.file_path,
                            "action": "deny",
                            "reason": f"License '{l.name}' is blocked by policy",
                        })

        report = {
            "summary": self._compute_summary(data),
            "policy_violations": policy_violations,
            "results": data,
        }

        out_path = self.output_dir / f"{name}.json"
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
        return str(out_path)

    def _compute_summary(self, data: list) -> dict:
        total_licenses = 0
        license_counts: dict[str, int] = {}
        for entry in data:
            for l in entry["licenses"]:
                total_licenses += 1
                license_counts[l["name"]] = license_counts.get(l["name"], 0) + 1
        return {
            "total_repos": len(data),
            "total_licenses": total_licenses,
            "unique_licenses": len(license_counts),
            "by_license": license_counts,
        }

    def _check_policy(self, license_name: str) -> str:
        name = license_name.lower()
        for key, action in self.policy.items():
            if key.lower() == name:
                return action
        return "allow"

    def print_summary(self, results: list) -> None:
        for r in results:
            if r.licenses:
                names = ", ".join(sorted(set(l.name for l in r.licenses)))
                print(f"  {r.repo}: {len(r.licenses)} files, licenses: {names}")

    def print_violations(self, results: list) -> list[dict]:
        violations = []
        if not self.policy:
            return violations
        for r in results:
            for l in r.licenses:
                action = self._check_policy(l.name)
                if action == "deny":
                    violations.append({
                        "repo": r.repo,
                        "license": l.name,
                        "package": l.package,
                        "file_path": l.file_path,
                    })
                    print(f"  POLICY VIOLATION: {l.name} in {r.repo} ({l.file_path})")
        return violations
