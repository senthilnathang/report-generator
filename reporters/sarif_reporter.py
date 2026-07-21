import json
from pathlib import Path


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "UNKNOWN": "none",
}

SARIF_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "UNKNOWN": "none",
}


class SarifReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: list, name: str = "vulnerability_report") -> str:
        runs = []
        for r in results:
            run = self._result_to_run(r)
            if run:
                runs.append(run)

        sarif_doc = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": runs,
        }

        out_path = self.output_dir / f"{name}.sarif"
        with open(out_path, "w") as f:
            json.dump(sarif_doc, f, indent=2)
        return str(out_path)

    def _result_to_run(self, result) -> dict:
        tool_name = result.scanner.capitalize()
        artifact_uri = result.repo

        results_list = []
        for v in result.vulnerabilities:
            level = SARIF_LEVEL_MAP.get(v.severity.upper(), "none")
            results_list.append({
                "ruleId": v.id,
                "level": level,
                "message": {
                    "text": v.description or f"{v.id} in {v.package} {v.installed_version}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": artifact_uri,
                            },
                            "region": {
                                "message": {
                                    "text": f"{v.package} {v.installed_version}"
                                }
                            }
                        }
                    }
                ],
                "properties": {
                    "package": v.package,
                    "installed_version": v.installed_version,
                    "fixed_version": v.fixed_version or "",
                    "severity": v.severity,
                    "type": v.type,
                }
            })

        rules = []
        seen_rules = set()
        for v in result.vulnerabilities:
            if v.id not in seen_rules:
                seen_rules.add(v.id)
                rules.append({
                    "id": v.id,
                    "shortDescription": {
                        "text": v.description or v.id,
                    },
                    "fullDescription": {
                        "text": v.description or f"{v.id} in {v.package} {v.installed_version}",
                    },
                    "properties": {
                        "tags": [v.severity.lower(), v.type],
                    },
                })

        return {
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": f"https://github.com/aquasecurity/{tool_name.lower()}" if tool_name != "Snyk" else "https://snyk.io",
                    "rules": rules,
                }
            },
            "artifacts": [
                {
                    "location": {
                        "uri": artifact_uri,
                    }
                }
            ],
            "results": results_list,
            "columnKind": "utf16CodeUnits",
            "properties": {
                "scan_date": result.scan_date,
                "errors": result.errors,
            },
        }
