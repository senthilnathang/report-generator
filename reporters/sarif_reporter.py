import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _sarif_level(severity: str) -> str:
    s = severity.upper()
    if s in ("CRITICAL", "HIGH"):
        return "error"
    if s == "MEDIUM":
        return "warning"
    if s == "LOW":
        return "note"
    return "none"


def _uri_from_vuln(vuln) -> str:
    vtype = vuln.type.lower()
    if vtype in ("secret", "sast", "iac"):
        return vuln.package.split(":")[0] if ":" in vuln.package else vuln.package
    return f"pkg:{vuln.package}"


def _line_from_vuln(vuln) -> int:
    if ":" in vuln.package:
        try:
            return int(vuln.package.split(":")[-1])
        except ValueError:
            pass
    return 1


class SarifReporter:
    def __init__(self, output_dir: str = "reports", tool_name: str = "scan-tui"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.tool_name = tool_name

    def generate(self, results: list, name: str = "results") -> str:
        rules_map: dict = {}
        results_list = []
        run_artifacts: dict = {}

        for scan in results:
            for v in scan.vulnerabilities:
                rule_id = v.id or "unknown"
                if rule_id not in rules_map:
                    rules_map[rule_id] = {
                        "id": rule_id,
                        "name": rule_id,
                        "shortDescription": {"text": v.description[:200] if v.description else rule_id},
                        "fullDescription": {"text": v.description or ""},
                        "defaultConfiguration": {"level": _sarif_level(v.severity)},
                        "properties": {
                            "severity": v.severity,
                            "type": v.type,
                            "scanner": scan.scanner,
                            "repo": scan.repo,
                        },
                    }
                    if v.epss is not None:
                        rules_map[rule_id]["properties"]["epss"] = v.epss
                    if v.fixed_version:
                        rules_map[rule_id]["properties"]["fixedVersion"] = v.fixed_version
                    if v.installed_version:
                        rules_map[rule_id]["properties"]["installedVersion"] = v.installed_version

                rule_level = "error" if v.severity.upper() in ("CRITICAL", "HIGH") else "warning"

                artifact_uri = _uri_from_vuln(v)
                run_artifacts[artifact_uri] = artifact_uri

                result = {
                    "ruleId": rule_id,
                    "ruleIndex": list(rules_map.keys()).index(rule_id),
                    "level": rule_level,
                    "message": {"text": v.description or rule_id},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": artifact_uri},
                                "region": {"startLine": _line_from_vuln(v)},
                            }
                        }
                    ],
                    "properties": {
                        "scanner": scan.scanner,
                        "repo": scan.repo,
                        "package": v.package,
                        "installedVersion": v.installed_version or "",
                        "fixedVersion": v.fixed_version or "",
                        "type": v.type,
                    },
                }

                results_list.append(result)

        runs = [
            {
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": "1.0.0",
                        "informationUri": "https://github.com/user/scan-tui",
                        "rules": list(rules_map.values()),
                    }
                },
                "artifacts": [{"location": {"uri": u}} for u in run_artifacts],
                "results": results_list,
                "columnKind": "unicodeCodePoints",
                "properties": {
                    "totalScanResults": len(results_list),
                    "scannersUsed": list({s.scanner for s in results}),
                    "reposScanned": list({s.repo for s in results}),
                },
            }
        ]

        sarif_doc = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": runs,
        }

        out_path = self.output_dir / f"{name}.sarif"
        with open(out_path, "w") as f:
            json.dump(sarif_doc, f, indent=2)

        return str(out_path)
