import json
import os
import subprocess
from datetime import datetime

from models import ScanResult, Vulnerability


class BanditScanner:
    def __init__(self, binary: str = "bandit"):
        self.binary = binary

    def scan(self, repo: str) -> ScanResult:
        result = ScanResult(
            repo=repo,
            scanner="bandit",
            scan_date=datetime.utcnow().isoformat(),
        )

        if not os.path.isdir(repo):
            result.errors.append("bandit requires a local directory")
            return result

        try:
            proc = subprocess.run(
                [self.binary, "-f", "json", "-r", repo],
                capture_output=True,
                text=True,
                timeout=600,
            )
            data = json.loads(proc.stdout)
            self._parse(result, data)

        except FileNotFoundError:
            result.errors.append(f"bandit binary not found at '{self.binary}'")
        except subprocess.TimeoutExpired:
            result.errors.append("bandit scan timed out (600s)")
        except json.JSONDecodeError as e:
            result.errors.append(f"failed to parse bandit output: {e}")
        except Exception as e:
            result.errors.append(f"unexpected error: {e}")

        return result

    def _severity_map(self, sev: str) -> str:
        return {"HIGH": "CRITICAL", "MEDIUM": "HIGH", "LOW": "LOW"}.get(sev.upper(), "UNKNOWN")

    def _parse(self, result: ScanResult, data: dict) -> None:
        for issue in data.get("results", []):
            sev = issue.get("issue_severity", "LOW")
            result.vulnerabilities.append(Vulnerability(
                id=issue.get("test_id", "B000"),
                package=f"{issue.get('filename', '')}:{issue.get('line_number', 0)}",
                installed_version="",
                fixed_version=None,
                severity=self._severity_map(sev),
                type="sast",
                description=issue.get("issue_text", ""),
            ))
