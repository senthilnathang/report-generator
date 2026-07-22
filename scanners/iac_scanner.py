import json
import os
import subprocess
from datetime import datetime

from models import ScanResult, Vulnerability


class IacScanner:
    def __init__(self, binary: str = "checkov"):
        self.binary = binary

    def scan(self, repo: str) -> ScanResult:
        result = ScanResult(
            repo=repo,
            scanner="checkov",
            scan_date=datetime.utcnow().isoformat(),
        )

        if not os.path.isdir(repo):
            result.errors.append("IaC scanner requires a local directory")
            return result

        try:
            proc = subprocess.run(
                [self.binary, "-d", repo, "--output", "json", "--quiet"],
                capture_output=True,
                text=True,
                timeout=600,
            )
            if proc.returncode not in (0, 1):
                result.errors.append(proc.stderr.strip()[:200])
                return result

            stdout = proc.stdout.strip()
            if not stdout:
                return result

            data = json.loads(stdout)
            self._parse(result, data)

        except FileNotFoundError:
            result.errors.append(f"checkov binary not found at '{self.binary}'")
        except subprocess.TimeoutExpired:
            result.errors.append("checkov scan timed out (600s)")
        except json.JSONDecodeError as e:
            result.errors.append(f"failed to parse checkov output: {e}")
        except Exception as e:
            result.errors.append(f"unexpected error: {e}")

        return result

    def _severity_map(self, sev: str | None) -> str:
        return {"CRITICAL": "CRITICAL", "HIGH": "CRITICAL",
                "MEDIUM": "HIGH", "LOW": "MEDIUM"}.get(sev.upper() if sev else "", "HIGH")

    def _parse(self, result: ScanResult, data: dict) -> None:
        results_data = data.get("results", {})
        for c in results_data.get("failed_checks", []):
            sev = c.get("severity") or "HIGH"
            line = c.get("file_line_range", [0, 0])[0]
            file_path = c.get("file_abs_path") or c.get("file_path", "")
            result.vulnerabilities.append(Vulnerability(
                id=c.get("check_id", "unknown"),
                package=f"{file_path}:{line}",
                installed_version="",
                fixed_version=None,
                severity=self._severity_map(sev),
                type="iac",
                description=c.get("check_name", ""),
            ))
