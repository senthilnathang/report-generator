import json
import os
import subprocess
from datetime import datetime

from models import ScanResult, Vulnerability


class SemgrepScanner:
    def __init__(self, binary: str = "semgrep"):
        self.binary = binary

    def scan(self, repo: str) -> ScanResult:
        result = ScanResult(
            repo=repo,
            scanner="semgrep",
            scan_date=datetime.utcnow().isoformat(),
        )

        if not os.path.isdir(repo):
            result.errors.append("semgrep requires a local directory")
            return result

        try:
            proc = subprocess.run(
                [self.binary, "--json", "--config", "auto", "--quiet", repo],
                capture_output=True,
                text=True,
                timeout=600,
            )
            if proc.returncode not in (0, 1):
                result.errors.append(proc.stderr.strip())
                return result

            data = json.loads(proc.stdout)
            self._parse(result, data)

        except FileNotFoundError:
            result.errors.append(f"semgrep binary not found at '{self.binary}'")
        except subprocess.TimeoutExpired:
            result.errors.append("semgrep scan timed out (600s)")
        except json.JSONDecodeError as e:
            result.errors.append(f"failed to parse semgrep output: {e}")
        except Exception as e:
            result.errors.append(f"unexpected error: {e}")

        return result

    def _severity_map(self, sev: str) -> str:
        return {"ERROR": "CRITICAL", "WARNING": "HIGH", "INFO": "LOW"}.get(sev.upper(), "UNKNOWN")

    def _parse(self, result: ScanResult, data: dict) -> None:
        for match in data.get("results", []):
            extra = match.get("extra", {})
            sev = extra.get("severity", "WARNING")
            start = match.get("start", {})
            result.vulnerabilities.append(Vulnerability(
                id=match.get("check_id", "unknown"),
                package=f"{match.get('path', '')}:{start.get('line', 0)}",
                installed_version="",
                fixed_version=None,
                severity=self._severity_map(sev),
                type="sast",
                description=extra.get("message", ""),
            ))
