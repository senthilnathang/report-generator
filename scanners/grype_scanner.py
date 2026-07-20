import json
import subprocess
import sys
from datetime import datetime

from models import ScanResult, Vulnerability


class GrypeScanner:
    def __init__(self, binary: str = "grype"):
        self.binary = binary

    def scan(self, repo: str) -> ScanResult:
        result = ScanResult(
            repo=repo,
            scanner="grype",
            scan_date=datetime.utcnow().isoformat(),
        )

        try:
            proc = subprocess.run(
                [self.binary, repo, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=600,
            )
            if proc.returncode != 0:
                result.errors.append(proc.stderr.strip())
                return result

            data = json.loads(proc.stdout)
            self._parse(result, data)

        except FileNotFoundError:
            result.errors.append(f"grype binary not found at '{self.binary}'")
        except subprocess.TimeoutExpired:
            result.errors.append("grype scan timed out (600s)")
        except json.JSONDecodeError as e:
            result.errors.append(f"failed to parse grype output: {e}")
        except Exception as e:
            result.errors.append(f"unexpected error: {e}")

        return result

    def _parse(self, result: ScanResult, data: dict) -> None:
        for match in data.get("matches", []):
            art = match.get("artifact", {})
            vuln = match.get("vulnerability", {})
            result.vulnerabilities.append(Vulnerability(
                id=vuln.get("id", "unknown"),
                package=art.get("name", "unknown"),
                installed_version=art.get("version", "unknown"),
                fixed_version=vuln.get("fix", {}).get("versions", [None])[0] if vuln.get("fix") else None,
                severity=vuln.get("severity", "UNKNOWN"),
                type=art.get("type", "unknown"),
                description=vuln.get("description", ""),
            ))
