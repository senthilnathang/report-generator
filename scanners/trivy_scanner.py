import json
import os
import subprocess
import sys
from datetime import datetime

from models import ScanResult, Vulnerability


class TrivyScanner:
    def __init__(self, binary: str = "trivy"):
        self.binary = binary

    def scan(self, repo: str) -> ScanResult:
        result = ScanResult(
            repo=repo,
            scanner="trivy",
            scan_date=datetime.utcnow().isoformat(),
        )

        is_local = os.path.isdir(repo)
        cmd = [self.binary, "fs" if is_local else "repo", "--format", "json", "--quiet", repo]

        try:
            proc = subprocess.run(
                cmd,
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
            result.errors.append(f"trivy binary not found at '{self.binary}'")
        except subprocess.TimeoutExpired:
            result.errors.append("trivy scan timed out (600s)")
        except json.JSONDecodeError as e:
            result.errors.append(f"failed to parse trivy output: {e}")
        except Exception as e:
            result.errors.append(f"unexpected error: {e}")

        return result

    def _parse(self, result: ScanResult, data: dict) -> None:
        for target in data.get("Results", []):
            target_type = target.get("Type", "unknown")
            for vuln in target.get("Vulnerabilities", []):
                result.vulnerabilities.append(Vulnerability(
                    id=vuln.get("VulnerabilityID", "unknown"),
                    package=vuln.get("PkgName", "unknown"),
                    installed_version=vuln.get("InstalledVersion", "unknown"),
                    fixed_version=vuln.get("FixedVersion"),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    type=target_type,
                    description=vuln.get("Title", ""),
                ))
