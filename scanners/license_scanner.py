import json
import os
import subprocess
from datetime import datetime

from models import LicenseFinding, ScanResult


class LicenseScanner:
    def __init__(self, binary: str = "trivy"):
        self.binary = binary

    def scan(self, repo: str) -> ScanResult:
        result = ScanResult(
            repo=repo,
            scanner="license",
            scan_date=datetime.utcnow().isoformat(),
        )

        if not os.path.isdir(repo):
            result.errors.append("license scanner requires a local directory")
            return result

        cmd = [
            self.binary, "fs",
            "--scanners", "license",
            "--license-full",
            "--format", "json",
            "--quiet",
            repo,
        ]

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
            result.errors.append("license scan timed out (600s)")
        except json.JSONDecodeError as e:
            result.errors.append(f"failed to parse trivy output: {e}")
        except Exception as e:
            result.errors.append(f"unexpected error: {e}")

        return result

    def _parse(self, result: ScanResult, data: dict) -> None:
        for target in data.get("Results", []):
            for lic in target.get("Licenses", []):
                result.licenses.append(LicenseFinding(
                    name=lic.get("Name", "unknown"),
                    severity=lic.get("Severity", "LOW"),
                    category=lic.get("Category", ""),
                    package=lic.get("PkgName", ""),
                    file_path=lic.get("FilePath", ""),
                    confidence=lic.get("Confidence", 0.0),
                    link=lic.get("Link", ""),
                ))
