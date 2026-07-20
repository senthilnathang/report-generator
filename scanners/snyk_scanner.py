import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from models import ScanResult, Vulnerability


class SnykScanner:
    def __init__(self, binary: str = "snyk"):
        self.binary = binary

    def scan(self, repo: str) -> ScanResult:
        result = ScanResult(
            repo=repo,
            scanner="snyk",
            scan_date=datetime.utcnow().isoformat(),
        )

        is_local = os.path.isdir(repo)

        try:
            if is_local:
                proc = subprocess.run(
                    [self.binary, "test", "--json"],
                    cwd=repo,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
            else:
                proc = subprocess.run(
                    [self.binary, "test", f"--remote-repo-url={repo}", "--json"],
                    capture_output=True,
                    text=True,
                    timeout=600,
                )

            stdout = proc.stdout.strip()
            if not stdout:
                result.errors.append(proc.stderr.strip() or "empty output from snyk")
                return result

            data = json.loads(stdout)
            self._parse(result, data)

        except FileNotFoundError:
            result.errors.append(f"snyk binary not found at '{self.binary}'")
        except subprocess.TimeoutExpired:
            result.errors.append("snyk scan timed out (600s)")
        except json.JSONDecodeError as e:
            result.errors.append(f"failed to parse snyk output: {e}")
        except Exception as e:
            result.errors.append(f"unexpected error: {e}")

        return result

    def _parse(self, result: ScanResult, data: list | dict) -> None:
        if isinstance(data, list):
            for item in data:
                self._parse_vuln(result, item)
        elif isinstance(data, dict):
            for vuln in data.get("vulnerabilities", []):
                self._parse_vuln(result, vuln)

    def _parse_vuln(self, result: ScanResult, vuln: dict) -> None:
        result.vulnerabilities.append(Vulnerability(
            id=vuln.get("id", "unknown"),
            package=vuln.get("packageName", "unknown"),
            installed_version=vuln.get("version", "unknown"),
            fixed_version=vuln.get("fixedIn", [None])[0] if vuln.get("fixedIn") else None,
            severity=vuln.get("severity", "UNKNOWN"),
            type=vuln.get("packageManager", "unknown"),
            description=vuln.get("title", ""),
        ))
