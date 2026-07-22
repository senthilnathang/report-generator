import json
import os
import subprocess
import tempfile
from datetime import datetime

from models import ScanResult, Vulnerability


class SecretScanner:
    def __init__(self, binary: str = "gitleaks"):
        self.binary = binary

    def scan(self, repo: str) -> ScanResult:
        result = ScanResult(
            repo=repo,
            scanner="gitleaks",
            scan_date=datetime.utcnow().isoformat(),
        )

        if not os.path.isdir(repo):
            result.errors.append("secret scanner requires a local directory")
            return result

        try:
            is_git = os.path.isdir(os.path.join(repo, ".git"))
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                report_path = tmp.name

            cmd = [self.binary, "detect", "--source", repo,
                   "-f", "json", "--report-path", report_path]
            if not is_git:
                cmd.append("--no-git")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            if proc.returncode not in (0, 1):
                result.errors.append(proc.stderr.strip())
                if os.path.exists(report_path):
                    os.unlink(report_path)
                return result

            if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
                with open(report_path) as f:
                    data = json.load(f)
                self._parse(result, data)
                os.unlink(report_path)

        except FileNotFoundError:
            result.errors.append(f"gitleaks binary not found at '{self.binary}'")
        except subprocess.TimeoutExpired:
            result.errors.append("secret scan timed out (600s)")
        except json.JSONDecodeError as e:
            result.errors.append(f"failed to parse gitleaks output: {e}")
        except Exception as e:
            result.errors.append(f"unexpected error: {e}")

        return result

    def _severity_from_tags(self, tags: list[str]) -> str:
        tag_set = {t.lower() for t in tags}
        high_risk = {"aws", "gcp", "azure", "github", "gitlab", "slack", "stripe",
                     "private", "password", "credential", "token", "api"}
        if tag_set & high_risk:
            return "CRITICAL"
        if tags:
            return "HIGH"
        return "HIGH"

    def _parse(self, result: ScanResult, data: list[dict]) -> None:
        for leak in data:
            tags = leak.get("Tags", [])
            result.vulnerabilities.append(Vulnerability(
                id=leak.get("RuleID", "unknown"),
                package=f"{leak.get('File', '')}:{leak.get('StartLine', 0)}",
                installed_version="",
                fixed_version=None,
                severity=self._severity_from_tags(tags),
                type="secret",
                description=leak.get("Description", ""),
            ))
