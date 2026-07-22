import json
import shutil
import subprocess
import sys
from datetime import datetime

from models import ScanResult, Vulnerability


class ContainerScanner:
    def __init__(self, binary: str = "trivy"):
        self.binary = binary

    def scan(self, image: str) -> ScanResult:
        result = ScanResult(
            repo=image,
            scanner="container",
            scan_date=datetime.utcnow().isoformat(),
        )

        if not shutil.which(self.binary):
            result.errors.append(f"{self.binary} not found in PATH")
            return result

        try:
            proc = subprocess.run(
                [self.binary, "image", "--format", "json", "--quiet", "--no-progress", image],
                capture_output=True,
                text=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            result.errors.append(f"trivy image scan timed out for {image}")
            return result
        except subprocess.SubprocessError as e:
            result.errors.append(str(e))
            return result

        if proc.returncode != 0:
            result.errors.append(proc.stderr.strip() or proc.stdout.strip() or "unknown error")
            return result

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            result.errors.append(f"failed to parse trivy json: {e}")
            return result

        results_list = data.get("Results") or []
        seen: set = set()

        for r in results_list:
            target = r.get("Target", "unknown")
            vulns = r.get("Vulnerabilities") or []

            for v in vulns:
                vid = v.get("VulnerabilityID") or v.get("Id") or ""
                if not vid or vid in seen:
                    continue
                seen.add(vid)

                pkg_name = v.get("PkgName") or v.get("Package") or ""

                result.vulnerabilities.append(Vulnerability(
                    id=vid,
                    package=pkg_name,
                    installed_version=v.get("InstalledVersion") or "",
                    fixed_version=v.get("FixedVersion") or v.get("FixedVersion") or None,
                    severity=v.get("Severity") or v.get("Severity") or "UNKNOWN",
                    type="container",
                    description=v.get("Title") or v.get("Description") or "",
                ))

        return result
