import json
import subprocess
from pathlib import Path


class SbomReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_for_target(self, target: str, name: str = "sbom", fmt: str = "cyclonedx") -> str | None:
        if not Path(target).is_dir():
            return None

        out_path = self.output_dir / f"{name}-sbom.{fmt}.json"

        try:
            proc = subprocess.run(
                ["trivy", "fs", "--format", fmt, "--quiet", target],
                capture_output=True, text=True, timeout=180,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                return None

            data = json.loads(proc.stdout)
            with open(out_path, "w") as f:
                json.dump(data, f, indent=2)
            return str(out_path)

        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return None
