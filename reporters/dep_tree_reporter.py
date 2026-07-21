import csv
import json
import os
import subprocess
from pathlib import Path


class DependencyTreeReporter:
    """Extract full dependency tree from a repo using Trivy's package metadata."""

    def __init__(self, output_dir: str = "reports", binary: str = "trivy"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.binary = binary

    def generate(self, results: list, name: str = "dependency_tree") -> str:
        all_pkgs = []
        for r in results:
            all_pkgs.append({
                "repo": r["repo"],
                "packages": r["packages"],
                "summary": {
                    "total": r["total"],
                    "direct": r["direct"],
                    "indirect": r["indirect"],
                },
            })

        out_path = self.output_dir / f"{name}.json"
        with open(out_path, "w") as f:
            json.dump(all_pkgs, f, indent=2)
        return str(out_path)

    def generate_csv(self, results: list, name: str = "dependency_tree") -> str:
        out_path = self.output_dir / f"{name}.csv"
        with open(out_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["repo", "name", "version", "relationship", "type", "purl", "depends_on"])
            for r in results:
                for p in r["packages"]:
                    w.writerow([
                        r["repo"],
                        p["name"],
                        p["version"],
                        p["relationship"],
                        p["type"],
                        p["purl"],
                        p["depends_on"],
                    ])
        return str(out_path)

    def scan_target(self, target: str) -> dict | None:
        if not os.path.isdir(target):
            return None

        cmd = [
            self.binary, "fs",
            "--format", "json",
            "--quiet",
            target,
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if proc.returncode != 0:
                return {"repo": target, "error": proc.stderr.strip(), "packages": [],
                        "total": 0, "direct": 0, "indirect": 0}

            data = json.loads(proc.stdout)
            return self._extract(target, data)

        except FileNotFoundError:
            return {"repo": target, "error": f"trivy binary not found", "packages": [],
                    "total": 0, "direct": 0, "indirect": 0}
        except subprocess.TimeoutExpired:
            return {"repo": target, "error": "trivy timed out", "packages": [],
                    "total": 0, "direct": 0, "indirect": 0}
        except json.JSONDecodeError as e:
            return {"repo": target, "error": f"parse error: {e}", "packages": [],
                    "total": 0, "direct": 0, "indirect": 0}
        except Exception as e:
            return {"repo": target, "error": str(e), "packages": [],
                    "total": 0, "direct": 0, "indirect": 0}

    def _extract(self, repo: str, data: dict) -> dict:
        all_packages: list[dict] = []
        seen = set()

        for result in data.get("Results", []):
            pkg_type = result.get("Type", "unknown")
            for pkg in result.get("Packages", []):
                pkg_id = pkg.get("ID", "")
                if pkg_id in seen:
                    continue
                seen.add(pkg_id)

                purl = ""
                identifier = pkg.get("Identifier", {})
                if isinstance(identifier, dict):
                    purl = identifier.get("PURL", "")

                depends_on = pkg.get("DependsOn", [])
                relationship = pkg.get("Relationship", "unknown")

                all_packages.append({
                    "id": pkg_id,
                    "name": pkg.get("Name", ""),
                    "version": pkg.get("Version", ""),
                    "relationship": relationship,
                    "type": pkg_type,
                    "purl": purl,
                    "depends_on": "; ".join(depends_on) if depends_on else "",
                })

        direct = sum(1 for p in all_packages if p["relationship"] == "direct")
        indirect = sum(1 for p in all_packages if p["relationship"] in ("indirect", "transitive"))

        return {
            "repo": repo,
            "packages": all_packages,
            "total": len(all_packages),
            "direct": direct,
            "indirect": indirect,
            "error": "",
        }

    def print_summary(self, results: list) -> None:
        for r in results:
            if r.get("error"):
                print(f"  {r['repo']}: ERROR - {r['error']}")
            else:
                print(f"  {r['repo']}: {r['total']} deps ({r['direct']} direct, {r['indirect']} indirect)")
