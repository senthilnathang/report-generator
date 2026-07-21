import json
from pathlib import Path

from scan_history import ScanHistory


class DiffReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def compute(self, results: list, repo_map: dict[str, str], history_db: str) -> list[dict]:
        history = ScanHistory(db_path=history_db)
        diffs = []

        for r in results:
            diff = self._diff_vulns(r, repo_map, history)
            if diff is not None:
                diffs.append(diff)

        return diffs

    def _diff_vulns(self, result, repo_map: dict[str, str], history: ScanHistory) -> dict | None:
        repo_url = next((u for u, p in repo_map.items() if p == result.repo), result.repo)
        last = history.get_last_scan(repo_url, result.scanner)
        if last is None:
            return None

        prev_vulns = history.get_scan_vulns(last["id"])
        prev_by_id = {v["id"] for v in prev_vulns}
        curr_by_id = {v.id for v in result.vulnerabilities}

        new_ids = curr_by_id - prev_by_id
        fixed_ids = prev_by_id - curr_by_id
        unchanged_ids = curr_by_id & prev_by_id

        new_vulns = [
            {"id": v.id, "package": v.package, "severity": v.severity,
             "installed_version": v.installed_version, "fixed_version": v.fixed_version}
            for v in result.vulnerabilities if v.id in new_ids
        ]
        fixed_vulns = [v for v in prev_vulns if v["id"] in fixed_ids]

        return {
            "repo_url": repo_url,
            "scanner": result.scanner,
            "current_scan": {
                "commit_sha": last["commit_sha"],
                "scan_date": result.scan_date,
            },
            "previous_scan": {
                "commit_sha": last["commit_sha"],
                "scan_date": last["scan_date"],
            },
            "summary": {
                "new": len(new_vulns),
                "fixed": len(fixed_vulns),
                "unchanged": len(unchanged_ids),
            },
            "new_vulnerabilities": new_vulns,
            "fixed_vulnerabilities": fixed_vulns,
        }

    def generate(self, diffs: list[dict], name: str = "diff_report") -> str:
        out_path = self.output_dir / f"{name}.json"
        with open(out_path, "w") as f:
            json.dump(diffs, f, indent=2)
        return str(out_path)

    def print_summary(self, diffs: list[dict]) -> None:
        total_new = 0
        total_fixed = 0
        for d in diffs:
            s = d["summary"]
            total_new += s["new"]
            total_fixed += s["fixed"]
            parts = []
            if s["new"]:
                parts.append(f"{s['new']} new")
            if s["fixed"]:
                parts.append(f"{s['fixed']} fixed")
            if s["unchanged"]:
                parts.append(f"{s['unchanged']} unchanged")
            print(f"  {d['repo_url']} | {d['scanner']} | {', '.join(parts)}")
        if total_new or total_fixed:
            print(f"  diff totals: {total_new} new, {total_fixed} fixed")
