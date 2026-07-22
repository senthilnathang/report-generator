import json
import os
import subprocess
from datetime import datetime
from pathlib import Path


SCORECARD_CHECKS = [
    "Binary-Artifacts", "Branch-Protection", "CI-Tests", "Code-Review",
    "Contributors", "Dangerous-Workflow", "Dependency-Update-Tool",
    "Fuzzing", "License", "Maintained", "Packaging", "Pinned-Dependencies",
    "SAST", "Security-Policy", "Signed-Releases", "Token-Permissions",
    "Vulnerabilities",
]


class ScorecardRunner:
    def __init__(self, binary: str = "scorecard"):
        self.binary = binary

    def run(self, repo: str) -> dict | None:
        try:
            is_local = os.path.isdir(repo)
            cmd = [self.binary]
            if is_local:
                cmd.extend(["--local", repo])
            else:
                cmd.extend(["--repo", repo])
            cmd.extend(["--format", "json", "--show-details"])

            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
            if proc.returncode != 0:
                return None

            return json.loads(proc.stdout)

        except (FileNotFoundError, subprocess.TimeoutExpired,
                json.JSONDecodeError, Exception):
            return None


def score_repos(repos: list[str], runner: ScorecardRunner | None = None) -> list[dict]:
    if runner is None:
        runner = ScorecardRunner()

    results = []
    for repo in repos:
        name = Path(repo).name if os.path.isdir(repo) else repo.split("/")[-1]
        print(f"  scoring {name}...")
        data = runner.run(repo)
        if data and "checks" in data:
            results.append(data)
        else:
            results.append({
                "date": datetime.now().isoformat(),
                "repo": {"name": repo, "commit": "unknown"},
                "score": 0,
                "checks": [],
                "error": "scorecard scan failed",
            })

    return results


def compute_summary(results: list[dict]) -> dict:
    total = len(results)
    if total == 0:
        return {"total_repos": 0, "avg_score": 0, "repos": []}

    repo_summaries = []
    for r in results:
        repo_name = r.get("repo", {}).get("name", "unknown")
        score = r.get("score", 0)
        check_scores = {c["name"]: c["score"] for c in r.get("checks", [])}
        repo_summaries.append({
            "repo": repo_name,
            "score": score,
            "checks": check_scores,
        })

    avg_score = sum(s["score"] for s in repo_summaries) / total
    return {
        "total_repos": total,
        "avg_score": round(avg_score, 1),
        "repos": repo_summaries,
    }
