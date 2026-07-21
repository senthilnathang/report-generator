import json
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from packaging.version import Version


REGISTRY_URLS = {
    "npm": "https://registry.npmjs.org/{name}/latest",
    "pypi": "https://pypi.org/pypi/{name}/json",
}


class OutdatedReporter:
    def __init__(self, output_dir: str = "reports", max_workers: int = 10):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers
        self._cache: dict[str, str | None] = {}

    def generate(self, dep_results: list, name: str = "outdated_report") -> str:
        pkgs = self._collect_packages(dep_results)
        outdated = self._check_outdated(pkgs)

        report = {
            "summary": self._summarize(outdated),
            "results": outdated,
        }

        json_path = self.output_dir / f"{name}.json"
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

        html_path = self.output_dir / f"{name}.html"
        with open(html_path, "w") as f:
            f.write(self._render_html(report))

        return str(json_path)

    def _collect_packages(self, dep_results: list) -> list[dict]:
        seen: dict[str, dict] = {}
        for entry in dep_results:
            repo = entry.get("repo", "unknown")
            for p in entry.get("packages", []):
                key = f"{p['name']}@{p['version']}"
                if key not in seen:
                    seen[key] = {
                        "name": p["name"],
                        "installed": p["version"],
                        "type": p["type"],
                        "repos": [],
                    }
                if repo not in seen[key]["repos"]:
                    seen[key]["repos"].append(repo)
        return list(seen.values())

    def _fetch_latest(self, name: str, pkg_type: str) -> str | None:
        cache_key = f"{pkg_type}:{name}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        url_template = REGISTRY_URLS.get(pkg_type)
        if not url_template:
            self._cache[cache_key] = None
            return None

        url = url_template.format(name=urllib.parse.quote(name, safe=""))

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "report-generator/1.0", "Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())

            if pkg_type == "npm":
                latest = data.get("version")
            elif pkg_type == "pypi":
                latest = data.get("info", {}).get("version")
            else:
                latest = data.get("version")

            self._cache[cache_key] = latest
            return latest
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, KeyError):
            self._cache[cache_key] = None
            return None

    def _check_outdated(self, pkgs: list[dict]) -> list[dict]:
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            fut_map = {}
            for p in pkgs:
                fut = executor.submit(self._fetch_latest, p["name"], p["type"])
                fut_map[fut] = p

            for fut in as_completed(fut_map):
                p = fut_map[fut]
                latest = fut.result()
                installed = p["installed"]

                entry = {
                    "name": p["name"],
                    "type": p["type"],
                    "installed": installed,
                    "latest": latest or "unknown",
                    "behind": "unknown",
                    "repos": p["repos"],
                }

                if latest:
                    entry["behind"] = self._version_diff(installed, latest)

                results.append(entry)

        results.sort(key=lambda x: self._sort_key(x["behind"]), reverse=True)
        return results

    def _version_diff(self, installed: str, latest: str) -> str:
        try:
            v_inst = Version(installed)
            v_latest = Version(latest)
        except Exception:
            return "unknown"

        if v_inst >= v_latest:
            return "up-to-date"

        # simple semver check
        parts_inst = [p for p in str(v_inst).split(".")]
        parts_latest = [p for p in str(v_latest).split(".")]

        if len(parts_inst) >= 1 and len(parts_latest) >= 1 and parts_inst[0] != parts_latest[0]:
            return f"{int(parts_latest[0]) - int(parts_inst[0])} major behind"
        if len(parts_inst) >= 2 and len(parts_latest) >= 2 and parts_inst[1] != parts_latest[1]:
            return f"{int(parts_latest[1]) - int(parts_inst[1])} minor behind"
        return f"{int(parts_latest[2]) - int(parts_inst[2])} patch behind" if len(parts_inst) >= 3 and len(parts_latest) >= 3 else "up-to-date"

    def _sort_key(self, behind: str) -> int:
        if "major" in behind:
            return 3
        if "minor" in behind:
            return 2
        if "patch" in behind:
            return 1
        return 0

    def _summarize(self, results: list) -> dict:
        total = len(results)
        outdated_count = sum(1 for r in results if r["behind"] not in ("up-to-date", "unknown"))
        major = sum(1 for r in results if "major" in r["behind"])
        minor = sum(1 for r in results if "minor" in r["behind"])
        patch = sum(1 for r in results if "patch" in r["behind"])
        return {
            "total_packages": total,
            "outdated": outdated_count,
            "major_behind": major,
            "minor_behind": minor,
            "patch_behind": patch,
            "up_to_date": total - outdated_count,
        }

    def _render_html(self, report: dict) -> str:
        rows = ""
        for r in report["results"]:
            behind = r["behind"]
            color = "#e53e3e" if "major" in behind else "#ed8936" if "minor" in behind else "#d69e2e" if "patch" in behind else "#38a169"
            rows += f"""
            <tr>
              <td><strong>{r['name']}</strong></td>
              <td>{r['type']}</td>
              <td>{r['installed']}</td>
              <td>{r['latest']}</td>
              <td style="color:{color};font-weight:600;">{behind}</td>
              <td>{', '.join(r['repos'][:2])}</td>
            </tr>"""

        s = report["summary"]
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Outdated Dependencies Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #1a1a2e; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.3rem; }}
  .subtitle {{ color: #666; margin-bottom: 2rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: #fff; border-radius: 10px; padding: 1rem; box-shadow: 0 2px 8px rgba(0,0,0,0.06); text-align: center; }}
  .card .count {{ font-size: 1.8rem; font-weight: 700; }}
  .card .label {{ font-size: 0.75rem; text-transform: uppercase; color: #888; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  th {{ background: #2d3748; color: #fff; padding: 0.7rem 1rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #edf2f7; font-size: 0.9rem; }}
  tr:hover {{ background: #f7fafc; }}
</style>
</head>
<body>
  <h1>Outdated Dependencies</h1>
  <p class="subtitle">{s['total_packages']} packages checked</p>
  <div class="cards">
    <div class="card"><div class="count" style="color:#e53e3e">{s['major_behind']}</div><div class="label">Major Behind</div></div>
    <div class="card"><div class="count" style="color:#ed8936">{s['minor_behind']}</div><div class="label">Minor Behind</div></div>
    <div class="card"><div class="count" style="color:#d69e2e">{s['patch_behind']}</div><div class="label">Patch Behind</div></div>
    <div class="card"><div class="count" style="color:#38a169">{s['up_to_date']}</div><div class="label">Up to Date</div></div>
  </div>
  <table>
    <thead><tr><th>Package</th><th>Type</th><th>Installed</th><th>Latest</th><th>Behind</th><th>Repos</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""

    def print_summary(self, report: dict) -> None:
        s = report["summary"]
        print(f"\nOutdated Dependencies Summary")
        print(f"{'='*40}")
        print(f"  Total packages: {s['total_packages']}")
        print(f"  Outdated: {s['outdated']}")
        print(f"    Major behind: {s['major_behind']}")
        print(f"    Minor behind: {s['minor_behind']}")
        print(f"    Patch behind: {s['patch_behind']}")
        print(f"  Up to date: {s['up_to_date']}")
        print()
        for r in report["results"]:
            if r["behind"] not in ("up-to-date", "unknown"):
                print(f"  {r['name']:35s} {r['installed']:12s} → {r['latest']:12s}  ({r['behind']})")
