import json
import sqlite3
from datetime import datetime
from pathlib import Path

from scan_history import ScanHistory


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Regression Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #1a1a2e; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; }}
  .subtitle {{ color: #666; margin-bottom: 1.5rem; }}
  .alert {{ padding: 1rem; border-radius: 10px; margin-bottom: 1.5rem; font-weight: 600; }}
  .alert-pass {{ background: #c6f6d5; color: #276749; }}
  .alert-fail {{ background: #fed7d7; color: #9b2c2c; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 1.2rem; text-align: center; }}
  .card .n {{ font-size: 2rem; font-weight: 800; }}
  .card .l {{ color: #888; font-size: 0.75rem; text-transform: uppercase; }}
  .red {{ color: #e53e3e; }} .green {{ color: #38a169; }} .yellow {{ color: #d69e2e; }}
  .repo-box {{ background: #fff; border-radius: 14px; box-shadow: 0 2px 12px rgba(0,0,0,0.06); margin-bottom: 1.5rem; overflow: hidden; }}
  .repo-hdr {{ padding: 0.8rem 1.2rem; background: #2d3748; color: #fff; display: flex; justify-content: space-between; }}
  .repo-hdr h2 {{ font-size: 1rem; }}
  .repo-bd {{ padding: 1rem 1.2rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align: left; padding: 0.5rem 0.6rem; background: #edf2f7; color: #4a5568; }}
  td {{ padding: 0.4rem 0.6rem; border-bottom: 1px solid #edf2f7; }}
  .tag {{ display: inline-block; padding: 0.1rem 0.4rem; border-radius: 8px; font-size: 0.7rem; font-weight: 600; }}
  .tag-new {{ background: #fed7d7; color: #9b2c2c; }}
  .tag-re {{ background: #fefcbf; color: #744210; }}
  .sev-crit {{ color: #e53e3e; font-weight: 700; }}
  .sev-high {{ color: #ed8936; font-weight: 600; }}
  .sev-med {{ color: #d69e2e; }}
  .sev-low {{ color: #38a169; }}
</style>
</head>
<body>
  <h1>Regression Report</h1>
  <p class="subtitle">{date} | {repos} repos | {scans} historical scans</p>

  <div class="alert alert-{cls}">{msg}</div>

  <div class="cards">
    <div class="card"><div class="n red">{new_v}</div><div class="l">New Regressions</div></div>
    <div class="card"><div class="n yellow">{re_v}</div><div class="l">Reintroduced</div></div>
    <div class="card"><div class="n green">{fixed_v}</div><div class="l">Fixed</div></div>
  </div>

  {sections}
</body>
</html>"""


def _analyze_repo(repo_url: str, scans: list, history: ScanHistory, history_db: str) -> dict:
    scanner_new: dict[str, set[str]] = {}
    scanner_reintro: dict[str, set[str]] = {}
    scanner_fixed: dict[str, set[str]] = {}
    scanner_vulns: list[dict] = []

    for scan in scans:
        scanner = scan.scanner
        curr_ids = {v.id for v in scan.vulnerabilities}

        for v in scan.vulnerabilities:
            scanner_vulns.append({
                "id": v.id, "severity": v.severity, "package": v.package,
                "scanner": scanner, "status": "existing",
            })

        prev = history.get_last_scan(repo_url, scanner, offset=1)
        if not prev:
            scanner_new[scanner] = curr_ids
            continue

        prev_vulns = history.get_scan_vulns(prev["id"])
        prev_ids = {v["id"] for v in prev_vulns}
        prev_latest = {v["id"]: v for v in prev_vulns}

        new_ids = curr_ids - prev_ids
        scanner_new[scanner] = new_ids

        fixed_ids = prev_ids - curr_ids
        scanner_fixed[scanner] = fixed_ids

        prev2 = history.get_last_scan(repo_url, scanner, offset=2)
        reintro_ids: set[str] = set()
        if prev2:
            prev2_vulns = history.get_scan_vulns(prev2["id"])
            prev2_ids = {v["id"] for v in prev2_vulns}
            reintro_ids = (prev2_ids - prev_ids) & curr_ids
        scanner_reintro[scanner] = reintro_ids

    total_new = set()
    total_reintro = set()
    total_fixed = set()
    for s in scanner_new:
        total_new |= scanner_new[s]
    for s in scanner_reintro:
        total_reintro |= scanner_reintro[s]
    for s in scanner_fixed:
        total_fixed |= scanner_fixed[s]

    # Update status for vulns
    for v in scanner_vulns:
        if v["id"] in total_new:
            v["status"] = "new"
        elif v["id"] in total_reintro:
            v["status"] = "reintroduced"

    prev_count = 0
    for scan in scans:
        prev = history.get_last_scan(repo_url, scan.scanner, offset=1)
        if prev:
            prev_vulns = history.get_scan_vulns(prev["id"])
            prev_count += len(prev_vulns)

    curr_count = sum(len(s.vulnerabilities) for s in scans)

    return {
        "repo": repo_url,
        "new_regressions": len(total_new),
        "reintroduced": len(total_reintro),
        "fixed": len(total_fixed),
        "before_vulns": prev_count,
        "after_vulns": curr_count,
        "vulns": sorted(scanner_vulns, key=lambda x: x["severity"]),
    }


class RegressionReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, current_results: list, history_db: str, name: str = "regression_report") -> str:
        history = ScanHistory(db_path=history_db)

        repo_groups: dict[str, list] = {}
        for r in current_results:
            repo_groups.setdefault(r.repo, []).append(r)

        repo_data = []
        for repo_url, scans in repo_groups.items():
            repo_data.append(_analyze_repo(repo_url, scans, history, history_db))

        all_new = sum(r["new_regressions"] for r in repo_data)
        all_re = sum(r["reintroduced"] for r in repo_data)
        all_fixed = sum(r["fixed"] for r in repo_data)
        all_before = sum(r["before_vulns"] for r in repo_data)
        all_after = sum(r["after_vulns"] for r in repo_data)

        has_regression = all_new > 0 or all_re > 0

        total_scans = 0
        with sqlite3.connect(history_db) as conn:
            for repo_url in repo_groups:
                cur = conn.execute("SELECT COUNT(*) FROM scan_runs WHERE repo_url=?", (repo_url,))
                total_scans += cur.fetchone()[0]

        sections = ""
        for rd in repo_data:
            short = rd["repo"].split("/")[-1] if "/" in rd["repo"] else rd["repo"]
            rows = ""
            for v in rd["vulns"]:
                tag = ""
                if v["status"] == "new":
                    tag = '<span class="tag tag-new">NEW</span>'
                elif v["status"] == "reintroduced":
                    tag = '<span class="tag tag-re">RE</span>'
                sev_cls = f"sev-{v['severity'].lower()}"
                rows += f"""<tr>
                  <td>{tag} {v['id']}</td>
                  <td class="{sev_cls}">{v['severity']}</td>
                  <td>{v['package'][:45]}</td>
                  <td>{v['scanner']}</td>
                </tr>"""
            if not rows:
                rows = '<tr><td colspan="4" style="text-align:center;color:#888;">No vulnerabilities</td></tr>'

            sections += f"""
            <div class="repo-box">
              <div class="repo-hdr">
                <h2>{short}</h2>
                <span>{rd['new_regressions']} new / {rd['reintroduced']} reintro / {rd['fixed']} fixed</span>
              </div>
              <div class="repo-bd">
                <table><thead><tr><th>ID</th><th>Severity</th><th>Package</th><th>Scanner</th></tr></thead>
                <tbody>{rows}</tbody></table>
              </div>
            </div>"""

        overall_cls = "fail" if has_regression else "pass"
        overall_msg = (
            f"No regressions detected ({all_fixed} fixed)"
            if not has_regression
            else f"{all_new} new regression(s), {all_re} reintroduced across {len(repo_data)} repo(s)"
        )

        report = {
            "generated_at": datetime.now().isoformat(),
            "overall_status": "regression" if has_regression else "pass",
            "new_regressions": all_new,
            "reintroduced": all_re,
            "fixed_count": all_fixed,
            "before_vulns": all_before,
            "after_vulns": all_after,
            "total_repos": len(repo_data),
            "total_scans": total_scans,
            "repos": repo_data,
        }

        html = HTML_TEMPLATE.format(
            date=report["generated_at"][:19].replace("T", " "),
            repos=report["total_repos"],
            scans=report["total_scans"],
            cls=overall_cls,
            msg=overall_msg,
            new_v=all_new,
            re_v=all_re,
            fixed_v=all_fixed,
            sections=sections,
        )

        out_path = self.output_dir / f"{name}.html"
        with open(out_path, "w") as f:
            f.write(html)

        json_path = self.output_dir / f"{name}.json"
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

        return str(out_path)

    def print_summary(self, report: dict) -> None:
        print(f"\nRegression Check")
        print("=" * 50)
        print(f"  Status:          {report['overall_status'].upper()}")
        print(f"  New regressions: {report['new_regressions']}")
        print(f"  Reintroduced:    {report['reintroduced']}")
        print(f"  Fixed:           {report['fixed_count']}")
        print(f"  Before:          {report['before_vulns']} vulns")
        print(f"  After:           {report['after_vulns']} vulns")
        for rd in report.get("repos", []):
            short = rd["repo"].split("/")[-1]
            print(f"  {short:30s} +{rd['new_regressions']}/~{rd['reintroduced']}/-{rd['fixed']}")
