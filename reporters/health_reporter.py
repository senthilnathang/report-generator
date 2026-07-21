import json
from datetime import datetime
from pathlib import Path


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Repository Health Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #1a1a2e; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.3rem; }}
  .subtitle {{ color: #666; margin-bottom: 2rem; }}
  .overall {{ text-align: center; margin-bottom: 2rem; }}
  .score-ring {{ width: 140px; height: 140px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 2.5rem; font-weight: 800; color: #fff; }}
  .score-excellent {{ background: #38a169; }} .score-good {{ background: #4299e1; }}
  .score-fair {{ background: #d69e2e; }} .score-poor {{ background: #e53e3e; }}
  .score-label {{ font-size: 0.85rem; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.5rem; }}
  .repo-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
  .repo-card {{ background: #fff; border-radius: 14px; box-shadow: 0 2px 12px rgba(0,0,0,0.06); overflow: hidden; }}
  .repo-card h2 {{ font-size: 1.1rem; padding: 1rem 1.2rem; background: #2d3748; color: #fff; }}
  .repo-card h2 small {{ font-weight: 400; font-size: 0.8rem; opacity: 0.7; }}
  .repo-body {{ padding: 1rem 1.2rem; }}
  .metric-row {{ display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #edf2f7; }}
  .metric-row:last-child {{ border: none; }}
  .metric-label {{ color: #4a5568; }}
  .metric-value {{ font-weight: 600; }}
  .crit {{ color: #e53e3e; }} .high {{ color: #ed8936; }} .med {{ color: #d69e2e; }} .low {{ color: #38a169; }}
  .sub-scores {{ display: flex; gap: 0.5rem; margin-top: 0.8rem; }}
  .sub-score {{ flex: 1; text-align: center; padding: 0.5rem; border-radius: 8px; font-size: 0.8rem; }}
  .sub-score .val {{ font-weight: 700; font-size: 1.1rem; }}
  .sub-security {{ background: #fff5f5; }} .sub-deps {{ background: #ebf8ff; }} .sub-license {{ background: #f0fff4; }}
  canvas {{ max-height: 200px; }}
  @media (max-width: 768px) {{ .repo-cards {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
  <h1>Repository Health Report</h1>
  <p class="subtitle">{date} &middot; {total_repos} repos</p>

  <div class="overall">
    <div class="score-ring score-{overall_class}">{overall_score}</div>
    <div class="score-label">Overall Health Score</div>
  </div>

  <div class="repo-cards">
    {repo_cards}
  </div>

  <canvas id="overviewChart"></canvas>
  <script>
    const scores = {chart_data};
    new Chart(document.getElementById('overviewChart'), {{
      type: 'bar',
      data: {{
        labels: scores.map(s => s.repo),
        datasets: [
          {{ label: 'Security', data: scores.map(s => s.security), backgroundColor: '#e53e3e' }},
          {{ label: 'Dependencies', data: scores.map(s => s.deps), backgroundColor: '#4299e1' }},
          {{ label: 'License', data: scores.map(s => s.license), backgroundColor: '#38a169' }},
        ]
      }},
      options: {{
        responsive: true,
        plugins: {{ legend: {{ position: 'bottom' }} }},
        scales: {{ y: {{ min: 0, max: 100, beginAtZero: true }} }}
      }}
    }});
  </script>
</body>
</html>"""


class HealthReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, vuln_results: list, dep_results: list | None = None,
                 license_results: list | None = None, name: str = "health_report") -> str:
        dep_map = {}
        if dep_results:
            for d in dep_results:
                dep_map[d.get("repo", "")] = d

        lic_map = {}
        if license_results:
            for lr in license_results:
                lic_map[lr.get("repo", "")] = lr

        repos = self._group_by_repo(vuln_results, dep_map, lic_map)
        report = self._build_report(repos)

        html = self._render_html(report)

        out_path = self.output_dir / f"{name}.html"
        with open(out_path, "w") as f:
            f.write(html)

        json_path = self.output_dir / f"{name}.json"
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

        return str(out_path)

    def _group_by_repo(self, vuln_results: list, dep_map: dict, lic_map: dict) -> list[dict]:
        seen: dict[str, dict] = {}
        for r in vuln_results:
            if hasattr(r, 'to_dict'):
                r = r.to_dict()
            repo_name = r.get("repo", "unknown")
            summary = r.get("summary", {})
            scanner = r.get("scanner", "")

            if repo_name not in seen:
                seen[repo_name] = {
                    "repo": repo_name,
                    "scanners": set(),
                    "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
                }
            entry = seen[repo_name]
            entry["scanners"].add(scanner)
            for sev, count in summary.items():
                if sev in entry["summary"]:
                    entry["summary"][sev] += count

        result = []
        for repo_name, entry in seen.items():
            entry["scanners"] = sorted(entry["scanners"])
            entry["dep_info"] = dep_map.get(repo_name, {})
            entry["lic_info"] = lic_map.get(repo_name, {})
            self._compute_health(entry)
            result.append(entry)

        result.sort(key=lambda r: r["health"]["overall"], reverse=True)
        return result

    def _compute_health(self, entry: dict) -> None:
        s = entry["summary"]
        total_vulns = sum(s.values())

        # security score (0-100)
        security = 100
        security -= s.get("CRITICAL", 0) * 30
        security -= s.get("HIGH", 0) * 15
        security -= s.get("MEDIUM", 0) * 5
        security -= s.get("LOW", 0) * 1
        security = max(0, security)

        # dependency score (0-100)
        deps = 100
        dep_info = entry.get("dep_info", {})
        indirect = dep_info.get("indirect", dep_info.get("summary", {}).get("indirect", 0)) if isinstance(dep_info, dict) else 0
        deps -= (indirect // 50) * 5
        deps = max(0, deps)

        # license score (0-100)
        lic = 100
        lic_info = entry.get("lic_info", {})
        if isinstance(lic_info, dict):
            violations = len(lic_info.get("policy_violations", []))
            lic -= violations * 50
        lic = max(0, lic)

        overall = int(security * 0.5 + deps * 0.25 + lic * 0.25)

        entry["health"] = {
            "overall": overall,
            "security": security,
            "deps": deps,
            "license": lic,
            "total_vulns": total_vulns,
        }

    def _build_report(self, repos: list[dict]) -> dict:
        total_repos = len(repos)
        avg_overall = int(sum(r["health"]["overall"] for r in repos) / max(total_repos, 1))
        total_vulns = sum(r["health"]["total_vulns"] for r in repos)
        total_crit = sum(r["summary"].get("CRITICAL", 0) for r in repos)
        total_high = sum(r["summary"].get("HIGH", 0) for r in repos)

        return {
            "generated_at": datetime.now().isoformat(),
            "total_repos": total_repos,
            "overall_score": avg_overall,
            "total_vulnerabilities": total_vulns,
            "total_critical": total_crit,
            "total_high": total_high,
            "repos": repos,
        }

    def _score_class(self, score: int) -> str:
        if score >= 80:
            return "excellent"
        elif score >= 60:
            return "good"
        elif score >= 40:
            return "fair"
        return "poor"

    def _render_html(self, report: dict) -> str:
        overall = report["overall_score"]
        overall_class = self._score_class(overall)

        chart_data = []
        card_html = ""
        for r in report["repos"]:
            h = r["health"]
            short_name = r["repo"].split("/")[-1]
            sec_class = self._score_class(h["security"])
            dep_class = self._score_class(h["deps"])
            lic_class = self._score_class(h["license"])

            s = r["summary"]
            dep_info = r["dep_info"] if isinstance(r["dep_info"], dict) else {}
            dep_s = dep_info  # flat keys: total, direct, indirect
            lic_s = r.get("lic_info", {})
            violations = len(lic_s.get("policy_violations", [])) if isinstance(lic_s, dict) else 0

            chart_data.append({
                "repo": short_name,
                "security": h["security"],
                "deps": h["deps"],
                "license": h["license"],
            })

            card_html += f"""
            <div class="repo-card">
              <h2>{short_name} <small>{', '.join(r['scanners'])}</small></h2>
              <div class="repo-body">
                <div class="metric-row">
                  <span class="metric-label">Overall</span>
                  <span class="metric-value">{h['overall']}/100</span>
                </div>
                <div class="metric-row">
                  <span class="metric-label">Vulnerabilities</span>
                  <span class="metric-value">
                    <span class="crit">{s.get('CRITICAL',0)}</span> /
                    <span class="high">{s.get('HIGH',0)}</span> /
                    <span class="med">{s.get('MEDIUM',0)}</span> /
                    <span class="low">{s.get('LOW',0)}</span>
                    <span style="color:#888;">(C/H/M/L)</span>
                  </span>
                </div>
                <div class="metric-row">
                  <span class="metric-label">Dependencies</span>
                  <span class="metric-value">{dep_s.get('direct',0)} direct / {dep_s.get('indirect',0)} indirect</span>
                </div>
                <div class="metric-row">
                  <span class="metric-label">License violations</span>
                  <span class="metric-value" style="color:{'#e53e3e' if violations else '#38a169'}">{violations}</span>
                </div>
                <div class="sub-scores">
                  <div class="sub-score sub-security">
                    <div class="val">{h['security']}</div>
                    <div>Security</div>
                  </div>
                  <div class="sub-score sub-deps">
                    <div class="val">{h['deps']}</div>
                    <div>Deps</div>
                  </div>
                  <div class="sub-score sub-license">
                    <div class="val">{h['license']}</div>
                    <div>License</div>
                  </div>
                </div>
              </div>
            </div>"""

        return HTML_TEMPLATE.format(
            date=report["generated_at"][:19].replace("T", " "),
            total_repos=report["total_repos"],
            overall_score=overall,
            overall_class=overall_class,
            repo_cards=card_html,
            chart_data=json.dumps(chart_data),
        )

    def print_summary(self, report: dict) -> None:
        print(f"\nRepository Health Summary")
        print(f"{'='*50}")
        print(f"  Overall score: {report['overall_score']}/100")
        print(f"  Repos: {report['total_repos']}")
        print(f"  Total vulns: {report['total_vulnerabilities']} ({report['total_critical']} critical, {report['total_high']} high)")
        print()
        for r in report["repos"]:
            h = r["health"]
            short = r["repo"].split("/")[-1]
            print(f"  {short:20s}  {h['overall']:3d}/100  (S:{h['security']:3d} D:{h['deps']:3d} L:{h['license']:3d})")
