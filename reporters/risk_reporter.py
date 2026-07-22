import json
from datetime import datetime
from pathlib import Path

from risk_scorer import enrich as risk_enrich, get_top


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Risk Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #1a1a2e; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.3rem; }}
  .subtitle {{ color: #666; margin-bottom: 2rem; }}
  .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); text-align: center; padding: 1.2rem; }}
  .card .num {{ font-size: 2rem; font-weight: 800; }}
  .card .lbl {{ color: #888; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .risk-critical {{ color: #e53e3e; }} .risk-high {{ color: #ed8936; }}
  .risk-medium {{ color: #d69e2e; }} .risk-low {{ color: #38a169; }} .risk-info {{ color: #718096; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  th {{ text-align: left; padding: 0.8rem 1rem; background: #2d3748; color: #fff; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.7rem 1rem; border-bottom: 1px solid #edf2f7; }}
  tr:last-child td {{ border: none; }}
  tr:hover {{ background: #f7fafc; }}
  .score-bar {{ display: inline-block; height: 6px; border-radius: 3px; margin-right: 0.5rem; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 10px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }}
  .bg-critical {{ background: #fed7d7; color: #9b2c2c; }} .bg-high {{ background: #feebc8; color: #9c4221; }}
  .bg-medium {{ background: #fefcbf; color: #744210; }} .bg-low {{ background: #c6f6d5; color: #276749; }} .bg-info {{ background: #e2e8f0; color: #4a5568; }}
  canvas {{ max-height: 250px; margin-bottom: 2rem; }}
  @media (max-width: 768px) {{ body {{ padding: 1rem; }} table {{ font-size: 0.8rem; }} th, td {{ padding: 0.5rem; }} }}
</style>
</head>
<body>
  <h1>Risk Report</h1>
  <p class="subtitle">{date} &middot; {total_vulns} vulnerabilities &middot; {total_repos} repos</p>

  <div class="summary-cards">
    <div class="card"><div class="num risk-critical">{critical_count}</div><div class="lbl">Critical Risk</div></div>
    <div class="card"><div class="num risk-high">{high_count}</div><div class="lbl">High Risk</div></div>
    <div class="card"><div class="num risk-medium">{medium_count}</div><div class="lbl">Medium Risk</div></div>
    <div class="card"><div class="num risk-low">{low_count}</div><div class="lbl">Low Risk</div></div>
    <div class="card"><div class="num risk-info">{info_count}</div><div class="lbl">Info</div></div>
  </div>

  <canvas id="riskChart"></canvas>

  <table>
    <thead><tr><th>Rank</th><th>Score</th><th>ID</th><th>Package</th><th>Severity</th><th>EPSS</th><th>Fix</th><th>Repo</th><th>Risk</th></tr></thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <script>
    new Chart(document.getElementById('riskChart'), {{
      type: 'doughnut',
      data: {{
        labels: ['Critical ({critical_count})', 'High ({high_count})', 'Medium ({medium_count})', 'Low ({low_count})', 'Info ({info_count})'],
        datasets: [{{ data: [{critical_count}, {high_count}, {medium_count}, {low_count}, {info_count}], backgroundColor: ['#e53e3e','#ed8936','#d69e2e','#38a169','#a0aec0'] }}]
      }},
      options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom' }} }} }}
    }});
  </script>
</body>
</html>"""


class RiskReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: list, name: str = "risk_report") -> str:
        results = risk_enrich(results)
        top = get_top(results, n=500)

        summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for scan in results:
            for v in scan.vulnerabilities:
                level = v.risk_level or "info"
                if level in summary:
                    summary[level] += 1

        report = {
            "generated_at": datetime.now().isoformat(),
            "total_vulns": sum(summary.values()),
            "total_repos": len({r.repo for r in results}),
            "summary": summary,
            "top_findings": top,
        }

        html = self._render_html(report, summary)

        out_path = self.output_dir / f"{name}.html"
        with open(out_path, "w") as f:
            f.write(html)

        json_path = self.output_dir / f"{name}.json"
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

        return str(out_path)

    def _render_html(self, report: dict, summary: dict) -> str:
        rows = ""
        for i, f in enumerate(report["top_findings"], 1):
            level = f.get("risk_level", "info")
            score = f.get("risk_score", 0)
            sev = f.get("severity", "").lower()

            bar_color = {"critical": "#e53e3e", "high": "#ed8936", "medium": "#d69e2e",
                         "low": "#38a169", "info": "#a0aec0"}.get(level, "#a0aec0")
            badge_cls = f"bg-{level}"
            epss_str = f"{f['epss']:.2%}" if f.get("epss") is not None else "-"
            fix_str = f["fixed_version"] or "no fix"

            rows += f"""<tr>
              <td>{i}</td>
              <td><span class="score-bar" style="width:{score/2}px;background:{bar_color}"></span>{score:.0f}</td>
              <td><strong>{f['id']}</strong></td>
              <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{f['package']}</td>
              <td class="risk-{sev}"><strong>{f['severity']}</strong></td>
              <td>{epss_str}</td>
              <td>{fix_str}</td>
              <td style="max-width:150px;overflow:hidden;text-overflow:ellipsis">{f['repo']}</td>
              <td><span class="badge {badge_cls}">{level}</span></td>
            </tr>"""

        return HTML_TEMPLATE.format(
            date=report["generated_at"][:19].replace("T", " "),
            total_vulns=report["total_vulns"],
            total_repos=report["total_repos"],
            critical_count=summary.get("critical", 0),
            high_count=summary.get("high", 0),
            medium_count=summary.get("medium", 0),
            low_count=summary.get("low", 0),
            info_count=summary.get("info", 0),
            rows=rows,
        )

    def print_summary(self, report: dict) -> None:
        s = report.get("summary", {})
        print(f"\nRisk Summary")
        print("=" * 40)
        print(f"  Total vulns:  {report['total_vulns']}")
        print(f"  Critical risk: {s.get('critical', 0)}")
        print(f"  High risk:     {s.get('high', 0)}")
        print(f"  Medium risk:   {s.get('medium', 0)}")
        print(f"  Low risk:      {s.get('low', 0)}")
        print(f"  Info:          {s.get('info', 0)}")
        top = report.get("top_findings", [])
        if top:
            print(f"\n  Top {len(top)} findings:")
            for f in top[:5]:
                print(f"    {f['risk_score']:5.0f}  {f['id']:25s}  {f['risk_level']:8s}  {f['repo'][:30]}")
