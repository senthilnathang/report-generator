import json
from pathlib import Path


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vulnerability Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #1a1a2e; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
  .subtitle {{ color: #666; margin-bottom: 2rem; }}
  .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: #fff; border-radius: 12px; padding: 1.2rem; box-shadow: 0 2px 8px rgba(0,0,0,0.06); text-align: center; }}
  .card .count {{ font-size: 2rem; font-weight: 700; }}
  .card .label {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: #888; margin-top: 0.3rem; }}
  .critical .count {{ color: #e53e3e; }} .high .count {{ color: #ed8936; }} .medium .count {{ color: #d69e2e; }} .low .count {{ color: #38a169; }} .total .count {{ color: #4a5568; }}
  .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }}
  .chart-box {{ background: #fff; border-radius: 12px; padding: 1rem; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  .chart-box h2 {{ font-size: 1rem; margin-bottom: 0.5rem; color: #4a5568; }}
  .chart-box canvas {{ max-height: 260px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  th {{ background: #2d3748; color: #fff; padding: 0.75rem 1rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.65rem 1rem; border-bottom: 1px solid #edf2f7; font-size: 0.9rem; }}
  tr:hover {{ background: #f7fafc; }}
  .sev-critical {{ color: #e53e3e; font-weight: 600; }} .sev-high {{ color: #ed8936; font-weight: 600; }}
  .sev-medium {{ color: #d69e2e; }} .sev-low {{ color: #38a169; }} .sev-unknown {{ color: #a0aec0; }}
  .repo-section {{ margin-bottom: 2rem; }}
  .repo-section h2 {{ font-size: 1.1rem; margin-bottom: 0.5rem; color: #2d3748; }}
  .error-badge {{ display: inline-block; background: #fed7d7; color: #c53030; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; }}
  @media (max-width: 768px) {{ .charts {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
  <h1>Vulnerability Report</h1>
  <p class="subtitle">{date} &middot; {total_scans} scans &middot; {total_vulns} vulnerabilities</p>

  <div class="summary-cards">
    <div class="card critical"><div class="count">{critical}</div><div class="label">Critical</div></div>
    <div class="card high"><div class="count">{high}</div><div class="label">High</div></div>
    <div class="card medium"><div class="count">{medium}</div><div class="label">Medium</div></div>
    <div class="card low"><div class="count">{low}</div><div class="label">Low</div></div>
    <div class="card total"><div class="count">{total_vulns}</div><div class="label">Total</div></div>
  </div>

  <div class="charts">
    <div class="chart-box"><h2>Severity Distribution</h2><canvas id="severityChart"></canvas></div>
    <div class="chart-box"><h2>By Scanner</h2><canvas id="scannerChart"></canvas></div>
  </div>

  <div id="reports"></div>

  <script>
    const data = {json_data};
    const summary = {json_summary};

    new Chart(document.getElementById('severityChart'), {{
      type: 'doughnut',
      data: {{
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{{
          data: [summary.critical, summary.high, summary.medium, summary.low],
          backgroundColor: ['#e53e3e', '#ed8936', '#d69e2e', '#38a169'],
        }}]
      }},
      options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom' }} }} }}
    }});

    const scannerLabels = Object.keys(summary.by_scanner);
    const scannerCounts = Object.values(summary.by_scanner);
    const colors = ['#4299e1', '#48bb78', '#ed64a6'];
    new Chart(document.getElementById('scannerChart'), {{
      type: 'bar',
      data: {{
        labels: scannerLabels,
        datasets: [{{
          label: 'Vulnerabilities',
          data: scannerCounts,
          backgroundColor: colors.slice(0, scannerLabels.length),
        }}]
      }},
      options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }} }}
    }});

    const reports = document.getElementById('reports');
    data.forEach(r => {{
      const div = document.createElement('div');
      div.className = 'repo-section';
      const errs = r.errors && r.errors.length ? `<span class="error-badge">${{r.errors.length}} errors</span>` : '';
      div.innerHTML = `
        <h2>${{r.repo}} <small>${{r.scanner}}</small> ${{errs}}</h2>
        <table>
          <thead><tr><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Severity</th><th>Type</th></tr></thead>
          <tbody>
            ${{r.vulnerabilities.map(v => `
              <tr>
                <td><strong>${{v.id}}</strong></td>
                <td>${{v.package}}</td>
                <td>${{v.installed_version}}</td>
                <td>${{v.fixed_version || '—'}}</td>
                <td class="sev-${{v.severity.toLowerCase()}}">${{v.severity}}</td>
                <td>${{v.type}}</td>
              </tr>
            `).join('')}}
          </tbody>
        </table>
      `;
      reports.appendChild(div);
    }});
  </script>
</body>
</html>"""


class HtmlReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: list, name: str = "vulnerability_report") -> str:
        from datetime import datetime

        data = [r.to_dict() for r in results]
        total_vulns = sum(len(r.vulnerabilities) for r in results)
        critical = sum(r.summary.get("CRITICAL", 0) for r in results)
        high = sum(r.summary.get("HIGH", 0) for r in results)
        medium = sum(r.summary.get("MEDIUM", 0) for r in results)
        low = sum(r.summary.get("LOW", 0) for r in results)

        by_scanner = {}
        for r in results:
            by_scanner[r.scanner] = by_scanner.get(r.scanner, 0) + len(r.vulnerabilities)

        summary = {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total": total_vulns,
            "by_scanner": by_scanner,
        }

        html = HTML_TEMPLATE.format(
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_scans=len(results),
            total_vulns=total_vulns,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            json_data=json.dumps(data),
            json_summary=json.dumps(summary),
        )

        out_path = self.output_dir / f"{name}.html"
        with open(out_path, "w") as f:
            f.write(html)
        return str(out_path)
