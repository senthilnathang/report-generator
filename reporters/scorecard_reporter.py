import json
from datetime import datetime
from pathlib import Path

from scorers.scorecard_scorer import score_repos, compute_summary


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenSSF Scorecard Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #1a1a2e; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.3rem; }}
  .subtitle {{ color: #666; margin-bottom: 2rem; }}
  .overall {{ text-align: center; margin-bottom: 2rem; }}
  .score-ring {{ width: 140px; height: 140px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 2.8rem; font-weight: 800; color: #fff; margin-bottom: 0.5rem; }}
  .score-excellent {{ background: #38a169; }} .score-good {{ background: #4299e1; }}
  .score-fair {{ background: #d69e2e; }} .score-poor {{ background: #e53e3e; }}
  .repo-section {{ background: #fff; border-radius: 14px; box-shadow: 0 2px 12px rgba(0,0,0,0.06); margin-bottom: 2rem; overflow: hidden; }}
  .repo-header {{ padding: 1rem 1.5rem; background: #2d3748; color: #fff; display: flex; justify-content: space-between; align-items: center; }}
  .repo-header h2 {{ font-size: 1.1rem; }}
  .repo-body {{ padding: 1.5rem; }}
  .check-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 0.8rem; }}
  .check-card {{ border: 1px solid #edf2f7; border-radius: 10px; padding: 0.8rem 1rem; }}
  .check-card .check-name {{ font-weight: 600; font-size: 0.85rem; color: #4a5568; margin-bottom: 0.3rem; }}
  .check-card .check-score {{ font-size: 1.3rem; font-weight: 700; }}
  .sc-10 {{ color: #38a169; }} .sc-7 {{ color: #4299e1; }} .sc-4 {{ color: #d69e2e; }} .sc-0 {{ color: #e53e3e; }}
  canvas {{ max-height: 300px; margin-bottom: 2rem; }}
  @media (max-width: 768px) {{ body {{ padding: 1rem; }} }}
</style>
</head>
<body>
  <h1>OpenSSF Scorecard Report</h1>
  <p class="subtitle">{date} &middot; {total_repos} repo(s) &middot; Average Score: {avg_score}/10</p>

  <div class="overall">
    <div class="score-ring score-{avg_class}">{avg_score}</div>
    <div style="color:#888;text-transform:uppercase;font-size:0.8rem;letter-spacing:0.05em;">Average Score</div>
  </div>

  <canvas id="overviewChart"></canvas>

  {repo_sections}

  <script>
    const chartData = {chart_data};
    new Chart(document.getElementById('overviewChart'), {{
      type: 'radar',
      data: {{
        labels: chartData[0].labels,
        datasets: chartData.map(d => ({{
          label: d.repo,
          data: d.scores,
          fill: true,
        }}))
      }},
      options: {{
        responsive: true,
        scales: {{ r: {{ min: 0, max: 10, ticks: {{ stepSize: 2 }} }} }},
        plugins: {{ legend: {{ position: 'bottom' }} }}
      }}
    }});
  </script>
</body>
</html>"""


class ScorecardReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, repos: list[str], name: str = "scorecard_report") -> str:
        results = score_repos(repos)
        summary = compute_summary(results)
        summary["generated_at"] = datetime.now().isoformat()

        html = self._render_html(summary, results)
        out_path = self.output_dir / f"{name}.html"
        with open(out_path, "w") as f:
            f.write(html)

        json_path = self.output_dir / f"{name}.json"
        with open(json_path, "w") as f:
            json.dump(summary, f, indent=2)

        return str(out_path)

    def _score_class(self, score: float) -> str:
        if score >= 8: return "excellent"
        if score >= 6: return "good"
        if score >= 4: return "fair"
        return "poor"

    def _score_css(self, score: float) -> str:
        if score >= 8: return "sc-10"
        if score >= 6: return "sc-7"
        if score >= 4: return "sc-4"
        return "sc-0"

    def _render_html(self, summary: dict, raw_results: list[dict]) -> str:
        avg = summary["avg_score"]
        avg_class = self._score_class(avg)

        chart_data = []
        repo_sections = ""
        all_check_names: set[str] = set()

        for r in raw_results:
            repo_name = r.get("repo", {}).get("name", "unknown")
            score = r.get("score", 0)
            checks = {c["name"]: c for c in r.get("checks", [])}
            for c_name in checks:
                all_check_names.add(c_name)

        for r in raw_results:
            repo_name = r.get("repo", {}).get("name", "unknown")
            score = r.get("score", 0)
            checks = {c["name"]: c for c in r.get("checks", [])}

            check_cards = ""
            radar_labels = []
            radar_scores = []
            for c_name in sorted(checks.keys()):
                c = checks[c_name]
                c_score = c.get("score", 0)
                css = self._score_css(c_score)
                check_cards += f"""
                <div class="check-card">
                  <div class="check-name">{c_name}</div>
                  <div class="check-score {css}">{c_score}/10</div>
                  <div style="font-size:0.75rem;color:#888;">{c.get('reason', '')[:60]}</div>
                </div>"""
                radar_labels.append(c_name)
                radar_scores.append(c_score)

            chart_data.append({"repo": repo_name.split("/")[-1], "labels": radar_labels, "scores": radar_scores})
            repo_class = self._score_class(score)

            repo_sections += f"""
            <div class="repo-section">
              <div class="repo-header">
                <h2>{repo_name}</h2>
                <span class="score-ring score-{repo_class}" style="width:50px;height:50px;font-size:1.2rem;">{score}</span>
              </div>
              <div class="repo-body">
                <div class="check-grid">{check_cards}</div>
              </div>
            </div>"""

        return HTML_TEMPLATE.format(
            date=summary.get("generated_at", "")[:19].replace("T", " "),
            total_repos=summary["total_repos"],
            avg_score=avg,
            avg_class=avg_class,
            repo_sections=repo_sections,
            chart_data=json.dumps(chart_data),
        )

    def print_summary(self, summary: dict) -> None:
        print(f"\nOpenSSF Scorecard Summary")
        print("=" * 40)
        print(f"  Repos:        {summary['total_repos']}")
        print(f"  Average score: {summary['avg_score']}/10")
        for r in summary.get("repos", []):
            print(f"  {r['repo'][:50]:50s} {r['score']}/10")
