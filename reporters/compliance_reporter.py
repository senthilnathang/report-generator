import json
from datetime import datetime
from pathlib import Path

from compliance_mapping import ComplianceEngine


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Compliance Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #1a1a2e; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.3rem; }}
  .subtitle {{ color: #666; margin-bottom: 2rem; }}
  .framework {{ background: #fff; border-radius: 14px; box-shadow: 0 2px 12px rgba(0,0,0,0.06); margin-bottom: 2rem; overflow: hidden; }}
  .fw-header {{ padding: 1rem 1.5rem; background: #2d3748; color: #fff; display: flex; justify-content: space-between; align-items: center; }}
  .fw-header h2 {{ font-size: 1.2rem; }}
  .fw-header small {{ font-weight: 400; font-size: 0.8rem; opacity: 0.7; }}
  .score-badge {{ padding: 0.3rem 1rem; border-radius: 20px; font-weight: 700; font-size: 1.1rem; }}
  .score-pass {{ background: #38a169; }} .score-warn {{ background: #d69e2e; }} .score-fail {{ background: #e53e3e; }}
  .fw-body {{ padding: 1.5rem; }}
  .control {{ border: 1px solid #edf2f7; border-radius: 8px; margin-bottom: 0.8rem; overflow: hidden; }}
  .ctrl-header {{ display: flex; justify-content: space-between; align-items: center; padding: 0.8rem 1rem; cursor: pointer; background: #f7fafc; }}
  .ctrl-header:hover {{ background: #edf2f7; }}
  .ctrl-id {{ font-weight: 700; color: #2d3748; min-width: 100px; }}
  .ctrl-name {{ flex: 1; color: #4a5568; margin: 0 1rem; }}
  .ctrl-status {{ padding: 0.2rem 0.6rem; border-radius: 10px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
  .status-pass {{ background: #c6f6d5; color: #276749; }}
  .status-violated {{ background: #fed7d7; color: #9b2c2c; }}
  .ctrl-detail {{ padding: 0 1rem 1rem; display: none; }}
  .ctrl-detail.open {{ display: block; }}
  .finding-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  .finding-table th {{ text-align: left; padding: 0.4rem 0.5rem; background: #edf2f7; color: #4a5568; }}
  .finding-table td {{ padding: 0.4rem 0.5rem; border-bottom: 1px solid #edf2f7; }}
  .sev-critical {{ color: #e53e3e; font-weight: 700; }} .sev-high {{ color: #ed8936; font-weight: 600; }}
  .sev-medium {{ color: #d69e2e; }} .sev-low {{ color: #38a169; }}
  .overall {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .fw-summary {{ text-align: center; padding: 1.5rem; background: #fff; border-radius: 14px; box-shadow: 0 2px 12px rgba(0,0,0,0.06); }}
  .fw-summary .big {{ font-size: 2.5rem; font-weight: 800; }}
  .fw-summary .label {{ color: #888; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  @media (max-width: 768px) {{ .fw-header {{ flex-direction: column; text-align: center; gap: 0.5rem; }} }}
</style>
</head>
<body>
  <h1>Compliance Report</h1>
  <p class="subtitle">{date} &middot; {total_frameworks} framework(s)</p>

  <div class="overall">
    {fw_summaries}
  </div>

  {framework_sections}

<script>
  document.querySelectorAll('.ctrl-header').forEach(h => {{
    h.addEventListener('click', () => {{
      h.nextElementSibling.classList.toggle('open');
    }});
  }});
</script>
</body>
</html>"""


class ComplianceReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        results: list,
        compliance_map: str | None = None,
        name: str = "compliance_report",
    ) -> str:
        engine = ComplianceEngine.load(compliance_map)
        if not engine.frameworks:
            json_out = self.output_dir / f"{name}.json"
            report = {"frameworks": {}, "generated_at": datetime.now().isoformat(), "error": "no compliance mapping loaded"}
            with open(json_out, "w") as f:
                json.dump(report, f, indent=2)
            return str(json_out)

        report = engine.evaluate(results)

        out_path = self.output_dir / f"{name}.html"
        html = self._render_html(report)
        with open(out_path, "w") as f:
            f.write(html)

        json_path = self.output_dir / f"{name}.json"
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

        return str(out_path)

    def _score_class(self, score: int) -> str:
        if score >= 80:
            return "pass"
        elif score >= 50:
            return "warn"
        return "fail"

    def _render_html(self, report: dict) -> str:
        fws = report.get("frameworks", {})
        total = len(fws)

        fw_summaries = ""
        framework_sections = ""
        for fw_id, fw_data in fws.items():
            score = fw_data["compliance_score"]
            cls = self._score_class(score)
            fw_summaries += f"""
            <div class="fw-summary">
              <div class="big score-{cls}" style="color:{'#38a169' if cls=='pass' else '#d69e2e' if cls=='warn' else '#e53e3e'}">{score}%</div>
              <div class="label">{fw_id}</div>
              <div>{fw_data['violated_controls']}/{fw_data['total_controls']} controls violated</div>
            </div>"""

            ctrl_rows = ""
            for ctrl in fw_data["controls"]:
                status_cls = "status-pass" if ctrl["status"] == "passed" else "status-violated"
                findings = ctrl.get("affected_findings", [])
                finding_rows = ""
                for f in findings:
                    sev_cls = f"sev-{f['severity'].lower()}"
                    finding_rows += f"""<tr>
                      <td class="{sev_cls}">{f['id']}</td>
                      <td>{f['package']}</td>
                      <td><span class="{sev_cls}">{f['severity']}</span></td>
                      <td>{f['scanner']}</td>
                      <td>{f['repo'][:40]}</td>
                    </tr>"""

                detail_style = "open" if ctrl["status"] == "violated" else ""
                ctrl_rows += f"""
                <div class="control">
                  <div class="ctrl-header">
                    <span class="ctrl-id">{ctrl['id']}</span>
                    <span class="ctrl-name">{ctrl['name']}</span>
                    <span class="ctrl-status {status_cls}">{ctrl['status']} ({ctrl['violations']})</span>
                  </div>
                  <div class="ctrl-detail {detail_style}">
                    <p style="color:#718096; margin:0.5rem 0;">{ctrl.get('description', '')}</p>
                    <table class="finding-table">
                      <thead><tr><th>ID</th><th>Package</th><th>Severity</th><th>Scanner</th><th>Repo</th></tr></thead>
                      <tbody>{finding_rows}</tbody>
                    </table>
                  </div>
                </div>"""

            ver = f" v{fw_data['version']}" if fw_data.get("version") else ""
            framework_sections += f"""
            <div class="framework">
              <div class="fw-header">
                <h2>{fw_id}{ver}</h2>
                <span class="score-badge score-{cls}">{score}%</span>
              </div>
              <div class="fw-body">
                {ctrl_rows}
              </div>
            </div>"""

        return HTML_TEMPLATE.format(
            date=report.get("generated_at", datetime.now().isoformat())[:19].replace("T", " "),
            total_frameworks=total,
            fw_summaries=fw_summaries,
            framework_sections=framework_sections,
        )

    def print_summary(self, report: dict) -> None:
        fws = report.get("frameworks", {})
        if not fws:
            print("  no compliance data")
            return
        print("\nCompliance Summary")
        print("=" * 60)
        for fw_id, fw_data in fws.items():
            score = fw_data["compliance_score"]
            violated = fw_data["violated_controls"]
            total = fw_data["total_controls"]
            print(f"  {fw_id:15s}  {score:3d}%  ({violated}/{total} controls violated)")
            for ctrl in fw_data["controls"]:
                if ctrl["status"] == "violated":
                    print(f"    x {ctrl['id']}: {ctrl['violations']} finding(s)")
