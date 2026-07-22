import json
from datetime import datetime
from pathlib import Path


def _recommendation(scan_repo: str, vuln) -> dict:
    vid = vuln.id
    pkg = vuln.package
    installed = vuln.installed_version
    fixed = vuln.fixed_version
    sev = vuln.severity
    vtype = vuln.type.lower()
    desc = vuln.description
    epss = vuln.epss

    action = ""
    detail = ""
    effort = "medium"

    if vtype == "secret":
        line = pkg.split(":")[-1] if ":" in pkg else "?"
        filepath = pkg.split(":")[0] if ":" in pkg else pkg
        action = f"Rotate the exposed secret and remove it from source code"
        detail = f"File: {filepath}:{line} — {desc or vid}"
        effort = "high"

    elif vtype == "sast":
        line = pkg.split(":")[-1] if ":" in pkg else "?"
        filepath = pkg.split(":")[0] if ":" in pkg else pkg
        action = f"Review and fix the code issue"
        detail = f"{filepath}:{line} — {desc or vid}"
        effort = "medium"

    elif vtype == "iac":
        line = pkg.split(":")[-1] if ":" in pkg else "?"
        filepath = pkg.split(":")[0] if ":" in pkg else pkg
        action = f"Fix IaC misconfiguration"
        detail = f"{filepath}:{line} — Rule {vid}: {desc}"
        effort = "medium"

    elif vtype in ("secret",):
        pass

    else:
        if fixed and fixed.strip():
            action = f"Upgrade {pkg} from {installed or 'current'} to {fixed}"
        elif installed:
            action = f"No fix version available for {pkg} {installed}. Consider removing or isolating this dependency."
            effort = "high"
        else:
            action = f"No fix version available for {vid}. Monitor for updates."
            effort = "high"

        if epss is not None and epss > 0.5:
            detail = f"EPSS {epss:.1%} exploit probability — HIGH priority"
            if effort == "medium":
                effort = "high"

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    priority = sev_rank.get(sev.upper(), 4)
    if epss is not None:
        priority = min(priority, 0 if epss > 0.5 else 1 if epss > 0.1 else priority)

    return {
        "id": vid,
        "package": pkg,
        "severity": sev,
        "type": vtype,
        "action": action,
        "detail": detail,
        "effort": effort,
        "priority": priority,
        "epss": epss,
        "repo": scan_repo,
        "description": desc,
    }


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fix Recommendations</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #1a1a2e; padding: 2rem; }
  h1 { font-size: 1.8rem; margin-bottom: 0.3rem; }
  .subtitle { color: #666; margin-bottom: 2rem; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 1.2rem; text-align: center; }
  .stat-card .n { font-size: 1.8rem; font-weight: 800; }
  .stat-card .l { color: #888; font-size: 0.75rem; text-transform: uppercase; }
  .item { background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); margin-bottom: 1rem; overflow: hidden; }
  .item-header { padding: 0.8rem 1.2rem; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
  .item-header:hover { background: #f7fafc; }
  .item-id { font-weight: 700; min-width: 150px; }
  .item-sev { padding: 0.2rem 0.6rem; border-radius: 10px; font-size: 0.75rem; font-weight: 600; }
  .sev-critical { background: #fed7d7; color: #9b2c2c; } .sev-high { background: #feebc8; color: #9c4221; }
  .sev-medium { background: #fefcbf; color: #744210; } .sev-low { background: #c6f6d5; color: #276749; }
  .item-body { padding: 0 1.2rem 1rem; display: none; }
  .item-body.open { display: block; }
  .action-box { background: #ebf8ff; border-left: 4px solid #4299e1; padding: 0.8rem; border-radius: 6px; margin: 0.5rem 0; }
  .action-box .action-label { font-weight: 700; color: #2b6cb0; font-size: 0.8rem; text-transform: uppercase; }
  .action-box .action-text { margin-top: 0.3rem; }
  .detail-box { background: #f7fafc; padding: 0.8rem; border-radius: 6px; margin: 0.5rem 0; font-size: 0.85rem; color: #4a5568; }
  .effort-badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 8px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
  .effort-high { background: #fed7d7; color: #9b2c2c; } .effort-medium { background: #fefcbf; color: #744210; }
  .effort-low { background: #c6f6d5; color: #276749; }
  .repo-tag { color: #718096; font-size: 0.8rem; }
</style>
</head>
<body>
  <h1>Fix Recommendations</h1>
  <p class="subtitle">{date} &middot; {total} recommendations across {repos} repos</p>

  <div class="summary">
    <div class="stat-card"><div class="n" style="color:#e53e3e">{p0}</div><div class="l">Critical Priority</div></div>
    <div class="stat-card"><div class="n" style="color:#ed8936">{p1}</div><div class="l">High Priority</div></div>
    <div class="stat-card"><div class="n" style="color:#d69e2e">{p2}</div><div class="l">Medium Priority</div></div>
    <div class="stat-card"><div class="n" style="color:#38a169">{p3}</div><div class="l">Low Priority</div></div>
    <div class="stat-card"><div class="n" style="color:#718096">{p4}</div><div class="l">Info</div></div>
  </div>

  {items}

  <script>
    document.querySelectorAll('.item-header').forEach(h => h.addEventListener('click', () => {
      h.nextElementSibling.classList.toggle('open');
    }));
  </script>
</body>
</html>"""


class FixRecommendationsReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: list, name: str = "fix_recommendations") -> str:
        recs = []
        for scan in results:
            for v in scan.vulnerabilities:
                recs.append(_recommendation(scan.repo, v))

        recs.sort(key=lambda r: r["priority"])

        priorities = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
        for r in recs:
            priorities[r["priority"]] = priorities.get(r["priority"], 0) + 1

        items_html = ""
        for r in recs:
            sev_cls = f"sev-{r['severity'].lower()}"
            effort_cls = f"effort-{r['effort']}"
            items_html += f"""
            <div class="item">
              <div class="item-header">
                <span class="item-id">{r['id']}</span>
                <span class="repo-tag">{r['repo'][:40]}</span>
                <span class="item-sev {sev_cls}">{r['severity']}</span>
                <span class="effort-badge {effort_cls}">{r['effort']}</span>
              </div>
              <div class="item-body">
                <div class="action-box">
                  <div class="action-label">Recommended Action</div>
                  <div class="action-text">{r['action']}</div>
                </div>
                <div class="detail-box">
                  <strong>Package:</strong> {r['package']} &middot;
                  <strong>Type:</strong> {r['type']} &middot;
                  <strong>Repo:</strong> {r['repo'][:50]}
                  {f'<br><strong>EPSS:</strong> {r["epss"]:.1%}' if r.get('epss') else ''}
                  {f'<br><strong>Detail:</strong> {r["detail"]}' if r.get('detail') else ''}
                  {f'<br><strong>Description:</strong> {r["description"][:200]}' if r.get('description') else ''}
                </div>
              </div>
            </div>"""

        if not items_html:
            items_html = '<p style="text-align:center;color:#888;padding:2rem;">No vulnerabilities found — no recommendations needed.</p>'

        report = {
            "generated_at": datetime.now().isoformat(),
            "total": len(recs),
            "repos": len({r["repo"] for r in recs}),
            "priorities": priorities,
            "recommendations": recs,
        }

        html = (HTML_TEMPLATE
            .replace("{date}", report["generated_at"][:19].replace("T", " "))
            .replace("{total}", str(len(recs)))
            .replace("{repos}", str(report["repos"]))
            .replace("{p0}", str(priorities.get(0, 0)))
            .replace("{p1}", str(priorities.get(1, 0)))
            .replace("{p2}", str(priorities.get(2, 0)))
            .replace("{p3}", str(priorities.get(3, 0)))
            .replace("{p4}", str(priorities.get(4, 0)))
            .replace("{items}", items_html)
        )

        out_path = self.output_dir / f"{name}.html"
        with open(out_path, "w") as f:
            f.write(html)

        json_path = self.output_dir / f"{name}.json"
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

        return str(out_path)

    def print_summary(self, report: dict) -> None:
        print(f"\nFix Recommendations")
        print("=" * 50)
        print(f"  Total: {report['total']} recommendations across {report['repos']} repos")
        pri = report.get("priorities", {})
        if pri.get(0):
            print(f"  Critical: {pri[0]}")
        if pri.get(1):
            print(f"  High:     {pri[1]}")
        if pri.get(2):
            print(f"  Medium:   {pri[2]}")
        if pri.get(3):
            print(f"  Low:      {pri[3]}")

        for r in report.get("recommendations", [])[:5]:
            print(f"  [{r['severity']:8s}] {r['id']:25s} {r['action'][:60]}")
        if len(report.get("recommendations", [])) > 5:
            print(f"  ... and {len(report['recommendations']) - 5} more")
