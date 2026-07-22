import json
from datetime import datetime
from pathlib import Path


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SBOM Diff Report</title>
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
  .num-added {{ color: #38a169; }} .num-removed {{ color: #e53e3e; }} .num-changed {{ color: #d69e2e; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.06); margin-bottom: 1.5rem; }}
  th {{ text-align: left; padding: 0.7rem 1rem; background: #2d3748; color: #fff; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #edf2f7; }}
  tr:last-child td {{ border: none; }}
  tr:hover {{ background: #f7fafc; }}
  .added-row td {{ background: #f0fff4; }} .removed-row td {{ background: #fff5f5; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 10px; font-size: 0.7rem; font-weight: 600; }}
  .bg-added {{ background: #c6f6d5; color: #276749; }} .bg-removed {{ background: #fed7d7; color: #9b2c2c; }}
  .bg-changed {{ background: #fefcbf; color: #744210; }}
  .version-old {{ color: #e53e3e; text-decoration: line-through; margin-right: 0.5rem; }}
  .version-new {{ color: #38a169; font-weight: 600; }}
  .section-title {{ font-size: 1.1rem; font-weight: 700; margin: 1.5rem 0 0.5rem; }}
  canvas {{ max-height: 250px; margin-bottom: 1.5rem; }}
  .file-meta {{ color: #888; font-size: 0.85rem; margin-bottom: 1rem; }}
  .file-meta span {{ margin-right: 1.5rem; }}
</style>
</head>
<body>
  <h1>SBOM Diff Report</h1>
  <p class="subtitle">{date}</p>
  <div class="file-meta">
    <span>Old: {old_file}</span>
    <span>New: {new_file}</span>
  </div>

  <div class="summary-cards">
    <div class="card"><div class="num num-added">{added_count}</div><div class="lbl">Packages Added</div></div>
    <div class="card"><div class="num num-removed">{removed_count}</div><div class="lbl">Packages Removed</div></div>
    <div class="card"><div class="num num-changed">{changed_count}</div><div class="lbl">Versions Changed</div></div>
    <div class="card"><div class="num">{old_total}</div><div class="lbl">Before</div></div>
    <div class="card"><div class="num">{new_total}</div><div class="lbl">After</div></div>
  </div>

  <canvas id="summaryChart"></canvas>

  <div class="section-title">Added Packages ({added_count})</div>
  <table>
    <thead><tr><th>Package</th><th>Version</th><th>Type</th><th>PURL</th></tr></thead>
    <tbody>{added_rows}</tbody>
  </table>

  <div class="section-title">Removed Packages ({removed_count})</div>
  <table>
    <thead><tr><th>Package</th><th>Version</th><th>Type</th><th>PURL</th></tr></thead>
    <tbody>{removed_rows}</tbody>
  </table>

  <div class="section-title">Version Changes ({changed_count})</div>
  <table>
    <thead><tr><th>Package</th><th>Old Version</th><th>New Version</th><th>Type</th></tr></thead>
    <tbody>{changed_rows}</tbody>
  </table>

  <script>
    new Chart(document.getElementById('summaryChart'), {{
      type: 'bar',
      data: {{
        labels: ['Added', 'Removed', 'Changed', 'Total Before', 'Total After'],
        datasets: [{{
          data: [{added_count}, {removed_count}, {changed_count}, {old_total}, {new_total}],
          backgroundColor: ['#38a169', '#e53e3e', '#d69e2e', '#4299e1', '#667eea']
        }}]
      }},
      options: {{
        responsive: true,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{ y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }} }}
      }}
    }});
  </script>
</body>
</html>"""


def _load_sbom(path: str) -> tuple[list[dict], str, str]:
    with open(path) as f:
        data = json.load(f)

    if "components" in data:
        return data["components"], data.get("bomFormat", "cyclonedx"), data.get("specVersion", "")

    if "packages" in data:
        return data["packages"], "spdx", data.get("spdxVersion", "")

    raise ValueError(f"unrecognized SBOM format in {path}")


def _get_type(comp: dict) -> str:
    return comp.get("type", comp.get("name", "").split("/")[0] if "/" in comp.get("name", "") else "library")


def compute_diff(old_path: str, new_path: str) -> dict:
    old_comps, old_fmt, old_ver = _load_sbom(old_path)
    new_comps, new_fmt, new_ver = _load_sbom(new_path)

    old_by_name: dict[str, dict] = {}
    for c in old_comps:
        name = c.get("name", c.get("SPDXID", ""))
        old_by_name[name] = c

    new_by_name: dict[str, dict] = {}
    for c in new_comps:
        name = c.get("name", c.get("SPDXID", ""))
        new_by_name[name] = c

    old_names = set(old_by_name.keys())
    new_names = set(new_by_name.keys())

    added = []
    for name in sorted(new_names - old_names):
        c = new_by_name[name]
        added.append({
            "name": name,
            "version": c.get("version", c.get("versionInfo", "")),
            "type": _get_type(c),
            "purl": c.get("purl", c.get("externalRefs", [{}])[0].get("referenceLocator", "") if c.get("externalRefs") else ""),
        })

    removed = []
    for name in sorted(old_names - new_names):
        c = old_by_name[name]
        removed.append({
            "name": name,
            "version": c.get("version", c.get("versionInfo", "")),
            "type": _get_type(c),
            "purl": c.get("purl", c.get("externalRefs", [{}])[0].get("referenceLocator", "") if c.get("externalRefs") else ""),
        })

    changed = []
    for name in sorted(old_names & new_names):
        old_c = old_by_name[name]
        new_c = new_by_name[name]
        old_ver = old_c.get("version", old_c.get("versionInfo", ""))
        new_ver = new_c.get("version", new_c.get("versionInfo", ""))
        if old_ver != new_ver:
            changed.append({
                "name": name,
                "old_version": old_ver,
                "new_version": new_ver,
                "type": _get_type(new_c),
            })

    return {
        "old_file": old_path,
        "new_file": new_path,
        "old_format": old_fmt,
        "new_format": new_fmt,
        "old_total": len(old_comps),
        "new_total": len(new_comps),
        "added": added,
        "removed": removed,
        "changed": changed,
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
    }


class SbomDiffReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, old_sbom: str, new_sbom: str, name: str = "sbom_diff") -> str:
        result = compute_diff(old_sbom, new_sbom)
        result["generated_at"] = datetime.now().isoformat()

        html = self._render_html(result)
        out_path = self.output_dir / f"{name}.html"
        with open(out_path, "w") as f:
            f.write(html)

        json_path = self.output_dir / f"{name}.json"
        with open(json_path, "w") as f:
            json.dump(result, f, indent=2)

        return str(out_path)

    def _render_html(self, result: dict) -> str:
        def _row(item: dict, cls: str = "") -> str:
            purl = item.get("purl", "")
            purl_short = purl[:60] + "..." if len(purl) > 60 else purl
            return f"""<tr class="{cls}">
              <td><strong>{item['name'][:60]}</strong></td>
              <td>{item['version'][:30]}</td>
              <td>{item['type']}</td>
              <td style="font-size:0.8rem;color:#718096;max-width:250px;overflow:hidden;text-overflow:ellipsis">{purl_short}</td>
            </tr>"""

        added_rows = "".join(_row(a, "added-row") for a in result.get("added", []))
        removed_rows = "".join(_row(r, "removed-row") for r in result.get("removed", []))
        changed_rows = "".join(
            f"""<tr>
              <td><strong>{c['name'][:60]}</strong></td>
              <td><span class="version-old">{c['old_version'][:30]}</span></td>
              <td><span class="version-new">{c['new_version'][:30]}</span></td>
              <td>{c['type']}</td>
            </tr>"""
            for c in result.get("changed", [])
        )

        if not added_rows:
            added_rows = '<tr><td colspan="4" style="text-align:center;color:#888;padding:1rem;">No packages added</td></tr>'
        if not removed_rows:
            removed_rows = '<tr><td colspan="4" style="text-align:center;color:#888;padding:1rem;">No packages removed</td></tr>'
        if not changed_rows:
            changed_rows = '<tr><td colspan="4" style="text-align:center;color:#888;padding:1rem;">No version changes</td></tr>'

        return HTML_TEMPLATE.format(
            date=result.get("generated_at", "")[:19].replace("T", " "),
            old_file=Path(result["old_file"]).name,
            new_file=Path(result["new_file"]).name,
            added_count=result["added_count"],
            removed_count=result["removed_count"],
            changed_count=result["changed_count"],
            old_total=result["old_total"],
            new_total=result["new_total"],
            added_rows=added_rows,
            removed_rows=removed_rows,
            changed_rows=changed_rows,
        )

    def print_summary(self, result: dict) -> None:
        print(f"\nSBOM Diff: {result['old_file']} -> {result['new_file']}")
        print("=" * 50)
        print(f"  Total packages: {result['old_total']} -> {result['new_total']}")
        print(f"  Added:   {result['added_count']}")
        print(f"  Removed: {result['removed_count']}")
        print(f"  Changed: {result['changed_count']}")
        if result.get("added"):
            print(f"\n  Added packages:")
            for a in result["added"][:5]:
                print(f"    + {a['name']}@{a['version']}")
            if len(result["added"]) > 5:
                print(f"    ... and {len(result['added']) - 5} more")
        if result.get("removed"):
            print(f"\n  Removed packages:")
            for r in result["removed"][:5]:
                print(f"    - {r['name']}@{r['version']}")
            if len(result["removed"]) > 5:
                print(f"    ... and {len(result['removed']) - 5} more")
