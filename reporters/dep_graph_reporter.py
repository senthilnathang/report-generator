import json
from pathlib import Path


HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dependency Graph</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#1a1a2e;color:#e2e8f0;overflow:hidden;height:100vh}
#header{position:fixed;top:0;left:0;right:0;z-index:100;background:rgba(26,26,46,0.95);padding:0.8rem 1.5rem;display:flex;align-items:center;gap:1rem;border-bottom:1px solid #2d3748}
#header h1{font-size:1.1rem;font-weight:700;color:#fff}
#search{flex:1;max-width:400px;padding:0.4rem 0.8rem;border-radius:6px;border:1px solid #4a5568;background:#2d3748;color:#fff;font-size:0.85rem}
#search:focus{outline:none;border-color:#667eea}
#legend{display:flex;gap:1rem;margin-left:auto;font-size:0.75rem}
.legend-item{display:flex;align-items:center;gap:0.3rem}
.legend-dot{width:10px;height:10px;border-radius:50%}
#graph{width:100vw;height:100vh}
#tooltip{position:fixed;display:none;background:rgba(26,26,46,0.95);border:1px solid #4a5568;border-radius:8px;padding:0.6rem 1rem;font-size:0.8rem;pointer-events:none;z-index:200;max-width:350px}
#tooltip .tt-name{font-weight:700;color:#fff;margin-bottom:0.2rem}
#tooltip .tt-detail{color:#a0aec0}
#stats{position:fixed;bottom:1rem;right:1rem;z-index:100;background:rgba(26,26,46,0.9);border:1px solid #2d3748;border-radius:8px;padding:0.6rem 1rem;font-size:0.75rem;color:#a0aec0;text-align:right}
</style>
</head>
<body>
<div id="header">
  <h1>{title}</h1>
  <input id="search" type="text" placeholder="Search packages..." oninput="filterGraph(this.value)">
  <div id="legend">
    <div class="legend-item"><div class="legend-dot" style="background:#38a169"></div>Direct</div>
    <div class="legend-item"><div class="legend-dot" style="background:#667eea"></div>Indirect</div>
    <div class="legend-item"><div class="legend-dot" style="background:#e53e3e"></div>Has Vulns</div>
  </div>
</div>
<div id="tooltip"></div>
<div id="graph"></div>
<div id="stats">{direct} direct &middot; {indirect} indirect &middot; {total} total</div>
<script>
const graphData = {graph_json};

function filterGraph(query) {{
  const q = query.toLowerCase();
  d3.selectAll('g.node').each(function(d) {{
    const match = !q || d.name.toLowerCase().includes(q) || (d.id && d.id.toLowerCase().includes(q));
    d3.select(this).style('opacity', match ? 1 : 0.1);
  }});
  d3.selectAll('line.link').each(function(d) {{
    const src = d.source.id || d.source.name || '';
    const tgt = d.target.id || d.target.name || '';
    const match = !q || src.toLowerCase().includes(q) || tgt.toLowerCase().includes(q);
    d3.select(this).style('opacity', match ? 0.3 : 0.02);
  }});
}}

const width = window.innerWidth;
const height = window.innerHeight;

const svg = d3.select('#graph').append('svg')
  .attr('width', width)
  .attr('height', height);

svg.append('defs').append('marker')
  .attr('id','arrow')
  .attr('viewBox','0 -5 10 10')
  .attr('refX',20)
  .attr('refY',0)
  .attr('markerWidth',6)
  .attr('markerHeight',6)
  .attr('orient','auto')
  .append('path')
  .attr('d','M0,-5L10,0L0,5')
  .attr('fill','#4a5568');

const simulation = d3.forceSimulation(graphData.nodes)
  .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(80).strength(0.3))
  .force('charge', d3.forceManyBody().strength(-200))
  .force('center', d3.forceCenter(width/2, height/2))
  .force('collision', d3.forceCollide().radius(d => Math.sqrt(d.size || 8) * 4));

const link = svg.append('g')
  .selectAll('line')
  .data(graphData.links)
  .join('line')
  .attr('class','link')
  .attr('stroke','#4a5568')
  .attr('stroke-width',1)
  .attr('stroke-opacity',0.3)
  .attr('marker-end','url(#arrow)');

const node = svg.append('g')
  .selectAll('g')
  .data(graphData.nodes)
  .join('g')
  .attr('class','node')
  .call(d3.drag()
    .on('start',(e,d)=>{{
      if(!e.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x; d.fy = d.y;
    }})
    .on('drag',(e,d)=>{{ d.fx = e.x; d.fy = e.y; }})
    .on('end',(e,d)=>{{ if(!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }})
  );

node.append('circle')
  .attr('r', d => Math.max(4, Math.min(20, Math.sqrt(d.size || 8) * 2)))
  .attr('fill', d => d.has_vulns ? '#e53e3e' : (d.direct ? '#38a169' : '#667eea'))
  .attr('stroke', '#1a1a2e')
  .attr('stroke-width', 2);

node.append('text')
  .text(d => d.name.length > 20 ? d.name.slice(0,18)+'..' : d.name)
  .attr('x', d => Math.max(4, Math.min(20, Math.sqrt(d.size || 8) * 2)) + 5)
  .attr('y', 4)
  .attr('fill', '#a0aec0')
  .attr('font-size', '0.7rem');

node.on('mouseover', (e,d) => {{
  const tip = d3.select('#tooltip');
  tip.style('display','block')
    .style('left', (e.pageX + 10) + 'px')
    .style('top', (e.pageY - 10) + 'px')
    .html(`<div class="tt-name">${{d.name}}@${{d.version}}</div>
           <div class="tt-detail">${{d.type}} | ${{d.relationship}}</div>
           <div class="tt-detail">${{d.has_vulns ? '<span style="color:#e53e3e">Has vulnerabilities</span>' : 'No vulnerabilities'}}</div>`);
}})
.on('mouseout', () => d3.select('#tooltip').style('display','none'));

simulation.on('tick', () => {{
  link
    .attr('x1', d => d.source.x)
    .attr('y1', d => d.source.y)
    .attr('x2', d => d.target.x)
    .attr('y2', d => d.target.y);
  node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
}});

window.addEventListener('resize', () => {{
  svg.attr('width', window.innerWidth).attr('height', window.innerHeight);
  simulation.force('center', d3.forceCenter(window.innerWidth/2, window.innerHeight/2));
  simulation.alpha(0.3).restart();
}});
</script>
</body>
</html>"""


def _build_graph(dep_data: list[dict], vuln_set: set[str]) -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []
    seen_ids: dict[str, int] = {}
    node_id_counter = 0

    for repo_data in dep_data:
        packages = repo_data.get("packages", [])
        for pkg in packages:
            pkg_id = pkg.get("id", pkg.get("name", ""))
            name = pkg.get("name", pkg_id.split("@")[0] if "@" in pkg_id else pkg_id)
            version = pkg.get("version", "")

            if pkg_id not in seen_ids:
                seen_ids[pkg_id] = node_id_counter
                has_vulns = pkg_id in vuln_set or name in vuln_set
                nodes.append({
                    "id": pkg_id,
                    "name": name,
                    "version": version,
                    "type": pkg.get("type", "unknown"),
                    "relationship": pkg.get("relationship", "unknown"),
                    "direct": pkg.get("relationship") == "direct",
                    "has_vulns": has_vulns,
                    "size": 10,
                })
                node_id_counter += 1

        for pkg in packages:
            src_id = pkg.get("id", pkg.get("name", ""))
            if src_id not in seen_ids:
                continue
            deps_str = pkg.get("depends_on", "")
            if not deps_str:
                continue
            for dep_id in deps_str.split("; "):
                dep_id = dep_id.strip()
                if dep_id and dep_id in seen_ids:
                    edges.append({
                        "source": seen_ids[src_id],
                        "target": seen_ids[dep_id],
                    })

    return {"nodes": nodes, "links": edges}


class DepGraphReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        dep_results: list[dict],
        vuln_results: list | None = None,
        name: str = "dep_graph",
    ) -> str:
        vuln_set: set[str] = set()
        if vuln_results:
            for r in vuln_results:
                vulns = r.vulnerabilities if hasattr(r, "vulnerabilities") else r.get("vulnerabilities", [])
                for v in vulns:
                    vid = v.id if hasattr(v, "id") else v.get("id", "")
                    vuln_set.add(vid)
                    pkg = v.package if hasattr(v, "package") else v.get("package", "")
                    if pkg:
                        vuln_set.add(pkg.split("/")[-1].split(":")[-1].split("@")[0])

        graph = _build_graph(dep_results, vuln_set)

        total = len(graph["nodes"])
        direct = sum(1 for n in graph["nodes"] if n.get("direct"))
        indirect = total - direct
        repo_names = ", ".join(d.get("repo", "?") for d in dep_results)

        json_out = self.output_dir / f"{name}.json"
        with open(json_out, "w") as f:
            json.dump(graph, f, indent=2)

        html = (HTML
            .replace("{title}", f"Dependency Graph &mdash; {repo_names[:60]}")
            .replace("{graph_json}", json.dumps(graph))
            .replace("{total}", str(total))
            .replace("{direct}", str(direct))
            .replace("{indirect}", str(indirect))
        )

        html_out = self.output_dir / f"{name}.html"
        with open(html_out, "w") as f:
            f.write(html)

        return str(html_out)

    def print_summary(self, dep_results: list[dict]) -> None:
        for r in dep_results:
            print(f"  {r.get('repo','?')}: {r.get('total',0)} packages")
