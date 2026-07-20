# Report Generator

Multi-scanner vulnerability scanning pipeline for GitHub repositories. Runs **Trivy**, **Grype**, and **Snyk** in parallel and consolidates results into **Excel**, **JSON**, and **PDF** reports.

## Architecture

```
repolist.txt ──> main.py ──> scanners/ ──> reporters/ ──> reports/
                    │            │               │
              config.yaml    trivy           excel
              (optional)     grype           json
                             snyk            pdf
```

| Layer | Directory | Description |
|-------|-----------|-------------|
| **CLI** | `main.py` | Argparse entry point; dispatches scans and reports |
| **Models** | `models.py` | `Vulnerability` / `ScanResult` dataclasses with severity rollup |
| **Scanners** | `scanners/` | One module per tool; subprocesses the CLI, parses JSON output |
| **Reporters** | `reporters/` | One module per format; transforms `ScanResult` into output files |
| **Repo Manager** | `repo_manager.py` | Clones/fetches repos with token auth and branch checkout |
| **Config** | `config.yaml` | Git tokens, per-repo branch/scan mode |

### Scanners

| Scanner | Remote mode | Local mode | Output parsed |
|---------|-------------|------------|---------------|
| **Trivy** | `trivy repo <url>` | `trivy fs <path>` | JSON → `Results[].Vulnerabilities[]` |
| **Grype** | `grype <url>` | `grype dir:<path>` | JSON → `matches[].vulnerability` |
| **Snyk** | `snyk test --remote-repo-url=<url>` | `snyk test --json` (runs in repo dir) | JSON → `vulnerabilities[]` |

### Reports

| Format | Library | Sheets / Sections |
|--------|---------|-------------------|
| **Excel** | `openpyxl` | Summary sheet (severity counts) + Details sheet (all vulns with severity coloring) |
| **JSON** | built-in | Array of serialized `ScanResult` objects with auto-computed summary |
| **PDF** | `reportlab` | Summary table + detailed findings table (landscape A4) |

## Business Use Cases

- **CI/CD pipeline gating** — Scan every PR branch for new vulnerabilities before merge
- **Quarterly audit reporting** — Generate Excel/PDF reports for compliance (SOC 2, PCI-DSS)
- **Multi-repo portfolio scan** — Maintain a `repolist.txt` of all org repos; run nightly to track vulnerability drift
- **M&A due diligence** — Clone target company repos with token auth and run all three scanners for a comprehensive risk profile
- **Vendor risk assessment** — Scan open-source dependencies used by third-party vendors before procurement

## Requirements

- Python 3.10+
- [Trivy](https://github.com/aquasecurity/trivy) (`brew install trivy` / `apt install trivy`)
- [Grype](https://github.com/anchore/grype) (`brew install grype` / `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh`)
- [Snyk](https://docs.snyk.io/snyk-cli) (`npm install -g snyk` / `curl -L https://static.snyk.io/cli/latest/snyk-linux -o snyk`)
- Snyk requires authentication: `snyk auth`

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install openpyxl reportlab pyyaml
```

## Usage

### 1. List repos to scan

```
# repolist.txt
https://github.com/expressjs/express
https://github.com/lodash/lodash
https://github.com/axios/axios
```

### 2. Run scan

```bash
# Scan remotely with Trivy, output JSON
python main.py -s trivy -f json

# Run all scanners, all formats, 8 parallel jobs
python main.py -s trivy grype snyk -f excel json pdf -j 8

# Clone repos locally and scan (uses config.yaml)
python main.py --local -s trivy -f excel

# Custom input file and output directory
python main.py -i my-org-repos.txt -s grype -f json pdf -o ./audit
```

### Local scan mode

When `--local` is passed, repos with `scan_mode: local` in `config.yaml` are cloned (or fetched if already cloned) to `.repos/` and scanners run against the local filesystem. This is useful for:

- Scanning private repos (tokens in `config.yaml`)
- Scanning a specific branch (`branch: v1.x`)
- Scanning uncommitted changes in a working tree

```yaml
# config.yaml
git:
  tokens:
    github.com: ghp_your_token_here

repositories:
  - url: https://github.com/myorg/private-repo
    branch: develop
    scan_mode: local

  - url: https://github.com/myorg/public-repo
    # no branch → scans remote URL
```

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --input` | `repolist.txt` | File with repo URLs (one per line) |
| `-s, --scanners` | `trivy` | Scanners: `trivy`, `grype`, `snyk` |
| `-f, --formats` | `json` | Output formats: `excel`, `json`, `pdf` |
| `-o, --output-dir` | `reports` | Directory to write reports |
| `-j, --jobs` | `4` | Parallel scan workers |
| `-l, --local` | — | Enable local clone mode |
| `-c, --config` | `config.yaml` | YAML config for tokens and repo settings |
| `--clone-dir` | `.repos` | Where to clone repos in `--local` mode |

## Output

```
reports/
├── vulnerability_report.json   # Full structured data
├── vulnerability_report.xlsx   # Summary + Details sheets
└── vulnerability_report.pdf    # Landscape tables with severity
```

Console summary:
```
scan targets: 3
scanners: trivy, grype
formats: json, excel, pdf

[1/6] https://github.com/axios/axios | TrivyScanner | 3 vulns | ok
[2/6] https://github.com/expressjs/express | TrivyScanner | 0 vulns | ok
...

report (json): reports/vulnerability_report.json
report (excel): reports/vulnerability_report.xlsx
report (pdf): reports/vulnerability_report.pdf

summary: 6 scans, 12 vulnerabilities, 0 failures
```

## Project Structure

```
├── main.py                  CLI orchestrator
├── models.py                Data models (Vulnerability, ScanResult)
├── repo_manager.py          Git clone/fetch with token auth
├── config.yaml              Per-repo configuration
├── repolist.txt             Repo URL list
├── scanners/
│   ├── trivy_scanner.py     Trivy integration
│   ├── grype_scanner.py     Grype integration
│   └── snyk_scanner.py      Snyk integration
├── reporters/
│   ├── excel_reporter.py    Excel (openpyxl)
│   ├── json_reporter.py     JSON (built-in)
│   └── pdf_reporter.py      PDF (reportlab)
└── .gitignore
```
