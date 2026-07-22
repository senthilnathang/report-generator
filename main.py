import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from tqdm import tqdm

from scanners import TrivyScanner, GrypeScanner, SnykScanner, BanditScanner, SemgrepScanner, SecretScanner, IacScanner
from scanners.license_scanner import LicenseScanner
from reporters import ExcelReporter, JsonReporter, PdfReporter, HtmlReporter, SarifReporter
from reporters.sbom_reporter import SbomReporter
from reporters.diff_reporter import DiffReporter
from reporters.license_reporter import LicenseReporter
from reporters.dep_tree_reporter import DependencyTreeReporter
from reporters.health_reporter import HealthReporter
from reporters.outdated_reporter import OutdatedReporter
from reporters.compliance_reporter import ComplianceReporter
from reporters.risk_reporter import RiskReporter
from reporters.sbom_diff_reporter import SbomDiffReporter
from reporters.scorecard_reporter import ScorecardReporter
from reporters.regression_reporter import RegressionReporter
from reporters.dep_graph_reporter import DepGraphReporter
from reporters.fix_recommendations_reporter import FixRecommendationsReporter
from scanners.container_scanner import ContainerScanner

from repo_manager import RepoManager
from scan_history import ScanHistory
from suppressions import SuppressionManager
from epss_scorer import enrich as epss_enrich, filter_by_threshold as epss_filter

SCANNER_MAP = {
    "trivy": TrivyScanner,
    "grype": GrypeScanner,
    "snyk": SnykScanner,
    "bandit": BanditScanner,
    "semgrep": SemgrepScanner,
    "gitleaks": SecretScanner,
    "checkov": IacScanner,
}

REPORTER_MAP = {
    "excel": ExcelReporter,
    "json": JsonReporter,
    "pdf": PdfReporter,
    "html": HtmlReporter,
    "sarif": SarifReporter,
}


def read_repo_list(path: str) -> list[str]:
    repos = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                repos.append(line)
    return repos


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Multi-scanner vulnerability scanner for repositories",
    )
    p.add_argument("-i", "--input", default="repolist.txt",
                    help="Path to repo list file (default: repolist.txt)")
    p.add_argument("-s", "--scanners", nargs="+",
                    choices=list(SCANNER_MAP.keys()), default=["trivy"],
                    help="Scanners to run (default: trivy)")
    p.add_argument("-f", "--formats", nargs="+",
                    choices=list(REPORTER_MAP.keys()), default=["json"],
                    help="Report output formats (default: json)")
    p.add_argument("-o", "--output-dir", default="reports",
                    help="Output directory for reports (default: reports)")
    p.add_argument("-j", "--jobs", type=int, default=4,
                    help="Parallel scan jobs (default: 4)")
    p.add_argument("-l", "--local", action="store_true",
                    help="Clone/fetch repos locally before scanning (uses config.yaml)")
    p.add_argument("-c", "--config", default="config.yaml",
                    help="Path to YAML config file (default: config.yaml)")
    p.add_argument("--clone-dir", default=".repos",
                    help="Directory for cloned repos (default: .repos)")
    p.add_argument("--sync", action="store_true",
                    help="Update config.yaml with latest commit SHAs before scanning")
    p.add_argument("--history", action="store_true",
                    help="Record scan results in SQLite history database")
    p.add_argument("--history-db", default="reports/scan_history.db",
                    help="Path to scan history database (default: reports/scan_history.db)")
    p.add_argument("--skip-scanned", action="store_true",
                    help="Skip targets already scanned at the same commit (requires --history)")
    p.add_argument("--sbom", choices=["cyclonedx", "spdx"], const="cyclonedx", nargs="?",
                    help="Generate SBOM using Trivy (cyclonedx or spdx)")
    p.add_argument("--diff", action="store_true",
                    help="Diff against last scan from history (requires --history)")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None,
                    help="Exit non-zero if any vulnerabilities at this severity or higher are found")
    p.add_argument("--license", action="store_true",
                    help="Scan for software licenses using Trivy (requires --local)")
    p.add_argument("--license-policy", nargs="*", default=None,
                    help="License policy rules: 'allow=MIT,Apache-2.0' or 'deny=GPL-3.0,AGPL-3.0'")
    p.add_argument("--dep-tree", action="store_true",
                    help="Export full dependency tree (all packages, not just vulnerable ones)")
    p.add_argument("--select-branch", action="store_true",
                    help="Interactively select branch for each repo from remote branches")
    p.add_argument("--health-report", action="store_true",
                    help="Generate repository health report (aggregates vulns, dep-tree, license)")
    p.add_argument("--outdated", action="store_true",
                    help="Check outdated dependencies against package registries (requires --dep-tree)")
    p.add_argument("--suppressions", default=None,
                    help="Path to suppressions YAML file (default: none)")
    p.add_argument("--compliance", default=None,
                    help="Path to compliance mapping YAML file (default: none)")
    p.add_argument("--epss", action="store_true",
                    help="Enrich vulnerabilities with EPSS exploit prediction scores")
    p.add_argument("--epss-threshold", type=float, default=None,
                    help="Drop vulnerabilities below EPSS score threshold (0.0-1.0)")
    p.add_argument("--risk-score", action="store_true",
                    help="Compute composite risk scores for vulnerabilities")
    p.add_argument("--sbom-diff", nargs=2, metavar=("OLD_SBOM", "NEW_SBOM"), default=None,
                    help="Compare two SBOM files and generate diff report")
    p.add_argument("--scorecard", action="store_true",
                    help="Run OpenSSF Scorecard on repositories and generate report")
    p.add_argument("--regression-check", action="store_true",
                    help="Compare current vulns against history and detect regressions (requires --history)")
    p.add_argument("--dep-graph", action="store_true",
                    help="Generate interactive dependency graph HTML (requires --dep-tree)")
    p.add_argument("--fix-recommendations", action="store_true",
                    help="Generate actionable fix recommendations per vulnerability")
    p.add_argument("--sarif", action="store_true",
                    help="Export results in SARIF 2.1.0 format (GitHub Code Scanning compatible)")
    p.add_argument("--container", nargs="+", default=[],
                    help="Scan container images (e.g., --container alpine:latest nginx:1.25)")
    p.add_argument("--generate-cicd", choices=["github-actions", "gitlab-ci"], default=None,
                    help="Generate CI/CD pipeline template for vulnerability scanning")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    if args.generate_cicd:
        tmpl_dir = Path(__file__).parent / "cicd"
        if args.generate_cicd == "github-actions":
            tmpl = tmpl_dir / "github_actions.yml"
        else:
            tmpl = tmpl_dir / "gitlab_ci.yml"
        if tmpl.exists():
            print(tmpl.read_text())
        else:
            print(f"template not found: {tmpl}", file=sys.stderr)
            sys.exit(1)
        return

    if not Path(args.input).exists():
        print(f"error: repo list not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    repo_urls = read_repo_list(args.input)
    if not repo_urls:
        print("error: no repositories found in list", file=sys.stderr)
        sys.exit(1)

    mgr = RepoManager(config_path=args.config, clone_dir=args.clone_dir)

    if args.sync:
        print("syncing commit SHAs from remote repositories...")
        mgr.update_config_with_commits(repo_urls)
        print()

    if args.select_branch:
        print("interactive branch selection...")
        mgr.interactive_select_branches(repo_urls)

    if args.local:
        print("preparing local repositories...")
        repo_map = mgr.prepare_repos(repo_urls)
        scan_targets = list(repo_map.values())
    else:
        repo_map = {u: u for u in repo_urls}
        scan_targets = repo_urls

    history: ScanHistory | None = None
    if args.history:
        history = ScanHistory(db_path=args.history_db)

    scanners = [SCANNER_MAP[name]() for name in args.scanners]
    reporters = [REPORTER_MAP[name](output_dir=args.output_dir) for name in args.formats]

    print(f"scan targets: {len(scan_targets)}")
    print(f"scanners: {', '.join(args.scanners)}")
    if args.sbom:
        print(f"sbom: {args.sbom}")
    print(f"output dir: {args.output_dir}")
    print()

    all_results = []

    if args.container:
        print(f"\nscanning {len(args.container)} container image(s)...")
        cscanner = ContainerScanner()
        for img in args.container:
            cr = cscanner.scan(img)
            all_results.append(cr)
            sev = cr.summary
            total = sum(sev.values())
            errs = ", ".join(cr.errors) if cr.errors else "ok"
            print(f"  {img}: {total} vulns ({errs})")
        print()

    total_scans = len(scan_targets) * len(scanners)
    skipped = 0

    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {}
        for target in scan_targets:
            for scanner in scanners:
                if args.skip_scanned and history:
                    repo_url = next((u for u, p in repo_map.items() if p == target), target)
                    config = mgr.get_config(repo_url)
                    commit_sha = config.get("commit", "")
                    if commit_sha and history.was_commit_scanned(repo_url, commit_sha, scanner.__class__.__name__.lower().replace("scanner", "")):
                        skipped += 1
                        continue
                fut = executor.submit(scanner.scan, target)
                futures[fut] = (target, scanner, repo_map)

        progress = tqdm(total=total_scans - skipped, unit="scan", desc="scanning")
        for fut in as_completed(futures):
            target, scanner, rmap = futures[fut]
            try:
                result = fut.result()
                all_results.append(result)
                vuln_count = len(result.vulnerabilities)
                err_count = len(result.errors)
                status = "ok"
                if err_count:
                    status = f"errors({err_count})"
                progress.set_postfix(vulns=vuln_count, status=status)
                progress.update(1)

                if history:
                    repo_url = next((u for u, p in rmap.items() if p == target), target)
                    config = mgr.get_config(repo_url)
                    s = result.summary
                    history.record_scan(
                        repo_url=repo_url,
                        branch=config.get("branch", ""),
                        commit_sha=config.get("commit", ""),
                        scanner=result.scanner,
                        scan_date=result.scan_date,
                        vulns=result.vulnerabilities,
                        summary=s,
                        status=status,
                    )
            except Exception as e:
                progress.set_postfix(error=str(e))
                progress.update(1)

        progress.close()

    if skipped:
        print(f"skipped: {skipped} (already scanned at same commit)")
    print()
    total_vulns = sum(len(r.vulnerabilities) for r in all_results)
    failed = sum(1 for r in all_results if r.errors)

    suppressions = SuppressionManager.load(args.suppressions)
    if suppressions.rules:
        print(f"suppressions: {len(suppressions.rules)} rule(s) loaded from {args.suppressions}")
        all_results, suppressed_log = suppressions.filter_results(all_results)
        total_vulns = sum(len(r.vulnerabilities) for r in all_results)
        print(f"suppressed: {len(suppressed_log)} finding(s) removed")
        for s in suppressed_log:
            print(f"  suppressed {s['id']} in {s['repo']} ({s['scanner']}): {s['severity']}")

    if args.epss:
        print("enriching with EPSS scores...")
        all_results = epss_enrich(all_results)
        enriched_count = sum(1 for r in all_results for v in r.vulnerabilities if v.epss is not None)
        print(f"  enriched {enriched_count} CVE(s)")

        if args.epss_threshold is not None:
            pre = sum(len(r.vulnerabilities) for r in all_results)
            all_results = epss_filter(all_results, args.epss_threshold)
            post = sum(len(r.vulnerabilities) for r in all_results)
            total_vulns = post
            print(f"  epss threshold {args.epss_threshold}: dropped {pre - post} vuln(s) below threshold")

    for reporter in reporters:
        name = reporter.__class__.__name__.replace("Reporter", "").lower()
        out = reporter.generate(all_results, name="vulnerability_report")
        print(f"report ({name}): {out}")

    if args.diff and history:
        diffs = DiffReporter(output_dir=args.output_dir).compute(all_results, repo_map, args.history_db)
        if diffs:
            print("diff:")
            DiffReporter(output_dir=args.output_dir).print_summary(diffs)
            out = DiffReporter(output_dir=args.output_dir).generate(diffs, name="vulnerability_report-diff")
            print(f"report (diff): {out}")

    if args.sbom and args.local:
        sbom_gen = SbomReporter(output_dir=args.output_dir)
        for target in scan_targets:
            if Path(target).is_dir():
                out = sbom_gen.generate_for_target(target, name=f"vulnerability_report-{Path(target).name}", fmt=args.sbom)
                if out:
                    print(f"sbom ({args.sbom}): {out}")

    dep_results_global = None

    if args.dep_tree and args.local:
        print("\nbuilding dependency tree...")
        dep_reporter = DependencyTreeReporter(output_dir=args.output_dir)
        dep_results = []
        for target in scan_targets:
            if Path(target).is_dir():
                dr = dep_reporter.scan_target(target)
                if dr:
                    dep_results.append(dr)

        dep_results_global = dep_results
        if dep_results:
            dep_reporter.print_summary(dep_results)
            out_json = dep_reporter.generate(dep_results, name="dependency_tree")
            print(f"report (dep-tree json): {out_json}")
            out_csv = dep_reporter.generate_csv(dep_results, name="dependency_tree")
            print(f"report (dep-tree csv): {out_csv}")

    if args.dep_graph and dep_results_global:
        print("\ngenerating dependency graph...")
        dep_graph_rpt = DepGraphReporter(output_dir=args.output_dir)
        out = dep_graph_rpt.generate(dep_results_global, vuln_results=all_results)
        print(f"report (dep-graph html): {out}")

    if args.outdated:
        if dep_results_global:
            print("\nchecking outdated dependencies...")
            outdated_rpt = OutdatedReporter(output_dir=args.output_dir)
            out = outdated_rpt.generate(dep_results_global, name="outdated_report")
            report_data = json.loads(Path(out).read_text())
            outdated_rpt.print_summary(report_data)
            print(f"report (outdated html): {Path(out).with_suffix('.html')}")
        else:
            print("--outdated requires --dep-tree data (use --dep-tree)")

    license_violations = False
    if args.license and args.local:
        print("\nscanning licenses...")
        policy = _parse_license_policy(args.license_policy)
        lic_scanner = LicenseScanner()
        lic_results = []
        for target in scan_targets:
            if Path(target).is_dir():
                lr = lic_scanner.scan(target)
                if lr.licenses or lr.errors:
                    lic_results.append(lr)

        if lic_results:
            lic_reporter = LicenseReporter(output_dir=args.output_dir, policy=policy)
            out = lic_reporter.generate(lic_results, name="license_report")
            print(f"report (license): {out}")
            lic_reporter.print_summary(lic_results)
            violations = lic_reporter.print_violations(lic_results)
            if violations:
                license_violations = True
                print(f"\nlicense policy violations: {len(violations)}")
        else:
            print("  no license data found")

    print()
    print(f"summary: {total_scans - skipped} scans, {total_vulns} vulnerabilities, {failed} failures")

    exit_code = 0
    if args.fail_on:
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = severity_rank[args.fail_on]
        for r in all_results:
            for v in r.vulnerabilities:
                sev = v.severity.upper()
                rank = severity_rank.get(sev.lower(), 99)
                if rank <= threshold:
                    print(f"\nfail-on {args.fail_on}: found {sev} vulnerability {v.id} in {r.repo} ({v.package})")
                    exit_code = 1

    if license_violations:
        exit_code = 1

    if args.health_report and all_results:
        print("\ngenerating health report...")
        dep_tree = None
        lic_data = None

        if args.dep_tree:
            dep_tree = dep_results_global if hasattr(args, 'dep_results_global') else None
        if dep_tree is None and args.local:
            dep_rpt = DependencyTreeReporter(output_dir=args.output_dir)
            dep_tree = []
            for target in scan_targets:
                if Path(target).is_dir():
                    dr = dep_rpt.scan_target(target)
                    if dr:
                        dep_tree.append(dr)

        if args.license:
            lic_data = lic_results if 'lic_results' in dir() else None
        if lic_data is None and args.local and not args.license:
            from scanners.license_scanner import LicenseScanner
            ls = LicenseScanner()
            lic_data = []
            for target in scan_targets:
                if Path(target).is_dir():
                    lr = ls.scan(target)
                    if lr.licenses or lr.errors:
                        lic_data.append({
                            "repo": lr.repo,
                            "licenses": [{"name": l.name, "severity": l.severity,
                                          "package": l.package, "file_path": l.file_path,
                                          "confidence": l.confidence, "link": l.link}
                                         for l in lr.licenses],
                            "errors": lr.errors,
                            "policy_violations": [],
                        })

        health = HealthReporter(output_dir=args.output_dir)
        out = health.generate(all_results, dep_tree, lic_data)
        report_data = json.loads(Path(out).with_suffix('.json').read_text())
        health.print_summary(report_data)
        print(f"report (health html): {out}")

    if args.risk_score and all_results:
        print("\ngenerating risk report...")
        risk_rpt = RiskReporter(output_dir=args.output_dir)
        out = risk_rpt.generate(all_results)
        report_data = json.loads(Path(out).with_suffix('.json').read_text())
        risk_rpt.print_summary(report_data)
        print(f"report (risk html): {out}")

    if args.sbom_diff:
        old_sbom, new_sbom = args.sbom_diff
        if Path(old_sbom).exists() and Path(new_sbom).exists():
            print(f"\ncomparing SBOMs: {old_sbom} -> {new_sbom}")
            sbom_diff_rpt = SbomDiffReporter(output_dir=args.output_dir)
            out = sbom_diff_rpt.generate(old_sbom, new_sbom)
            result_data = json.loads(Path(out).with_suffix('.json').read_text())
            sbom_diff_rpt.print_summary(result_data)
            print(f"report (sbom-diff html): {out}")
        else:
            print("error: --sbom-diff requires two existing SBOM files")

    if args.fix_recommendations and all_results:
        print("\ngenerating fix recommendations...")
        fix_rpt = FixRecommendationsReporter(output_dir=args.output_dir)
        out = fix_rpt.generate(all_results)
        report_data = json.loads(Path(out).with_suffix('.json').read_text())
        fix_rpt.print_summary(report_data)
        print(f"report (fix-recommendations html): {out}")

    if args.sarif and all_results and "sarif" not in args.formats:
        print("\nexporting sarif...")
        sarif_rpt = SarifReporter(output_dir=args.output_dir)
        out = sarif_rpt.generate(all_results)
        print(f"report (sarif): {out}")

    if args.scorecard:
        print("\nrunning OpenSSF Scorecard...")
        targets = [repo_map.get(u, u) for u in repo_urls] if args.local else repo_urls
        scorecard_rpt = ScorecardReporter(output_dir=args.output_dir)
        out = scorecard_rpt.generate(targets)
        result_data = json.loads(Path(out).with_suffix('.json').read_text())
        scorecard_rpt.print_summary(result_data)
        print(f"report (scorecard html): {out}")

    if args.regression_check and history and all_results:
        print("\nchecking for regressions...")
        reg_rpt = RegressionReporter(output_dir=args.output_dir)
        out = reg_rpt.generate(all_results, args.history_db)
        report_data = json.loads(Path(out).with_suffix('.json').read_text())
        reg_rpt.print_summary(report_data)
        print(f"report (regression html): {out}")
        if report_data["overall_status"] == "regression":
            print("  REGRESSIONS DETECTED")
            if exit_code == 0:
                exit_code = 2

    if args.compliance and all_results:
        print("\ngenerating compliance report...")
        compliance_rpt = ComplianceReporter(output_dir=args.output_dir)
        out = compliance_rpt.generate(all_results, compliance_map=args.compliance)
        report_data = json.loads(Path(out).with_suffix('.json').read_text())
        compliance_rpt.print_summary(report_data)
        print(f"report (compliance html): {out}")

    if exit_code:
        sys.exit(exit_code)


def _parse_license_policy(rules: list[str] | None) -> dict[str, str]:
    """Parse --license-policy args into a {license_name: action} dict.

    Example: --license-policy "allow=MIT,Apache-2.0" "deny=GPL-3.0"
    """
    policy: dict[str, str] = {}
    if not rules:
        return policy
    for rule in rules:
        if "=" not in rule:
            continue
        action, names = rule.split("=", 1)
        action = action.strip().lower()
        if action not in ("allow", "deny"):
            continue
        for name in names.split(","):
            name = name.strip()
            if name:
                policy[name] = action
    return policy


if __name__ == "__main__":
    main()
