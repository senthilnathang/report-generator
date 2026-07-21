import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from tqdm import tqdm

from scanners import TrivyScanner, GrypeScanner, SnykScanner
from scanners.license_scanner import LicenseScanner
from reporters import ExcelReporter, JsonReporter, PdfReporter, HtmlReporter, SarifReporter
from reporters.sbom_reporter import SbomReporter
from reporters.diff_reporter import DiffReporter
from reporters.license_reporter import LicenseReporter
from reporters.dep_tree_reporter import DependencyTreeReporter
from reporters.health_reporter import HealthReporter
from repo_manager import RepoManager
from scan_history import ScanHistory

SCANNER_MAP = {
    "trivy": TrivyScanner,
    "grype": GrypeScanner,
    "snyk": SnykScanner,
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
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

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

    if args.dep_tree and args.local:
        print("\nbuilding dependency tree...")
        dep_reporter = DependencyTreeReporter(output_dir=args.output_dir)
        dep_results = []
        for target in scan_targets:
            if Path(target).is_dir():
                dr = dep_reporter.scan_target(target)
                if dr:
                    dep_results.append(dr)

        if dep_results:
            dep_reporter.print_summary(dep_results)
            out_json = dep_reporter.generate(dep_results, name="dependency_tree")
            print(f"report (dep-tree json): {out_json}")
            out_csv = dep_reporter.generate_csv(dep_results, name="dependency_tree")
            print(f"report (dep-tree csv): {out_csv}")

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
