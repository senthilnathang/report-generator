import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from scanners import TrivyScanner, GrypeScanner, SnykScanner
from reporters import ExcelReporter, JsonReporter, PdfReporter

SCANNER_MAP = {
    "trivy": TrivyScanner,
    "grype": GrypeScanner,
    "snyk": SnykScanner,
}

REPORTER_MAP = {
    "excel": ExcelReporter,
    "json": JsonReporter,
    "pdf": PdfReporter,
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
    p.add_argument(
        "-i", "--input",
        default="repolist.txt",
        help="Path to repo list file (default: repolist.txt)",
    )
    p.add_argument(
        "-s", "--scanners",
        nargs="+",
        choices=list(SCANNER_MAP.keys()),
        default=["trivy"],
        help="Scanners to run (default: trivy)",
    )
    p.add_argument(
        "-f", "--formats",
        nargs="+",
        choices=list(REPORTER_MAP.keys()),
        default=["json"],
        help="Report output formats (default: json)",
    )
    p.add_argument(
        "-o", "--output-dir",
        default="reports",
        help="Output directory for reports (default: reports)",
    )
    p.add_argument(
        "-j", "--jobs",
        type=int,
        default=4,
        help="Parallel scan jobs (default: 4)",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    if not Path(args.input).exists():
        print(f"error: repo list not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    repos = read_repo_list(args.input)
    if not repos:
        print("error: no repositories found in list", file=sys.stderr)
        sys.exit(1)

    scanners = [SCANNER_MAP[name]() for name in args.scanners]
    reporters = [REPORTER_MAP[name](output_dir=args.output_dir) for name in args.formats]

    print(f"repositories: {len(repos)}")
    print(f"scanners: {', '.join(args.scanners)}")
    print(f"formats: {', '.join(args.formats)}")
    print(f"output dir: {args.output_dir}")
    print()

    all_results = []
    total_scans = len(repos) * len(scanners)
    completed = 0
    failed = 0

    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {}
        for repo in repos:
            for scanner in scanners:
                fut = executor.submit(scanner.scan, repo)
                futures[fut] = (repo, scanner.__class__.__name__)

        for fut in as_completed(futures):
            repo, scanner_name = futures[fut]
            completed += 1
            try:
                result = fut.result()
                all_results.append(result)
                vuln_count = len(result.vulnerabilities)
                err_count = len(result.errors)
                status = "ok"
                if err_count:
                    status = f"errors({err_count})"
                    failed += 1
                print(f"[{completed}/{total_scans}] {repo} | {scanner_name} | {vuln_count} vulns | {status}")
            except Exception as e:
                failed += 1
                print(f"[{completed}/{total_scans}] {repo} | {scanner_name} | error: {e}")

    print()
    total_vulns = sum(len(r.vulnerabilities) for r in all_results)

    for reporter in reporters:
        name = reporter.__class__.__name__.replace("Reporter", "").lower()
        out = reporter.generate(all_results, name="vulnerability_report")
        print(f"report ({name}): {out}")

    print()
    print(f"summary: {total_scans} scans, {total_vulns} vulnerabilities, {failed} failures")


if __name__ == "__main__":
    main()
