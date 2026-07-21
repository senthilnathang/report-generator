import sqlite3
from pathlib import Path


class ScanHistory:
    def __init__(self, db_path: str = "scan_history.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_url TEXT NOT NULL,
                    branch TEXT,
                    commit_sha TEXT,
                    scanner TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    total_vulns INTEGER DEFAULT 0,
                    critical INTEGER DEFAULT 0,
                    high INTEGER DEFAULT 0,
                    medium INTEGER DEFAULT 0,
                    low INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'ok'
                );
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER NOT NULL,
                    vuln_id TEXT NOT NULL,
                    package TEXT,
                    installed_version TEXT,
                    fixed_version TEXT,
                    severity TEXT,
                    type TEXT,
                    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
                );
            """)

    def was_commit_scanned(self, repo_url: str, commit_sha: str, scanner: str) -> bool:
        if not commit_sha:
            return False
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute(
                "SELECT COUNT(*) FROM scan_runs WHERE repo_url=? AND commit_sha=? AND scanner=?",
                (repo_url, commit_sha, scanner),
            )
            return cursor.fetchone()[0] > 0

    def record_scan(
        self, repo_url: str, branch: str, commit_sha: str,
        scanner: str, scan_date: str, vulns: list,
        summary: dict[str, int], status: str,
    ) -> int:
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute(
                """INSERT INTO scan_runs
                   (repo_url, branch, commit_sha, scanner, scan_date,
                    total_vulns, critical, high, medium, low, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (repo_url, branch, commit_sha, scanner, scan_date,
                 len(vulns), summary.get("CRITICAL", 0), summary.get("HIGH", 0),
                 summary.get("MEDIUM", 0), summary.get("LOW", 0), status),
            )
            scan_run_id = cursor.lastrowid
            for v in vulns:
                conn.execute(
                    """INSERT INTO vulnerabilities
                       (scan_run_id, vuln_id, package, installed_version, fixed_version, severity, type)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (scan_run_id, v.id, v.package, v.installed_version,
                     v.fixed_version, v.severity, v.type),
                )
            conn.commit()
        return scan_run_id
