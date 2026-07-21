use std::path::Path;
use std::process::Stdio;

use color_eyre::eyre::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Dashboard,
    Scanning,
    Results,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Scanner {
    Trivy,
    Grype,
    Snyk,
}

impl Scanner {
    pub const ALL: [Scanner; 3] = [Scanner::Trivy, Scanner::Grype, Scanner::Snyk];

    pub fn as_str(&self) -> &'static str {
        match self {
            Scanner::Trivy => "trivy",
            Scanner::Grype => "grype",
            Scanner::Snyk => "snyk",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Excel,
    Pdf,
    Html,
    Sarif,
}

impl Format {
    pub const ALL: [Format; 5] = [Format::Json, Format::Excel, Format::Pdf, Format::Html, Format::Sarif];

    pub fn as_str(&self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Excel => "excel",
            Format::Pdf => "pdf",
            Format::Html => "html",
            Format::Sarif => "sarif",
        }
    }
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct ConfigRepos {
    url: String,
    branch: Option<String>,
    scan_mode: Option<String>,
    commit: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct Config {
    repositories: Vec<ConfigRepos>,
}

#[derive(Clone)]
pub struct ScanResult {
    pub repo: String,
    pub scanner: String,
    pub vulns: usize,
    pub errors: Vec<String>,
    #[allow(dead_code)]
    pub scan_date: String,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl ScanResult {
    fn from_json(value: &Value) -> Option<Self> {
        let repo = value.get("repo")?.as_str()?.to_string();
        let scanner = value.get("scanner")?.as_str()?.to_string();
        let scan_date = value.get("scan_date")?.as_str()?.to_string();
        let vulns = value.get("vulnerabilities")?.as_array()?;
        let errors: Vec<String> = value
            .get("errors")?
            .as_array()?
            .iter()
            .filter_map(|v: &Value| v.as_str().map(String::from))
            .collect();
        let summary = value.get("summary")?;
        let critical = summary.get("CRITICAL").and_then(Value::as_u64).unwrap_or(0) as usize;
        let high = summary.get("HIGH").and_then(Value::as_u64).unwrap_or(0) as usize;
        let medium = summary.get("MEDIUM").and_then(Value::as_u64).unwrap_or(0) as usize;
        let low = summary.get("LOW").and_then(Value::as_u64).unwrap_or(0) as usize;

        Some(ScanResult {
            repo,
            scanner,
            vulns: vulns.len(),
            errors,
            scan_date,
            critical,
            high,
            medium,
            low,
        })
    }
}

pub struct App {
    pub mode: Mode,
    pub repos: Vec<String>,
    pub scanners: Vec<Scanner>,
    pub formats: Vec<Format>,
    pub log_lines: Vec<String>,
    pub scan_results: Vec<ScanResult>,
    pub scan_pid: Option<u32>,
    pub result_file: String,
    pub status_message: String,
    pub total_critical: usize,
    pub total_high: usize,
    pub total_medium: usize,
    pub total_low: usize,
    pub total_vulns: usize,
    pub total_targets: usize,
    pub completed_targets: usize,
    pub should_quit: bool,
    pub diff_enabled: bool,
    pub log_scroll: usize,
    pub scan_timeout_secs: u64,
    scan_start: Option<std::time::Instant>,
    #[allow(dead_code)]
    pub list_index: usize,
    pub scanner_index: usize,
    pub format_index: usize,
    log_rx: Option<mpsc::Receiver<String>>,
    child: Option<Child>,
}

impl App {
    pub fn new(project_root: &Path) -> Result<Self> {
        let repos = read_repo_list(&project_root.join("repolist.txt"))?;
        let total_targets = repos.len() * 3; // worst-case: all 3 scanners
        Ok(App {
            mode: Mode::Dashboard,
            repos,
            scanners: vec![Scanner::Trivy],
            formats: vec![Format::Json],
            log_lines: Vec::new(),
            scan_results: Vec::new(),
            scan_pid: None,
            result_file: project_root.join("reports").to_string_lossy().to_string(),
            status_message: String::new(),
            total_critical: 0,
            total_high: 0,
            total_medium: 0,
            total_low: 0,
            total_vulns: 0,
            total_targets,
            completed_targets: 0,
            should_quit: false,
            diff_enabled: false,
            log_scroll: 0,
            scan_timeout_secs: 600,
            scan_start: None,
            list_index: 0,
            scanner_index: 0,
            format_index: 0,
            log_rx: None,
            child: None,
        })
    }

    pub fn toggle_scanner(&mut self, idx: usize) {
        if idx >= Scanner::ALL.len() {
            return;
        }
        let scanner = Scanner::ALL[idx];
        if let Some(pos) = self.scanners.iter().position(|s| *s == scanner) {
            if self.scanners.len() > 1 {
                self.scanners.remove(pos);
            }
        } else {
            self.scanners.push(scanner);
        }
    }

    #[allow(dead_code)]
    pub fn toggle_format(&mut self, idx: usize) {
        if idx >= Format::ALL.len() {
            return;
        }
        let fmt = Format::ALL[idx];
        if let Some(pos) = self.formats.iter().position(|f| *f == fmt) {
            if self.formats.len() > 1 {
                self.formats.remove(pos);
            }
        } else {
            self.formats.push(fmt);
        }
    }

    pub fn start_scan(&mut self, project_root: &Path) -> Result<()> {
        let scanner_args: Vec<&str> = self.scanners.iter().map(|s| s.as_str()).collect();
        let format_args: Vec<&str> = self.formats.iter().map(|f| f.as_str()).collect();
        self.total_targets = self.repos.len() * self.scanners.len();
        self.completed_targets = 0;

        let mut cmd = Command::new("python3");
        cmd.arg("main.py")
            .arg("-i")
            .arg("repolist.txt")
            .arg("-s")
            .args(&scanner_args)
            .arg("-f")
            .args(&format_args)
            .arg("-o")
            .arg(self.result_file.as_str())
            .arg("--local")
            .arg("--sync")
            .arg("--history");
        if self.diff_enabled {
            cmd.arg("--diff");
        }
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(project_root);

        let mut child = cmd.spawn().wrap_err("failed to spawn python3")?;
        self.scan_pid = child.id();
        let (tx, rx) = mpsc::channel(256);
        self.log_rx = Some(rx);

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let tx1 = tx.clone();
        if let Some(stdout) = stdout {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    if tx1.send(line).await.is_err() {
                        break;
                    }
                }
            });
        }

        if let Some(stderr) = stderr {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    if tx.send(line).await.is_err() {
                        break;
                    }
                }
            });
        }

        self.child = Some(child);
        self.scan_start = Some(std::time::Instant::now());
        self.mode = Mode::Scanning;
        self.log_lines.clear();
        self.status_message = "scanning...".to_string();
        Ok(())
    }

    pub fn poll_logs(&mut self) {
        if let Some(rx) = &mut self.log_rx {
            while let Ok(line) = rx.try_recv() {
                self.log_lines.push(line);
            }
            if self.log_lines.len() > 10_000 {
                self.log_lines.drain(0..self.log_lines.len() - 10_000);
            }
        }
    }

    pub async fn kill_child(&mut self) {
        if let Some(pid) = self.scan_pid {
            // SIGTERM first
            let _ = tokio::process::Command::new("kill")
                .args(["-15", &pid.to_string()])
                .spawn();
            // brief wait, then SIGKILL
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let _ = tokio::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .spawn();
        }
        self.scan_pid = None;
        self.child = None;
    }

    pub async fn poll_child(&mut self) {
        if let Some(start) = self.scan_start {
            if start.elapsed().as_secs() > self.scan_timeout_secs {
                self.status_message = "scan timed out".to_string();
                self.kill_child().await;
                self.mode = Mode::Results;
                return;
            }
        }
        if let Some(mut child) = self.child.take() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.scan_pid = None;
                    self.scan_start = None;
                    if status.success() {
                        self.status_message = "scan completed successfully".to_string();
                        self.load_results();
                        self.mode = Mode::Results;
                    } else {
                        self.status_message =
                            format!("scan failed with exit code: {:?}", status.code());
                        self.mode = Mode::Results;
                    }
                }
                Ok(None) => {
                    self.child = Some(child);
                }
                Err(e) => {
                    self.scan_start = None;
                    self.status_message = format!("scan error: {e}");
                    self.mode = Mode::Results;
                }
            }
        }
    }

    fn load_results(&mut self) {
        let path = Path::new(&self.result_file).join("vulnerability_report.json");
        if !path.exists() {
            return;
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        let values: Vec<Value> = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return,
        };
        self.scan_results = values.iter().filter_map(|v| ScanResult::from_json(v)).collect();
        self.total_critical = self.scan_results.iter().map(|r| r.critical).sum();
        self.total_high = self.scan_results.iter().map(|r| r.high).sum();
        self.total_medium = self.scan_results.iter().map(|r| r.medium).sum();
        self.total_low = self.scan_results.iter().map(|r| r.low).sum();
        self.total_vulns = self.scan_results.iter().map(|r| r.vulns).sum();
        self.completed_targets = self.scan_results.len();
    }
}

fn read_repo_list(path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path).wrap_err_with(|| format!("reading {}", path.display()))?;
    let repos: Vec<String> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    Ok(repos)
}
