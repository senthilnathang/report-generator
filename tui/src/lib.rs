use std::path::Path;

use color_eyre::eyre::{Context, Result};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

// ── enums ─────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Scanner {
    Trivy, Grype, Snyk, Bandit, Semgrep, Gitleaks, Checkov,
}
impl Scanner {
    pub const ALL: [Scanner; 7] = [
        Self::Trivy, Self::Grype, Self::Snyk, Self::Bandit,
        Self::Semgrep, Self::Gitleaks, Self::Checkov,
    ];
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trivy => "trivy", Self::Grype => "grype", Self::Snyk => "snyk",
            Self::Bandit => "bandit", Self::Semgrep => "semgrep",
            Self::Gitleaks => "gitleaks", Self::Checkov => "checkov",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json, Excel, Pdf, Html, Sarif,
}
impl Format {
    pub const ALL: [Format; 5] = [Self::Json, Self::Excel, Self::Pdf, Self::Html, Self::Sarif];
    pub fn as_str(&self) -> &'static str {
        match self { Self::Json => "json", Self::Excel => "excel", Self::Pdf => "pdf", Self::Html => "html", Self::Sarif => "sarif" }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OptionField {
    Diff, DepTree, License, Health, Outdated, DepGraph, FixRecs,
    Epss, RiskScore, Scorecard, SbomDiff,
    Suppressions, Compliance, RegressionCheck,
}
impl OptionField {
    pub const ALL: [Self; 14] = [
        Self::Diff, Self::DepTree, Self::License, Self::Health, Self::Outdated,
        Self::DepGraph, Self::FixRecs,
        Self::Epss, Self::RiskScore, Self::Scorecard, Self::SbomDiff,
        Self::Suppressions, Self::Compliance, Self::RegressionCheck,
    ];
    pub fn label(&self) -> &'static str {
        match self {
            Self::Diff => "diff", Self::DepTree => "dep-tree", Self::License => "license",
            Self::Health => "health", Self::Outdated => "outdated", Self::DepGraph => "dep-graph",
            Self::FixRecs => "fix-recs", Self::Epss => "epss", Self::RiskScore => "risk-score",
            Self::Scorecard => "scorecard", Self::SbomDiff => "sbom-diff",
            Self::Suppressions => "suppressions", Self::Compliance => "compliance",
            Self::RegressionCheck => "regression-check",
        }
    }
    pub fn category(&self) -> &'static str {
        match self {
            Self::Diff | Self::DepTree | Self::License | Self::Health
            | Self::Outdated | Self::DepGraph | Self::FixRecs => " Reports ",
            Self::Epss | Self::RiskScore | Self::Scorecard | Self::SbomDiff => " Analysis ",
            Self::Suppressions | Self::Compliance | Self::RegressionCheck => " Security ",
        }
    }
}

// ── config / state ────────────────────────────────────────────

#[derive(Clone)]
pub struct ScanOptions {
    pub diff: bool, pub dep_tree: bool, pub license: bool,
    pub health: bool, pub outdated: bool, pub dep_graph: bool, pub fix_recs: bool,
    pub epss: bool, pub risk_score: bool, pub scorecard: bool, pub sbom_diff: bool,
    pub suppressions: bool, pub compliance: bool, pub regression: bool,
}

impl Default for ScanOptions {
    fn default() -> Self { Self { diff: false, dep_tree: false, license: false, health: false, outdated: false, dep_graph: false, fix_recs: false, epss: false, risk_score: false, scorecard: false, sbom_diff: false, suppressions: false, compliance: false, regression: false } }
}

#[derive(Clone)]
pub struct ScanConfig {
    pub scanners: Vec<Scanner>,
    pub formats: Vec<Format>,
    pub opts: ScanOptions,
    pub fail_on_index: usize,
    pub epss_threshold: f64,
    pub container_images: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            scanners: vec![Scanner::Trivy, Scanner::Grype, Scanner::Bandit],
            formats: vec![Format::Json, Format::Html],
            opts: ScanOptions::default(),
            fail_on_index: 0, epss_threshold: 0.5, container_images: String::new(),
        }
    }
}

#[derive(Clone)]
pub struct ScanResult {
    pub repo: String, pub scanner: String, pub vulns: usize,
    pub errors: Vec<String>, pub scan_date: String,
    pub critical: usize, pub high: usize, pub medium: usize, pub low: usize,
}
impl ScanResult {
    pub fn from_json(v: &Value) -> Option<Self> {
        Some(Self {
            repo: v.get("repo")?.as_str()?.to_string(),
            scanner: v.get("scanner")?.as_str()?.to_string(),
            scan_date: v.get("scan_date")?.as_str()?.to_string(),
            vulns: v.get("vulnerabilities")?.as_array()?.len(),
            errors: v.get("errors")?.as_array()?.iter().filter_map(|e| e.as_str().map(String::from)).collect(),
            critical: v.get("summary")?.get("CRITICAL").and_then(Value::as_u64).unwrap_or(0) as usize,
            high: v.get("summary")?.get("HIGH").and_then(Value::as_u64).unwrap_or(0) as usize,
            medium: v.get("summary")?.get("MEDIUM").and_then(Value::as_u64).unwrap_or(0) as usize,
            low: v.get("summary")?.get("LOW").and_then(Value::as_u64).unwrap_or(0) as usize,
        })
    }
}

pub struct ScanHandle {
    pub child: Option<Child>,
    pub log_rx: Option<mpsc::Receiver<String>>,
    pub scan_start: Option<std::time::Instant>,
    pub completed_targets: usize,
    pub total_targets: usize,
    pub scan_results: Vec<ScanResult>,
    pub total_critical: usize, pub total_high: usize, pub total_medium: usize,
    pub total_low: usize, pub total_vulns: usize,
}
impl ScanHandle {
    pub fn load_results(&mut self, result_file: &str) {
        let path = Path::new(result_file).join("vulnerability_report.json");
        let content = match std::fs::read_to_string(&path) { Ok(c) => c, Err(_) => return };
        let values: Vec<Value> = match serde_json::from_str(&content) { Ok(v) => v, Err(_) => return };
        self.scan_results = values.iter().filter_map(|v| ScanResult::from_json(v)).collect();
        self.total_critical = self.scan_results.iter().map(|r| r.critical).sum();
        self.total_high = self.scan_results.iter().map(|r| r.high).sum();
        self.total_medium = self.scan_results.iter().map(|r| r.medium).sum();
        self.total_low = self.scan_results.iter().map(|r| r.low).sum();
        self.total_vulns = self.scan_results.iter().map(|r| r.vulns).sum();
        self.completed_targets = self.scan_results.len();
    }
}

pub const FAIL_ON_LEVELS: [&str; 5] = ["none", "critical", "high", "medium", "low"];

// ── scan command builder ──────────────────────────────────────

pub fn build_scan_cmd(config: &ScanConfig, _repos: &[String], project_root: &Path) -> Result<Command> {
    let sc_args: Vec<&str> = config.scanners.iter().map(|s| s.as_str()).collect();
    let fmt_args: Vec<&str> = config.formats.iter().map(|f| f.as_str()).collect();
    let mut cmd = Command::new("python3");
    cmd.arg("main.py").arg("-i").arg("repolist.txt")
        .arg("-s").args(&sc_args).arg("-f").args(&fmt_args)
        .arg("-o").arg("reports")
        .arg("--local").arg("--sync").arg("--history");
    let o = &config.opts;
    if o.diff { cmd.arg("--diff"); }
    if o.dep_tree { cmd.arg("--dep-tree"); }
    if o.license { cmd.arg("--license"); }
    if o.health { cmd.arg("--health-report"); }
    if o.outdated { cmd.arg("--outdated"); }
    if o.dep_graph { cmd.arg("--dep-graph"); }
    if o.fix_recs { cmd.arg("--fix-recommendations"); }
    if o.epss { cmd.arg("--epss"); }
    if o.risk_score { cmd.arg("--risk-score"); }
    if o.scorecard { cmd.arg("--scorecard"); }
    if o.sbom_diff { cmd.arg("--sbom-diff"); }
    if o.suppressions { cmd.arg("--suppressions"); }
    if o.compliance { cmd.arg("--compliance"); }
    if o.regression { cmd.arg("--regression-check"); }
    if config.fail_on_index > 0 { cmd.arg("--fail-on").arg(FAIL_ON_LEVELS[config.fail_on_index]); }
    if o.epss && config.epss_threshold > 0.0 { cmd.arg("--epss-threshold").arg(format!("{}", config.epss_threshold)); }
    if !config.container_images.is_empty() { cmd.arg("--container"); for img in config.container_images.split_whitespace() { cmd.arg(img); } }
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).current_dir(project_root);
    Ok(cmd)
}

pub fn spawn_scan(cmd: &mut Command) -> Result<ScanHandle> {
    let mut child = cmd.spawn()?;
    let (tx, rx) = mpsc::channel(256);
    if let Some(o) = child.stdout.take() { let t = tx.clone(); tokio::spawn(async move { let mut r = BufReader::new(o).lines(); while let Ok(Some(l)) = r.next_line().await { if t.send(l).await.is_err() { break; } } }); }
    if let Some(e) = child.stderr.take() { tokio::spawn(async move { let mut r = BufReader::new(e).lines(); while let Ok(Some(l)) = r.next_line().await { if tx.send(l).await.is_err() { break; } } }); }
    Ok(ScanHandle {
        child: Some(child), log_rx: Some(rx), scan_start: Some(std::time::Instant::now()),
        completed_targets: 0, total_targets: 0, scan_results: Vec::new(),
        total_critical: 0, total_high: 0, total_medium: 0, total_low: 0, total_vulns: 0,
    })
}

pub fn read_repo_list(path: &Path) -> Result<Vec<String>> {
    Ok(std::fs::read_to_string(path)
        .wrap_err_with(|| format!("reading {}", path.display()))?
        .lines().map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from).collect())
}
