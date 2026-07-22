use std::path::Path;

use color_eyre::eyre::Result;
use scan_tui::{self, read_repo_list, Format, OptionField, Scanner};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode { Dashboard, EditingContainer, Scanning, Results }

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Panel { Scanners, Formats, Options }

pub struct TuiApp {
    pub mode: Mode,
    pub panel_focus: Panel,
    pub scanner_cursor: usize,
    pub format_cursor: usize,
    pub option_cursor: usize,
    pub scan: scan_tui::ScanConfig,
    pub handle: Option<scan_tui::ScanHandle>,
    pub repos: Vec<String>,
    pub status_message: String,
    pub log_lines: Vec<String>,
    pub log_scroll: usize,
    pub should_quit: bool,
    pub total_critical: usize,   pub total_high: usize,
    pub total_medium: usize,     pub total_low: usize,
    pub total_vulns: usize,
    pub completed_targets: usize,
    pub total_targets: usize,
    pub scan_results: Vec<scan_tui::ScanResult>,
}

impl TuiApp {
    pub fn new(project_root: &Path) -> Result<Self> {
        let repos = read_repo_list(&project_root.join("repolist.txt"))?;
        Ok(Self {
            mode: Mode::Dashboard,
            panel_focus: Panel::Scanners,
            scanner_cursor: 0, format_cursor: 0, option_cursor: 0,
            scan: scan_tui::ScanConfig::default(),
            handle: None,
            repos,
            status_message: String::new(),
            log_lines: Vec::new(), log_scroll: 0, should_quit: false,
            total_critical: 0, total_high: 0, total_medium: 0, total_low: 0,
            total_vulns: 0, completed_targets: 0, total_targets: 0,
            scan_results: Vec::new(),
        })
    }

    pub fn toggle_scanner(&mut self, idx: usize) {
        if idx >= Scanner::ALL.len() { return; }
        let s = Scanner::ALL[idx];
        if let Some(p) = self.scan.scanners.iter().position(|x| *x == s) {
            if self.scan.scanners.len() > 1 { self.scan.scanners.remove(p); }
        } else { self.scan.scanners.push(s); }
    }

    pub fn toggle_format(&mut self, idx: usize) {
        if idx >= Format::ALL.len() { return; }
        let f = Format::ALL[idx];
        if let Some(p) = self.scan.formats.iter().position(|x| *x == f) {
            if self.scan.formats.len() > 1 { self.scan.formats.remove(p); }
        } else { self.scan.formats.push(f); }
    }

    pub fn toggle_option(&mut self, f: OptionField) {
        let o = &mut self.scan.opts;
        match f {
            OptionField::Diff => o.diff ^= true,
            OptionField::DepTree => o.dep_tree ^= true,
            OptionField::License => o.license ^= true,
            OptionField::Health => o.health ^= true,
            OptionField::Outdated => o.outdated ^= true,
            OptionField::DepGraph => o.dep_graph ^= true,
            OptionField::FixRecs => o.fix_recs ^= true,
            OptionField::Epss => o.epss ^= true,
            OptionField::RiskScore => o.risk_score ^= true,
            OptionField::Scorecard => o.scorecard ^= true,
            OptionField::SbomDiff => o.sbom_diff ^= true,
            OptionField::Suppressions => o.suppressions ^= true,
            OptionField::Compliance => o.compliance ^= true,
            OptionField::RegressionCheck => o.regression ^= true,
        }
    }

    pub fn is_option_enabled(&self, f: OptionField) -> bool {
        let o = &self.scan.opts;
        match f {
            OptionField::Diff => o.diff,           OptionField::DepTree => o.dep_tree,
            OptionField::License => o.license,      OptionField::Health => o.health,
            OptionField::Outdated => o.outdated,    OptionField::DepGraph => o.dep_graph,
            OptionField::FixRecs => o.fix_recs,
            OptionField::Epss => o.epss,            OptionField::RiskScore => o.risk_score,
            OptionField::Scorecard => o.scorecard,  OptionField::SbomDiff => o.sbom_diff,
            OptionField::Suppressions => o.suppressions,
            OptionField::Compliance => o.compliance,
            OptionField::RegressionCheck => o.regression,
        }
    }

    pub fn options_enabled_count(&self) -> usize {
        let o = &self.scan.opts;
        [o.diff, o.dep_tree, o.license, o.health, o.outdated, o.dep_graph, o.fix_recs,
         o.epss, o.risk_score, o.scorecard, o.sbom_diff, o.suppressions, o.compliance, o.regression]
            .iter().filter(|&&x| x).count()
    }

    pub fn start_scan(&mut self, project_root: &Path) -> Result<()> {
        let mut cmd = scan_tui::build_scan_cmd(&self.scan, &self.repos, project_root)?;
        let mut handle = scan_tui::spawn_scan(&mut cmd)?;
        handle.total_targets = self.repos.len() * self.scan.scanners.len();
        self.total_targets = handle.total_targets;
        self.completed_targets = 0;
        self.handle = Some(handle);
        self.mode = Mode::Scanning;
        self.log_lines.clear();
        self.status_message = "scanning...".to_string();
        Ok(())
    }

    fn sync_from_handle(&mut self) {
        if let Some(h) = &self.handle {
            self.scan_results = h.scan_results.clone();
            self.total_critical = h.total_critical;
            self.total_high = h.total_high;
            self.total_medium = h.total_medium;
            self.total_low = h.total_low;
            self.total_vulns = h.total_vulns;
            self.completed_targets = h.completed_targets;
            self.total_targets = h.total_targets;
        }
    }

    pub fn poll_logs(&mut self) {
        if let Some(h) = &mut self.handle {
            if let Some(rx) = &mut h.log_rx {
                while let Ok(l) = rx.try_recv() { self.log_lines.push(l); }
                if self.log_lines.len() > 10_000 {
                    self.log_lines.drain(0..self.log_lines.len() - 10_000);
                }
            }
        }
    }

    pub async fn kill_child(&mut self) {
        if let Some(h) = &self.handle {
            if let Some(ref child) = h.child {
                if let Some(pid) = child.id() {
                    let _ = tokio::process::Command::new("kill").args(["-15", &pid.to_string()]).spawn();
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    let _ = tokio::process::Command::new("kill").args(["-9", &pid.to_string()]).spawn();
                }
            }
        }
        if let Some(h) = &mut self.handle { h.child = None; }
        self.mode = Mode::Dashboard;
    }

    pub async fn poll_child(&mut self) {
        if let Some(h) = &mut self.handle {
            if let Some(start) = h.scan_start {
                if start.elapsed().as_secs() > 600 {
                    self.status_message = "timed out".to_string();
                    self.handle = None;
                    self.mode = Mode::Results;
                    return;
                }
            }
            if let Some(mut child) = h.child.take() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        h.child = None;
                        h.scan_start = None;
                        if status.success() {
                            h.load_results("reports");
                            self.sync_from_handle();
                            self.status_message = "scan complete".to_string();
                        } else {
                            self.status_message = format!("failed: {:?}", status.code());
                        }
                        self.mode = Mode::Results;
                    }
                    Ok(None) => { h.child = Some(child); }
                    Err(e) => {
                        h.scan_start = None;
                        self.status_message = format!("error: {e}");
                        self.mode = Mode::Results;
                    }
                }
            }
        }
    }
}
