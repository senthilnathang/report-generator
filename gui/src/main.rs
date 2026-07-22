use std::path::Path;
use std::sync::{Arc, Mutex};

use eframe::egui::{self, Color32, RichText};
use scan_tui::{
    self, read_repo_list, FAIL_ON_LEVELS, Format, OptionField, Scanner, ScanConfig, ScanHandle,
    ScanResult,
};

#[derive(PartialEq)]
enum Tab { Config, Scan, Results }

struct AppState {
    config: ScanConfig,
    repos: Vec<String>,
    handle: Option<ScanHandle>,
    log_lines: Vec<String>,
    scan_results: Vec<ScanResult>,
    total_critical: usize, total_high: usize, total_medium: usize, total_low: usize, total_vulns: usize,
    completed: usize, total: usize,
    status: String,
    tab: Tab,
    started: bool,
}

impl Default for AppState {
    fn default() -> Self {
        let repos = read_repo_list(&Path::new("/opt/report-generator/repolist.txt")).unwrap_or_default();
        Self {
            config: ScanConfig::default(), repos, handle: None, log_lines: Vec::new(),
            scan_results: Vec::new(), total_critical: 0, total_high: 0, total_medium: 0,
            total_low: 0, total_vulns: 0, completed: 0, total: 0,
            status: String::new(), tab: Tab::Config, started: false,
        }
    }
}

impl AppState {
    fn opts_count(&self) -> usize {
        let o = &self.config.opts;
        [o.diff, o.dep_tree, o.license, o.health, o.outdated, o.dep_graph, o.fix_recs,
         o.epss, o.risk_score, o.scorecard, o.sbom_diff, o.suppressions, o.compliance, o.regression]
            .iter().filter(|&&x| x).count()
    }

    fn start_scan(&mut self) {
        self.log_lines.clear();
        self.started = true;
        self.status = "starting...".to_string();
        let mut cmd = match scan_tui::build_scan_cmd(&self.config, &self.repos, Path::new("/opt/report-generator")) {
            Ok(c) => c, Err(e) => { self.status = format!("error: {e}"); return; }
        };
        match scan_tui::spawn_scan(&mut cmd) {
            Ok(mut h) => { h.total_targets = self.repos.len() * self.config.scanners.len();
                self.handle = Some(h); }
            Err(e) => self.status = format!("error: {e}"),
        }
    }

    fn poll(&mut self) {
        if let Some(h) = &mut self.handle {
            if let Some(rx) = &mut h.log_rx {
                while let Ok(l) = rx.try_recv() { self.log_lines.push(l); }
            }
            if let Some(mut child) = h.child.take() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        h.child = None; h.scan_start = None;
                        if status.success() { h.load_results("reports"); self.sync_results(); }
                        self.status = if status.success() { "complete".to_string() } else { format!("failed: {:?}", status.code()) };
                        self.tab = Tab::Results;
                    }
                    Ok(None) => { h.child = Some(child); }
                    Err(e) => { self.status = format!("error: {e}"); }
                }
            }
        }
    }

    fn sync_results(&mut self) {
        if let Some(h) = &self.handle {
            self.scan_results = h.scan_results.clone();
            self.total_critical = h.total_critical; self.total_high = h.total_high;
            self.total_medium = h.total_medium; self.total_low = h.total_low;
            self.total_vulns = h.total_vulns;
            self.completed = h.completed_targets; self.total = h.total_targets;
        }
    }
}

fn main() -> eframe::Result<()> {
    let state = Arc::new(Mutex::new(AppState::default()));
    let s2 = state.clone();
    eframe::run_ui_native("scan-gui", eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 600.0]),
        ..Default::default()
    }, Box::new(move |ui: &mut egui::Ui, _frame: &mut eframe::Frame| {
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
        let mut s = s2.lock().unwrap();
        if s.started { s.poll(); }
        render_topbar(ui, &mut s);
        egui::CentralPanel::default().show(ui, |ui| {
            match s.tab {
                Tab::Config => render_config(ui, &mut s),
                Tab::Scan => render_scan(ui, &mut s),
                Tab::Results => render_results(ui, &mut s),
            }
        });
    }))
}

fn render_topbar(ui: &mut egui::Ui, s: &mut AppState) {
    egui::Panel::top("header").show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.heading(RichText::new("⚡ scan-gui").color(Color32::from_rgb(0, 200, 255)));
            ui.label(format!("  {} repos · {} scanners · {} formats",
                s.repos.len(), s.config.scanners.len(), s.config.formats.len()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Quit").clicked() { std::process::exit(0); }
            });
        });
    });
    egui::Panel::top("tabs").show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut s.tab, Tab::Config, "⚙  Config");
            ui.selectable_value(&mut s.tab, Tab::Scan, "▶  Scan");
            ui.selectable_value(&mut s.tab, Tab::Results, "📊  Results");
        });
    });
}

fn render_config(ui: &mut egui::Ui, s: &mut AppState) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.columns(3, |cols| {
            cols[0].vertical(|ui| {
                ui.label(RichText::new("Scanners").size(16.0).strong());
                ui.separator();
                for sc in &Scanner::ALL {
                    let checked = s.config.scanners.contains(sc);
                    let mut c = checked;
                    ui.checkbox(&mut c, sc.as_str());
                    if c && !checked { s.config.scanners.push(*sc); }
                    if !c && checked {
                        if let Some(p) = s.config.scanners.iter().position(|x| x == sc) {
                            if s.config.scanners.len() > 1 { s.config.scanners.remove(p); }
                        }
                    }
                }
                ui.add_space(16.0);
                ui.label(RichText::new("Formats").size(16.0).strong());
                ui.separator();
                for fmt in &Format::ALL {
                    let checked = s.config.formats.contains(fmt);
                    let mut c = checked;
                    ui.checkbox(&mut c, fmt.as_str());
                    if c && !checked { s.config.formats.push(*fmt); }
                    if !c && checked {
                        if let Some(p) = s.config.formats.iter().position(|x| x == fmt) {
                            if s.config.formats.len() > 1 { s.config.formats.remove(p); }
                        }
                    }
                }
            });
            cols[1].vertical(|ui| {
                ui.label(RichText::new("Options").size(16.0).strong());
                ui.separator();
                let mut cat = "";
                for opt in &OptionField::ALL {
                    let c = opt.category().trim();
                    if c != cat { cat = c; ui.label(RichText::new(c).color(Color32::GRAY).italics()); }
                    let enabled = s.config.opts.enabled(opt);
                    let mut e = enabled;
                    ui.checkbox(&mut e, opt.label());
                    if e != enabled { s.config.opts.set(opt, e); }
                }
            });
            cols[2].vertical(|ui| {
                ui.label(RichText::new("Config").size(16.0).strong());
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Fail-on:");
                    let idx = &mut s.config.fail_on_index;
                    egui::ComboBox::from_id_salt("fail_on")
                        .selected_text(FAIL_ON_LEVELS[*idx])
                        .show_ui(ui, |ui| {
                            for (i, lv) in FAIL_ON_LEVELS.iter().enumerate() {
                                ui.selectable_value(idx, i, *lv);
                            }
                        });
                });
                ui.horizontal(|ui| {
                    ui.label("EPSS:");
                    ui.add(egui::Slider::new(&mut s.config.epss_threshold, 0.0..=1.0).step_by(0.1));
                });
                ui.horizontal(|ui| {
                    ui.label("Containers:");
                    ui.text_edit_singleline(&mut s.config.container_images);
                });
                ui.add_space(16.0);
                ui.label(format!("{} scanners · {} formats · {} options",
                    s.config.scanners.len(), s.config.formats.len(), s.opts_count()));
                ui.add_space(8.0);
                if ui.add_sized([200.0, 40.0], egui::Button::new(
                    RichText::new("▶  START SCAN").size(18.0).color(Color32::WHITE))
                    .fill(Color32::from_rgb(0, 120, 0)))
                    .clicked()
                {
                    s.start_scan();
                    s.tab = Tab::Scan;
                }
            });
        });
    });
}

fn render_scan(ui: &mut egui::Ui, s: &mut AppState) {
    let elapsed = s.handle.as_ref().and_then(|h| h.scan_start).map(|t| t.elapsed().as_secs()).unwrap_or(0);
    let pct = if s.total > 0 { (s.completed as f64 / s.total as f64 * 100.0) as u32 } else { 0 };

    ui.vertical_centered(|ui| {
        ui.heading(RichText::new("Scanning").color(Color32::from_rgb(0, 200, 100)));
        ui.label(format!("{:02}:{:02}:{:02}  — {}/{} scans", elapsed/3600, (elapsed%3600)/60, elapsed%60, s.completed, s.total));
        let pb = egui::ProgressBar::new(pct as f32 / 100.0).desired_width(400.0).text(format!("{}%", pct));
        ui.add(pb);
        if s.started && s.handle.is_none() { ui.label(RichText::new("Scan not started yet").color(Color32::GRAY)); }
        ui.add_space(8.0);
        ui.label(&s.status);
    });
    ui.separator();
    egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
        for line in s.log_lines.iter().rev().take(100).rev() {
            let col = if line.contains("error") || line.contains("fail") { Color32::RED }
                      else if line.contains("CVE-") { Color32::YELLOW }
                      else if line.contains("ok") { Color32::GREEN } else { Color32::GRAY };
            ui.label(RichText::new(line).color(col));
        }
    });
}

fn render_results(ui: &mut egui::Ui, s: &mut AppState) {
    ui.vertical_centered(|ui| {
        ui.heading(RichText::new("Results").color(Color32::from_rgb(0, 200, 100)));
        ui.label(format!("{} scans · {} vulns", s.scan_results.len(), s.total_vulns));
    });
    ui.separator();
    ui.horizontal(|ui| { card(ui, "CRITICAL", s.total_critical, Color32::RED);
        card(ui, "HIGH", s.total_high, Color32::YELLOW);
        card(ui, "MEDIUM", s.total_medium, Color32::from_rgb(200, 100, 200));
        card(ui, "LOW", s.total_low, Color32::GREEN);
        card(ui, "TOTAL", s.total_vulns, Color32::from_rgb(0, 200, 255));
    });
    ui.separator();
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("grid").striped(true).min_col_width(80.0).show(ui, |ui| {
            ui.label("Repo"); ui.label("Scanner"); ui.label("Vulns");
            ui.label("C"); ui.label("H"); ui.label("M"); ui.label("L"); ui.label("Status");
            ui.end_row();
            for r in &s.scan_results {
                ui.label(shorten(&r.repo, 28)); ui.label(&r.scanner);
                ui.label(r.vulns.to_string());
                ui.colored_label(Color32::RED, r.critical.to_string());
                ui.colored_label(Color32::YELLOW, r.high.to_string());
                ui.colored_label(Color32::from_rgb(200, 100, 200), r.medium.to_string());
                ui.colored_label(Color32::GREEN, r.low.to_string());
                ui.label(if r.errors.is_empty() { "ok".into() } else { format!("{} err", r.errors.len()) });
                ui.end_row();
            }
        });
    });
}

fn card(ui: &mut egui::Ui, label: &str, count: usize, color: Color32) {
    egui::Frame::new()
        .fill(egui::Color32::from_black_alpha(20))
        .stroke(egui::epaint::Stroke::new(1.0, color))
        .corner_radius(8.0)
        .show(ui, |ui| {
            ui.set_min_size(egui::vec2(120.0, 60.0));
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(count.to_string()).size(24.0).color(color).strong());
                ui.label(RichText::new(label).size(10.0).color(Color32::GRAY));
            });
        });
    ui.add_space(4.0);
}

fn shorten(s: &str, max: usize) -> String {
    if s.len() > max { format!("…{}", &s[s.len()-max+1..]) } else { s.to_string() }
}

trait OptionHelpers {
    fn enabled(&self, f: &OptionField) -> bool;
    fn set(&mut self, f: &OptionField, v: bool);
}

impl OptionHelpers for scan_tui::ScanOptions {
    fn enabled(&self, f: &OptionField) -> bool {
        match f {
            OptionField::Diff => self.diff, OptionField::DepTree => self.dep_tree,
            OptionField::License => self.license, OptionField::Health => self.health,
            OptionField::Outdated => self.outdated, OptionField::DepGraph => self.dep_graph,
            OptionField::FixRecs => self.fix_recs,
            OptionField::Epss => self.epss, OptionField::RiskScore => self.risk_score,
            OptionField::Scorecard => self.scorecard, OptionField::SbomDiff => self.sbom_diff,
            OptionField::Suppressions => self.suppressions,
            OptionField::Compliance => self.compliance, OptionField::RegressionCheck => self.regression,
        }
    }
    fn set(&mut self, f: &OptionField, v: bool) {
        match f {
            OptionField::Diff => self.diff = v, OptionField::DepTree => self.dep_tree = v,
            OptionField::License => self.license = v, OptionField::Health => self.health = v,
            OptionField::Outdated => self.outdated = v, OptionField::DepGraph => self.dep_graph = v,
            OptionField::FixRecs => self.fix_recs = v,
            OptionField::Epss => self.epss = v, OptionField::RiskScore => self.risk_score = v,
            OptionField::Scorecard => self.scorecard = v, OptionField::SbomDiff => self.sbom_diff = v,
            OptionField::Suppressions => self.suppressions = v,
            OptionField::Compliance => self.compliance = v, OptionField::RegressionCheck => self.regression = v,
        }
    }
}
