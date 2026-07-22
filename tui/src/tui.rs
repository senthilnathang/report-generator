use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Gauge, Paragraph, Row, Table,
};
use ratatui::Frame;

use crate::app::{Mode, Panel, TuiApp};
use scan_tui::{FAIL_ON_LEVELS, Format, OptionField, Scanner};

// ── colour aliases ────────────────────────────────────────────
const CYAN: Color = Color::Cyan;
const BLUE: Color = Color::Blue;
const GREEN: Color = Color::Green;
const YELLOW: Color = Color::Yellow;
const RED: Color = Color::Red;
const MAGENTA: Color = Color::Magenta;
const DG: Color = Color::DarkGray;
const WHITE: Color = Color::White;
const RESET: Color = Color::Reset;

fn panel_style(title: String, focused: bool) -> Block<'static> {
    let (_col, border) = if focused {
        (CYAN, BorderType::Thick)
    } else {
        (DG, BorderType::Rounded)
    };
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(border)
        .border_style(Style::default().fg(if focused { CYAN } else { DG }))
}

// ── main dispatch ─────────────────────────────────────────────
pub fn render(f: &mut Frame, app: &TuiApp) {
    match app.mode {
        Mode::Dashboard | Mode::EditingContainer => render_dashboard(f, app),
        Mode::Scanning => render_scanning(f, app),
        Mode::Results => render_results(f, app),
    }
}

// ═══════════════════════  DASHBOARD  ═══════════════════════════
fn render_dashboard(f: &mut Frame, app: &TuiApp) {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(12), Constraint::Length(2), Constraint::Length(1)])
        .split(f.area());
    render_header(f, app, v[0]);
    render_body(f, app, v[1]);
    render_config_bar(f, app, v[2]);
    render_footer(f, app, v[3]);
}

// ── header ────────────────────────────────────────────────────
fn render_header(f: &mut Frame, app: &TuiApp, area: Rect) {
    let parts: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(" ⚡ scan-tui ", Style::default().fg(CYAN).bold()),
            Span::styled(" v1.0 ", Style::default().fg(DG)),
            Span::raw("  "),
            Span::styled(format!("{} repos", app.repos.len()), Style::default().fg(WHITE)),
            Span::raw(" · "),
            Span::styled(format!("{} scanners", app.scan.scanners.len()), Style::default().fg(GREEN)),
            Span::raw(" · "),
            Span::styled(format!("{} formats", app.scan.formats.len()), Style::default().fg(BLUE)),
            Span::raw(" · "),
            Span::styled(format!("{} options", app.options_enabled_count()), Style::default().fg(YELLOW)),
        ]),
    ];
    let block = Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(DG));
    f.render_widget(Paragraph::new(Text::from(parts)).block(block), area);
}

// ── 3-column body ─────────────────────────────────────────────
fn render_body(f: &mut Frame, app: &TuiApp, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(35, 100), Constraint::Ratio(38, 100), Constraint::Ratio(27, 100)])
        .split(area);
    let left_cols = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(7), Constraint::Length(7)])
        .split(cols[0]);
    render_scanner_panel(f, app, left_cols[0]);
    render_format_panel(f, app, left_cols[1]);
    render_options_panel(f, app, cols[1]);
    render_info_panel(f, app, cols[2]);
}

// ── scanners ──────────────────────────────────────────────────
fn render_scanner_panel(f: &mut Frame, app: &TuiApp, area: Rect) {
    let focused = app.panel_focus == Panel::Scanners;
    let mut lines = Vec::new();
    for (i, s) in Scanner::ALL.iter().enumerate() {
        let checked = app.scan.scanners.contains(s);
        let is_cursor = focused && i == app.scanner_cursor;
        let (fg, prefix) = if checked { (GREEN, "◉") } else { (DG, "○") };
        let bg = if is_cursor { Some(CYAN) } else { None };
        let mut sty = Style::default().fg(fg);
        if checked { sty = sty.bold(); }
        if let Some(c) = bg { sty = sty.bg(c).fg(RESET); }
        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", prefix), sty),
            Span::styled(s.as_str(), sty),
        ]));
    }
    let block = panel_style(format!(" Scanners ({}/{}) ", app.scan.scanners.len(), Scanner::ALL.len()), focused);
    f.render_widget(Paragraph::new(Text::from(lines)).block(block), area);
}

// ── formats ───────────────────────────────────────────────────
fn render_format_panel(f: &mut Frame, app: &TuiApp, area: Rect) {
    let focused = app.panel_focus == Panel::Formats;
    let mut lines = Vec::new();
    for (i, fmt) in Format::ALL.iter().enumerate() {
        let checked = app.scan.formats.contains(fmt);
        let is_cursor = focused && i == app.format_cursor;
        let (fg, prefix) = if checked { (BLUE, "◉") } else { (DG, "○") };
        let mut sty = Style::default().fg(fg);
        if checked { sty = sty.bold(); }
        if is_cursor { sty = sty.bg(CYAN).fg(RESET); }
        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", prefix), sty),
            Span::styled(fmt.as_str(), sty),
        ]));
    }
    let block = panel_style(format!(" Formats ({}/{}) ", app.scan.formats.len(), Format::ALL.len()), focused);
    f.render_widget(Paragraph::new(Text::from(lines)).block(block), area);
}

// ── options ───────────────────────────────────────────────────
fn render_options_panel(f: &mut Frame, app: &TuiApp, area: Rect) {
    let focused = app.panel_focus == Panel::Options;
    let mut lines = Vec::new();
    let mut cat = "";
    for (i, opt) in OptionField::ALL.iter().enumerate() {
        let c = opt.category();
        if c != cat {
            cat = c;
            lines.push(Line::from(
                Span::styled(c, Style::default().fg(CYAN).dim()),
            ));
        }
        let enabled = app.is_option_enabled(*opt);
        let is_cursor = focused && i == app.option_cursor;
        let (fg, prefix) = if enabled { (GREEN, "◉") } else { (DG, "○") };
        let mut sty = Style::default().fg(fg);
        if enabled { sty = sty.bold(); }
        if is_cursor { sty = sty.bg(CYAN).fg(RESET); }
        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", prefix), sty),
            Span::styled(opt.label(), sty),
        ]));
    }
    let count = app.options_enabled_count();
    let block = panel_style(format!(" Options ({count}/{}) ", OptionField::ALL.len()), focused);
    f.render_widget(Paragraph::new(Text::from(lines)).block(block), area);
}

// ── info panel ────────────────────────────────────────────────
fn render_info_panel(f: &mut Frame, app: &TuiApp, area: Rect) {
    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Length(6), Constraint::Min(1)])
        .split(area);

    // ── config summary card ──
    let level = FAIL_ON_LEVELS[app.scan.fail_on_index];
    let lvl_col = match app.scan.fail_on_index {
        1 => RED, 2 => YELLOW, 3 => MAGENTA, 4 => GREEN, _ => DG,
    };
    let container = if app.scan.container_images.is_empty() { "(none)".into() } else { app.scan.container_images.chars().take(20).collect::<String>() };
    let cfg_lines = vec![
        Line::from(vec![Span::styled(" fail-on    ", Style::default().fg(DG)), Span::styled(level, Style::default().fg(lvl_col).bold())]),
        Line::from(vec![Span::styled(" epss thr.  ", Style::default().fg(DG)), Span::styled(format!("{:.1}", app.scan.epss_threshold), Style::default().fg(YELLOW))]),
        Line::from(vec![Span::styled(" containers ", Style::default().fg(DG)), Span::styled(container, Style::default().fg(if app.scan.container_images.is_empty() { DG } else { GREEN }))]),
        Line::from(""),
        Line::from(vec![Span::styled(" ▶  Enter  ", Style::default().fg(CYAN).bold()), Span::styled("start scan", Style::default().fg(DG))]),
    ];
    f.render_widget(
        Paragraph::new(Text::from(cfg_lines)).block(panel_style(" Config ".into(), false)),
        inner[0],
    );

    // ── keybinds card ──
    let kb_lines = vec![
        Line::from(vec![Span::styled(" Tab  ", Style::default().fg(CYAN)), Span::styled("focus panel", Style::default().fg(DG))]),
        Line::from(vec![Span::styled(" ↑↓   ", Style::default().fg(CYAN)), Span::styled("navigate", Style::default().fg(DG))]),
        Line::from(vec![Span::styled(" Space", Style::default().fg(CYAN)), Span::styled("toggle item", Style::default().fg(DG))]),
        Line::from(vec![Span::styled(" F    ", Style::default().fg(CYAN)), Span::styled("fail-on", Style::default().fg(DG))]),
        Line::from(vec![Span::styled(" E    ", Style::default().fg(CYAN)), Span::styled("epss threshold", Style::default().fg(DG))]),
        Line::from(vec![Span::styled(" I    ", Style::default().fg(CYAN)), Span::styled("container img", Style::default().fg(DG))]),
    ];
    f.render_widget(
        Paragraph::new(Text::from(kb_lines)).block(panel_style(" Keys ".into(), false)),
        inner[1],
    );

    // ── status ──
    if !app.status_message.is_empty() {
        let col = if app.status_message.contains("fail") { RED } else { WHITE };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(&app.status_message, Style::default().fg(col))))
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(DG)).border_type(BorderType::Rounded)),
            inner[2],
        );
    }
}

// ── config bar ────────────────────────────────────────────────
fn render_config_bar(f: &mut Frame, app: &TuiApp, area: Rect) {
    let level = FAIL_ON_LEVELS[app.scan.fail_on_index];
    let lvl_col = match app.scan.fail_on_index { 1 => RED, 2 => YELLOW, 3 => MAGENTA, 4 => GREEN, _ => DG };
    let container = if app.scan.container_images.is_empty() { "none".into() } else { app.scan.container_images.clone() };
    let edit_hint = if app.mode == Mode::EditingContainer {
        Line::from(Span::styled(" typing containers — Enter done, Esc cancel ", Style::default().fg(YELLOW).bg(DG)))
    } else {
        Line::from(vec![
            Span::styled(" F", Style::default().fg(CYAN).bold()), Span::raw(" fail-on "),
            Span::styled("E", Style::default().fg(CYAN).bold()), Span::raw(" epss "),
            Span::styled("I", Style::default().fg(CYAN).bold()), Span::raw(" containers "),
        ])
    };

    let bar = Line::from(vec![
        Span::raw(" "),
        Span::styled("fail-on", Style::default().fg(DG)),
        Span::raw(" "),
        Span::styled(format!("[{}]", level), Style::default().fg(lvl_col).bold()),
        Span::raw(" │ "),
        Span::styled("epss", Style::default().fg(DG)),
        Span::raw(" "),
        Span::styled(format!("[{:.1}]", app.scan.epss_threshold), Style::default().fg(YELLOW)),
        Span::raw(" │ "),
        Span::styled("containers", Style::default().fg(DG)),
        Span::raw(" "),
        Span::styled(format!("[{}]", container), Style::default().fg(if app.scan.container_images.is_empty() { DG } else { GREEN })),
    ]);

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);
    f.render_widget(Paragraph::new(bar).block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(DG))), inner[0]);
    f.render_widget(Paragraph::new(edit_hint).style(Style::default().fg(DG)), inner[1]);
}

// ── footer ────────────────────────────────────────────────────
fn render_footer(f: &mut Frame, app: &TuiApp, area: Rect) {
    let text = if app.repos.is_empty() {
        " no repositories loaded ".into()
    } else {
        format!(" Enter start scan → {} targets × {} scanners = {} scans ",
            app.repos.len(), app.scan.scanners.len(), app.repos.len() * app.scan.scanners.len())
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(text, Style::default().fg(DG))))
            .style(Style::default().bg(DG).fg(WHITE)),
        area,
    );
}

// ═══════════════════════  SCANNING  ═══════════════════════════
fn render_scanning(f: &mut Frame, app: &TuiApp) {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(1), Constraint::Length(2)])
        .split(f.area());

    let elapsed = app.handle.as_ref().and_then(|h| h.scan_start).map(|s| s.elapsed().as_secs()).unwrap_or(0);
    let hrs = elapsed / 3600; let mins = (elapsed % 3600) / 60; let secs = elapsed % 60;
    let progress_pct = if app.total_targets > 0 {
        (app.completed_targets as f64 / app.total_targets as f64 * 100.0) as u16
    } else { 0 };

    // header
    let header = vec![
        Line::from(vec![
            Span::styled(" ● scanning ", Style::default().fg(GREEN).bold()),
            Span::raw(format!(" {:02}:{:02}:{:02}", hrs, mins, secs)),
            Span::raw("  "),
            Span::styled(format!("{}/{}", app.completed_targets, app.total_targets), Style::default().fg(CYAN)),
            Span::raw(" scans"),
            Span::raw("  "),
            Span::styled(format!("{} vulns", app.log_lines.iter().filter(|l| l.contains("vulns")).count()), Style::default().fg(YELLOW)),
        ]),
    ];
    f.render_widget(
        Paragraph::new(Text::from(header)).block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(DG))),
        v[0],
    );

    // log
    let max_lines = v[1].height.saturating_sub(2) as usize;
    let total = app.log_lines.len();
    let scroll = app.log_scroll.min(total.saturating_sub(1));
    let end = total.saturating_sub(scroll);
    let start = end.saturating_sub(max_lines);
    let log_text: Vec<Line> = app.log_lines[start..end].iter().map(|l| {
        let (fg, prefix) = if l.contains("error") || l.contains("Error") || l.contains("fail") { (RED, "✗ ") }
            else if l.contains("vuln") || l.contains("CVE-") { (YELLOW, "! ") }
            else if l.contains("scanning") || l.contains("Scanning") || l.contains("ok") { (GREEN, "✓ ") }
            else { (DG, "  ") };
        Line::from(Span::styled(format!("{}{}", prefix, l), Style::default().fg(fg)))
    }).collect();
    f.render_widget(
        Paragraph::new(Text::from(log_text)).block(
            Block::default().borders(Borders::ALL).border_style(Style::default().fg(DG)).border_type(BorderType::Rounded)
                .title(format!(" output ({} lines) ", total)),
        ),
        v[1],
    );

    // progress bar
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(DG)).border_type(BorderType::Rounded))
        .gauge_style(Style::default().fg(CYAN).bg(DG))
        .percent(progress_pct)
        .label(format!(" {}% — {}/{} scans ", progress_pct, app.completed_targets, app.total_targets));
    f.render_widget(gauge, v[2]);
}

// ═══════════════════════  RESULTS  ════════════════════════════
fn render_results(f: &mut Frame, app: &TuiApp) {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Length(3), Constraint::Min(1), Constraint::Length(1)])
        .split(f.area());

    // header
    let header = Line::from(vec![
        Span::styled(" ✓ scan complete ", Style::default().fg(GREEN).bold()),
        Span::raw(format!("  {} scans · {} vulns", app.scan_results.len(), app.total_vulns)),
    ]);
    f.render_widget(
        Paragraph::new(header).block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(DG))),
        v[0],
    );

    render_severity_cards(f, app, v[1]);
    render_vuln_table(f, app, v[2]);

    // footer
    let ft = Line::from(vec![
        Span::styled(" R ", Style::default().fg(CYAN).bold()), Span::raw(" re-run  "),
        Span::styled(" Esc ", Style::default().fg(CYAN).bold()), Span::raw(" dashboard  "),
        Span::styled(" Q ", Style::default().fg(CYAN).bold()), Span::raw(" quit"),
    ]);
    f.render_widget(
        Paragraph::new(ft).style(Style::default().bg(DG).fg(WHITE)),
        v[3],
    );
}

fn render_severity_cards(f: &mut Frame, app: &TuiApp, area: Rect) {
    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 5), Constraint::Ratio(1, 5), Constraint::Ratio(1, 5),
            Constraint::Ratio(1, 5), Constraint::Ratio(1, 5),
        ])
        .split(area);

    let data = [
        ("CRITICAL", app.total_critical, RED),
        ("HIGH", app.total_high, YELLOW),
        ("MEDIUM", app.total_medium, MAGENTA),
        ("LOW", app.total_low, GREEN),
        ("TOTAL", app.total_vulns, CYAN),
    ];

    for (i, (label, count, col)) in data.iter().enumerate() {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(*col))
            .border_type(BorderType::Rounded);
        let text = Text::from(vec![
            Line::from(Span::styled(count.to_string(), Style::default().fg(*col).bold())),
            Line::from(Span::styled(*label, Style::default().fg(DG))),
        ]);
        f.render_widget(Paragraph::new(text).block(block).centered(), cards[i]);
    }
}

fn render_vuln_table(f: &mut Frame, app: &TuiApp, area: Rect) {
    let col_widths = vec![
        Constraint::Percentage(25), Constraint::Percentage(12), Constraint::Percentage(8),
        Constraint::Percentage(8), Constraint::Percentage(8), Constraint::Percentage(8),
        Constraint::Percentage(8), Constraint::Percentage(10),
    ];

    let header_cells = ["Repository", "Scanner", "Vulns", "Crit", "High", "Med", "Low", "Status"]
        .iter().map(|h| Cell::from(*h).style(Style::default().fg(CYAN).bold()));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app.scan_results.iter().map(|r| {
        let repo = if r.repo.len() > 28 { format!("…{}", &r.repo[r.repo.len()-27..]) } else { r.repo.clone() };
        let status = if r.errors.is_empty() { "ok".into() } else { format!("{} err", r.errors.len()) };
        Row::new(vec![
            Cell::from(repo), Cell::from(r.scanner.clone()),
            Cell::from(r.vulns.to_string()),
            Cell::from(r.critical.to_string()).style(Style::default().fg(RED).bold()),
            Cell::from(r.high.to_string()).style(Style::default().fg(YELLOW).bold()),
            Cell::from(r.medium.to_string()).style(Style::default().fg(MAGENTA)),
            Cell::from(r.low.to_string()).style(Style::default().fg(GREEN)),
            Cell::from(status).style(Style::default().fg(if r.errors.is_empty() { GREEN } else { RED })),
        ])
    }).collect();

    f.render_widget(
        Table::new(rows, col_widths).header(header)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(DG)).border_type(BorderType::Rounded)
                .title(format!(" {} scans ", app.scan_results.len()))),
        area,
    );
}
