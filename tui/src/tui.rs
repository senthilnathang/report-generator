use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table,
};
use ratatui::Frame;

use crate::app::{App, FAIL_ON_LEVELS, Format, Mode, Scanner};

pub fn render(f: &mut Frame, app: &App) {
    match app.mode {
        Mode::Dashboard => render_dashboard(f, app),
        Mode::Scanning => render_scanning(f, app),
        Mode::Results => render_results(f, app),
    }
}

fn render_dashboard(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(6),
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(f.area());

    let title = Paragraph::new(Line::from(" Vuln Scanner TUI ").centered())
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
    f.render_widget(title, chunks[0]);

    render_repo_list(f, app, chunks[1]);
    render_scanner_panel(f, app, chunks[2]);
    render_format_panel(f, app, chunks[3]);
    render_options_panel(f, app, chunks[4]);
    render_footer(f, app, chunks[5]);
}

fn render_repo_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .repos
        .iter()
        .map(|r| {
            ListItem::new(Line::from(vec![Span::raw(format!("  {r}"))]))
                .style(Style::default().fg(Color::White))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Repositories ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    f.render_widget(list, area);
}

fn render_scanner_panel(f: &mut Frame, app: &App, area: Rect) {
    let mut cells = vec![];
    for (i, scanner) in Scanner::ALL.iter().enumerate() {
        let checked = app.scanners.contains(scanner);
        let prefix = if checked { "[x]" } else { "[ ]" };
        let selected = i == app.scanner_index;
        let mut style = if checked {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        if selected {
            style = style.bg(Color::DarkGray);
        }
        cells.push(Paragraph::new(Line::from(vec![
            Span::styled(format!("{prefix} {} ", scanner.as_str()), style),
        ])));
    }

    let inner = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![Constraint::Ratio(1, 3); 3])
        .split(area);
    for (i, cell) in cells.into_iter().enumerate() {
        f.render_widget(cell, inner[i]);
    }

    let block = Block::default()
        .title(" Scanners (↑↓ navigate, SPACE toggle) ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);
    f.render_widget(block, area);
}

fn render_format_panel(f: &mut Frame, app: &App, area: Rect) {
    let mut cells = vec![];
    for (i, fmt) in Format::ALL.iter().enumerate() {
        let checked = app.formats.contains(fmt);
        let prefix = if checked { "[x]" } else { "[ ]" };
        let selected = i == app.format_index;
        let mut style = if checked {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        if selected {
            style = style.bg(Color::DarkGray);
        }
        cells.push(Paragraph::new(Line::from(vec![
            Span::styled(format!("{prefix} {} ", fmt.as_str()), style),
        ])));
    }

    let n = Format::ALL.len();
    let inner = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![Constraint::Ratio(1, n as u32); n])
        .split(area);
    for (i, cell) in cells.into_iter().enumerate() {
        f.render_widget(cell, inner[i]);
    }

    let block = Block::default()
        .title(" Output Formats (← → navigate, F toggle) ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);
    f.render_widget(block, area);
}

fn render_options_panel(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .margin(1)
        .split(area);

    let opts = [
        ("D", app.diff_enabled, "diff"),
        ("T", app.dep_tree_enabled, "dep-tree"),
        ("L", app.license_enabled, "license"),
        ("H", app.health_report_enabled, "health"),
        ("O", app.outdated_enabled, "outdated"),
    ];
    let inner = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![Constraint::Ratio(1, 5); 5])
        .split(chunks[0]);
    for (i, (key, enabled, label)) in opts.iter().enumerate() {
        let prefix = if *enabled { "[x]" } else { "[ ]" };
        let style = if *enabled {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let p = Paragraph::new(Line::from(vec![
            Span::styled(format!(" {prefix} {label} "), style),
            Span::styled(format!("({key})"), Style::default().fg(Color::Cyan)),
        ]));
        f.render_widget(p, inner[i]);
    }

    let level = FAIL_ON_LEVELS[app.fail_on_index];
    let fail_style = if app.fail_on_index > 0 {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let fail_text = Line::from(vec![
        Span::styled(" Fail-on: ", Style::default().fg(Color::Cyan)),
        Span::styled(format!("[{level}]"), fail_style),
        Span::styled(" (P cycle) ", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(fail_text), chunks[1]);

    let block = Block::default()
        .title(" Scan Options ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);
    f.render_widget(block, area);
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let text = match app.mode {
        Mode::Dashboard => {
            let sc: Vec<&str> = app.scanners.iter().map(|s| s.as_str()).collect();
            let fm: Vec<&str> = app.formats.iter().map(|f| f.as_str()).collect();
            format!(
                " Enter: Scan ({} repos, sc: {}, fmt: {}) | SPACE: scanner | F: format | DTLHO: toggles | Q: Quit ",
                app.repos.len(),
                sc.join(","),
                fm.join(","),
            )
        }
        Mode::Scanning => " Esc: Cancel scan | Up/Down: Scroll log ".to_string(),
        Mode::Results => " R: Re-run | Esc: Dashboard | Q: Quit ".to_string(),
    };
    let footer = Paragraph::new(Line::from(text).centered())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
    f.render_widget(footer, area);
}

fn render_scanning(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1), Constraint::Length(3)])
        .split(f.area());

    let title = Paragraph::new(Line::from(" Scanning in Progress... ").centered())
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
    f.render_widget(title, chunks[0]);

    let max_lines = f.area().height.saturating_sub(10) as usize;
    let total = app.log_lines.len();
    let scroll = app.log_scroll.min(total.saturating_sub(1));
    let end = total.saturating_sub(scroll);
    let start = end.saturating_sub(max_lines);
    let log_text: Vec<Line> = app.log_lines[start..end]
        .iter()
        .map(|l| Line::from(Span::raw(l)))
        .collect();
    let log = Paragraph::new(Text::from(log_text))
        .block(
            Block::default()
                .title(format!(" Live Output ({} lines, scroll={}) ", total, scroll))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(log, chunks[1]);

    let pct = if app.total_targets > 0 {
        (app.completed_targets * 100 / app.total_targets) as u16
    } else {
        0
    };
    let progress = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .gauge_style(Style::default().fg(Color::Cyan))
        .percent(pct)
        .label(format!("{}/{}", app.completed_targets, app.total_targets));
    f.render_widget(progress, chunks[2]);
}

fn render_results(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(f.area());

    let title = Paragraph::new(Line::from(" Scan Results ").centered())
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
    f.render_widget(title, chunks[0]);

    render_summary(f, app, chunks[1]);
    render_vuln_table(f, app, chunks[2]);
    render_footer(f, app, chunks[3]);
}

fn render_summary(f: &mut Frame, app: &App, area: Rect) {
    let text = format!(
        " CRITICAL: {}  HIGH: {}  MEDIUM: {}  LOW: {}  TOTAL: {}  scans: {}",
        app.total_critical,
        app.total_high,
        app.total_medium,
        app.total_low,
        app.total_vulns,
        app.scan_results.len(),
    );
    let summary = Paragraph::new(Line::from(text))
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .title(" Summary ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
    f.render_widget(summary, area);
}

fn render_vuln_table(f: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["Repo", "Scanner", "Vulns", "Crit", "High", "Med", "Low", "Errors"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .scan_results
        .iter()
        .map(|r| {
            let repo_short = if r.repo.len() > 30 {
                format!("...{}", &r.repo[r.repo.len() - 27..])
            } else {
                r.repo.clone()
            };
            let err_str = if r.errors.is_empty() {
                "ok".to_string()
            } else {
                r.errors.len().to_string()
            };
            let cells = vec![
                Cell::from(repo_short),
                Cell::from(r.scanner.clone()),
                Cell::from(r.vulns.to_string()),
                Cell::from(r.critical.to_string()).style(Style::default().fg(Color::Red)),
                Cell::from(r.high.to_string()).style(Style::default().fg(Color::Yellow)),
                Cell::from(r.medium.to_string()).style(Style::default().fg(Color::Magenta)),
                Cell::from(r.low.to_string()).style(Style::default().fg(Color::Green)),
                Cell::from(err_str),
            ];
            Row::new(cells)
        })
        .collect();

    let table = Table::new(rows, vec![
        Constraint::Percentage(30),
        Constraint::Percentage(10),
        Constraint::Percentage(8),
        Constraint::Percentage(8),
        Constraint::Percentage(8),
        Constraint::Percentage(8),
        Constraint::Percentage(8),
        Constraint::Percentage(8),
    ])
    .header(header)
    .block(
        Block::default()
            .title(" Vulnerabilities ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded),
    );
    f.render_widget(table, area);
}
