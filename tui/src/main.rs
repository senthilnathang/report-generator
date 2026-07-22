mod tui;
mod app;

use std::io;
use std::path::Path;
use std::time::Duration;

use color_eyre::eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use app::{Mode, Panel, TuiApp};
use scan_tui::{FAIL_ON_LEVELS, Format, OptionField, Scanner};

const PARENT_ROOT: &str = "/opt/report-generator";

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let project_root = Path::new(PARENT_ROOT);
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = TuiApp::new(project_root)?;
    let res = run_app(&mut terminal, &mut app).await;
    disable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(LeaveAlternateScreen)?;
    if let Err(e) = &res { eprintln!("error: {e}"); }
    res
}

async fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut TuiApp) -> Result<()> {
    let tick = Duration::from_millis(100);
    loop {
        if app.should_quit { break; }
        terminal.draw(|f| tui::render(f, app))?;
        if event::poll(tick)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match app.mode {
                        Mode::Dashboard => handle_dashboard_key(app, key.code),
                        Mode::EditingContainer => handle_editing_key(app, key.code),
                        Mode::Scanning => handle_scanning_key(app, key.code),
                        Mode::Results => handle_results_key(app, key.code),
                    }
                }
            }
        }
        if app.mode == Mode::Scanning {
            app.poll_logs();
            app.poll_child().await;
        }
    }
    Ok(())
}

fn handle_dashboard_key(app: &mut TuiApp, key: KeyCode) {
    match key {
        KeyCode::Char('q') => { app.should_quit = true; }
        KeyCode::Enter => {
            if !app.repos.is_empty() && !app.scan.scanners.is_empty() {
                if let Err(e) = app.start_scan(Path::new(PARENT_ROOT)) {
                    app.status_message = format!("failed: {e}");
                }
            }
        }
        KeyCode::Tab => {
            app.panel_focus = match app.panel_focus {
                Panel::Scanners => Panel::Formats,
                Panel::Formats => Panel::Options,
                Panel::Options => Panel::Scanners,
            };
        }
        KeyCode::BackTab => {
            app.panel_focus = match app.panel_focus {
                Panel::Scanners => Panel::Options,
                Panel::Formats => Panel::Scanners,
                Panel::Options => Panel::Formats,
            };
        }
        KeyCode::Up => match app.panel_focus {
            Panel::Scanners => { let n = Scanner::ALL.len(); app.scanner_cursor = (app.scanner_cursor + n - 1) % n; }
            Panel::Formats => { let n = Format::ALL.len(); app.format_cursor = (app.format_cursor + n - 1) % n; }
            Panel::Options => { let n = OptionField::ALL.len(); app.option_cursor = (app.option_cursor + n - 1) % n; }
        },
        KeyCode::Down => match app.panel_focus {
            Panel::Scanners => { let n = Scanner::ALL.len(); app.scanner_cursor = (app.scanner_cursor + 1) % n; }
            Panel::Formats => { let n = Format::ALL.len(); app.format_cursor = (app.format_cursor + 1) % n; }
            Panel::Options => { let n = OptionField::ALL.len(); app.option_cursor = (app.option_cursor + 1) % n; }
        },
        KeyCode::Char(' ') => match app.panel_focus {
            Panel::Scanners => { app.toggle_scanner(app.scanner_cursor); }
            Panel::Formats => { app.toggle_format(app.format_cursor); }
            Panel::Options => { app.toggle_option(OptionField::ALL[app.option_cursor]); }
        },
        KeyCode::Char('f') | KeyCode::Char('F') => {
            let n = FAIL_ON_LEVELS.len();
            app.scan.fail_on_index = (app.scan.fail_on_index + 1) % n;
            app.status_message = format!("fail-on: {}", FAIL_ON_LEVELS[app.scan.fail_on_index]);
        }
        KeyCode::Char('e') | KeyCode::Char('E') => {
            let t = [0.0, 0.1, 0.3, 0.5, 0.7, 0.9];
            let i = t.iter().position(|x| (*x - app.scan.epss_threshold).abs() < 0.01).unwrap_or(3);
            app.scan.epss_threshold = t[(i + 1) % t.len()];
            app.status_message = format!("epss: {:.1}", app.scan.epss_threshold);
        }
        KeyCode::Char('i') | KeyCode::Char('I') => { app.mode = Mode::EditingContainer; }
        _ => {}
    }
}

fn handle_editing_key(app: &mut TuiApp, key: KeyCode) {
    match key {
        KeyCode::Esc => { app.mode = Mode::Dashboard; app.status_message = String::new(); }
        KeyCode::Enter => {
            app.mode = Mode::Dashboard;
            app.scan.container_images = app.scan.container_images.trim().to_string();
            let n = if app.scan.container_images.is_empty() { 0 } else { app.scan.container_images.split_whitespace().count() };
            app.status_message = format!("containers: {n}");
        }
        KeyCode::Backspace => { app.scan.container_images.pop(); }
        KeyCode::Char(c) => { app.scan.container_images.push(c); }
        _ => {}
    }
}

fn handle_scanning_key(app: &mut TuiApp, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            let old_handle = app.handle.take();
            app.mode = Mode::Dashboard;
            app.status_message = "cancelled".to_string();
            if let Some(h) = old_handle {
                if let Some(ref child) = h.child {
                    if let Some(pid) = child.id() {
                        let _ = std::process::Command::new("kill").args(["-9", &pid.to_string()]).output();
                    }
                }
            }
        }
        KeyCode::Up => { app.log_scroll = app.log_scroll.saturating_add(1); }
        KeyCode::Down => { app.log_scroll = app.log_scroll.saturating_sub(1); }
        _ => {}
    }
}

fn handle_results_key(app: &mut TuiApp, key: KeyCode) {
    match key {
        KeyCode::Esc => { app.mode = Mode::Dashboard; }
        KeyCode::Char('q') => { app.should_quit = true; }
        KeyCode::Char('r') => { app.mode = Mode::Dashboard; }
        _ => {}
    }
}
