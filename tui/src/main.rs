mod app;
mod tui;

use std::io;
use std::path::Path;
use std::time::Duration;

use color_eyre::eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use app::{App, FAIL_ON_LEVELS, Format, Mode, Scanner};

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

    let mut app = App::new(project_root)?;

    let res = run_app(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(LeaveAlternateScreen)?;

    if let Err(e) = &res {
        eprintln!("error: {e}");
    }

    res
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    let tick_rate = Duration::from_millis(100);

    loop {
        if app.should_quit {
            break;
        }

        terminal.draw(|f| tui::render(f, app))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match app.mode {
                        Mode::Dashboard => handle_dashboard_key(app, key.code).await,
                        Mode::Scanning => handle_scanning_key(app, key.code).await,
                        Mode::Results => handle_results_key(app, key.code).await,
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

async fn handle_dashboard_key(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('q') => {
            app.kill_child().await;
            app.should_quit = true;
        }
        KeyCode::Enter => {
            if !app.repos.is_empty() && !app.scanners.is_empty() {
                if let Err(e) = app.start_scan(Path::new(PARENT_ROOT)) {
                    app.status_message = format!("failed to start scan: {e}");
                }
            }
        }
        KeyCode::Up => {
            let n = Scanner::ALL.len();
            app.scanner_index = (app.scanner_index + n - 1) % n;
            app.status_message = format!("scanner: {}", Scanner::ALL[app.scanner_index].as_str());
        }
        KeyCode::Down => {
            let n = Scanner::ALL.len();
            app.scanner_index = (app.scanner_index + 1) % n;
            app.status_message = format!("scanner: {}", Scanner::ALL[app.scanner_index].as_str());
        }
        KeyCode::Right => {
            let n = Format::ALL.len();
            app.format_index = (app.format_index + 1) % n;
            app.status_message = format!("format: {}", Format::ALL[app.format_index].as_str());
        }
        KeyCode::Left => {
            let n = Format::ALL.len();
            app.format_index = (app.format_index + n - 1) % n;
            app.status_message = format!("format: {}", Format::ALL[app.format_index].as_str());
        }
        KeyCode::Char(' ') => {
            app.toggle_scanner(app.scanner_index);
        }
        KeyCode::Char('f') => {
            app.toggle_format(app.format_index);
        }
        KeyCode::Char('d') => {
            app.diff_enabled = !app.diff_enabled;
            app.status_message = if app.diff_enabled { "diff on" } else { "diff off" }.to_string();
        }
        KeyCode::Char('t') => {
            app.dep_tree_enabled = !app.dep_tree_enabled;
            app.status_message = if app.dep_tree_enabled { "dep-tree on" } else { "dep-tree off" }.to_string();
        }
        KeyCode::Char('l') => {
            app.license_enabled = !app.license_enabled;
            app.status_message = if app.license_enabled { "license scan on" } else { "license scan off" }.to_string();
        }
        KeyCode::Char('h') => {
            app.health_report_enabled = !app.health_report_enabled;
            app.status_message = if app.health_report_enabled { "health report on" } else { "health report off" }.to_string();
        }
        KeyCode::Char('o') => {
            app.outdated_enabled = !app.outdated_enabled;
            app.status_message = if app.outdated_enabled { "outdated check on" } else { "outdated check off" }.to_string();
        }
        KeyCode::Char('p') => {
            let n = FAIL_ON_LEVELS.len();
            app.fail_on_index = (app.fail_on_index + 1) % n;
            app.status_message = format!("fail-on: {}", FAIL_ON_LEVELS[app.fail_on_index]);
        }
        _ => {}
    }
}

async fn handle_scanning_key(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            app.kill_child().await;
            app.mode = Mode::Dashboard;
            app.status_message = "scan cancelled".to_string();
        }
        KeyCode::Up => {
            app.log_scroll = app.log_scroll.saturating_add(1);
        }
        KeyCode::Down => {
            app.log_scroll = app.log_scroll.saturating_sub(1);
        }
        _ => {}
    }
}

async fn handle_results_key(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            app.mode = Mode::Dashboard;
        }
        KeyCode::Char('q') => {
            app.kill_child().await;
            app.should_quit = true;
        }
        KeyCode::Char('r') => {
            app.mode = Mode::Dashboard;
        }
        _ => {}
    }
}
