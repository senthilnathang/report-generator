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

use app::{App, Mode};

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
        KeyCode::Char(' ') => {
            app.toggle_scanner(app.scanner_index);
        }
        KeyCode::Char('f') => {
            app.toggle_format(app.format_index);
        }
        KeyCode::Char('d') => {
            app.diff_enabled = !app.diff_enabled;
            app.status_message = if app.diff_enabled {
                "diff enabled".to_string()
            } else {
                "diff disabled".to_string()
            };
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
