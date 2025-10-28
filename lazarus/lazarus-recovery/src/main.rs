use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::io;

pub mod boot;
pub mod restore;
pub mod hardware;
pub mod partition;

enum AppState {
    StorageSelection,
    RepositoryConnection,
    SnapshotList,
}

struct App {
    state: AppState,
    storage_backends: Vec<String>,
    selected_storage: usize,
    repository_path: String,
    password: String,
    snapshots: Vec<String>,
    selected_snapshot: usize,
    input_mode: InputMode,
    current_input: String,
}

enum InputMode {
    Normal,
    EditingPath,
    EditingPassword,
}

impl Default for App {
    fn default() -> Self {
        Self {
            state: AppState::StorageSelection,
            storage_backends: vec![
                "Local Disk".to_string(),
                "S3 Storage".to_string(),
                "SSH/SFTP".to_string(),
            ],
            selected_storage: 0,
            repository_path: String::new(),
            password: String::new(),
            snapshots: Vec::new(),
            selected_snapshot: 0,
            input_mode: InputMode::Normal,
            current_input: String::new(),
        }
    }
}

impl App {
    fn next_storage(&mut self) {
        if !self.storage_backends.is_empty() {
            self.selected_storage = (self.selected_storage + 1) % self.storage_backends.len();
        }
    }

    fn previous_storage(&mut self) {
        if !self.storage_backends.is_empty() {
            if self.selected_storage > 0 {
                self.selected_storage -= 1;
            } else {
                self.selected_storage = self.storage_backends.len() - 1;
            }
        }
    }

    fn next_snapshot(&mut self) {
        if !self.snapshots.is_empty() {
            self.selected_snapshot = (self.selected_snapshot + 1) % self.snapshots.len();
        }
    }

    fn previous_snapshot(&mut self) {
        if !self.snapshots.is_empty() {
            if self.selected_snapshot > 0 {
                self.selected_snapshot -= 1;
            } else {
                self.selected_snapshot = self.snapshots.len() - 1;
            }
        }
    }
}

fn main() -> Result<(), io::Error> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run
    let app = App::default();
    let res = run_app(&mut terminal, app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("Error: {:?}", err);
    }

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, &app))?;

        if let Event::Key(key) = event::read()? {
            match app.input_mode {
                InputMode::Normal => match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Down => match app.state {
                        AppState::StorageSelection => app.next_storage(),
                        AppState::SnapshotList => app.next_snapshot(),
                        _ => {}
                    },
                    KeyCode::Up => match app.state {
                        AppState::StorageSelection => app.previous_storage(),
                        AppState::SnapshotList => app.previous_snapshot(),
                        _ => {}
                    },
                    KeyCode::Enter => match app.state {
                        AppState::StorageSelection => {
                            app.state = AppState::RepositoryConnection;
                        }
                        AppState::RepositoryConnection => {
                            if !app.repository_path.is_empty() && !app.password.is_empty() {
                                // In a real implementation, we would connect here
                                // For now, just populate some dummy snapshots
                                app.snapshots = vec![
                                    "2025-10-28T14:30:00".to_string(),
                                    "2025-10-27T14:30:00".to_string(),
                                    "2025-10-26T14:30:00".to_string(),
                                ];
                                app.state = AppState::SnapshotList;
                            }
                        }
                        AppState::SnapshotList => {
                            // Snapshot selected - would trigger restore
                        }
                    },
                    KeyCode::Char('p') if matches!(app.state, AppState::RepositoryConnection) => {
                        app.input_mode = InputMode::EditingPath;
                        app.current_input = app.repository_path.clone();
                    }
                    KeyCode::Char('w') if matches!(app.state, AppState::RepositoryConnection) => {
                        app.input_mode = InputMode::EditingPassword;
                        app.current_input.clear();
                    }
                    KeyCode::Esc => match app.state {
                        AppState::RepositoryConnection => app.state = AppState::StorageSelection,
                        AppState::SnapshotList => app.state = AppState::RepositoryConnection,
                        _ => {}
                    },
                    _ => {}
                },
                InputMode::EditingPath | InputMode::EditingPassword => match key.code {
                    KeyCode::Enter => {
                        match app.input_mode {
                            InputMode::EditingPath => {
                                app.repository_path = app.current_input.clone();
                            }
                            InputMode::EditingPassword => {
                                app.password = app.current_input.clone();
                            }
                            _ => {}
                        }
                        app.current_input.clear();
                        app.input_mode = InputMode::Normal;
                    }
                    KeyCode::Char(c) => {
                        app.current_input.push(c);
                    }
                    KeyCode::Backspace => {
                        app.current_input.pop();
                    }
                    KeyCode::Esc => {
                        app.current_input.clear();
                        app.input_mode = InputMode::Normal;
                    }
                    _ => {}
                },
            }
        }
    }
}

fn ui(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.area());

    // Title
    let title = Paragraph::new("Lazarus Bare Metal Recovery")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Main content
    match app.state {
        AppState::StorageSelection => {
            let items: Vec<ListItem> = app
                .storage_backends
                .iter()
                .enumerate()
                .map(|(i, backend)| {
                    let style = if i == app.selected_storage {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    ListItem::new(backend.as_str()).style(style)
                })
                .collect();

            let list = List::new(items)
                .block(
                    Block::default()
                        .title("Select Storage Backend")
                        .borders(Borders::ALL),
                )
                .highlight_style(Style::default().add_modifier(Modifier::BOLD));

            f.render_widget(list, chunks[1]);
        }
        AppState::RepositoryConnection => {
            let text = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("Repository Path: ", Style::default().fg(Color::Yellow)),
                    Span::raw(&app.repository_path),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Password: ", Style::default().fg(Color::Yellow)),
                    Span::raw("*".repeat(app.password.len())),
                ]),
                Line::from(""),
                Line::from("Press 'p' to edit path, 'w' to edit password, Enter to connect"),
            ];

            if matches!(app.input_mode, InputMode::EditingPath) {
                let text = vec![
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("Enter Repository Path: ", Style::default().fg(Color::Green)),
                        Span::raw(&app.current_input),
                    ]),
                ];
                let input = Paragraph::new(text).block(
                    Block::default()
                        .title("Edit Repository Path")
                        .borders(Borders::ALL),
                );
                f.render_widget(input, chunks[1]);
            } else if matches!(app.input_mode, InputMode::EditingPassword) {
                let text = vec![
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("Enter Password: ", Style::default().fg(Color::Green)),
                        Span::raw("*".repeat(app.current_input.len())),
                    ]),
                ];
                let input = Paragraph::new(text).block(
                    Block::default()
                        .title("Edit Password")
                        .borders(Borders::ALL),
                );
                f.render_widget(input, chunks[1]);
            } else {
                let para = Paragraph::new(text).block(
                    Block::default()
                        .title("Repository Connection")
                        .borders(Borders::ALL),
                );
                f.render_widget(para, chunks[1]);
            }
        }
        AppState::SnapshotList => {
            let items: Vec<ListItem> = app
                .snapshots
                .iter()
                .enumerate()
                .map(|(i, snapshot)| {
                    let style = if i == app.selected_snapshot {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    ListItem::new(snapshot.as_str()).style(style)
                })
                .collect();

            let list = List::new(items)
                .block(
                    Block::default()
                        .title("Select Snapshot to Restore")
                        .borders(Borders::ALL),
                )
                .highlight_style(Style::default().add_modifier(Modifier::BOLD));

            f.render_widget(list, chunks[1]);
        }
    }

    // Help
    let help = Paragraph::new("↑/↓: Navigate | Enter: Select | Esc: Back | q: Quit")
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(help, chunks[2]);
}
