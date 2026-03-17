use std::io;
use std::time::Duration;

use af_sdk::{AgentFortClient, SdkConfig};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

#[derive(Debug)]
struct App {
    title: String,
    status: String,
    input: String,
    messages: Vec<Message>,
    last_action: String,
    should_quit: bool,
}

impl App {
    fn new(status: String) -> Self {
        let mut messages = Vec::new();
        messages.push(Message::system(
            "Welcome to Agent TUI. Type a message and press Enter.",
        ));

        Self {
            title: "Agent Fort - Agent TUI".to_string(),
            status,
            input: String::new(),
            messages,
            last_action: "Ready".to_string(),
            should_quit: false,
        }
    }

    fn on_send(&mut self) {
        let message = self.input.trim();
        if message.is_empty() {
            return;
        }

        self.messages.push(Message::user(message.to_string()));
        self.last_action = "Captured input and queued locally".to_string();
        self.input.clear();
    }

    fn user_message_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|message| matches!(message.role, MessageRole::User))
            .count()
    }
}

#[derive(Debug)]
struct Message {
    role: MessageRole,
    content: String,
}

impl Message {
    fn system(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::System,
            content: content.into(),
        }
    }

    fn user(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::User,
            content: content.into(),
        }
    }
}

#[derive(Debug)]
enum MessageRole {
    System,
    User,
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalSession {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    fn draw(&mut self, app: &App) -> io::Result<()> {
        self.terminal.draw(|frame| draw_ui(frame, app))?;
        Ok(())
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = execute!(
            self.terminal.backend_mut(),
            cursor::Show,
            LeaveAlternateScreen
        );
        let _ = disable_raw_mode();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_status = initialize_sdk().await;
    run_tui(sdk_status)?;
    Ok(())
}

async fn initialize_sdk() -> String {
    let config = SdkConfig::default();

    if let Err(error) = AgentFortClient::initialize(config.clone()).await {
        return format!("SDK initialize failed: {error}");
    }

    let mut client = match AgentFortClient::connect(config).await {
        Ok(client) => client,
        Err(error) => return format!("SDK connect failed: {error}"),
    };

    match client.ping().await {
        Ok(response) => {
            let endpoint = client
                .endpoint_uri()
                .unwrap_or_else(|| client.configured_endpoint_uri());
            format!(
                "SDK ready: endpoint={endpoint}, daemon_instance_id={}",
                response.daemon_instance_id
            )
        }
        Err(error) => format!("SDK ping failed: {error}"),
    }
}

fn run_tui(status: String) -> io::Result<()> {
    let mut app = App::new(status);
    let mut terminal = TerminalSession::enter()?;

    loop {
        terminal.draw(&app)?;
        if app.should_quit {
            break;
        }

        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(key) => handle_key_event(key, &mut app),
                Event::Paste(text) => app.input.push_str(&text),
                _ => {}
            }
        }
    }

    Ok(())
}

fn handle_key_event(key: KeyEvent, app: &mut App) {
    if key.kind != KeyEventKind::Press {
        return;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    match key.code {
        KeyCode::Esc => app.should_quit = true,
        KeyCode::Enter => app.on_send(),
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Char(ch) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL) {
                app.input.push(ch);
            }
        }
        _ => {}
    }
}

fn draw_ui(frame: &mut Frame<'_>, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(frame.area());

    draw_header(frame, layout[0], app);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(72), Constraint::Percentage(28)])
        .split(layout[1]);
    draw_messages(frame, body[0], app);
    draw_sidebar(frame, body[1], app);

    draw_input(frame, layout[2], app);
}

fn draw_header(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let line = Line::from(vec![
        Span::styled(
            app.title.as_str(),
            Style::default()
                .fg(ratatui::style::Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  |  "),
        Span::styled("SDK ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(app.status.as_str()),
    ]);

    let widget = Paragraph::new(line).block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(widget, area);
}

fn draw_messages(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let mut lines = Vec::new();
    for message in &app.messages {
        match message.role {
            MessageRole::User => lines.push(Line::from(vec![
                Span::styled(
                    "You ",
                    Style::default().fg(ratatui::style::Color::Green).bold(),
                ),
                Span::raw(message.content.as_str()),
            ])),
            MessageRole::System => lines.push(Line::from(vec![
                Span::styled(
                    "System ",
                    Style::default()
                        .fg(ratatui::style::Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(message.content.as_str()),
            ])),
        }
    }

    let max_lines = area.height.saturating_sub(2) as usize;
    if lines.len() > max_lines {
        lines = lines.split_off(lines.len() - max_lines);
    }

    let widget = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Conversation"))
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, area);
}

fn draw_sidebar(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let info = vec![
        Line::from(vec![
            Span::styled("Mode: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Local TUI"),
        ]),
        Line::from(vec![
            Span::styled("Messages: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(app.user_message_count().to_string()),
        ]),
        Line::from(vec![Span::styled(
            "Last Action:",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(app.last_action.as_str()),
        Line::default(),
        Line::from("Shortcuts"),
        Line::from("Enter  send"),
        Line::from("Esc    quit"),
        Line::from("Ctrl+C quit"),
    ];

    let widget = Paragraph::new(info)
        .block(Block::default().borders(Borders::ALL).title("Inspector"))
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, area);
}

fn draw_input(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let prompt = format!("> {}", app.input);
    let widget = Paragraph::new(prompt.as_str())
        .block(Block::default().borders(Borders::ALL).title("Input"));
    frame.render_widget(widget, area);

    let cursor_x = area.x.saturating_add(3 + app.input.chars().count() as u16);
    let max_x = area.x + area.width.saturating_sub(2);
    frame.set_cursor_position((cursor_x.min(max_x), area.y.saturating_add(1)));
}
