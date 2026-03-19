use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use af_rpc_proto::ApprovalDecision as RpcApprovalDecision;
use af_rpc_proto::ApprovalStatus as RpcApprovalStatus;
use af_rpc_proto::task_outcome::Outcome as RpcTaskOutcome;
use af_sdk::{AgentFortClient, BootstrapConfig, SdkConfig, SdkError, TaskOperation};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use prost_types::{Struct as ProstStruct, Value as ProstValue, value::Kind as ProstValueKind};
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
    conversation_scroll: u16,
    scroll_to_bottom: bool,
    last_action: String,
    sdk_ready: bool,
    should_quit: bool,
}

impl App {
    fn new(status: String, sdk_ready: bool) -> Self {
        let mut messages = Vec::new();
        messages.push(Message::system(
            "Type a shell command and press Enter to run CreateSession/CreateTask flow. If approval is required, reply with yes/no.",
        ));

        Self {
            title: "Agent Fort - Agent TUI".to_string(),
            status,
            input: String::new(),
            messages,
            conversation_scroll: 0,
            scroll_to_bottom: true,
            last_action: "Ready".to_string(),
            sdk_ready,
            should_quit: false,
        }
    }

    fn on_send(&mut self, executor: Option<&mut CommandExecutor>) {
        let input = self.input.trim().to_string();
        if input.is_empty() {
            return;
        }

        self.messages.push(Message::user(input.clone()));
        self.input.clear();

        match executor {
            Some(executor) => {
                if executor.has_pending_approval() {
                    let Some(approve) = parse_approval_response(&input) else {
                        self.messages.push(Message::system(
                            "A task is waiting for approval. Reply with yes or no.",
                        ));
                        self.last_action = "Waiting for yes/no approval response".to_string();
                        self.request_scroll_to_bottom();
                        return;
                    };

                    self.last_action = "Responding to approval".to_string();
                    match executor.respond_pending_approval(approve) {
                        Ok(message) => {
                            self.messages.push(Message::system(message));
                            if executor.has_pending_approval() {
                                self.messages.push(Message::system(
                                    "A task is waiting for approval. Reply with yes or no.",
                                ));
                                self.last_action = "Waiting for approval response".to_string();
                            } else {
                                self.last_action = "Approval handled".to_string();
                            }
                        }
                        Err(error) => {
                            self.messages.push(Message::system(format!(
                                "Approval response failed: {error}"
                            )));
                            self.last_action = "Approval response failed".to_string();
                        }
                    }
                } else {
                    self.last_action = "Running session/task pipeline".to_string();
                    match executor.run_command(&input) {
                        Ok(stdout) => {
                            self.messages.push(Message::system(stdout));
                            if executor.has_pending_approval() {
                                self.messages.push(Message::system(
                                    "A task is waiting for approval. Reply with yes or no.",
                                ));
                                self.last_action = "Waiting for approval response".to_string();
                            } else {
                                self.last_action = "Task finished".to_string();
                            }
                        }
                        Err(error) => {
                            self.messages
                                .push(Message::system(format!("Execution failed: {error}")));
                            self.last_action = "Task failed".to_string();
                        }
                    }
                }
            }
            None => {
                self.messages.push(Message::system(
                    "SDK is unavailable; check startup status and policy path.",
                ));
                self.last_action = "SDK unavailable".to_string();
            }
        }

        self.request_scroll_to_bottom();
    }

    fn user_message_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|message| matches!(message.role, MessageRole::User))
            .count()
    }

    fn request_scroll_to_bottom(&mut self) {
        self.scroll_to_bottom = true;
    }

    fn scroll_conversation_up(&mut self, lines: u16) {
        self.scroll_to_bottom = false;
        self.conversation_scroll = self.conversation_scroll.saturating_sub(lines);
    }

    fn scroll_conversation_down(&mut self, lines: u16) {
        self.scroll_to_bottom = false;
        self.conversation_scroll = self.conversation_scroll.saturating_add(lines);
    }

    fn scroll_conversation_to_top(&mut self) {
        self.scroll_to_bottom = false;
        self.conversation_scroll = 0;
    }

    fn scroll_conversation_to_bottom(&mut self) {
        self.scroll_to_bottom = true;
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

#[derive(Debug, Clone)]
struct ExampleSdkParams {
    agent_name: String,
    bootstrap_binary_url: String,
    install_root: PathBuf,
    bundle_manifest: String,
    endpoint: Option<String>,
    policy_dir: PathBuf,
    store_path: PathBuf,
}

impl ExampleSdkParams {
    fn fixed() -> Self {
        let root = agent_tui_root();
        let workspace = workspace_root();
        Self {
            agent_name: "agent-tui".to_string(),
            bootstrap_binary_url: workspace
                .join("target")
                .join("debug")
                .join("af-bootstrap")
                .display()
                .to_string(),
            install_root: root.join("runtime").join("install-root"),
            bundle_manifest: workspace
                .join("assets")
                .join("agent-fortd")
                .join("linux-x86_64")
                .join("manifest.json")
                .display()
                .to_string(),
            endpoint: Some(format!(
                "unix://{}",
                root.join("runtime").join("agent-fortd.sock").display()
            )),
            policy_dir: root.join("policies"),
            store_path: root.join("runtime").join("agent-fortd.sqlite3"),
        }
    }

    fn to_sdk_config(&self) -> SdkConfig {
        SdkConfig::new(
            self.agent_name.clone(),
            Some(BootstrapConfig {
                bootstrap_binary_url: Some(self.bootstrap_binary_url.clone()),
                install_root: Some(self.install_root.clone()),
                bundle_manifest: Some(self.bundle_manifest.clone()),
                endpoint: self.endpoint.clone(),
                policy_dir: Some(self.policy_dir.clone()),
                store_path: Some(self.store_path.clone()),
            }),
        )
    }
}

struct CommandExecutor {
    runtime: tokio::runtime::Runtime,
    client: AgentFortClient,
    pending_approval: Option<PendingApprovalContext>,
    idempotency_seq: u64,
}

#[derive(Debug, Clone)]
struct PendingApprovalContext {
    session_id: String,
    rebind_token: String,
    approval_id: String,
    task_id: String,
}

impl CommandExecutor {
    fn has_pending_approval(&self) -> bool {
        self.pending_approval.is_some()
    }

    fn run_command(&mut self, command: &str) -> Result<String, String> {
        if self.pending_approval.is_some() {
            return Err("pending approval exists; reply with yes or no first".to_string());
        }
        let command = command.to_string();
        let (message, pending_approval) = self
            .runtime
            .block_on(Self::run_command_async(&mut self.client, command))
            .map_err(|error| error.to_string())?;
        self.pending_approval = pending_approval;
        Ok(message)
    }

    fn respond_pending_approval(&mut self, approve: bool) -> Result<String, String> {
        let pending_approval = self
            .pending_approval
            .as_ref()
            .cloned()
            .ok_or_else(|| "no pending approval".to_string())?;

        self.idempotency_seq = self.idempotency_seq.saturating_add(1);
        let idempotency_key = format!(
            "agent-tui-{}-{}-{}",
            if approve { "approve" } else { "deny" },
            now_ms(),
            self.idempotency_seq
        );

        let (message, next_pending) = self
            .runtime
            .block_on(Self::respond_pending_approval_async(
                &mut self.client,
                pending_approval,
                approve,
                idempotency_key,
            ))
            .map_err(|error| error.to_string())?;
        self.pending_approval = next_pending;
        Ok(message)
    }

    async fn run_command_async(
        client: &mut AgentFortClient,
        command: String,
    ) -> af_sdk::Result<(String, Option<PendingApprovalContext>)> {
        let session = {
            let mut sessions = client.sessions().await?;
            sessions.create_session().await?
        };

        let session_id = session.session_id.clone();
        let lease = session
            .lease
            .ok_or_else(|| SdkError::Protocol("CreateSessionResponse missing lease".to_string()))?;
        let rebind_token = lease.rebind_token.clone();

        let task_response = {
            let mut tasks = client.tasks().await?;
            tasks
                .create(
                    session_id.clone(),
                    rebind_token.clone(),
                    build_exec_operation(&command),
                    Some(format!("exec: {command}")),
                )
                .await?
        };

        let task_id = task_response
            .task
            .as_ref()
            .map(|task| task.task_id.as_str())
            .unwrap_or("unknown");

        map_task_outcome(
            task_id,
            task_response.outcome.and_then(|outcome| outcome.outcome),
            session_id,
            rebind_token,
        )
    }

    async fn respond_pending_approval_async(
        client: &mut AgentFortClient,
        pending: PendingApprovalContext,
        approve: bool,
        idempotency_key: String,
    ) -> af_sdk::Result<(String, Option<PendingApprovalContext>)> {
        let decision = if approve {
            RpcApprovalDecision::Approve
        } else {
            RpcApprovalDecision::Deny
        };
        let reason = Some(if approve {
            "approved in agent-tui".to_string()
        } else {
            "denied in agent-tui".to_string()
        });

        let response = {
            let mut approvals = client.approvals().await?;
            approvals
                .respond(
                    pending.session_id.clone(),
                    pending.approval_id.clone(),
                    decision,
                    idempotency_key,
                    reason,
                    pending.rebind_token.clone(),
                )
                .await?
        };

        let task_id = response
            .task
            .as_ref()
            .map(|task| task.task_id.clone())
            .unwrap_or_else(|| pending.task_id.clone());

        match response.outcome.and_then(|outcome| outcome.outcome) {
            Some(task_outcome) => map_task_outcome(
                task_id.as_str(),
                Some(task_outcome),
                pending.session_id,
                pending.rebind_token,
            ),
            None => {
                let mut approval_status = response
                    .approval
                    .as_ref()
                    .and_then(|approval| RpcApprovalStatus::try_from(approval.status).ok())
                    .unwrap_or(RpcApprovalStatus::Unspecified);
                let mut status_source = "respond";
                if approval_status == RpcApprovalStatus::Pending
                    && let Ok(refreshed_status) =
                        Self::fetch_approval_status_async(client, &pending).await
                {
                    approval_status = refreshed_status;
                    status_source = "refresh";
                }
                let status = approval_status.as_str_name().to_string();
                let task_status = response
                    .task
                    .as_ref()
                    .map(|task| task.status.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let next_pending = if approval_status == RpcApprovalStatus::Pending {
                    Some(pending)
                } else {
                    None
                };
                Ok((
                    if approve {
                        format!(
                            "task_id={task_id} approval accepted (status={status}, source={status_source}, task_status={task_status}). No immediate task outcome was returned."
                        )
                    } else {
                        format!(
                            "task_id={task_id} approval denied (status={status}, source={status_source}, task_status={task_status}). No immediate task outcome was returned."
                        )
                    },
                    next_pending,
                ))
            }
        }
    }

    async fn fetch_approval_status_async(
        client: &mut AgentFortClient,
        pending: &PendingApprovalContext,
    ) -> af_sdk::Result<RpcApprovalStatus> {
        let approval = {
            let mut approvals = client.approvals().await?;
            approvals
                .get(
                    pending.session_id.clone(),
                    pending.approval_id.clone(),
                    pending.rebind_token.clone(),
                )
                .await?
        };
        Ok(RpcApprovalStatus::try_from(approval.status).unwrap_or(RpcApprovalStatus::Unspecified))
    }
}

fn map_task_outcome(
    task_id: &str,
    outcome: Option<RpcTaskOutcome>,
    session_id: String,
    rebind_token: String,
) -> af_sdk::Result<(String, Option<PendingApprovalContext>)> {
    match outcome {
        Some(RpcTaskOutcome::Execution(execution)) => {
            Ok((format_execution_result(task_id, &execution), None))
        }
        Some(RpcTaskOutcome::Approval(approval)) => {
            let pending = PendingApprovalContext {
                session_id,
                rebind_token,
                approval_id: approval.approval_id.clone(),
                task_id: if approval.task_id.is_empty() {
                    task_id.to_string()
                } else {
                    approval.task_id.clone()
                },
            };
            Ok((
                format!(
                    "task_id={task_id} pending approval: {} ({})\nReply yes/no to continue.",
                    approval.summary, approval.approval_id
                ),
                Some(pending),
            ))
        }
        Some(RpcTaskOutcome::Denied(denied)) => Ok((
            format!(
                "task_id={task_id} denied: [{}] {}",
                denied.code.unwrap_or_else(|| "POLICY_DENIED".to_string()),
                denied
                    .message
                    .unwrap_or_else(|| "policy denied command".to_string())
            ),
            None,
        )),
        None => Err(SdkError::Protocol(format!(
            "task_id={task_id} missing task outcome"
        ))),
    }
}

fn format_execution_result(task_id: &str, execution: &af_rpc_proto::ExecutionResult) -> String {
    let mut lines = Vec::new();
    let exit_code = execution
        .exit_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "none".to_string());
    lines.push(format!(
        "task_id={task_id} execution state={} exit_code={} timed_out={}",
        execution.state, exit_code, execution.timed_out
    ));

    if !execution.stdout.is_empty() {
        lines.push("stdout:".to_string());
        lines.push(execution.stdout.clone());
    }
    if !execution.stderr.is_empty() {
        lines.push("stderr:".to_string());
        lines.push(execution.stderr.clone());
    }
    if execution.stdout.is_empty() && execution.stderr.is_empty() {
        lines.push("(stdout/stderr are empty)".to_string());
    }
    if execution.stdout_truncated || execution.stderr_truncated {
        lines.push(format!(
            "output truncated: stdout={}, stderr={}",
            execution.stdout_truncated, execution.stderr_truncated
        ));
    }

    lines.join("\n")
}

fn parse_approval_response(input: &str) -> Option<bool> {
    let normalized = input
        .trim()
        .trim_start_matches('/')
        .trim_end_matches(|ch: char| ch == '.' || ch == '!' || ch == '。' || ch == '！')
        .to_ascii_lowercase();
    match normalized.as_str() {
        "yes" | "y" | "true" | "1" | "ok" | "approve" | "是" => Some(true),
        "no" | "n" | "false" | "0" | "deny" | "否" => Some(false),
        _ => None,
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn build_exec_operation(command: &str) -> TaskOperation {
    let mut payload_fields = BTreeMap::new();
    payload_fields.insert(
        "command".to_string(),
        ProstValue {
            kind: Some(ProstValueKind::StringValue(command.to_string())),
        },
    );

    TaskOperation {
        kind: "exec".to_string(),
        payload: Some(ProstStruct {
            fields: payload_fields,
        }),
        options: None,
        labels: HashMap::new(),
    }
}

fn agent_tui_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(|parent| parent.parent()) {
        Some(root) => root.to_path_buf(),
        None => manifest_dir,
    }
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

    fn draw(&mut self, app: &mut App) -> io::Result<()> {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_params = ExampleSdkParams::fixed();
    let (sdk_status, mut executor) = initialize_executor(sdk_params.clone())?;
    run_tui(sdk_status, &mut executor)?;
    cleanup_runtime_on_exit(&sdk_params, executor);
    Ok(())
}

fn initialize_executor(
    sdk_params: ExampleSdkParams,
) -> Result<(String, Option<CommandExecutor>), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let config = sdk_params.to_sdk_config();
    let init_result = runtime.block_on(async {
        AgentFortClient::initialize(config.clone()).await?;

        let mut client = AgentFortClient::connect(config).await?;
        let ping = client.ping().await?;
        let endpoint = client
            .endpoint_uri()
            .unwrap_or_else(|| client.configured_endpoint_uri());

        Ok::<(AgentFortClient, String), SdkError>((
            client,
            format!(
                "ready endpoint={endpoint}, daemon_instance_id={}, policy_dir={}, store_path={}",
                ping.daemon_instance_id,
                sdk_params.policy_dir.display(),
                sdk_params.store_path.display()
            ),
        ))
    });

    match init_result {
        Ok((client, status)) => Ok((
            status,
            Some(CommandExecutor {
                runtime,
                client,
                pending_approval: None,
                idempotency_seq: 0,
            }),
        )),
        Err(error) => Ok((
            format!(
                "SDK initialize failed: {error}; policy_dir={}, store_path={}",
                sdk_params.policy_dir.display(),
                sdk_params.store_path.display()
            ),
            None,
        )),
    }
}

fn run_tui(status: String, executor: &mut Option<CommandExecutor>) -> io::Result<()> {
    let mut app = App::new(status, executor.is_some());
    let mut terminal = TerminalSession::enter()?;

    loop {
        terminal.draw(&mut app)?;
        if app.should_quit {
            break;
        }

        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(key) => handle_key_event(key, &mut app, executor.as_mut()),
                Event::Paste(text) => app.input.push_str(&text),
                _ => {}
            }
        }
    }

    Ok(())
}

fn cleanup_runtime_on_exit(sdk_params: &ExampleSdkParams, executor: Option<CommandExecutor>) {
    drop(executor);

    if let Err(error) = stop_daemon_with_bootstrap(sdk_params) {
        eprintln!("failed to stop daemon via bootstrap: {error}");
    }

    if sdk_params.install_root.exists() {
        if let Err(error) = fs::remove_dir_all(&sdk_params.install_root) {
            eprintln!(
                "failed to remove install_root {}: {error}",
                sdk_params.install_root.display()
            );
        }
    }
}

fn stop_daemon_with_bootstrap(sdk_params: &ExampleSdkParams) -> Result<(), String> {
    let bootstrap_path = resolve_bootstrap_path(&sdk_params.bootstrap_binary_url);
    let mut command = Command::new(&bootstrap_path);
    command
        .arg("stop")
        .arg("--install-root")
        .arg(&sdk_params.install_root);
    if let Some(endpoint) = &sdk_params.endpoint {
        command.arg("--endpoint").arg(endpoint);
    }

    let output = command
        .output()
        .map_err(|error| format!("spawn {} failed: {error}", bootstrap_path.display()))?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(format!(
        "bootstrap stop failed (status={}): stdout=`{stdout}` stderr=`{stderr}`",
        output.status
    ))
}

fn resolve_bootstrap_path(raw: &str) -> PathBuf {
    if let Some(file_url) = raw.strip_prefix("file://") {
        return PathBuf::from(file_url);
    }
    PathBuf::from(raw)
}

fn handle_key_event(key: KeyEvent, app: &mut App, executor: Option<&mut CommandExecutor>) {
    if key.kind != KeyEventKind::Press {
        return;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    match key.code {
        KeyCode::Esc => app.should_quit = true,
        KeyCode::Enter => app.on_send(executor),
        KeyCode::PageUp => app.scroll_conversation_up(10),
        KeyCode::PageDown => app.scroll_conversation_down(10),
        KeyCode::Home => app.scroll_conversation_to_top(),
        KeyCode::End => app.scroll_conversation_to_bottom(),
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

fn draw_ui(frame: &mut Frame<'_>, app: &mut App) {
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

fn draw_messages(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &mut App) {
    let content_width = area.width.saturating_sub(2).max(1) as usize;
    let lines = build_wrapped_conversation_lines(&app.messages, content_width);
    let visible_lines = area.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(visible_lines) as u16;
    if app.scroll_to_bottom {
        app.conversation_scroll = max_scroll;
        app.scroll_to_bottom = false;
    } else if app.conversation_scroll > max_scroll {
        app.conversation_scroll = max_scroll;
    }

    let widget = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Conversation"))
        .scroll((app.conversation_scroll, 0));
    frame.render_widget(widget, area);
}

fn build_wrapped_conversation_lines(
    messages: &[Message],
    content_width: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for message in messages {
        match message.role {
            MessageRole::User => append_wrapped_message(
                &mut lines,
                "You ",
                Style::default().fg(ratatui::style::Color::Green).bold(),
                &message.content,
                content_width,
            ),
            MessageRole::System => append_wrapped_message(
                &mut lines,
                "System ",
                Style::default()
                    .fg(ratatui::style::Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                &message.content,
                content_width,
            ),
        }
    }
    lines
}

fn append_wrapped_message(
    lines: &mut Vec<Line<'static>>,
    prefix: &str,
    prefix_style: Style,
    content: &str,
    content_width: usize,
) {
    let mut content_lines = content.split('\n');
    if let Some(first) = content_lines.next() {
        let prefix_width = prefix.chars().count();
        let first_width = content_width.saturating_sub(prefix_width).max(1);
        let wrapped_first = wrap_text_fixed_width(first, first_width);
        if let Some(first_segment) = wrapped_first.first() {
            lines.push(Line::from(vec![
                Span::styled(prefix.to_string(), prefix_style),
                Span::raw(first_segment.clone()),
            ]));
            for segment in wrapped_first.into_iter().skip(1) {
                lines.push(Line::from(segment));
            }
        }
    }
    for line in content_lines {
        for segment in wrap_text_fixed_width(line, content_width) {
            lines.push(Line::from(segment));
        }
    }
}

fn wrap_text_fixed_width(input: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    if input.is_empty() {
        return vec![String::new()];
    }

    let mut result = Vec::new();
    let mut current = String::new();
    let mut count = 0usize;

    for ch in input.chars() {
        if count >= width {
            result.push(std::mem::take(&mut current));
            count = 0;
        }
        current.push(ch);
        count += 1;
    }

    if current.is_empty() {
        result.push(String::new());
    } else {
        result.push(current);
    }
    result
}

fn draw_sidebar(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let mode = if app.sdk_ready {
        "SDK Task Flow"
    } else {
        "SDK Unavailable"
    };

    let info = vec![
        Line::from(vec![
            Span::styled("Mode: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(mode),
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
        Line::from("Enter  run command"),
        Line::from("yes/no respond approval"),
        Line::from("PgUp/Dn conversation scroll"),
        Line::from("Home/End jump top/bottom"),
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
