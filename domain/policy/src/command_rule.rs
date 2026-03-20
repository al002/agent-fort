#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommandRuleSet {
    pub revision: u64,
    pub rules: Vec<CommandRule>,
}

impl CommandRuleSet {
    pub fn empty() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRule {
    pub source: RuleSource,
    pub pattern: Vec<PatternToken>,
    pub when: Option<RuleCondition>,
    pub capabilities: RuleCapabilities,
    pub reason: Option<String>,
}

impl CommandRule {
    pub fn matches(&self, argv: &[String]) -> bool {
        self.matches_pattern(argv) && self.when.as_ref().is_none_or(|when| when.matches(argv))
    }

    pub fn matches_pattern(&self, argv: &[String]) -> bool {
        if argv.len() < self.pattern.len() {
            return false;
        }
        self.pattern
            .iter()
            .zip(argv.iter())
            .all(|(token, value)| token.matches(value))
    }

    pub fn source_key(&self) -> String {
        self.source.key()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSource {
    pub file: String,
    pub line: usize,
    pub ordinal: usize,
}

impl RuleSource {
    pub fn key(&self) -> String {
        format!("{}:{}#{}", self.file, self.line, self.ordinal)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternToken {
    Single(String),
    Alts(Vec<String>),
}

impl PatternToken {
    pub fn matches(&self, token: &str) -> bool {
        match self {
            Self::Single(expected) => expected == token,
            Self::Alts(alternatives) => alternatives.iter().any(|candidate| candidate == token),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleCapabilities {
    pub fs_read: Vec<ValueRef>,
    pub fs_write: Vec<ValueRef>,
    pub fs_delete: Vec<ValueRef>,
    pub net_connect: Vec<NetConnectSpec>,
    pub host_exec: bool,
    pub process_control: bool,
    pub privilege: bool,
    pub credential_access: bool,
    pub mark_unknown: bool,
    pub risk_tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetConnectSpec {
    pub host: ValueRef,
    pub port: Option<u16>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueRef {
    Literal(String),
    Arg(usize),
    ArgAfter(String),
    ArgAfterAny(Vec<String>),
    Positional(usize),
    AllPositionals,
    UrlHostFromArg(usize),
    Cwd,
    ResolvePath(Box<ValueRef>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleCondition {
    Has(String),
    HasAny(Vec<String>),
    HasAll(Vec<String>),
    ShellWrapper(ShellWrapperKind),
}

impl RuleCondition {
    pub fn matches(&self, argv: &[String]) -> bool {
        let args = argv.get(1..).unwrap_or_default();
        match self {
            Self::Has(token) => args.iter().any(|value| value == token),
            Self::HasAny(tokens) => tokens
                .iter()
                .any(|token| args.iter().any(|value| value == token)),
            Self::HasAll(tokens) => tokens
                .iter()
                .all(|token| args.iter().any(|value| value == token)),
            Self::ShellWrapper(kind) => kind.matches(argv),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellWrapperKind {
    None,
    C,
    Lc,
    Any,
}

impl ShellWrapperKind {
    pub fn matches(self, argv: &[String]) -> bool {
        let wrapper = detect_shell_wrapper(argv);
        match self {
            Self::None => wrapper == ShellWrapperKind::None,
            Self::C => wrapper == ShellWrapperKind::C,
            Self::Lc => wrapper == ShellWrapperKind::Lc,
            Self::Any => wrapper == ShellWrapperKind::C || wrapper == ShellWrapperKind::Lc,
        }
    }
}

fn detect_shell_wrapper(argv: &[String]) -> ShellWrapperKind {
    let binary = argv
        .first()
        .map(|value| {
            std::path::Path::new(value)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(value)
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    if !matches!(binary.as_str(), "sh" | "bash" | "zsh" | "dash" | "ksh") {
        return ShellWrapperKind::None;
    }

    let args = argv.get(1..).unwrap_or_default();
    if args.iter().any(|token| token == "-lc") {
        ShellWrapperKind::Lc
    } else if args.iter().any(|token| token == "-c") {
        ShellWrapperKind::C
    } else {
        ShellWrapperKind::None
    }
}
