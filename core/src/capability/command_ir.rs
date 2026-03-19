#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommandIR {
    pub commands: Vec<CommandNode>,
    pub redirections: Vec<Redirection>,
    pub has_pipeline: bool,
    pub has_subshell: bool,
    pub has_command_substitution: bool,
    pub parse_error: bool,
}

impl CommandIR {
    pub fn is_complex_shell(&self) -> bool {
        self.has_pipeline || self.has_subshell || self.has_command_substitution
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommandNode {
    pub raw: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirection {
    pub kind: RedirectionKind,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectionKind {
    Read,
    Write,
    Append,
    Heredoc,
    Unknown,
}
