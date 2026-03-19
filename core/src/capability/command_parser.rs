use thiserror::Error;
use tree_sitter::{Node, Parser};

use super::{CommandIR, CommandNode, Redirection, RedirectionKind};

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandParser;

impl CommandParser {
    pub fn parse(&self, command: &str) -> Result<CommandIR, CommandParseError> {
        let mut parser = Parser::new();
        let language = tree_sitter_bash::LANGUAGE;
        parser
            .set_language(&language.into())
            .map_err(|_| CommandParseError::LanguageUnavailable)?;

        let Some(tree) = parser.parse(command, None) else {
            return Err(CommandParseError::ParseFailed);
        };

        let mut ir = CommandIR {
            parse_error: tree.root_node().has_error(),
            ..CommandIR::default()
        };
        walk(tree.root_node(), command, &mut ir);

        Ok(ir)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommandParseError {
    #[error("tree-sitter bash language is unavailable")]
    LanguageUnavailable,
    #[error("tree-sitter failed to parse command")]
    ParseFailed,
}

fn walk(node: Node<'_>, source: &str, ir: &mut CommandIR) {
    match node.kind() {
        "command" => {
            if let Ok(raw) = node.utf8_text(source.as_bytes()) {
                let argv = tokenize_shell_fragment(raw);
                if !argv.is_empty() {
                    ir.commands.push(CommandNode {
                        raw: raw.trim().to_string(),
                        argv,
                    });
                }
            }
        }
        "pipeline" => ir.has_pipeline = true,
        "subshell" => ir.has_subshell = true,
        kind if kind.contains("command_substitution") => ir.has_command_substitution = true,
        kind if kind.contains("redirect") => {
            if let Ok(raw) = node.utf8_text(source.as_bytes()) {
                ir.redirections.push(parse_redirection(raw));
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, ir);
    }
}

fn parse_redirection(raw: &str) -> Redirection {
    let trimmed = raw.trim();
    let (kind, target) = if let Some(target) = extract_redirect_target(trimmed, ">>") {
        (RedirectionKind::Append, target)
    } else if let Some(target) = extract_redirect_target(trimmed, "<<") {
        (RedirectionKind::Heredoc, target)
    } else if let Some(target) = extract_redirect_target(trimmed, ">") {
        (RedirectionKind::Write, target)
    } else if let Some(target) = extract_redirect_target(trimmed, "<") {
        (RedirectionKind::Read, target)
    } else {
        (RedirectionKind::Unknown, None)
    };

    Redirection { kind, target }
}

fn extract_redirect_target(raw: &str, operator: &str) -> Option<Option<String>> {
    let index = raw.find(operator)?;
    let after = raw[index + operator.len()..].trim();
    if after.is_empty() {
        return Some(None);
    }

    let token = tokenize_shell_fragment(after).into_iter().next();
    Some(token)
}

fn tokenize_shell_fragment(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escape = false;

    for ch in raw.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }

        match ch {
            '\\' if quote != Some('"') => {
                escape = true;
            }
            '\\' => current.push(ch),
            '"' | '\'' => {
                if quote == Some(ch) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(ch);
                } else {
                    current.push(ch);
                }
            }
            ch if ch.is_whitespace() && quote.is_none() => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands_and_redirects() {
        let ir = CommandParser
            .parse("cat in.txt | grep key > out.txt")
            .expect("parse command");

        assert!(ir.has_pipeline);
        assert_eq!(ir.commands.len(), 2);
        assert!(
            ir.redirections
                .iter()
                .any(|redirection| redirection.kind == RedirectionKind::Write)
        );
    }

    #[test]
    fn parses_command_substitution_flag() {
        let ir = CommandParser
            .parse("echo $(uname -a)")
            .expect("parse command");
        assert!(ir.has_command_substitution);
    }
}
