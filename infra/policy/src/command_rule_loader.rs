use std::fs;
use std::path::{Path, PathBuf};

use af_policy::CommandRuleSet;
use tracing::warn;

use crate::command_rule_parser::CommandRuleParser;
use crate::{PolicyInfraError, PolicyInfraResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedCommandRules {
    pub rules: CommandRuleSet,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CommandRuleLoader;

impl CommandRuleLoader {
    pub fn load(
        &self,
        root: &Path,
        strict: bool,
        runtime_revision: u64,
    ) -> PolicyInfraResult<LoadedCommandRules> {
        let files = find_rule_files(root, strict)?;
        let parser = CommandRuleParser;
        let mut rules = Vec::new();

        for (absolute_path, relative_path) in files {
            let raw = match fs::read_to_string(&absolute_path) {
                Ok(raw) => raw,
                Err(error) if !strict => {
                    warn!(
                        path = %relative_path,
                        error = %error,
                        "command rule file read failed"
                    );
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            match parser.parse_file(&relative_path, &raw) {
                Ok(mut parsed) => {
                    rules.append(&mut parsed);
                }
                Err(error) if !strict => {
                    warn!(path = %relative_path, error = %error, "command rule file rejected");
                }
                Err(error) => return Err(error),
            }
        }

        Ok(LoadedCommandRules {
            rules: CommandRuleSet {
                revision: runtime_revision,
                rules,
            },
        })
    }
}

fn find_rule_files(root: &Path, strict: bool) -> PolicyInfraResult<Vec<(PathBuf, String)>> {
    match fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(PolicyInfraError::DirectoryNotReadable {
                path: root.to_path_buf(),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !strict => {
            return Ok(Vec::new());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PolicyInfraError::DirectoryNotReadable {
                path: root.to_path_buf(),
            });
        }
        Err(error) => return Err(error.into()),
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("rules") {
            continue;
        }
        let Some(file_name) = path
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        files.push((path, file_name));
    }

    files.sort_by(|left, right| left.1.cmp(&right.1));
    Ok(files)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn loads_rules_in_lexicographic_order() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("rules");
        fs::create_dir_all(&root).expect("create rules dir");
        fs::write(
            root.join("20.rules"),
            r#"
command_rule(
    pattern = ["echo"],
    capabilities = cap(),
)
"#,
        )
        .expect("write");
        fs::write(
            root.join("10.rules"),
            r#"
command_rule(
    pattern = ["ls"],
    capabilities = cap(),
)
"#,
        )
        .expect("write");

        let loaded = CommandRuleLoader
            .load(&root, true, 7)
            .expect("load command rules");
        assert_eq!(loaded.rules.revision, 7);
        assert_eq!(loaded.rules.rules.len(), 2);
        assert_eq!(loaded.rules.rules[0].pattern.len(), 1);
    }

    #[test]
    fn non_strict_mode_allows_missing_rule_directory() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("missing");

        let loaded = CommandRuleLoader
            .load(&root, false, 1)
            .expect("load empty rules");
        assert!(loaded.rules.rules.is_empty());
    }
}
