use std::fs;
use std::path::{Path, PathBuf};

use af_policy::{PolicyDirectorySnapshot, PolicyFile};

use crate::{PolicyInfraError, PolicyInfraResult};

#[derive(Debug, Clone)]
pub struct PolicyDirectoryLoader {
    root: PathBuf,
}

impl PolicyDirectoryLoader {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn load(&self) -> PolicyInfraResult<PolicyDirectorySnapshot> {
        ensure_directory(&self.root)?;

        let mut files = Vec::new();
        collect_policy_files(&self.root, &self.root, &mut files)?;
        files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

        Ok(PolicyDirectorySnapshot {
            root: self.root.clone(),
            files,
        })
    }
}

fn ensure_directory(path: &Path) -> PolicyInfraResult<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(PolicyInfraError::DirectoryNotReadable {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(PolicyInfraError::DirectoryNotReadable {
                path: path.to_path_buf(),
            })
        }
        Err(error) => Err(error.into()),
    }
}

fn collect_policy_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<PolicyFile>,
) -> PolicyInfraResult<()> {
    let mut entries = fs::read_dir(current)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_policy_files(root, &path, files)?;
            continue;
        }
        if file_type.is_file() && is_policy_file(&path) {
            files.push(PolicyFile {
                absolute_path: path.clone(),
                relative_path: normalize_relative_path(root, &path)?,
            });
        }
    }

    Ok(())
}

pub(crate) fn collect_watched_directories(root: &Path) -> PolicyInfraResult<Vec<PathBuf>> {
    let mut directories = Vec::new();
    if root.exists() {
        ensure_directory(root)?;
        collect_directories(root, &mut directories)?;
    }
    if let Some(parent) = root.parent() {
        directories.push(parent.to_path_buf());
    } else {
        directories.push(root.to_path_buf());
    }
    directories.sort();
    directories.dedup();
    Ok(directories)
}

fn collect_directories(current: &Path, directories: &mut Vec<PathBuf>) -> PolicyInfraResult<()> {
    directories.push(current.to_path_buf());

    let mut entries = fs::read_dir(current)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_directories(&entry.path(), directories)?;
        }
    }

    Ok(())
}

fn is_policy_file(path: &Path) -> bool {
    match path.extension().and_then(|value| value.to_str()) {
        Some("yaml") | Some("yml") => true,
        Some(extension) => {
            extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml")
        }
        None => false,
    }
}

fn normalize_relative_path(root: &Path, path: &Path) -> PolicyInfraResult<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let normalized = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/");
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn loads_yaml_files_in_stable_relative_path_order() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(root.join("b/nested")).expect("create nested dirs");
        fs::create_dir_all(root.join("a")).expect("create sibling dir");
        fs::write(root.join("b/nested/20.yaml"), "version: 1").expect("write nested policy");
        fs::write(root.join("a/10.yml"), "version: 1").expect("write sibling policy");
        fs::write(root.join("ignored.txt"), "not policy").expect("write non-policy file");

        let snapshot = PolicyDirectoryLoader::new(&root)
            .load()
            .expect("load policy dir");

        let relative_paths = snapshot
            .files
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(relative_paths, vec!["a/10.yml", "b/nested/20.yaml"]);
    }

    #[test]
    fn collects_parent_watch_directory_alongside_policy_subdirectories() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let root = temp_dir.path().join("policies");
        fs::create_dir_all(root.join("nested")).expect("create nested dir");

        let directories = collect_watched_directories(&root).expect("collect watched dirs");

        assert!(directories.contains(&root));
        assert!(directories.contains(&root.join("nested")));
        assert!(directories.contains(&temp_dir.path().to_path_buf()));
    }
}
