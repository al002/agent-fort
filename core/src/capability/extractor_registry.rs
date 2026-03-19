use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractorKind {
    CurlLike,
    Git,
    PythonLike,
    NodeLike,
    GenericShell,
}

#[derive(Debug, Clone)]
pub struct ExtractorRegistry {
    by_binary: BTreeMap<String, ExtractorKind>,
}

impl Default for ExtractorRegistry {
    fn default() -> Self {
        let mut by_binary = BTreeMap::new();

        for binary in ["curl", "wget", "ssh", "scp", "nc"] {
            by_binary.insert(binary.to_string(), ExtractorKind::CurlLike);
        }
        by_binary.insert("git".to_string(), ExtractorKind::Git);

        for binary in ["python", "python3", "python3.11", "perl", "ruby"] {
            by_binary.insert(binary.to_string(), ExtractorKind::PythonLike);
        }
        for binary in ["node", "deno"] {
            by_binary.insert(binary.to_string(), ExtractorKind::NodeLike);
        }
        for binary in ["sh", "bash", "zsh", "dash", "ksh"] {
            by_binary.insert(binary.to_string(), ExtractorKind::GenericShell);
        }
        for binary in ["ls", "pwd"] {
            by_binary.insert(binary.to_string(), ExtractorKind::GenericShell);
        }

        Self { by_binary }
    }
}

impl ExtractorRegistry {
    pub fn get(&self, binary: &str) -> Option<ExtractorKind> {
        self.by_binary.get(binary).copied()
    }
}
