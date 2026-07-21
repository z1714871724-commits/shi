//! Trust-on-first-use (TOFU) host-key verification.
//!
//! On first connect to a host the server key fingerprint is recorded; on later
//! connects the fingerprint must match or the connection is refused. Stored as
//! a plain-text `known_hosts` file next to the client state.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// Result of comparing a presented key against the stored entry.
pub enum KeyCheck {
    /// No entry yet -> caller should record the key (TOFU).
    New,
    /// Matches the recorded fingerprint.
    Trusted,
    /// Recorded fingerprint differs -> refuse to connect.
    Mismatch { expected: String, received: String },
}

#[derive(Debug, Clone)]
pub struct KnownHosts {
    path: PathBuf,
    entries: HashMap<String, String>,
}

impl KnownHosts {
    pub fn path() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .context("no config directory for this platform")?
            .join("ssh-client");
        std::fs::create_dir_all(&dir).context("create config dir")?;
        Ok(dir.join("known_hosts"))
    }

    pub fn load() -> Self {
        let path = Self::path().unwrap_or_else(|_| PathBuf::from("known_hosts"));
        let mut entries = HashMap::new();
        if let Ok(s) = std::fs::read_to_string(&path) {
            for line in s.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once(char::is_whitespace) {
                    entries.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }
        Self { path, entries }
    }

    fn key(host: &str, port: u16) -> String {
        format!("{host}:{port}")
    }

    pub fn check(&self, host: &str, port: u16, fingerprint: &str) -> KeyCheck {
        match self.entries.get(&Self::key(host, port)) {
            None => KeyCheck::New,
            Some(stored) if stored == fingerprint => KeyCheck::Trusted,
            Some(stored) => KeyCheck::Mismatch {
                expected: stored.clone(),
                received: fingerprint.to_string(),
            },
        }
    }

    pub fn add(&mut self, host: &str, port: u16, fingerprint: &str) {
        self.entries
            .insert(Self::key(host, port), fingerprint.to_string());
    }

    pub fn save(&self) -> Result<()> {
        let mut s = String::new();
        for (k, v) in &self.entries {
            s.push_str(k);
            s.push(' ');
            s.push_str(v);
            s.push('\n');
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&self.path, s).context("write known_hosts")
    }
}
