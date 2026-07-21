//! Local on-disk state for the client.
//!
//! The working copy keeps passwords and key passphrases in *plaintext* on the
//! user's own machine (so SSH can use them). Everything that leaves the device
//! is encrypted first by [`crate::sync::SyncClient`]; see that module for the
//! end-to-end encryption story.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use protocol::types::HostConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalVaultEntry {
    pub id: String,
    pub label: String,
    /// Plaintext passphrase, local only.
    pub passphrase: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalState {
    #[serde(default)]
    pub server_url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub hosts: Vec<HostConfig>,
    #[serde(default)]
    pub vault: Vec<LocalVaultEntry>,
    /// Monospace font family for the terminal (e.g. "JetBrainsMono Nerd Font").
    #[serde(default)]
    pub terminal_font: String,
    /// UI theme: "dark" or "light".
    #[serde(default)]
    pub theme: String,
    /// UI language code, e.g. "en" or "zh".
    #[serde(default)]
    pub lang: String,
}

impl LocalState {
    pub fn terminal_font_or_default(&self) -> String {
        if self.terminal_font.trim().is_empty() {
            "Menlo".to_string()
        } else {
            self.terminal_font.clone()
        }
    }

    pub fn theme_or_default(&self) -> String {
        match self.theme.trim() {
            "light" => "light".to_string(),
            _ => "dark".to_string(),
        }
    }

    pub fn lang_or_default(&self) -> String {
        if self.lang.trim().is_empty() {
            "en".to_string()
        } else {
            self.lang.clone()
        }
    }
}

impl LocalState {
    pub fn config_path() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .context("no config directory for this platform")?
            .join("ssh-client");
        std::fs::create_dir_all(&dir).context("create config dir")?;
        Ok(dir.join("state.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        Self::load_from(&path)
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("parse state.json"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).context("read state.json"),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        self.save_to(&path)
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context("serialize state.json")?;
        std::fs::write(path, bytes).context("write state.json")
    }

    pub fn upsert_host(&mut self, host: HostConfig) {
        if let Some(existing) = self.hosts.iter_mut().find(|h| h.id == host.id) {
            *existing = host;
        } else {
            self.hosts.push(host);
        }
    }

    pub fn delete_host(&mut self, id: &str) {
        self.hosts.retain(|h| h.id != id);
        self.vault.retain(|v| {
            // drop orphaned vault entries
            self.hosts
                .iter()
                .any(|h| h.key_password_id.as_deref() == Some(v.id.as_str()))
        });
    }

    pub fn upsert_vault(&mut self, entry: LocalVaultEntry) {
        if let Some(existing) = self.vault.iter_mut().find(|v| v.id == entry.id) {
            *existing = entry;
        } else {
            self.vault.push(entry);
        }
    }

    pub fn passphrase_for(&self, host: &HostConfig) -> Option<&str> {
        host.key_password_id
            .as_ref()
            .and_then(|id| self.vault.iter().find(|v| &v.id == id))
            .map(|v| v.passphrase.as_str())
    }
}
