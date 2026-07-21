//! Domain types shared between client and server.

use serde::{Deserialize, Serialize};

/// A configured SSH host. `key_password_id` optionally links the host to a
/// vault entry holding the passphrase for its private key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostConfig {
    /// Stable client-generated id (uuid-like string).
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Auth method: "password" or "key".
    pub auth_method: AuthMethod,
    /// Password (for "password" auth). Encrypted at rest on the server when
    /// synced; stored locally in plaintext only on the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Path to a private key file (for "key" auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    /// Id of the vault entry holding the key passphrase, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_password_id: Option<String>,
    /// Free-form tags / group for filtering in the UI.
    #[serde(default)]
    pub group: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Password,
    Key,
}

/// An encrypted SSH key passphrase stored on the server.
/// Only `label`, `nonce` and `ciphertext` are uploaded; the key itself is
/// derived on the client from the master password.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultEntry {
    pub id: String,
    pub label: String,
    /// Base64 AES-GCM nonce.
    pub nonce: String,
    /// Base64 ciphertext (label-bound AAD).
    pub ciphertext: String,
    pub updated_at: i64,
}
