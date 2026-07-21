//! HTTP API request/response shapes for the sync server.

use serde::{Deserialize, Serialize};

use crate::types::{HostConfig, VaultEntry};

/// Standard API error body.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

// ---- Auth ----

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    /// Base64 Argon2 salt for vault key derivation. Uploaded once at register
    /// time (and treated as updatable) so other devices can sync the vault.
    pub vault_salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub username: String,
    /// Base64 vault salt, so a freshly-logged-in client can derive its vault key.
    pub vault_salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetVaultSaltRequest {
    pub vault_salt: String,
}

// ---- Host configs ----

#[derive(Debug, Serialize, Deserialize)]
pub struct HostListResponse {
    pub hosts: Vec<HostConfig>,
    /// Server's view of the latest update timestamp across all hosts, for
    /// simple last-write-wins conflict resolution.
    pub latest_updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpsertHostRequest {
    pub host: HostConfig,
}

// ---- Vault ----

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultListResponse {
    pub entries: Vec<VaultEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpsertVaultEntryRequest {
    pub entry: VaultEntry,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct OkResponse {
    pub ok: bool,
}

// ---- Health ----

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

pub const API_PREFIX: &str = "/api/v1";
