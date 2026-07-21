//! HTTP client for the sync server, with end-to-end encryption.
//!
//! Two classes of secret are protected:
//!   * SSH host passwords (`auth_method = password`) - encrypted with the
//!     vault key, AAD-bound to the host id, before upload.
//!   * SSH key passphrases - stored as vault entries, encrypted with the vault
//!     key, AAD-bound to the entry label.
//!
//! The server only ever stores ciphertext. The vault key is derived on the
//! client from the user's master password + the per-user salt (Argon2id) and
//! never transmitted.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use protocol::api::*;
use protocol::types::{AuthMethod, HostConfig, VaultEntry};
use protocol::{decrypt_secret, derive_vault_key, encrypt_secret, new_salt, KEY_LEN};

use crate::store::LocalVaultEntry;

#[derive(Debug, Clone)]
pub struct SyncClient {
    http: reqwest::Client,
    base_url: String,
    token: Option<String>,
    vault_key: Option<[u8; KEY_LEN]>,
}

#[derive(Debug, Clone, Default)]
pub struct PulledState {
    pub hosts: Vec<HostConfig>,
    pub vault: Vec<LocalVaultEntry>,
}

impl SyncClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let base_url = base_url.trim().trim_end_matches('/').to_string();
        if base_url.is_empty() {
            anyhow::bail!("server URL is empty");
        }
        // Validate up front so we surface a friendly error instead of a
        // reqwest "builder error" at request time.
        reqwest::Url::parse(&base_url)
            .with_context(|| format!("invalid server URL {base_url:?}"))?;
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            anyhow::bail!("server URL must start with http:// or https:// (got {base_url:?})");
        }
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()?;
        Ok(Self {
            http,
            base_url,
            token: None,
            vault_key: None,
        })
    }

    #[cfg(test)]
    fn base_url_str(&self) -> &str {
        &self.base_url
    }

    #[allow(dead_code)]
    pub fn is_authed(&self) -> bool {
        self.token.is_some() && self.vault_key.is_some()
    }

    #[allow(dead_code)]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}{}", self.base_url, API_PREFIX, path)
    }

    fn auth_header(&self) -> Result<String> {
        Ok(format!(
            "Bearer {}",
            self.token
                .as_ref()
                .ok_or_else(|| anyhow!("not logged in"))?
        ))
    }

    fn key(&self) -> Result<&[u8; KEY_LEN]> {
        self.vault_key
            .as_ref()
            .ok_or_else(|| anyhow!("no vault key"))
    }

    /// Register a new user. Generates the vault salt, derives the vault key
    /// locally, and uploads only the salt (not the password, not the key).
    pub async fn register(&mut self, username: &str, password: &str) -> Result<AuthResponse> {
        let salt = new_salt();
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
        let vault_key = derive_vault_key(password, &salt)?;
        let req = RegisterRequest {
            username: username.to_string(),
            password: password.to_string(),
            vault_salt: salt_b64.clone(),
        };
        let resp = self
            .http
            .post(self.url("/register"))
            .json(&req)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Self::err(resp).await);
        }
        let auth: AuthResponse = resp.json().await?;
        self.token = Some(auth.token.clone());
        self.vault_key = Some(vault_key);
        Ok(auth)
    }

    /// Log in. The server returns the vault salt; the client re-derives the
    /// vault key from the typed password. A wrong password fails server auth
    /// before any decryption is attempted.
    pub async fn login(&mut self, username: &str, password: &str) -> Result<AuthResponse> {
        let req = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        };
        let resp = self.http.post(self.url("/login")).json(&req).send().await?;
        if !resp.status().is_success() {
            return Err(Self::err(resp).await);
        }
        let auth: AuthResponse = resp.json().await?;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(&auth.vault_salt)
            .context("invalid vault_salt from server")?;
        let vault_key = derive_vault_key(password, &salt)?;
        self.token = Some(auth.token.clone());
        self.vault_key = Some(vault_key);
        Ok(auth)
    }

    /// Push local hosts + vault to the server. Everything secret is encrypted
    /// first; structural fields (name, host, port, username, auth method, key
    /// path, group) are uploaded in the clear so they can be browsed server-side-free.
    pub async fn push(&self, hosts: &[HostConfig], vault: &[LocalVaultEntry]) -> Result<()> {
        let key = self.key()?;

        // Vault entries first (so host.key_password_id references resolve).
        for entry in vault {
            let (nonce, ct) = encrypt_secret(key, &entry.passphrase, entry.label.as_bytes())?;
            let ve = VaultEntry {
                id: entry.id.clone(),
                label: entry.label.clone(),
                nonce,
                ciphertext: ct,
                updated_at: entry.updated_at,
            };
            let resp = self
                .http
                .put(self.url("/vault"))
                .header("Authorization", self.auth_header()?)
                .json(&UpsertVaultEntryRequest { entry: ve })
                .send()
                .await?;
            if !resp.status().is_success() {
                return Err(Self::err(resp).await);
            }
        }

        // Hosts: encrypt the password field if present.
        for host in hosts {
            let mut sync_host = host.clone();
            if matches!(host.auth_method, AuthMethod::Password) {
                if let Some(pw) = &host.password {
                    let (nonce, ct) = encrypt_secret(key, pw, host.id.as_bytes())?;
                    // Pack nonce + ciphertext so the round-trip is self-describing.
                    sync_host.password = Some(format!("{nonce}:{ct}"));
                }
            } else {
                // Key auth: no password to sync. Keep key_path + key_password_id.
                sync_host.password = None;
            }
            let resp = self
                .http
                .put(self.url("/hosts"))
                .header("Authorization", self.auth_header()?)
                .json(&UpsertHostRequest { host: sync_host })
                .send()
                .await?;
            if !resp.status().is_success() {
                return Err(Self::err(resp).await);
            }
        }
        Ok(())
    }

    /// Pull hosts + vault from the server and decrypt everything locally.
    pub async fn pull(&self) -> Result<PulledState> {
        let key = self.key()?;
        let host_resp = self
            .http
            .get(self.url("/hosts"))
            .header("Authorization", self.auth_header()?)
            .send()
            .await?;
        if !host_resp.status().is_success() {
            return Err(Self::err(host_resp).await);
        }
        let host_list: HostListResponse = host_resp.json().await?;
        let vault_resp = self
            .http
            .get(self.url("/vault"))
            .header("Authorization", self.auth_header()?)
            .send()
            .await?;
        if !vault_resp.status().is_success() {
            return Err(Self::err(vault_resp).await);
        }
        let vault_list: VaultListResponse = vault_resp.json().await?;

        let mut hosts = Vec::with_capacity(host_list.hosts.len());
        for mut h in host_list.hosts {
            if matches!(h.auth_method, AuthMethod::Password) {
                if let Some(packed) = h.password.take() {
                    h.password = Self::decrypt_packed(key, &packed, h.id.as_bytes())?;
                }
            } else {
                h.password = None;
            }
            hosts.push(h);
        }
        let mut vault = Vec::with_capacity(vault_list.entries.len());
        for ve in vault_list.entries {
            let passphrase = decrypt_secret(key, &ve.nonce, &ve.ciphertext, ve.label.as_bytes())?;
            vault.push(LocalVaultEntry {
                id: ve.id,
                label: ve.label,
                passphrase,
                updated_at: ve.updated_at,
            });
        }
        Ok(PulledState { hosts, vault })
    }

    pub async fn delete_host(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(self.url(&format!("/hosts/{id}")))
            .header("Authorization", self.auth_header()?)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Self::err(resp).await);
        }
        Ok(())
    }

    pub async fn delete_vault(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(self.url(&format!("/vault/{id}")))
            .header("Authorization", self.auth_header()?)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Self::err(resp).await);
        }
        Ok(())
    }

    fn decrypt_packed(key: &[u8; KEY_LEN], packed: &str, aad: &[u8]) -> Result<Option<String>> {
        let mut parts = packed.splitn(2, ':');
        let nonce = parts
            .next()
            .ok_or_else(|| anyhow!("malformed ciphertext"))?;
        let ct = parts
            .next()
            .ok_or_else(|| anyhow!("malformed ciphertext"))?;
        Ok(Some(decrypt_secret(key, nonce, ct, aad)?))
    }

    async fn err(resp: reqwest::Response) -> anyhow::Error {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow!("server returned {status}: {body}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_server_url() {
        assert!(SyncClient::new("").is_err());
        assert!(SyncClient::new("   ").is_err());
        assert!(SyncClient::new("not a url").is_err());
        assert!(SyncClient::new("127.0.0.1:8787").is_err()); // missing scheme
        assert!(SyncClient::new("http://127.0.0.1:8787").is_ok());
        assert!(SyncClient::new("http://127.0.0.1:8787/").is_ok());
        let c = SyncClient::new("http://127.0.0.1:8787/").unwrap();
        assert_eq!(c.base_url_str(), "http://127.0.0.1:8787");
    }
}
